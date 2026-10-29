"""Two-phase, content-addressed execution preparation for formal PAPER batches.

The child ledgers are first replayed in memory from their immutable checkpoints.
Only after every expected fill and the parent net order plan are frozen may the
real paper-ledger mutation phase begin.  This module is deliberately broker
agnostic and cannot submit an order.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, InvalidOperation
import math
import re
from typing import Any, Mapping, Sequence

from .order_allocation import (
    OrderAllocationError,
    build_parent_order_plan,
    validate_parent_order_plan,
)
from .platform_portfolio import PLATFORM_PORTFOLIO_ASSESSMENT_SCHEMA
from .portfolio_stress import PORTFOLIO_STRESS_ASSESSMENT_SCHEMA
from .provenance import sha256_digest


PRETRADE_CHILD_RECEIPT_SCHEMA = "quant-core/pretrade-child-execution-receipt/v1"
PRETRADE_BATCH_SCHEMA = "quant-platform/pretrade-execution-batch/v2"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")


class ExecutionOrchestrationError(ValueError):
    """Raised when a prepared execution batch cannot be reproduced exactly."""


def _hash(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not HASH_RE.fullmatch(text):
        raise ExecutionOrchestrationError(f"{label} must be a lowercase sha256")
    return text


def _day(value: Any, label: str) -> str:
    text = str(value or "")
    try:
        parsed = date.fromisoformat(text)
    except ValueError as exc:
        raise ExecutionOrchestrationError(f"{label} must be an ISO date") from exc
    if parsed.isoformat() != text:
        raise ExecutionOrchestrationError(f"{label} must be a canonical ISO date")
    return text


def _timestamp(value: Any, label: str) -> str:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ExecutionOrchestrationError(
            f"{label} must be an ISO datetime"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ExecutionOrchestrationError(f"{label} must include a timezone")
    return parsed.isoformat()


def _number(value: Any, label: str, *, positive: bool = False) -> float:
    if isinstance(value, bool):
        raise ExecutionOrchestrationError(f"{label} must be numeric")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ExecutionOrchestrationError(f"{label} must be numeric") from exc
    if not math.isfinite(number) or (positive and number <= 0) or (not positive and number < 0):
        raise ExecutionOrchestrationError(f"{label} is outside its valid range")
    return number


def _decimal_text(value: Any, label: str, *, positive: bool = False) -> str:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ExecutionOrchestrationError(f"{label} must be decimal") from exc
    if not number.is_finite() or (positive and number <= 0) or (not positive and number < 0):
        raise ExecutionOrchestrationError(f"{label} is outside its valid range")
    normalized = format(number.normalize(), "f")
    return "0" if normalized in {"-0", ""} else normalized


def _notionals(value: Mapping[str, Any], label: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ExecutionOrchestrationError(f"{label} must be an object")
    output: dict[str, str] = {}
    for raw_code, raw_notional in value.items():
        code = str(raw_code).strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", code):
            raise ExecutionOrchestrationError(f"{label} symbol is invalid")
        notional = _decimal_text(raw_notional, f"{label}.{code}")
        if Decimal(notional) > 0:
            output[code] = notional
    return dict(sorted(output.items()))


def _planned_fill(value: Mapping[str, Any], *, trade_date: str) -> dict[str, Any]:
    raw = dict(value)
    required = {
        "id",
        "order_id",
        "signal_date",
        "date",
        "side",
        "code",
        "name",
        "quantity",
        "price",
        "reference_price",
        "notional",
        "commission",
        "stamp_tax",
        "transfer_fee",
        "cost",
        "slippage_cost",
        "status",
        "fee_policy_id",
    }
    if set(raw) != required:
        raise ExecutionOrchestrationError(
            "planned fill fields do not match the canonical execution contract"
        )
    fill_id = str(raw["id"]).strip()
    order_id = str(raw["order_id"]).strip()
    code = str(raw["code"]).strip()
    if not ID_RE.fullmatch(fill_id) or not ID_RE.fullmatch(order_id):
        raise ExecutionOrchestrationError("planned fill identifiers are invalid")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", code):
        raise ExecutionOrchestrationError("planned fill symbol is invalid")
    side = str(raw["side"])
    status = str(raw["status"])
    if side not in {"buy", "sell"}:
        raise ExecutionOrchestrationError("planned fill side is invalid")
    if status not in {"FILLED", "PARTIALLY_FILLED"}:
        raise ExecutionOrchestrationError("planned fill status is invalid")
    quantity = raw["quantity"]
    if not isinstance(quantity, int) or isinstance(quantity, bool) or quantity <= 0:
        raise ExecutionOrchestrationError("planned fill quantity must be positive integer")
    if _day(raw["date"], "planned fill date") != trade_date:
        raise ExecutionOrchestrationError("planned fill trade date mismatch")
    signal_date = _day(raw["signal_date"], "planned fill signal_date")
    if signal_date >= trade_date:
        raise ExecutionOrchestrationError("planned fill must follow its signal date")
    return {
        "id": fill_id,
        "order_id": order_id,
        "signal_date": signal_date,
        "date": trade_date,
        "side": side,
        "code": code,
        "name": str(raw["name"]),
        "quantity": quantity,
        "price": _number(raw["price"], "planned fill price", positive=True),
        "reference_price": _number(
            raw["reference_price"], "planned fill reference_price", positive=True
        ),
        "notional": _number(raw["notional"], "planned fill notional"),
        "commission": _number(raw["commission"], "planned fill commission"),
        "stamp_tax": _number(raw["stamp_tax"], "planned fill stamp_tax"),
        "transfer_fee": _number(
            raw["transfer_fee"], "planned fill transfer_fee"
        ),
        "cost": _number(raw["cost"], "planned fill cost"),
        "slippage_cost": _number(
            raw["slippage_cost"], "planned fill slippage_cost"
        ),
        "status": status,
        "fee_policy_id": str(raw["fee_policy_id"]).strip(),
    }


def build_pretrade_child_receipt(
    *,
    strategy_id: str,
    trade_date: str | date,
    recorded_at: str | datetime,
    signal_sha256: str,
    market_manifest_sha256: str,
    platform_preflight_sha256: str,
    source_checkpoint_sha256: str,
    source_snapshot_sha256: str,
    planned_rebalance: Mapping[str, Any],
    planned_fills: Sequence[Mapping[str, Any]],
    planned_reconciliation: Mapping[str, Any],
    planned_equity: Any,
    planned_cash: Any,
    planned_positions_notional: Mapping[str, Any],
    planned_snapshot_sha256: str,
) -> dict[str, Any]:
    """Build a child preparation receipt without changing a persistent ledger."""
    child_id = str(strategy_id).strip()
    if not ID_RE.fullmatch(child_id):
        raise ExecutionOrchestrationError("strategy_id is invalid")
    day = _day(trade_date, "trade_date")
    moment = _timestamp(recorded_at, "recorded_at")
    fills = [_planned_fill(dict(item), trade_date=day) for item in planned_fills]
    fill_ids = [str(item["id"]) for item in fills]
    if len(fill_ids) != len(set(fill_ids)):
        raise ExecutionOrchestrationError("planned fill ids must be unique")
    rebalance = dict(planned_rebalance)
    if set(rebalance) != {"cost", "turnover"}:
        raise ExecutionOrchestrationError("planned rebalance fields are invalid")
    normalized_rebalance = {
        "cost": _number(rebalance["cost"], "planned rebalance cost"),
        "turnover": _number(rebalance["turnover"], "planned rebalance turnover"),
    }
    reconciliation = dict(planned_reconciliation)
    if reconciliation.get("ok") is not True or reconciliation.get("date") != day:
        raise ExecutionOrchestrationError(
            "planned reconciliation must pass on the execution date"
        )
    equity_text = _decimal_text(planned_equity, "planned_equity", positive=True)
    cash_text = _decimal_text(planned_cash, "planned_cash")
    position_notionals = _notionals(
        planned_positions_notional, "planned_positions_notional"
    )
    if abs(
        Decimal(cash_text)
        + sum((Decimal(value) for value in position_notionals.values()), Decimal("0"))
        - Decimal(equity_text)
    ) > Decimal("0.01"):
        raise ExecutionOrchestrationError(
            "planned cash plus positions does not reconcile to planned equity"
        )
    identity = {
        "schema": PRETRADE_CHILD_RECEIPT_SCHEMA,
        "strategy_id": child_id,
        "trade_date": day,
        "recorded_at": moment,
        "signal_sha256": _hash(signal_sha256, "signal_sha256"),
        "market_manifest_sha256": _hash(
            market_manifest_sha256, "market_manifest_sha256"
        ),
        "platform_preflight_sha256": _hash(
            platform_preflight_sha256, "platform_preflight_sha256"
        ),
        "source_checkpoint_sha256": _hash(
            source_checkpoint_sha256, "source_checkpoint_sha256"
        ),
        "source_snapshot_sha256": _hash(
            source_snapshot_sha256, "source_snapshot_sha256"
        ),
        "planned_rebalance": normalized_rebalance,
        "planned_fills": fills,
        "planned_reconciliation": reconciliation,
        "planned_equity": equity_text,
        "planned_cash": cash_text,
        "planned_positions_notional": position_notionals,
        "planned_snapshot_sha256": _hash(
            planned_snapshot_sha256, "planned_snapshot_sha256"
        ),
        "real_orders": False,
    }
    return {**identity, "receipt_sha256": sha256_digest(identity)}


def validate_pretrade_child_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    receipt = dict(value)
    required = {
        "schema",
        "strategy_id",
        "trade_date",
        "recorded_at",
        "signal_sha256",
        "market_manifest_sha256",
        "platform_preflight_sha256",
        "source_checkpoint_sha256",
        "source_snapshot_sha256",
        "planned_rebalance",
        "planned_fills",
        "planned_reconciliation",
        "planned_equity",
        "planned_cash",
        "planned_positions_notional",
        "planned_snapshot_sha256",
        "real_orders",
        "receipt_sha256",
    }
    if set(receipt) != required or receipt.get("schema") != PRETRADE_CHILD_RECEIPT_SCHEMA:
        raise ExecutionOrchestrationError(
            "pretrade child receipt fields do not match contract"
        )
    if receipt.get("real_orders") is not False:
        raise ExecutionOrchestrationError("pretrade child receipt must be PAPER-only")
    rebuilt = build_pretrade_child_receipt(
        strategy_id=receipt["strategy_id"],
        trade_date=receipt["trade_date"],
        recorded_at=receipt["recorded_at"],
        signal_sha256=receipt["signal_sha256"],
        market_manifest_sha256=receipt["market_manifest_sha256"],
        platform_preflight_sha256=receipt["platform_preflight_sha256"],
        source_checkpoint_sha256=receipt["source_checkpoint_sha256"],
        source_snapshot_sha256=receipt["source_snapshot_sha256"],
        planned_rebalance=dict(receipt["planned_rebalance"]),
        planned_fills=list(receipt["planned_fills"]),
        planned_reconciliation=dict(receipt["planned_reconciliation"]),
        planned_equity=receipt["planned_equity"],
        planned_cash=receipt["planned_cash"],
        planned_positions_notional=dict(receipt["planned_positions_notional"]),
        planned_snapshot_sha256=receipt["planned_snapshot_sha256"],
    )
    if rebuilt != receipt:
        raise ExecutionOrchestrationError(
            "pretrade child receipt is not exactly reproducible"
        )
    return rebuilt


def child_order_intents(value: Mapping[str, Any]) -> list[dict[str, Any]]:
    receipt = validate_pretrade_child_receipt(value)
    return [
        {
            "intent_id": f"{receipt['strategy_id']}:{fill['id']}",
            "strategy_id": receipt["strategy_id"],
            "code": fill["code"],
            "side": fill["side"],
            "quantity": fill["quantity"],
            "order_type": "market",
            "limit_price": None,
            "reference_price": _decimal_text(
                fill["reference_price"], "reference_price", positive=True
            ),
            "source_receipt_sha256": receipt["receipt_sha256"],
        }
        for fill in receipt["planned_fills"]
    ]


def _prepared_assessment(
    value: Mapping[str, Any], *, schema: str
) -> dict[str, Any]:
    assessment = dict(value)
    hash_field = "assessment_sha256"
    if assessment.get("schema") != schema or assessment.get("real_orders") is not False:
        raise ExecutionOrchestrationError(
            "prepared portfolio assessment identity is invalid"
        )
    if assessment.get("decision") not in {
        "PASS",
        "REDUCE_ONLY",
        "MONITOR_ONLY",
    }:
        raise ExecutionOrchestrationError(
            "prepared portfolio assessment does not authorize commit"
        )
    expected = _hash(assessment.get(hash_field), hash_field)
    identity = {key: item for key, item in assessment.items() if key != hash_field}
    if sha256_digest(identity) != expected:
        raise ExecutionOrchestrationError(
            "prepared portfolio assessment hash mismatch"
        )
    proposed = assessment.get("proposed")
    if not isinstance(proposed, Mapping) or not isinstance(
        proposed.get("breaches"), list
    ):
        raise ExecutionOrchestrationError(
            "prepared portfolio assessment lacks breach evidence"
        )
    return assessment


def build_pretrade_execution_batch(
    child_receipts: Sequence[Mapping[str, Any]],
    *,
    parent_order_allocation_plan: Mapping[str, Any],
    batch_request_sha256: str,
    platform_preflight_sha256: str,
    trade_date: str | date,
    recorded_at: str | datetime,
    prepared_portfolio_assessment: Mapping[str, Any],
    prepared_stress_assessment: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind every child preview and the exact parent net order before commit."""
    request_sha = _hash(batch_request_sha256, "batch_request_sha256")
    preflight_sha = _hash(platform_preflight_sha256, "platform_preflight_sha256")
    day = _day(trade_date, "trade_date")
    moment = _timestamp(recorded_at, "recorded_at")
    children = sorted(
        [validate_pretrade_child_receipt(dict(item)) for item in child_receipts],
        key=lambda item: str(item["strategy_id"]),
    )
    strategy_ids = [str(item["strategy_id"]) for item in children]
    if len(strategy_ids) != len(set(strategy_ids)):
        raise ExecutionOrchestrationError(
            "pretrade batch child strategy ids must be unique"
        )
    for child in children:
        if (
            child["trade_date"] != day
            or child["recorded_at"] != moment
            or child["platform_preflight_sha256"] != preflight_sha
        ):
            raise ExecutionOrchestrationError(
                "pretrade child receipt is outside the batch identity"
            )
    intents = [intent for child in children for intent in child_order_intents(child)]
    try:
        expected_plan = build_parent_order_plan(
            intents,
            batch_request_sha256=request_sha,
            trade_date=day,
            account_fingerprint="paper-parent-account",
            mode="PAPER",
        )
        supplied_plan = validate_parent_order_plan(parent_order_allocation_plan)
    except OrderAllocationError as exc:
        raise ExecutionOrchestrationError(str(exc)) from exc
    if supplied_plan != expected_plan:
        raise ExecutionOrchestrationError(
            "parent allocation plan differs from prepared child executions"
        )
    portfolio_assessment = _prepared_assessment(
        prepared_portfolio_assessment,
        schema=PLATFORM_PORTFOLIO_ASSESSMENT_SCHEMA,
    )
    stress_assessment = _prepared_assessment(
        prepared_stress_assessment,
        schema=PORTFOLIO_STRESS_ASSESSMENT_SCHEMA,
    )
    assessment_decisions = {
        portfolio_assessment["decision"],
        stress_assessment["decision"],
    }
    if "MONITOR_ONLY" in assessment_decisions:
        if children or supplied_plan["child_intents"] or supplied_plan["parent_orders"]:
            raise ExecutionOrchestrationError(
                "MONITOR_ONLY pretrade batches must be observation-only"
            )
        effective_decision = "MONITOR_ONLY"
    elif "REDUCE_ONLY" in assessment_decisions:
        effective_decision = "REDUCE_ONLY"
    else:
        effective_decision = "PASS"
    blockers = sorted(
        set(
            list(dict(portfolio_assessment["proposed"])["breaches"])
            + list(dict(stress_assessment["proposed"])["breaches"])
        )
    )
    identity = {
        "schema": PRETRADE_BATCH_SCHEMA,
        "trade_date": day,
        "recorded_at": moment,
        "batch_request_sha256": request_sha,
        "platform_preflight_sha256": preflight_sha,
        "child_receipts": children,
        "parent_order_allocation_plan": supplied_plan,
        "prepared_portfolio_assessment": portfolio_assessment,
        "prepared_stress_assessment": stress_assessment,
        "effective_decision": effective_decision,
        "blockers": blockers,
        "status": "PREPARED",
        "real_orders": False,
    }
    return {**identity, "pretrade_batch_sha256": sha256_digest(identity)}


def validate_pretrade_execution_batch(value: Mapping[str, Any]) -> dict[str, Any]:
    batch = dict(value)
    required = {
        "schema",
        "trade_date",
        "recorded_at",
        "batch_request_sha256",
        "platform_preflight_sha256",
        "child_receipts",
        "parent_order_allocation_plan",
        "prepared_portfolio_assessment",
        "prepared_stress_assessment",
        "effective_decision",
        "blockers",
        "status",
        "real_orders",
        "pretrade_batch_sha256",
    }
    if set(batch) != required or batch.get("schema") != PRETRADE_BATCH_SCHEMA:
        raise ExecutionOrchestrationError(
            "pretrade execution batch fields do not match contract"
        )
    if batch.get("status") != "PREPARED" or batch.get("real_orders") is not False:
        raise ExecutionOrchestrationError("pretrade batch is not a PAPER preparation")
    rebuilt = build_pretrade_execution_batch(
        list(batch["child_receipts"]),
        parent_order_allocation_plan=dict(batch["parent_order_allocation_plan"]),
        batch_request_sha256=batch["batch_request_sha256"],
        platform_preflight_sha256=batch["platform_preflight_sha256"],
        trade_date=batch["trade_date"],
        recorded_at=batch["recorded_at"],
        prepared_portfolio_assessment=dict(
            batch["prepared_portfolio_assessment"]
        ),
        prepared_stress_assessment=dict(
            batch["prepared_stress_assessment"]
        ),
    )
    if rebuilt != batch:
        raise ExecutionOrchestrationError(
            "pretrade execution batch is not exactly reproducible"
        )
    return rebuilt
