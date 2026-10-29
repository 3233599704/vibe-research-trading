"""Content-addressed broker/parent/child end-of-day reconciliation evidence."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import re
from typing import Any, Iterator, Mapping, Sequence

from .broker_account_control import (
    BrokerAccountControlError,
    BrokerAccountReservationBook,
    validate_broker_account_snapshot,
)
from .broker_order_lifecycle import (
    TERMINAL_STATUSES,
    BrokerOrderJournal,
    BrokerOrderJournalError,
)
from .execution import SimulationLedger
from .provenance import sha256_digest


BROKER_DAILY_RECONCILIATION_SCHEMA = (
    "quant-core/broker-daily-reconciliation/v1"
)
BROKER_DAILY_RECONCILIATION_RECORD_SCHEMA = (
    "quant-core/broker-daily-reconciliation-record/v1"
)
BROKER_DAILY_RECONCILIATION_HEAD_SCHEMA = (
    "quant-core/broker-daily-reconciliation-head/v1"
)
BROKER_DAILY_RECONCILIATION_INSPECTION_SCHEMA = (
    "quant-core/broker-daily-reconciliation-inspection/v1"
)
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BrokerDailyReconciliationError(RuntimeError):
    """Raised when source evidence is malformed, corrupt, or misbound."""


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not ID_RE.fullmatch(text):
        raise BrokerDailyReconciliationError(f"{label} is invalid")
    return text


def _decimal(value: Any, label: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise BrokerDailyReconciliationError(
            f"{label} must be a finite decimal"
        ) from exc
    if not parsed.is_finite():
        raise BrokerDailyReconciliationError(f"{label} is invalid")
    return parsed


def _decimal_text(value: Decimal) -> str:
    return format(value.normalize(), "f")


def _hash(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not SHA256_RE.fullmatch(text):
        raise BrokerDailyReconciliationError(f"{label} must be a sha256 digest")
    return text


def _timestamp(value: Any, label: str) -> str:
    try:
        parsed = (
            value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        )
    except ValueError as exc:
        raise BrokerDailyReconciliationError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise BrokerDailyReconciliationError(f"{label} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    )
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _immutable_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    )
    if path.exists():
        if path.read_text(encoding="utf-8") != encoded:
            raise BrokerDailyReconciliationError(
                f"immutable daily reconciliation conflict: {path.name}"
            )
        return
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _signed_integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise BrokerDailyReconciliationError(f"{label} must be an exact integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise BrokerDailyReconciliationError(
            f"{label} must be an exact integer"
        ) from exc
    if str(parsed) != str(value).strip():
        raise BrokerDailyReconciliationError(f"{label} must be an exact integer")
    return parsed


def _normalize_cash_adjustments(
    values: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_value in values:
        raw = dict(raw_value)
        if set(raw) != {
            "adjustment_id",
            "cash_balance_delta",
            "cash_available_delta",
            "source_reference",
        }:
            raise BrokerDailyReconciliationError(
                "cash adjustment fields are invalid"
            )
        adjustment_id = _identifier(raw["adjustment_id"], "adjustment_id")
        if adjustment_id in seen:
            raise BrokerDailyReconciliationError("cash adjustment is duplicated")
        seen.add(adjustment_id)
        normalized.append(
            {
                "adjustment_id": adjustment_id,
                "cash_balance_delta": _decimal_text(
                    _decimal(raw["cash_balance_delta"], "cash_balance_delta")
                ),
                "cash_available_delta": _decimal_text(
                    _decimal(raw["cash_available_delta"], "cash_available_delta")
                ),
                "source_reference": _identifier(
                    raw["source_reference"], "source_reference"
                ),
            }
        )
    return sorted(normalized, key=lambda item: item["adjustment_id"])


def _normalize_position_adjustments(
    values: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_value in values:
        raw = dict(raw_value)
        if set(raw) != {
            "adjustment_id",
            "code",
            "total_quantity_delta",
            "sellable_quantity_delta",
            "frozen_quantity_delta",
            "source_reference",
        }:
            raise BrokerDailyReconciliationError(
                "position adjustment fields are invalid"
            )
        adjustment_id = _identifier(raw["adjustment_id"], "adjustment_id")
        if adjustment_id in seen:
            raise BrokerDailyReconciliationError(
                "position adjustment is duplicated"
            )
        seen.add(adjustment_id)
        normalized.append(
            {
                "adjustment_id": adjustment_id,
                "code": _identifier(raw["code"], "position code"),
                "total_quantity_delta": _signed_integer(
                    raw["total_quantity_delta"], "total_quantity_delta"
                ),
                "sellable_quantity_delta": _signed_integer(
                    raw["sellable_quantity_delta"], "sellable_quantity_delta"
                ),
                "frozen_quantity_delta": _signed_integer(
                    raw["frozen_quantity_delta"], "frozen_quantity_delta"
                ),
                "source_reference": _identifier(
                    raw["source_reference"], "source_reference"
                ),
            }
        )
    return sorted(normalized, key=lambda item: item["adjustment_id"])


def _position_state(snapshot: dict[str, Any]) -> dict[str, dict[str, int]]:
    return {
        str(item["code"]): {
            "total_quantity": int(item["total_quantity"]),
            "sellable_quantity": int(item["sellable_quantity"]),
            "frozen_quantity": int(item["frozen_quantity"]),
        }
        for item in snapshot["positions"]
    }


def _economic_group() -> dict[str, Any]:
    return {"quantity": 0, "notional": Decimal("0"), "fee_fen": 0}


def _serialize_groups(
    groups: Mapping[tuple[str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "code": code,
            "side": side,
            "quantity": int(value["quantity"]),
            "notional": _decimal_text(Decimal(value["notional"])),
            "fee_fen": int(value["fee_fen"]),
        }
        for (code, side), value in sorted(groups.items())
        if int(value["quantity"]) or int(value["fee_fen"])
    ]


def build_broker_daily_reconciliation(
    *,
    opening_snapshot: Mapping[str, Any],
    closing_snapshot: Mapping[str, Any],
    reservation_book: BrokerAccountReservationBook,
    journal: BrokerOrderJournal,
    child_ledger_snapshots: Mapping[str, Mapping[str, Any]],
    cash_adjustments: Sequence[Mapping[str, Any]] = (),
    position_adjustments: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Reconcile terminal parent economics to broker and child-ledger evidence."""

    try:
        opening = validate_broker_account_snapshot(dict(opening_snapshot))
        closing = validate_broker_account_snapshot(dict(closing_snapshot))
    except BrokerAccountControlError as exc:
        raise BrokerDailyReconciliationError(
            f"broker account snapshot is invalid: {exc}"
        ) from exc
    if (
        opening != reservation_book.account_snapshot
        or reservation_book.journal is not journal
        or opening["adapter_id"] != closing["adapter_id"]
        or opening["account_fingerprint"] != closing["account_fingerprint"]
        or opening["trade_date"] != closing["trade_date"]
        or opening["currency"] != closing["currency"]
    ):
        raise BrokerDailyReconciliationError(
            "daily reconciliation sources are not bound to one account day"
        )
    normalized_cash_adjustments = _normalize_cash_adjustments(cash_adjustments)
    normalized_position_adjustments = _normalize_position_adjustments(
        position_adjustments
    )
    inspection = reservation_book.inspect()
    if inspection["status"] == "DEGRADED":
        raise BrokerDailyReconciliationError(
            "account reservation evidence is degraded"
        )

    latest = reservation_book.latest_events()
    open_operations = sorted(
        event["operation_key"]
        for event in latest
        if event["status"] not in TERMINAL_STATUSES
    )
    parent_groups: dict[tuple[str, str], dict[str, Any]] = {}
    expected_cash_balance = Decimal(opening["cash_balance"])
    expected_cash_available = Decimal(opening["cash_available"])
    expected_positions = _position_state(opening)
    operation_settlements: dict[str, dict[str, dict[str, Any]]] = {}
    for event in latest:
        operation_key = event["operation_key"]
        lifecycle = journal.latest(operation_key)
        if (
            lifecycle is None
            or event["source_lifecycle_event_sha256"]
            != lifecycle["event_sha256"]
        ):
            raise BrokerDailyReconciliationError(
                "parent lifecycle and account reservation are not synchronized"
            )
        filled = int(event["cumulative_filled_quantity"])
        code = str(event["code"])
        side = str(event["side"])
        group = parent_groups.setdefault((code, side), _economic_group())
        group["quantity"] += filled
        if filled:
            group["notional"] += Decimal(str(event["average_price"])) * filled
        group["fee_fen"] += int(event["cumulative_fee_fen"])
        cash_delta = Decimal(event["realized_cash_delta"])
        expected_cash_balance += cash_delta
        expected_cash_available += cash_delta
        position = expected_positions.setdefault(
            code,
            {
                "total_quantity": 0,
                "sellable_quantity": 0,
                "frozen_quantity": 0,
            },
        )
        position["total_quantity"] += filled if side == "buy" else -filled
        if side == "sell":
            position["sellable_quantity"] -= filled
        try:
            histories = journal.fill_settlement_history(operation_key)
        except BrokerOrderJournalError as exc:
            raise BrokerDailyReconciliationError(
                f"parent fill settlement evidence is invalid: {exc}"
            ) from exc
        operation_settlements[operation_key] = {
            item["settlement_sha256"]: item for item in histories
        }

    for adjustment in normalized_cash_adjustments:
        expected_cash_balance += Decimal(adjustment["cash_balance_delta"])
        expected_cash_available += Decimal(adjustment["cash_available_delta"])
    for adjustment in normalized_position_adjustments:
        position = expected_positions.setdefault(
            adjustment["code"],
            {
                "total_quantity": 0,
                "sellable_quantity": 0,
                "frozen_quantity": 0,
            },
        )
        for field in (
            "total_quantity",
            "sellable_quantity",
            "frozen_quantity",
        ):
            position[field] += int(adjustment[f"{field}_delta"])
    if any(
        value[field] < 0
        for value in expected_positions.values()
        for field in (
            "total_quantity",
            "sellable_quantity",
            "frozen_quantity",
        )
    ):
        raise BrokerDailyReconciliationError(
            "expected closing position became negative"
        )
    expected_positions = {
        code: value
        for code, value in sorted(expected_positions.items())
        if any(value.values())
    }

    child_groups: dict[tuple[str, str], dict[str, Any]] = {}
    child_sources: list[dict[str, str]] = []
    seen_fill_ids: set[str] = set()
    known_settlements = {
        settlement_sha: (operation_key, settlement)
        for operation_key, settlements in operation_settlements.items()
        for settlement_sha, settlement in settlements.items()
    }
    for strategy_id, raw_snapshot in sorted(child_ledger_snapshots.items()):
        try:
            ledger = SimulationLedger.from_snapshot(dict(raw_snapshot))
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            raise BrokerDailyReconciliationError(
                f"child ledger snapshot is invalid: {strategy_id}: {exc}"
            ) from exc
        for fill in ledger.fills:
            if not fill.get("external_broker_allocation") or fill.get(
                "date"
            ) != opening["trade_date"]:
                continue
            fill_id = _identifier(fill.get("id"), "child fill id")
            if fill_id in seen_fill_ids:
                raise BrokerDailyReconciliationError(
                    "child broker fill id is duplicated across ledgers"
                )
            seen_fill_ids.add(fill_id)
            settlement_sha = str(fill.get("source_settlement_sha256") or "")
            source = known_settlements.get(settlement_sha)
            if source is None:
                raise BrokerDailyReconciliationError(
                    "child broker fill references an unknown parent settlement"
                )
            code = str(fill.get("code") or "")
            side = str(fill.get("side") or "")
            quantity = int(fill.get("quantity") or 0)
            fee_fen = int(fill.get("fee_fen") or 0)
            if quantity < 0 or fee_fen < 0:
                raise BrokerDailyReconciliationError(
                    "child broker fill economics are invalid"
                )
            group = child_groups.setdefault((code, side), _economic_group())
            group["quantity"] += quantity
            group["notional"] += _decimal(fill.get("notional"), "child notional")
            group["fee_fen"] += fee_fen
            child_sources.append(
                {
                    "strategy_id": str(strategy_id),
                    "snapshot_sha256": str(raw_snapshot["snapshot_sha256"]),
                    "fill_id": fill_id,
                    "settlement_sha256": settlement_sha,
                    "operation_key": source[0],
                }
            )

    expected_parent = _serialize_groups(parent_groups)
    actual_child = _serialize_groups(child_groups)
    actual_positions = _position_state(closing)
    mismatches: list[str] = []
    if Decimal(closing["cash_balance"]) != expected_cash_balance:
        mismatches.append("broker_cash_balance")
    if Decimal(closing["cash_available"]) != expected_cash_available:
        mismatches.append("broker_cash_available")
    if actual_positions != expected_positions:
        mismatches.append("broker_positions")
    if actual_child != expected_parent:
        mismatches.append("child_parent_economics")
    if mismatches:
        status = "FAIL"
    elif open_operations:
        status = "PENDING_OPEN_ORDERS"
    else:
        status = "PASS"
    identity = {
        "schema": BROKER_DAILY_RECONCILIATION_SCHEMA,
        "status": status,
        "trade_date": opening["trade_date"],
        "adapter_id": opening["adapter_id"],
        "account_fingerprint": opening["account_fingerprint"],
        "opening_snapshot_sha256": opening["snapshot_sha256"],
        "closing_snapshot_sha256": closing["snapshot_sha256"],
        "account_control_policy_sha256": reservation_book.policy["policy_sha256"],
        "open_operation_keys": open_operations,
        "cash_adjustments": normalized_cash_adjustments,
        "position_adjustments": normalized_position_adjustments,
        "expected_closing_cash_balance": _decimal_text(expected_cash_balance),
        "actual_closing_cash_balance": closing["cash_balance"],
        "expected_closing_cash_available": _decimal_text(expected_cash_available),
        "actual_closing_cash_available": closing["cash_available"],
        "expected_closing_positions": expected_positions,
        "actual_closing_positions": actual_positions,
        "parent_economics": expected_parent,
        "child_economics": actual_child,
        "child_sources": sorted(
            child_sources,
            key=lambda item: (item["strategy_id"], item["fill_id"]),
        ),
        "mismatches": mismatches,
    }
    return {
        **identity,
        "reconciliation_sha256": sha256_digest(identity),
    }


def _validate_position_map(value: Any, label: str) -> dict[str, dict[str, int]]:
    if not isinstance(value, dict):
        raise BrokerDailyReconciliationError(f"{label} must be an object")
    normalized: dict[str, dict[str, int]] = {}
    for raw_code, raw_position in value.items():
        code = _identifier(raw_code, "position code")
        if not isinstance(raw_position, dict) or set(raw_position) != {
            "total_quantity",
            "sellable_quantity",
            "frozen_quantity",
        }:
            raise BrokerDailyReconciliationError(f"{label} fields are invalid")
        position = {
            field: _signed_integer(raw_position[field], field)
            for field in (
                "total_quantity",
                "sellable_quantity",
                "frozen_quantity",
            )
        }
        if (
            any(quantity < 0 for quantity in position.values())
            or position["sellable_quantity"] + position["frozen_quantity"]
            > position["total_quantity"]
            or not any(position.values())
        ):
            raise BrokerDailyReconciliationError(f"{label} is incoherent")
        normalized[code] = position
    return dict(sorted(normalized.items()))


def _validate_economic_groups(value: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise BrokerDailyReconciliationError(f"{label} must be an array")
    normalized: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != {
            "code",
            "side",
            "quantity",
            "notional",
            "fee_fen",
        }:
            raise BrokerDailyReconciliationError(f"{label} fields are invalid")
        code = _identifier(raw["code"], "economic code")
        side = str(raw["side"])
        if side not in {"buy", "sell"}:
            raise BrokerDailyReconciliationError(f"{label} side is invalid")
        key = (code, side)
        if key in seen:
            raise BrokerDailyReconciliationError(f"{label} group is duplicated")
        seen.add(key)
        quantity = _signed_integer(raw["quantity"], "quantity")
        fee_fen = _signed_integer(raw["fee_fen"], "fee_fen")
        notional = _decimal(raw["notional"], "notional")
        if quantity <= 0 or fee_fen < 0 or notional < 0:
            raise BrokerDailyReconciliationError(f"{label} economics are invalid")
        normalized.append(
            {
                "code": code,
                "side": side,
                "quantity": quantity,
                "notional": _decimal_text(notional),
                "fee_fen": fee_fen,
            }
        )
    normalized.sort(key=lambda item: (item["code"], item["side"]))
    return normalized


def validate_broker_daily_reconciliation(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate the canonical shape, semantics and content address of a receipt."""

    if not isinstance(value, Mapping):
        raise BrokerDailyReconciliationError(
            "daily reconciliation must be an object"
        )
    receipt = dict(value)
    required = {
        "schema",
        "status",
        "trade_date",
        "adapter_id",
        "account_fingerprint",
        "opening_snapshot_sha256",
        "closing_snapshot_sha256",
        "account_control_policy_sha256",
        "open_operation_keys",
        "cash_adjustments",
        "position_adjustments",
        "expected_closing_cash_balance",
        "actual_closing_cash_balance",
        "expected_closing_cash_available",
        "actual_closing_cash_available",
        "expected_closing_positions",
        "actual_closing_positions",
        "parent_economics",
        "child_economics",
        "child_sources",
        "mismatches",
        "reconciliation_sha256",
    }
    if set(receipt) != required or receipt.get(
        "schema"
    ) != BROKER_DAILY_RECONCILIATION_SCHEMA:
        raise BrokerDailyReconciliationError(
            "daily reconciliation fields are invalid"
        )
    try:
        trade_date = date.fromisoformat(str(receipt["trade_date"])).isoformat()
    except ValueError as exc:
        raise BrokerDailyReconciliationError(
            "daily reconciliation trade_date is invalid"
        ) from exc
    status = str(receipt["status"])
    if status not in {"PASS", "FAIL", "PENDING_OPEN_ORDERS"}:
        raise BrokerDailyReconciliationError(
            "daily reconciliation status is invalid"
        )
    open_operations = [
        _identifier(item, "open operation key")
        for item in list(receipt["open_operation_keys"])
    ]
    if open_operations != sorted(set(open_operations)):
        raise BrokerDailyReconciliationError(
            "open operation keys are duplicated or unsorted"
        )
    mismatches = [str(item) for item in list(receipt["mismatches"])]
    allowed_mismatches = {
        "broker_cash_balance",
        "broker_cash_available",
        "broker_positions",
        "child_parent_economics",
    }
    if (
        mismatches != sorted(set(mismatches), key=mismatches.index)
        or not set(mismatches) <= allowed_mismatches
    ):
        raise BrokerDailyReconciliationError(
            "daily reconciliation mismatches are invalid"
        )
    if status == "PASS" and (open_operations or mismatches):
        raise BrokerDailyReconciliationError("PASS reconciliation is not clean")
    if status == "FAIL" and not mismatches:
        raise BrokerDailyReconciliationError("FAIL reconciliation has no mismatch")
    if status == "PENDING_OPEN_ORDERS" and (
        not open_operations or mismatches
    ):
        raise BrokerDailyReconciliationError(
            "PENDING reconciliation semantics are invalid"
        )
    normalized = {
        **receipt,
        "trade_date": trade_date,
        "adapter_id": _identifier(receipt["adapter_id"], "adapter_id"),
        "account_fingerprint": str(receipt["account_fingerprint"]).strip(),
        "opening_snapshot_sha256": _hash(
            receipt["opening_snapshot_sha256"], "opening_snapshot_sha256"
        ),
        "closing_snapshot_sha256": _hash(
            receipt["closing_snapshot_sha256"], "closing_snapshot_sha256"
        ),
        "account_control_policy_sha256": _hash(
            receipt["account_control_policy_sha256"],
            "account_control_policy_sha256",
        ),
        "open_operation_keys": open_operations,
        "cash_adjustments": _normalize_cash_adjustments(
            list(receipt["cash_adjustments"])
        ),
        "position_adjustments": _normalize_position_adjustments(
            list(receipt["position_adjustments"])
        ),
        "expected_closing_cash_balance": _decimal_text(
            _decimal(
                receipt["expected_closing_cash_balance"],
                "expected_closing_cash_balance",
            )
        ),
        "actual_closing_cash_balance": _decimal_text(
            _decimal(
                receipt["actual_closing_cash_balance"],
                "actual_closing_cash_balance",
            )
        ),
        "expected_closing_cash_available": _decimal_text(
            _decimal(
                receipt["expected_closing_cash_available"],
                "expected_closing_cash_available",
            )
        ),
        "actual_closing_cash_available": _decimal_text(
            _decimal(
                receipt["actual_closing_cash_available"],
                "actual_closing_cash_available",
            )
        ),
        "expected_closing_positions": _validate_position_map(
            receipt["expected_closing_positions"],
            "expected_closing_positions",
        ),
        "actual_closing_positions": _validate_position_map(
            receipt["actual_closing_positions"],
            "actual_closing_positions",
        ),
        "parent_economics": _validate_economic_groups(
            receipt["parent_economics"], "parent_economics"
        ),
        "child_economics": _validate_economic_groups(
            receipt["child_economics"], "child_economics"
        ),
        "mismatches": mismatches,
    }
    account = normalized["account_fingerprint"]
    if not account or len(account) > 160:
        raise BrokerDailyReconciliationError(
            "daily reconciliation account_fingerprint is invalid"
        )
    child_sources: list[dict[str, str]] = []
    seen_fill_ids: set[str] = set()
    for raw in list(receipt["child_sources"]):
        if not isinstance(raw, dict) or set(raw) != {
            "strategy_id",
            "snapshot_sha256",
            "fill_id",
            "settlement_sha256",
            "operation_key",
        }:
            raise BrokerDailyReconciliationError(
                "daily reconciliation child source fields are invalid"
            )
        fill_id = _identifier(raw["fill_id"], "fill_id")
        if fill_id in seen_fill_ids:
            raise BrokerDailyReconciliationError("child source fill is duplicated")
        seen_fill_ids.add(fill_id)
        child_sources.append(
            {
                "strategy_id": _identifier(raw["strategy_id"], "strategy_id"),
                "snapshot_sha256": _hash(
                    raw["snapshot_sha256"], "snapshot_sha256"
                ),
                "fill_id": fill_id,
                "settlement_sha256": _hash(
                    raw["settlement_sha256"], "settlement_sha256"
                ),
                "operation_key": _identifier(
                    raw["operation_key"], "operation_key"
                ),
            }
        )
    child_sources.sort(key=lambda item: (item["strategy_id"], item["fill_id"]))
    normalized["child_sources"] = child_sources
    supplied_digest = _hash(
        receipt["reconciliation_sha256"], "reconciliation_sha256"
    )
    normalized["reconciliation_sha256"] = supplied_digest
    identity = {
        key: value
        for key, value in normalized.items()
        if key != "reconciliation_sha256"
    }
    if normalized != receipt or sha256_digest(identity) != supplied_digest:
        raise BrokerDailyReconciliationError(
            "daily reconciliation hash or canonical form mismatch"
        )
    return normalized


def verify_broker_daily_reconciliation(
    value: Mapping[str, Any],
    **source_arguments: Any,
) -> dict[str, Any]:
    """Rebuild a receipt from source evidence and require byte-level semantics."""

    receipt = validate_broker_daily_reconciliation(value)
    rebuilt = build_broker_daily_reconciliation(**source_arguments)
    if receipt != rebuilt:
        raise BrokerDailyReconciliationError(
            "daily reconciliation differs from source evidence"
        )
    return receipt


class BrokerDailyReconciliationStore:
    """Append-only authority for restart-verifiable daily reconciliation history."""

    def __init__(
        self,
        root: str | Path,
        *,
        adapter_id: str,
        account_fingerprint: str,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.adapter_id = _identifier(adapter_id, "adapter_id")
        self.account_fingerprint = str(account_fingerprint).strip()
        if not self.account_fingerprint or len(self.account_fingerprint) > 160:
            raise BrokerDailyReconciliationError(
                "account_fingerprint is invalid"
            )

    @property
    def head_path(self) -> Path:
        return self.root / "head.json"

    def _record_path(self, sequence: int, digest: str) -> Path:
        return self.root / "records" / f"{sequence:012d}-{digest}.json"

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True)
        lock_path = self.root / ".lock"
        handle = lock_path.open("a+b")
        if lock_path.stat().st_size == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise BrokerDailyReconciliationError(
                "daily reconciliation store is locked by another process"
            ) from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:  # pragma: no cover
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def _load_chain(self) -> list[dict[str, Any]]:
        paths = sorted((self.root / "records").glob("*.json"))
        if not self.head_path.exists():
            if paths:
                raise BrokerDailyReconciliationError(
                    "daily reconciliation head is missing while records exist"
                )
            return []
        try:
            head = dict(_read_json(self.head_path))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrokerDailyReconciliationError(
                f"daily reconciliation head is unreadable: {exc}"
            ) from exc
        if set(head) != {"schema", "sequence", "record_sha256"} or head.get(
            "schema"
        ) != BROKER_DAILY_RECONCILIATION_HEAD_SCHEMA:
            raise BrokerDailyReconciliationError(
                "daily reconciliation head fields are invalid"
            )
        records: list[dict[str, Any]] = []
        previous_sha: str | None = None
        previous_date: str | None = None
        passed_dates: set[str] = set()
        for expected_sequence, path in enumerate(paths, start=1):
            try:
                record = dict(_read_json(path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerDailyReconciliationError(
                    f"daily reconciliation record is unreadable: {path.name}: {exc}"
                ) from exc
            required = {
                "schema",
                "sequence",
                "previous_record_sha256",
                "recorded_at",
                "adapter_id",
                "account_fingerprint",
                "trade_date",
                "reconciliation",
                "record_sha256",
            }
            if set(record) != required or record.get(
                "schema"
            ) != BROKER_DAILY_RECONCILIATION_RECORD_SCHEMA:
                raise BrokerDailyReconciliationError(
                    "daily reconciliation record fields are invalid"
                )
            identity = {
                key: value for key, value in record.items() if key != "record_sha256"
            }
            digest = _hash(record["record_sha256"], "record_sha256")
            receipt = validate_broker_daily_reconciliation(
                record["reconciliation"]
            )
            if (
                sha256_digest(identity) != digest
                or path.name != self._record_path(expected_sequence, digest).name
                or record["sequence"] != expected_sequence
                or record["previous_record_sha256"] != previous_sha
                or record["adapter_id"] != self.adapter_id
                or record["account_fingerprint"] != self.account_fingerprint
                or record["trade_date"] != receipt["trade_date"]
                or receipt["adapter_id"] != self.adapter_id
                or receipt["account_fingerprint"] != self.account_fingerprint
                or _timestamp(record["recorded_at"], "recorded_at")
                != record["recorded_at"]
            ):
                raise BrokerDailyReconciliationError(
                    "daily reconciliation record chain identity broke"
                )
            if previous_date is not None and record["trade_date"] < previous_date:
                raise BrokerDailyReconciliationError(
                    "daily reconciliation trade date moved backwards"
                )
            if record["trade_date"] in passed_dates:
                raise BrokerDailyReconciliationError(
                    "a passed daily reconciliation was reopened"
                )
            if receipt["status"] == "PASS":
                passed_dates.add(record["trade_date"])
            records.append(record)
            previous_sha = digest
            previous_date = record["trade_date"]
        expected_head = {
            "schema": BROKER_DAILY_RECONCILIATION_HEAD_SCHEMA,
            "sequence": len(records),
            "record_sha256": records[-1]["record_sha256"],
        }
        if not records or head != expected_head:
            raise BrokerDailyReconciliationError(
                "daily reconciliation head does not match chain tip"
            )
        return records

    def record(
        self,
        reconciliation: Mapping[str, Any],
        *,
        recorded_at: datetime,
        source_arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        receipt = verify_broker_daily_reconciliation(
            reconciliation, **dict(source_arguments)
        )
        if (
            receipt["adapter_id"] != self.adapter_id
            or receipt["account_fingerprint"] != self.account_fingerprint
        ):
            raise BrokerDailyReconciliationError(
                "daily reconciliation store identity mismatch"
            )
        recorded_text = _timestamp(recorded_at, "recorded_at")
        with self._lock():
            records = self._load_chain()
            same_receipt = [
                item
                for item in records
                if item["reconciliation"]["reconciliation_sha256"]
                == receipt["reconciliation_sha256"]
            ]
            same_day = [
                item for item in records if item["trade_date"] == receipt["trade_date"]
            ]
            if (
                same_day
                and same_day[-1]["reconciliation"]["status"] == "PASS"
                and same_day[-1]["reconciliation"]["reconciliation_sha256"]
                != receipt["reconciliation_sha256"]
            ):
                raise BrokerDailyReconciliationError(
                    "a passed daily reconciliation cannot be replaced"
                )
            if same_receipt:
                return {**same_receipt[0], "idempotent": True}
            if records and receipt["trade_date"] < records[-1]["trade_date"]:
                raise BrokerDailyReconciliationError(
                    "daily reconciliation trade date moved backwards"
                )
            identity = {
                "schema": BROKER_DAILY_RECONCILIATION_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": (
                    records[-1]["record_sha256"] if records else None
                ),
                "recorded_at": recorded_text,
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "trade_date": receipt["trade_date"],
                "reconciliation": receipt,
            }
            digest = sha256_digest(identity)
            record = {**identity, "record_sha256": digest}
            _immutable_json(self._record_path(identity["sequence"], digest), record)
            _atomic_json(
                self.head_path,
                {
                    "schema": BROKER_DAILY_RECONCILIATION_HEAD_SCHEMA,
                    "sequence": identity["sequence"],
                    "record_sha256": digest,
                },
            )
            return {**record, "idempotent": False}

    def latest_for_trade_date(self, trade_date: str) -> dict[str, Any] | None:
        """Return the latest validated reconciliation receipt for one day."""

        try:
            day = date.fromisoformat(str(trade_date)).isoformat()
        except ValueError as exc:
            raise BrokerDailyReconciliationError(
                "daily reconciliation trade_date is invalid"
            ) from exc
        records = self._load_chain()
        matches = [
            record["reconciliation"]
            for record in records
            if record["trade_date"] == day
        ]
        return dict(matches[-1]) if matches else None

    def inspect(self) -> dict[str, Any]:
        try:
            records = self._load_chain()
            latest_by_date: dict[str, dict[str, Any]] = {}
            for record in records:
                latest_by_date[record["trade_date"]] = record
            latest = records[-1] if records else None
            latest_status = (
                latest["reconciliation"]["status"] if latest is not None else None
            )
            return {
                "schema": BROKER_DAILY_RECONCILIATION_INSPECTION_SCHEMA,
                "status": (
                    "EMPTY"
                    if not records
                    else "READY"
                    if latest_status == "PASS"
                    else "ACTION_REQUIRED"
                ),
                "read_only_recommended": bool(records)
                and latest_status != "PASS",
                "error": None,
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "record_count": len(records),
                "trade_dates": [
                    {
                        "trade_date": trade_date,
                        "status": record["reconciliation"]["status"],
                        "reconciliation_sha256": record["reconciliation"][
                            "reconciliation_sha256"
                        ],
                        "record_sha256": record["record_sha256"],
                    }
                    for trade_date, record in sorted(latest_by_date.items())
                ],
                "latest_trade_date": latest["trade_date"] if latest else None,
                "latest_reconciliation_status": latest_status,
                "latest_record_sha256": (
                    latest["record_sha256"] if latest else None
                ),
            }
        except (
            BrokerDailyReconciliationError,
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            return {
                "schema": BROKER_DAILY_RECONCILIATION_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "read_only_recommended": True,
                "error": str(exc),
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "record_count": 0,
                "trade_dates": [],
                "latest_trade_date": None,
                "latest_reconciliation_status": None,
                "latest_record_sha256": None,
            }
