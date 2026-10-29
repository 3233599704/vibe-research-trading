"""Deterministic parent-account order netting and broker-fill allocation.

The planner is an accounting primitive. It never contacts a broker and never
mutates child ledgers. PAPER plans describe what a shared parent account would
have submitted after preserving every child intent and internal cross.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal, InvalidOperation
import re
from typing import Any, Mapping, Sequence

from .provenance import sha256_digest


PARENT_ORDER_PLAN_SCHEMA = "quant-core/parent-order-allocation-plan/v1"
PARENT_FILL_ALLOCATION_SCHEMA = "quant-core/parent-fill-allocation/v2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
SYMBOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


class OrderAllocationError(ValueError):
    """Raised when parent-account allocation evidence is unsafe or incoherent."""


def _decimal(value: Any, label: str, *, positive: bool = False) -> Decimal:
    try:
        number = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise OrderAllocationError(f"{label} must be a finite decimal") from exc
    if not number.is_finite() or (positive and number <= 0):
        qualifier = "positive" if positive else "finite"
        raise OrderAllocationError(f"{label} must be {qualifier}")
    return number


def _quantity(value: Any, label: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not (
        isinstance(value, int)
        or (isinstance(value, str) and value.strip().isdigit())
    ):
        raise OrderAllocationError(f"{label} must be an exact integer")
    quantity = int(value)
    if quantity < 0 or (quantity == 0 and not allow_zero):
        raise OrderAllocationError(f"{label} must be positive")
    return quantity


def _decimal_text(value: Decimal) -> str:
    return format(value.normalize(), "f")


def _hash(value: Any, label: str) -> str:
    digest = str(value or "").lower()
    if not SHA256_RE.fullmatch(digest):
        raise OrderAllocationError(f"{label} must be a sha256 digest")
    return digest


def _normalize_intent(raw: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "intent_id",
        "strategy_id",
        "code",
        "side",
        "quantity",
        "order_type",
        "limit_price",
        "reference_price",
        "source_receipt_sha256",
    }
    if set(raw) != required:
        raise OrderAllocationError("child order intent fields do not match contract")
    intent_id = str(raw["intent_id"]).strip()
    strategy_id = str(raw["strategy_id"]).strip()
    code = str(raw["code"]).strip()
    side = str(raw["side"]).strip().lower()
    order_type = str(raw["order_type"]).strip().lower()
    if not ID_RE.fullmatch(intent_id) or not ID_RE.fullmatch(strategy_id):
        raise OrderAllocationError("child order intent identifiers are invalid")
    if not SYMBOL_RE.fullmatch(code):
        raise OrderAllocationError("child order intent symbol is invalid")
    if side not in {"buy", "sell"}:
        raise OrderAllocationError("child order intent side must be buy or sell")
    if order_type not in {"limit", "market"}:
        raise OrderAllocationError("child order intent order_type is unsupported")
    reference = _decimal(raw["reference_price"], "reference_price", positive=True)
    limit_raw = raw.get("limit_price")
    if order_type == "limit":
        limit_price: str | None = _decimal_text(
            _decimal(limit_raw, "limit_price", positive=True)
        )
    elif limit_raw is not None:
        raise OrderAllocationError("market child intent cannot contain limit_price")
    else:
        limit_price = None
    identity = {
        "intent_id": intent_id,
        "strategy_id": strategy_id,
        "code": code,
        "side": side,
        "quantity": _quantity(raw["quantity"], "quantity"),
        "order_type": order_type,
        "limit_price": limit_price,
        "reference_price": _decimal_text(reference),
        "source_receipt_sha256": _hash(
            raw["source_receipt_sha256"], "source_receipt_sha256"
        ),
    }
    return {**identity, "intent_sha256": sha256_digest(identity)}


def build_parent_order_plan(
    intents: Sequence[Mapping[str, Any]],
    *,
    batch_request_sha256: str,
    trade_date: str | date,
    account_fingerprint: str,
    mode: str = "PAPER",
    authorization_sha256: str | None = None,
) -> dict[str, Any]:
    """Freeze child intents, internal crosses and residual parent orders."""

    try:
        day = (
            trade_date
            if isinstance(trade_date, date)
            else date.fromisoformat(str(trade_date))
        )
    except (TypeError, ValueError) as exc:
        raise OrderAllocationError("trade_date must be an ISO date") from exc
    account = str(account_fingerprint).strip()
    if not account or len(account) > 160:
        raise OrderAllocationError("account_fingerprint is invalid")
    normalized_mode = str(mode).strip().upper()
    if normalized_mode not in {"PAPER", "LIVE_AUTHORIZED"}:
        raise OrderAllocationError("allocation mode is unsupported")
    if normalized_mode == "PAPER":
        if authorization_sha256 is not None:
            raise OrderAllocationError("PAPER allocation cannot bind live authorization")
        authorization = None
        real_orders = False
    else:
        authorization = _hash(authorization_sha256, "authorization_sha256")
        real_orders = True

    children = [_normalize_intent(dict(item)) for item in intents]
    ids = [item["intent_id"] for item in children]
    if len(ids) != len(set(ids)):
        raise OrderAllocationError("child intent_id values must be unique")
    strategy_sides: dict[tuple[str, str], set[str]] = {}
    for item in children:
        key = (item["strategy_id"], item["code"])
        strategy_sides.setdefault(key, set()).add(item["side"])
    if any(len(sides) > 1 for sides in strategy_sides.values()):
        raise OrderAllocationError(
            "one strategy cannot submit both sides of the same symbol"
        )
    children.sort(
        key=lambda item: (
            item["code"],
            item["side"],
            item["strategy_id"],
            item["intent_id"],
        )
    )

    internal_crosses: list[dict[str, Any]] = []
    parent_orders: list[dict[str, Any]] = []
    for code in sorted({item["code"] for item in children}):
        code_items = [item for item in children if item["code"] == code]
        execution_terms = {
            (item["order_type"], item["limit_price"], item["reference_price"])
            for item in code_items
        }
        if len(execution_terms) != 1:
            raise OrderAllocationError(
                f"child intents for {code} have incompatible execution terms"
            )
        order_type, limit_price, reference_price = next(iter(execution_terms))
        buys = [
            {**item, "remaining": int(item["quantity"])}
            for item in code_items
            if item["side"] == "buy"
        ]
        sells = [
            {**item, "remaining": int(item["quantity"])}
            for item in code_items
            if item["side"] == "sell"
        ]
        buy_index = sell_index = 0
        while buy_index < len(buys) and sell_index < len(sells):
            buy = buys[buy_index]
            sell = sells[sell_index]
            crossed = min(int(buy["remaining"]), int(sell["remaining"]))
            internal_crosses.append(
                {
                    "cross_id": "cross-"
                    + sha256_digest(
                        {
                            "batch_request_sha256": batch_request_sha256,
                            "buy_intent_sha256": buy["intent_sha256"],
                            "sell_intent_sha256": sell["intent_sha256"],
                        }
                    )[:24],
                    "code": code,
                    "quantity": crossed,
                    "reference_price": reference_price,
                    "buy_strategy_id": buy["strategy_id"],
                    "buy_intent_id": buy["intent_id"],
                    "sell_strategy_id": sell["strategy_id"],
                    "sell_intent_id": sell["intent_id"],
                }
            )
            buy["remaining"] -= crossed
            sell["remaining"] -= crossed
            if buy["remaining"] == 0:
                buy_index += 1
            if sell["remaining"] == 0:
                sell_index += 1

        remaining_buys = [item for item in buys if item["remaining"] > 0]
        remaining_sells = [item for item in sells if item["remaining"] > 0]
        residuals = remaining_buys or remaining_sells
        if remaining_buys and remaining_sells:
            raise OrderAllocationError("internal cross failed to produce one residual side")
        if residuals:
            side = "buy" if remaining_buys else "sell"
            claims = [
                {
                    "intent_id": item["intent_id"],
                    "strategy_id": item["strategy_id"],
                    "quantity": int(item["remaining"]),
                    "intent_sha256": item["intent_sha256"],
                }
                for item in residuals
            ]
            quantity = sum(item["quantity"] for item in claims)
            parent_identity = {
                "batch_request_sha256": _hash(
                    batch_request_sha256, "batch_request_sha256"
                ),
                "code": code,
                "side": side,
                "quantity": quantity,
                "order_type": order_type,
                "limit_price": limit_price,
                "reference_price": reference_price,
                "residual_claims": claims,
            }
            parent_orders.append(
                {
                    "parent_order_id": "parent-"
                    + sha256_digest(parent_identity)[:24],
                    **parent_identity,
                }
            )

    identity = {
        "schema": PARENT_ORDER_PLAN_SCHEMA,
        "batch_request_sha256": _hash(
            batch_request_sha256, "batch_request_sha256"
        ),
        "trade_date": day.isoformat(),
        "account_fingerprint": account,
        "mode": normalized_mode,
        "authorization_sha256": authorization,
        "child_intents": children,
        "internal_crosses": internal_crosses,
        "parent_orders": parent_orders,
        "real_orders": real_orders,
    }
    return {**identity, "allocation_plan_sha256": sha256_digest(identity)}


def validate_parent_order_plan(value: Mapping[str, Any]) -> dict[str, Any]:
    plan = dict(value)
    required = {
        "schema",
        "batch_request_sha256",
        "trade_date",
        "account_fingerprint",
        "mode",
        "authorization_sha256",
        "child_intents",
        "internal_crosses",
        "parent_orders",
        "real_orders",
        "allocation_plan_sha256",
    }
    if set(plan) != required or plan.get("schema") != PARENT_ORDER_PLAN_SCHEMA:
        raise OrderAllocationError("parent order plan fields do not match contract")
    children = []
    for item in list(plan.get("child_intents") or []):
        raw = dict(item)
        intent_sha = raw.pop("intent_sha256", None)
        normalized = _normalize_intent(raw)
        if intent_sha != normalized["intent_sha256"]:
            raise OrderAllocationError("child intent hash mismatch")
        children.append(raw)
    rebuilt = build_parent_order_plan(
        children,
        batch_request_sha256=str(plan["batch_request_sha256"]),
        trade_date=str(plan["trade_date"]),
        account_fingerprint=str(plan["account_fingerprint"]),
        mode=str(plan["mode"]),
        authorization_sha256=plan.get("authorization_sha256"),
    )
    if rebuilt != plan:
        raise OrderAllocationError("parent order allocation plan is not reproducible")
    return rebuilt


def _hamilton(
    total: int,
    claims: Sequence[tuple[str, int]],
    *,
    cap_to_claims: bool = False,
) -> dict[str, int]:
    denominator = sum(quantity for _, quantity in claims)
    if denominator <= 0 or total < 0 or (cap_to_claims and total > denominator):
        raise OrderAllocationError("allocation total exceeds residual claims")
    allocations = {
        intent_id: total * quantity // denominator
        for intent_id, quantity in claims
    }
    remainder = total - sum(allocations.values())
    ranking = sorted(
        claims,
        key=lambda item: (-(total * item[1] % denominator), item[0]),
    )
    for intent_id, _ in ranking[:remainder]:
        allocations[intent_id] += 1
    return allocations


def validate_parent_fill_allocation(
    plan_value: Mapping[str, Any], value: Mapping[str, Any]
) -> dict[str, Any]:
    """Validate one cumulative, content-addressed fill-allocation receipt."""

    plan = validate_parent_order_plan(plan_value)
    allocation = dict(value)
    required = {
        "schema",
        "allocation_sequence",
        "previous_fill_allocation_sha256",
        "allocation_plan_sha256",
        "parent_order_id",
        "broker_order_id",
        "as_of_time",
        "status",
        "filled_quantity",
        "average_price",
        "fee_fen",
        "child_allocations",
        "incremental_child_allocations",
        "unfilled_quantity",
        "real_orders",
        "fill_allocation_sha256",
    }
    if set(allocation) != required or allocation.get("schema") != PARENT_FILL_ALLOCATION_SCHEMA:
        raise OrderAllocationError("fill allocation fields do not match contract")
    digest = allocation.pop("fill_allocation_sha256")
    if _hash(digest, "fill_allocation_sha256") != sha256_digest(allocation):
        raise OrderAllocationError("fill allocation hash mismatch")
    allocation["fill_allocation_sha256"] = digest
    if allocation["allocation_plan_sha256"] != plan["allocation_plan_sha256"]:
        raise OrderAllocationError("fill allocation plan hash mismatch")
    matches = [
        item
        for item in plan["parent_orders"]
        if item["parent_order_id"] == allocation["parent_order_id"]
    ]
    if len(matches) != 1:
        raise OrderAllocationError("fill allocation parent_order_id is not in the plan")
    parent = matches[0]
    sequence = _quantity(allocation["allocation_sequence"], "allocation_sequence")
    previous_sha = allocation["previous_fill_allocation_sha256"]
    if sequence == 1:
        if previous_sha is not None:
            raise OrderAllocationError("first fill allocation cannot have a predecessor")
    else:
        _hash(previous_sha, "previous_fill_allocation_sha256")
    broker_order_id = str(allocation["broker_order_id"]).strip()
    if not ID_RE.fullmatch(broker_order_id):
        raise OrderAllocationError("broker_order_id is invalid")
    try:
        moment = datetime.fromisoformat(
            str(allocation["as_of_time"]).replace("Z", "+00:00")
        )
    except (TypeError, ValueError) as exc:
        raise OrderAllocationError("fill allocation as_of_time is invalid") from exc
    if moment.tzinfo is None:
        raise OrderAllocationError("fill allocation as_of_time must include timezone")
    status = str(allocation["status"])
    if status not in {"OPEN", "PARTIALLY_FILLED", "FILLED", "CANCELLED"}:
        raise OrderAllocationError("fill allocation status is unsupported")
    filled = _quantity(
        allocation["filled_quantity"], "filled_quantity", allow_zero=True
    )
    fee_fen = _quantity(allocation["fee_fen"], "fee_fen", allow_zero=True)
    if filled > int(parent["quantity"]):
        raise OrderAllocationError("fill allocation exceeds parent quantity")
    if allocation["unfilled_quantity"] != int(parent["quantity"]) - filled:
        raise OrderAllocationError("fill allocation unfilled quantity is incoherent")
    if status == "OPEN" and filled != 0:
        raise OrderAllocationError("OPEN fill allocation must have zero quantity")
    if status == "FILLED" and filled != int(parent["quantity"]):
        raise OrderAllocationError("FILLED status requires the complete parent quantity")
    if status == "PARTIALLY_FILLED" and not 0 < filled < int(parent["quantity"]):
        raise OrderAllocationError("PARTIALLY_FILLED quantity is incoherent")
    if filled == 0:
        if allocation["average_price"] is not None or fee_fen != 0:
            raise OrderAllocationError("zero fill cannot contain price or fees")
        average_price_text = None
    else:
        average_price_text = _decimal_text(
            _decimal(allocation["average_price"], "average_price", positive=True)
        )
        if allocation["average_price"] != average_price_text:
            raise OrderAllocationError("average_price is not canonical")
    claim_lookup = {
        str(item["intent_id"]): dict(item) for item in parent["residual_claims"]
    }

    def validate_children(raw_items: Any, *, incremental: bool) -> list[dict[str, Any]]:
        items = [dict(item) for item in list(raw_items or [])]
        ids = [str(item.get("intent_id") or "") for item in items]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            raise OrderAllocationError("child fill allocations must be uniquely sorted")
        normalized: list[dict[str, Any]] = []
        for item in items:
            if set(item) != {
                "intent_id",
                "strategy_id",
                "quantity",
                "average_price",
                "fee_fen",
            }:
                raise OrderAllocationError("child fill allocation fields are invalid")
            intent_id = str(item["intent_id"])
            claim = claim_lookup.get(intent_id)
            if claim is None or item["strategy_id"] != claim["strategy_id"]:
                raise OrderAllocationError("child fill allocation identity is invalid")
            quantity = _quantity(
                item["quantity"], "child quantity", allow_zero=incremental
            )
            child_fee = _quantity(item["fee_fen"], "child fee", allow_zero=True)
            if incremental and quantity == 0 and child_fee == 0:
                raise OrderAllocationError("empty incremental child allocation is invalid")
            if quantity == 0:
                if item["average_price"] is not None:
                    raise OrderAllocationError("zero child fill cannot contain average price")
                child_average = None
            else:
                child_average = _decimal_text(
                    _decimal(item["average_price"], "child average_price", positive=True)
                )
                if item["average_price"] != child_average:
                    raise OrderAllocationError("child average_price is not canonical")
            if not incremental and (
                quantity > int(claim["quantity"])
                or child_average != average_price_text
            ):
                raise OrderAllocationError("cumulative child allocation is incoherent")
            normalized.append(dict(item))
        return normalized

    children = validate_children(allocation["child_allocations"], incremental=False)
    increments = validate_children(
        allocation["incremental_child_allocations"], incremental=True
    )
    if sum(item["quantity"] for item in children) != filled:
        raise OrderAllocationError("child quantities do not conserve parent fill")
    if sum(item["fee_fen"] for item in children) != fee_fen:
        raise OrderAllocationError("child fees do not conserve parent fee")
    if sequence == 1 and increments != children:
        raise OrderAllocationError("first fill allocation increment must equal cumulative state")
    if allocation["real_orders"] is not bool(plan["real_orders"]):
        raise OrderAllocationError("fill allocation real_orders flag is incoherent")
    return dict(allocation)


def allocate_parent_fill(
    plan_value: Mapping[str, Any],
    broker_fill: Mapping[str, Any],
    *,
    previous_allocation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Allocate only the new part of a cumulative fill, preserving monotonicity."""

    plan = validate_parent_order_plan(plan_value)
    required = {
        "broker_order_id",
        "parent_order_id",
        "filled_quantity",
        "average_price",
        "fee_fen",
        "as_of_time",
        "status",
    }
    if set(broker_fill) != required:
        raise OrderAllocationError("broker fill fields do not match contract")
    parent_id = str(broker_fill["parent_order_id"])
    matches = [
        item for item in plan["parent_orders"] if item["parent_order_id"] == parent_id
    ]
    if len(matches) != 1:
        raise OrderAllocationError("broker fill parent_order_id is not in the plan")
    parent = matches[0]
    filled = _quantity(
        broker_fill["filled_quantity"], "filled_quantity", allow_zero=True
    )
    if filled > int(parent["quantity"]):
        raise OrderAllocationError("broker fill exceeds parent order quantity")
    status = str(broker_fill["status"]).strip().upper()
    if status not in {"OPEN", "PARTIALLY_FILLED", "FILLED", "CANCELLED"}:
        raise OrderAllocationError("broker fill status is unsupported")
    if status == "OPEN" and filled != 0:
        raise OrderAllocationError("OPEN broker fill must have zero quantity")
    if status == "FILLED" and filled != int(parent["quantity"]):
        raise OrderAllocationError("FILLED status requires the complete parent quantity")
    if status == "PARTIALLY_FILLED" and not 0 < filled < int(parent["quantity"]):
        raise OrderAllocationError("PARTIALLY_FILLED quantity is incoherent")
    try:
        moment = datetime.fromisoformat(
            str(broker_fill["as_of_time"]).replace("Z", "+00:00")
        )
    except (TypeError, ValueError) as exc:
        raise OrderAllocationError("broker fill as_of_time is invalid") from exc
    if moment.tzinfo is None:
        raise OrderAllocationError("broker fill as_of_time must include timezone")
    fee_fen = _quantity(broker_fill["fee_fen"], "fee_fen", allow_zero=True)
    if filled == 0:
        if broker_fill["average_price"] is not None or fee_fen > 0:
            raise OrderAllocationError("zero-quantity broker fill cannot contain price or fees")
        average_price = None
        average_price_text = None
    else:
        average_price = _decimal(
            broker_fill["average_price"], "average_price", positive=True
        )
        average_price_text = _decimal_text(average_price)
    broker_order_id = str(broker_fill["broker_order_id"]).strip()
    if not ID_RE.fullmatch(broker_order_id):
        raise OrderAllocationError("broker_order_id is invalid")

    claim_lookup = {
        str(item["intent_id"]): dict(item) for item in parent["residual_claims"]
    }
    previous = (
        validate_parent_fill_allocation(plan, previous_allocation)
        if previous_allocation is not None
        else None
    )
    if previous is not None:
        if (
            previous["parent_order_id"] != parent_id
            or previous["broker_order_id"] != broker_order_id
        ):
            raise OrderAllocationError("broker fill identity changed within allocation chain")
        snapshot_fields = {
            "as_of_time": moment.isoformat(),
            "status": status,
            "filled_quantity": filled,
            "average_price": average_price_text,
            "fee_fen": fee_fen,
        }
        if all(previous[field] == value for field, value in snapshot_fields.items()):
            return dict(previous)
        if previous["status"] in {"FILLED", "CANCELLED"}:
            raise OrderAllocationError("terminal fill allocation cannot be reopened")
        previous_moment = datetime.fromisoformat(previous["as_of_time"])
        if moment <= previous_moment:
            raise OrderAllocationError("changed broker fill time must move forwards")
        allowed_statuses = {
            "OPEN": {"OPEN", "PARTIALLY_FILLED", "FILLED", "CANCELLED"},
            "PARTIALLY_FILLED": {"PARTIALLY_FILLED", "FILLED", "CANCELLED"},
        }
        if status not in allowed_statuses[previous["status"]]:
            raise OrderAllocationError("broker fill status moved backwards")
        if filled < previous["filled_quantity"]:
            raise OrderAllocationError("broker filled quantity decreased")
        if fee_fen < previous["fee_fen"]:
            raise OrderAllocationError("broker cumulative fee decreased")

    prior_children = {
        item["intent_id"]: dict(item)
        for item in (previous["child_allocations"] if previous else [])
    }
    prior_filled = int(previous["filled_quantity"]) if previous else 0
    prior_fee = int(previous["fee_fen"]) if previous else 0
    delta_filled = filled - prior_filled
    delta_fee = fee_fen - prior_fee
    remaining_claims = [
        (
            intent_id,
            int(claim["quantity"])
            - int(prior_children.get(intent_id, {}).get("quantity", 0)),
        )
        for intent_id, claim in sorted(claim_lookup.items())
    ]
    if delta_filled == 0:
        quantity_increments = {intent_id: 0 for intent_id in claim_lookup}
    else:
        quantity_increments = _hamilton(
            delta_filled, remaining_claims, cap_to_claims=True
        )
    cumulative_quantities = {
        intent_id: int(prior_children.get(intent_id, {}).get("quantity", 0))
        + int(quantity_increments.get(intent_id, 0))
        for intent_id in claim_lookup
    }
    fee_weights = [
        (intent_id, quantity)
        for intent_id, quantity in sorted(cumulative_quantities.items())
        if quantity > 0
    ]
    if delta_fee > 0 and not fee_weights:
        raise OrderAllocationError("broker fee cannot be allocated without a fill")
    fee_increments = (
        _hamilton(delta_fee, fee_weights)
        if delta_fee > 0
        else {intent_id: 0 for intent_id in claim_lookup}
    )
    cumulative_fees = {
        intent_id: int(prior_children.get(intent_id, {}).get("fee_fen", 0))
        + int(fee_increments.get(intent_id, 0))
        for intent_id in claim_lookup
    }
    if delta_filled > 0:
        assert average_price is not None
        previous_notional = Decimal("0")
        if previous and previous["filled_quantity"] > 0:
            previous_notional = Decimal(previous["average_price"]) * prior_filled
        incremental_notional = average_price * filled - previous_notional
        incremental_average = incremental_notional / delta_filled
        if not incremental_average.is_finite() or incremental_average <= 0:
            raise OrderAllocationError("incremental broker fill average price is invalid")
        incremental_average_text = _decimal_text(incremental_average)
    else:
        incremental_average_text = None
    allocations = [
        {
            "intent_id": intent_id,
            "strategy_id": str(claim_lookup[intent_id]["strategy_id"]),
            "quantity": quantity,
            "average_price": average_price_text,
            "fee_fen": cumulative_fees[intent_id],
        }
        for intent_id, quantity in sorted(cumulative_quantities.items())
        if quantity > 0
    ]
    increments = [
        {
            "intent_id": intent_id,
            "strategy_id": str(claim_lookup[intent_id]["strategy_id"]),
            "quantity": int(quantity_increments.get(intent_id, 0)),
            "average_price": (
                incremental_average_text
                if int(quantity_increments.get(intent_id, 0)) > 0
                else None
            ),
            "fee_fen": int(fee_increments.get(intent_id, 0)),
        }
        for intent_id in sorted(claim_lookup)
        if int(quantity_increments.get(intent_id, 0)) > 0
        or int(fee_increments.get(intent_id, 0)) > 0
    ]
    identity = {
        "schema": PARENT_FILL_ALLOCATION_SCHEMA,
        "allocation_sequence": (
            int(previous["allocation_sequence"]) + 1 if previous else 1
        ),
        "previous_fill_allocation_sha256": (
            previous["fill_allocation_sha256"] if previous else None
        ),
        "allocation_plan_sha256": plan["allocation_plan_sha256"],
        "parent_order_id": parent_id,
        "broker_order_id": broker_order_id,
        "as_of_time": moment.isoformat(),
        "status": status,
        "filled_quantity": filled,
        "average_price": average_price_text,
        "fee_fen": fee_fen,
        "child_allocations": allocations,
        "incremental_child_allocations": increments,
        "unfilled_quantity": int(parent["quantity"]) - filled,
        "real_orders": bool(plan["real_orders"]),
    }
    result = {**identity, "fill_allocation_sha256": sha256_digest(identity)}
    return validate_parent_fill_allocation(plan, result)
