"""Content-addressed broker account snapshots and durable order reservations."""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from pathlib import Path
import re
from typing import Any, Iterator

from .broker_order_lifecycle import (
    BrokerOrderJournal,
    BrokerOrderJournalError,
    TERMINAL_STATUSES,
)
from .order_allocation import OrderAllocationError, validate_parent_order_plan
from .provenance import sha256_digest


BROKER_ACCOUNT_SNAPSHOT_SCHEMA = "quant-core/broker-account-snapshot/v1"
BROKER_ACCOUNT_CONTROL_POLICY_SCHEMA = "quant-core/broker-account-control-policy/v1"
BROKER_ACCOUNT_RESERVATION_EVENT_SCHEMA = (
    "quant-core/broker-account-reservation-event/v1"
)
BROKER_ACCOUNT_RESERVATION_HEAD_SCHEMA = (
    "quant-core/broker-account-reservation-head/v1"
)
BROKER_ACCOUNT_RESERVATION_INSPECTION_SCHEMA = (
    "quant-core/broker-account-reservation-inspection/v1"
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
SYMBOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
RESERVATION_STATUSES = frozenset(
    {
        "RESERVED",
        "SUBMITTING",
        "ACCEPTED",
        "PARTIALLY_FILLED",
        "FILLED",
        "CANCEL_PENDING",
        "CANCELLED",
        "REJECTED",
        "UNKNOWN",
        "BREACHED",
    }
)


class BrokerAccountControlError(RuntimeError):
    """Raised when account evidence or reservation state is unsafe."""


class BrokerAccountReservationConflict(BrokerAccountControlError):
    """Raised when a reservation identity or resource claim conflicts."""


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not ID_RE.fullmatch(text):
        raise BrokerAccountControlError(f"{label} is invalid")
    return text


def _symbol(value: Any) -> str:
    text = str(value or "").strip()
    if not SYMBOL_RE.fullmatch(text):
        raise BrokerAccountControlError("position code is invalid")
    return text


def _hash(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    text = str(value or "").lower()
    if not SHA256_RE.fullmatch(text):
        raise BrokerAccountControlError(f"{label} must be a sha256 digest")
    return text


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not (
        isinstance(value, int)
        or (isinstance(value, str) and value.strip().isdigit())
    ):
        raise BrokerAccountControlError(f"{label} must be an exact integer")
    parsed = int(value)
    if parsed < 0 or (positive and parsed == 0):
        raise BrokerAccountControlError(f"{label} is invalid")
    return parsed


def _decimal(value: Any, label: str, *, positive: bool = False) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise BrokerAccountControlError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite() or parsed < 0 or (positive and parsed == 0):
        raise BrokerAccountControlError(f"{label} is invalid")
    return parsed


def _decimal_text(value: Any, label: str, *, positive: bool = False) -> str:
    return format(_decimal(value, label, positive=positive).normalize(), "f")


def _signed_decimal_text(value: Any, label: str) -> str:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise BrokerAccountControlError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite():
        raise BrokerAccountControlError(f"{label} is invalid")
    return format(parsed.normalize(), "f")


def _money_up(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"), rounding=ROUND_CEILING)


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise BrokerAccountControlError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise BrokerAccountControlError(f"{label} must include timezone")
    utc = parsed.astimezone(timezone.utc)
    return utc.isoformat(), utc


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
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != encoded:
            raise BrokerAccountReservationConflict(
                f"immutable account control record conflict: {path.name}"
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


def build_broker_account_snapshot(
    *,
    adapter_id: str,
    account_fingerprint: str,
    trade_date: str,
    currency: str,
    cash_balance: Any,
    cash_available: Any,
    equity: Any,
    positions: list[dict[str, Any]],
    other_assets: Any = 0,
    liabilities: Any = 0,
    broker_reported_at: Any,
    received_at: Any,
    source_reference: str,
) -> dict[str, Any]:
    """Normalize a broker account/position snapshot and prove conservation."""

    adapter = _identifier(adapter_id, "adapter_id")
    account = str(account_fingerprint or "").strip()
    if not account or len(account) > 160:
        raise BrokerAccountControlError("account_fingerprint is invalid")
    try:
        day = date.fromisoformat(str(trade_date)).isoformat()
    except ValueError as exc:
        raise BrokerAccountControlError("trade_date is invalid") from exc
    currency_value = str(currency or "").strip().upper()
    if currency_value != "CNY":
        raise BrokerAccountControlError("only explicit CNY account snapshots are supported")
    cash = _decimal(cash_balance, "cash_balance")
    available = _decimal(cash_available, "cash_available")
    if available > cash:
        raise BrokerAccountControlError("cash_available exceeds cash_balance")
    other = _decimal(other_assets, "other_assets")
    debt = _decimal(liabilities, "liabilities")
    normalized_positions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in positions:
        if not isinstance(raw, dict) or set(raw) != {
            "code",
            "total_quantity",
            "sellable_quantity",
            "frozen_quantity",
            "market_price",
        }:
            raise BrokerAccountControlError("account position fields are invalid")
        code = _symbol(raw["code"])
        if code in seen:
            raise BrokerAccountControlError("account position code is duplicated")
        seen.add(code)
        total = _integer(raw["total_quantity"], "total_quantity")
        sellable = _integer(raw["sellable_quantity"], "sellable_quantity")
        frozen = _integer(raw["frozen_quantity"], "frozen_quantity")
        if sellable + frozen > total:
            raise BrokerAccountControlError(
                "sellable plus frozen quantity exceeds total position"
            )
        price = _decimal(raw["market_price"], "market_price", positive=True)
        normalized_positions.append(
            {
                "code": code,
                "total_quantity": total,
                "sellable_quantity": sellable,
                "frozen_quantity": frozen,
                "market_price": format(price.normalize(), "f"),
                "market_value": format((price * total).normalize(), "f"),
            }
        )
    normalized_positions.sort(key=lambda item: item["code"])
    position_value = sum(
        (Decimal(item["market_value"]) for item in normalized_positions),
        Decimal("0"),
    )
    equity_value = _decimal(equity, "equity")
    expected_equity = cash + position_value + other - debt
    if equity_value != expected_equity:
        raise BrokerAccountControlError(
            "account snapshot cash, positions, other assets and liabilities do not reconcile"
        )
    broker_text, broker_time = _timestamp(
        broker_reported_at, "broker_reported_at"
    )
    received_text, received_time = _timestamp(received_at, "received_at")
    if broker_time > received_time:
        raise BrokerAccountControlError(
            "broker account snapshot time is after local receipt time"
        )
    identity = {
        "schema": BROKER_ACCOUNT_SNAPSHOT_SCHEMA,
        "adapter_id": adapter,
        "account_fingerprint": account,
        "trade_date": day,
        "currency": currency_value,
        "cash_balance": format(cash.normalize(), "f"),
        "cash_available": format(available.normalize(), "f"),
        "cash_frozen": format((cash - available).normalize(), "f"),
        "equity": format(equity_value.normalize(), "f"),
        "other_assets": format(other.normalize(), "f"),
        "liabilities": format(debt.normalize(), "f"),
        "position_market_value": format(position_value.normalize(), "f"),
        "positions": normalized_positions,
        "broker_reported_at": broker_text,
        "received_at": received_text,
        "source_reference": _identifier(source_reference, "source_reference"),
    }
    return {**identity, "snapshot_sha256": sha256_digest(identity)}


def validate_broker_account_snapshot(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrokerAccountControlError("broker account snapshot must be an object")
    required = {
        "schema",
        "adapter_id",
        "account_fingerprint",
        "trade_date",
        "currency",
        "cash_balance",
        "cash_available",
        "cash_frozen",
        "equity",
        "other_assets",
        "liabilities",
        "position_market_value",
        "positions",
        "broker_reported_at",
        "received_at",
        "source_reference",
        "snapshot_sha256",
    }
    if set(value) != required or value.get("schema") != BROKER_ACCOUNT_SNAPSHOT_SCHEMA:
        raise BrokerAccountControlError("broker account snapshot fields are invalid")
    rebuilt = build_broker_account_snapshot(
        adapter_id=value["adapter_id"],
        account_fingerprint=value["account_fingerprint"],
        trade_date=value["trade_date"],
        currency=value["currency"],
        cash_balance=value["cash_balance"],
        cash_available=value["cash_available"],
        equity=value["equity"],
        positions=[
            {
                key: position[key]
                for key in (
                    "code",
                    "total_quantity",
                    "sellable_quantity",
                    "frozen_quantity",
                    "market_price",
                )
            }
            for position in value["positions"]
        ],
        other_assets=value["other_assets"],
        liabilities=value["liabilities"],
        broker_reported_at=value["broker_reported_at"],
        received_at=value["received_at"],
        source_reference=value["source_reference"],
    )
    if value != rebuilt:
        raise BrokerAccountControlError("broker account snapshot hash or semantics mismatch")
    return rebuilt


def build_broker_account_control_policy(
    *,
    policy_id: str,
    max_snapshot_age_seconds: int,
    limit_order_fee_buffer_bps: int,
    market_order_price_buffer_bps: int,
    market_order_fee_buffer_bps: int,
) -> dict[str, Any]:
    identity = {
        "schema": BROKER_ACCOUNT_CONTROL_POLICY_SCHEMA,
        "policy_id": _identifier(policy_id, "policy_id"),
        "max_snapshot_age_seconds": _integer(
            max_snapshot_age_seconds, "max_snapshot_age_seconds", positive=True
        ),
        "limit_order_fee_buffer_bps": _integer(
            limit_order_fee_buffer_bps, "limit_order_fee_buffer_bps"
        ),
        "market_order_price_buffer_bps": _integer(
            market_order_price_buffer_bps, "market_order_price_buffer_bps"
        ),
        "market_order_fee_buffer_bps": _integer(
            market_order_fee_buffer_bps, "market_order_fee_buffer_bps"
        ),
    }
    return {**identity, "policy_sha256": sha256_digest(identity)}


def validate_broker_account_control_policy(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrokerAccountControlError("account control policy must be an object")
    required = {
        "schema",
        "policy_id",
        "max_snapshot_age_seconds",
        "limit_order_fee_buffer_bps",
        "market_order_price_buffer_bps",
        "market_order_fee_buffer_bps",
        "policy_sha256",
    }
    if set(value) != required or value.get("schema") != BROKER_ACCOUNT_CONTROL_POLICY_SCHEMA:
        raise BrokerAccountControlError("account control policy fields are invalid")
    rebuilt = build_broker_account_control_policy(
        policy_id=value["policy_id"],
        max_snapshot_age_seconds=value["max_snapshot_age_seconds"],
        limit_order_fee_buffer_bps=value["limit_order_fee_buffer_bps"],
        market_order_price_buffer_bps=value["market_order_price_buffer_bps"],
        market_order_fee_buffer_bps=value["market_order_fee_buffer_bps"],
    )
    if value != rebuilt:
        raise BrokerAccountControlError("account control policy hash mismatch")
    return rebuilt


class BrokerAccountReservationBook:
    """Append-only account resource reservations tied to a lifecycle journal."""

    def __init__(
        self,
        root: str | Path,
        *,
        journal: BrokerOrderJournal,
        account_snapshot: dict[str, Any],
        policy: dict[str, Any],
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.journal = journal
        self.account_snapshot = validate_broker_account_snapshot(account_snapshot)
        self.policy = validate_broker_account_control_policy(policy)
        if self.account_snapshot["account_fingerprint"] != journal.account_fingerprint:
            raise BrokerAccountControlError(
                "account snapshot and lifecycle journal identities differ"
            )
        _immutable_json(self.root / "account-snapshot.json", self.account_snapshot)
        _immutable_json(self.root / "policy.json", self.policy)

    @property
    def adapter_id(self) -> str:
        return str(self.account_snapshot["adapter_id"])

    @property
    def account_fingerprint(self) -> str:
        return str(self.account_snapshot["account_fingerprint"])

    @property
    def trade_date(self) -> str:
        return str(self.account_snapshot["trade_date"])

    @property
    def snapshot_sha256(self) -> str:
        return str(self.account_snapshot["snapshot_sha256"])

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
            raise BrokerAccountControlError(
                "account reservation book is locked by another process"
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

    @property
    def head_path(self) -> Path:
        return self.root / "head.json"

    def _event_path(self, sequence: int, digest: str) -> Path:
        return self.root / "events" / f"{sequence:012d}-{digest}.json"

    @staticmethod
    def _validate_event_shape(event: dict[str, Any]) -> None:
        required = {
            "schema",
            "sequence",
            "previous_event_sha256",
            "previous_operation_event_sha256",
            "recorded_at",
            "account_fingerprint",
            "account_snapshot_sha256",
            "account_control_policy_sha256",
            "operation_key",
            "client_order_id",
            "authorization_sha256",
            "allocation_plan_sha256",
            "parent_order_id",
            "code",
            "side",
            "order_quantity",
            "order_type",
            "price_cap",
            "fee_buffer_bps",
            "initial_reserved_cash",
            "initial_reserved_quantity",
            "status",
            "cumulative_filled_quantity",
            "average_price",
            "cumulative_fee_fen",
            "realized_cash_delta",
            "consumed_sellable_quantity",
            "remaining_reserved_cash",
            "remaining_reserved_quantity",
            "source_lifecycle_event_sha256",
            "event_sha256",
        }
        if set(event) != required or event.get(
            "schema"
        ) != BROKER_ACCOUNT_RESERVATION_EVENT_SCHEMA:
            raise BrokerAccountControlError("account reservation event fields are invalid")
        digest = str(event.get("event_sha256") or "")
        identity = {key: value for key, value in event.items() if key != "event_sha256"}
        if not SHA256_RE.fullmatch(digest) or sha256_digest(identity) != digest:
            raise BrokerAccountControlError("account reservation event hash mismatch")

    def _load_chain(self) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
        paths = sorted((self.root / "events").glob("*.json"))
        if not self.head_path.exists():
            if paths:
                raise BrokerAccountControlError(
                    "account reservation head is missing while events exist"
                )
            return [], {}
        try:
            head = dict(_read_json(self.head_path))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrokerAccountControlError(
                f"account reservation head is unreadable: {exc}"
            ) from exc
        if set(head) != {"schema", "sequence", "event_sha256"} or head.get(
            "schema"
        ) != BROKER_ACCOUNT_RESERVATION_HEAD_SCHEMA:
            raise BrokerAccountControlError("account reservation head fields are invalid")
        if int(head.get("sequence") or 0) != len(paths):
            raise BrokerAccountControlError(
                "account reservation chain has missing or orphan events"
            )
        events: list[dict[str, Any]] = []
        latest: dict[str, dict[str, Any]] = {}
        previous_sha: str | None = None
        for expected_sequence, path in enumerate(paths, start=1):
            try:
                event = dict(_read_json(path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerAccountControlError(
                    f"account reservation event is unreadable: {path.name}: {exc}"
                ) from exc
            self._validate_event_shape(event)
            digest = event["event_sha256"]
            key = _identifier(event["operation_key"], "operation_key")
            previous_operation = latest.get(key)
            if path.name != self._event_path(expected_sequence, digest).name:
                raise BrokerAccountControlError(
                    "account reservation event filename mismatch"
                )
            if (
                event["sequence"] != expected_sequence
                or event["previous_event_sha256"] != previous_sha
                or event["previous_operation_event_sha256"]
                != (
                    previous_operation["event_sha256"]
                    if previous_operation is not None
                    else None
                )
                or event["account_fingerprint"] != self.account_fingerprint
                or event["account_snapshot_sha256"] != self.snapshot_sha256
                or event["account_control_policy_sha256"]
                != self.policy["policy_sha256"]
            ):
                raise BrokerAccountControlError(
                    "account reservation chain identity broke"
                )
            self._validate_event_semantics(previous_operation, event)
            events.append(event)
            latest[key] = event
            previous_sha = digest
        if head != {
            "schema": BROKER_ACCOUNT_RESERVATION_HEAD_SCHEMA,
            "sequence": len(events),
            "event_sha256": events[-1]["event_sha256"],
        }:
            raise BrokerAccountControlError(
                "account reservation head does not match chain tip"
            )
        return events, latest

    def _validate_event_semantics(
        self,
        previous: dict[str, Any] | None,
        event: dict[str, Any],
    ) -> None:
        try:
            recorded_at = datetime.fromisoformat(str(event["recorded_at"]))
        except ValueError as exc:
            raise BrokerAccountControlError(
                "account reservation recorded_at is invalid"
            ) from exc
        if recorded_at.tzinfo is None:
            raise BrokerAccountControlError(
                "account reservation recorded_at lacks timezone"
            )
        status = str(event["status"])
        if status not in RESERVATION_STATUSES:
            raise BrokerAccountControlError("account reservation status is invalid")
        _identifier(event["client_order_id"], "client_order_id")
        _identifier(event["parent_order_id"], "parent_order_id")
        _symbol(event["code"])
        side = str(event["side"])
        if side not in {"buy", "sell"}:
            raise BrokerAccountControlError("account reservation side is invalid")
        order_type = str(event["order_type"])
        if order_type not in {"limit", "market"}:
            raise BrokerAccountControlError("account reservation order_type is invalid")
        _hash(event["authorization_sha256"], "authorization_sha256")
        _hash(event["allocation_plan_sha256"], "allocation_plan_sha256")
        source_sha = _hash(
            event["source_lifecycle_event_sha256"],
            "source_lifecycle_event_sha256",
            nullable=True,
        )
        quantity = _integer(event["order_quantity"], "order_quantity", positive=True)
        filled = _integer(
            event["cumulative_filled_quantity"], "cumulative_filled_quantity"
        )
        fee_fen = _integer(event["cumulative_fee_fen"], "cumulative_fee_fen")
        if filled > quantity:
            raise BrokerAccountControlError(
                "account reservation cumulative fill exceeds order quantity"
            )
        _decimal(event["price_cap"], "price_cap", positive=True)
        initial_cash = _decimal(
            event["initial_reserved_cash"], "initial_reserved_cash"
        )
        initial_quantity = _integer(
            event["initial_reserved_quantity"], "initial_reserved_quantity"
        )
        _integer(event["fee_buffer_bps"], "fee_buffer_bps")
        realized_cash_delta = _signed_decimal_text(
            event["realized_cash_delta"], "realized_cash_delta"
        )
        consumed_sellable_quantity = _integer(
            event["consumed_sellable_quantity"],
            "consumed_sellable_quantity",
        )
        remaining_cash = _decimal(
            event["remaining_reserved_cash"], "remaining_reserved_cash"
        )
        remaining_quantity = _integer(
            event["remaining_reserved_quantity"],
            "remaining_reserved_quantity",
        )
        if previous is None:
            if (
                status != "RESERVED"
                or source_sha is not None
                or filled != 0
                or fee_fen != 0
                or event["average_price"] is not None
            ):
                raise BrokerAccountControlError(
                    "first account reservation event is not a clean reservation"
                )
            if side == "buy" and not (
                initial_cash > 0
                and initial_quantity == 0
                and remaining_cash == initial_cash
                and remaining_quantity == 0
                and realized_cash_delta == "0"
                and consumed_sellable_quantity == 0
            ):
                raise BrokerAccountControlError(
                    "initial buy reservation does not conserve cash"
                )
            if side == "sell" and not (
                initial_cash == 0
                and initial_quantity == quantity
                and remaining_cash == 0
                and remaining_quantity == quantity
                and realized_cash_delta == "0"
                and consumed_sellable_quantity == 0
            ):
                raise BrokerAccountControlError(
                    "initial sell reservation does not conserve sellable quantity"
                )
        else:
            if previous["status"] in TERMINAL_STATUSES:
                raise BrokerAccountControlError(
                    "terminal account reservation cannot reopen"
                )
            for field in (
                "account_fingerprint",
                "account_snapshot_sha256",
                "account_control_policy_sha256",
                "operation_key",
                "client_order_id",
                "authorization_sha256",
                "allocation_plan_sha256",
                "parent_order_id",
                "code",
                "side",
                "order_quantity",
                "order_type",
                "price_cap",
                "fee_buffer_bps",
                "initial_reserved_cash",
                "initial_reserved_quantity",
            ):
                if event[field] != previous[field]:
                    raise BrokerAccountControlError(
                        f"account reservation identity changed: {field}"
                    )
            if source_sha is None:
                raise BrokerAccountControlError(
                    "reconciled reservation lacks lifecycle source"
                )
            lifecycle = self.journal.event_by_sha256(source_sha)
            if lifecycle is None or any(
                (
                    lifecycle["operation_key"] != event["operation_key"],
                    lifecycle["client_order_id"] != event["client_order_id"],
                    lifecycle["allocation_plan_sha256"]
                    != event["allocation_plan_sha256"],
                    lifecycle["parent_order_id"] != event["parent_order_id"],
                    lifecycle["status"] != status,
                    int(lifecycle["order_quantity"]) != quantity,
                    int(lifecycle["cumulative_filled_quantity"]) != filled,
                    lifecycle["average_price"] != event["average_price"],
                    int(lifecycle["cumulative_fee_fen"]) != fee_fen,
                )
            ):
                raise BrokerAccountControlError(
                    "account reservation lifecycle binding mismatch"
                )
            expected = self._state_from_lifecycle(previous, lifecycle)
            for field, expected_value in expected.items():
                if event[field] != expected_value:
                    raise BrokerAccountControlError(
                        f"account reservation derived state mismatch: {field}"
                    )

    def _state_from_lifecycle(
        self, previous: dict[str, Any], lifecycle: dict[str, Any]
    ) -> dict[str, Any]:
        status = str(lifecycle["status"])
        filled = int(lifecycle["cumulative_filled_quantity"])
        quantity = int(previous["order_quantity"])
        average = lifecycle["average_price"]
        fee_fen = int(lifecycle["cumulative_fee_fen"])
        notional = Decimal("0") if filled == 0 else Decimal(str(average)) * filled
        fee = Decimal(fee_fen) / Decimal("100")
        terminal = status in TERMINAL_STATUSES
        remaining_quantity = 0 if terminal else quantity - filled
        if previous["side"] == "buy":
            realized_cash_delta = -(notional + fee)
            fee_buffer = Decimal(int(previous["fee_buffer_bps"])) / Decimal("10000")
            remaining_cash = (
                Decimal("0")
                if terminal
                else _money_up(
                    Decimal(previous["price_cap"])
                    * remaining_quantity
                    * (Decimal("1") + fee_buffer)
                )
            )
            consumed_sellable = 0
            remaining_sellable = 0
        else:
            realized_cash_delta = notional - fee
            remaining_cash = Decimal("0")
            consumed_sellable = filled
            remaining_sellable = remaining_quantity
        return {
            "status": status,
            "cumulative_filled_quantity": filled,
            "average_price": average,
            "cumulative_fee_fen": fee_fen,
            "realized_cash_delta": _signed_decimal_text(
                realized_cash_delta, "realized_cash_delta"
            ),
            "consumed_sellable_quantity": consumed_sellable,
            "remaining_reserved_cash": _decimal_text(
                remaining_cash, "remaining_reserved_cash"
            ),
            "remaining_reserved_quantity": remaining_sellable,
        }

    def _availability(
        self, latest: dict[str, dict[str, Any]]
    ) -> tuple[Decimal, dict[str, int]]:
        available_cash = Decimal(self.account_snapshot["cash_available"])
        sellable = {
            item["code"]: int(item["sellable_quantity"])
            for item in self.account_snapshot["positions"]
        }
        for event in latest.values():
            available_cash += Decimal(event["realized_cash_delta"])
            available_cash -= Decimal(event["remaining_reserved_cash"])
            if event["side"] == "sell":
                code = event["code"]
                sellable[code] = sellable.get(code, 0) - int(
                    event["consumed_sellable_quantity"]
                ) - int(event["remaining_reserved_quantity"])
        return available_cash, dict(sorted(sellable.items()))

    def _append(self, identity: dict[str, Any]) -> dict[str, Any]:
        with self._lock():
            events, latest = self._load_chain()
            key = _identifier(identity["operation_key"], "operation_key")
            previous = latest.get(key)
            event_identity = {
                "schema": BROKER_ACCOUNT_RESERVATION_EVENT_SCHEMA,
                "sequence": len(events) + 1,
                "previous_event_sha256": (
                    events[-1]["event_sha256"] if events else None
                ),
                "previous_operation_event_sha256": (
                    previous["event_sha256"] if previous is not None else None
                ),
                **identity,
            }
            if previous is not None:
                if identity.get("status") == "RESERVED" and identity.get(
                    "source_lifecycle_event_sha256"
                ) is None:
                    immutable_fields = (
                        "account_fingerprint",
                        "account_snapshot_sha256",
                        "account_control_policy_sha256",
                        "operation_key",
                        "client_order_id",
                        "authorization_sha256",
                        "allocation_plan_sha256",
                        "parent_order_id",
                        "code",
                        "side",
                        "order_quantity",
                        "order_type",
                        "price_cap",
                        "fee_buffer_bps",
                        "initial_reserved_cash",
                        "initial_reserved_quantity",
                    )
                    mismatches = [
                        field
                        for field in immutable_fields
                        if identity.get(field) != previous.get(field)
                    ]
                    if mismatches:
                        raise BrokerAccountReservationConflict(
                            "operation conflicts with existing account reservation: "
                            + ", ".join(mismatches)
                        )
                    return {**dict(previous), "idempotent": True}
                comparable = {
                    field: value
                    for field, value in event_identity.items()
                    if field
                    not in {
                        "sequence",
                        "previous_event_sha256",
                        "previous_operation_event_sha256",
                        "recorded_at",
                    }
                }
                previous_comparable = {
                    field: value
                    for field, value in previous.items()
                    if field
                    not in {
                        "sequence",
                        "previous_event_sha256",
                        "previous_operation_event_sha256",
                        "recorded_at",
                        "event_sha256",
                    }
                }
                if comparable == previous_comparable:
                    return {**dict(previous), "idempotent": True}
            digest = sha256_digest(event_identity)
            event = {**event_identity, "event_sha256": digest}
            self._validate_event_semantics(previous, event)
            projected = {**latest, key: event}
            cash, positions = self._availability(projected)
            if cash < 0 or any(value < 0 for value in positions.values()):
                raise BrokerAccountReservationConflict(
                    "account reservation would overdraw cash or sellable position"
                )
            _immutable_json(self._event_path(event_identity["sequence"], digest), event)
            _atomic_json(
                self.head_path,
                {
                    "schema": BROKER_ACCOUNT_RESERVATION_HEAD_SCHEMA,
                    "sequence": event_identity["sequence"],
                    "event_sha256": digest,
                },
            )
            return {**event, "idempotent": False}

    def latest(self, operation_key: str) -> dict[str, Any] | None:
        _, latest = self._load_chain()
        value = latest.get(_identifier(operation_key, "operation_key"))
        return dict(value) if value is not None else None

    def event_by_sha256(self, event_sha256: str) -> dict[str, Any] | None:
        """Resolve one verified reservation event by its content address."""

        digest = _hash(event_sha256, "event_sha256")
        events, _ = self._load_chain()
        matches = [event for event in events if event["event_sha256"] == digest]
        if len(matches) > 1:
            raise BrokerAccountControlError(
                "account reservation event_sha256 is ambiguous"
            )
        return dict(matches[0]) if matches else None

    def latest_events(self) -> list[dict[str, Any]]:
        """Return the verified latest reservation state for every operation."""

        _, latest = self._load_chain()
        return [dict(latest[key]) for key in sorted(latest)]

    def reserve_order(
        self,
        plan_value: dict[str, Any],
        *,
        parent_order_id: str,
        operation_key: str,
        client_order_id: str,
        authorization_sha256: str,
        recorded_at: datetime,
    ) -> dict[str, Any]:
        try:
            plan = validate_parent_order_plan(plan_value)
        except OrderAllocationError as exc:
            raise BrokerAccountReservationConflict(
                f"account reservation plan is invalid: {exc}"
            ) from exc
        if (
            plan["account_fingerprint"] != self.account_fingerprint
            or plan["trade_date"] != self.trade_date
            or plan["authorization_sha256"] != authorization_sha256
        ):
            raise BrokerAccountReservationConflict(
                "account reservation plan differs from frozen account scope"
            )
        matches = [
            item
            for item in plan["parent_orders"]
            if item["parent_order_id"] == str(parent_order_id)
        ]
        if len(matches) != 1:
            raise BrokerAccountReservationConflict(
                "account reservation parent order is absent or ambiguous"
            )
        parent = matches[0]
        order_type = str(parent["order_type"])
        reference = Decimal(str(parent["reference_price"]))
        if order_type == "limit":
            price_cap = Decimal(str(parent["limit_price"]))
            fee_buffer_bps = int(self.policy["limit_order_fee_buffer_bps"])
        else:
            price_cap = reference * (
                Decimal("1")
                + Decimal(int(self.policy["market_order_price_buffer_bps"]))
                / Decimal("10000")
            )
            fee_buffer_bps = int(self.policy["market_order_fee_buffer_bps"])
        quantity = int(parent["quantity"])
        side = str(parent["side"])
        initial_cash = (
            _money_up(
                price_cap
                * quantity
                * (
                    Decimal("1")
                    + Decimal(fee_buffer_bps) / Decimal("10000")
                )
            )
            if side == "buy"
            else Decimal("0")
        )
        initial_quantity = quantity if side == "sell" else 0
        recorded_text, _ = _timestamp(recorded_at, "recorded_at")
        return self._append(
            {
                "recorded_at": recorded_text,
                "account_fingerprint": self.account_fingerprint,
                "account_snapshot_sha256": self.snapshot_sha256,
                "account_control_policy_sha256": self.policy["policy_sha256"],
                "operation_key": _identifier(operation_key, "operation_key"),
                "client_order_id": _identifier(client_order_id, "client_order_id"),
                "authorization_sha256": _hash(
                    authorization_sha256, "authorization_sha256"
                ),
                "allocation_plan_sha256": plan["allocation_plan_sha256"],
                "parent_order_id": _identifier(parent_order_id, "parent_order_id"),
                "code": _symbol(parent["code"]),
                "side": side,
                "order_quantity": quantity,
                "order_type": order_type,
                "price_cap": _decimal_text(price_cap, "price_cap", positive=True),
                "fee_buffer_bps": fee_buffer_bps,
                "initial_reserved_cash": _decimal_text(
                    initial_cash, "initial_reserved_cash"
                ),
                "initial_reserved_quantity": initial_quantity,
                "status": "RESERVED",
                "cumulative_filled_quantity": 0,
                "average_price": None,
                "cumulative_fee_fen": 0,
                "realized_cash_delta": "0",
                "consumed_sellable_quantity": 0,
                "remaining_reserved_cash": _decimal_text(
                    initial_cash, "remaining_reserved_cash"
                ),
                "remaining_reserved_quantity": initial_quantity,
                "source_lifecycle_event_sha256": None,
            }
        )

    def reconcile_lifecycle(self, lifecycle_event: dict[str, Any]) -> dict[str, Any]:
        operation_key = _identifier(
            lifecycle_event.get("operation_key"), "operation_key"
        )
        previous = self.latest(operation_key)
        if previous is None:
            raise BrokerAccountReservationConflict(
                "lifecycle event has no prior account reservation"
            )
        source_sha = _hash(
            lifecycle_event.get("event_sha256"), "lifecycle_event_sha256"
        )
        verified = self.journal.event_by_sha256(source_sha)
        supplied = {
            key: value
            for key, value in lifecycle_event.items()
            if key != "idempotent"
        }
        if verified is None or verified != supplied:
            raise BrokerAccountReservationConflict(
                "account reservation lifecycle source is not verified"
            )
        lifecycle_event = verified
        state = self._state_from_lifecycle(previous, lifecycle_event)
        recorded_text, _ = _timestamp(
            lifecycle_event["recorded_at"], "recorded_at"
        )
        identity = {
            key: value
            for key, value in previous.items()
            if key
            not in {
                "schema",
                "sequence",
                "previous_event_sha256",
                "previous_operation_event_sha256",
                "recorded_at",
                "status",
                "cumulative_filled_quantity",
                "average_price",
                "cumulative_fee_fen",
                "realized_cash_delta",
                "consumed_sellable_quantity",
                "remaining_reserved_cash",
                "remaining_reserved_quantity",
                "source_lifecycle_event_sha256",
                "event_sha256",
                "idempotent",
            }
        }
        return self._append(
            {
                "recorded_at": recorded_text,
                **identity,
                **state,
                "source_lifecycle_event_sha256": source_sha,
            }
        )

    def inspect(self) -> dict[str, Any]:
        try:
            stored_snapshot = validate_broker_account_snapshot(
                dict(_read_json(self.root / "account-snapshot.json"))
            )
            stored_policy = validate_broker_account_control_policy(
                dict(_read_json(self.root / "policy.json"))
            )
            if stored_snapshot != self.account_snapshot or stored_policy != self.policy:
                raise BrokerAccountControlError(
                    "stored account control inputs changed"
                )
            events, latest = self._load_chain()
            cash, positions = self._availability(latest)
            unresolved: list[str] = []
            pending_lifecycle: list[str] = []
            pending_reconciliation: list[str] = []
            operations: list[dict[str, Any]] = []
            for key, event in sorted(latest.items()):
                lifecycle = self.journal.latest(key)
                if event["status"] in {"UNKNOWN", "BREACHED"}:
                    unresolved.append(key)
                if lifecycle is None:
                    sync_status = "PENDING_LIFECYCLE"
                    pending_lifecycle.append(key)
                elif (
                    event["source_lifecycle_event_sha256"]
                    != lifecycle["event_sha256"]
                ):
                    sync_status = "PENDING_RECONCILIATION"
                    pending_reconciliation.append(key)
                else:
                    sync_status = "SYNCED"
                operations.append(
                    {
                        "operation_key": key,
                        "status": event["status"],
                        "sync_status": sync_status,
                        "code": event["code"],
                        "side": event["side"],
                        "remaining_reserved_cash": event[
                            "remaining_reserved_cash"
                        ],
                        "remaining_reserved_quantity": event[
                            "remaining_reserved_quantity"
                        ],
                        "event_sha256": event["event_sha256"],
                        "source_lifecycle_event_sha256": event[
                            "source_lifecycle_event_sha256"
                        ],
                        "latest_lifecycle_event_sha256": (
                            lifecycle["event_sha256"]
                            if lifecycle is not None
                            else None
                        ),
                    }
                )
            if unresolved:
                inspection_status = "UNRESOLVED"
            elif pending_reconciliation:
                inspection_status = "PENDING_RECONCILIATION"
            elif pending_lifecycle:
                inspection_status = "PENDING_LIFECYCLE"
            else:
                inspection_status = "READY"
            return {
                "schema": BROKER_ACCOUNT_RESERVATION_INSPECTION_SCHEMA,
                "status": inspection_status,
                "read_only_recommended": inspection_status != "READY",
                "error": None,
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "trade_date": self.trade_date,
                "account_snapshot_sha256": self.snapshot_sha256,
                "account_control_policy_sha256": self.policy["policy_sha256"],
                "event_count": len(events),
                "available_cash_after_reservations": _signed_decimal_text(
                    cash, "available_cash_after_reservations"
                ),
                "available_sellable_positions": positions,
                "unresolved_operation_keys": unresolved,
                "pending_lifecycle_operation_keys": pending_lifecycle,
                "pending_reconciliation_operation_keys": pending_reconciliation,
                "operations": operations,
            }
        except (
            BrokerAccountControlError,
            BrokerOrderJournalError,
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            return {
                "schema": BROKER_ACCOUNT_RESERVATION_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "read_only_recommended": True,
                "error": str(exc),
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "trade_date": self.trade_date,
                "account_snapshot_sha256": self.snapshot_sha256,
                "account_control_policy_sha256": self.policy["policy_sha256"],
                "event_count": 0,
                "available_cash_after_reservations": None,
                "available_sellable_positions": {},
                "unresolved_operation_keys": [],
                "pending_lifecycle_operation_keys": [],
                "pending_reconciliation_operation_keys": [],
                "operations": [],
            }
