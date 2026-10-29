"""Crash-safe, content-addressed lifecycle journal for parent broker orders.

The journal is deliberately vendor-neutral.  It records the submission intent
before an adapter call, then appends broker acknowledgements and cumulative
snapshots.  A process crash can therefore never turn an unknown prior outcome
into an unrecorded retry.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
import re
from typing import Any, Iterator

from .provenance import sha256_digest
from .order_allocation import (
    OrderAllocationError,
    allocate_parent_fill,
    validate_parent_order_plan,
)


BROKER_ORDER_EVENT_SCHEMA = "quant-core/broker-order-lifecycle-event/v1"
BROKER_ORDER_HEAD_SCHEMA = "quant-core/broker-order-lifecycle-head/v1"
BROKER_ORDER_INSPECTION_SCHEMA = "quant-core/broker-order-lifecycle-inspection/v1"
BROKER_FILL_SETTLEMENT_SCHEMA = "quant-core/broker-fill-settlement/v1"
BROKER_FILL_SETTLEMENT_HEAD_SCHEMA = "quant-core/broker-fill-settlement-head/v1"
BROKER_FILL_SETTLEMENT_INSPECTION_SCHEMA = (
    "quant-core/broker-fill-settlement-inspection/v1"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
TERMINAL_STATUSES = frozenset({"FILLED", "CANCELLED", "REJECTED"})
AMBIGUOUS_STATUSES = frozenset({"SUBMITTING", "UNKNOWN"})
VALID_STATUSES = frozenset(
    {
        "SUBMITTING",
        "ACCEPTED",
        "PARTIALLY_FILLED",
        "FILLED",
        "CANCEL_PENDING",
        "CANCELLED",
        "REJECTED",
        "UNKNOWN",
    }
)
EVENT_STATUS = {
    "SUBMISSION_PREPARED": {"SUBMITTING"},
    "BROKER_ACKNOWLEDGED": {"ACCEPTED", "REJECTED"},
    "SUBMISSION_UNKNOWN": {"UNKNOWN"},
    "BROKER_RECONCILED": {
        "ACCEPTED",
        "PARTIALLY_FILLED",
        "FILLED",
        "CANCEL_PENDING",
        "CANCELLED",
        "REJECTED",
        "UNKNOWN",
    },
    "CANCEL_REQUESTED": {"CANCEL_PENDING"},
    "CANCEL_UNKNOWN": {"UNKNOWN"},
}
TRANSITIONS = {
    None: {"SUBMITTING"},
    "SUBMITTING": {
        "ACCEPTED",
        "PARTIALLY_FILLED",
        "FILLED",
        "CANCELLED",
        "REJECTED",
        "UNKNOWN",
    },
    "UNKNOWN": {
        "ACCEPTED",
        "PARTIALLY_FILLED",
        "FILLED",
        "CANCEL_PENDING",
        "CANCELLED",
        "REJECTED",
        "UNKNOWN",
    },
    "ACCEPTED": {
        "PARTIALLY_FILLED",
        "FILLED",
        "CANCEL_PENDING",
        "CANCELLED",
        "UNKNOWN",
    },
    "PARTIALLY_FILLED": {
        "PARTIALLY_FILLED",
        "FILLED",
        "CANCEL_PENDING",
        "CANCELLED",
        "UNKNOWN",
    },
    "CANCEL_PENDING": {
        "CANCEL_PENDING",
        "PARTIALLY_FILLED",
        "FILLED",
        "CANCELLED",
        "UNKNOWN",
    },
    "FILLED": set(),
    "CANCELLED": set(),
    "REJECTED": set(),
}


class BrokerOrderJournalError(RuntimeError):
    """Raised when a broker order journal is corrupt or semantically unsafe."""


class BrokerOrderJournalConflict(BrokerOrderJournalError):
    """Raised when an operation identity or lifecycle transition conflicts."""


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None:
        raise BrokerOrderJournalError("broker lifecycle timestamp must include timezone")
    return value.astimezone(timezone.utc).isoformat()


def _decimal_text(value: Any, label: str, *, positive: bool = False) -> str:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise BrokerOrderJournalError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite() or (positive and parsed <= 0) or parsed < 0:
        raise BrokerOrderJournalError(f"{label} is invalid")
    return format(parsed.normalize(), "f")


def _quantity(value: Any, label: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not (
        isinstance(value, int)
        or (isinstance(value, str) and value.strip().isdigit())
    ):
        raise BrokerOrderJournalError(f"{label} must be an exact integer")
    result = int(value)
    if result < 0 or (result == 0 and not allow_zero):
        raise BrokerOrderJournalError(f"{label} is invalid")
    return result


def _hash(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    text = str(value or "").lower()
    if not SHA256_RE.fullmatch(text):
        raise BrokerOrderJournalError(f"{label} must be a sha256 digest")
    return text


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not ID_RE.fullmatch(text):
        raise BrokerOrderJournalError(f"{label} is invalid")
    return text


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
            raise BrokerOrderJournalConflict(
                f"immutable broker lifecycle record conflict: {path.name}"
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


class BrokerOrderJournal:
    """Append-only global and per-operation hash chains with atomic head."""

    def __init__(self, root: str | Path, *, account_fingerprint: str) -> None:
        self.root = Path(root).expanduser().resolve()
        self.account_fingerprint = str(account_fingerprint).strip()
        if not self.account_fingerprint or len(self.account_fingerprint) > 160:
            raise ValueError("account_fingerprint is invalid")

    @property
    def head_path(self) -> Path:
        return self.root / "head.json"

    @property
    def lock_path(self) -> Path:
        return self.root / ".journal.lock"

    @property
    def settlement_root(self) -> Path:
        return self.root / "fill-settlements"

    def _event_path(self, sequence: int, digest: str) -> Path:
        return self.root / "events" / f"{sequence:012d}-{digest}.json"

    def _settlement_plan_path(self, allocation_plan_sha256: str) -> Path:
        return self.settlement_root / "plans" / f"{allocation_plan_sha256}.json"

    def _settlement_operation_root(self, operation_key: str) -> Path:
        return self.settlement_root / "operations" / operation_key

    def _settlement_path(
        self, operation_key: str, sequence: int, digest: str
    ) -> Path:
        return (
            self._settlement_operation_root(operation_key)
            / "receipts"
            / f"{sequence:012d}-{digest}.json"
        )

    @staticmethod
    def _read_json(path: Path) -> Any:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {constant}")
            ),
        )

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+b")
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:  # pragma: no cover - production workspace is Windows
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            raise BrokerOrderJournalError(
                "broker lifecycle journal is locked by another process"
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

    @staticmethod
    def _validate_event_shape(event: dict[str, Any]) -> None:
        required = {
            "schema",
            "sequence",
            "previous_event_sha256",
            "previous_operation_event_sha256",
            "account_fingerprint",
            "recorded_at",
            "operation_key",
            "client_order_id",
            "authorization_sha256",
            "intent_sha256",
            "allocation_plan_sha256",
            "parent_order_id",
            "broker_order_id",
            "event_type",
            "status",
            "order_quantity",
            "cumulative_filled_quantity",
            "average_price",
            "cumulative_fee_fen",
            "event_sha256",
        }
        if set(event) != required or event.get("schema") != BROKER_ORDER_EVENT_SCHEMA:
            raise BrokerOrderJournalError(
                "broker lifecycle event fields do not match contract"
            )
        digest = str(event.get("event_sha256") or "")
        identity = {key: value for key, value in event.items() if key != "event_sha256"}
        if not SHA256_RE.fullmatch(digest) or sha256_digest(identity) != digest:
            raise BrokerOrderJournalError("broker lifecycle event hash mismatch")
        _quantity(event["sequence"], "sequence")
        _hash(
            event["previous_event_sha256"],
            "previous_event_sha256",
            nullable=True,
        )
        _hash(
            event["previous_operation_event_sha256"],
            "previous_operation_event_sha256",
            nullable=True,
        )
        _identifier(event["operation_key"], "operation_key")
        _identifier(event["client_order_id"], "client_order_id")
        _hash(event["authorization_sha256"], "authorization_sha256")
        _hash(event["intent_sha256"], "intent_sha256")
        _hash(event["allocation_plan_sha256"], "allocation_plan_sha256")
        _identifier(event["parent_order_id"], "parent_order_id")
        if event["broker_order_id"] is not None:
            _identifier(event["broker_order_id"], "broker_order_id")
        try:
            recorded_at = datetime.fromisoformat(str(event["recorded_at"]))
        except ValueError as exc:
            raise BrokerOrderJournalError(
                "broker lifecycle recorded_at is invalid"
            ) from exc
        if recorded_at.tzinfo is None:
            raise BrokerOrderJournalError(
                "broker lifecycle recorded_at must include timezone"
            )

    @staticmethod
    def _validate_transition(
        previous: dict[str, Any] | None, event: dict[str, Any]
    ) -> None:
        status = str(event["status"])
        event_type = str(event["event_type"])
        if status not in VALID_STATUSES or status not in EVENT_STATUS.get(event_type, set()):
            raise BrokerOrderJournalConflict("broker lifecycle event/status is invalid")
        previous_status = str(previous["status"]) if previous is not None else None
        if status not in TRANSITIONS[previous_status]:
            raise BrokerOrderJournalConflict(
                f"broker lifecycle transition is invalid: {previous_status} -> {status}"
            )
        quantity = _quantity(event["order_quantity"], "order_quantity")
        filled = _quantity(
            event["cumulative_filled_quantity"],
            "cumulative_filled_quantity",
            allow_zero=True,
        )
        fee_fen = _quantity(
            event["cumulative_fee_fen"], "cumulative_fee_fen", allow_zero=True
        )
        if filled > quantity:
            raise BrokerOrderJournalConflict("cumulative fill exceeds order quantity")
        if previous is not None:
            if int(previous["order_quantity"]) != quantity:
                raise BrokerOrderJournalConflict("order quantity changed within lifecycle")
            if filled < int(previous["cumulative_filled_quantity"]):
                raise BrokerOrderJournalConflict("cumulative fill quantity decreased")
            if fee_fen < int(previous["cumulative_fee_fen"]):
                raise BrokerOrderJournalConflict("cumulative fee decreased")
            for field in (
                "account_fingerprint",
                "operation_key",
                "client_order_id",
                "authorization_sha256",
                "intent_sha256",
                "allocation_plan_sha256",
                "parent_order_id",
            ):
                if event[field] != previous[field]:
                    raise BrokerOrderJournalConflict(
                        f"broker lifecycle identity changed: {field}"
                    )
            prior_broker_id = previous.get("broker_order_id")
            if prior_broker_id and event.get("broker_order_id") != prior_broker_id:
                raise BrokerOrderJournalConflict("broker_order_id changed")
            if datetime.fromisoformat(event["recorded_at"]) < datetime.fromisoformat(
                previous["recorded_at"]
            ):
                raise BrokerOrderJournalConflict("broker lifecycle time moved backwards")
        if status in {"SUBMITTING", "ACCEPTED", "REJECTED"} and filled != 0:
            raise BrokerOrderJournalConflict(f"{status} cannot contain a fill")
        if status == "PARTIALLY_FILLED" and not 0 < filled < quantity:
            raise BrokerOrderJournalConflict("partial-fill quantity is incoherent")
        if status == "FILLED" and filled != quantity:
            raise BrokerOrderJournalConflict("FILLED requires the complete quantity")
        average_price = event.get("average_price")
        if filled > 0:
            _decimal_text(average_price, "average_price", positive=True)
        elif average_price is not None:
            raise BrokerOrderJournalConflict("zero fill cannot contain average_price")
        if status in {"ACCEPTED", "PARTIALLY_FILLED", "FILLED", "CANCEL_PENDING", "CANCELLED"}:
            if not str(event.get("broker_order_id") or "").strip():
                raise BrokerOrderJournalConflict(f"{status} requires broker_order_id")

    def _load_chain(self) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
        paths = sorted((self.root / "events").glob("*.json"))
        if not self.head_path.exists():
            if paths:
                raise BrokerOrderJournalError(
                    "broker lifecycle head is missing while events exist"
                )
            return [], {}
        try:
            head = self._read_json(self.head_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrokerOrderJournalError(f"broker lifecycle head is unreadable: {exc}") from exc
        if set(head) != {"schema", "sequence", "event_sha256"} or head.get(
            "schema"
        ) != BROKER_ORDER_HEAD_SCHEMA:
            raise BrokerOrderJournalError("broker lifecycle head fields are invalid")
        if int(head.get("sequence") or 0) != len(paths):
            raise BrokerOrderJournalError(
                "broker lifecycle contains missing or orphan events"
            )
        events: list[dict[str, Any]] = []
        latest_by_operation: dict[str, dict[str, Any]] = {}
        previous_global: str | None = None
        for expected_sequence, path in enumerate(paths, start=1):
            try:
                event = dict(self._read_json(path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerOrderJournalError(
                    f"broker lifecycle event is unreadable: {path.name}: {exc}"
                ) from exc
            self._validate_event_shape(event)
            digest = str(event["event_sha256"])
            if path.name != self._event_path(expected_sequence, digest).name:
                raise BrokerOrderJournalError("broker lifecycle event filename mismatch")
            if int(event["sequence"]) != expected_sequence:
                raise BrokerOrderJournalError("broker lifecycle sequence is not contiguous")
            if event["previous_event_sha256"] != previous_global:
                raise BrokerOrderJournalError("broker lifecycle global hash chain broke")
            if event["account_fingerprint"] != self.account_fingerprint:
                raise BrokerOrderJournalError("broker lifecycle account mismatch")
            operation_key = str(event["operation_key"])
            previous_operation = latest_by_operation.get(operation_key)
            expected_previous_operation = (
                previous_operation["event_sha256"]
                if previous_operation is not None
                else None
            )
            if event["previous_operation_event_sha256"] != expected_previous_operation:
                raise BrokerOrderJournalError("broker lifecycle operation hash chain broke")
            self._validate_transition(previous_operation, event)
            latest_by_operation[operation_key] = event
            events.append(event)
            previous_global = digest
        if (
            int(head["sequence"]) != len(events)
            or head["event_sha256"] != events[-1]["event_sha256"]
        ):
            raise BrokerOrderJournalError("broker lifecycle head does not match chain tip")
        return events, latest_by_operation

    def inspect(self) -> dict[str, Any]:
        try:
            events, latest = self._load_chain()
            operations = [
                {
                    "operation_key": key,
                    "status": value["status"],
                    "broker_order_id": value["broker_order_id"],
                    "event_sha256": value["event_sha256"],
                }
                for key, value in sorted(latest.items())
            ]
            return {
                "schema": BROKER_ORDER_INSPECTION_SCHEMA,
                "status": "EMPTY" if not events else "READY",
                "read_only_recommended": False,
                "error": None,
                "event_count": len(events),
                "operations": operations,
                "ambiguous_operation_keys": sorted(
                    key
                    for key, value in latest.items()
                    if value["status"] in AMBIGUOUS_STATUSES
                ),
                "open_operation_keys": sorted(
                    key
                    for key, value in latest.items()
                    if value["status"] not in TERMINAL_STATUSES
                ),
                "head_event_sha256": events[-1]["event_sha256"] if events else None,
            }
        except (BrokerOrderJournalError, KeyError, TypeError, ValueError) as exc:
            return {
                "schema": BROKER_ORDER_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "read_only_recommended": True,
                "error": str(exc),
                "event_count": 0,
                "operations": [],
                "ambiguous_operation_keys": [],
                "open_operation_keys": [],
                "head_event_sha256": None,
            }

    def latest(self, operation_key: str) -> dict[str, Any] | None:
        _, latest = self._load_chain()
        value = latest.get(str(operation_key).strip())
        return dict(value) if value is not None else None

    def history(self, operation_key: str) -> list[dict[str, Any]]:
        """Return the verified lifecycle history for one durable operation."""

        key = _identifier(operation_key, "operation_key")
        events, _ = self._load_chain()
        return [dict(event) for event in events if event["operation_key"] == key]

    def event_by_sha256(self, event_sha256: str) -> dict[str, Any] | None:
        """Resolve a verified lifecycle event by its content address."""

        digest = _hash(event_sha256, "event_sha256")
        events, _ = self._load_chain()
        matches = [event for event in events if event["event_sha256"] == digest]
        if len(matches) > 1:
            raise BrokerOrderJournalConflict(
                "event_sha256 is ambiguous in lifecycle journal"
            )
        return dict(matches[0]) if matches else None

    def latest_for_broker_order_id(
        self, broker_order_id: str
    ) -> dict[str, Any] | None:
        _, latest = self._load_chain()
        matches = [
            value
            for value in latest.values()
            if value.get("broker_order_id") == str(broker_order_id).strip()
        ]
        if len(matches) > 1:
            raise BrokerOrderJournalConflict(
                "broker_order_id is ambiguous in lifecycle journal"
            )
        return dict(matches[0]) if matches else None

    def _append(
        self,
        *,
        event_type: str,
        status: str,
        recorded_at: datetime,
        operation_key: str,
        client_order_id: str,
        authorization_sha256: str,
        intent_sha256: str,
        allocation_plan_sha256: str,
        parent_order_id: str,
        broker_order_id: str | None,
        order_quantity: int,
        cumulative_filled_quantity: int,
        average_price: Any | None,
        cumulative_fee_fen: int,
    ) -> dict[str, Any]:
        with self._lock():
            events, latest = self._load_chain()
            key = _identifier(operation_key, "operation_key")
            previous_operation = latest.get(key)
            recorded_text = _utc_text(recorded_at)
            identity = {
                "schema": BROKER_ORDER_EVENT_SCHEMA,
                "sequence": len(events) + 1,
                "previous_event_sha256": (
                    events[-1]["event_sha256"] if events else None
                ),
                "previous_operation_event_sha256": (
                    previous_operation["event_sha256"]
                    if previous_operation is not None
                    else None
                ),
                "account_fingerprint": self.account_fingerprint,
                "recorded_at": recorded_text,
                "operation_key": key,
                "client_order_id": _identifier(client_order_id, "client_order_id"),
                "authorization_sha256": _hash(
                    authorization_sha256, "authorization_sha256"
                ),
                "intent_sha256": _hash(intent_sha256, "intent_sha256"),
                "allocation_plan_sha256": _hash(
                    allocation_plan_sha256, "allocation_plan_sha256"
                ),
                "parent_order_id": _identifier(parent_order_id, "parent_order_id"),
                "broker_order_id": (
                    _identifier(broker_order_id, "broker_order_id")
                    if broker_order_id is not None
                    else None
                ),
                "event_type": str(event_type),
                "status": str(status).upper(),
                "order_quantity": _quantity(order_quantity, "order_quantity"),
                "cumulative_filled_quantity": _quantity(
                    cumulative_filled_quantity,
                    "cumulative_filled_quantity",
                    allow_zero=True,
                ),
                "average_price": (
                    _decimal_text(average_price, "average_price", positive=True)
                    if average_price is not None
                    else None
                ),
                "cumulative_fee_fen": _quantity(
                    cumulative_fee_fen, "cumulative_fee_fen", allow_zero=True
                ),
            }
            if previous_operation is not None:
                comparable = {
                    key: value
                    for key, value in identity.items()
                    if key
                    not in {
                        "sequence",
                        "previous_event_sha256",
                        "previous_operation_event_sha256",
                        "recorded_at",
                        "event_type",
                    }
                }
                prior_comparable = {
                    key: value
                    for key, value in previous_operation.items()
                    if key
                    not in {
                        "sequence",
                        "previous_event_sha256",
                        "previous_operation_event_sha256",
                        "recorded_at",
                        "event_type",
                        "event_sha256",
                    }
                }
                if comparable == prior_comparable:
                    return {**dict(previous_operation), "idempotent": True}
            event_sha256 = sha256_digest(identity)
            event = {**identity, "event_sha256": event_sha256}
            self._validate_transition(previous_operation, event)
            _immutable_json(self._event_path(identity["sequence"], event_sha256), event)
            _atomic_json(
                self.head_path,
                {
                    "schema": BROKER_ORDER_HEAD_SCHEMA,
                    "sequence": identity["sequence"],
                    "event_sha256": event_sha256,
                },
            )
            return {**event, "idempotent": False}

    def prepare_submission(
        self,
        *,
        recorded_at: datetime,
        operation_key: str,
        client_order_id: str,
        authorization_sha256: str,
        intent_sha256: str,
        allocation_plan_sha256: str,
        parent_order_id: str,
        order_quantity: int,
    ) -> dict[str, Any]:
        return self._append(
            event_type="SUBMISSION_PREPARED",
            status="SUBMITTING",
            recorded_at=recorded_at,
            operation_key=operation_key,
            client_order_id=client_order_id,
            authorization_sha256=authorization_sha256,
            intent_sha256=intent_sha256,
            allocation_plan_sha256=allocation_plan_sha256,
            parent_order_id=parent_order_id,
            broker_order_id=None,
            order_quantity=order_quantity,
            cumulative_filled_quantity=0,
            average_price=None,
            cumulative_fee_fen=0,
        )

    def acknowledge_submission(
        self,
        operation_key: str,
        *,
        recorded_at: datetime,
        broker_order_id: str | None,
        accepted: bool,
    ) -> dict[str, Any]:
        previous = self.latest(operation_key)
        if previous is None:
            raise BrokerOrderJournalConflict("submission was not prepared")
        return self._append(
            event_type="BROKER_ACKNOWLEDGED",
            status="ACCEPTED" if accepted else "REJECTED",
            recorded_at=recorded_at,
            operation_key=operation_key,
            client_order_id=previous["client_order_id"],
            authorization_sha256=previous["authorization_sha256"],
            intent_sha256=previous["intent_sha256"],
            allocation_plan_sha256=previous["allocation_plan_sha256"],
            parent_order_id=previous["parent_order_id"],
            broker_order_id=broker_order_id,
            order_quantity=previous["order_quantity"],
            cumulative_filled_quantity=0,
            average_price=None,
            cumulative_fee_fen=0,
        )

    def mark_unknown(
        self,
        operation_key: str,
        *,
        recorded_at: datetime,
        event_type: str = "SUBMISSION_UNKNOWN",
    ) -> dict[str, Any]:
        previous = self.latest(operation_key)
        if previous is None:
            raise BrokerOrderJournalConflict("unknown outcome lacks prepared operation")
        return self._append(
            event_type=event_type,
            status="UNKNOWN",
            recorded_at=recorded_at,
            operation_key=operation_key,
            client_order_id=previous["client_order_id"],
            authorization_sha256=previous["authorization_sha256"],
            intent_sha256=previous["intent_sha256"],
            allocation_plan_sha256=previous["allocation_plan_sha256"],
            parent_order_id=previous["parent_order_id"],
            broker_order_id=previous["broker_order_id"],
            order_quantity=previous["order_quantity"],
            cumulative_filled_quantity=previous["cumulative_filled_quantity"],
            average_price=previous["average_price"],
            cumulative_fee_fen=previous["cumulative_fee_fen"],
        )

    def reconcile(
        self,
        operation_key: str,
        *,
        recorded_at: datetime,
        status: str,
        broker_order_id: str | None,
        cumulative_filled_quantity: int = 0,
        average_price: Any | None = None,
        cumulative_fee_fen: int = 0,
    ) -> dict[str, Any]:
        previous = self.latest(operation_key)
        if previous is None:
            raise BrokerOrderJournalConflict("broker snapshot lacks prepared operation")
        return self._append(
            event_type="BROKER_RECONCILED",
            status=str(status).upper(),
            recorded_at=recorded_at,
            operation_key=operation_key,
            client_order_id=previous["client_order_id"],
            authorization_sha256=previous["authorization_sha256"],
            intent_sha256=previous["intent_sha256"],
            allocation_plan_sha256=previous["allocation_plan_sha256"],
            parent_order_id=previous["parent_order_id"],
            broker_order_id=broker_order_id,
            order_quantity=previous["order_quantity"],
            cumulative_filled_quantity=cumulative_filled_quantity,
            average_price=average_price,
            cumulative_fee_fen=cumulative_fee_fen,
        )

    def request_cancel(
        self, broker_order_id: str, *, recorded_at: datetime
    ) -> dict[str, Any]:
        _, latest = self._load_chain()
        matches = [
            value
            for value in latest.values()
            if value.get("broker_order_id") == str(broker_order_id)
        ]
        if len(matches) != 1:
            raise BrokerOrderJournalConflict(
                "broker_order_id is absent or ambiguous in lifecycle journal"
            )
        previous = matches[0]
        if previous["status"] not in {"ACCEPTED", "PARTIALLY_FILLED"}:
            raise BrokerOrderJournalConflict(
                f"cancel is invalid from lifecycle status {previous['status']}"
            )
        return self._append(
            event_type="CANCEL_REQUESTED",
            status="CANCEL_PENDING",
            recorded_at=recorded_at,
            operation_key=previous["operation_key"],
            client_order_id=previous["client_order_id"],
            authorization_sha256=previous["authorization_sha256"],
            intent_sha256=previous["intent_sha256"],
            allocation_plan_sha256=previous["allocation_plan_sha256"],
            parent_order_id=previous["parent_order_id"],
            broker_order_id=previous["broker_order_id"],
            order_quantity=previous["order_quantity"],
            cumulative_filled_quantity=previous["cumulative_filled_quantity"],
            average_price=previous["average_price"],
            cumulative_fee_fen=previous["cumulative_fee_fen"],
        )

    @staticmethod
    def _lifecycle_broker_fill(event: dict[str, Any]) -> dict[str, Any]:
        status = str(event["status"])
        filled = int(event["cumulative_filled_quantity"])
        quantity = int(event["order_quantity"])
        if status in {"ACCEPTED", "CANCEL_PENDING"}:
            if filled == 0:
                allocation_status = "OPEN"
            elif filled == quantity:
                allocation_status = "FILLED"
            else:
                allocation_status = "PARTIALLY_FILLED"
        elif status == "PARTIALLY_FILLED":
            allocation_status = "PARTIALLY_FILLED"
        elif status == "FILLED":
            allocation_status = "FILLED"
        elif status == "CANCELLED":
            allocation_status = "CANCELLED"
        else:
            raise BrokerOrderJournalConflict(
                f"lifecycle status cannot be settled: {status}"
            )
        broker_order_id = str(event.get("broker_order_id") or "")
        if not broker_order_id:
            raise BrokerOrderJournalConflict(
                "settleable lifecycle event lacks broker_order_id"
            )
        return {
            "broker_order_id": broker_order_id,
            "parent_order_id": event["parent_order_id"],
            "filled_quantity": filled,
            "average_price": event["average_price"],
            "fee_fen": int(event["cumulative_fee_fen"]),
            "as_of_time": event["recorded_at"],
            "status": allocation_status,
        }

    def _load_settlement_chain(
        self,
        *,
        plan: dict[str, Any],
        operation_key: str,
        lifecycle_events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        operation_root = self._settlement_operation_root(operation_key)
        head_path = operation_root / "head.json"
        paths = sorted((operation_root / "receipts").glob("*.json"))
        if not head_path.exists():
            if paths:
                raise BrokerOrderJournalError(
                    "fill settlement head is missing while receipts exist"
                )
            return []
        try:
            head = self._read_json(head_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrokerOrderJournalError(
                f"fill settlement head is unreadable: {exc}"
            ) from exc
        if set(head) != {
            "schema",
            "sequence",
            "settlement_sha256",
            "allocation_plan_sha256",
        } or head.get("schema") != BROKER_FILL_SETTLEMENT_HEAD_SCHEMA:
            raise BrokerOrderJournalError("fill settlement head fields are invalid")
        if head["allocation_plan_sha256"] != plan["allocation_plan_sha256"]:
            raise BrokerOrderJournalError("fill settlement head plan hash mismatch")
        if int(head.get("sequence") or 0) != len(paths):
            raise BrokerOrderJournalError(
                "fill settlement contains missing or orphan receipts"
            )
        lifecycle_by_hash = {
            event["event_sha256"]: event for event in lifecycle_events
        }
        receipts: list[dict[str, Any]] = []
        previous_settlement_sha: str | None = None
        previous_allocation: dict[str, Any] | None = None
        previous_lifecycle_sequence = 0
        required = {
            "schema",
            "sequence",
            "previous_settlement_sha256",
            "account_fingerprint",
            "operation_key",
            "source_lifecycle_event_sha256",
            "allocation_plan_sha256",
            "parent_order_id",
            "fill_allocation",
            "settlement_sha256",
        }
        for expected_sequence, path in enumerate(paths, start=1):
            try:
                receipt = dict(self._read_json(path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerOrderJournalError(
                    f"fill settlement receipt is unreadable: {path.name}: {exc}"
                ) from exc
            if set(receipt) != required or receipt.get(
                "schema"
            ) != BROKER_FILL_SETTLEMENT_SCHEMA:
                raise BrokerOrderJournalError(
                    "fill settlement receipt fields are invalid"
                )
            digest = str(receipt.get("settlement_sha256") or "")
            identity = {
                key: value
                for key, value in receipt.items()
                if key != "settlement_sha256"
            }
            if not SHA256_RE.fullmatch(digest) or sha256_digest(identity) != digest:
                raise BrokerOrderJournalError("fill settlement hash mismatch")
            if path.name != self._settlement_path(
                operation_key, expected_sequence, digest
            ).name:
                raise BrokerOrderJournalError("fill settlement filename mismatch")
            if (
                receipt["sequence"] != expected_sequence
                or receipt["previous_settlement_sha256"]
                != previous_settlement_sha
                or receipt["account_fingerprint"] != self.account_fingerprint
                or receipt["operation_key"] != operation_key
                or receipt["allocation_plan_sha256"]
                != plan["allocation_plan_sha256"]
            ):
                raise BrokerOrderJournalError("fill settlement chain identity broke")
            lifecycle = lifecycle_by_hash.get(
                receipt["source_lifecycle_event_sha256"]
            )
            if lifecycle is None or lifecycle["operation_key"] != operation_key:
                raise BrokerOrderJournalError(
                    "fill settlement source lifecycle event is absent"
                )
            if int(lifecycle["sequence"]) <= previous_lifecycle_sequence:
                raise BrokerOrderJournalError(
                    "fill settlement lifecycle source moved backwards"
                )
            if receipt["parent_order_id"] != lifecycle["parent_order_id"]:
                raise BrokerOrderJournalError(
                    "fill settlement parent order identity mismatch"
                )
            try:
                expected_allocation = allocate_parent_fill(
                    plan,
                    self._lifecycle_broker_fill(lifecycle),
                    previous_allocation=previous_allocation,
                )
            except (OrderAllocationError, BrokerOrderJournalError) as exc:
                raise BrokerOrderJournalError(
                    f"fill settlement cannot be reproduced: {exc}"
                ) from exc
            if receipt["fill_allocation"] != expected_allocation:
                raise BrokerOrderJournalError(
                    "fill settlement allocation is not reproducible"
                )
            receipts.append(receipt)
            previous_settlement_sha = digest
            previous_allocation = expected_allocation
            previous_lifecycle_sequence = int(lifecycle["sequence"])
        if (
            head["sequence"] != len(receipts)
            or head["settlement_sha256"] != receipts[-1]["settlement_sha256"]
        ):
            raise BrokerOrderJournalError(
                "fill settlement head does not match chain tip"
            )
        return receipts

    def settle_latest_parent_fill(
        self,
        plan_value: dict[str, Any],
        operation_key: str,
    ) -> dict[str, Any]:
        """Persist the latest settleable lifecycle snapshot as a child allocation."""

        try:
            plan = validate_parent_order_plan(plan_value)
        except OrderAllocationError as exc:
            raise BrokerOrderJournalConflict(
                f"parent fill settlement plan is invalid: {exc}"
            ) from exc
        key = _identifier(operation_key, "operation_key")
        with self._lock():
            lifecycle_events, latest_by_operation = self._load_chain()
            lifecycle = latest_by_operation.get(key)
            if lifecycle is None:
                raise BrokerOrderJournalConflict(
                    "parent fill settlement lacks lifecycle operation"
                )
            if (
                lifecycle["allocation_plan_sha256"]
                != plan["allocation_plan_sha256"]
                or lifecycle["account_fingerprint"] != plan["account_fingerprint"]
            ):
                raise BrokerOrderJournalConflict(
                    "parent fill settlement plan differs from lifecycle identity"
                )
            parent_matches = [
                item
                for item in plan["parent_orders"]
                if item["parent_order_id"] == lifecycle["parent_order_id"]
            ]
            if (
                len(parent_matches) != 1
                or int(parent_matches[0]["quantity"])
                != int(lifecycle["order_quantity"])
            ):
                raise BrokerOrderJournalConflict(
                    "parent fill settlement order differs from lifecycle quantity"
                )
            self._lifecycle_broker_fill(lifecycle)
            _immutable_json(
                self._settlement_plan_path(plan["allocation_plan_sha256"]), plan
            )
            receipts = self._load_settlement_chain(
                plan=plan,
                operation_key=key,
                lifecycle_events=lifecycle_events,
            )
            if (
                receipts
                and receipts[-1]["source_lifecycle_event_sha256"]
                == lifecycle["event_sha256"]
            ):
                return {**dict(receipts[-1]), "idempotent": True}
            previous_allocation = (
                dict(receipts[-1]["fill_allocation"]) if receipts else None
            )
            try:
                allocation = allocate_parent_fill(
                    plan,
                    self._lifecycle_broker_fill(lifecycle),
                    previous_allocation=previous_allocation,
                )
            except OrderAllocationError as exc:
                raise BrokerOrderJournalConflict(
                    f"parent fill allocation failed: {exc}"
                ) from exc
            identity = {
                "schema": BROKER_FILL_SETTLEMENT_SCHEMA,
                "sequence": len(receipts) + 1,
                "previous_settlement_sha256": (
                    receipts[-1]["settlement_sha256"] if receipts else None
                ),
                "account_fingerprint": self.account_fingerprint,
                "operation_key": key,
                "source_lifecycle_event_sha256": lifecycle["event_sha256"],
                "allocation_plan_sha256": plan["allocation_plan_sha256"],
                "parent_order_id": lifecycle["parent_order_id"],
                "fill_allocation": allocation,
            }
            digest = sha256_digest(identity)
            receipt = {**identity, "settlement_sha256": digest}
            _immutable_json(
                self._settlement_path(key, identity["sequence"], digest), receipt
            )
            _atomic_json(
                self._settlement_operation_root(key) / "head.json",
                {
                    "schema": BROKER_FILL_SETTLEMENT_HEAD_SCHEMA,
                    "sequence": identity["sequence"],
                    "settlement_sha256": digest,
                    "allocation_plan_sha256": plan["allocation_plan_sha256"],
                },
            )
            return {**receipt, "idempotent": False}

    def settle_latest_parent_fill_for_operation(
        self, operation_key: str
    ) -> dict[str, Any]:
        key = _identifier(operation_key, "operation_key")
        head_path = self._settlement_operation_root(key) / "head.json"
        try:
            head = dict(self._read_json(head_path))
            plan_sha = _hash(
                head.get("allocation_plan_sha256"),
                "allocation_plan_sha256",
            )
            plan = dict(self._read_json(self._settlement_plan_path(plan_sha)))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrokerOrderJournalError(
                "fill settlement plan cannot be recovered for operation"
            ) from exc
        return self.settle_latest_parent_fill(plan, key)

    def fill_settlement_history(
        self, operation_key: str
    ) -> list[dict[str, Any]]:
        """Return the verified settlement chain for one durable operation."""

        key = _identifier(operation_key, "operation_key")
        head_path = self._settlement_operation_root(key) / "head.json"
        if not head_path.exists():
            return []
        try:
            head = dict(self._read_json(head_path))
            plan_sha = _hash(
                head.get("allocation_plan_sha256"),
                "allocation_plan_sha256",
            )
            plan = validate_parent_order_plan(
                dict(self._read_json(self._settlement_plan_path(plan_sha)))
            )
            lifecycle_events, _ = self._load_chain()
            receipts = self._load_settlement_chain(
                plan=plan,
                operation_key=key,
                lifecycle_events=lifecycle_events,
            )
        except (OSError, json.JSONDecodeError, ValueError, OrderAllocationError) as exc:
            raise BrokerOrderJournalError(
                "fill settlement history cannot be recovered for operation"
            ) from exc
        return [dict(receipt) for receipt in receipts]

    def fill_settlement_by_sha256(
        self, operation_key: str, settlement_sha256: str
    ) -> dict[str, Any] | None:
        """Resolve a verified settlement receipt by its content address."""

        digest = _hash(settlement_sha256, "settlement_sha256")
        matches = [
            receipt
            for receipt in self.fill_settlement_history(operation_key)
            if receipt["settlement_sha256"] == digest
        ]
        if len(matches) > 1:
            raise BrokerOrderJournalConflict(
                "settlement_sha256 is ambiguous in fill settlement chain"
            )
        return dict(matches[0]) if matches else None

    def inspect_fill_settlements(self) -> dict[str, Any]:
        try:
            lifecycle_events, _ = self._load_chain()
            operations_root = self.settlement_root / "operations"
            operation_roots = sorted(
                path for path in operations_root.glob("*") if path.is_dir()
            )
            operations: list[dict[str, Any]] = []
            total_receipts = 0
            for operation_root in operation_roots:
                key = _identifier(operation_root.name, "operation_key")
                head = self._read_json(operation_root / "head.json")
                plan_sha = _hash(
                    head.get("allocation_plan_sha256"),
                    "allocation_plan_sha256",
                )
                plan = dict(self._read_json(self._settlement_plan_path(plan_sha)))
                receipts = self._load_settlement_chain(
                    plan=validate_parent_order_plan(plan),
                    operation_key=key,
                    lifecycle_events=lifecycle_events,
                )
                total_receipts += len(receipts)
                operations.append(
                    {
                        "operation_key": key,
                        "receipt_count": len(receipts),
                        "status": receipts[-1]["fill_allocation"]["status"],
                        "settlement_sha256": receipts[-1]["settlement_sha256"],
                    }
                )
            return {
                "schema": BROKER_FILL_SETTLEMENT_INSPECTION_SCHEMA,
                "status": "EMPTY" if not operations else "READY",
                "read_only_recommended": False,
                "error": None,
                "receipt_count": total_receipts,
                "operations": operations,
            }
        except (
            BrokerOrderJournalError,
            OrderAllocationError,
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            return {
                "schema": BROKER_FILL_SETTLEMENT_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "read_only_recommended": True,
                "error": str(exc),
                "receipt_count": 0,
                "operations": [],
            }
