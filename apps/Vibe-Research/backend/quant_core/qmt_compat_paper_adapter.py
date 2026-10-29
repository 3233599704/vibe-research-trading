"""Durable QMT-shaped adapter for an offline PAPER compatibility rehearsal.

This module deliberately does not import, discover, or emulate the vendor runtime.
It consumes explicitly injected callback-shaped dictionaries so the platform can
exercise asynchronous order lifecycle and recovery semantics without a broker,
account, credential, network connection, or real-order capability.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
from threading import RLock
from typing import Any, BinaryIO, Callable

from .broker import BrokerCapability, BrokerPermissionError


QMT_COMPAT_CONFIG_SCHEMA = "quant-core/qmt-compat-paper-config/v1"
QMT_COMPAT_EVENT_SCHEMA = "quant-core/qmt-compat-paper-event/v2"
QMT_COMPAT_HEAD_SCHEMA = "quant-core/qmt-compat-paper-head/v2"
QMT_COMPAT_SNAPSHOT_SCHEMA = "quant-core/qmt-compat-paper-snapshot/v2"
_ZERO_HASH = "0" * 64
_TERMINAL = frozenset({"FILLED", "CANCELLED", "REJECTED"})
_EVENT_KEYS = frozenset(
    {
        "schema",
        "sequence",
        "recorded_at",
        "event_type",
        "previous_event_sha256",
        "payload",
        "real_orders",
        "config_sha256",
        "event_sha256",
    }
)
_HEAD_KEYS = frozenset(
    {"schema", "sequence", "event_sha256", "config_sha256", "real_orders"}
)
_CONFIG_KEYS = frozenset(
    {"schema", "adapter_id", "adapter_version", "initial_cash", "currency", "real_orders"}
)
_INTENT_KEYS = frozenset(
    {"code", "side", "quantity", "order_type", "limit_price", "reference_price"}
)
_DURABLE_BLOCKERS = frozenset(
    {
        "ADAPTER_CLOSED",
        "DURABLE_EVENT_CHAIN_CORRUPT",
        "DURABLE_CONFIG_CORRUPT",
        "DURABLE_CONFIG_DRIFT",
        "DURABLE_CONFIG_MISSING",
        "DURABLE_CONFIG_TEMPORARY_PRESENT",
        "DURABLE_HEAD_TEMPORARY_PRESENT",
        "DURABLE_WRITE_FAILED",
    }
)


class QmtCompatPaperError(RuntimeError):
    """Base error for the compatibility adapter."""


class QmtCompatPaperConflict(QmtCompatPaperError):
    """A stable identity or callback sequence was reused with other content."""


class QmtCompatPaperDegraded(QmtCompatPaperError):
    """Mutation was rejected because durable state is incomplete or corrupt."""


class _TransitionRejected(QmtCompatPaperConflict):
    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


def _validate_unicode_scalars(value: Any, active: set[int] | None = None) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise QmtCompatPaperError("canonical data contains a lone surrogate")
        return
    if isinstance(value, Mapping):
        marker = id(value)
        active = set() if active is None else active
        if marker in active:
            raise QmtCompatPaperError("canonical data contains a reference cycle")
        active.add(marker)
        try:
            for key, item in value.items():
                if not isinstance(key, str):
                    raise QmtCompatPaperError("canonical object keys must be strings")
                _validate_unicode_scalars(key, active)
                _validate_unicode_scalars(item, active)
        finally:
            active.remove(marker)
        return
    if isinstance(value, (list, tuple)):
        marker = id(value)
        active = set() if active is None else active
        if marker in active:
            raise QmtCompatPaperError("canonical data contains a reference cycle")
        active.add(marker)
        try:
            for item in value:
                _validate_unicode_scalars(item, active)
        finally:
            active.remove(marker)


def _canonical_bytes(value: Any) -> bytes:
    try:
        _validate_unicode_scalars(value)
        return (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
    except QmtCompatPaperError:
        raise
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise QmtCompatPaperError("value cannot be canonicalized") from exc


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_canonical_object(raw: bytes) -> dict[str, Any]:
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
    except QmtCompatPaperError:
        raise
    except (UnicodeError, ValueError, TypeError, OverflowError, RecursionError) as exc:
        raise QmtCompatPaperError("canonical JSON cannot be parsed") from exc
    if not isinstance(parsed, dict) or _canonical_bytes(parsed) != raw:
        raise QmtCompatPaperError("JSON is not a canonical object")
    return parsed


def _read_canonical_object(path: Path) -> dict[str, Any]:
    return _parse_canonical_object(path.read_bytes())


def _exact_int(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool):
        raise QmtCompatPaperError(f"{field} must be an exact integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value and all("0" <= item <= "9" for item in value):
        try:
            parsed = int(value)
        except (ValueError, OverflowError) as exc:
            raise QmtCompatPaperError(f"{field} must be an exact integer") from exc
    else:
        raise QmtCompatPaperError(f"{field} must be an exact integer")
    if parsed < minimum:
        raise QmtCompatPaperError(f"{field} is below its minimum")
    return parsed


def _decimal(value: Any, field: str, *, positive: bool = False) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise QmtCompatPaperError(f"{field} must be a finite decimal") from exc
    if not parsed.is_finite() or (positive and parsed <= 0) or (not positive and parsed < 0):
        raise QmtCompatPaperError(f"{field} must be a valid decimal")
    return parsed


def _canonical_decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return "0" if text in {"", "-0"} else text


def _nonempty_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise QmtCompatPaperError(f"{field} must be a non-empty canonical string")
    _validate_unicode_scalars(value)
    return value


def _exact_keys(value: dict[str, Any], keys: frozenset[str], field: str) -> None:
    if set(value) != keys:
        raise QmtCompatPaperError(f"{field} fields are not exact")


class QmtCompatPaperAdapter:
    """Offline BrokerAdapter with a single-writer durable callback journal.

    A process-scoped OS lock is held for the adapter lifetime.  Order mutation
    and callback draining use different gates: a callback may close a sequence
    gap or reconnect a disconnected session, while submissions and cancels are
    denied without writing whenever any degraded condition is present.
    """

    adapter_id = "qmt-compat-sandbox"
    adapter_version = "1.2.0"
    implementation_fingerprint = hashlib.sha256(
        b"quant-core/qmt-compat-paper-adapter/v1.2"
    ).hexdigest()
    environment = "offline-paper-sandbox"
    account_fingerprint = "offline-qmt-compat-no-account"

    def __init__(
        self,
        root: Path | str,
        *,
        initial_cash: str | int | Decimal = "100000",
        clock: Callable[[], str] | None = None,
    ) -> None:
        self.root = Path(root)
        self._events_dir = self.root / "events"
        self._config_path = self.root / "config.json"
        self._config_temporary_path = self.root / "config.json.tmp"
        self._head_path = self.root / "head.json"
        self._head_temporary_path = self.root / "head.json.tmp"
        self._lock_path = self.root / ".adapter.lock"
        self._initial_cash = _decimal(initial_cash, "initial_cash", positive=True)
        self._initial_cash_text = _canonical_decimal_text(self._initial_cash)
        self._clock = clock or (lambda: "1970-01-01T00:00:00+00:00")
        self._mutex = RLock()
        self._lock_handle: BinaryIO | None = None
        self._closed = False
        self._head_sequence = 0
        self._head_hash = _ZERO_HASH
        self._callback_next = 1
        self._callback_seen: dict[int, str] = {}
        self._callback_buffer: dict[int, tuple[str, dict[str, Any], str]] = {}
        self._connection_epoch = 0
        self._connected = True
        self._orders: dict[str, dict[str, Any]] = {}
        self._client_to_order: dict[str, str] = {}
        self._trade_hashes: dict[str, str] = {}
        self._daily_usage: dict[str, dict[str, Any]] = {}
        self._quarantines: dict[str, dict[str, Any]] = {}
        self._degraded_reasons: set[str] = set()
        self._config_sha256: str | None = None
        self.root.mkdir(parents=True, exist_ok=True)
        self._acquire_process_lock()
        try:
            self._events_dir.mkdir(parents=True, exist_ok=True)
            self._load_or_create_config()
            if not (self._degraded_reasons & _DURABLE_BLOCKERS):
                self._recover()
            if not (self._degraded_reasons & _DURABLE_BLOCKERS):
                try:
                    self._drain_buffered()
                except QmtCompatPaperDegraded:
                    pass
        except Exception:
            self.close()
            raise

    def _acquire_process_lock(self) -> None:
        handle = self._lock_path.open("a+b")
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
            os.fsync(handle.fileno())
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
            raise QmtCompatPaperDegraded(
                "QMT compatibility adapter root is locked by another process"
            ) from exc
        self._lock_handle = handle

    def close(self) -> None:
        with self._mutex:
            handle = self._lock_handle
            if handle is None:
                self._closed = True
                return
            try:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:  # pragma: no cover
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()
                self._lock_handle = None
                self._closed = True
                self._degraded_reasons.add("ADAPTER_CLOSED")

    def __enter__(self) -> "QmtCompatPaperAdapter":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        del exc_type, exc, traceback
        self.close()

    def __del__(self) -> None:  # pragma: no cover - explicit close is required
        try:
            self.close()
        except Exception:
            pass

    def capabilities(self) -> set[str]:
        return {
            BrokerCapability.ACCOUNT_READ.value,
            BrokerCapability.POSITIONS_READ.value,
            BrokerCapability.ORDERS_READ.value,
            BrokerCapability.PAPER_ORDER.value,
            BrokerCapability.CANCEL_ORDER.value,
            BrokerCapability.CLIENT_ORDER_IDEMPOTENCY.value,
            BrokerCapability.DAILY_USAGE_READ.value,
            BrokerCapability.ATOMIC_ACCOUNT_SNAPSHOT_READ.value,
        }

    @property
    def is_degraded(self) -> bool:
        return bool(self._degraded_reasons)

    def status(self) -> dict[str, Any]:
        with self._mutex:
            if not self._closed and self._config_sha256 is not None:
                try:
                    self._verify_config_identity()
                except QmtCompatPaperDegraded:
                    pass
            result = {
                "adapter_id": self.adapter_id,
                "mode": "CLOSED" if self._closed else ("DEGRADED" if self.is_degraded else "READY"),
                "connected": self._connected,
                "connection_epoch": self._connection_epoch,
                "callback_next_sequence": self._callback_next,
                "buffered_sequences": sorted(self._callback_buffer),
                "degraded_reasons": sorted(self._degraded_reasons),
                "active_quarantines": [
                    deepcopy(self._quarantines[key])
                    for key in sorted(self._quarantines)
                ],
                "event_cut": {
                    "sequence": self._head_sequence,
                    "event_sha256": self._head_hash,
                    "config_sha256": self._config_sha256,
                },
                "real_orders": False,
                "qmt_runtime_accessed": False,
            }
            if not self._closed and self._config_sha256 is not None:
                try:
                    self._verify_config_identity()
                except QmtCompatPaperDegraded:
                    result["mode"] = "DEGRADED"
                    result["degraded_reasons"] = sorted(self._degraded_reasons)
            return result

    def _require_open(self) -> None:
        if self._closed or self._lock_handle is None:
            raise QmtCompatPaperDegraded("QMT compatibility adapter is closed")

    def _require_durable_writable(self) -> None:
        self._require_open()
        self._verify_config_identity()
        blockers = self._degraded_reasons & _DURABLE_BLOCKERS
        if blockers:
            raise QmtCompatPaperDegraded(
                "adapter durable state is degraded: " + ",".join(sorted(blockers))
            )

    def _require_order_mutation_allowed(self) -> None:
        self._require_durable_writable()
        if not self._connected:
            raise QmtCompatPaperDegraded("adapter is disconnected")
        if self._degraded_reasons:
            raise QmtCompatPaperDegraded(
                "adapter state is degraded: "
                + ",".join(sorted(self._degraded_reasons))
            )

    def _write_atomic(self, path: Path, payload: bytes) -> None:
        temporary = path.with_name(path.name + ".tmp")
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)

    def _expected_config(self) -> dict[str, Any]:
        return {
            "schema": QMT_COMPAT_CONFIG_SCHEMA,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "initial_cash": self._initial_cash_text,
            "currency": "CNY",
            "real_orders": False,
        }

    def _load_or_create_config(self) -> None:
        if self._config_temporary_path.exists():
            self._degraded_reasons.add("DURABLE_CONFIG_TEMPORARY_PRESENT")
            return
        expected = self._expected_config()
        if self._config_path.exists():
            try:
                raw = self._config_path.read_bytes()
                config = _parse_canonical_object(raw)
                if set(config) != _CONFIG_KEYS:
                    raise ValueError("config fields are not exact")
            except Exception:
                self._degraded_reasons.add("DURABLE_CONFIG_CORRUPT")
                return
            if config != expected:
                raise QmtCompatPaperDegraded(
                    "QMT compatibility adapter initial_cash or config identity differs from durable genesis"
                )
            self._config_sha256 = hashlib.sha256(raw).hexdigest()
            return
        if self._head_path.exists() or any(self._events_dir.iterdir()):
            self._degraded_reasons.add("DURABLE_CONFIG_MISSING")
            return
        payload = _canonical_bytes(expected)
        try:
            self._write_atomic(self._config_path, payload)
        except Exception as exc:
            self._degraded_reasons.add("DURABLE_WRITE_FAILED")
            raise QmtCompatPaperDegraded(
                "durable QMT compatibility config write failed"
            ) from exc
        self._config_sha256 = hashlib.sha256(payload).hexdigest()

    def _verify_config_identity(self) -> None:
        try:
            raw = self._config_path.read_bytes()
            config = _parse_canonical_object(raw)
            digest = hashlib.sha256(raw).hexdigest()
            if (
                set(config) != _CONFIG_KEYS
                or config != self._expected_config()
                or self._config_sha256 is None
                or digest != self._config_sha256
            ):
                raise QmtCompatPaperError("durable config identity mismatch")
        except Exception as exc:
            self._degraded_reasons.add("DURABLE_CONFIG_DRIFT")
            raise QmtCompatPaperDegraded(
                "durable QMT compatibility config identity drifted"
            ) from exc

    def _append_prevalidated(
        self,
        event_type: str,
        payload: dict[str, Any],
        transition: dict[str, Any],
    ) -> dict[str, Any]:
        self._require_durable_writable()
        sequence = self._head_sequence + 1
        base = {
            "schema": QMT_COMPAT_EVENT_SCHEMA,
            "sequence": sequence,
            "recorded_at": _nonempty_text(self._clock(), "recorded_at"),
            "event_type": event_type,
            "previous_event_sha256": self._head_hash,
            "payload": deepcopy(payload),
            "real_orders": False,
            "config_sha256": self._config_sha256,
        }
        event = {**base, "event_sha256": _digest(base)}
        event_path = self._events_dir / f"{sequence:020d}.json"
        head = {
            "schema": QMT_COMPAT_HEAD_SCHEMA,
            "sequence": sequence,
            "event_sha256": event["event_sha256"],
            "config_sha256": self._config_sha256,
            "real_orders": False,
        }
        try:
            with event_path.open("xb") as handle:
                handle.write(_canonical_bytes(event))
                handle.flush()
                os.fsync(handle.fileno())
            self._write_atomic(self._head_path, _canonical_bytes(head))
        except Exception as exc:
            self._degraded_reasons.add("DURABLE_WRITE_FAILED")
            raise QmtCompatPaperDegraded(
                "durable QMT compatibility event write failed"
            ) from exc
        self._verify_config_identity()
        self._head_sequence = sequence
        self._head_hash = event["event_sha256"]
        self._apply_transition(transition)
        return event

    def _recover(self) -> None:
        if self._head_temporary_path.exists():
            self._degraded_reasons.add("DURABLE_HEAD_TEMPORARY_PRESENT")
            return
        replay = _RecoveryReplica.from_adapter(self)
        try:
            entries = sorted(self._events_dir.iterdir(), key=lambda item: item.name)
            if any(
                not item.is_file()
                or len(item.name) != 25
                or not item.name.endswith(".json")
                or not item.name[:20].isdigit()
                for item in entries
            ):
                raise ValueError("event directory contains an unexpected entry")
            previous = _ZERO_HASH
            expected = 1
            for path in entries:
                event = _read_canonical_object(path)
                if set(event) != _EVENT_KEYS:
                    raise ValueError("event fields are not exact")
                event_without_hash = dict(event)
                event_hash = event_without_hash.pop("event_sha256")
                if (
                    path.name != f"{expected:020d}.json"
                    or event.get("schema") != QMT_COMPAT_EVENT_SCHEMA
                    or event.get("sequence") != expected
                    or not isinstance(event.get("recorded_at"), str)
                    or not event["recorded_at"].strip()
                    or event.get("previous_event_sha256") != previous
                    or event.get("real_orders") is not False
                    or event.get("config_sha256") != self._config_sha256
                    or not isinstance(event.get("payload"), dict)
                    or not isinstance(event_hash, str)
                    or _digest(event_without_hash) != event_hash
                ):
                    raise ValueError("event chain mismatch")
                transition = replay._preview_recovered_event(
                    str(event["event_type"]), dict(event["payload"])
                )
                replay._apply_transition(transition)
                previous = event_hash
                expected += 1
            replay._head_sequence = expected - 1
            replay._head_hash = previous
            if self._head_path.exists():
                if not entries:
                    raise ValueError("head exists without any durable event")
                head = _read_canonical_object(self._head_path)
                if set(head) != _HEAD_KEYS or head != {
                    "schema": QMT_COMPAT_HEAD_SCHEMA,
                    "sequence": replay._head_sequence,
                    "event_sha256": replay._head_hash,
                    "config_sha256": self._config_sha256,
                    "real_orders": False,
                }:
                    raise ValueError("head mismatch")
            elif entries:
                raise ValueError("head missing")
        except Exception:
            self._degraded_reasons.add("DURABLE_EVENT_CHAIN_CORRUPT")
            return
        try:
            self._verify_config_identity()
        except QmtCompatPaperDegraded:
            return
        if any(order["status"] == "INTENT_DURABLE" for order in replay._orders.values()):
            replay._degraded_reasons.add("UNRESOLVED_DURABLE_INTENT")
        if replay._callback_buffer:
            replay._degraded_reasons.add("CALLBACK_SEQUENCE_GAP")
        self._publish_recovery(replay)

    def _publish_recovery(self, replay: "_RecoveryReplica") -> None:
        self._head_sequence = replay._head_sequence
        self._head_hash = replay._head_hash
        self._callback_next = replay._callback_next
        self._callback_seen = replay._callback_seen
        self._callback_buffer = replay._callback_buffer
        self._connection_epoch = replay._connection_epoch
        self._connected = replay._connected
        self._orders = replay._orders
        self._client_to_order = replay._client_to_order
        self._trade_hashes = replay._trade_hashes
        self._daily_usage = replay._daily_usage
        self._quarantines = replay._quarantines
        self._degraded_reasons.update(replay._degraded_reasons)

    def _preview_recovered_event(
        self, event_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        if event_type == "PAPER_INTENT_DURABLE":
            _exact_keys(
                payload,
                frozenset(
                    {
                        "client_order_id",
                        "broker_order_id",
                        "intent",
                        "intent_sha256",
                        "trade_date",
                        "notional",
                    }
                ),
                "PAPER_INTENT_DURABLE payload",
            )
            client = _nonempty_text(payload["client_order_id"], "client_order_id")
            order_id = _nonempty_text(payload["broker_order_id"], "broker_order_id")
            if client in self._client_to_order or order_id in self._orders:
                raise QmtCompatPaperError("durable order identity is duplicated")
            if order_id != self._order_id(client):
                raise QmtCompatPaperError("broker_order_id is not derived from client_order_id")
            if not isinstance(payload["intent"], dict):
                raise QmtCompatPaperError("durable intent is not an object")
            _exact_keys(payload["intent"], _INTENT_KEYS, "durable intent")
            normalized, notional = self._normalize_intent(
                {**payload["intent"], "client_order_id": client}
            )
            if normalized != payload["intent"] or payload["intent_sha256"] != _digest(normalized):
                raise QmtCompatPaperError("durable intent hash or normalization mismatch")
            if str(notional) != payload["notional"]:
                raise QmtCompatPaperError("durable intent notional mismatch")
            trade_date = _nonempty_text(payload["trade_date"], "trade_date")
            return self._preview_intent(client, order_id, normalized, trade_date, notional)
        if event_type == "PAPER_LOCAL_ACCEPTED":
            _exact_keys(payload, frozenset({"broker_order_id"}), "PAPER_LOCAL_ACCEPTED payload")
            return self._preview_local_accept(payload["broker_order_id"])
        if event_type == "PAPER_CANCEL_INTENT_DURABLE":
            _exact_keys(payload, frozenset({"broker_order_id"}), "PAPER_CANCEL_INTENT_DURABLE payload")
            return self._preview_cancel(payload["broker_order_id"])
        if event_type in {"CALLBACK_BUFFERED", "CALLBACK_APPLIED"}:
            _exact_keys(
                payload,
                frozenset(
                    {
                        "callback_sequence",
                        "callback_type",
                        "callback",
                        "callback_sha256",
                    }
                ),
                f"{event_type} payload",
            )
            callback_type = _nonempty_text(payload["callback_type"], "callback_type")
            if not isinstance(payload["callback"], dict):
                raise QmtCompatPaperError("callback is not an object")
            callback = self._normalize_callback(callback_type, payload["callback"])
            sequence = callback["sequence"]
            callback_hash = _digest({"callback_type": callback_type, "callback": callback})
            if (
                sequence != payload["callback_sequence"]
                or callback != payload["callback"]
                or callback_hash != payload["callback_sha256"]
            ):
                raise QmtCompatPaperError("callback durable binding mismatch")
            if event_type == "CALLBACK_BUFFERED":
                return self._preview_buffer(sequence, callback_type, callback, callback_hash)
            return self._preview_callback_event(sequence, callback_type, callback, callback_hash)
        if event_type == "CALLBACK_QUARANTINED":
            _exact_keys(
                payload,
                frozenset(
                    {
                        "quarantine_key",
                        "callback_type",
                        "callback_sequence",
                        "reason",
                        "candidate_sha256",
                        "financial_state_applied",
                    }
                ),
                "CALLBACK_QUARANTINED payload",
            )
            callback_type = _nonempty_text(payload["callback_type"], "callback_type")
            reason = _nonempty_text(payload["reason"], "reason")
            sequence = payload["callback_sequence"]
            if sequence is not None:
                sequence = _exact_int(sequence, "callback_sequence", minimum=1)
            candidate_sha256 = _nonempty_text(
                payload["candidate_sha256"], "candidate_sha256"
            )
            if len(candidate_sha256) != 64 or any(
                character not in "0123456789abcdef" for character in candidate_sha256
            ):
                raise QmtCompatPaperError("candidate_sha256 is invalid")
            identity = {
                "callback_type": callback_type,
                "callback_sequence": sequence,
                "reason": reason,
                "candidate_sha256": candidate_sha256,
                "financial_state_applied": False,
            }
            if (
                payload["financial_state_applied"] is not False
                or payload["quarantine_key"] != _digest(identity)
                or payload["quarantine_key"] in self._quarantines
            ):
                raise QmtCompatPaperError("callback quarantine identity is invalid")
            return {
                "kind": "QUARANTINE",
                "quarantine_key": payload["quarantine_key"],
                "quarantine": {**identity, "quarantine_key": payload["quarantine_key"]},
            }
        raise QmtCompatPaperError("durable event type is unsupported")

    def _apply_transition(self, transition: dict[str, Any]) -> None:
        kind = transition["kind"]
        if kind == "INTENT":
            self._client_to_order[transition["client_order_id"]] = transition["broker_order_id"]
            self._orders[transition["broker_order_id"]] = transition["order"]
            self._daily_usage[transition["trade_date"]] = transition["usage"]
        elif kind == "ORDER_STATE":
            self._orders[transition["broker_order_id"]] = transition["order"]
        elif kind == "BUFFER":
            self._callback_buffer[transition["sequence"]] = transition["buffered"]
            self._degraded_reasons.add("CALLBACK_SEQUENCE_GAP")
        elif kind == "CALLBACK":
            sequence = transition["sequence"]
            self._callback_seen[sequence] = transition["callback_sha256"]
            self._callback_buffer.pop(sequence, None)
            self._callback_next = sequence + 1
            if transition.get("order") is not None:
                self._orders[transition["broker_order_id"]] = transition["order"]
            if transition.get("trade_id") is not None:
                self._trade_hashes[transition["trade_id"]] = transition["trade_sha256"]
            if transition.get("connected") is not None:
                self._connected = transition["connected"]
                self._connection_epoch = transition["connection_epoch"]
            for reason in transition.get("clear_reasons", ()):
                self._degraded_reasons.discard(reason)
            if not self._callback_buffer:
                self._degraded_reasons.discard("CALLBACK_SEQUENCE_GAP")
        elif kind == "QUARANTINE":
            quarantine = transition["quarantine"]
            self._quarantines[transition["quarantine_key"]] = quarantine
            self._degraded_reasons.add(quarantine["reason"])

    def _normalize_intent(self, intent: dict[str, Any]) -> tuple[dict[str, Any], Decimal]:
        required = {"code", "side", "quantity", "order_type", "reference_price", "client_order_id"}
        if not isinstance(intent, dict) or not required.issubset(intent):
            raise QmtCompatPaperError("paper intent is incomplete")
        _nonempty_text(intent["client_order_id"], "client_order_id")
        code = _nonempty_text(intent["code"], "code")
        side = _nonempty_text(intent["side"], "side").lower()
        order_type = _nonempty_text(intent["order_type"], "order_type")
        quantity = _exact_int(intent["quantity"], "quantity", minimum=1)
        price = _decimal(intent["reference_price"], "reference_price", positive=True)
        limit_price = intent.get("limit_price")
        if limit_price is not None:
            limit_price = str(_decimal(limit_price, "limit_price", positive=True))
        normalized = {
            "code": code,
            "side": side,
            "quantity": quantity,
            "order_type": order_type,
            "limit_price": limit_price,
            "reference_price": str(price),
        }
        if side not in {"buy", "sell"}:
            raise QmtCompatPaperError("side is invalid")
        return normalized, price * quantity

    @staticmethod
    def _order_id(client_order_id: str) -> str:
        return "qmt-paper-" + hashlib.sha256(client_order_id.encode("utf-8")).hexdigest()[:20]

    def _preview_intent(
        self,
        client: str,
        order_id: str,
        normalized: dict[str, Any],
        trade_date: str,
        notional: Decimal,
    ) -> dict[str, Any]:
        usage = self._daily_usage.get(
            trade_date, {"order_count": 0, "notional": Decimal("0")}
        )
        return {
            "kind": "INTENT",
            "client_order_id": client,
            "broker_order_id": order_id,
            "trade_date": trade_date,
            "usage": {
                "order_count": int(usage["order_count"]) + 1,
                "notional": Decimal(usage["notional"]) + notional,
            },
            "order": {
                **normalized,
                "client_order_id": client,
                "broker_order_id": order_id,
                "status": "INTENT_DURABLE",
                "cancel_requested": False,
                "cumulative_filled_quantity": 0,
                "reported_filled_quantity": 0,
                "trade_filled_quantity": 0,
                "average_price": None,
                "last_callback_sequence": 0,
            },
        }

    def _preview_local_accept(self, broker_order_id: Any) -> dict[str, Any]:
        order_id = _nonempty_text(broker_order_id, "broker_order_id")
        order = self._orders.get(order_id)
        if order is None or order["status"] != "INTENT_DURABLE":
            raise QmtCompatPaperError("local acceptance has no unique durable intent")
        updated = deepcopy(order)
        updated["status"] = "ACCEPTED"
        return {"kind": "ORDER_STATE", "broker_order_id": order_id, "order": updated}

    def _preview_cancel(self, broker_order_id: Any) -> dict[str, Any]:
        order_id = _nonempty_text(broker_order_id, "broker_order_id")
        order = self._orders.get(order_id)
        if order is None or order["status"] in _TERMINAL or order["cancel_requested"]:
            raise QmtCompatPaperError("cancel intent has no unique mutable order")
        updated = deepcopy(order)
        updated["cancel_requested"] = True
        updated["status"] = "CANCEL_PENDING"
        return {"kind": "ORDER_STATE", "broker_order_id": order_id, "order": updated}

    def submit_paper_order(self, intent: dict[str, Any]) -> dict[str, Any]:
        with self._mutex:
            self._require_order_mutation_allowed()
            if not isinstance(intent, dict):
                raise QmtCompatPaperError("paper intent must be an object")
            client = _nonempty_text(intent.get("client_order_id"), "client_order_id")
            normalized, notional = self._normalize_intent(intent)
            intent_hash = _digest(normalized)
            previous_id = self._client_to_order.get(client)
            if previous_id is not None:
                previous = self._orders[previous_id]
                if _digest({key: previous.get(key) for key in normalized}) != intent_hash:
                    raise QmtCompatPaperConflict("client_order_id was reused for another intent")
                return self._submission_result(previous, idempotent=True)
            order_id = self._order_id(client)
            if order_id in self._orders:
                self._degraded_reasons.add("ORDER_ID_COLLISION")
                raise QmtCompatPaperConflict("derived broker_order_id collided")
            trade_date = _nonempty_text(
                intent.get("trade_date") or self._clock()[:10], "trade_date"
            )
            transition = self._preview_intent(
                client, order_id, normalized, trade_date, notional
            )
            self._append_prevalidated(
                "PAPER_INTENT_DURABLE",
                {
                    "client_order_id": client,
                    "broker_order_id": order_id,
                    "intent": normalized,
                    "intent_sha256": intent_hash,
                    "trade_date": trade_date,
                    "notional": str(notional),
                },
                transition,
            )
            accepted = self._preview_local_accept(order_id)
            self._append_prevalidated(
                "PAPER_LOCAL_ACCEPTED", {"broker_order_id": order_id}, accepted
            )
            return self._submission_result(self._orders[order_id], idempotent=False)

    def submit_live_order(self, intent: dict[str, Any]) -> dict[str, Any]:
        del intent
        raise BrokerPermissionError(
            "QMT compatibility adapter permanently forbids live orders"
        )

    def _submission_result(self, order: dict[str, Any], *, idempotent: bool) -> dict[str, Any]:
        return {
            "broker_order_id": order["broker_order_id"],
            "client_order_id": order["client_order_id"],
            "status": str(order["status"]).lower(),
            "idempotent": idempotent,
            "real_orders": False,
        }

    def cancel_order(self, broker_order_id: str) -> dict[str, Any]:
        with self._mutex:
            self._require_order_mutation_allowed()
            order_id = _nonempty_text(broker_order_id, "broker_order_id")
            order = self._orders.get(order_id)
            if order is None:
                self._degraded_reasons.add("UNKNOWN_CANCEL_TARGET")
                raise QmtCompatPaperDegraded("cancel target is unknown")
            if order["status"] in _TERMINAL:
                return {
                    "broker_order_id": order_id,
                    "status": order["status"].lower(),
                    "idempotent": True,
                }
            if not order["cancel_requested"]:
                transition = self._preview_cancel(order_id)
                self._append_prevalidated(
                    "PAPER_CANCEL_INTENT_DURABLE",
                    {"broker_order_id": order_id},
                    transition,
                )
                idempotent = False
            else:
                idempotent = True
            return {
                "broker_order_id": order_id,
                "status": "cancel_pending",
                "idempotent": idempotent,
            }

    def _normalize_callback(
        self, callback_type: str, callback: Any
    ) -> dict[str, Any]:
        if not isinstance(callback, Mapping):
            raise QmtCompatPaperError("callback must be a mapping")
        try:
            callback = dict(callback)
        except Exception as exc:
            raise QmtCompatPaperError("callback mapping cannot be read") from exc
        callback_type = _nonempty_text(callback_type, "callback_type")
        definitions: dict[str, tuple[frozenset[str], frozenset[str]]] = {
            "ORDER": (
                frozenset({"sequence", "order_id", "order_status", "traded_volume"}),
                frozenset({"stock_code", "client_order_id"}),
            ),
            "TRADE": (
                frozenset(
                    {"sequence", "order_id", "trade_id", "traded_volume", "traded_price"}
                ),
                frozenset({"stock_code", "client_order_id"}),
            ),
            "ORDER_ERROR": (
                frozenset({"sequence", "order_id", "error_id", "error_msg"}),
                frozenset({"client_order_id"}),
            ),
            "CANCEL_ERROR": (
                frozenset({"sequence", "order_id", "error_id", "error_msg"}),
                frozenset({"client_order_id"}),
            ),
            "DISCONNECTED": (frozenset({"sequence", "reason"}), frozenset()),
            "RECONNECTED": (frozenset({"sequence", "session"}), frozenset()),
        }
        if callback_type not in definitions:
            raise QmtCompatPaperError("callback type is unsupported")
        required, optional = definitions[callback_type]
        if not required.issubset(callback) or not set(callback).issubset(required | optional):
            raise QmtCompatPaperError("callback fields are not exact")
        normalized = deepcopy(callback)
        normalized["sequence"] = _exact_int(callback["sequence"], "callback sequence", minimum=1)
        if callback_type in {"ORDER", "TRADE", "ORDER_ERROR", "CANCEL_ERROR"}:
            normalized["order_id"] = _nonempty_text(callback["order_id"], "order_id")
            if "client_order_id" in callback:
                normalized["client_order_id"] = _nonempty_text(
                    callback["client_order_id"], "client_order_id"
                )
        if "stock_code" in callback:
            normalized["stock_code"] = _nonempty_text(callback["stock_code"], "stock_code")
        if callback_type == "ORDER":
            normalized["order_status"] = _nonempty_text(
                callback["order_status"], "order_status"
            ).upper()
            if normalized["order_status"] not in {
                "ACCEPTED",
                "PARTIAL",
                "FILLED",
                "CANCELLED",
                "REJECTED",
            }:
                raise QmtCompatPaperError("order_status is unsupported")
            normalized["traded_volume"] = _exact_int(
                callback["traded_volume"], "traded_volume"
            )
        elif callback_type == "TRADE":
            normalized["trade_id"] = _nonempty_text(callback["trade_id"], "trade_id")
            normalized["traded_volume"] = _exact_int(
                callback["traded_volume"], "traded_volume", minimum=1
            )
            normalized["traded_price"] = str(
                _decimal(callback["traded_price"], "traded_price", positive=True)
            )
        elif callback_type in {"ORDER_ERROR", "CANCEL_ERROR"}:
            normalized["error_id"] = _nonempty_text(callback["error_id"], "error_id")
            normalized["error_msg"] = _nonempty_text(callback["error_msg"], "error_msg")
        elif callback_type == "DISCONNECTED":
            normalized["reason"] = _nonempty_text(callback["reason"], "reason")
        elif callback_type == "RECONNECTED":
            normalized["session"] = _nonempty_text(callback["session"], "session")
        return normalized

    def _validate_callback_order(
        self, callback: dict[str, Any]
    ) -> tuple[str, dict[str, Any]]:
        order_id = callback["order_id"]
        order = self._orders.get(order_id)
        if order is None:
            raise _TransitionRejected("UNKNOWN_CALLBACK_ORDER", "callback order is unknown")
        client = callback.get("client_order_id")
        if client is not None and client != order["client_order_id"]:
            raise _TransitionRejected(
                "CALLBACK_CLIENT_ID_CONFLICT", "callback client_order_id does not match"
            )
        stock_code = callback.get("stock_code")
        if stock_code is not None and stock_code != order["code"]:
            raise _TransitionRejected(
                "CALLBACK_STOCK_CODE_CONFLICT", "callback stock_code does not match"
            )
        return order_id, order

    def _preview_buffer(
        self,
        sequence: int,
        callback_type: str,
        callback: dict[str, Any],
        callback_hash: str,
    ) -> dict[str, Any]:
        if sequence <= self._callback_next or sequence in self._callback_seen or sequence in self._callback_buffer:
            raise QmtCompatPaperError("buffered callback sequence is not unique and future")
        if callback_type not in {"DISCONNECTED", "RECONNECTED"}:
            self._validate_callback_order(callback)
        return {
            "kind": "BUFFER",
            "sequence": sequence,
            "buffered": (callback_type, deepcopy(callback), callback_hash),
        }

    @staticmethod
    def _trade_identity(callback: dict[str, Any]) -> str:
        return _digest(
            {
                key: value
                for key, value in callback.items()
                if key != "sequence"
            }
        )

    def _preview_callback_event(
        self,
        sequence: int,
        callback_type: str,
        callback: dict[str, Any],
        callback_hash: str,
    ) -> dict[str, Any]:
        if sequence != self._callback_next or sequence in self._callback_seen:
            raise QmtCompatPaperError("applied callback sequence is not the next durable cut")
        buffered = self._callback_buffer.get(sequence)
        if buffered is not None and buffered != (callback_type, callback, callback_hash):
            raise QmtCompatPaperError("applied callback does not match durable buffer")
        transition: dict[str, Any] = {
            "kind": "CALLBACK",
            "sequence": sequence,
            "callback_sha256": callback_hash,
            "order": None,
            "trade_id": None,
            "connected": None,
            "clear_reasons": [],
        }
        if callback_type == "DISCONNECTED":
            transition.update(
                {"connected": False, "connection_epoch": self._connection_epoch + 1}
            )
            return transition
        if callback_type == "RECONNECTED":
            transition.update(
                {"connected": True, "connection_epoch": self._connection_epoch}
            )
            return transition
        order_id, current = self._validate_callback_order(callback)
        order = deepcopy(current)
        order["last_callback_sequence"] = sequence
        quantity = int(order["quantity"])
        if callback_type == "ORDER":
            status = callback["order_status"]
            filled = callback["traded_volume"]
            current_status = order["status"]
            if filled > quantity:
                raise _TransitionRejected(
                    "IMPOSSIBLE_CUMULATIVE_FILL", "order cumulative fill is impossible"
                )
            if current_status == "FILLED":
                if status in {"CANCELLED", "REJECTED"}:
                    raise _TransitionRejected(
                        "TERMINAL_STATE_CONFLICT", "filled order cannot regress"
                    )
                order["reported_filled_quantity"] = max(
                    int(order["reported_filled_quantity"]), filled
                )
                order["cumulative_filled_quantity"] = quantity
                order["status"] = "FILLED"
                transition["broker_order_id"] = order_id
                transition["order"] = order
                return transition
            if filled < int(order["reported_filled_quantity"]):
                raise _TransitionRejected(
                    "IMPOSSIBLE_CUMULATIVE_FILL", "order cumulative fill regressed"
                )
            if status == "ACCEPTED" and filled != 0:
                raise _TransitionRejected("IMPOSSIBLE_TERMINAL_STATE", "accepted order has fills")
            if status == "PARTIAL" and not (0 < filled < quantity):
                raise _TransitionRejected("IMPOSSIBLE_TERMINAL_STATE", "partial order fill is invalid")
            if status == "FILLED" and filled != quantity:
                raise _TransitionRejected("IMPOSSIBLE_TERMINAL_STATE", "filled order is incomplete")
            if status == "CANCELLED" and filled >= quantity:
                raise _TransitionRejected("IMPOSSIBLE_TERMINAL_STATE", "cancelled order is fully filled")
            if status == "REJECTED" and (filled != 0 or order["cumulative_filled_quantity"]):
                raise _TransitionRejected("REJECT_AFTER_FILL_CONFLICT", "rejected order has fills")
            if current_status == "REJECTED" and status != "REJECTED":
                raise _TransitionRejected("TERMINAL_STATE_CONFLICT", "rejected order cannot reopen")
            if current_status == "CANCELLED" and status not in {"CANCELLED", "FILLED"}:
                raise _TransitionRejected("TERMINAL_STATE_CONFLICT", "cancelled order cannot reopen")
            order["reported_filled_quantity"] = filled
            order["cumulative_filled_quantity"] = max(
                filled, int(order["trade_filled_quantity"])
            )
            if status == "FILLED" or order["cumulative_filled_quantity"] == quantity:
                order["status"] = "FILLED"
            elif status == "CANCELLED":
                order["status"] = "CANCELLED"
            elif status == "REJECTED":
                order["status"] = "REJECTED"
            elif order["cancel_requested"]:
                order["status"] = "CANCEL_PENDING"
            elif order["cumulative_filled_quantity"] > 0:
                order["status"] = "PARTIAL"
            else:
                order["status"] = status
        elif callback_type == "TRADE":
            trade_id = callback["trade_id"]
            trade_hash = self._trade_identity(callback)
            previous = self._trade_hashes.get(trade_id)
            if previous is not None and previous != trade_hash:
                raise _TransitionRejected("TRADE_ID_CONFLICT", "trade_id payload conflict")
            if previous is None:
                if order["status"] == "REJECTED":
                    raise _TransitionRejected(
                        "TRADE_AFTER_TERMINAL_STATE", "trade arrived after definite rejection"
                    )
                volume = callback["traded_volume"]
                price = Decimal(callback["traded_price"])
                prior_quantity = int(order["trade_filled_quantity"])
                new_quantity = prior_quantity + volume
                if new_quantity > quantity:
                    raise _TransitionRejected(
                        "IMPOSSIBLE_CUMULATIVE_FILL", "trade volume exceeds order quantity"
                    )
                prior_value = Decimal(str(order["average_price"] or 0)) * prior_quantity
                order["trade_filled_quantity"] = new_quantity
                order["cumulative_filled_quantity"] = max(
                    new_quantity, int(order["reported_filled_quantity"])
                )
                order["average_price"] = str((prior_value + price * volume) / new_quantity)
                if order["cumulative_filled_quantity"] == quantity:
                    order["status"] = "FILLED"
                elif current["status"] == "CANCELLED":
                    order["status"] = "CANCELLED"
                elif order["cancel_requested"]:
                    order["status"] = "CANCEL_PENDING"
                else:
                    order["status"] = "PARTIAL"
                transition["trade_id"] = trade_id
                transition["trade_sha256"] = trade_hash
        elif callback_type == "ORDER_ERROR":
            if order["cumulative_filled_quantity"]:
                raise _TransitionRejected(
                    "REJECT_AFTER_FILL_CONFLICT", "definite reject arrived after a fill"
                )
            if order["status"] not in {"INTENT_DURABLE", "ACCEPTED", "CANCEL_PENDING", "REJECTED"}:
                raise _TransitionRejected("TERMINAL_STATE_CONFLICT", "reject conflicts with order state")
            if order["status"] == "REJECTED" and order.get("error_id") != callback["error_id"]:
                raise _TransitionRejected("TERMINAL_STATE_CONFLICT", "reject identity changed")
            order["status"] = "REJECTED"
            order["error_id"] = callback["error_id"]
            order["error_msg"] = callback["error_msg"]
        elif callback_type == "CANCEL_ERROR":
            if not order["cancel_requested"]:
                raise _TransitionRejected("CANCEL_OUTCOME_UNKNOWN", "cancel error has no cancel intent")
            order["status"] = "UNKNOWN"
        transition["broker_order_id"] = order_id
        transition["order"] = order
        if current["status"] == "INTENT_DURABLE":
            other_unresolved = any(
                key != order_id and value["status"] == "INTENT_DURABLE"
                for key, value in self._orders.items()
            )
            if not other_unresolved:
                transition["clear_reasons"].append("UNRESOLVED_DURABLE_INTENT")
        return transition

    @staticmethod
    def _candidate_sha256(callback: Any) -> str:
        if isinstance(callback, Mapping):
            try:
                return _digest({"callback": dict(callback)})
            except Exception:
                pass
        identity = (
            f"noncanonical:{type(callback).__module__}.{type(callback).__qualname__}"
        )
        return hashlib.sha256(identity.encode("utf-8")).hexdigest()

    def _record_quarantine(
        self,
        *,
        callback_type: str,
        callback: Any,
        sequence: int | None,
        reason: str,
        candidate_sha256: str | None = None,
    ) -> bool:
        identity = {
            "callback_type": callback_type,
            "callback_sequence": sequence,
            "reason": reason,
            "candidate_sha256": candidate_sha256 or self._candidate_sha256(callback),
            "financial_state_applied": False,
        }
        quarantine_key = _digest(identity)
        if quarantine_key in self._quarantines:
            self._degraded_reasons.add(reason)
            return False
        quarantine = {**identity, "quarantine_key": quarantine_key}
        self._append_prevalidated(
            "CALLBACK_QUARANTINED",
            quarantine,
            {
                "kind": "QUARANTINE",
                "quarantine_key": quarantine_key,
                "quarantine": quarantine,
            },
        )
        return True

    def _ingest(self, callback_type: str, callback: Any) -> dict[str, Any]:
        with self._mutex:
            self._require_durable_writable()
            normalized: dict[str, Any] | None = None
            parsed_sequence: int | None = None
            callback_hash: str | None = None
            try:
                normalized = self._normalize_callback(callback_type, callback)
                parsed_sequence = normalized["sequence"]
                callback_hash = _digest(
                    {"callback_type": callback_type, "callback": normalized}
                )
            except QmtCompatPaperDegraded:
                raise
            except QmtCompatPaperError:
                self._record_quarantine(
                    callback_type=callback_type,
                    callback=normalized if normalized is not None else callback,
                    sequence=parsed_sequence,
                    reason="CALLBACK_VALIDATION_FAILED",
                    candidate_sha256=callback_hash,
                )
                raise
            except Exception as exc:
                error = QmtCompatPaperError(
                    "callback normalization or canonicalization failed"
                )
                self._record_quarantine(
                    callback_type=callback_type,
                    callback=normalized if normalized is not None else callback,
                    sequence=parsed_sequence,
                    reason="CALLBACK_VALIDATION_FAILED",
                    candidate_sha256=callback_hash,
                )
                raise error from exc

            buffer_transition: dict[str, Any] | None = None
            callback_transition: dict[str, Any] | None = None
            try:
                prior_hash = self._callback_seen.get(parsed_sequence)
                if prior_hash is not None:
                    if prior_hash != callback_hash:
                        raise _TransitionRejected(
                            "CALLBACK_SEQUENCE_CONFLICT", "callback sequence payload conflict"
                        )
                    return {"applied": False, "idempotent": True, "buffered": False}
                buffered = self._callback_buffer.get(parsed_sequence)
                if buffered is not None:
                    if buffered != (callback_type, normalized, callback_hash):
                        raise _TransitionRejected(
                            "CALLBACK_SEQUENCE_CONFLICT", "buffered callback sequence payload conflict"
                        )
                    return {
                        "applied": False,
                        "idempotent": True,
                        "buffered": True,
                        "drain_blocked": parsed_sequence == self._callback_next,
                    }
                if parsed_sequence > self._callback_next:
                    buffer_transition = self._preview_buffer(
                        parsed_sequence, callback_type, normalized, callback_hash
                    )
                elif parsed_sequence < self._callback_next:
                    raise _TransitionRejected(
                        "CALLBACK_SEQUENCE_CONFLICT", "callback sequence is below durable cut"
                    )
                else:
                    callback_transition = self._preview_callback_event(
                        parsed_sequence, callback_type, normalized, callback_hash
                    )
            except _TransitionRejected as exc:
                self._record_quarantine(
                    callback_type=callback_type,
                    callback=normalized if normalized is not None else callback,
                    sequence=parsed_sequence,
                    reason=exc.reason,
                    candidate_sha256=callback_hash,
                )
                raise

            if buffer_transition is not None:
                self._append_prevalidated(
                    "CALLBACK_BUFFERED",
                    {
                        "callback_sequence": parsed_sequence,
                        "callback_type": callback_type,
                        "callback": normalized,
                        "callback_sha256": callback_hash,
                    },
                    buffer_transition,
                )
                return {"applied": False, "idempotent": False, "buffered": True}

            if callback_transition is None:
                raise QmtCompatPaperError("callback transition was not prepared")
            self._commit_callback(
                parsed_sequence,
                callback_type,
                normalized,
                callback_hash,
                callback_transition,
            )
            drained = self._drain_buffered()
            return {
                "applied": True,
                "idempotent": False,
                "buffered": False,
                "drained_count": drained["drained_count"],
                "drain_blocked": drained["drain_blocked"],
                "drain_blocked_reason": drained["drain_blocked_reason"],
            }

    def _commit_callback(
        self,
        sequence: int,
        callback_type: str,
        callback: dict[str, Any],
        callback_hash: str,
        transition: dict[str, Any],
    ) -> None:
        self._append_prevalidated(
            "CALLBACK_APPLIED",
            {
                "callback_sequence": sequence,
                "callback_type": callback_type,
                "callback": callback,
                "callback_sha256": callback_hash,
            },
            transition,
        )

    def _drain_buffered(self) -> dict[str, Any]:
        drained = 0
        while self._callback_next in self._callback_buffer:
            callback_type, callback, callback_hash = self._callback_buffer[self._callback_next]
            try:
                transition = self._preview_callback_event(
                    self._callback_next, callback_type, callback, callback_hash
                )
            except _TransitionRejected as exc:
                self._degraded_reasons.add(exc.reason)
                return {
                    "drained_count": drained,
                    "drain_blocked": True,
                    "drain_blocked_reason": exc.reason,
                }
            except QmtCompatPaperError:
                self._degraded_reasons.add("CALLBACK_VALIDATION_FAILED")
                return {
                    "drained_count": drained,
                    "drain_blocked": True,
                    "drain_blocked_reason": "CALLBACK_VALIDATION_FAILED",
                }
            self._commit_callback(
                self._callback_next, callback_type, callback, callback_hash, transition
            )
            drained += 1
        if not self._callback_buffer:
            self._degraded_reasons.discard("CALLBACK_SEQUENCE_GAP")
        return {
            "drained_count": drained,
            "drain_blocked": False,
            "drain_blocked_reason": None,
        }

    def on_stock_order(self, callback: Any) -> dict[str, Any]:
        return self._ingest("ORDER", callback)

    def on_stock_trade(self, callback: Any) -> dict[str, Any]:
        return self._ingest("TRADE", callback)

    def on_order_error(self, callback: Any) -> dict[str, Any]:
        return self._ingest("ORDER_ERROR", callback)

    def on_cancel_error(self, callback: Any) -> dict[str, Any]:
        return self._ingest("CANCEL_ERROR", callback)

    def on_disconnected(self, callback: Any) -> dict[str, Any]:
        return self._ingest("DISCONNECTED", callback)

    def on_reconnected(self, callback: Any) -> dict[str, Any]:
        return self._ingest("RECONNECTED", callback)

    def list_orders(self) -> list[dict[str, Any]]:
        with self._mutex:
            self._require_open()
            self._verify_config_identity()
            result = [deepcopy(self._orders[key]) for key in sorted(self._orders)]
            self._verify_config_identity()
            return result

    def find_order_by_client_id(self, client_order_id: str) -> dict[str, Any] | None:
        with self._mutex:
            self._require_open()
            self._verify_config_identity()
            client = _nonempty_text(client_order_id, "client_order_id")
            order_id = self._client_to_order.get(client)
            result = None if order_id is None else deepcopy(self._orders[order_id])
            self._verify_config_identity()
            return result

    def get_daily_order_usage(self, trade_date: str) -> dict[str, Any]:
        with self._mutex:
            self._require_open()
            self._verify_config_identity()
            day = _nonempty_text(trade_date, "trade_date")
            usage = self._daily_usage.get(
                day, {"order_count": 0, "notional": Decimal("0")}
            )
            result = {
                "order_count": int(usage["order_count"]),
                "notional": str(usage["notional"]),
                "conservative": True,
            }
            self._verify_config_identity()
            return result

    def get_positions(self) -> list[dict[str, Any]]:
        with self._mutex:
            self._require_open()
            self._verify_config_identity()
            positions: dict[str, int] = {}
            for order in self._orders.values():
                signed = int(order["cumulative_filled_quantity"]) * (
                    1 if order["side"] == "buy" else -1
                )
                positions[order["code"]] = positions.get(order["code"], 0) + signed
            result = [
                {"code": code, "quantity": quantity}
                for code, quantity in sorted(positions.items())
                if quantity
            ]
            self._verify_config_identity()
            return result

    def get_account(self) -> dict[str, Any]:
        with self._mutex:
            self._require_open()
            self._verify_config_identity()
            result = {
                "equity": self._initial_cash_text,
                "currency": "CNY",
                "real_orders": False,
            }
            self._verify_config_identity()
            return result

    def get_atomic_account_snapshot(self) -> dict[str, Any]:
        with self._mutex:
            self._require_open()
            self._verify_config_identity()
            positions: dict[str, int] = {}
            for order in self._orders.values():
                signed = int(order["cumulative_filled_quantity"]) * (
                    1 if order["side"] == "buy" else -1
                )
                positions[order["code"]] = positions.get(order["code"], 0) + signed
            result = {
                "schema": QMT_COMPAT_SNAPSHOT_SCHEMA,
                "account": {
                    "equity": self._initial_cash_text,
                    "currency": "CNY",
                    "real_orders": False,
                },
                "positions": [
                    {"code": code, "quantity": quantity}
                    for code, quantity in sorted(positions.items())
                    if quantity
                ],
                "orders": [deepcopy(self._orders[key]) for key in sorted(self._orders)],
                "cut": {
                    "sequence": self._head_sequence,
                    "event_sha256": self._head_hash,
                    "config_sha256": self._config_sha256,
                },
                "callback_cut": self._callback_next - 1,
                "connection_epoch": self._connection_epoch,
                "connected": self._connected,
                "degraded": self.is_degraded,
                "real_orders": False,
            }
            self._verify_config_identity()
            return result


class _RecoveryReplica(QmtCompatPaperAdapter):
    """Fully initialized, filesystem-inert target for atomic journal replay."""

    @classmethod
    def from_adapter(cls, source: QmtCompatPaperAdapter) -> "_RecoveryReplica":
        replay = object.__new__(cls)
        replay.root = source.root
        replay._events_dir = source._events_dir
        replay._config_path = source._config_path
        replay._config_temporary_path = source._config_temporary_path
        replay._head_path = source._head_path
        replay._head_temporary_path = source._head_temporary_path
        replay._lock_path = source._lock_path
        replay._initial_cash = source._initial_cash
        replay._initial_cash_text = source._initial_cash_text
        replay._clock = source._clock
        replay._mutex = RLock()
        replay._lock_handle = None
        replay._closed = False
        replay._head_sequence = 0
        replay._head_hash = _ZERO_HASH
        replay._callback_next = 1
        replay._callback_seen = {}
        replay._callback_buffer = {}
        replay._connection_epoch = 0
        replay._connected = True
        replay._orders = {}
        replay._client_to_order = {}
        replay._trade_hashes = {}
        replay._daily_usage = {}
        replay._quarantines = {}
        replay._degraded_reasons = set()
        replay._config_sha256 = source._config_sha256
        return replay

    def close(self) -> None:
        """Recovery replicas never own the process lock or filesystem resources."""

    def __del__(self) -> None:
        """Do not invoke the adapter resource lifecycle for an inert replica."""
