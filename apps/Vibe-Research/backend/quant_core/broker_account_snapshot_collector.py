"""Trusted atomic broker account snapshot collection and replay evidence."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Iterator, Mapping, Protocol

from .broker_account_control import (
    BrokerAccountControlError,
    build_broker_account_snapshot,
    validate_broker_account_snapshot,
)
from .provenance import sha256_digest


BROKER_ACCOUNT_SNAPSHOT_MAPPING_SCHEMA = (
    "quant-core/broker-account-snapshot-mapping/v1"
)
BROKER_ACCOUNT_SOURCE_PAYLOAD_SCHEMA = (
    "quant-core/broker-account-source-payload/v1"
)
BROKER_ACCOUNT_COLLECTION_RECORD_SCHEMA = (
    "quant-core/broker-account-collection-record/v1"
)
BROKER_ACCOUNT_COLLECTION_HEAD_SCHEMA = (
    "quant-core/broker-account-collection-head/v1"
)
BROKER_ACCOUNT_COLLECTION_INSPECTION_SCHEMA = (
    "quant-core/broker-account-collection-inspection/v1"
)

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
FIELD_PATH_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_-]{0,63}(\.[A-Za-z_][A-Za-z0-9_-]{0,63})*$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ACCOUNT_FIELDS = frozenset(
    {
        "currency",
        "cash_balance",
        "cash_available",
        "equity",
        "other_assets",
        "liabilities",
    }
)
POSITION_FIELDS = frozenset(
    {
        "code",
        "total_quantity",
        "sellable_quantity",
        "frozen_quantity",
        "market_price",
    }
)


class AtomicAccountSnapshotAdapter(Protocol):
    adapter_id: str
    account_fingerprint: str

    def capabilities(self) -> set[str]: ...

    def get_atomic_account_snapshot(self) -> dict[str, Any]: ...


class BrokerAccountSnapshotCollectorError(RuntimeError):
    """Raised when broker account source evidence is unsafe or corrupt."""


class BrokerAccountSnapshotConflict(BrokerAccountSnapshotCollectorError):
    """Raised when a broker source identity is reused inconsistently."""


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not ID_RE.fullmatch(text):
        raise BrokerAccountSnapshotCollectorError(f"{label} is invalid")
    return text


def _field_path(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not FIELD_PATH_RE.fullmatch(text):
        raise BrokerAccountSnapshotCollectorError(f"{label} is invalid")
    return text


def _hash(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not SHA256_RE.fullmatch(text):
        raise BrokerAccountSnapshotCollectorError(
            f"{label} must be a sha256 digest"
        )
    return text


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    try:
        parsed = (
            value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        )
    except (TypeError, ValueError) as exc:
        raise BrokerAccountSnapshotCollectorError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise BrokerAccountSnapshotCollectorError(
            f"{label} must include timezone"
        )
    utc = parsed.astimezone(timezone.utc)
    return utc.isoformat(), utc


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _encoded(payload: Any) -> str:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    )


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    encoded = _encoded(payload)
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
    encoded = _encoded(payload)
    if path.exists():
        if path.read_text(encoding="utf-8") != encoded:
            raise BrokerAccountSnapshotConflict(
                f"immutable broker account collection conflict: {path.name}"
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


def _extract(value: Mapping[str, Any], path: str, label: str) -> Any:
    current: Any = value
    for segment in path.split("."):
        if not isinstance(current, Mapping) or segment not in current:
            raise BrokerAccountSnapshotCollectorError(
                f"mapped broker field is absent: {label}"
            )
        current = current[segment]
    if isinstance(current, (dict, list, tuple, set)):
        raise BrokerAccountSnapshotCollectorError(
            f"mapped broker field is not scalar: {label}"
        )
    return current


def build_broker_account_snapshot_mapping(
    *,
    adapter_id: str,
    mapping_version: str,
    account_fields: Mapping[str, str],
    position_fields: Mapping[str, str],
) -> dict[str, Any]:
    account = dict(account_fields)
    positions = dict(position_fields)
    if set(account) != ACCOUNT_FIELDS or set(positions) != POSITION_FIELDS:
        raise BrokerAccountSnapshotCollectorError(
            "broker account snapshot mapping fields are incomplete"
        )
    identity = {
        "schema": BROKER_ACCOUNT_SNAPSHOT_MAPPING_SCHEMA,
        "adapter_id": _identifier(adapter_id, "adapter_id"),
        "mapping_version": _identifier(mapping_version, "mapping_version"),
        "account_fields": {
            key: _field_path(account[key], f"account_fields.{key}")
            for key in sorted(account)
        },
        "position_fields": {
            key: _field_path(positions[key], f"position_fields.{key}")
            for key in sorted(positions)
        },
    }
    return {**identity, "mapping_sha256": sha256_digest(identity)}


def validate_broker_account_snapshot_mapping(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BrokerAccountSnapshotCollectorError(
            "broker account snapshot mapping must be an object"
        )
    mapping = dict(value)
    if set(mapping) != {
        "schema",
        "adapter_id",
        "mapping_version",
        "account_fields",
        "position_fields",
        "mapping_sha256",
    } or mapping.get("schema") != BROKER_ACCOUNT_SNAPSHOT_MAPPING_SCHEMA:
        raise BrokerAccountSnapshotCollectorError(
            "broker account snapshot mapping fields are invalid"
        )
    rebuilt = build_broker_account_snapshot_mapping(
        adapter_id=mapping["adapter_id"],
        mapping_version=mapping["mapping_version"],
        account_fields=dict(mapping["account_fields"]),
        position_fields=dict(mapping["position_fields"]),
    )
    if mapping != rebuilt:
        raise BrokerAccountSnapshotCollectorError(
            "broker account snapshot mapping hash mismatch"
        )
    return rebuilt


class BrokerAccountSnapshotCollector:
    """Collect one atomic vendor snapshot and retain replayable mapped evidence."""

    def __init__(
        self,
        root: str | Path,
        *,
        adapter: AtomicAccountSnapshotAdapter,
        mapping: Mapping[str, Any],
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.adapter = adapter
        self.mapping = validate_broker_account_snapshot_mapping(mapping)
        if self.mapping["adapter_id"] != str(adapter.adapter_id):
            raise BrokerAccountSnapshotCollectorError(
                "account snapshot mapping and adapter identities differ"
            )
        self.account_fingerprint = str(adapter.account_fingerprint).strip()
        if not self.account_fingerprint or len(self.account_fingerprint) > 160:
            raise BrokerAccountSnapshotCollectorError(
                "adapter account_fingerprint is invalid"
            )
        _immutable_json(self.root / "mapping.json", self.mapping)

    @property
    def adapter_id(self) -> str:
        return str(self.mapping["adapter_id"])

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
            raise BrokerAccountSnapshotCollectorError(
                "broker account snapshot collector is locked by another process"
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
    def _validate_payload(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "account",
            "positions",
            "broker_reported_at",
            "source_reference",
        }:
            raise BrokerAccountSnapshotCollectorError(
                "atomic broker account source payload fields are invalid"
            )
        if value["schema"] != BROKER_ACCOUNT_SOURCE_PAYLOAD_SCHEMA:
            raise BrokerAccountSnapshotCollectorError(
                "atomic broker account source payload schema is unsupported"
            )
        if not isinstance(value["account"], dict) or not isinstance(
            value["positions"], list
        ) or any(not isinstance(item, dict) for item in value["positions"]):
            raise BrokerAccountSnapshotCollectorError(
                "atomic broker account source payload values are invalid"
            )
        _identifier(value["source_reference"], "source_reference")
        _timestamp(value["broker_reported_at"], "broker_reported_at")
        try:
            _encoded(value)
        except (TypeError, ValueError) as exc:
            raise BrokerAccountSnapshotCollectorError(
                "atomic broker account source payload is not canonical JSON"
            ) from exc
        return value

    def _snapshot_from_payload(
        self,
        payload: dict[str, Any],
        *,
        trade_date: str,
        received_at: str,
    ) -> dict[str, Any]:
        account = payload["account"]
        positions = payload["positions"]
        account_fields = self.mapping["account_fields"]
        position_fields = self.mapping["position_fields"]
        mapped_positions = [
            {
                canonical: _extract(
                    raw,
                    position_fields[canonical],
                    f"positions[{index}].{canonical}",
                )
                for canonical in sorted(POSITION_FIELDS)
            }
            for index, raw in enumerate(positions)
        ]
        try:
            return build_broker_account_snapshot(
                adapter_id=self.adapter_id,
                account_fingerprint=self.account_fingerprint,
                trade_date=trade_date,
                currency=_extract(
                    account, account_fields["currency"], "account.currency"
                ),
                cash_balance=_extract(
                    account,
                    account_fields["cash_balance"],
                    "account.cash_balance",
                ),
                cash_available=_extract(
                    account,
                    account_fields["cash_available"],
                    "account.cash_available",
                ),
                equity=_extract(
                    account, account_fields["equity"], "account.equity"
                ),
                other_assets=_extract(
                    account,
                    account_fields["other_assets"],
                    "account.other_assets",
                ),
                liabilities=_extract(
                    account,
                    account_fields["liabilities"],
                    "account.liabilities",
                ),
                positions=mapped_positions,
                broker_reported_at=payload["broker_reported_at"],
                received_at=received_at,
                source_reference=payload["source_reference"],
            )
        except BrokerAccountControlError as exc:
            raise BrokerAccountSnapshotCollectorError(
                f"mapped broker account snapshot is invalid: {exc}"
            ) from exc

    def _load_chain(self) -> list[dict[str, Any]]:
        try:
            stored_mapping = validate_broker_account_snapshot_mapping(
                dict(_read_json(self.root / "mapping.json"))
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrokerAccountSnapshotCollectorError(
                f"stored account snapshot mapping is unreadable: {exc}"
            ) from exc
        if stored_mapping != self.mapping:
            raise BrokerAccountSnapshotCollectorError(
                "stored account snapshot mapping changed"
            )
        paths = sorted((self.root / "records").glob("*.json"))
        if not self.head_path.exists():
            if paths:
                raise BrokerAccountSnapshotCollectorError(
                    "account collection head is missing while records exist"
                )
            return []
        try:
            head = dict(_read_json(self.head_path))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrokerAccountSnapshotCollectorError(
                f"account collection head is unreadable: {exc}"
            ) from exc
        if set(head) != {"schema", "sequence", "record_sha256"} or head.get(
            "schema"
        ) != BROKER_ACCOUNT_COLLECTION_HEAD_SCHEMA:
            raise BrokerAccountSnapshotCollectorError(
                "account collection head fields are invalid"
            )
        records: list[dict[str, Any]] = []
        previous_sha: str | None = None
        source_references: dict[str, str] = {}
        for expected_sequence, path in enumerate(paths, start=1):
            try:
                record = dict(_read_json(path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerAccountSnapshotCollectorError(
                    f"account collection record is unreadable: {path.name}: {exc}"
                ) from exc
            required = {
                "schema",
                "sequence",
                "previous_record_sha256",
                "adapter_id",
                "account_fingerprint",
                "mapping_sha256",
                "trade_date",
                "received_at",
                "broker_reported_at",
                "source_reference",
                "raw_payload_sha256",
                "account_snapshot",
                "record_sha256",
            }
            if set(record) != required or record.get(
                "schema"
            ) != BROKER_ACCOUNT_COLLECTION_RECORD_SCHEMA:
                raise BrokerAccountSnapshotCollectorError(
                    "account collection record fields are invalid"
                )
            identity = {
                key: value for key, value in record.items() if key != "record_sha256"
            }
            digest = _hash(record["record_sha256"], "record_sha256")
            snapshot = validate_broker_account_snapshot(record["account_snapshot"])
            reference = _identifier(record["source_reference"], "source_reference")
            if (
                sha256_digest(identity) != digest
                or path.name != self._record_path(expected_sequence, digest).name
                or record["sequence"] != expected_sequence
                or record["previous_record_sha256"] != previous_sha
                or record["adapter_id"] != self.adapter_id
                or record["account_fingerprint"] != self.account_fingerprint
                or record["mapping_sha256"] != self.mapping["mapping_sha256"]
                or record["trade_date"] != snapshot["trade_date"]
                or record["received_at"] != snapshot["received_at"]
                or record["broker_reported_at"] != snapshot["broker_reported_at"]
                or reference != snapshot["source_reference"]
                or snapshot["adapter_id"] != self.adapter_id
                or snapshot["account_fingerprint"] != self.account_fingerprint
            ):
                raise BrokerAccountSnapshotCollectorError(
                    "account collection record chain identity broke"
                )
            prior_raw = source_references.get(reference)
            if prior_raw is not None and prior_raw != record["raw_payload_sha256"]:
                raise BrokerAccountSnapshotCollectorError(
                    "broker source reference was reused with different payload"
                )
            source_references[reference] = _hash(
                record["raw_payload_sha256"], "raw_payload_sha256"
            )
            records.append(record)
            previous_sha = digest
        expected_head = {
            "schema": BROKER_ACCOUNT_COLLECTION_HEAD_SCHEMA,
            "sequence": len(records),
            "record_sha256": records[-1]["record_sha256"],
        }
        if not records or head != expected_head:
            raise BrokerAccountSnapshotCollectorError(
                "account collection head does not match chain tip"
            )
        return records

    def collect(
        self,
        *,
        trade_date: str,
        received_at: datetime,
    ) -> dict[str, Any]:
        try:
            day = date.fromisoformat(str(trade_date)).isoformat()
        except ValueError as exc:
            raise BrokerAccountSnapshotCollectorError(
                "trade_date is invalid"
            ) from exc
        received_text, received_time = _timestamp(received_at, "received_at")
        capabilities = {
            item.value if hasattr(item, "value") else str(item)
            for item in self.adapter.capabilities()
        }
        if "ATOMIC_ACCOUNT_SNAPSHOT_READ" not in capabilities:
            raise BrokerAccountSnapshotCollectorError(
                "adapter lacks ATOMIC_ACCOUNT_SNAPSHOT_READ capability"
            )
        method = getattr(self.adapter, "get_atomic_account_snapshot", None)
        if not callable(method):
            raise BrokerAccountSnapshotCollectorError(
                "adapter lacks atomic account snapshot method"
            )
        try:
            payload = self._validate_payload(method())
        except BrokerAccountSnapshotCollectorError:
            raise
        except Exception as exc:
            raise BrokerAccountSnapshotCollectorError(
                "adapter atomic account snapshot call failed"
            ) from exc
        broker_text, broker_time = _timestamp(
            payload["broker_reported_at"], "broker_reported_at"
        )
        if broker_time > received_time:
            raise BrokerAccountSnapshotCollectorError(
                "broker account source time is after local receipt time"
            )
        raw_sha = sha256_digest(payload)
        snapshot = self._snapshot_from_payload(
            payload, trade_date=day, received_at=received_text
        )
        reference = str(payload["source_reference"])
        with self._lock():
            records = self._load_chain()
            same_reference = [
                record for record in records if record["source_reference"] == reference
            ]
            if same_reference:
                existing = same_reference[0]
                if (
                    existing["raw_payload_sha256"] != raw_sha
                    or existing["trade_date"] != day
                ):
                    raise BrokerAccountSnapshotConflict(
                        "broker source reference was reused inconsistently"
                    )
                return {**existing, "idempotent": True}
            identity = {
                "schema": BROKER_ACCOUNT_COLLECTION_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": (
                    records[-1]["record_sha256"] if records else None
                ),
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "mapping_sha256": self.mapping["mapping_sha256"],
                "trade_date": day,
                "received_at": received_text,
                "broker_reported_at": broker_text,
                "source_reference": reference,
                "raw_payload_sha256": raw_sha,
                "account_snapshot": snapshot,
            }
            digest = sha256_digest(identity)
            record = {**identity, "record_sha256": digest}
            _immutable_json(self._record_path(identity["sequence"], digest), record)
            _atomic_json(
                self.head_path,
                {
                    "schema": BROKER_ACCOUNT_COLLECTION_HEAD_SCHEMA,
                    "sequence": identity["sequence"],
                    "record_sha256": digest,
                },
            )
            return {**record, "idempotent": False}

    def snapshot_by_sha256(self, snapshot_sha256: str) -> dict[str, Any] | None:
        digest = _hash(snapshot_sha256, "snapshot_sha256")
        records = self._load_chain()
        matches = [
            record["account_snapshot"]
            for record in records
            if record["account_snapshot"]["snapshot_sha256"] == digest
        ]
        if len(matches) > 1:
            raise BrokerAccountSnapshotCollectorError(
                "account snapshot_sha256 is ambiguous"
            )
        return dict(matches[0]) if matches else None

    def inspect(self) -> dict[str, Any]:
        try:
            records = self._load_chain()
            latest = records[-1] if records else None
            return {
                "schema": BROKER_ACCOUNT_COLLECTION_INSPECTION_SCHEMA,
                "status": "EMPTY" if not records else "READY",
                "read_only_recommended": False,
                "error": None,
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "mapping_sha256": self.mapping["mapping_sha256"],
                "record_count": len(records),
                "latest_trade_date": latest["trade_date"] if latest else None,
                "latest_snapshot_sha256": (
                    latest["account_snapshot"]["snapshot_sha256"]
                    if latest
                    else None
                ),
                "latest_record_sha256": (
                    latest["record_sha256"] if latest else None
                ),
            }
        except (
            BrokerAccountSnapshotCollectorError,
            BrokerAccountControlError,
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            return {
                "schema": BROKER_ACCOUNT_COLLECTION_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "read_only_recommended": True,
                "error": str(exc),
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "mapping_sha256": self.mapping["mapping_sha256"],
                "record_count": 0,
                "latest_trade_date": None,
                "latest_snapshot_sha256": None,
                "latest_record_sha256": None,
            }
