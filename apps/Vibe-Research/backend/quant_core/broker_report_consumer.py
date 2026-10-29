"""Durable, sequence-aware consumer for normalized broker execution reports.

The adapter-facing report contract is intentionally cumulative and strict.  A
report is persisted before it can mutate the order lifecycle.  Separate
application receipts make a crash between broker-report receipt, lifecycle
append, fill settlement, and receipt publication recoverable without applying
the same cumulative state twice.
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

from .broker_order_lifecycle import (
    BrokerOrderJournal,
    BrokerOrderJournalError,
)
from .broker_account_control import (
    BrokerAccountControlError,
    BrokerAccountReservationBook,
)
from .provenance import sha256_digest


BROKER_REPORT_MAPPING_SCHEMA = "quant-core/broker-report-status-mapping/v1"
BROKER_EXECUTION_REPORT_SCHEMA = "quant-core/broker-execution-report/v1"
BROKER_REPORT_RECORD_SCHEMA = "quant-core/broker-report-record/v1"
BROKER_REPORT_HEAD_SCHEMA = "quant-core/broker-report-head/v1"
BROKER_REPORT_APPLICATION_SCHEMA = "quant-core/broker-report-application/v1"
BROKER_REPORT_APPLICATION_HEAD_SCHEMA = (
    "quant-core/broker-report-application-head/v1"
)
BROKER_REPORT_CONSUMPTION_SCHEMA = "quant-core/broker-report-consumption/v1"
BROKER_REPORT_INSPECTION_SCHEMA = "quant-core/broker-report-inspection/v1"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
RAW_STATUS_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,79}$")
CANONICAL_STATUSES = frozenset(
    {
        "ACCEPTED",
        "PARTIALLY_FILLED",
        "FILLED",
        "CANCEL_PENDING",
        "CANCELLED",
        "REJECTED",
        "UNKNOWN",
    }
)


class BrokerReportConsumerError(RuntimeError):
    """Raised when report evidence is corrupt, incomplete, or unsafe."""


class BrokerReportConflict(BrokerReportConsumerError):
    """Raised when broker report identity or sequence is reused inconsistently."""


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not ID_RE.fullmatch(text):
        raise BrokerReportConsumerError(f"{label} is invalid")
    return text


def _hash(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if nullable and value is None:
        return None
    text = str(value or "").lower()
    if not SHA256_RE.fullmatch(text):
        raise BrokerReportConsumerError(f"{label} must be a sha256 digest")
    return text


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not (
        isinstance(value, int)
        or (isinstance(value, str) and value.strip().isdigit())
    ):
        raise BrokerReportConsumerError(f"{label} must be an exact integer")
    parsed = int(value)
    if parsed < 0 or (positive and parsed == 0):
        raise BrokerReportConsumerError(f"{label} is invalid")
    return parsed


def _decimal_text(value: Any, label: str, *, positive: bool = False) -> str:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise BrokerReportConsumerError(f"{label} must be a finite decimal") from exc
    if not parsed.is_finite() or parsed < 0 or (positive and parsed == 0):
        raise BrokerReportConsumerError(f"{label} is invalid")
    return format(parsed.normalize(), "f")


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value))
        except ValueError as exc:
            raise BrokerReportConsumerError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise BrokerReportConsumerError(f"{label} must include timezone")
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
            raise BrokerReportConflict(
                f"immutable broker report record conflict: {path.name}"
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


def build_broker_report_mapping(
    *,
    adapter_id: str,
    mapping_version: str,
    status_map: dict[str, str],
    max_future_clock_skew_seconds: int = 300,
) -> dict[str, Any]:
    """Build a content-addressed, adapter-specific raw-status mapping."""

    adapter = _identifier(adapter_id, "adapter_id")
    version = _identifier(mapping_version, "mapping_version")
    if not isinstance(status_map, dict) or not status_map:
        raise BrokerReportConsumerError("status_map must not be empty")
    normalized: dict[str, str] = {}
    for raw_value, canonical_value in status_map.items():
        raw = str(raw_value or "").strip().lower().replace("-", "_")
        canonical = str(canonical_value or "").strip().upper()
        if not RAW_STATUS_RE.fullmatch(raw):
            raise BrokerReportConsumerError("raw broker status is invalid")
        if raw in normalized:
            raise BrokerReportConsumerError("raw broker status is duplicated")
        if canonical not in CANONICAL_STATUSES:
            raise BrokerReportConsumerError("canonical broker status is unsupported")
        normalized[raw] = canonical
    skew = _integer(
        max_future_clock_skew_seconds,
        "max_future_clock_skew_seconds",
    )
    identity = {
        "schema": BROKER_REPORT_MAPPING_SCHEMA,
        "adapter_id": adapter,
        "mapping_version": version,
        "max_future_clock_skew_seconds": skew,
        "status_map": dict(sorted(normalized.items())),
    }
    return {**identity, "mapping_sha256": sha256_digest(identity)}


def validate_broker_report_mapping(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BrokerReportConsumerError("broker report mapping must be an object")
    required = {
        "schema",
        "adapter_id",
        "mapping_version",
        "max_future_clock_skew_seconds",
        "status_map",
        "mapping_sha256",
    }
    if set(value) != required or value.get("schema") != BROKER_REPORT_MAPPING_SCHEMA:
        raise BrokerReportConsumerError("broker report mapping fields are invalid")
    expected = build_broker_report_mapping(
        adapter_id=value["adapter_id"],
        mapping_version=value["mapping_version"],
        status_map=value["status_map"],
        max_future_clock_skew_seconds=value["max_future_clock_skew_seconds"],
    )
    if value != expected:
        raise BrokerReportConsumerError("broker report mapping hash mismatch")
    return expected


class BrokerReportConsumer:
    """Persist, order, and exactly-once apply cumulative broker reports."""

    def __init__(
        self,
        root: str | Path,
        *,
        journal: BrokerOrderJournal,
        mapping: dict[str, Any],
        account_reservation_book: BrokerAccountReservationBook,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.journal = journal
        self.account_reservation_book = account_reservation_book
        self.mapping = validate_broker_report_mapping(mapping)
        if account_reservation_book.journal is not journal:
            raise BrokerReportConsumerError(
                "broker report consumer and account reservation book use different journals"
            )
        if account_reservation_book.account_fingerprint != journal.account_fingerprint:
            raise BrokerReportConsumerError(
                "broker report consumer and account reservation book identities differ"
            )
        _immutable_json(self.root / "mapping.json", self.mapping)

    @property
    def adapter_id(self) -> str:
        return str(self.mapping["adapter_id"])

    @property
    def account_fingerprint(self) -> str:
        return self.journal.account_fingerprint

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
            raise BrokerReportConsumerError(
                "broker report consumer is locked by another process"
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
    def _operation_directory_name(operation_key: str) -> str:
        return sha256_digest({"operation_key": operation_key})

    def _operation_root(self, operation_key: str) -> Path:
        key = _identifier(operation_key, "operation_key")
        return self.root / "operations" / self._operation_directory_name(key)

    def _report_path(self, operation_key: str, sequence: int, digest: str) -> Path:
        return (
            self._operation_root(operation_key)
            / "reports"
            / f"{sequence:012d}-{digest}.json"
        )

    def _application_path(
        self, operation_key: str, sequence: int, digest: str
    ) -> Path:
        return (
            self._operation_root(operation_key)
            / "applications"
            / f"{sequence:012d}-{digest}.json"
        )

    def _normalize_report(self, value: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise BrokerReportConsumerError("broker execution report must be an object")
        required = {
            "schema",
            "adapter_id",
            "account_fingerprint",
            "report_id",
            "report_sequence",
            "operation_key",
            "client_order_id",
            "broker_order_id",
            "raw_status",
            "cumulative_filled_quantity",
            "average_price",
            "cumulative_fee_fen",
            "broker_reported_at",
            "received_at",
        }
        if set(value) != required or value.get("schema") != BROKER_EXECUTION_REPORT_SCHEMA:
            raise BrokerReportConsumerError("broker execution report fields are invalid")
        adapter_id = _identifier(value["adapter_id"], "adapter_id")
        account = str(value["account_fingerprint"] or "").strip()
        if adapter_id != self.adapter_id:
            raise BrokerReportConsumerError("broker report adapter identity mismatch")
        if account != self.account_fingerprint:
            raise BrokerReportConsumerError("broker report account identity mismatch")
        raw_status = str(value["raw_status"] or "").strip().lower().replace("-", "_")
        if raw_status not in self.mapping["status_map"]:
            raise BrokerReportConsumerError("raw broker status is not approved")
        broker_reported_text, broker_reported = _timestamp(
            value["broker_reported_at"], "broker_reported_at"
        )
        received_text, received = _timestamp(value["received_at"], "received_at")
        future_skew = (broker_reported - received).total_seconds()
        if future_skew > int(self.mapping["max_future_clock_skew_seconds"]):
            raise BrokerReportConsumerError(
                "broker_reported_at exceeds the approved future clock skew"
            )
        operation_key = _identifier(value["operation_key"], "operation_key")
        try:
            latest = self.journal.latest(operation_key)
        except BrokerOrderJournalError as exc:
            raise BrokerReportConsumerError(
                "durable lifecycle is unreadable while validating broker report"
            ) from exc
        if latest is None:
            raise BrokerReportConsumerError(
                "broker report operation is absent from durable lifecycle"
            )
        client_order_id = _identifier(value["client_order_id"], "client_order_id")
        broker_order_id = _identifier(value["broker_order_id"], "broker_order_id")
        if client_order_id != latest["client_order_id"]:
            raise BrokerReportConsumerError("broker report client_order_id mismatch")
        if latest.get("broker_order_id") not in {None, broker_order_id}:
            raise BrokerReportConsumerError("broker report broker_order_id mismatch")
        filled = _integer(
            value["cumulative_filled_quantity"],
            "cumulative_filled_quantity",
        )
        fee_fen = _integer(value["cumulative_fee_fen"], "cumulative_fee_fen")
        order_quantity = int(latest["order_quantity"])
        if filled > order_quantity:
            raise BrokerReportConsumerError("broker report fill exceeds order quantity")
        average_price = value["average_price"]
        if filled == 0:
            if average_price is not None:
                raise BrokerReportConsumerError(
                    "zero-fill broker report cannot contain average_price"
                )
            normalized_price = None
        else:
            normalized_price = _decimal_text(
                average_price, "average_price", positive=True
            )
        canonical_status = str(self.mapping["status_map"][raw_status])
        if canonical_status == "ACCEPTED" and filled > 0:
            canonical_status = (
                "FILLED" if filled == order_quantity else "PARTIALLY_FILLED"
            )
        elif canonical_status == "CANCEL_PENDING" and filled == order_quantity:
            canonical_status = "FILLED"
        if canonical_status == "PARTIALLY_FILLED" and not 0 < filled < order_quantity:
            raise BrokerReportConsumerError("partial-fill broker report is incoherent")
        if canonical_status == "FILLED" and filled != order_quantity:
            raise BrokerReportConsumerError("filled broker report is incomplete")
        if canonical_status in {"ACCEPTED", "REJECTED"} and filled != 0:
            raise BrokerReportConsumerError(
                f"{canonical_status} broker report cannot contain fills"
            )
        payload = {
            "schema": BROKER_EXECUTION_REPORT_SCHEMA,
            "adapter_id": adapter_id,
            "account_fingerprint": account,
            "report_id": _identifier(value["report_id"], "report_id"),
            "report_sequence": _integer(
                value["report_sequence"], "report_sequence", positive=True
            ),
            "operation_key": operation_key,
            "client_order_id": client_order_id,
            "broker_order_id": broker_order_id,
            "raw_status": raw_status,
            "canonical_status": canonical_status,
            "order_quantity": order_quantity,
            "cumulative_filled_quantity": filled,
            "average_price": normalized_price,
            "cumulative_fee_fen": fee_fen,
            "broker_reported_at": broker_reported_text,
            "received_at": received_text,
            "delivery_latency_milliseconds": int(
                (received - broker_reported).total_seconds() * 1000
            ),
            "mapping_sha256": self.mapping["mapping_sha256"],
        }
        return {**payload, "source_payload_sha256": sha256_digest(payload)}

    def _validate_record(self, record: dict[str, Any]) -> None:
        required = {
            "schema",
            "arrival_sequence",
            "previous_report_sha256",
            "adapter_id",
            "account_fingerprint",
            "report_id",
            "report_sequence",
            "operation_key",
            "client_order_id",
            "broker_order_id",
            "raw_status",
            "canonical_status",
            "order_quantity",
            "cumulative_filled_quantity",
            "average_price",
            "cumulative_fee_fen",
            "broker_reported_at",
            "received_at",
            "delivery_latency_milliseconds",
            "mapping_sha256",
            "source_payload_sha256",
            "report_sha256",
        }
        if set(record) != required or record.get("schema") != BROKER_REPORT_RECORD_SCHEMA:
            raise BrokerReportConsumerError("stored broker report fields are invalid")
        digest = str(record.get("report_sha256") or "")
        identity = {key: value for key, value in record.items() if key != "report_sha256"}
        if not SHA256_RE.fullmatch(digest) or sha256_digest(identity) != digest:
            raise BrokerReportConsumerError("stored broker report hash mismatch")
        replay_input = {
            "schema": BROKER_EXECUTION_REPORT_SCHEMA,
            "adapter_id": record["adapter_id"],
            "account_fingerprint": record["account_fingerprint"],
            "report_id": record["report_id"],
            "report_sequence": record["report_sequence"],
            "operation_key": record["operation_key"],
            "client_order_id": record["client_order_id"],
            "broker_order_id": record["broker_order_id"],
            "raw_status": record["raw_status"],
            "cumulative_filled_quantity": record[
                "cumulative_filled_quantity"
            ],
            "average_price": record["average_price"],
            "cumulative_fee_fen": record["cumulative_fee_fen"],
            "broker_reported_at": record["broker_reported_at"],
            "received_at": record["received_at"],
        }
        replayed = self._normalize_report(replay_input)
        stored_normalized = {
            key: (
                BROKER_EXECUTION_REPORT_SCHEMA
                if key == "schema"
                else record[key]
            )
            for key in replayed
        }
        if replayed != stored_normalized:
            raise BrokerReportConsumerError(
                "stored broker report semantic replay mismatch"
            )

    def _load_reports(
        self, operation_key: str, *, repair: bool
    ) -> list[dict[str, Any]]:
        key = _identifier(operation_key, "operation_key")
        operation_root = self._operation_root(key)
        head_path = operation_root / "report-head.json"
        paths = sorted((operation_root / "reports").glob("*.json"))
        head: dict[str, Any] | None = None
        if head_path.exists():
            try:
                head = dict(_read_json(head_path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerReportConsumerError(
                    f"broker report head is unreadable: {exc}"
                ) from exc
            if set(head) != {"schema", "arrival_sequence", "report_sha256"} or head.get(
                "schema"
            ) != BROKER_REPORT_HEAD_SCHEMA:
                raise BrokerReportConsumerError("broker report head fields are invalid")
        reports: list[dict[str, Any]] = []
        previous_sha: str | None = None
        report_ids: set[str] = set()
        report_sequences: set[int] = set()
        for expected_arrival, path in enumerate(paths, start=1):
            try:
                report = dict(_read_json(path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerReportConsumerError(
                    f"stored broker report is unreadable: {path.name}: {exc}"
                ) from exc
            self._validate_record(report)
            digest = report["report_sha256"]
            if path.name != self._report_path(key, expected_arrival, digest).name:
                raise BrokerReportConsumerError("stored broker report filename mismatch")
            if (
                report["arrival_sequence"] != expected_arrival
                or report["previous_report_sha256"] != previous_sha
                or report["operation_key"] != key
                or report["adapter_id"] != self.adapter_id
                or report["account_fingerprint"] != self.account_fingerprint
                or report["mapping_sha256"] != self.mapping["mapping_sha256"]
            ):
                raise BrokerReportConsumerError("stored broker report chain identity broke")
            if report["report_id"] in report_ids:
                raise BrokerReportConsumerError("stored broker report_id is duplicated")
            if int(report["report_sequence"]) in report_sequences:
                raise BrokerReportConsumerError("stored broker report sequence is duplicated")
            report_ids.add(report["report_id"])
            report_sequences.add(int(report["report_sequence"]))
            previous_sha = digest
            reports.append(report)
        if not reports:
            if head is not None:
                raise BrokerReportConsumerError("broker report head exists without reports")
            return []
        expected_head = {
            "schema": BROKER_REPORT_HEAD_SCHEMA,
            "arrival_sequence": len(reports),
            "report_sha256": reports[-1]["report_sha256"],
        }
        if head is None:
            if not repair:
                raise BrokerReportConsumerError("broker report head is missing")
            _atomic_json(head_path, expected_head)
        elif head != expected_head:
            head_sequence = _integer(
                head.get("arrival_sequence"), "arrival_sequence", positive=True
            )
            prefix_valid = (
                head_sequence <= len(reports)
                and head.get("report_sha256")
                == reports[head_sequence - 1]["report_sha256"]
            )
            if not repair or not prefix_valid:
                raise BrokerReportConsumerError(
                    "broker report head does not match the report chain"
                )
            _atomic_json(head_path, expected_head)
        return reports

    def _load_applications(
        self,
        operation_key: str,
        reports: list[dict[str, Any]],
        *,
        repair: bool,
    ) -> list[dict[str, Any]]:
        key = _identifier(operation_key, "operation_key")
        operation_root = self._operation_root(key)
        head_path = operation_root / "application-head.json"
        paths = sorted((operation_root / "applications").glob("*.json"))
        head: dict[str, Any] | None = None
        if head_path.exists():
            try:
                head = dict(_read_json(head_path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerReportConsumerError(
                    f"broker report application head is unreadable: {exc}"
                ) from exc
            if set(head) != {
                "schema",
                "application_sequence",
                "application_sha256",
            } or head.get("schema") != BROKER_REPORT_APPLICATION_HEAD_SCHEMA:
                raise BrokerReportConsumerError(
                    "broker report application head fields are invalid"
                )
        reports_by_sha = {report["report_sha256"]: report for report in reports}
        applications: list[dict[str, Any]] = []
        previous_sha: str | None = None
        for expected_sequence, path in enumerate(paths, start=1):
            try:
                application = dict(_read_json(path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerReportConsumerError(
                    f"broker report application is unreadable: {path.name}: {exc}"
                ) from exc
            required = {
                "schema",
                "application_sequence",
                "previous_application_sha256",
                "account_fingerprint",
                "adapter_id",
                "operation_key",
                "source_report_sha256",
                "source_report_sequence",
                "lifecycle_event_sha256",
                "fill_settlement_sha256",
                "account_reservation_event_sha256",
                "lifecycle_recorded_at",
                "application_sha256",
            }
            if set(application) != required or application.get(
                "schema"
            ) != BROKER_REPORT_APPLICATION_SCHEMA:
                raise BrokerReportConsumerError(
                    "broker report application fields are invalid"
                )
            digest = str(application.get("application_sha256") or "")
            identity = {
                name: value
                for name, value in application.items()
                if name != "application_sha256"
            }
            if not SHA256_RE.fullmatch(digest) or sha256_digest(identity) != digest:
                raise BrokerReportConsumerError(
                    "broker report application hash mismatch"
                )
            if path.name != self._application_path(
                key, expected_sequence, digest
            ).name:
                raise BrokerReportConsumerError(
                    "broker report application filename mismatch"
                )
            if (
                application["application_sequence"] != expected_sequence
                or application["previous_application_sha256"] != previous_sha
                or application["source_report_sequence"] != expected_sequence
                or application["operation_key"] != key
                or application["adapter_id"] != self.adapter_id
                or application["account_fingerprint"] != self.account_fingerprint
            ):
                raise BrokerReportConsumerError(
                    "broker report application chain identity broke"
                )
            report = reports_by_sha.get(application["source_report_sha256"])
            if report is None or int(report["report_sequence"]) != expected_sequence:
                raise BrokerReportConsumerError(
                    "broker report application source is absent"
                )
            lifecycle = self.journal.event_by_sha256(
                application["lifecycle_event_sha256"]
            )
            if lifecycle is None or any(
                (
                    lifecycle["operation_key"] != key,
                    lifecycle["client_order_id"] != report["client_order_id"],
                    lifecycle["broker_order_id"] != report["broker_order_id"],
                    lifecycle["status"] != report["canonical_status"],
                    int(lifecycle["cumulative_filled_quantity"])
                    != int(report["cumulative_filled_quantity"]),
                    lifecycle["average_price"] != report["average_price"],
                    int(lifecycle["cumulative_fee_fen"])
                    != int(report["cumulative_fee_fen"]),
                    lifecycle["recorded_at"]
                    != application["lifecycle_recorded_at"],
                )
            ):
                raise BrokerReportConsumerError(
                    "broker report application lifecycle binding mismatch"
                )
            settlement_sha = application["fill_settlement_sha256"]
            if settlement_sha is not None:
                settlement = self.journal.fill_settlement_by_sha256(
                    key, settlement_sha
                )
                if (
                    settlement is None
                    or settlement["source_lifecycle_event_sha256"]
                    != lifecycle["event_sha256"]
                ):
                    raise BrokerReportConsumerError(
                        "broker report application settlement binding mismatch"
                    )
            elif report["canonical_status"] not in {"REJECTED", "UNKNOWN"}:
                raise BrokerReportConsumerError(
                    "settleable broker report application lacks settlement"
                )
            reservation = self.account_reservation_book.event_by_sha256(
                application["account_reservation_event_sha256"]
            )
            if (
                reservation is None
                or reservation["operation_key"] != key
                or reservation["source_lifecycle_event_sha256"]
                != lifecycle["event_sha256"]
            ):
                raise BrokerReportConsumerError(
                    "broker report application reservation binding mismatch"
                )
            previous_sha = digest
            applications.append(application)
        if not applications:
            if head is not None:
                raise BrokerReportConsumerError(
                    "broker report application head exists without applications"
                )
            return []
        expected_head = {
            "schema": BROKER_REPORT_APPLICATION_HEAD_SCHEMA,
            "application_sequence": len(applications),
            "application_sha256": applications[-1]["application_sha256"],
        }
        if head is None:
            if not repair:
                raise BrokerReportConsumerError(
                    "broker report application head is missing"
                )
            _atomic_json(head_path, expected_head)
        elif head != expected_head:
            head_sequence = _integer(
                head.get("application_sequence"),
                "application_sequence",
                positive=True,
            )
            prefix_valid = (
                head_sequence <= len(applications)
                and head.get("application_sha256")
                == applications[head_sequence - 1]["application_sha256"]
            )
            if not repair or not prefix_valid:
                raise BrokerReportConsumerError(
                    "broker report application head does not match its chain"
                )
            _atomic_json(head_path, expected_head)
        return applications

    def _discover_operation_keys(self) -> list[str]:
        operations_root = self.root / "operations"
        keys: list[str] = []
        for operation_root in sorted(
            path for path in operations_root.glob("*") if path.is_dir()
        ):
            report_paths = sorted((operation_root / "reports").glob("*.json"))
            if not report_paths:
                raise BrokerReportConsumerError(
                    "broker report operation directory has no report evidence"
                )
            try:
                key = _identifier(
                    dict(_read_json(report_paths[0]))["operation_key"],
                    "operation_key",
                )
            except (OSError, json.JSONDecodeError, ValueError, KeyError) as exc:
                raise BrokerReportConsumerError(
                    "broker report operation identity cannot be recovered"
                ) from exc
            if operation_root.name != self._operation_directory_name(key):
                raise BrokerReportConsumerError(
                    "broker report operation directory identity mismatch"
                )
            keys.append(key)
        if len(keys) != len(set(keys)):
            raise BrokerReportConsumerError(
                "broker report operation identity is duplicated"
            )
        return sorted(keys)

    def _verify_all(self, *, repair: bool) -> dict[str, tuple[list, list]]:
        try:
            stored_mapping = validate_broker_report_mapping(
                dict(_read_json(self.root / "mapping.json"))
            )
            if stored_mapping != self.mapping:
                raise BrokerReportConsumerError(
                    "stored broker report mapping changed"
                )
            verified: dict[str, tuple[list, list]] = {}
            for key in self._discover_operation_keys():
                reports = self._load_reports(key, repair=repair)
                applications = self._load_applications(
                    key, reports, repair=repair
                )
                verified[key] = (reports, applications)
            return verified
        except BrokerReportConsumerError:
            raise
        except (
            BrokerOrderJournalError,
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise BrokerReportConsumerError(
                f"broker report evidence cannot be verified: {exc}"
            ) from exc

    def _persist_report(
        self,
        normalized: dict[str, Any],
        reports: list[dict[str, Any]],
    ) -> dict[str, Any]:
        operation_key = normalized["operation_key"]
        identity = {
            "schema": BROKER_REPORT_RECORD_SCHEMA,
            "arrival_sequence": len(reports) + 1,
            "previous_report_sha256": (
                reports[-1]["report_sha256"] if reports else None
            ),
            **{
                key: value
                for key, value in normalized.items()
                if key != "schema"
            },
        }
        digest = sha256_digest(identity)
        record = {**identity, "report_sha256": digest}
        _immutable_json(
            self._report_path(operation_key, identity["arrival_sequence"], digest),
            record,
        )
        _atomic_json(
            self._operation_root(operation_key) / "report-head.json",
            {
                "schema": BROKER_REPORT_HEAD_SCHEMA,
                "arrival_sequence": identity["arrival_sequence"],
                "report_sha256": digest,
            },
        )
        return record

    def _apply_report(
        self,
        report: dict[str, Any],
        applications: list[dict[str, Any]],
        *,
        allocation_plan: dict[str, Any] | None,
    ) -> dict[str, Any]:
        operation_key = report["operation_key"]
        latest = self.journal.latest(operation_key)
        if latest is None:
            raise BrokerReportConsumerError(
                "broker report application lost its lifecycle operation"
            )
        if latest["client_order_id"] != report["client_order_id"] or latest.get(
            "broker_order_id"
        ) not in {None, report["broker_order_id"]}:
            raise BrokerReportConflict(
                "broker report application conflicts with lifecycle identity"
            )
        received_at = datetime.fromisoformat(report["received_at"])
        prior_recorded_at = datetime.fromisoformat(latest["recorded_at"])
        lifecycle_recorded_at = max(received_at, prior_recorded_at)
        status = report["canonical_status"]
        try:
            if (
                latest["status"] == "SUBMITTING"
                and status in {"ACCEPTED", "REJECTED"}
                and int(report["cumulative_filled_quantity"]) == 0
                and int(report["cumulative_fee_fen"]) == 0
            ):
                lifecycle = self.journal.acknowledge_submission(
                    operation_key,
                    recorded_at=lifecycle_recorded_at,
                    broker_order_id=report["broker_order_id"],
                    accepted=status == "ACCEPTED",
                )
            else:
                lifecycle = self.journal.reconcile(
                    operation_key,
                    recorded_at=lifecycle_recorded_at,
                    status=status,
                    broker_order_id=report["broker_order_id"],
                    cumulative_filled_quantity=report[
                        "cumulative_filled_quantity"
                    ],
                    average_price=report["average_price"],
                    cumulative_fee_fen=report["cumulative_fee_fen"],
                )
            settlement = None
            if status not in {"REJECTED", "UNKNOWN"}:
                settlement = (
                    self.journal.settle_latest_parent_fill(
                        allocation_plan, operation_key
                    )
                    if allocation_plan is not None
                    else self.journal.settle_latest_parent_fill_for_operation(
                        operation_key
                    )
                )
            reservation = self.account_reservation_book.reconcile_lifecycle(
                lifecycle
            )
        except (BrokerOrderJournalError, BrokerAccountControlError) as exc:
            raise BrokerReportConflict(
                "broker report conflicts with durable lifecycle or settlement"
            ) from exc
        identity = {
            "schema": BROKER_REPORT_APPLICATION_SCHEMA,
            "application_sequence": len(applications) + 1,
            "previous_application_sha256": (
                applications[-1]["application_sha256"] if applications else None
            ),
            "account_fingerprint": self.account_fingerprint,
            "adapter_id": self.adapter_id,
            "operation_key": operation_key,
            "source_report_sha256": report["report_sha256"],
            "source_report_sequence": report["report_sequence"],
            "lifecycle_event_sha256": lifecycle["event_sha256"],
            "fill_settlement_sha256": (
                settlement["settlement_sha256"] if settlement is not None else None
            ),
            "account_reservation_event_sha256": reservation["event_sha256"],
            "lifecycle_recorded_at": lifecycle["recorded_at"],
        }
        if identity["application_sequence"] != report["report_sequence"]:
            raise BrokerReportConflict(
                "broker report application sequence is not contiguous"
            )
        digest = sha256_digest(identity)
        application = {**identity, "application_sha256": digest}
        _immutable_json(
            self._application_path(
                operation_key, identity["application_sequence"], digest
            ),
            application,
        )
        _atomic_json(
            self._operation_root(operation_key) / "application-head.json",
            {
                "schema": BROKER_REPORT_APPLICATION_HEAD_SCHEMA,
                "application_sequence": identity["application_sequence"],
                "application_sha256": digest,
            },
        )
        return application

    def consume(
        self,
        report_value: dict[str, Any],
        *,
        allocation_plan: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Persist one report and drain every now-contiguous broker sequence."""

        normalized = self._normalize_report(report_value)
        operation_key = normalized["operation_key"]
        with self._lock():
            verified = self._verify_all(repair=True)
            reports, applications = verified.get(operation_key, ([], []))
            by_id = {report["report_id"]: report for report in reports}
            by_sequence = {
                int(report["report_sequence"]): report for report in reports
            }
            existing = by_id.get(normalized["report_id"])
            sequence_existing = by_sequence.get(int(normalized["report_sequence"]))
            if existing is not None or sequence_existing is not None:
                candidate = existing or sequence_existing
                assert candidate is not None
                if (
                    existing is not sequence_existing
                    or candidate["source_payload_sha256"]
                    != normalized["source_payload_sha256"]
                ):
                    raise BrokerReportConflict(
                        "broker report id or sequence was reused with different evidence"
                    )
                stored = candidate
                report_idempotent = True
            else:
                stored = self._persist_report(normalized, reports)
                reports = [*reports, stored]
                report_idempotent = False
            reports_by_sequence = {
                int(item["report_sequence"]): item for item in reports
            }
            applied: list[dict[str, Any]] = []
            next_sequence = len(applications) + 1
            while next_sequence in reports_by_sequence:
                application = self._apply_report(
                    reports_by_sequence[next_sequence],
                    applications,
                    allocation_plan=allocation_plan,
                )
                applications.append(application)
                applied.append(application)
                if (
                    reports_by_sequence[next_sequence]["canonical_status"]
                    == "UNKNOWN"
                ):
                    break
                next_sequence += 1
            pending = sorted(
                sequence
                for sequence in reports_by_sequence
                if sequence > len(applications)
            )
            next_expected = len(applications) + 1
            unresolved = bool(applications) and reports_by_sequence[
                len(applications)
            ]["canonical_status"] == "UNKNOWN"
            return {
                "schema": BROKER_REPORT_CONSUMPTION_SCHEMA,
                "status": (
                    "UNRESOLVED"
                    if unresolved
                    else "GAP_WAITING"
                    if pending and pending[0] > next_expected
                    else "READY"
                ),
                "operation_key": operation_key,
                "report_sha256": stored["report_sha256"],
                "report_idempotent": report_idempotent,
                "applied": applied,
                "next_expected_report_sequence": next_expected,
                "pending_report_sequences": pending,
            }

    def inspect(self) -> dict[str, Any]:
        """Verify mappings, report chains, application receipts, and gaps."""

        try:
            verified = self._verify_all(repair=False)
            operations: list[dict[str, Any]] = []
            total_reports = 0
            total_applications = 0
            overall = "EMPTY" if not verified else "READY"
            priority = {
                "EMPTY": 0,
                "READY": 1,
                "PENDING_APPLICATION": 2,
                "GAP_WAITING": 3,
                "UNRESOLVED": 4,
            }
            for key, (reports, applications) in sorted(verified.items()):
                total_reports += len(reports)
                total_applications += len(applications)
                report_sequences = sorted(
                    int(report["report_sequence"]) for report in reports
                )
                next_expected = len(applications) + 1
                pending = [
                    sequence
                    for sequence in report_sequences
                    if sequence >= next_expected
                ]
                if applications and next(
                    report
                    for report in reports
                    if int(report["report_sequence"]) == len(applications)
                )["canonical_status"] == "UNKNOWN":
                    status = "UNRESOLVED"
                elif pending and pending[0] > next_expected:
                    status = "GAP_WAITING"
                elif pending:
                    status = "PENDING_APPLICATION"
                else:
                    status = "READY"
                if priority[status] > priority[overall]:
                    overall = status
                operations.append(
                    {
                        "operation_key": key,
                        "status": status,
                        "report_count": len(reports),
                        "application_count": len(applications),
                        "next_expected_report_sequence": next_expected,
                        "pending_report_sequences": pending,
                    }
                )
            return {
                "schema": BROKER_REPORT_INSPECTION_SCHEMA,
                "status": overall,
                "read_only_recommended": overall not in {"EMPTY", "READY"},
                "error": None,
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "mapping_sha256": self.mapping["mapping_sha256"],
                "report_count": total_reports,
                "application_count": total_applications,
                "operations": operations,
            }
        except (
            BrokerReportConsumerError,
            BrokerOrderJournalError,
            BrokerAccountControlError,
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            return {
                "schema": BROKER_REPORT_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "read_only_recommended": True,
                "error": str(exc),
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "mapping_sha256": self.mapping["mapping_sha256"],
                "report_count": 0,
                "application_count": 0,
                "operations": [],
            }
