"""Content-addressed sandbox certification evidence for broker adapters."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from typing import Any, Iterator, Mapping, Protocol, Sequence

from .provenance import sha256_digest


BROKER_ADAPTER_SCENARIO_EVIDENCE_SCHEMA = (
    "quant-core/broker-adapter-scenario-evidence/v1"
)
BROKER_ADAPTER_CERTIFICATION_REPORT_SCHEMA = (
    "quant-core/broker-adapter-certification-report/v1"
)
BROKER_ADAPTER_CERTIFICATION_RECORD_SCHEMA = (
    "quant-core/broker-adapter-certification-record/v1"
)
BROKER_ADAPTER_CERTIFICATION_HEAD_SCHEMA = (
    "quant-core/broker-adapter-certification-head/v1"
)
BROKER_ADAPTER_CERTIFICATION_INSPECTION_SCHEMA = (
    "quant-core/broker-adapter-certification-inspection/v1"
)
BROKER_ADAPTER_CERTIFICATION_SUITE_ID = "broker-adapter-sandbox-v1"
BROKER_ADAPTER_CERTIFICATION_SUITE_VERSION = "1.0.0"
MAX_CERTIFICATION_VALIDITY_DAYS = 90

REQUIRED_BROKER_ADAPTER_SCENARIOS = (
    "account_order_report_identity_binding",
    "adapter_identity_and_capabilities",
    "atomic_account_snapshot",
    "broker_clock_semantics",
    "cancel_idempotency",
    "cancel_timeout_recovery",
    "client_order_id_idempotency",
    "daily_usage_reconciliation",
    "definite_rejection_terminality",
    "duplicate_client_id_conflict",
    "duplicate_report_idempotency",
    "out_of_order_report_gap_recovery",
    "partial_fill_monotonicity",
    "post_acceptance_timeout_recovery",
    "read_only_and_kill_switch",
    "restart_replay_without_resubmit",
)
REQUIRED_BROKER_ADAPTER_CAPABILITIES = (
    "ACCOUNT_READ",
    "ATOMIC_ACCOUNT_SNAPSHOT_READ",
    "CANCEL_ORDER",
    "CLIENT_ORDER_IDEMPOTENCY",
    "DAILY_USAGE_READ",
    "LIVE_ORDER",
    "ORDERS_READ",
    "POSITIONS_READ",
)

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
ASSERTION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._:-]{0,159}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BrokerAdapterCertificationError(RuntimeError):
    """Raised when certification evidence is malformed or unsafe."""


class BrokerAdapterCertificationConflict(BrokerAdapterCertificationError):
    """Raised when immutable certification identity is reused inconsistently."""


class BrokerAdapterCertificationDriver(Protocol):
    """Vendor-specific sandbox driver used only by the certification runner."""

    adapter_id: str
    adapter_version: str
    adapter_implementation_sha256: str
    sandbox_endpoint_sha256: str
    account_fingerprint: str
    environment: str

    def run_scenario(self, scenario_id: str) -> Mapping[str, Any]: ...


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not ID_RE.fullmatch(text):
        raise BrokerAdapterCertificationError(f"{label} is invalid")
    return text


def _assertion_id(value: Any) -> str:
    text = str(value or "").strip()
    if not ASSERTION_RE.fullmatch(text):
        raise BrokerAdapterCertificationError("assertion_id is invalid")
    return text


def _hash(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not SHA256_RE.fullmatch(text):
        raise BrokerAdapterCertificationError(f"{label} must be a sha256 digest")
    return text


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    try:
        parsed = (
            value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        )
    except (TypeError, ValueError) as exc:
        raise BrokerAdapterCertificationError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise BrokerAdapterCertificationError(f"{label} must include timezone")
    utc = parsed.astimezone(timezone.utc)
    return utc.isoformat(), utc


def _json_hash(value: Any, label: str) -> str:
    try:
        json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise BrokerAdapterCertificationError(
            f"{label} must be canonical JSON"
        ) from exc
    return sha256_digest(value)


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
            raise BrokerAdapterCertificationConflict(
                f"immutable adapter certification conflict: {path.name}"
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


def build_broker_adapter_scenario_evidence(
    *,
    scenario_id: str,
    observed_at: datetime,
    assertions: Sequence[Mapping[str, Any]],
    source_references: Sequence[str],
) -> dict[str, Any]:
    """Hash raw expected/actual observations without persisting their values."""

    scenario = _identifier(scenario_id, "scenario_id")
    if scenario not in REQUIRED_BROKER_ADAPTER_SCENARIOS:
        raise BrokerAdapterCertificationError(
            f"unsupported adapter certification scenario: {scenario}"
        )
    observed_text, _ = _timestamp(observed_at, "observed_at")
    normalized_assertions: list[dict[str, Any]] = []
    seen_assertions: set[str] = set()
    for raw in assertions:
        item = dict(raw)
        if set(item) != {"assertion_id", "passed", "expected", "actual"}:
            raise BrokerAdapterCertificationError(
                "adapter certification assertion fields are invalid"
            )
        assertion_id = _assertion_id(item["assertion_id"])
        if assertion_id in seen_assertions:
            raise BrokerAdapterCertificationError(
                "adapter certification assertion is duplicated"
            )
        seen_assertions.add(assertion_id)
        if not isinstance(item["passed"], bool):
            raise BrokerAdapterCertificationError("assertion passed must be boolean")
        normalized_assertions.append(
            {
                "assertion_id": assertion_id,
                "passed": item["passed"],
                "expected_sha256": _json_hash(item["expected"], "expected"),
                "actual_sha256": _json_hash(item["actual"], "actual"),
            }
        )
    if not normalized_assertions:
        raise BrokerAdapterCertificationError(
            "adapter certification scenario has no assertions"
        )
    references = sorted(
        {_identifier(value, "source_reference") for value in source_references}
    )
    if not references:
        raise BrokerAdapterCertificationError(
            "adapter certification scenario has no source references"
        )
    identity = {
        "schema": BROKER_ADAPTER_SCENARIO_EVIDENCE_SCHEMA,
        "scenario_id": scenario,
        "status": (
            "PASS"
            if all(item["passed"] for item in normalized_assertions)
            else "FAIL"
        ),
        "observed_at": observed_text,
        "assertions": sorted(
            normalized_assertions, key=lambda item: item["assertion_id"]
        ),
        "source_references": references,
    }
    return {**identity, "evidence_sha256": sha256_digest(identity)}


def validate_broker_adapter_scenario_evidence(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    evidence = dict(value)
    required = {
        "schema",
        "scenario_id",
        "status",
        "observed_at",
        "assertions",
        "source_references",
        "evidence_sha256",
    }
    if set(evidence) != required or evidence.get(
        "schema"
    ) != BROKER_ADAPTER_SCENARIO_EVIDENCE_SCHEMA:
        raise BrokerAdapterCertificationError(
            "adapter scenario evidence fields are invalid"
        )
    scenario = _identifier(evidence["scenario_id"], "scenario_id")
    if scenario not in REQUIRED_BROKER_ADAPTER_SCENARIOS:
        raise BrokerAdapterCertificationError("adapter scenario is unsupported")
    observed_text, _ = _timestamp(evidence["observed_at"], "observed_at")
    raw_assertions = evidence.get("assertions")
    if not isinstance(raw_assertions, list) or not raw_assertions:
        raise BrokerAdapterCertificationError("adapter scenario assertions are invalid")
    assertions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in raw_assertions:
        item = dict(raw)
        if set(item) != {
            "assertion_id",
            "passed",
            "expected_sha256",
            "actual_sha256",
        }:
            raise BrokerAdapterCertificationError(
                "adapter scenario assertion fields are invalid"
            )
        assertion_id = _assertion_id(item["assertion_id"])
        if assertion_id in seen or not isinstance(item["passed"], bool):
            raise BrokerAdapterCertificationError(
                "adapter scenario assertion identity is invalid"
            )
        seen.add(assertion_id)
        assertions.append(
            {
                "assertion_id": assertion_id,
                "passed": item["passed"],
                "expected_sha256": _hash(
                    item["expected_sha256"], "expected_sha256"
                ),
                "actual_sha256": _hash(item["actual_sha256"], "actual_sha256"),
            }
        )
    references = evidence.get("source_references")
    if not isinstance(references, list) or not references:
        raise BrokerAdapterCertificationError(
            "adapter scenario source references are invalid"
        )
    normalized_references = sorted(
        {_identifier(value, "source_reference") for value in references}
    )
    if len(normalized_references) != len(references):
        raise BrokerAdapterCertificationError(
            "adapter scenario source references are duplicated"
        )
    status = "PASS" if all(item["passed"] for item in assertions) else "FAIL"
    identity = {
        "schema": BROKER_ADAPTER_SCENARIO_EVIDENCE_SCHEMA,
        "scenario_id": scenario,
        "status": status,
        "observed_at": observed_text,
        "assertions": sorted(assertions, key=lambda item: item["assertion_id"]),
        "source_references": normalized_references,
    }
    normalized = {**identity, "evidence_sha256": sha256_digest(identity)}
    if normalized != evidence or _hash(
        evidence["evidence_sha256"], "evidence_sha256"
    ) != normalized["evidence_sha256"]:
        raise BrokerAdapterCertificationError(
            "adapter scenario evidence hash or canonical form mismatch"
        )
    return normalized


def _scenario_summaries(
    evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "scenario_id": item["scenario_id"],
            "status": item["status"],
            "assertion_count": len(item["assertions"]),
            "evidence_sha256": item["evidence_sha256"],
        }
        for item in sorted(evidence, key=lambda item: item["scenario_id"])
    ]


def build_broker_adapter_certification_report(
    *,
    adapter_id: str,
    adapter_version: str,
    adapter_implementation_sha256: str,
    sandbox_endpoint_sha256: str,
    account_fingerprint: str,
    started_at: datetime,
    completed_at: datetime,
    valid_until: datetime,
    scenario_evidence: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    started_text, started = _timestamp(started_at, "started_at")
    completed_text, completed = _timestamp(completed_at, "completed_at")
    valid_text, valid = _timestamp(valid_until, "valid_until")
    if completed < started:
        raise BrokerAdapterCertificationError(
            "adapter certification completed before it started"
        )
    if valid <= completed or valid - completed > timedelta(
        days=MAX_CERTIFICATION_VALIDITY_DAYS
    ):
        raise BrokerAdapterCertificationError(
            "adapter certification validity is invalid or too long"
        )
    fingerprint = str(account_fingerprint or "").strip()
    if not fingerprint or len(fingerprint) > 160:
        raise BrokerAdapterCertificationError("account_fingerprint is invalid")
    evidence = [
        validate_broker_adapter_scenario_evidence(item)
        for item in scenario_evidence
    ]
    scenario_ids = [item["scenario_id"] for item in evidence]
    if sorted(scenario_ids) != list(REQUIRED_BROKER_ADAPTER_SCENARIOS):
        raise BrokerAdapterCertificationError(
            "adapter certification scenarios are incomplete or duplicated"
        )
    for item in evidence:
        _, observed = _timestamp(item["observed_at"], "observed_at")
        if observed < started or observed > completed:
            raise BrokerAdapterCertificationError(
                "adapter scenario observation is outside certification window"
            )
    scenarios = _scenario_summaries(evidence)
    identity = {
        "schema": BROKER_ADAPTER_CERTIFICATION_REPORT_SCHEMA,
        "suite_id": BROKER_ADAPTER_CERTIFICATION_SUITE_ID,
        "suite_version": BROKER_ADAPTER_CERTIFICATION_SUITE_VERSION,
        "status": (
            "PASS" if all(item["status"] == "PASS" for item in scenarios) else "FAIL"
        ),
        "adapter_id": _identifier(adapter_id, "adapter_id"),
        "adapter_version": _identifier(adapter_version, "adapter_version"),
        "adapter_implementation_sha256": _hash(
            adapter_implementation_sha256, "adapter_implementation_sha256"
        ),
        "environment": "sandbox",
        "sandbox_endpoint_sha256": _hash(
            sandbox_endpoint_sha256, "sandbox_endpoint_sha256"
        ),
        "account_fingerprint": fingerprint,
        "required_capabilities": list(REQUIRED_BROKER_ADAPTER_CAPABILITIES),
        "started_at": started_text,
        "completed_at": completed_text,
        "valid_until": valid_text,
        "scenarios": scenarios,
    }
    return {**identity, "report_sha256": sha256_digest(identity)}


def validate_broker_adapter_certification_report(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    report = dict(value)
    required = {
        "schema",
        "suite_id",
        "suite_version",
        "status",
        "adapter_id",
        "adapter_version",
        "adapter_implementation_sha256",
        "environment",
        "sandbox_endpoint_sha256",
        "account_fingerprint",
        "required_capabilities",
        "started_at",
        "completed_at",
        "valid_until",
        "scenarios",
        "report_sha256",
    }
    if set(report) != required or report.get(
        "schema"
    ) != BROKER_ADAPTER_CERTIFICATION_REPORT_SCHEMA:
        raise BrokerAdapterCertificationError(
            "adapter certification report fields are invalid"
        )
    if report.get("suite_id") != BROKER_ADAPTER_CERTIFICATION_SUITE_ID or report.get(
        "suite_version"
    ) != BROKER_ADAPTER_CERTIFICATION_SUITE_VERSION:
        raise BrokerAdapterCertificationError(
            "adapter certification suite is unsupported"
        )
    if report.get("environment") != "sandbox":
        raise BrokerAdapterCertificationError(
            "adapter certification was not executed in sandbox"
        )
    started_text, started = _timestamp(report["started_at"], "started_at")
    completed_text, completed = _timestamp(report["completed_at"], "completed_at")
    valid_text, valid = _timestamp(report["valid_until"], "valid_until")
    if completed < started or valid <= completed or valid - completed > timedelta(
        days=MAX_CERTIFICATION_VALIDITY_DAYS
    ):
        raise BrokerAdapterCertificationError(
            "adapter certification time window is invalid"
        )
    capabilities = report.get("required_capabilities")
    if capabilities != list(REQUIRED_BROKER_ADAPTER_CAPABILITIES):
        raise BrokerAdapterCertificationError(
            "adapter certification capability contract changed"
        )
    raw_scenarios = report.get("scenarios")
    if not isinstance(raw_scenarios, list):
        raise BrokerAdapterCertificationError(
            "adapter certification scenarios are invalid"
        )
    scenarios: list[dict[str, Any]] = []
    for raw in raw_scenarios:
        item = dict(raw)
        if set(item) != {
            "scenario_id",
            "status",
            "assertion_count",
            "evidence_sha256",
        }:
            raise BrokerAdapterCertificationError(
                "adapter certification scenario summary is invalid"
            )
        scenario_id = _identifier(item["scenario_id"], "scenario_id")
        if scenario_id not in REQUIRED_BROKER_ADAPTER_SCENARIOS:
            raise BrokerAdapterCertificationError(
                "adapter certification scenario is unsupported"
            )
        if item["status"] not in {"PASS", "FAIL"}:
            raise BrokerAdapterCertificationError(
                "adapter certification scenario status is invalid"
            )
        if isinstance(item["assertion_count"], bool) or not isinstance(
            item["assertion_count"], int
        ) or item["assertion_count"] < 1:
            raise BrokerAdapterCertificationError(
                "adapter certification assertion_count is invalid"
            )
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "status": item["status"],
                "assertion_count": item["assertion_count"],
                "evidence_sha256": _hash(
                    item["evidence_sha256"], "evidence_sha256"
                ),
            }
        )
    scenarios.sort(key=lambda item: item["scenario_id"])
    if [item["scenario_id"] for item in scenarios] != list(
        REQUIRED_BROKER_ADAPTER_SCENARIOS
    ):
        raise BrokerAdapterCertificationError(
            "adapter certification scenarios are incomplete or duplicated"
        )
    status = "PASS" if all(item["status"] == "PASS" for item in scenarios) else "FAIL"
    fingerprint = str(report.get("account_fingerprint") or "").strip()
    if not fingerprint or len(fingerprint) > 160:
        raise BrokerAdapterCertificationError("account_fingerprint is invalid")
    identity = {
        "schema": BROKER_ADAPTER_CERTIFICATION_REPORT_SCHEMA,
        "suite_id": BROKER_ADAPTER_CERTIFICATION_SUITE_ID,
        "suite_version": BROKER_ADAPTER_CERTIFICATION_SUITE_VERSION,
        "status": status,
        "adapter_id": _identifier(report["adapter_id"], "adapter_id"),
        "adapter_version": _identifier(report["adapter_version"], "adapter_version"),
        "adapter_implementation_sha256": _hash(
            report["adapter_implementation_sha256"],
            "adapter_implementation_sha256",
        ),
        "environment": "sandbox",
        "sandbox_endpoint_sha256": _hash(
            report["sandbox_endpoint_sha256"], "sandbox_endpoint_sha256"
        ),
        "account_fingerprint": fingerprint,
        "required_capabilities": list(REQUIRED_BROKER_ADAPTER_CAPABILITIES),
        "started_at": started_text,
        "completed_at": completed_text,
        "valid_until": valid_text,
        "scenarios": scenarios,
    }
    normalized = {**identity, "report_sha256": sha256_digest(identity)}
    if normalized != report or _hash(
        report["report_sha256"], "report_sha256"
    ) != normalized["report_sha256"]:
        raise BrokerAdapterCertificationError(
            "adapter certification report hash or canonical form mismatch"
        )
    return normalized


def run_broker_adapter_certification(
    driver: BrokerAdapterCertificationDriver,
    *,
    started_at: datetime,
    completed_at: datetime,
    valid_until: datetime,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run the frozen scenario list through a vendor-specific sandbox driver."""

    if str(driver.environment).lower() != "sandbox":
        raise BrokerAdapterCertificationError(
            "adapter certification driver must target sandbox"
        )
    evidence: list[dict[str, Any]] = []
    for scenario_id in REQUIRED_BROKER_ADAPTER_SCENARIOS:
        try:
            observation = dict(driver.run_scenario(scenario_id))
            if set(observation) != {
                "observed_at",
                "assertions",
                "source_references",
            }:
                raise BrokerAdapterCertificationError(
                    "scenario driver observation fields are invalid"
                )
            item = build_broker_adapter_scenario_evidence(
                scenario_id=scenario_id,
                observed_at=observation["observed_at"],
                assertions=list(observation["assertions"]),
                source_references=list(observation["source_references"]),
            )
        except Exception as exc:
            item = build_broker_adapter_scenario_evidence(
                scenario_id=scenario_id,
                observed_at=completed_at,
                assertions=[
                    {
                        "assertion_id": "scenario_driver_completed",
                        "passed": False,
                        "expected": "completed-without-error",
                        "actual": type(exc).__name__,
                    }
                ],
                source_references=[f"driver-error:{scenario_id}"],
            )
        evidence.append(item)
    report = build_broker_adapter_certification_report(
        adapter_id=driver.adapter_id,
        adapter_version=driver.adapter_version,
        adapter_implementation_sha256=driver.adapter_implementation_sha256,
        sandbox_endpoint_sha256=driver.sandbox_endpoint_sha256,
        account_fingerprint=driver.account_fingerprint,
        started_at=started_at,
        completed_at=completed_at,
        valid_until=valid_until,
        scenario_evidence=evidence,
    )
    return report, evidence


class BrokerAdapterCertificationRegistry:
    """Append-only registry for certification reports and revocations."""

    def __init__(
        self,
        root: str | Path,
        *,
        adapter_id: str,
        account_fingerprint: str,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.adapter_id = _identifier(adapter_id, "adapter_id")
        self.account_fingerprint = str(account_fingerprint or "").strip()
        if not self.account_fingerprint or len(self.account_fingerprint) > 160:
            raise BrokerAdapterCertificationError("account_fingerprint is invalid")

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
            raise BrokerAdapterCertificationError(
                "adapter certification registry is locked"
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
                raise BrokerAdapterCertificationError(
                    "adapter certification head is missing while records exist"
                )
            return []
        try:
            head = dict(_read_json(self.head_path))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise BrokerAdapterCertificationError(
                f"adapter certification head is unreadable: {exc}"
            ) from exc
        if set(head) != {"schema", "sequence", "record_sha256"} or head.get(
            "schema"
        ) != BROKER_ADAPTER_CERTIFICATION_HEAD_SCHEMA:
            raise BrokerAdapterCertificationError(
                "adapter certification head fields are invalid"
            )
        records: list[dict[str, Any]] = []
        previous_sha: str | None = None
        previous_recorded_at: datetime | None = None
        registered: dict[str, dict[str, Any]] = {}
        revoked: dict[str, str] = {}
        for expected_sequence, path in enumerate(paths, start=1):
            try:
                record = dict(_read_json(path))
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                raise BrokerAdapterCertificationError(
                    f"adapter certification record is unreadable: {path.name}: {exc}"
                ) from exc
            required = {
                "schema",
                "sequence",
                "previous_record_sha256",
                "recorded_at",
                "adapter_id",
                "account_fingerprint",
                "action",
                "report_sha256",
                "report",
                "scenario_evidence",
                "revocation_reference",
                "record_sha256",
            }
            if set(record) != required or record.get(
                "schema"
            ) != BROKER_ADAPTER_CERTIFICATION_RECORD_SCHEMA:
                raise BrokerAdapterCertificationError(
                    "adapter certification record fields are invalid"
                )
            identity = {
                key: value for key, value in record.items() if key != "record_sha256"
            }
            digest = _hash(record["record_sha256"], "record_sha256")
            report_sha = _hash(record["report_sha256"], "report_sha256")
            recorded_text, recorded_at = _timestamp(
                record["recorded_at"], "recorded_at"
            )
            if (
                sha256_digest(identity) != digest
                or path.name != self._record_path(expected_sequence, digest).name
                or record["sequence"] != expected_sequence
                or record["previous_record_sha256"] != previous_sha
                or record["adapter_id"] != self.adapter_id
                or record["account_fingerprint"] != self.account_fingerprint
                or recorded_text != record["recorded_at"]
                or (
                    previous_recorded_at is not None
                    and recorded_at < previous_recorded_at
                )
            ):
                raise BrokerAdapterCertificationError(
                    "adapter certification record chain identity broke"
                )
            if record["action"] == "REGISTER":
                if (
                    report_sha in registered
                    or report_sha in revoked
                    or record["revocation_reference"] is not None
                    or not isinstance(record["report"], dict)
                    or not isinstance(record["scenario_evidence"], list)
                ):
                    raise BrokerAdapterCertificationError(
                        "adapter certification registration is invalid"
                    )
                report = validate_broker_adapter_certification_report(
                    record["report"]
                )
                evidence = [
                    validate_broker_adapter_scenario_evidence(item)
                    for item in record["scenario_evidence"]
                ]
                if (
                    report["report_sha256"] != report_sha
                    or report["adapter_id"] != self.adapter_id
                    or report["account_fingerprint"] != self.account_fingerprint
                    or _scenario_summaries(evidence) != report["scenarios"]
                ):
                    raise BrokerAdapterCertificationError(
                        "adapter certification registration evidence is misbound"
                    )
                registered[report_sha] = record
            elif record["action"] == "REVOKE":
                if (
                    report_sha not in registered
                    or report_sha in revoked
                    or record["report"] is not None
                    or record["scenario_evidence"] is not None
                ):
                    raise BrokerAdapterCertificationError(
                        "adapter certification revocation is invalid"
                    )
                revoked[report_sha] = _identifier(
                    record["revocation_reference"], "revocation_reference"
                )
            else:
                raise BrokerAdapterCertificationError(
                    "adapter certification action is invalid"
                )
            records.append(record)
            previous_sha = digest
            previous_recorded_at = recorded_at
        expected_head = {
            "schema": BROKER_ADAPTER_CERTIFICATION_HEAD_SCHEMA,
            "sequence": len(records),
            "record_sha256": records[-1]["record_sha256"],
        }
        if not records or head != expected_head:
            raise BrokerAdapterCertificationError(
                "adapter certification head does not match chain tip"
            )
        return records

    def _append(self, identity: dict[str, Any]) -> dict[str, Any]:
        digest = sha256_digest(identity)
        record = {**identity, "record_sha256": digest}
        _immutable_json(self._record_path(identity["sequence"], digest), record)
        _atomic_json(
            self.head_path,
            {
                "schema": BROKER_ADAPTER_CERTIFICATION_HEAD_SCHEMA,
                "sequence": identity["sequence"],
                "record_sha256": digest,
            },
        )
        return record

    def register(
        self,
        report: Mapping[str, Any],
        *,
        scenario_evidence: Sequence[Mapping[str, Any]],
        recorded_at: datetime,
    ) -> dict[str, Any]:
        normalized_report = validate_broker_adapter_certification_report(report)
        evidence = sorted(
            (
                validate_broker_adapter_scenario_evidence(item)
                for item in scenario_evidence
            ),
            key=lambda item: item["scenario_id"],
        )
        if (
            normalized_report["adapter_id"] != self.adapter_id
            or normalized_report["account_fingerprint"] != self.account_fingerprint
            or _scenario_summaries(evidence) != normalized_report["scenarios"]
        ):
            raise BrokerAdapterCertificationError(
                "adapter certification report and evidence are misbound"
            )
        recorded_text, recorded = _timestamp(recorded_at, "recorded_at")
        _, completed = _timestamp(
            normalized_report["completed_at"], "completed_at"
        )
        if recorded < completed:
            raise BrokerAdapterCertificationError(
                "adapter certification was registered before suite completion"
            )
        with self._lock():
            records = self._load_chain()
            existing = [
                item
                for item in records
                if item["action"] == "REGISTER"
                and item["report_sha256"] == normalized_report["report_sha256"]
            ]
            if existing:
                if (
                    existing[0]["report"] != normalized_report
                    or existing[0]["scenario_evidence"] != evidence
                ):
                    raise BrokerAdapterCertificationConflict(
                        "adapter certification report identity was reused"
                    )
                return {**existing[0], "idempotent": True}
            if records and recorded_text < records[-1]["recorded_at"]:
                raise BrokerAdapterCertificationError(
                    "adapter certification recorded_at moved backwards"
                )
            identity = {
                "schema": BROKER_ADAPTER_CERTIFICATION_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": (
                    records[-1]["record_sha256"] if records else None
                ),
                "recorded_at": recorded_text,
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "action": "REGISTER",
                "report_sha256": normalized_report["report_sha256"],
                "report": normalized_report,
                "scenario_evidence": evidence,
                "revocation_reference": None,
            }
            return {**self._append(identity), "idempotent": False}

    def revoke(
        self,
        report_sha256: str,
        *,
        revocation_reference: str,
        recorded_at: datetime,
    ) -> dict[str, Any]:
        report_sha = _hash(report_sha256, "report_sha256")
        reference = _identifier(revocation_reference, "revocation_reference")
        recorded_text, _ = _timestamp(recorded_at, "recorded_at")
        with self._lock():
            records = self._load_chain()
            registrations = [
                item
                for item in records
                if item["action"] == "REGISTER"
                and item["report_sha256"] == report_sha
            ]
            if not registrations:
                raise BrokerAdapterCertificationError(
                    "cannot revoke an unknown adapter certification"
                )
            revocations = [
                item
                for item in records
                if item["action"] == "REVOKE"
                and item["report_sha256"] == report_sha
            ]
            if revocations:
                if revocations[0]["revocation_reference"] != reference:
                    raise BrokerAdapterCertificationConflict(
                        "adapter certification revocation identity changed"
                    )
                return {**revocations[0], "idempotent": True}
            if records and recorded_text < records[-1]["recorded_at"]:
                raise BrokerAdapterCertificationError(
                    "adapter certification recorded_at moved backwards"
                )
            identity = {
                "schema": BROKER_ADAPTER_CERTIFICATION_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": records[-1]["record_sha256"],
                "recorded_at": recorded_text,
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "action": "REVOKE",
                "report_sha256": report_sha,
                "report": None,
                "scenario_evidence": None,
                "revocation_reference": reference,
            }
            return {**self._append(identity), "idempotent": False}

    def resolve(self, report_sha256: str) -> dict[str, Any] | None:
        report_sha = _hash(report_sha256, "report_sha256")
        records = self._load_chain()
        if any(
            item["action"] == "REVOKE" and item["report_sha256"] == report_sha
            for item in records
        ):
            return None
        registrations = [
            item["report"]
            for item in records
            if item["action"] == "REGISTER" and item["report_sha256"] == report_sha
        ]
        return dict(registrations[0]) if registrations else None

    def inspect(self) -> dict[str, Any]:
        try:
            records = self._load_chain()
            registered = {
                item["report_sha256"]
                for item in records
                if item["action"] == "REGISTER"
            }
            revoked = {
                item["report_sha256"]
                for item in records
                if item["action"] == "REVOKE"
            }
            latest = records[-1] if records else None
            return {
                "schema": BROKER_ADAPTER_CERTIFICATION_INSPECTION_SCHEMA,
                "status": "EMPTY" if not records else "READY",
                "read_only_recommended": False,
                "error": None,
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "record_count": len(records),
                "registered_report_count": len(registered),
                "revoked_report_count": len(revoked),
                "active_report_count": len(registered - revoked),
                "latest_action": latest["action"] if latest else None,
                "latest_record_sha256": (
                    latest["record_sha256"] if latest else None
                ),
            }
        except (
            BrokerAdapterCertificationError,
            OSError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            return {
                "schema": BROKER_ADAPTER_CERTIFICATION_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "read_only_recommended": True,
                "error": str(exc),
                "adapter_id": self.adapter_id,
                "account_fingerprint": self.account_fingerprint,
                "record_count": 0,
                "registered_report_count": 0,
                "revoked_report_count": 0,
                "active_report_count": 0,
                "latest_action": None,
                "latest_record_sha256": None,
            }
