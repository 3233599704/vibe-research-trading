"""Content-addressed certification for provider normalization adapters.

Legal authorization proves that data may be used.  It does not prove that a
particular adapter version handles malformed, duplicated, reordered or changed
provider responses safely.  This module keeps those concerns separate: a
provider adapter must pass a frozen offline scenario suite, be registered in an
append-only chain, remain unexpired and not be revoked before it may support a
forward-observation source.

Certification never performs network access and never enables broker orders.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence
from zoneinfo import ZoneInfo

from .provenance import sha256_digest
from .provider_rehearsal import (
    SYNTHETIC_PROVENANCE_FORBIDDEN,
    ProviderRehearsalError,
    forbid_synthetic_provenance,
)
from .provider_sample_intake import (
    ProviderSampleIntakeError,
    ProviderSampleIntakeRegistry,
)
from .strict_contract_json import StrictContractJSONError, strict_json_file_object


PROVIDER_ADAPTER_CONTRACT_SCHEMA = "quant-platform/provider-adapter-contract/v1"
PROVIDER_ADAPTER_SCENARIO_EVIDENCE_SCHEMA = (
    "quant-platform/provider-adapter-scenario-evidence/v1"
)
PROVIDER_ADAPTER_CERTIFICATION_REPORT_SCHEMA = (
    "quant-platform/provider-adapter-certification-report/v1"
)
PROVIDER_ADAPTER_CERTIFICATION_RECORD_SCHEMA = (
    "quant-platform/provider-adapter-certification-record/v1"
)
PROVIDER_ADAPTER_CERTIFICATION_HEAD_SCHEMA = (
    "quant-platform/provider-adapter-certification-head/v1"
)
PROVIDER_ADAPTER_CERTIFICATION_INSPECTION_SCHEMA = (
    "quant-platform/provider-adapter-certification-inspection/v1"
)
PROVIDER_ADAPTER_CERTIFICATION_RESOLUTION_SCHEMA = (
    "quant-platform/provider-adapter-certification-resolution/v1"
)
PROVIDER_ADAPTER_CERTIFICATION_SUITE_ID = "provider-adapter-offline-v1"
PROVIDER_ADAPTER_CERTIFICATION_SUITE_VERSION = "1.1.0"
PROVIDER_ADAPTER_MAX_VALIDITY_DAYS = 90
PROVIDER_ADAPTER_CERTIFICATION_ENVIRONMENT = "offline_frozen_fixtures"

REQUIRED_PROVIDER_ADAPTER_SCENARIOS = (
    "adapter_identity_binding",
    "adjustment_semantics",
    "deterministic_normalization",
    "duplicate_missing_ordering_handling",
    "event_and_availability_time_semantics",
    "expected_output_contract",
    "provider_revision_lineage_and_corrections",
    "raw_fixture_integrity",
    "restart_replay_consistency",
    "schema_drift_fail_closed",
    "strict_parse_and_schema",
)
REQUIRED_PROVIDER_REVISION_ASSERTIONS = (
    "revision_prior_snapshot_replayable",
    "revision_corrected_snapshot_replayable",
    "revision_monotonic_available_at",
    "revision_preserves_prior_content_address",
)

SHANGHAI = ZoneInfo("Asia/Shanghai")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_ASSERTION_RE = re.compile(r"^[a-z][a-z0-9._-]{0,159}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class ProviderAdapterCertificationError(RuntimeError):
    """Raised when adapter certification evidence cannot be trusted."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "PROVIDER_ADAPTER_CERTIFICATION_DEGRADED",
    ) -> None:
        self.error_code = error_code
        super().__init__(message)


class ProviderAdapterCertificationConflict(ProviderAdapterCertificationError):
    """Raised when an immutable registration or revocation is reused."""


def _forbid_synthetic(value: Any) -> None:
    try:
        forbid_synthetic_provenance(value)
    except ProviderRehearsalError as exc:
        raise ProviderAdapterCertificationError(
            SYNTHETIC_PROVENANCE_FORBIDDEN,
            error_code=SYNTHETIC_PROVENANCE_FORBIDDEN,
        ) from exc


class ProviderAdapterCertificationDriver(Protocol):
    """Vendor-specific driver used only by the frozen offline test runner."""

    source_id: str
    source_version: str
    bundle_sha256: str
    authorization_grant_sha256: str
    endpoint_contract_sha256: str
    endpoint_normalizers: Mapping[str, str]
    sample_registry_path: str
    environment: str
    certified_by: str
    certification_reference: str
    limitations: Sequence[str]

    def run_scenario(self, endpoint_id: str, scenario_id: str) -> Mapping[str, Any]: ...


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _ID_RE.fullmatch(text):
        raise ProviderAdapterCertificationError(f"{label} is invalid")
    return text


def _assertion_id(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not _ASSERTION_RE.fullmatch(text):
        raise ProviderAdapterCertificationError("assertion_id is invalid")
    return text


def _text(value: Any, label: str, *, maximum: int = 500) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum:
        raise ProviderAdapterCertificationError(f"{label} is invalid")
    return text


def _hash(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA_RE.fullmatch(text):
        raise ProviderAdapterCertificationError(f"{label} must be a sha256 digest")
    return text


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ProviderAdapterCertificationError(
                f"{label} must be an ISO timestamp"
            ) from exc
    if parsed.tzinfo is None:
        raise ProviderAdapterCertificationError(f"{label} must include a timezone")
    canonical = parsed.isoformat()
    if not isinstance(value, datetime) and canonical != str(value):
        raise ProviderAdapterCertificationError(
            f"{label} is not canonical ISO format"
        )
    return canonical, parsed


def _json_hash(value: Any, label: str) -> str:
    try:
        json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProviderAdapterCertificationError(
            f"{label} must be canonical JSON"
        ) from exc
    return sha256_digest(value)


def _relative_reference(value: Any, label: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    candidate = Path(text)
    if (
        not text
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise ProviderAdapterCertificationError(
            f"{label} must be a safe relative path"
        )
    return text


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = strict_json_file_object(path)
    except (OSError, StrictContractJSONError) as exc:
        raise ProviderAdapterCertificationError(
            f"adapter certification JSON is unreadable: {path}: {exc}"
        ) from exc
    _forbid_synthetic(payload)
    return payload


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(
                payload,
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _immutable_json(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_file():
        if _read_json(path) != dict(payload):
            raise ProviderAdapterCertificationConflict(
                f"immutable provider adapter certification conflict: {path}"
            )
        return
    _atomic_json(path, payload)


def build_provider_adapter_contract(source: Mapping[str, Any]) -> dict[str, Any]:
    """Build the adapter-only portion of a provider source contract.

    Authorization and certification references are deliberately excluded to
    avoid circular hashes.  Endpoint semantics and every implementation
    artifact digest remain bound into the contract.
    """

    _forbid_synthetic(source)
    raw_endpoints = source.get("endpoints")
    if not isinstance(raw_endpoints, list) or not raw_endpoints:
        raise ProviderAdapterCertificationError("provider adapter endpoints are empty")
    endpoints: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_endpoint in raw_endpoints:
        if not isinstance(raw_endpoint, Mapping):
            raise ProviderAdapterCertificationError(
                "provider adapter endpoint must be an object"
            )
        endpoint_id = _identifier(raw_endpoint.get("endpoint_id"), "endpoint_id")
        if endpoint_id in seen:
            raise ProviderAdapterCertificationError(
                "provider adapter endpoint is duplicated"
            )
        seen.add(endpoint_id)
        artifacts: list[dict[str, str]] = []
        artifact_paths: set[str] = set()
        for raw_artifact in list(raw_endpoint.get("normalizer_artifacts") or []):
            if not isinstance(raw_artifact, Mapping) or set(raw_artifact) != {
                "path",
                "sha256",
            }:
                raise ProviderAdapterCertificationError(
                    "provider adapter artifact fields are invalid"
                )
            path = _text(raw_artifact.get("path"), "normalizer artifact path")
            if path in artifact_paths:
                raise ProviderAdapterCertificationError(
                    "provider adapter artifact path is duplicated"
                )
            artifact_paths.add(path)
            artifacts.append(
                {
                    "path": path.replace("\\", "/"),
                    "sha256": _hash(
                        raw_artifact.get("sha256"), "normalizer artifact sha256"
                    ),
                }
            )
        if not artifacts:
            raise ProviderAdapterCertificationError(
                "provider adapter endpoint has no implementation artifacts"
            )
        ceiling = raw_endpoint.get("capability_ceiling")
        if not isinstance(ceiling, Mapping) or not ceiling or any(
            not isinstance(value, bool) for value in ceiling.values()
        ):
            raise ProviderAdapterCertificationError(
                "provider adapter capability ceiling is invalid"
            )
        data_kinds = sorted(
            _identifier(value, "data_kind")
            for value in list(raw_endpoint.get("data_kinds") or [])
        )
        adjustments = sorted(
            _identifier(value, "allowed_adjustment")
            for value in list(raw_endpoint.get("allowed_adjustments") or [])
        )
        if (
            not data_kinds
            or len(data_kinds) != len(set(data_kinds))
            or not adjustments
            or len(adjustments) != len(set(adjustments))
        ):
            raise ProviderAdapterCertificationError(
                "provider adapter endpoint kinds or adjustments are invalid"
            )
        endpoints.append(
            {
                "endpoint_id": endpoint_id,
                "authority": _identifier(
                    raw_endpoint.get("authority"), "endpoint authority"
                ),
                "data_kinds": data_kinds,
                "allowed_adjustments": adjustments,
                "capability_ceiling": {
                    str(key): bool(value)
                    for key, value in sorted(ceiling.items())
                },
                "normalizer_id": _text(
                    raw_endpoint.get("normalizer_id"), "normalizer_id", maximum=160
                ),
                "normalizer_artifacts": sorted(
                    artifacts, key=lambda item: item["path"]
                ),
            }
        )
    return {
        "schema": PROVIDER_ADAPTER_CONTRACT_SCHEMA,
        "source_id": _identifier(source.get("source_id"), "source_id"),
        "source_version": _text(
            source.get("version"), "source_version", maximum=80
        ),
        "bundle_sha256": _hash(source.get("bundle_sha256"), "bundle_sha256"),
        "endpoints": sorted(endpoints, key=lambda item: item["endpoint_id"]),
    }


def provider_adapter_contract_sha256(source: Mapping[str, Any]) -> str:
    return sha256_digest(build_provider_adapter_contract(source))


def build_provider_adapter_scenario_evidence(
    *,
    endpoint_id: str,
    normalizer_id: str,
    scenario_id: str,
    observed_at: datetime,
    fixture_sha256s: Sequence[str],
    sample_receipt_sha256s: Sequence[str],
    assertions: Sequence[Mapping[str, Any]],
    source_references: Sequence[str],
) -> dict[str, Any]:
    _forbid_synthetic(assertions)
    scenario = _identifier(scenario_id, "scenario_id")
    if scenario not in REQUIRED_PROVIDER_ADAPTER_SCENARIOS:
        raise ProviderAdapterCertificationError(
            f"unsupported provider adapter scenario: {scenario}"
        )
    fixtures = sorted(_hash(value, "fixture_sha256") for value in fixture_sha256s)
    if not fixtures or len(fixtures) != len(set(fixtures)):
        raise ProviderAdapterCertificationError(
            "provider adapter fixture hashes are empty or duplicated"
        )
    receipts = sorted(
        _hash(value, "sample_receipt_sha256") for value in sample_receipt_sha256s
    )
    if not receipts or len(receipts) != len(set(receipts)):
        raise ProviderAdapterCertificationError(
            "provider adapter sample receipt hashes are empty or duplicated"
        )
    normalized_assertions: list[dict[str, Any]] = []
    seen_assertions: set[str] = set()
    for raw in assertions:
        item = dict(raw)
        if set(item) != {"assertion_id", "passed", "expected", "actual"}:
            raise ProviderAdapterCertificationError(
                "provider adapter assertion fields are invalid"
            )
        assertion_id = _assertion_id(item["assertion_id"])
        if assertion_id in seen_assertions or not isinstance(item["passed"], bool):
            raise ProviderAdapterCertificationError(
                "provider adapter assertion is duplicated or invalid"
            )
        seen_assertions.add(assertion_id)
        normalized_assertions.append(
            {
                "assertion_id": assertion_id,
                "passed": item["passed"],
                "expected_sha256": _json_hash(item["expected"], "expected"),
                "actual_sha256": _json_hash(item["actual"], "actual"),
            }
        )
    if not normalized_assertions:
        raise ProviderAdapterCertificationError(
            "provider adapter scenario has no assertions"
        )
    if scenario == "provider_revision_lineage_and_corrections":
        missing_revision_assertions = set(REQUIRED_PROVIDER_REVISION_ASSERTIONS) - set(
            seen_assertions
        )
        if missing_revision_assertions:
            raise ProviderAdapterCertificationError(
                "provider revision scenario lacks required assertions: "
                + ", ".join(sorted(missing_revision_assertions))
            )
    references = sorted(
        {_text(value, "source_reference", maximum=256) for value in source_references}
    )
    if not references:
        raise ProviderAdapterCertificationError(
            "provider adapter scenario has no source references"
        )
    identity = {
        "schema": PROVIDER_ADAPTER_SCENARIO_EVIDENCE_SCHEMA,
        "endpoint_id": _identifier(endpoint_id, "endpoint_id"),
        "normalizer_id": _text(normalizer_id, "normalizer_id", maximum=160),
        "scenario_id": scenario,
        "status": (
            "PASS" if all(item["passed"] for item in normalized_assertions) else "FAIL"
        ),
        "observed_at": _timestamp(observed_at, "observed_at")[0],
        "fixture_sha256s": fixtures,
        "sample_receipt_sha256s": receipts,
        "assertions": sorted(
            normalized_assertions, key=lambda item: item["assertion_id"]
        ),
        "source_references": references,
    }
    return {**identity, "evidence_sha256": sha256_digest(identity)}


def validate_provider_adapter_scenario_evidence(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    _forbid_synthetic(value)
    evidence = dict(value)
    required = {
        "schema",
        "endpoint_id",
        "normalizer_id",
        "scenario_id",
        "status",
        "observed_at",
        "fixture_sha256s",
        "sample_receipt_sha256s",
        "assertions",
        "source_references",
        "evidence_sha256",
    }
    if set(evidence) != required or evidence.get(
        "schema"
    ) != PROVIDER_ADAPTER_SCENARIO_EVIDENCE_SCHEMA:
        raise ProviderAdapterCertificationError(
            "provider adapter scenario evidence fields are invalid"
        )
    raw_assertions = evidence.get("assertions")
    if not isinstance(raw_assertions, list):
        raise ProviderAdapterCertificationError(
            "provider adapter scenario assertions are invalid"
        )
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
            raise ProviderAdapterCertificationError(
                "provider adapter assertion evidence fields are invalid"
            )
        assertion_id = _assertion_id(item["assertion_id"])
        if assertion_id in seen or not isinstance(item["passed"], bool):
            raise ProviderAdapterCertificationError(
                "provider adapter assertion evidence is duplicated or invalid"
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
    if not assertions:
        raise ProviderAdapterCertificationError(
            "provider adapter scenario assertions are empty"
        )
    scenario = _identifier(evidence.get("scenario_id"), "scenario_id")
    if scenario not in REQUIRED_PROVIDER_ADAPTER_SCENARIOS:
        raise ProviderAdapterCertificationError(
            "provider adapter scenario is unsupported"
        )
    fixtures = sorted(
        _hash(value, "fixture_sha256")
        for value in list(evidence.get("fixture_sha256s") or [])
    )
    receipts = sorted(
        _hash(value, "sample_receipt_sha256")
        for value in list(evidence.get("sample_receipt_sha256s") or [])
    )
    references = sorted(
        {
            _text(value, "source_reference", maximum=256)
            for value in list(evidence.get("source_references") or [])
        }
    )
    if (
        not fixtures
        or len(fixtures) != len(set(fixtures))
        or not receipts
        or len(receipts) != len(set(receipts))
        or not references
    ):
        raise ProviderAdapterCertificationError(
            "provider adapter scenario references are invalid"
        )
    status = "PASS" if all(item["passed"] for item in assertions) else "FAIL"
    identity = {
        "schema": PROVIDER_ADAPTER_SCENARIO_EVIDENCE_SCHEMA,
        "endpoint_id": _identifier(evidence.get("endpoint_id"), "endpoint_id"),
        "normalizer_id": _text(
            evidence.get("normalizer_id"), "normalizer_id", maximum=160
        ),
        "scenario_id": scenario,
        "status": status,
        "observed_at": _timestamp(evidence.get("observed_at"), "observed_at")[0],
        "fixture_sha256s": fixtures,
        "sample_receipt_sha256s": receipts,
        "assertions": sorted(assertions, key=lambda item: item["assertion_id"]),
        "source_references": references,
    }
    normalized = {**identity, "evidence_sha256": sha256_digest(identity)}
    if normalized != evidence or _hash(
        evidence.get("evidence_sha256"), "evidence_sha256"
    ) != normalized["evidence_sha256"]:
        raise ProviderAdapterCertificationError(
            "provider adapter scenario evidence hash or canonical form mismatch"
        )
    return normalized


def _scenario_summaries(
    evidence: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "endpoint_id": item["endpoint_id"],
            "normalizer_id": item["normalizer_id"],
            "scenario_id": item["scenario_id"],
            "status": item["status"],
            "fixture_sha256s": list(item["fixture_sha256s"]),
            "sample_receipt_sha256s": list(item["sample_receipt_sha256s"]),
            "assertion_count": len(item["assertions"]),
            "evidence_sha256": item["evidence_sha256"],
        }
        for item in sorted(
            evidence, key=lambda item: (item["endpoint_id"], item["scenario_id"])
        )
    ]


def _normalize_endpoint_normalizers(
    endpoint_normalizers: Mapping[str, str],
) -> list[dict[str, str]]:
    endpoints = [
        {
            "endpoint_id": _identifier(endpoint_id, "endpoint_id"),
            "normalizer_id": _text(normalizer_id, "normalizer_id", maximum=160),
        }
        for endpoint_id, normalizer_id in endpoint_normalizers.items()
    ]
    endpoints.sort(key=lambda item: item["endpoint_id"])
    if not endpoints or len({item["endpoint_id"] for item in endpoints}) != len(endpoints):
        raise ProviderAdapterCertificationError(
            "provider adapter endpoint normalizers are empty or duplicated"
        )
    return endpoints


def _validate_evidence_matrix(
    evidence: Sequence[Mapping[str, Any]],
    endpoints: Sequence[Mapping[str, str]],
    *,
    started: datetime,
    completed: datetime,
) -> None:
    expected = {
        (endpoint["endpoint_id"], scenario_id)
        for endpoint in endpoints
        for scenario_id in REQUIRED_PROVIDER_ADAPTER_SCENARIOS
    }
    normalizers = {
        endpoint["endpoint_id"]: endpoint["normalizer_id"] for endpoint in endpoints
    }
    observed: set[tuple[str, str]] = set()
    for item in evidence:
        key = (str(item["endpoint_id"]), str(item["scenario_id"]))
        if key in observed or key not in expected:
            raise ProviderAdapterCertificationError(
                "provider adapter scenario matrix is incomplete or duplicated"
            )
        observed.add(key)
        if item["normalizer_id"] != normalizers[key[0]]:
            raise ProviderAdapterCertificationError(
                "provider adapter scenario normalizer is misbound"
            )
        _, observed_at = _timestamp(item["observed_at"], "observed_at")
        if observed_at < started or observed_at > completed:
            raise ProviderAdapterCertificationError(
                "provider adapter scenario observation is outside certification window"
            )
    if observed != expected:
        raise ProviderAdapterCertificationError(
            "provider adapter scenario matrix is incomplete or duplicated"
        )


def build_provider_adapter_certification_report(
    *,
    source_id: str,
    source_version: str,
    bundle_sha256: str,
    authorization_grant_sha256: str,
    endpoint_contract_sha256: str,
    endpoint_normalizers: Mapping[str, str],
    sample_registry_path: str,
    started_at: datetime,
    completed_at: datetime,
    valid_until: datetime,
    certified_by: str,
    certification_reference: str,
    limitations: Sequence[str],
    scenario_evidence: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    _forbid_synthetic(endpoint_normalizers)
    _forbid_synthetic(scenario_evidence)
    started_text, started = _timestamp(started_at, "started_at")
    completed_text, completed = _timestamp(completed_at, "completed_at")
    valid_text, valid = _timestamp(valid_until, "valid_until")
    if completed < started or valid <= completed or valid - completed > timedelta(
        days=PROVIDER_ADAPTER_MAX_VALIDITY_DAYS
    ):
        raise ProviderAdapterCertificationError(
            "provider adapter certification time window is invalid"
        )
    endpoints = _normalize_endpoint_normalizers(endpoint_normalizers)
    evidence = [
        validate_provider_adapter_scenario_evidence(item)
        for item in scenario_evidence
    ]
    _validate_evidence_matrix(
        evidence, endpoints, started=started, completed=completed
    )
    normalized_limitations = [
        _text(value, "certification limitation") for value in limitations
    ]
    if not normalized_limitations:
        raise ProviderAdapterCertificationError(
            "provider adapter certification limitations are required"
        )
    scenarios = _scenario_summaries(evidence)
    acceptance_receipts = sorted(
        {
            receipt_sha
            for item in evidence
            for receipt_sha in item["sample_receipt_sha256s"]
        }
    )
    identity = {
        "schema": PROVIDER_ADAPTER_CERTIFICATION_REPORT_SCHEMA,
        "suite_id": PROVIDER_ADAPTER_CERTIFICATION_SUITE_ID,
        "suite_version": PROVIDER_ADAPTER_CERTIFICATION_SUITE_VERSION,
        "status": (
            "PASS" if all(item["status"] == "PASS" for item in scenarios) else "FAIL"
        ),
        "environment": PROVIDER_ADAPTER_CERTIFICATION_ENVIRONMENT,
        "source_id": _identifier(source_id, "source_id"),
        "source_version": _text(source_version, "source_version", maximum=80),
        "bundle_sha256": _hash(bundle_sha256, "bundle_sha256"),
        "authorization_grant_sha256": _hash(
            authorization_grant_sha256, "authorization_grant_sha256"
        ),
        "endpoint_contract_sha256": _hash(
            endpoint_contract_sha256, "endpoint_contract_sha256"
        ),
        "endpoints": endpoints,
        "sample_registry_path": _relative_reference(
            sample_registry_path, "sample_registry_path"
        ),
        "sample_acceptance_receipt_sha256s": acceptance_receipts,
        "started_at": started_text,
        "completed_at": completed_text,
        "valid_until": valid_text,
        "certified_by": _text(certified_by, "certified_by", maximum=256),
        "certification_reference": _text(
            certification_reference, "certification_reference", maximum=256
        ),
        "limitations": normalized_limitations,
        "scenarios": scenarios,
        "real_orders": False,
    }
    return {**identity, "report_sha256": sha256_digest(identity)}


def validate_provider_adapter_certification_report(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    _forbid_synthetic(value)
    report = dict(value)
    required = {
        "schema",
        "suite_id",
        "suite_version",
        "status",
        "environment",
        "source_id",
        "source_version",
        "bundle_sha256",
        "authorization_grant_sha256",
        "endpoint_contract_sha256",
        "endpoints",
        "sample_registry_path",
        "sample_acceptance_receipt_sha256s",
        "started_at",
        "completed_at",
        "valid_until",
        "certified_by",
        "certification_reference",
        "limitations",
        "scenarios",
        "real_orders",
        "report_sha256",
    }
    if set(report) != required or report.get(
        "schema"
    ) != PROVIDER_ADAPTER_CERTIFICATION_REPORT_SCHEMA:
        raise ProviderAdapterCertificationError(
            "provider adapter certification report fields are invalid"
        )
    if (
        report.get("suite_id") != PROVIDER_ADAPTER_CERTIFICATION_SUITE_ID
        or report.get("suite_version")
        != PROVIDER_ADAPTER_CERTIFICATION_SUITE_VERSION
        or report.get("environment")
        != PROVIDER_ADAPTER_CERTIFICATION_ENVIRONMENT
        or report.get("real_orders") is not False
    ):
        raise ProviderAdapterCertificationError(
            "provider adapter certification suite contract changed"
        )
    started_text, started = _timestamp(report.get("started_at"), "started_at")
    completed_text, completed = _timestamp(report.get("completed_at"), "completed_at")
    valid_text, valid = _timestamp(report.get("valid_until"), "valid_until")
    if completed < started or valid <= completed or valid - completed > timedelta(
        days=PROVIDER_ADAPTER_MAX_VALIDITY_DAYS
    ):
        raise ProviderAdapterCertificationError(
            "provider adapter certification time window is invalid"
        )
    raw_endpoints = report.get("endpoints")
    if not isinstance(raw_endpoints, list):
        raise ProviderAdapterCertificationError(
            "provider adapter certification endpoints are invalid"
        )
    endpoint_mapping: dict[str, str] = {}
    for raw in raw_endpoints:
        item = dict(raw)
        if set(item) != {"endpoint_id", "normalizer_id"}:
            raise ProviderAdapterCertificationError(
                "provider adapter certification endpoint fields are invalid"
            )
        endpoint_id = _identifier(item.get("endpoint_id"), "endpoint_id")
        if endpoint_id in endpoint_mapping:
            raise ProviderAdapterCertificationError(
                "provider adapter certification endpoint is duplicated"
            )
        endpoint_mapping[endpoint_id] = _text(
            item.get("normalizer_id"), "normalizer_id", maximum=160
        )
    endpoints = _normalize_endpoint_normalizers(endpoint_mapping)
    raw_scenarios = report.get("scenarios")
    if not isinstance(raw_scenarios, list):
        raise ProviderAdapterCertificationError(
            "provider adapter certification scenarios are invalid"
        )
    scenarios: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for raw in raw_scenarios:
        item = dict(raw)
        if set(item) != {
            "endpoint_id",
            "normalizer_id",
            "scenario_id",
            "status",
            "fixture_sha256s",
            "sample_receipt_sha256s",
            "assertion_count",
            "evidence_sha256",
        }:
            raise ProviderAdapterCertificationError(
                "provider adapter scenario summary fields are invalid"
            )
        endpoint_id = _identifier(item.get("endpoint_id"), "endpoint_id")
        scenario_id = _identifier(item.get("scenario_id"), "scenario_id")
        key = (endpoint_id, scenario_id)
        if (
            endpoint_id not in endpoint_mapping
            or scenario_id not in REQUIRED_PROVIDER_ADAPTER_SCENARIOS
            or key in seen
            or item.get("normalizer_id") != endpoint_mapping[endpoint_id]
        ):
            raise ProviderAdapterCertificationError(
                "provider adapter scenario summary is misbound"
            )
        seen.add(key)
        count = item.get("assertion_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 1:
            raise ProviderAdapterCertificationError(
                "provider adapter assertion_count is invalid"
            )
        fixtures = sorted(
            _hash(value, "fixture_sha256")
            for value in list(item.get("fixture_sha256s") or [])
        )
        if not fixtures or len(fixtures) != len(set(fixtures)):
            raise ProviderAdapterCertificationError(
                "provider adapter scenario fixture summary is invalid"
            )
        receipts = sorted(
            _hash(value, "sample_receipt_sha256")
            for value in list(item.get("sample_receipt_sha256s") or [])
        )
        if not receipts or len(receipts) != len(set(receipts)):
            raise ProviderAdapterCertificationError(
                "provider adapter scenario sample receipt summary is invalid"
            )
        if item.get("status") not in {"PASS", "FAIL"}:
            raise ProviderAdapterCertificationError(
                "provider adapter scenario status is invalid"
            )
        scenarios.append(
            {
                "endpoint_id": endpoint_id,
                "normalizer_id": endpoint_mapping[endpoint_id],
                "scenario_id": scenario_id,
                "status": item["status"],
                "fixture_sha256s": fixtures,
                "sample_receipt_sha256s": receipts,
                "assertion_count": count,
                "evidence_sha256": _hash(
                    item.get("evidence_sha256"), "evidence_sha256"
                ),
            }
        )
    expected = {
        (endpoint["endpoint_id"], scenario_id)
        for endpoint in endpoints
        for scenario_id in REQUIRED_PROVIDER_ADAPTER_SCENARIOS
    }
    if seen != expected:
        raise ProviderAdapterCertificationError(
            "provider adapter scenario matrix is incomplete or duplicated"
        )
    scenarios.sort(key=lambda item: (item["endpoint_id"], item["scenario_id"]))
    limitations = [
        _text(value, "certification limitation")
        for value in list(report.get("limitations") or [])
    ]
    if not limitations:
        raise ProviderAdapterCertificationError(
            "provider adapter certification limitations are required"
        )
    status = "PASS" if all(item["status"] == "PASS" for item in scenarios) else "FAIL"
    acceptance_receipts = sorted(
        {
            receipt_sha
            for item in scenarios
            for receipt_sha in item["sample_receipt_sha256s"]
        }
    )
    declared_receipts = sorted(
        _hash(value, "sample_acceptance_receipt_sha256")
        for value in list(report.get("sample_acceptance_receipt_sha256s") or [])
    )
    if (
        not declared_receipts
        or len(declared_receipts) != len(set(declared_receipts))
        or declared_receipts != acceptance_receipts
    ):
        raise ProviderAdapterCertificationError(
            "provider adapter sample acceptance receipt set is misbound"
        )
    identity = {
        "schema": PROVIDER_ADAPTER_CERTIFICATION_REPORT_SCHEMA,
        "suite_id": PROVIDER_ADAPTER_CERTIFICATION_SUITE_ID,
        "suite_version": PROVIDER_ADAPTER_CERTIFICATION_SUITE_VERSION,
        "status": status,
        "environment": PROVIDER_ADAPTER_CERTIFICATION_ENVIRONMENT,
        "source_id": _identifier(report.get("source_id"), "source_id"),
        "source_version": _text(
            report.get("source_version"), "source_version", maximum=80
        ),
        "bundle_sha256": _hash(report.get("bundle_sha256"), "bundle_sha256"),
        "authorization_grant_sha256": _hash(
            report.get("authorization_grant_sha256"),
            "authorization_grant_sha256",
        ),
        "endpoint_contract_sha256": _hash(
            report.get("endpoint_contract_sha256"), "endpoint_contract_sha256"
        ),
        "endpoints": endpoints,
        "sample_registry_path": _relative_reference(
            report.get("sample_registry_path"), "sample_registry_path"
        ),
        "sample_acceptance_receipt_sha256s": declared_receipts,
        "started_at": started_text,
        "completed_at": completed_text,
        "valid_until": valid_text,
        "certified_by": _text(
            report.get("certified_by"), "certified_by", maximum=256
        ),
        "certification_reference": _text(
            report.get("certification_reference"),
            "certification_reference",
            maximum=256,
        ),
        "limitations": limitations,
        "scenarios": scenarios,
        "real_orders": False,
    }
    normalized = {**identity, "report_sha256": sha256_digest(identity)}
    if normalized != report or _hash(
        report.get("report_sha256"), "report_sha256"
    ) != normalized["report_sha256"]:
        raise ProviderAdapterCertificationError(
            "provider adapter certification report hash or canonical form mismatch"
        )
    return normalized


def _validate_report_evidence_binding(
    report: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
) -> None:
    normalized = [
        validate_provider_adapter_scenario_evidence(item) for item in evidence
    ]
    _, started = _timestamp(report["started_at"], "started_at")
    _, completed = _timestamp(report["completed_at"], "completed_at")
    _validate_evidence_matrix(
        normalized,
        list(report["endpoints"]),
        started=started,
        completed=completed,
    )
    if _scenario_summaries(normalized) != report["scenarios"]:
        raise ProviderAdapterCertificationError(
            "provider adapter certification report evidence is misbound"
        )


def _verify_sample_acceptance_binding(
    report: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    *,
    platform_root: Path,
) -> None:
    relative = _relative_reference(
        report.get("sample_registry_path"), "sample_registry_path"
    )
    registry_root = (platform_root / relative).resolve()
    try:
        registry_root.relative_to(platform_root)
    except ValueError as exc:
        raise ProviderAdapterCertificationError(
            "provider sample registry escapes platform root"
        ) from exc
    registry = ProviderSampleIntakeRegistry(
        registry_root, platform_root=platform_root
    )
    resolved_receipts: set[str] = set()
    for item in evidence:
        fixture_hashes = set(item["fixture_sha256s"])
        receipt_hashes = set(item["sample_receipt_sha256s"])
        resolved_artifacts: set[str] = set()
        for receipt_sha in receipt_hashes:
            try:
                resolved = registry.resolve_acceptance(receipt_sha)
            except ProviderSampleIntakeError as exc:
                raise ProviderAdapterCertificationError(
                    f"provider adapter sample registry is invalid: {exc}"
                ) from exc
            if resolved is None:
                raise ProviderAdapterCertificationError(
                    "provider adapter sample acceptance is missing or revoked"
                )
            manifest = dict(resolved["manifest"])
            if (
                manifest.get("source_id") != report.get("source_id")
                or manifest.get("source_version") != report.get("source_version")
                or manifest.get("endpoint_id") != item.get("endpoint_id")
                or manifest.get("authorization_grant_sha256")
                != report.get("authorization_grant_sha256")
                or manifest.get("purpose") != "adapter_certification"
            ):
                raise ProviderAdapterCertificationError(
                    "provider adapter sample acceptance identity is misbound"
                )
            resolved_artifacts.add(str(manifest["artifact_sha256"]))
            resolved_receipts.add(receipt_sha)
        if resolved_artifacts != fixture_hashes:
            raise ProviderAdapterCertificationError(
                "provider adapter fixture hashes lack accepted sample receipts"
            )
    if resolved_receipts != set(report["sample_acceptance_receipt_sha256s"]):
        raise ProviderAdapterCertificationError(
            "provider adapter sample receipt set differs from report"
        )


def run_provider_adapter_certification(
    driver: ProviderAdapterCertificationDriver,
    *,
    started_at: datetime,
    completed_at: datetime,
    valid_until: datetime,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run every frozen scenario for every endpoint without network access."""

    if str(driver.environment) != PROVIDER_ADAPTER_CERTIFICATION_ENVIRONMENT:
        raise ProviderAdapterCertificationError(
            "provider adapter certification driver must use frozen offline fixtures"
        )
    endpoint_normalizers = dict(driver.endpoint_normalizers)
    endpoints = _normalize_endpoint_normalizers(endpoint_normalizers)
    evidence: list[dict[str, Any]] = []
    for endpoint in endpoints:
        for scenario_id in REQUIRED_PROVIDER_ADAPTER_SCENARIOS:
            try:
                observation = dict(
                    driver.run_scenario(endpoint["endpoint_id"], scenario_id)
                )
                if set(observation) != {
                    "observed_at",
                    "fixture_sha256s",
                    "sample_receipt_sha256s",
                    "assertions",
                    "source_references",
                }:
                    raise ProviderAdapterCertificationError(
                        "provider adapter driver observation fields are invalid"
                    )
                item = build_provider_adapter_scenario_evidence(
                    endpoint_id=endpoint["endpoint_id"],
                    normalizer_id=endpoint["normalizer_id"],
                    scenario_id=scenario_id,
                    observed_at=observation["observed_at"],
                    fixture_sha256s=list(observation["fixture_sha256s"]),
                    sample_receipt_sha256s=list(
                        observation["sample_receipt_sha256s"]
                    ),
                    assertions=list(observation["assertions"]),
                    source_references=list(observation["source_references"]),
                )
            except Exception as exc:
                item = build_provider_adapter_scenario_evidence(
                    endpoint_id=endpoint["endpoint_id"],
                    normalizer_id=endpoint["normalizer_id"],
                    scenario_id=scenario_id,
                    observed_at=completed_at,
                    fixture_sha256s=["0" * 64],
                    sample_receipt_sha256s=["0" * 64],
                    assertions=[
                        {
                            "assertion_id": "scenario_driver_completed",
                            "passed": False,
                            "expected": "completed-without-error",
                            "actual": type(exc).__name__,
                        }
                    ],
                    source_references=[
                        f"driver-error:{endpoint['endpoint_id']}:{scenario_id}"
                    ],
                )
            evidence.append(item)
    report = build_provider_adapter_certification_report(
        source_id=driver.source_id,
        source_version=driver.source_version,
        bundle_sha256=driver.bundle_sha256,
        authorization_grant_sha256=driver.authorization_grant_sha256,
        endpoint_contract_sha256=driver.endpoint_contract_sha256,
        endpoint_normalizers=endpoint_normalizers,
        sample_registry_path=driver.sample_registry_path,
        started_at=started_at,
        completed_at=completed_at,
        valid_until=valid_until,
        certified_by=driver.certified_by,
        certification_reference=driver.certification_reference,
        limitations=driver.limitations,
        scenario_evidence=evidence,
    )
    return report, evidence


class ProviderAdapterCertificationRegistry:
    """Append-only registry for adapter reports and irreversible revocations."""

    _FROZEN_WIRING_FIELDS = frozenset(
        {
            "root",
            "platform_root",
            "_uses_system_clock",
            "_clock",
            "_wiring_frozen",
            "_FROZEN_WIRING_FIELDS",
        }
    )

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_wiring_frozen", False):
            raise AttributeError("certification registry instance is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        root: str | Path,
        *,
        platform_root: str | Path,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.platform_root = Path(platform_root).expanduser().resolve()
        self._uses_system_clock = clock is None
        self._clock = clock or (lambda: datetime.now(SHANGHAI))
        self._wiring_frozen = True

    @property
    def uses_system_clock(self) -> bool:
        """Whether runtime time comes from the production system clock."""

        return self._uses_system_clock

    @property
    def head_path(self) -> Path:
        return self.root / "head.json"

    def _record_path(self, sequence: int, digest: str) -> Path:
        return self.root / "records" / f"{sequence:012d}-{digest}.json"

    @contextmanager
    def _lock(self) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / ".lock"
        handle = path.open("a+b")
        if path.stat().st_size == 0:
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
            raise ProviderAdapterCertificationError(
                "provider adapter certification registry is locked"
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
        if not self.head_path.is_file():
            if paths:
                raise ProviderAdapterCertificationError(
                    "provider adapter certification head is missing while records exist"
                )
            return []
        head = _read_json(self.head_path)
        if (
            set(head) != {"schema", "sequence", "record_sha256"}
            or head.get("schema") != PROVIDER_ADAPTER_CERTIFICATION_HEAD_SCHEMA
            or not paths
        ):
            raise ProviderAdapterCertificationError(
                "provider adapter certification head is invalid"
            )
        records: list[dict[str, Any]] = []
        previous_sha: str | None = None
        previous_time: datetime | None = None
        registered: dict[str, dict[str, Any]] = {}
        revoked: set[str] = set()
        required = {
            "schema",
            "sequence",
            "previous_record_sha256",
            "recorded_at",
            "action",
            "report_sha256",
            "report",
            "scenario_evidence",
            "revocation_reference",
            "record_sha256",
        }
        for sequence, path in enumerate(paths, start=1):
            record = _read_json(path)
            identity = {
                key: value for key, value in record.items() if key != "record_sha256"
            }
            digest = _hash(record.get("record_sha256"), "record_sha256")
            report_sha = _hash(record.get("report_sha256"), "report_sha256")
            recorded_text, recorded_at = _timestamp(
                record.get("recorded_at"), "recorded_at"
            )
            if (
                set(record) != required
                or record.get("schema")
                != PROVIDER_ADAPTER_CERTIFICATION_RECORD_SCHEMA
                or record.get("sequence") != sequence
                or record.get("previous_record_sha256") != previous_sha
                or sha256_digest(identity) != digest
                or path.name != self._record_path(sequence, digest).name
                or record.get("recorded_at") != recorded_text
                or (previous_time is not None and recorded_at < previous_time)
            ):
                raise ProviderAdapterCertificationError(
                    "provider adapter certification record chain broke"
                )
            if record.get("action") == "REGISTER":
                if (
                    report_sha in registered
                    or report_sha in revoked
                    or record.get("revocation_reference") is not None
                    or not isinstance(record.get("report"), dict)
                    or not isinstance(record.get("scenario_evidence"), list)
                ):
                    raise ProviderAdapterCertificationError(
                        "provider adapter certification registration is invalid"
                    )
                report = validate_provider_adapter_certification_report(
                    dict(record["report"])
                )
                evidence = [
                    validate_provider_adapter_scenario_evidence(item)
                    for item in record["scenario_evidence"]
                ]
                _validate_report_evidence_binding(report, evidence)
                _verify_sample_acceptance_binding(
                    report, evidence, platform_root=self.platform_root
                )
                _, completed_at = _timestamp(report["completed_at"], "completed_at")
                if (
                    report["report_sha256"] != report_sha
                    or report["status"] != "PASS"
                    or recorded_at < completed_at
                ):
                    raise ProviderAdapterCertificationError(
                        "provider adapter certification registration is misbound"
                    )
                registered[report_sha] = report
            elif record.get("action") == "REVOKE":
                if (
                    report_sha not in registered
                    or report_sha in revoked
                    or record.get("report") is not None
                    or record.get("scenario_evidence") is not None
                ):
                    raise ProviderAdapterCertificationError(
                        "provider adapter certification revocation is invalid"
                    )
                _text(record.get("revocation_reference"), "revocation_reference")
                revoked.add(report_sha)
            else:
                raise ProviderAdapterCertificationError(
                    "provider adapter certification action is invalid"
                )
            records.append(record)
            previous_sha = digest
            previous_time = recorded_at
        if (
            head.get("sequence") != len(records)
            or _hash(head.get("record_sha256"), "head record_sha256")
            != records[-1]["record_sha256"]
        ):
            raise ProviderAdapterCertificationError(
                "provider adapter certification head does not match chain"
            )
        return records

    def _append(self, identity: Mapping[str, Any]) -> dict[str, Any]:
        digest = sha256_digest(identity)
        record = {**identity, "record_sha256": digest}
        sequence = int(identity["sequence"])
        _immutable_json(self._record_path(sequence, digest), record)
        _atomic_json(
            self.head_path,
            {
                "schema": PROVIDER_ADAPTER_CERTIFICATION_HEAD_SCHEMA,
                "sequence": sequence,
                "record_sha256": digest,
            },
        )
        self._load_chain()
        return record

    def register(
        self,
        report: Mapping[str, Any],
        *,
        scenario_evidence: Sequence[Mapping[str, Any]],
        recorded_at: datetime,
    ) -> dict[str, Any]:
        normalized_report = validate_provider_adapter_certification_report(report)
        evidence = [
            validate_provider_adapter_scenario_evidence(item)
            for item in scenario_evidence
        ]
        _validate_report_evidence_binding(normalized_report, evidence)
        _verify_sample_acceptance_binding(
            normalized_report, evidence, platform_root=self.platform_root
        )
        if normalized_report["status"] != "PASS":
            raise ProviderAdapterCertificationError(
                "failed provider adapter certification cannot be registered"
            )
        recorded_text, recorded = _timestamp(recorded_at, "recorded_at")
        _, completed = _timestamp(normalized_report["completed_at"], "completed_at")
        if recorded < completed:
            raise ProviderAdapterCertificationError(
                "provider adapter certification was registered before completion"
            )
        report_sha = normalized_report["report_sha256"]
        with self._lock():
            records = self._load_chain()
            existing = [
                item
                for item in records
                if item["action"] == "REGISTER"
                and item["report_sha256"] == report_sha
            ]
            if existing:
                if (
                    existing[0]["report"] != normalized_report
                    or existing[0]["scenario_evidence"] != evidence
                ):
                    raise ProviderAdapterCertificationConflict(
                        "provider adapter certification identity changed"
                    )
                return {**existing[0], "idempotent": True}
            if any(
                item["action"] == "REVOKE" and item["report_sha256"] == report_sha
                for item in records
            ):
                raise ProviderAdapterCertificationConflict(
                    "revoked provider adapter certification cannot be registered again"
                )
            if records and recorded_text < records[-1]["recorded_at"]:
                raise ProviderAdapterCertificationError(
                    "provider adapter certification recorded_at moved backwards"
                )
            identity = {
                "schema": PROVIDER_ADAPTER_CERTIFICATION_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": (
                    records[-1]["record_sha256"] if records else None
                ),
                "recorded_at": recorded_text,
                "action": "REGISTER",
                "report_sha256": report_sha,
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
        reference = _text(revocation_reference, "revocation_reference")
        recorded_text, _ = _timestamp(recorded_at, "recorded_at")
        with self._lock():
            records = self._load_chain()
            if not any(
                item["action"] == "REGISTER"
                and item["report_sha256"] == report_sha
                for item in records
            ):
                raise ProviderAdapterCertificationError(
                    "cannot revoke an unknown provider adapter certification"
                )
            existing = [
                item
                for item in records
                if item["action"] == "REVOKE"
                and item["report_sha256"] == report_sha
            ]
            if existing:
                if existing[0]["revocation_reference"] != reference:
                    raise ProviderAdapterCertificationConflict(
                        "provider adapter certification revocation identity changed"
                    )
                return {**existing[0], "idempotent": True}
            if records and recorded_text < records[-1]["recorded_at"]:
                raise ProviderAdapterCertificationError(
                    "provider adapter certification recorded_at moved backwards"
                )
            identity = {
                "schema": PROVIDER_ADAPTER_CERTIFICATION_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": records[-1]["record_sha256"],
                "recorded_at": recorded_text,
                "action": "REVOKE",
                "report_sha256": report_sha,
                "report": None,
                "scenario_evidence": None,
                "revocation_reference": reference,
            }
            return {**self._append(identity), "idempotent": False}

    def resolve(
        self,
        report_sha256: str,
        *,
        as_of: datetime | None = None,
    ) -> dict[str, Any] | None:
        report_sha = _hash(report_sha256, "report_sha256")
        records = self._load_chain()
        if any(
            item["action"] == "REVOKE" and item["report_sha256"] == report_sha
            for item in records
        ):
            return None
        registrations = [
            item
            for item in records
            if item["action"] == "REGISTER"
            and item["report_sha256"] == report_sha
        ]
        if len(registrations) != 1:
            return None
        report = dict(registrations[0]["report"])
        moment = as_of or self._clock()
        if moment.tzinfo is None:
            raise ProviderAdapterCertificationError(
                "provider adapter certification as_of must include a timezone"
            )
        _, registered_at = _timestamp(
            registrations[0]["recorded_at"], "registered_at"
        )
        _, completed = _timestamp(report["completed_at"], "completed_at")
        _, valid_until = _timestamp(report["valid_until"], "valid_until")
        return report if registered_at <= moment and completed <= moment <= valid_until else None

    def resolve_with_proof(
        self,
        report_sha256: str,
        *,
        as_of: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Resolve one active report and bind it to the exact chain snapshot read."""

        report_sha = _hash(report_sha256, "report_sha256")
        records = self._load_chain()
        registrations = [
            item
            for item in records
            if item["action"] == "REGISTER" and item["report_sha256"] == report_sha
        ]
        if len(registrations) != 1 or any(
            item["action"] == "REVOKE" and item["report_sha256"] == report_sha
            for item in records
        ):
            return None
        report = dict(registrations[0]["report"])
        moment = as_of or self._clock()
        resolved_text, resolved_at = _timestamp(moment, "as_of")
        registered_text, registered_at = _timestamp(
            registrations[0]["recorded_at"], "registered_at"
        )
        _, completed = _timestamp(report["completed_at"], "completed_at")
        _, valid_until = _timestamp(report["valid_until"], "valid_until")
        if not registered_at <= resolved_at or not completed <= resolved_at <= valid_until:
            return None
        return {
            "schema": PROVIDER_ADAPTER_CERTIFICATION_RESOLUTION_SCHEMA,
            "report": report,
            "report_sha256": report_sha,
            "registration_record_sequence": registrations[0]["sequence"],
            "registration_record_sha256": registrations[0]["record_sha256"],
            "registered_at": registered_text,
            "head_sequence": len(records),
            "head_record_sha256": records[-1]["record_sha256"],
            "valid_from": report["completed_at"],
            "valid_until": report["valid_until"],
            "revocation_status": "ACTIVE_AS_OF",
            "resolved_at": resolved_text,
        }

    def fence_resolution_proof(
        self,
        proof: Mapping[str, Any],
    ) -> bool:
        """Fence with the registry's trusted clock; callers cannot backdate it."""

        payload = dict(proof)
        if payload.get("schema") != PROVIDER_ADAPTER_CERTIFICATION_RESOLUTION_SCHEMA:
            return False
        try:
            current = self.resolve_with_proof(
                str(payload.get("report_sha256") or "")
            )
        except ProviderAdapterCertificationError:
            return False
        if current is None:
            return False
        stable_fields = {
            "report",
            "report_sha256",
            "registration_record_sequence",
            "registration_record_sha256",
            "registered_at",
            "head_sequence",
            "head_record_sha256",
            "valid_from",
            "valid_until",
            "revocation_status",
        }
        return all(current.get(key) == payload.get(key) for key in stable_fields)

    def inspect(self, *, as_of: datetime | None = None) -> dict[str, Any]:
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
            active = [
                digest
                for digest in registered - revoked
                if self.resolve(digest, as_of=as_of) is not None
            ]
            return {
                "schema": PROVIDER_ADAPTER_CERTIFICATION_INSPECTION_SCHEMA,
                "status": "EMPTY" if not records else "READY",
                "error": None,
                "error_code": None,
                "real_orders": False,
                "record_count": len(records),
                "registered_report_count": len(registered),
                "revoked_report_count": len(revoked),
                "active_report_count": len(active),
                "head_record_sha256": (
                    records[-1]["record_sha256"] if records else None
                ),
            }
        except ProviderAdapterCertificationError as exc:
            return {
                "schema": PROVIDER_ADAPTER_CERTIFICATION_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "error": str(exc),
                "error_code": exc.error_code,
                "real_orders": False,
                "record_count": 0,
                "registered_report_count": 0,
                "revoked_report_count": 0,
                "active_report_count": 0,
                "head_record_sha256": None,
            }
