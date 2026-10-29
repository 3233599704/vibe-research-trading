"""Pure, write-free contracts for synthetic provider-admission rehearsal.

Synthetic rehearsal objects are deliberately recognizable at every nesting
level so production provider stores can reject them before validation, locks or
writes.  This module does not create directories, mutate registries, import a
provider SDK, access credentials, or contact a network service.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from .provenance import canonical_json, sha256_digest
from .strict_contract_json import (
    StrictContractJSONError,
    StrictJSONObject,
    strict_json_object,
)


SYNTHETIC_REHEARSAL_ARTIFACT_SCHEMA = (
    "quant-platform/synthetic-provider-rehearsal-artifact/v1"
)
PROVIDER_CANDIDATE_BOOTSTRAP_PLAN_SCHEMA = (
    "quant-platform/provider-candidate-bootstrap-plan/v1"
)
SYNTHETIC_REHEARSAL_NAMESPACE = "synthetic-provider-rehearsal/v1"
SYNTHETIC_REHEARSAL_PROVENANCE_CLASS = "SYNTHETIC_REHEARSAL"
SYNTHETIC_PROVENANCE_FORBIDDEN = "SYNTHETIC_PROVENANCE_FORBIDDEN"
RESEARCH_ONLY_MODE = "RESEARCH_ONLY"
UNAUTHORIZED_PLAN_KIND = "UNAUTHORIZED_PLAN_ONLY"

SYNTHETIC_REHEARSAL_CONTENT_HASH_DOMAIN = (
    "quant-platform/synthetic-provider-rehearsal-content/v1"
)
SYNTHETIC_REHEARSAL_ARTIFACT_HASH_DOMAIN = (
    "quant-platform/synthetic-provider-rehearsal-artifact-hash/v1"
)
PROVIDER_CANDIDATE_BOOTSTRAP_PLAN_HASH_DOMAIN = (
    "quant-platform/provider-candidate-bootstrap-plan-hash/v1"
)

SYNTHETIC_REHEARSAL_ARTIFACT_KINDS = (
    "DELIVERY",
    "FIXTURE",
    "RECEIPT",
    "REGISTRY",
)

PROVIDER_CANDIDATE_BOOTSTRAP_REQUIREMENT_IDS = tuple(
    sorted(
        {
            "allowed_usage_scope",
            "approved_by_identified",
            "authorization_reference_bound",
            "automated_api_access",
            "data_kind_scope",
            "derived_data_generation",
            "endpoint_scope",
            "evidence_sha256_bound",
            "internal_quant_research",
            "legal_authority_scope",
            "normalized_data_storage",
            "paper_trading_decisions",
            "platform_redistribution_disabled",
            "point_in_time_replay",
            "raw_response_archival",
            "revision_history_storage",
            "termination_retention_terms_defined",
            "upstream_market_data_rights_confirmed",
            "validity_window_defined",
        }
    )
)

_NON_EVIDENCE_PLACEHOLDERS = {
    "PENDING_CONTRACT",
    "PLACEHOLDER",
    "TBD",
    "TODO",
}


class ProviderRehearsalError(ValueError):
    """Stable failure raised by a rehearsal contract boundary."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


def forbid_synthetic_provenance(value: Any) -> None:
    """Reject exact rehearsal markers in any nested mapping.

    Free text is never scanned.  Only exact values of the two reserved mapping
    fields are admission barriers.
    """

    if isinstance(value, Mapping):
        if (
            value.get("schema") == SYNTHETIC_REHEARSAL_ARTIFACT_SCHEMA
            or value.get("provenance_class")
            == SYNTHETIC_REHEARSAL_PROVENANCE_CLASS
        ):
            raise ProviderRehearsalError(SYNTHETIC_PROVENANCE_FORBIDDEN)
        for item in value.values():
            forbid_synthetic_provenance(item)
    elif isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for item in value:
            forbid_synthetic_provenance(item)


def _domain_hash(domain: str, value: Any) -> str:
    try:
        prefix = domain.encode("ascii")
    except UnicodeEncodeError as exc:  # pragma: no cover - frozen constants
        raise ProviderRehearsalError("INVALID_HASH_DOMAIN") from exc
    return hashlib.sha256(
        prefix + b"\0" + canonical_json(value).encode("utf-8")
    ).hexdigest()


def _canonical_mapping(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    try:
        encoded = canonical_json(value)
        normalized = strict_json_object(encoded)
    except (TypeError, ValueError, StrictContractJSONError) as exc:
        code = getattr(exc, "code", "INVALID_CANONICAL_VALUE")
        raise ProviderRehearsalError(code, f"{label} is not canonical JSON") from exc
    if dict(normalized) != dict(value):
        raise ProviderRehearsalError(
            "NON_CANONICAL_VALUE", f"{label} changes during canonicalization"
        )
    return dict(normalized)


def _strict_canonical_raw_object(raw: str | bytes | bytearray) -> StrictJSONObject:
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else bytes(raw)
    try:
        payload = strict_json_object(raw_bytes)
    except StrictContractJSONError as exc:
        raise ProviderRehearsalError(exc.code, str(exc)) from exc
    expected = canonical_json(payload).encode("utf-8") + b"\n"
    if raw_bytes != expected:
        raise ProviderRehearsalError(
            "NON_CANONICAL_RAW_JSON",
            "raw JSON must equal canonical JSON followed by one LF",
        )
    return payload


def build_synthetic_provider_rehearsal_artifact(
    artifact_kind: str,
    content: Mapping[str, Any],
) -> dict[str, Any]:
    """Build one independently content-bound synthetic artifact in memory."""

    normalized_content = _canonical_mapping(content, label="rehearsal content")
    kind = str(artifact_kind or "")
    content_sha256 = _domain_hash(
        SYNTHETIC_REHEARSAL_CONTENT_HASH_DOMAIN, normalized_content
    )
    identity = {
        "schema": SYNTHETIC_REHEARSAL_ARTIFACT_SCHEMA,
        "namespace": SYNTHETIC_REHEARSAL_NAMESPACE,
        "artifact_kind": kind,
        "provenance_class": SYNTHETIC_REHEARSAL_PROVENANCE_CLASS,
        "mode": RESEARCH_ONLY_MODE,
        "trial_day_eligible": False,
        "admission_eligible": False,
        "authority_independence_eligible": False,
        "real_orders": False,
        "content": normalized_content,
        "content_sha256": content_sha256,
    }
    artifact = {
        **identity,
        "artifact_sha256": _domain_hash(
            SYNTHETIC_REHEARSAL_ARTIFACT_HASH_DOMAIN, identity
        ),
    }
    return validate_synthetic_provider_rehearsal_artifact(artifact)


def validate_synthetic_provider_rehearsal_artifact(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    artifact = _canonical_mapping(value, label="rehearsal artifact")
    expected = {
        "schema",
        "namespace",
        "artifact_kind",
        "provenance_class",
        "mode",
        "trial_day_eligible",
        "admission_eligible",
        "authority_independence_eligible",
        "real_orders",
        "content",
        "content_sha256",
        "artifact_sha256",
    }
    if set(artifact) != expected:
        raise ProviderRehearsalError("REHEARSAL_ARTIFACT_FIELDS_INVALID")
    if (
        artifact.get("schema") != SYNTHETIC_REHEARSAL_ARTIFACT_SCHEMA
        or artifact.get("namespace") != SYNTHETIC_REHEARSAL_NAMESPACE
        or artifact.get("artifact_kind")
        not in SYNTHETIC_REHEARSAL_ARTIFACT_KINDS
        or artifact.get("provenance_class")
        != SYNTHETIC_REHEARSAL_PROVENANCE_CLASS
        or artifact.get("mode") != RESEARCH_ONLY_MODE
        or artifact.get("trial_day_eligible") is not False
        or artifact.get("admission_eligible") is not False
        or artifact.get("authority_independence_eligible") is not False
        or artifact.get("real_orders") is not False
        or not isinstance(artifact.get("content"), Mapping)
    ):
        raise ProviderRehearsalError("REHEARSAL_ARTIFACT_INVARIANT_INVALID")
    content = _canonical_mapping(
        dict(artifact["content"]), label="rehearsal artifact content"
    )
    content_sha = _domain_hash(SYNTHETIC_REHEARSAL_CONTENT_HASH_DOMAIN, content)
    if artifact.get("content_sha256") != content_sha:
        raise ProviderRehearsalError("REHEARSAL_CONTENT_HASH_MISMATCH")
    identity = {key: item for key, item in artifact.items() if key != "artifact_sha256"}
    if artifact.get("artifact_sha256") != _domain_hash(
        SYNTHETIC_REHEARSAL_ARTIFACT_HASH_DOMAIN, identity
    ):
        raise ProviderRehearsalError("REHEARSAL_ARTIFACT_HASH_MISMATCH")
    return artifact


def validate_synthetic_provider_rehearsal_artifact_raw(
    raw: str | bytes | bytearray,
) -> dict[str, Any]:
    return validate_synthetic_provider_rehearsal_artifact(
        _strict_canonical_raw_object(raw)
    )


def _policy_identity(policy: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    normalized = _canonical_mapping(policy, label="provider procurement policy")
    declared = str(normalized.get("policy_sha256") or "")
    identity = {
        key: item for key, item in normalized.items() if key != "policy_sha256"
    }
    if declared != sha256_digest(identity):
        raise ProviderRehearsalError("PROVIDER_POLICY_HASH_MISMATCH")
    return normalized, declared


def build_provider_candidate_bootstrap_plan(
    policy: Mapping[str, Any], candidate_id: str
) -> dict[str, Any]:
    """Build a deterministic, explicitly unauthorized plan without evidence."""

    normalized_policy, policy_sha = _policy_identity(policy)
    candidates = [
        dict(item)
        for item in list(normalized_policy.get("candidates") or [])
        if isinstance(item, Mapping) and item.get("candidate_id") == candidate_id
    ]
    if len(candidates) != 1:
        raise ProviderRehearsalError("PROVIDER_CANDIDATE_NOT_UNIQUE")
    candidate = candidates[0]
    source_version = str(candidate.get("source_version") or "")
    reference_values = dict(candidate.get("official_api_references") or {})
    requirements = [
        {
            "requirement_id": requirement_id,
            "satisfied": False,
            "evidence_sha256": None,
            "evidence_reference": None,
            "approval_reference": None,
        }
        for requirement_id in PROVIDER_CANDIDATE_BOOTSTRAP_REQUIREMENT_IDS
    ]
    identity = {
        "schema": PROVIDER_CANDIDATE_BOOTSTRAP_PLAN_SCHEMA,
        "plan_kind": UNAUTHORIZED_PLAN_KIND,
        "mode": RESEARCH_ONLY_MODE,
        "candidate_id": str(candidate.get("candidate_id") or ""),
        "display_name": str(candidate.get("display_name") or ""),
        "role": str(candidate.get("role") or ""),
        "source_id": str(candidate.get("source_id") or ""),
        "source_version": source_version,
        "source_version_classification": (
            "NON_EVIDENCE_PLACEHOLDER"
            if source_version in _NON_EVIDENCE_PLACEHOLDERS
            else "NON_EVIDENCE_POLICY_VALUE"
        ),
        "declared_authority": str(candidate.get("authority") or ""),
        "required_data_kinds": sorted(
            str(item) for item in list(candidate.get("required_data_kinds") or [])
        ),
        "minimum_trial_trading_days": candidate.get("minimum_trial_trading_days"),
        "minimum_revisions_per_dataset": candidate.get(
            "minimum_revisions_per_dataset"
        ),
        "policy_binding": {
            "policy_id": str(normalized_policy.get("policy_id") or ""),
            "policy_sha256": policy_sha,
        },
        "informational_references": {
            "classification": "NON_EVIDENCE_POLICY_REFERENCE",
            "values": {key: reference_values[key] for key in sorted(reference_values)},
        },
        "requirements": requirements,
        "missing_requirement_ids": list(
            PROVIDER_CANDIDATE_BOOTSTRAP_REQUIREMENT_IDS
        ),
        "apply_allowed": False,
        "candidate_eligible": False,
        "admission_eligible": False,
        "trial_evidence_eligible": False,
        "authority_independence_eligible": False,
        "real_orders": False,
    }
    plan = {
        **identity,
        "plan_sha256": _domain_hash(
            PROVIDER_CANDIDATE_BOOTSTRAP_PLAN_HASH_DOMAIN, identity
        ),
    }
    return validate_provider_candidate_bootstrap_plan(plan)


def validate_provider_candidate_bootstrap_plan(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    plan = _canonical_mapping(value, label="provider candidate bootstrap plan")
    expected = {
        "schema",
        "plan_kind",
        "mode",
        "candidate_id",
        "display_name",
        "role",
        "source_id",
        "source_version",
        "source_version_classification",
        "declared_authority",
        "required_data_kinds",
        "minimum_trial_trading_days",
        "minimum_revisions_per_dataset",
        "policy_binding",
        "informational_references",
        "requirements",
        "missing_requirement_ids",
        "apply_allowed",
        "candidate_eligible",
        "admission_eligible",
        "trial_evidence_eligible",
        "authority_independence_eligible",
        "real_orders",
        "plan_sha256",
    }
    if set(plan) != expected:
        raise ProviderRehearsalError("BOOTSTRAP_PLAN_FIELDS_INVALID")
    if (
        plan.get("schema") != PROVIDER_CANDIDATE_BOOTSTRAP_PLAN_SCHEMA
        or plan.get("plan_kind") != UNAUTHORIZED_PLAN_KIND
        or plan.get("mode") != RESEARCH_ONLY_MODE
        or plan.get("apply_allowed") is not False
        or plan.get("candidate_eligible") is not False
        or plan.get("admission_eligible") is not False
        or plan.get("trial_evidence_eligible") is not False
        or plan.get("authority_independence_eligible") is not False
        or plan.get("real_orders") is not False
    ):
        raise ProviderRehearsalError("BOOTSTRAP_PLAN_INVARIANT_INVALID")
    for key in (
        "candidate_id",
        "display_name",
        "source_id",
        "source_version",
        "declared_authority",
    ):
        if not isinstance(plan.get(key), str) or not str(plan[key]).strip():
            raise ProviderRehearsalError("BOOTSTRAP_PLAN_IDENTITY_INVALID")
    if plan.get("role") not in {"PRIMARY", "CORROBORATION"}:
        raise ProviderRehearsalError("BOOTSTRAP_ROLE_INVALID")
    if plan.get("source_version_classification") not in {
        "NON_EVIDENCE_PLACEHOLDER",
        "NON_EVIDENCE_POLICY_VALUE",
    }:
        raise ProviderRehearsalError("BOOTSTRAP_SOURCE_VERSION_CLASS_INVALID")
    for key in ("minimum_trial_trading_days", "minimum_revisions_per_dataset"):
        value_int = plan.get(key)
        if isinstance(value_int, bool) or not isinstance(value_int, int) or value_int < 1:
            raise ProviderRehearsalError("BOOTSTRAP_POLICY_MINIMUM_INVALID")
    if plan.get("minimum_trial_trading_days") != 20:
        raise ProviderRehearsalError("BOOTSTRAP_TRIAL_MINIMUM_CHANGED")
    if plan.get("minimum_revisions_per_dataset") != 2:
        raise ProviderRehearsalError("BOOTSTRAP_REVISION_MINIMUM_CHANGED")
    data_kinds = list(plan.get("required_data_kinds") or [])
    if (
        not data_kinds
        or data_kinds != sorted(data_kinds)
        or len(data_kinds) != len(set(data_kinds))
        or any(not isinstance(item, str) or not item for item in data_kinds)
    ):
        raise ProviderRehearsalError("BOOTSTRAP_DATA_KINDS_INVALID")
    policy_binding = dict(plan.get("policy_binding") or {})
    if set(policy_binding) != {"policy_id", "policy_sha256"}:
        raise ProviderRehearsalError("BOOTSTRAP_POLICY_BINDING_INVALID")
    policy_sha256 = policy_binding.get("policy_sha256")
    if (
        not str(policy_binding.get("policy_id") or "").strip()
        or not isinstance(policy_sha256, str)
        or len(policy_sha256) != 64
        or any(character not in "0123456789abcdef" for character in policy_sha256)
    ):
        raise ProviderRehearsalError("BOOTSTRAP_POLICY_BINDING_INVALID")
    informational = dict(plan.get("informational_references") or {})
    if (
        set(informational) != {"classification", "values"}
        or informational.get("classification")
        != "NON_EVIDENCE_POLICY_REFERENCE"
        or not isinstance(informational.get("values"), Mapping)
        or any(
            not isinstance(value, str) or not value.strip()
            for value in dict(informational.get("values") or {}).values()
        )
    ):
        raise ProviderRehearsalError("BOOTSTRAP_INFORMATIONAL_REFERENCE_INVALID")
    requirements = list(plan.get("requirements") or [])
    if len(requirements) != len(PROVIDER_CANDIDATE_BOOTSTRAP_REQUIREMENT_IDS):
        raise ProviderRehearsalError("BOOTSTRAP_REQUIREMENTS_INCOMPLETE")
    observed_ids: list[str] = []
    for raw in requirements:
        if not isinstance(raw, Mapping):
            raise ProviderRehearsalError("BOOTSTRAP_REQUIREMENT_INVALID")
        requirement = dict(raw)
        if set(requirement) != {
            "requirement_id",
            "satisfied",
            "evidence_sha256",
            "evidence_reference",
            "approval_reference",
        }:
            raise ProviderRehearsalError("BOOTSTRAP_REQUIREMENT_FIELDS_INVALID")
        observed_ids.append(str(requirement.get("requirement_id") or ""))
        if (
            requirement.get("satisfied") is not False
            or requirement.get("evidence_sha256") is not None
            or requirement.get("evidence_reference") is not None
            or requirement.get("approval_reference") is not None
        ):
            raise ProviderRehearsalError("BOOTSTRAP_EVIDENCE_FORBIDDEN")
    expected_ids = list(PROVIDER_CANDIDATE_BOOTSTRAP_REQUIREMENT_IDS)
    if observed_ids != expected_ids or plan.get("missing_requirement_ids") != expected_ids:
        raise ProviderRehearsalError("BOOTSTRAP_REQUIREMENTS_NOT_CANONICAL")
    identity = {key: item for key, item in plan.items() if key != "plan_sha256"}
    if plan.get("plan_sha256") != _domain_hash(
        PROVIDER_CANDIDATE_BOOTSTRAP_PLAN_HASH_DOMAIN, identity
    ):
        raise ProviderRehearsalError("BOOTSTRAP_PLAN_HASH_MISMATCH")
    return plan


def validate_provider_candidate_bootstrap_plan_raw(
    raw: str | bytes | bytearray,
) -> dict[str, Any]:
    return validate_provider_candidate_bootstrap_plan(_strict_canonical_raw_object(raw))


def validate_provider_rehearsal_raw(
    raw: str | bytes | bytearray,
) -> dict[str, Any]:
    """Strictly dispatch one canonical raw object by its exact schema."""

    payload = _strict_canonical_raw_object(raw)
    schema = payload.get("schema")
    if schema == SYNTHETIC_REHEARSAL_ARTIFACT_SCHEMA:
        return validate_synthetic_provider_rehearsal_artifact(payload)
    if schema == PROVIDER_CANDIDATE_BOOTSTRAP_PLAN_SCHEMA:
        return validate_provider_candidate_bootstrap_plan(payload)
    raise ProviderRehearsalError("UNKNOWN_REHEARSAL_SCHEMA")
