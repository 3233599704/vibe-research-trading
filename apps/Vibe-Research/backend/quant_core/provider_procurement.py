"""Offline procurement posture for candidate formal market-data providers.

The procurement boundary is deliberately weaker than formal data admission and
stronger than a checklist.  It only reports evidence that is already frozen in
the platform registries.  It never imports a vendor SDK, reads credentials,
contacts a network endpoint, mutates the provider registry, or enables orders.
"""

from __future__ import annotations

import importlib.util
import re
from datetime import date, datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from zoneinfo import ZoneInfo

from .provider_adapter_certification import (
    ProviderAdapterCertificationError,
    ProviderAdapterCertificationRegistry,
)
from .provider_authorization import (
    ProviderAuthorizationError,
    ProviderAutomationAuthorizationRegistry,
)
from .provider_contract import ProviderContractError, ProviderDeliveryStore
from .provider_sample_intake import (
    ProviderSampleIntakeError,
    ProviderSampleIntakeRegistry,
)
from .provider_readiness import (
    ProviderReadinessError,
    resolve_formal_data_readiness_policy,
)
from .provenance import sha256_digest
from .strict_contract_json import StrictContractJSONError, strict_json_file_object


PROVIDER_PROCUREMENT_POLICY_PATH = (
    "config/data-quality/provider-procurement-candidates-v1.json"
)
PROVIDER_PROCUREMENT_POLICY_SCHEMA = (
    "quant-platform/provider-procurement-candidates/v1"
)
PROVIDER_PROCUREMENT_STATUS_SCHEMA = "quant-platform/provider-procurement-status/v1"

_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
SHANGHAI = ZoneInfo("Asia/Shanghai")
_SAFETY_INVARIANTS = {
    "sdk_detection": "FIND_SPEC_ONLY",
    "sdk_import_allowed": False,
    "network_probe_allowed": False,
    "credential_access_allowed": False,
    "source_registry_mutation_allowed": False,
    "real_orders": False,
}
_REGISTRY_KEYS = {
    "authorization",
    "sample_intake",
    "adapter_certification",
    "provider_catalog",
}
_CANDIDATE_FIELDS = {
    "candidate_id",
    "display_name",
    "priority",
    "role",
    "source_id",
    "source_version",
    "python_module",
    "authority",
    "official_api_references",
    "required_data_kinds",
    "minimum_trial_trading_days",
    "minimum_revisions_per_dataset",
    "evidence_bindings",
}
_EVIDENCE_FIELDS = {
    "authorization_grant_sha256",
    "sample_acceptance_receipt_sha256s",
    "adapter_certification_report_sha256",
    "publication_receipt_sha256s",
}
_REQUIRED_DATA_KINDS = {
    "trading_calendar",
    "market_bars",
    "adjustment_factors",
    "corporate_actions",
    "universe_membership",
    "security_master",
    "security_status_events",
    "industry_membership",
    "fundamental_publications",
    "daily_market_indicators",
}


class ProviderProcurementError(RuntimeError):
    """Raised when the frozen procurement policy or evidence is unsafe."""


def _relative_path(root: Path, value: Any, label: str) -> tuple[str, Path]:
    text = str(value or "").strip().replace("\\", "/")
    if not text or Path(text).is_absolute():
        raise ProviderProcurementError(f"{label} must be a relative platform path")
    path = (root / text).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ProviderProcurementError(f"{label} escapes platform root") from exc
    return text, path


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 128 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", text):
        raise ProviderProcurementError(f"{label} is invalid")
    return text


def _text(value: Any, label: str, maximum: int = 500) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum:
        raise ProviderProcurementError(f"{label} is invalid")
    return text


def _optional_hash(value: Any, label: str) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not _SHA_RE.fullmatch(text):
        raise ProviderProcurementError(f"{label} is invalid")
    return text


def _hash_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise ProviderProcurementError(f"{label} must be a list")
    values = [_optional_hash(item, label) for item in value]
    normalized = [item for item in values if item is not None]
    if len(normalized) != len(set(normalized)):
        raise ProviderProcurementError(f"{label} contains duplicates")
    return normalized


def resolve_provider_procurement_policy(
    platform_root: str | Path,
    policy_path: str | Path | None = None,
) -> dict[str, Any]:
    """Load and strictly validate the credential-free procurement policy."""

    root = Path(platform_root).expanduser().resolve()
    candidate_path = Path(policy_path or PROVIDER_PROCUREMENT_POLICY_PATH)
    path = candidate_path.resolve() if candidate_path.is_absolute() else (root / candidate_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ProviderProcurementError("procurement policy escapes platform root") from exc
    try:
        raw = strict_json_file_object(path)
    except (OSError, StrictContractJSONError) as exc:
        raise ProviderProcurementError(f"procurement policy is unreadable: {exc}") from exc
    if set(raw) != {
        "schema",
        "policy_id",
        "safety_invariants",
        "registry_paths",
        "minimum_independent_authorities",
        "candidate_order",
        "candidates",
        "policy_sha256",
    }:
        raise ProviderProcurementError("procurement policy fields are invalid")
    if raw.get("schema") != PROVIDER_PROCUREMENT_POLICY_SCHEMA:
        raise ProviderProcurementError("unsupported procurement policy schema")
    identity = {key: value for key, value in raw.items() if key != "policy_sha256"}
    if raw.get("policy_sha256") != sha256_digest(identity):
        raise ProviderProcurementError("procurement policy digest mismatch")
    if raw.get("safety_invariants") != _SAFETY_INVARIANTS:
        raise ProviderProcurementError("procurement safety invariants were weakened")
    registry_paths = dict(raw.get("registry_paths") or {})
    if set(registry_paths) != _REGISTRY_KEYS:
        raise ProviderProcurementError("procurement registry paths are incomplete")
    normalized_paths: dict[str, str] = {}
    for key, value in registry_paths.items():
        normalized_paths[key] = _relative_path(root, value, f"registry_paths.{key}")[0]
    minimum_authorities = raw.get("minimum_independent_authorities")
    if isinstance(minimum_authorities, bool) or minimum_authorities != 2:
        raise ProviderProcurementError(
            "procurement requires exactly two independent candidate authorities"
        )
    candidates = list(raw.get("candidates") or [])
    if len(candidates) != 2 or not all(isinstance(item, dict) for item in candidates):
        raise ProviderProcurementError("procurement policy must contain two candidates")
    normalized_candidates: list[dict[str, Any]] = []
    candidate_ids: list[str] = []
    authorities: list[str] = []
    priorities: list[int] = []
    for raw_candidate in candidates:
        if set(raw_candidate) != _CANDIDATE_FIELDS:
            raise ProviderProcurementError("procurement candidate fields are invalid")
        candidate_id = _identifier(raw_candidate.get("candidate_id"), "candidate_id")
        priority = raw_candidate.get("priority")
        if isinstance(priority, bool) or not isinstance(priority, int) or priority < 1:
            raise ProviderProcurementError("candidate priority is invalid")
        role = _identifier(raw_candidate.get("role"), "candidate role")
        if role not in {"PRIMARY", "CORROBORATION"}:
            raise ProviderProcurementError("candidate role is invalid")
        api_references = dict(raw_candidate.get("official_api_references") or {})
        if not api_references:
            raise ProviderProcurementError("official API references are required")
        normalized_references = {
            _identifier(key, "API reference key"): _text(value, "API reference URL")
            for key, value in api_references.items()
        }
        if any(not value.startswith("https://") for value in normalized_references.values()):
            raise ProviderProcurementError("official API references must use HTTPS")
        data_kinds = [
            _identifier(item, "required data kind")
            for item in list(raw_candidate.get("required_data_kinds") or [])
        ]
        if (
            len(data_kinds) != len(set(data_kinds))
            or set(data_kinds) != _REQUIRED_DATA_KINDS
        ):
            raise ProviderProcurementError(
                "required data kinds do not cover the complete formal contract"
            )
        minimum_days = raw_candidate.get("minimum_trial_trading_days")
        minimum_revisions = raw_candidate.get("minimum_revisions_per_dataset")
        if (
            isinstance(minimum_days, bool)
            or not isinstance(minimum_days, int)
            or minimum_days < 20
            or isinstance(minimum_revisions, bool)
            or not isinstance(minimum_revisions, int)
            or minimum_revisions < 2
        ):
            raise ProviderProcurementError("candidate trial thresholds were weakened")
        evidence = dict(raw_candidate.get("evidence_bindings") or {})
        if set(evidence) != _EVIDENCE_FIELDS:
            raise ProviderProcurementError("candidate evidence bindings are incomplete")
        normalized_evidence = {
            "authorization_grant_sha256": _optional_hash(
                evidence.get("authorization_grant_sha256"),
                "authorization_grant_sha256",
            ),
            "sample_acceptance_receipt_sha256s": _hash_list(
                evidence.get("sample_acceptance_receipt_sha256s"),
                "sample_acceptance_receipt_sha256s",
            ),
            "adapter_certification_report_sha256": _optional_hash(
                evidence.get("adapter_certification_report_sha256"),
                "adapter_certification_report_sha256",
            ),
            "publication_receipt_sha256s": _hash_list(
                evidence.get("publication_receipt_sha256s"),
                "publication_receipt_sha256s",
            ),
        }
        candidate_ids.append(candidate_id)
        authorities.append(_identifier(raw_candidate.get("authority"), "authority"))
        priorities.append(priority)
        normalized_candidates.append(
            {
                **raw_candidate,
                "candidate_id": candidate_id,
                "display_name": _text(raw_candidate.get("display_name"), "display_name"),
                "priority": priority,
                "role": role,
                "source_id": _identifier(raw_candidate.get("source_id"), "source_id"),
                "source_version": _text(raw_candidate.get("source_version"), "source_version", 80),
                "python_module": _identifier(raw_candidate.get("python_module"), "python_module"),
                "authority": authorities[-1],
                "official_api_references": normalized_references,
                "required_data_kinds": data_kinds,
                "minimum_trial_trading_days": minimum_days,
                "minimum_revisions_per_dataset": minimum_revisions,
                "evidence_bindings": normalized_evidence,
            }
        )
    order = [_identifier(item, "candidate_order") for item in list(raw.get("candidate_order") or [])]
    if order != candidate_ids or priorities != sorted(priorities) or len(set(authorities)) != 2:
        raise ProviderProcurementError(
            "candidate order, priorities or independent authorities are invalid"
        )
    return {
        **raw,
        "registry_paths": normalized_paths,
        "candidates": normalized_candidates,
        "policy_path": str(path.relative_to(root)).replace("\\", "/"),
    }


def _sdk_discoverable(module_name: str) -> bool:
    """Discover a top-level package without importing vendor code."""

    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _candidate_stage(checks: Mapping[str, bool]) -> str:
    if not checks["authorization_bound"]:
        return "AWAITING_WRITTEN_AUTHORIZATION"
    if not checks["accepted_sample_bound"]:
        return "AWAITING_SANITIZED_SAMPLE"
    if not checks["adapter_certification_bound"]:
        return "AWAITING_ADAPTER_CERTIFICATION"
    if not checks["approved_source_registered"]:
        return "AWAITING_CAPTURE_REGISTRATION"
    if not checks["trial_evidence_complete"]:
        return "TRIAL_OBSERVATION"
    return "TRIAL_ACCEPTED"


def _canonical_session_field(data_contract: Mapping[str, Any]) -> str | None:
    kind = data_contract.get("kind")
    primary_keys = {str(item) for item in data_contract.get("primary_keys") or []}
    fields = {str(item) for item in data_contract.get("fields") or []}
    expected_keys = {
        "trading_calendar": {"trade_date"},
        "market_bars": {"asset_id", "trade_date"},
    }.get(str(kind or ""))
    if expected_keys is None or primary_keys != expected_keys:
        return None
    return "trade_date" if "trade_date" in fields else None


def _publication_trade_dates(
    publication: Mapping[str, Any],
    data_contract: Mapping[str, Any],
) -> set[str]:
    binding = dict(publication.get("binding") or {})
    catalog = dict(binding.get("catalog") or {})
    payload = dict(catalog.get("payload") or {})
    session_field = _canonical_session_field(data_contract)
    if session_field is None:
        return set()
    result: set[str] = set()
    for raw_record in list(payload.get("records") or []):
        if not isinstance(raw_record, Mapping):
            continue
        value = str(raw_record.get(session_field) or "")
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is None:
            continue
        try:
            result.add(date.fromisoformat(value).isoformat())
        except ValueError:
            continue
    return result


def _longest_consecutive_session_run(
    calendar_dates: set[str], observed_dates: set[str]
) -> int:
    longest = 0
    current = 0
    for trading_day in sorted(calendar_dates):
        if trading_day in observed_dates:
            current += 1
            longest = max(longest, current)
        else:
            current = 0
    return longest


def _counts_as_market_observation(data_contract: Mapping[str, Any]) -> bool:
    record_count = data_contract.get("record_count")
    return (
        data_contract.get("kind") == "market_bars"
        and type(record_count) is int
        and record_count > 0
    )


def _shanghai_date(value: str) -> str:
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.utcoffset() is None:
        raise ValueError("provider available_at must be timezone-aware")
    return moment.astimezone(SHANGHAI).date().isoformat()


def assess_provider_procurement(
    platform_root: str | Path,
    *,
    policy_path: str | Path | None = None,
    as_of: datetime | None = None,
    sdk_detector: Callable[[str], bool] | None = None,
) -> dict[str, Any]:
    """Assess exact candidate evidence without credentials, SDK imports or I/O writes."""

    root = Path(platform_root).expanduser().resolve()
    policy = resolve_provider_procurement_policy(root, policy_path)
    formal_binding_errors: list[str] = []
    try:
        formal_policy = resolve_formal_data_readiness_policy(root)["policy"]
        primary = dict(formal_policy["source_roles"]["primary"])
        corroborators = [
            dict(item) for item in formal_policy["source_roles"]["corroborators"]
        ]
        formal_source_roles = {
            ("PRIMARY", primary["source_id"], primary["authority"]),
            *{
                ("CORROBORATION", item["source_id"], item["authority"])
                for item in corroborators
            },
        }
    except (ProviderReadinessError, KeyError, TypeError, ValueError) as exc:
        formal_source_roles = set()
        formal_binding_errors.append(str(exc))
    paths = {
        key: _relative_path(root, value, f"registry_paths.{key}")[1]
        for key, value in dict(policy["registry_paths"]).items()
    }
    authorization_registry = ProviderAutomationAuthorizationRegistry(
        paths["authorization"], platform_root=root
    )
    sample_registry = ProviderSampleIntakeRegistry(
        paths["sample_intake"], platform_root=root
    )
    certification_registry = ProviderAdapterCertificationRegistry(
        paths["adapter_certification"], platform_root=root
    )
    provider_store = ProviderDeliveryStore(
        platform_root=root,
        catalog_root=paths["provider_catalog"],
        authorization_as_of=as_of,
        certification_as_of=as_of,
    )
    inspections = {
        "authorization": authorization_registry.inspect(as_of=as_of),
        "sample_intake": sample_registry.inspect(),
        "adapter_certification": certification_registry.inspect(as_of=as_of),
        "provider_delivery": provider_store.status(),
    }
    degraded_inspections = [
        name for name, value in inspections.items() if value.get("status") == "DEGRADED"
    ]
    try:
        registered_sources = provider_store.load_registry()["sources"]
    except ProviderContractError:
        registered_sources = []
    detector = sdk_detector or _sdk_discoverable
    candidates: list[dict[str, Any]] = []
    for candidate in policy["candidates"]:
        source_id = candidate["source_id"]
        source_version = candidate["source_version"]
        binding = dict(candidate["evidence_bindings"])
        source_role_binding_valid = (
            candidate["role"], source_id, candidate["authority"]
        ) in formal_source_roles
        exact_sources = [
            item
            for item in registered_sources
            if item.get("source_id") == source_id
            and item.get("version") == source_version
        ]
        source_registered = len(exact_sources) == 1
        approved_source_registered = bool(
            source_registered
            and dict(exact_sources[0].get("automation_authorization") or {}).get("status")
            == "APPROVED"
            and "forward_observation" in list(exact_sources[0].get("allowed_usages") or [])
        )
        errors: list[str] = []
        grant = None
        grant_sha = binding["authorization_grant_sha256"]
        if grant_sha:
            try:
                grant = authorization_registry.resolve(grant_sha, as_of=as_of)
            except ProviderAuthorizationError as exc:
                errors.append(f"authorization: {exc}")
        authorization_bound = bool(
            grant
            and grant.get("source_id") == source_id
            and grant.get("source_version") == source_version
        )

        accepted_samples: list[dict[str, Any]] = []
        for receipt_sha in binding["sample_acceptance_receipt_sha256s"]:
            try:
                accepted = sample_registry.resolve_acceptance(receipt_sha)
            except ProviderSampleIntakeError as exc:
                errors.append(f"sample {receipt_sha}: {exc}")
                continue
            manifest = dict((accepted or {}).get("manifest") or {})
            if (
                accepted is not None
                and manifest.get("source_id") == source_id
                and manifest.get("source_version") == source_version
            ):
                accepted_samples.append(accepted)
            else:
                errors.append(f"sample {receipt_sha}: candidate identity mismatch")
        accepted_sample_bound = bool(accepted_samples)

        report = None
        report_sha = binding["adapter_certification_report_sha256"]
        if report_sha:
            try:
                report = certification_registry.resolve(report_sha, as_of=as_of)
            except ProviderAdapterCertificationError as exc:
                errors.append(f"adapter certification: {exc}")
        adapter_certification_bound = bool(
            report
            and report.get("source_id") == source_id
            and report.get("source_version") == source_version
            and report.get("authorization_grant_sha256") == grant_sha
            and set(report.get("sample_acceptance_receipt_sha256s") or [])
            <= set(binding["sample_acceptance_receipt_sha256s"])
        )

        verified_publications: list[dict[str, Any]] = []
        observed_kinds: set[str] = set()
        publication_dates: set[str] = set()
        market_observation_dates: set[str] = set()
        calendar_trade_dates: set[str] = set()
        lineage_kinds: set[str] = set()
        for receipt_sha in binding["publication_receipt_sha256s"]:
            publication = provider_store.verify_publication(receipt_sha)
            if publication.get("verified") is not True:
                errors.extend(
                    f"publication {receipt_sha}: {item}"
                    for item in publication.get("errors", [])
                )
                continue
            receipt = dict(publication.get("receipt") or {})
            delivery = provider_store.verify_delivery(
                str(receipt.get("delivery_sha256") or "")
            )
            envelope = dict(dict(delivery.get("evidence") or {}).get("envelope") or {})
            if (
                delivery.get("verified") is not True
                or envelope.get("source_id") != source_id
                or envelope.get("source_version") != source_version
            ):
                errors.append(f"publication {receipt_sha}: candidate delivery mismatch")
                continue
            verified_publications.append(publication)
            data_contract = dict(envelope.get("data_contract") or {})
            kind = str(data_contract.get("kind") or "")
            payload_trade_dates = _publication_trade_dates(
                publication,
                data_contract,
            )
            if kind:
                observed_kinds.add(kind)
            available_at = str(envelope.get("available_at") or "")
            try:
                publication_date = _shanghai_date(available_at)
                publication_dates.add(publication_date)
                if _counts_as_market_observation(data_contract):
                    if publication_date in payload_trade_dates:
                        market_observation_dates.add(publication_date)
                    else:
                        errors.append(
                            f"publication {receipt_sha}: market_bars available_at "
                            "date is not bound to a payload trade_date"
                        )
            except ValueError:
                errors.append(
                    f"publication {receipt_sha}: delivery available_at is invalid"
                )
            if kind == "trading_calendar":
                calendar_trade_dates.update(payload_trade_dates)
            lineage = provider_store.verify_revision_lineage(
                str(receipt.get("dataset_id") or ""),
                str(receipt.get("manifest_sha256") or ""),
                selected_manifest_sha256=str(
                    receipt.get("manifest_sha256") or ""
                ),
                minimum_revision_count=candidate[
                    "minimum_revisions_per_dataset"
                ],
            )
            if lineage.get("verified") is True and kind:
                lineage_kinds.add(kind)

        required_kinds = set(candidate["required_data_kinds"])
        product_coverage_complete = required_kinds <= observed_kinds
        revision_lineage_complete = required_kinds <= lineage_kinds
        observed_trading_days = _longest_consecutive_session_run(
            calendar_trade_dates,
            market_observation_dates & calendar_trade_dates,
        )
        observation_window_complete = (
            observed_trading_days >= candidate["minimum_trial_trading_days"]
        )
        sdk_discoverable = bool(detector(candidate["python_module"]))
        trial_evidence_complete = bool(
            sdk_discoverable
            and authorization_bound
            and accepted_sample_bound
            and adapter_certification_bound
            and approved_source_registered
            and product_coverage_complete
            and revision_lineage_complete
            and observation_window_complete
            and source_role_binding_valid
            and not errors
            and not degraded_inspections
        )
        checks = {
            "sdk_discoverable": sdk_discoverable,
            "source_role_binding_valid": source_role_binding_valid,
            "authorization_bound": authorization_bound,
            "accepted_sample_bound": accepted_sample_bound,
            "adapter_certification_bound": adapter_certification_bound,
            "source_registered": source_registered,
            "approved_source_registered": approved_source_registered,
            "product_coverage_complete": product_coverage_complete,
            "revision_lineage_complete": revision_lineage_complete,
            "observation_window_complete": observation_window_complete,
            "trial_evidence_complete": trial_evidence_complete,
        }
        blocker_map = {
            "sdk_discoverable": "SDK_NOT_DISCOVERABLE",
            "source_role_binding_valid": "FORMAL_SOURCE_ROLE_BINDING_MISMATCH",
            "authorization_bound": "WRITTEN_AUTOMATION_AUTHORIZATION_NOT_BOUND",
            "accepted_sample_bound": "ACCEPTED_SANITIZED_SAMPLE_NOT_BOUND",
            "adapter_certification_bound": "ADAPTER_CERTIFICATION_NOT_BOUND",
            "approved_source_registered": "APPROVED_CAPTURE_SOURCE_NOT_REGISTERED",
            "product_coverage_complete": "REQUIRED_PRODUCT_COVERAGE_INCOMPLETE",
            "revision_lineage_complete": "PROVIDER_REVISION_LINEAGE_INCOMPLETE",
            "observation_window_complete": "TWENTY_TRADING_DAY_TRIAL_INCOMPLETE",
        }
        blockers = [code for key, code in blocker_map.items() if not checks[key]]
        blockers.extend(
            f"{name.upper()}_REGISTRY_DEGRADED" for name in degraded_inspections
        )
        if errors:
            blockers.append("CANDIDATE_EVIDENCE_INVALID")
        stage = _candidate_stage(checks)
        candidates.append(
            {
                "candidate_id": candidate["candidate_id"],
                "display_name": candidate["display_name"],
                "priority": candidate["priority"],
                "role": candidate["role"],
                "source_id": source_id,
                "source_version": source_version,
                "authority": candidate["authority"],
                "python_module": candidate["python_module"],
                "stage": stage,
                "trial_accepted": stage == "TRIAL_ACCEPTED",
                "checks": checks,
                "accepted_sample_count": len(accepted_samples),
                "verified_publication_count": len(verified_publications),
                "observed_publication_date_count": len(publication_dates),
                "calendar_trade_date_count": len(calendar_trade_dates),
                "market_observation_date_count": len(market_observation_dates),
                "observed_trading_day_count": observed_trading_days,
                "minimum_trial_trading_days": candidate["minimum_trial_trading_days"],
                "required_data_kinds": sorted(required_kinds),
                "observed_data_kinds": sorted(observed_kinds),
                "lineage_verified_data_kinds": sorted(lineage_kinds),
                "official_api_references": candidate["official_api_references"],
                "blockers": list(dict.fromkeys(blockers)),
                "errors": errors,
                "formal_data_admission_eligible": False,
                "real_orders": False,
            }
        )

    accepted_count = sum(item["trial_accepted"] is True for item in candidates)
    if degraded_inspections or formal_binding_errors:
        status = "DEGRADED"
    elif accepted_count == len(candidates):
        status = "TRIAL_ACCEPTED"
    elif any(item["stage"] != "AWAITING_WRITTEN_AUTHORIZATION" for item in candidates):
        status = "INTAKE_IN_PROGRESS"
    else:
        status = "PROCUREMENT_REQUIRED"
    blockers = [
        f"{item['candidate_id'].upper()}_{blocker}"
        for item in candidates
        for blocker in item["blockers"]
    ]
    blockers.extend("FORMAL_READINESS_POLICY_INVALID" for _ in formal_binding_errors)
    identity = {
        "schema": PROVIDER_PROCUREMENT_STATUS_SCHEMA,
        "status": status,
        "policy_id": policy["policy_id"],
        "policy_path": policy["policy_path"],
        "policy_sha256": policy["policy_sha256"],
        "candidate_count": len(candidates),
        "trial_accepted_candidate_count": accepted_count,
        "minimum_independent_authorities": policy["minimum_independent_authorities"],
        "formal_source_role_binding_valid": bool(formal_source_roles)
        and all(
            item["checks"]["source_role_binding_valid"] is True
            for item in candidates
        ),
        "formal_source_role_binding_errors": formal_binding_errors,
        "candidates": candidates,
        "registry_inspections": inspections,
        "safety": {
            "sdk_detection": "FIND_SPEC_ONLY",
            "sdk_import_performed": False,
            "network_probe_performed": False,
            "credential_access_performed": False,
            "source_registry_mutation_performed": False,
        },
        "procurement_acceptance_ready": accepted_count == len(candidates),
        "formal_data_admission_eligible": False,
        "strategy_promotion_eligible": False,
        "real_orders": False,
        "blockers": list(dict.fromkeys(blockers)),
    }
    return {**identity, "assessment_sha256": sha256_digest(identity)}
