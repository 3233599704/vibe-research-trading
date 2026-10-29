"""Structured, append-only authorization for automated provider data use.

An evidence-file hash alone does not describe what a contract permits.  This
module binds a reviewed authorization scope to one provider version, keeps
grant/revocation history append-only, and applies a bounded re-review period.
It grants data use only; it never enables broker orders.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence
from zoneinfo import ZoneInfo

from .provenance import sha256_digest
from .provider_rehearsal import (
    SYNTHETIC_PROVENANCE_FORBIDDEN,
    ProviderRehearsalError,
    forbid_synthetic_provenance,
)
from .strict_contract_json import StrictContractJSONError, strict_json_file_object


PROVIDER_AUTHORIZATION_GRANT_SCHEMA = (
    "quant-platform/provider-automation-authorization-grant/v1"
)
PROVIDER_AUTHORIZATION_GRANT_V2_SCHEMA = (
    "quant-platform/provider-automation-authorization-grant/v2"
)
PROVIDER_AUTHORIZATION_RECORD_SCHEMA = (
    "quant-platform/provider-automation-authorization-record/v1"
)
PROVIDER_AUTHORIZATION_HEAD_SCHEMA = (
    "quant-platform/provider-automation-authorization-head/v1"
)
PROVIDER_AUTHORIZATION_INSPECTION_SCHEMA = (
    "quant-platform/provider-automation-authorization-inspection/v1"
)
PROVIDER_AUTHORIZATION_RESOLUTION_SCHEMA = (
    "quant-platform/provider-automation-authorization-resolution/v1"
)
PROVIDER_AUTHORIZATION_SCOPE_RESOLUTION_SCHEMA = (
    "quant-platform/provider-automation-authorization-scope-resolution/v1"
)
PROVIDER_AUTHORIZATION_MAX_REVIEW_DAYS = 366
REQUIRED_FORWARD_ENTITLEMENTS = {
    "automated_api_access",
    "raw_response_archival",
    "normalized_data_storage",
    "revision_history_storage",
    "derived_data_generation",
    "internal_quant_research",
    "paper_trading_decisions",
    "point_in_time_replay",
    "upstream_market_data_rights_confirmed",
    "termination_retention_terms_defined",
}
AUXILIARY_AUTHORIZATION_USAGES = frozenset(
    {"post_close_history_auxiliary", "future_calendar_reference"}
)
AUXILIARY_PERMISSION_KEYS = frozenset(
    {
        "automated_api_access",
        "ephemeral_validation",
        "internal_diagnostic_display",
        "raw_response_archival",
        "normalized_data_storage",
        "revision_history_storage",
        "derived_data_generation",
        "internal_quant_research",
        "signal_generation",
        "paper_trading_decisions",
        "point_in_time_replay",
        "independent_source_claim",
        "platform_redistribution",
        "real_orders",
        "upstream_market_data_rights_confirmed",
        "termination_retention_terms_defined",
    }
)
AUXILIARY_REQUIRED_PERMISSIONS = frozenset(
    {
        "automated_api_access",
        "ephemeral_validation",
        "internal_diagnostic_display",
        "upstream_market_data_rights_confirmed",
        "termination_retention_terms_defined",
    }
)
AUXILIARY_FORBIDDEN_PERMISSIONS = frozenset(
    {
        "raw_response_archival",
        "revision_history_storage",
        "derived_data_generation",
        "signal_generation",
        "paper_trading_decisions",
        "point_in_time_replay",
        "independent_source_claim",
        "platform_redistribution",
        "real_orders",
    }
)
AUXILIARY_ENDPOINT_SCOPE_FIELDS = frozenset(
    {
        "endpoint_id",
        "api_version",
        "authority",
        "data_kind",
        "http_method",
        "allowed_parameter_names",
        "max_rows",
        "max_requests_per_minute",
        "max_concurrency",
        "post_close_only",
        "current_session_allowed",
    }
)
AUXILIARY_ENTITLEMENT_PROFILES = {
    "POST_CLOSE_EPHEMERAL": {
        "usage": "post_close_history_auxiliary",
        "internal_quant_research": True,
        "normalized_data_storage": False,
        "normalized_retention": "NONE",
    },
    "POST_CLOSE_NORMALIZED_BOUNDED": {
        "usage": "post_close_history_auxiliary",
        "internal_quant_research": True,
        "normalized_data_storage": True,
        "normalized_retention": "BOUNDED_ENCRYPTED",
    },
    "FUTURE_CALENDAR_REFERENCE": {
        "usage": "future_calendar_reference",
        "internal_quant_research": False,
        "normalized_data_storage": False,
        "normalized_retention": "NONE",
    },
}
AUXILIARY_ENDPOINT_CONTRACTS = {
    "moneyflow_ind_ths": {
        "usage": "post_close_history_auxiliary",
        "data_kind": "industry_money_flow",
        "allowed_parameter_names": ["trade_date"],
        "max_rows": 5_000,
        "post_close_only": True,
    },
    "moneyflow_ind_dc": {
        "usage": "post_close_history_auxiliary",
        "data_kind": "board_money_flow",
        "allowed_parameter_names": ["trade_date"],
        "max_rows": 5_000,
        "post_close_only": True,
    },
    "moneyflow_cnt_ths": {
        "usage": "post_close_history_auxiliary",
        "data_kind": "concept_money_flow",
        "allowed_parameter_names": ["trade_date"],
        "max_rows": 5_000,
        "post_close_only": True,
    },
    "stk_mins": {
        "usage": "post_close_history_auxiliary",
        "data_kind": "stock_minute_bars",
        "allowed_parameter_names": ["end_date", "freq", "start_date", "ts_code"],
        "max_rows": 8_000,
        "post_close_only": True,
    },
    "trade_cal": {
        "usage": "future_calendar_reference",
        "data_kind": "exchange_calendar",
        "allowed_parameter_names": ["end_date", "exchange", "start_date"],
        "max_rows": 5_000,
        "post_close_only": False,
    },
}
AUXILIARY_DATA_HANDLING_FIELDS = frozenset(
    {
        "raw_response_retention",
        "normalized_retention",
        "derived_retention",
        "max_retention_days",
        "termination_disposition",
    }
)
AUXILIARY_REVOCATION_POLICY_FIELDS = frozenset(
    {
        "check_before_credential_lease",
        "check_before_request",
        "check_before_acceptance",
        "head_change_invalidates",
    }
)
SHANGHAI = ZoneInfo("Asia/Shanghai")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class ProviderAuthorizationError(RuntimeError):
    """Raised when provider authorization evidence cannot be trusted."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "PROVIDER_AUTHORIZATION_DEGRADED",
    ) -> None:
        self.error_code = error_code
        super().__init__(message)


class ProviderAuthorizationConflict(ProviderAuthorizationError):
    """Raised when an immutable grant/revocation identity is reused."""


def _forbid_synthetic(value: Any) -> None:
    try:
        forbid_synthetic_provenance(value)
    except ProviderRehearsalError as exc:
        raise ProviderAuthorizationError(
            SYNTHETIC_PROVENANCE_FORBIDDEN,
            error_code=SYNTHETIC_PROVENANCE_FORBIDDEN,
        ) from exc


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = strict_json_file_object(path)
    except (OSError, StrictContractJSONError) as exc:
        raise ProviderAuthorizationError(
            f"authorization JSON is unreadable: {path}: {exc}"
        ) from exc
    _forbid_synthetic(payload)
    return payload


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _ID_RE.fullmatch(text):
        raise ProviderAuthorizationError(f"{label} is invalid")
    return text


def _text(value: Any, label: str, *, maximum: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum:
        raise ProviderAuthorizationError(f"{label} is invalid")
    return text


def _hash(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA_RE.fullmatch(text):
        raise ProviderAuthorizationError(f"{label} is invalid")
    return text


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ProviderAuthorizationError(f"{label} must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise ProviderAuthorizationError(f"{label} must include a timezone")
    canonical = parsed.isoformat()
    if not isinstance(value, datetime) and canonical != str(value):
        raise ProviderAuthorizationError(f"{label} is not canonical ISO format")
    return canonical, parsed


def _inside(root: Path, relative: str, label: str) -> Path:
    text = str(relative or "").strip().replace("\\", "/")
    if not text or Path(text).is_absolute():
        raise ProviderAuthorizationError(f"{label} must be a relative platform path")
    path = (root / text).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ProviderAuthorizationError(f"{label} escapes platform root") from exc
    return path


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _immutable_json(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_file():
        if _read_json(path) != dict(payload):
            raise ProviderAuthorizationConflict(f"immutable authorization conflict: {path}")
        return
    _atomic_json(path, payload)


def _unique_ids(values: Sequence[Any], label: str) -> list[str]:
    normalized = sorted(_identifier(value, label) for value in values)
    if not normalized or len(normalized) != len(set(normalized)):
        raise ProviderAuthorizationError(f"{label} values are empty or duplicated")
    return normalized


def _bounded_integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProviderAuthorizationError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ProviderAuthorizationError(f"{label} is outside the allowed range")
    return value


def _validate_auxiliary_endpoint_scope(
    scope: Mapping[str, Any], *, usage: str
) -> dict[str, Any]:
    payload = dict(scope)
    if set(payload) != AUXILIARY_ENDPOINT_SCOPE_FIELDS:
        raise ProviderAuthorizationError("auxiliary endpoint scope fields are invalid")
    endpoint_id = _identifier(payload.get("endpoint_id"), "endpoint_id")
    if endpoint_id.startswith("rt_") or "://" in endpoint_id:
        raise ProviderAuthorizationError("real-time or URL endpoint scopes are forbidden")
    post_close_only = payload.get("post_close_only")
    current_session_allowed = payload.get("current_session_allowed")
    if not isinstance(post_close_only, bool) or current_session_allowed is not False:
        raise ProviderAuthorizationError("auxiliary endpoint session policy is invalid")
    if usage == "post_close_history_auxiliary" and post_close_only is not True:
        raise ProviderAuthorizationError("post-close history endpoint is not post-close only")
    method = _text(payload.get("http_method"), "http_method", maximum=12).upper()
    if method != "POST" or payload.get("http_method") != method:
        raise ProviderAuthorizationError("auxiliary endpoint HTTP method must be POST")
    parameter_names = _unique_ids(
        list(payload.get("allowed_parameter_names") or []), "allowed parameter name"
    )
    sensitive_components = {
        "auth",
        "authorization",
        "token",
        "secret",
        "password",
        "credential",
        "key",
        "apikey",
    }
    if any(
        sensitive_components.intersection(re.split(r"[_.-]+", parameter_name))
        for parameter_name in parameter_names
    ):
        raise ProviderAuthorizationError("credential parameters cannot enter an endpoint scope")
    normalized = {
        "endpoint_id": endpoint_id,
        "api_version": _text(payload.get("api_version"), "api_version", maximum=80),
        "authority": _identifier(payload.get("authority"), "authority"),
        "data_kind": _identifier(payload.get("data_kind"), "data_kind"),
        "http_method": method,
        "allowed_parameter_names": parameter_names,
        "max_rows": _bounded_integer(
            payload.get("max_rows"), "max_rows", minimum=1, maximum=8_000
        ),
        "max_requests_per_minute": _bounded_integer(
            payload.get("max_requests_per_minute"),
            "max_requests_per_minute",
            minimum=1,
            maximum=500,
        ),
        "max_concurrency": _bounded_integer(
            payload.get("max_concurrency"), "max_concurrency", minimum=1, maximum=1
        ),
        "post_close_only": post_close_only,
        "current_session_allowed": False,
    }
    if payload != normalized:
        raise ProviderAuthorizationError("auxiliary endpoint scope is not canonical")
    contract = AUXILIARY_ENDPOINT_CONTRACTS.get(endpoint_id)
    if contract is None:
        raise ProviderAuthorizationError("auxiliary endpoint is not on the fixed allowlist")
    if (
        usage != contract["usage"]
        or normalized["data_kind"] != contract["data_kind"]
        or normalized["allowed_parameter_names"]
        != contract["allowed_parameter_names"]
        or normalized["max_rows"] > contract["max_rows"]
        or normalized["post_close_only"] is not contract["post_close_only"]
    ):
        raise ProviderAuthorizationError(
            "auxiliary endpoint scope does not match its fixed contract"
        )
    return normalized


def _validate_auxiliary_data_handling(
    value: Mapping[str, Any], permissions: Mapping[str, bool]
) -> dict[str, Any]:
    payload = dict(value)
    if set(payload) != AUXILIARY_DATA_HANDLING_FIELDS:
        raise ProviderAuthorizationError("auxiliary data handling fields are invalid")
    raw = payload.get("raw_response_retention")
    normalized = payload.get("normalized_retention")
    derived = payload.get("derived_retention")
    if raw not in {"NONE", "EPHEMERAL_MEMORY_ONLY", "BOUNDED_ENCRYPTED"}:
        raise ProviderAuthorizationError("raw response retention is invalid")
    if normalized not in {"NONE", "BOUNDED_ENCRYPTED"}:
        raise ProviderAuthorizationError("normalized retention is invalid")
    if derived not in {"NONE", "BOUNDED_ENCRYPTED"}:
        raise ProviderAuthorizationError("derived retention is invalid")
    retention_days = _bounded_integer(
        payload.get("max_retention_days"),
        "max_retention_days",
        minimum=0,
        maximum=90,
    )
    bounded = "BOUNDED_ENCRYPTED" in {raw, normalized, derived}
    if bounded != (retention_days > 0):
        raise ProviderAuthorizationError("retention duration does not match storage policy")
    expected_flags = {
        "raw_response_archival": raw == "BOUNDED_ENCRYPTED",
        "normalized_data_storage": normalized == "BOUNDED_ENCRYPTED",
        "derived_data_generation": derived == "BOUNDED_ENCRYPTED",
    }
    if any(permissions[key] is not expected for key, expected in expected_flags.items()):
        raise ProviderAuthorizationError("data handling exceeds declared permissions")
    if permissions["revision_history_storage"] and not permissions[
        "normalized_data_storage"
    ]:
        raise ProviderAuthorizationError("revision history requires normalized storage")
    if payload.get("termination_disposition") != "DELETE_OR_CRYPTO_ERASE":
        raise ProviderAuthorizationError("termination disposition is invalid")
    return payload


def _validate_auxiliary_authorization_grant(
    grant: Mapping[str, Any], *, platform_root: str | Path
) -> dict[str, Any]:
    expected = {
        "schema",
        "grant_id",
        "source_id",
        "source_version",
        "usage",
        "entitlement_profile",
        "scope",
        "permissions",
        "data_handling",
        "credential_policy_id",
        "evidence_path",
        "evidence_sha256",
        "reviewed_at",
        "valid_from",
        "valid_until",
        "revocation_policy",
        "approved_by",
        "authorization_reference",
        "platform_redistribution_enabled",
        "limitations",
        "real_orders",
        "grant_sha256",
    }
    payload = dict(grant)
    if set(payload) != expected or payload.get("schema") != PROVIDER_AUTHORIZATION_GRANT_V2_SCHEMA:
        raise ProviderAuthorizationError("provider auxiliary authorization grant fields are invalid")
    identity = {key: value for key, value in payload.items() if key != "grant_sha256"}
    digest = _hash(payload.get("grant_sha256"), "grant_sha256")
    if sha256_digest(identity) != digest:
        raise ProviderAuthorizationError("provider authorization grant digest mismatch")
    reviewed_text, reviewed = _timestamp(payload.get("reviewed_at"), "reviewed_at")
    from_text, valid_from = _timestamp(payload.get("valid_from"), "valid_from")
    until_text, valid_until = _timestamp(payload.get("valid_until"), "valid_until")
    if not (valid_from <= reviewed <= valid_until):
        raise ProviderAuthorizationError("authorization review must fall inside validity window")
    if valid_until - reviewed > timedelta(days=PROVIDER_AUTHORIZATION_MAX_REVIEW_DAYS):
        raise ProviderAuthorizationError("provider authorization review window exceeds 366 days")
    usage = _identifier(payload.get("usage"), "usage")
    if usage not in AUXILIARY_AUTHORIZATION_USAGES:
        raise ProviderAuthorizationError("auxiliary usage is invalid")
    profile_name = _text(
        payload.get("entitlement_profile"), "entitlement_profile", maximum=80
    )
    profile = AUXILIARY_ENTITLEMENT_PROFILES.get(profile_name)
    if profile is None or profile["usage"] != usage:
        raise ProviderAuthorizationError("auxiliary entitlement profile is invalid")
    raw_scope = payload.get("scope")
    if not isinstance(raw_scope, Mapping):
        raise ProviderAuthorizationError("auxiliary endpoint scope must be an object")
    scope = _validate_auxiliary_endpoint_scope(dict(raw_scope), usage=usage)
    permissions = dict(payload.get("permissions") or {})
    if set(permissions) != AUXILIARY_PERMISSION_KEYS or any(
        not isinstance(value, bool) for value in permissions.values()
    ):
        raise ProviderAuthorizationError("auxiliary permissions are invalid")
    if any(permissions[key] is not True for key in AUXILIARY_REQUIRED_PERMISSIONS):
        raise ProviderAuthorizationError("required auxiliary permissions are missing")
    if any(permissions[key] is not False for key in AUXILIARY_FORBIDDEN_PERMISSIONS):
        raise ProviderAuthorizationError("auxiliary authorization attempts to expand authority")
    expected_permissions = {key: False for key in AUXILIARY_PERMISSION_KEYS}
    for key in AUXILIARY_REQUIRED_PERMISSIONS:
        expected_permissions[key] = True
    expected_permissions["internal_quant_research"] = profile[
        "internal_quant_research"
    ]
    expected_permissions["normalized_data_storage"] = profile[
        "normalized_data_storage"
    ]
    if permissions != expected_permissions:
        raise ProviderAuthorizationError(
            "auxiliary permissions do not match the fixed entitlement profile"
        )
    data_handling = _validate_auxiliary_data_handling(
        dict(payload.get("data_handling") or {}), permissions
    )
    expected_handling = {
        "raw_response_retention": "EPHEMERAL_MEMORY_ONLY",
        "normalized_retention": profile["normalized_retention"],
        "derived_retention": "NONE",
        "termination_disposition": "DELETE_OR_CRYPTO_ERASE",
    }
    if any(data_handling.get(key) != value for key, value in expected_handling.items()):
        raise ProviderAuthorizationError(
            "auxiliary data handling does not match the fixed entitlement profile"
        )
    if profile["normalized_data_storage"]:
        if not 1 <= data_handling["max_retention_days"] <= 90:
            raise ProviderAuthorizationError("bounded normalized retention is invalid")
    elif data_handling["max_retention_days"] != 0:
        raise ProviderAuthorizationError("ephemeral auxiliary retention must be zero")
    revocation_policy = dict(payload.get("revocation_policy") or {})
    if set(revocation_policy) != AUXILIARY_REVOCATION_POLICY_FIELDS or any(
        revocation_policy.get(key) is not True
        for key in AUXILIARY_REVOCATION_POLICY_FIELDS
    ):
        raise ProviderAuthorizationError("auxiliary revocation fencing is incomplete")
    if payload.get("platform_redistribution_enabled") is not False:
        raise ProviderAuthorizationError("platform redistribution must remain disabled")
    if payload.get("real_orders") is not False:
        raise ProviderAuthorizationError("provider authorization cannot enable real orders")
    root = Path(platform_root).expanduser().resolve()
    evidence_path_text = str(payload.get("evidence_path") or "")
    evidence_path = _inside(root, evidence_path_text, "evidence_path")
    evidence_sha = _hash(payload.get("evidence_sha256"), "evidence_sha256")
    if not evidence_path.is_file() or _file_sha(evidence_path) != evidence_sha:
        raise ProviderAuthorizationError("provider authorization evidence hash mismatch")
    limitations = [
        _text(value, "authorization limitation", maximum=500)
        for value in list(payload.get("limitations") or [])
    ]
    if not limitations:
        raise ProviderAuthorizationError("provider authorization limitations are required")
    return {
        **payload,
        "grant_id": _identifier(payload.get("grant_id"), "grant_id"),
        "source_id": _identifier(payload.get("source_id"), "source_id"),
        "source_version": _text(payload.get("source_version"), "source_version", maximum=80),
        "usage": usage,
        "entitlement_profile": profile_name,
        "scope": scope,
        "permissions": permissions,
        "data_handling": data_handling,
        "credential_policy_id": _identifier(
            payload.get("credential_policy_id"), "credential_policy_id"
        ),
        "evidence_path": evidence_path_text,
        "evidence_sha256": evidence_sha,
        "reviewed_at": reviewed_text,
        "valid_from": from_text,
        "valid_until": until_text,
        "revocation_policy": revocation_policy,
        "approved_by": _text(payload.get("approved_by"), "approved_by"),
        "authorization_reference": _text(
            payload.get("authorization_reference"), "authorization_reference"
        ),
        "limitations": limitations,
        "grant_sha256": digest,
    }


def validate_provider_automation_authorization_grant(
    grant: Mapping[str, Any],
    *,
    platform_root: str | Path,
) -> dict[str, Any]:
    """Validate a grant's semantics, evidence file, and bounded review window."""

    _forbid_synthetic(grant)
    if grant.get("schema") == PROVIDER_AUTHORIZATION_GRANT_V2_SCHEMA:
        return _validate_auxiliary_authorization_grant(
            grant, platform_root=platform_root
        )
    expected = {
        "schema",
        "source_id",
        "source_version",
        "authorities",
        "endpoint_ids",
        "data_kinds",
        "allowed_usages",
        "entitlements",
        "evidence_path",
        "evidence_sha256",
        "reviewed_at",
        "valid_from",
        "valid_until",
        "approved_by",
        "authorization_reference",
        "platform_redistribution_enabled",
        "limitations",
        "real_orders",
        "grant_sha256",
    }
    payload = dict(grant)
    if set(payload) != expected or payload.get("schema") != PROVIDER_AUTHORIZATION_GRANT_SCHEMA:
        raise ProviderAuthorizationError("provider authorization grant fields are invalid")
    identity = {key: value for key, value in payload.items() if key != "grant_sha256"}
    digest = _hash(payload.get("grant_sha256"), "grant_sha256")
    if sha256_digest(identity) != digest:
        raise ProviderAuthorizationError("provider authorization grant digest mismatch")
    reviewed_text, reviewed = _timestamp(payload.get("reviewed_at"), "reviewed_at")
    from_text, valid_from = _timestamp(payload.get("valid_from"), "valid_from")
    until_text, valid_until = _timestamp(payload.get("valid_until"), "valid_until")
    if not (valid_from <= reviewed <= valid_until):
        raise ProviderAuthorizationError("authorization review must fall inside validity window")
    if valid_until - reviewed > timedelta(days=PROVIDER_AUTHORIZATION_MAX_REVIEW_DAYS):
        raise ProviderAuthorizationError("provider authorization review window exceeds 366 days")
    entitlements = dict(payload.get("entitlements") or {})
    if set(entitlements) != REQUIRED_FORWARD_ENTITLEMENTS or any(
        value is not True for value in entitlements.values()
    ):
        raise ProviderAuthorizationError("provider forward entitlements are incomplete")
    usages = _unique_ids(list(payload.get("allowed_usages") or []), "allowed usage")
    if "forward_observation" not in usages:
        raise ProviderAuthorizationError("authorization grant omits forward_observation")
    if payload.get("platform_redistribution_enabled") is not False:
        raise ProviderAuthorizationError("platform redistribution must remain disabled")
    if payload.get("real_orders") is not False:
        raise ProviderAuthorizationError("provider authorization cannot enable real orders")
    root = Path(platform_root).expanduser().resolve()
    evidence_path_text = str(payload.get("evidence_path") or "")
    evidence_path = _inside(root, evidence_path_text, "evidence_path")
    evidence_sha = _hash(payload.get("evidence_sha256"), "evidence_sha256")
    if not evidence_path.is_file() or _file_sha(evidence_path) != evidence_sha:
        raise ProviderAuthorizationError("provider authorization evidence hash mismatch")
    limitations = [_text(value, "authorization limitation", maximum=500) for value in list(payload.get("limitations") or [])]
    if not limitations:
        raise ProviderAuthorizationError("provider authorization limitations are required")
    return {
        **payload,
        "source_id": _identifier(payload.get("source_id"), "source_id"),
        "source_version": _text(payload.get("source_version"), "source_version", maximum=80),
        "authorities": _unique_ids(list(payload.get("authorities") or []), "authority"),
        "endpoint_ids": _unique_ids(list(payload.get("endpoint_ids") or []), "endpoint_id"),
        "data_kinds": _unique_ids(list(payload.get("data_kinds") or []), "data_kind"),
        "allowed_usages": usages,
        "entitlements": entitlements,
        "evidence_path": evidence_path_text,
        "evidence_sha256": evidence_sha,
        "reviewed_at": reviewed_text,
        "valid_from": from_text,
        "valid_until": until_text,
        "approved_by": _text(payload.get("approved_by"), "approved_by"),
        "authorization_reference": _text(
            payload.get("authorization_reference"), "authorization_reference"
        ),
        "limitations": limitations,
        "grant_sha256": digest,
    }


def build_provider_automation_authorization_grant(
    *,
    platform_root: str | Path,
    source_id: str,
    source_version: str,
    authorities: Sequence[str],
    endpoint_ids: Sequence[str],
    data_kinds: Sequence[str],
    allowed_usages: Sequence[str],
    evidence_path: str,
    reviewed_at: datetime,
    valid_from: datetime,
    valid_until: datetime,
    approved_by: str,
    authorization_reference: str,
    limitations: Sequence[str],
) -> dict[str, Any]:
    """Build, but do not register, one PAPER-forward data authorization grant."""

    root = Path(platform_root).expanduser().resolve()
    evidence = _inside(root, evidence_path, "evidence_path")
    if not evidence.is_file():
        raise ProviderAuthorizationError("provider authorization evidence is missing")
    identity = {
        "schema": PROVIDER_AUTHORIZATION_GRANT_SCHEMA,
        "source_id": _identifier(source_id, "source_id"),
        "source_version": _text(source_version, "source_version", maximum=80),
        "authorities": _unique_ids(authorities, "authority"),
        "endpoint_ids": _unique_ids(endpoint_ids, "endpoint_id"),
        "data_kinds": _unique_ids(data_kinds, "data_kind"),
        "allowed_usages": _unique_ids(allowed_usages, "allowed usage"),
        "entitlements": {key: True for key in sorted(REQUIRED_FORWARD_ENTITLEMENTS)},
        "evidence_path": str(evidence_path).replace("\\", "/"),
        "evidence_sha256": _file_sha(evidence),
        "reviewed_at": _timestamp(reviewed_at, "reviewed_at")[0],
        "valid_from": _timestamp(valid_from, "valid_from")[0],
        "valid_until": _timestamp(valid_until, "valid_until")[0],
        "approved_by": _text(approved_by, "approved_by"),
        "authorization_reference": _text(
            authorization_reference, "authorization_reference"
        ),
        "platform_redistribution_enabled": False,
        "limitations": [
            _text(value, "authorization limitation", maximum=500)
            for value in limitations
        ],
        "real_orders": False,
    }
    grant = {**identity, "grant_sha256": sha256_digest(identity)}
    return validate_provider_automation_authorization_grant(
        grant, platform_root=root
    )


def build_provider_auxiliary_authorization_grant(
    *,
    platform_root: str | Path,
    grant_id: str,
    source_id: str,
    source_version: str,
    usage: str,
    entitlement_profile: str,
    scope: Mapping[str, Any],
    permissions: Mapping[str, bool],
    data_handling: Mapping[str, Any],
    credential_policy_id: str,
    evidence_path: str,
    reviewed_at: datetime,
    valid_from: datetime,
    valid_until: datetime,
    revocation_policy: Mapping[str, bool],
    approved_by: str,
    authorization_reference: str,
    limitations: Sequence[str],
) -> dict[str, Any]:
    """Build a least-privilege post-close/calendar grant without enabling it."""

    root = Path(platform_root).expanduser().resolve()
    evidence = _inside(root, evidence_path, "evidence_path")
    if not evidence.is_file():
        raise ProviderAuthorizationError("provider authorization evidence is missing")
    usage_value = _identifier(usage, "usage")
    if usage_value not in AUXILIARY_AUTHORIZATION_USAGES:
        raise ProviderAuthorizationError("auxiliary usage is invalid")
    scope_payload = dict(scope)
    if set(scope_payload) != AUXILIARY_ENDPOINT_SCOPE_FIELDS:
        raise ProviderAuthorizationError("auxiliary endpoint scope fields are invalid")
    scope_payload["allowed_parameter_names"] = _unique_ids(
        list(scope_payload.get("allowed_parameter_names") or []),
        "allowed parameter name",
    )
    normalized_scope = _validate_auxiliary_endpoint_scope(
        scope_payload, usage=usage_value
    )
    permissions_payload = dict(permissions)
    data_handling_payload = dict(data_handling)
    revocation_payload = dict(revocation_policy)
    identity = {
        "schema": PROVIDER_AUTHORIZATION_GRANT_V2_SCHEMA,
        "grant_id": _identifier(grant_id, "grant_id"),
        "source_id": _identifier(source_id, "source_id"),
        "source_version": _text(source_version, "source_version", maximum=80),
        "usage": usage_value,
        "entitlement_profile": _text(
            entitlement_profile, "entitlement_profile", maximum=80
        ),
        "scope": normalized_scope,
        "permissions": permissions_payload,
        "data_handling": data_handling_payload,
        "credential_policy_id": _identifier(
            credential_policy_id, "credential_policy_id"
        ),
        "evidence_path": str(evidence_path).replace("\\", "/"),
        "evidence_sha256": _file_sha(evidence),
        "reviewed_at": _timestamp(reviewed_at, "reviewed_at")[0],
        "valid_from": _timestamp(valid_from, "valid_from")[0],
        "valid_until": _timestamp(valid_until, "valid_until")[0],
        "revocation_policy": revocation_payload,
        "approved_by": _text(approved_by, "approved_by"),
        "authorization_reference": _text(
            authorization_reference, "authorization_reference"
        ),
        "platform_redistribution_enabled": False,
        "limitations": [
            _text(value, "authorization limitation", maximum=500)
            for value in limitations
        ],
        "real_orders": False,
    }
    grant = {**identity, "grant_sha256": sha256_digest(identity)}
    return validate_provider_automation_authorization_grant(
        grant, platform_root=root
    )


class ProviderAutomationAuthorizationRegistry:
    """Append-only registry of structured grants and irreversible revocations."""

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
            raise AttributeError("authorization registry instance is immutable")
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
            raise ProviderAuthorizationError("provider authorization registry is locked") from exc
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
                raise ProviderAuthorizationError("authorization head is missing while records exist")
            return []
        head = _read_json(self.head_path)
        if set(head) != {"schema", "sequence", "record_sha256"} or head.get(
            "schema"
        ) != PROVIDER_AUTHORIZATION_HEAD_SCHEMA:
            raise ProviderAuthorizationError("provider authorization head is invalid")
        records: list[dict[str, Any]] = []
        previous_sha: str | None = None
        previous_time: datetime | None = None
        grants: dict[str, dict[str, Any]] = {}
        revoked: set[str] = set()
        required = {
            "schema",
            "sequence",
            "previous_record_sha256",
            "recorded_at",
            "action",
            "grant_sha256",
            "grant",
            "revocation_reference",
            "record_sha256",
        }
        for sequence, path in enumerate(paths, start=1):
            record = _read_json(path)
            identity = {key: value for key, value in record.items() if key != "record_sha256"}
            digest = _hash(record.get("record_sha256"), "record_sha256")
            recorded_text, recorded = _timestamp(record.get("recorded_at"), "recorded_at")
            grant_sha = _hash(record.get("grant_sha256"), "grant_sha256")
            if (
                set(record) != required
                or record.get("schema") != PROVIDER_AUTHORIZATION_RECORD_SCHEMA
                or record.get("sequence") != sequence
                or record.get("previous_record_sha256") != previous_sha
                or sha256_digest(identity) != digest
                or path.name != self._record_path(sequence, digest).name
                or record.get("recorded_at") != recorded_text
                or (previous_time is not None and recorded < previous_time)
            ):
                raise ProviderAuthorizationError("provider authorization record chain broke")
            if record.get("action") == "GRANT":
                if grant_sha in grants or grant_sha in revoked or record.get("revocation_reference") is not None:
                    raise ProviderAuthorizationError("provider authorization grant record is invalid")
                grant = validate_provider_automation_authorization_grant(
                    dict(record.get("grant") or {}), platform_root=self.platform_root
                )
                _, reviewed = _timestamp(grant["reviewed_at"], "reviewed_at")
                if grant["grant_sha256"] != grant_sha or recorded < reviewed:
                    raise ProviderAuthorizationError("provider authorization grant is misbound")
                grants[grant_sha] = grant
            elif record.get("action") == "REVOKE":
                if grant_sha not in grants or grant_sha in revoked or record.get("grant") is not None:
                    raise ProviderAuthorizationError("provider authorization revocation is invalid")
                _text(record.get("revocation_reference"), "revocation_reference")
                revoked.add(grant_sha)
            else:
                raise ProviderAuthorizationError("provider authorization action is invalid")
            records.append(record)
            previous_sha = digest
            previous_time = recorded
        if not records:
            raise ProviderAuthorizationError(
                "provider authorization head exists without records"
            )
        expected_head = {
            "schema": PROVIDER_AUTHORIZATION_HEAD_SCHEMA,
            "sequence": len(records),
            "record_sha256": records[-1]["record_sha256"],
        }
        if head != expected_head:
            raise ProviderAuthorizationError("provider authorization head does not match chain tip")
        return records

    def _append(self, identity: dict[str, Any]) -> dict[str, Any]:
        digest = sha256_digest(identity)
        record = {**identity, "record_sha256": digest}
        _immutable_json(self._record_path(identity["sequence"], digest), record)
        _atomic_json(
            self.head_path,
            {
                "schema": PROVIDER_AUTHORIZATION_HEAD_SCHEMA,
                "sequence": identity["sequence"],
                "record_sha256": digest,
            },
        )
        return record

    def register(self, grant: Mapping[str, Any], *, recorded_at: datetime) -> dict[str, Any]:
        normalized = validate_provider_automation_authorization_grant(
            grant, platform_root=self.platform_root
        )
        recorded_text, recorded = _timestamp(recorded_at, "recorded_at")
        _, reviewed = _timestamp(normalized["reviewed_at"], "reviewed_at")
        if recorded < reviewed:
            raise ProviderAuthorizationError("authorization was registered before review")
        with self._lock():
            records = self._load_chain()
            existing = [
                item
                for item in records
                if item["action"] == "GRANT"
                and item["grant_sha256"] == normalized["grant_sha256"]
            ]
            if existing:
                if existing[0]["grant"] != normalized:
                    raise ProviderAuthorizationConflict("authorization grant identity was reused")
                return {**existing[0], "idempotent": True}
            if records and recorded_text < records[-1]["recorded_at"]:
                raise ProviderAuthorizationError("authorization recorded_at moved backwards")
            identity = {
                "schema": PROVIDER_AUTHORIZATION_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": records[-1]["record_sha256"] if records else None,
                "recorded_at": recorded_text,
                "action": "GRANT",
                "grant_sha256": normalized["grant_sha256"],
                "grant": normalized,
                "revocation_reference": None,
            }
            return {**self._append(identity), "idempotent": False}

    def revoke(
        self,
        grant_sha256: str,
        *,
        revocation_reference: str,
        recorded_at: datetime,
    ) -> dict[str, Any]:
        grant_sha = _hash(grant_sha256, "grant_sha256")
        reference = _text(revocation_reference, "revocation_reference")
        recorded_text, _ = _timestamp(recorded_at, "recorded_at")
        with self._lock():
            records = self._load_chain()
            grants = [item for item in records if item["action"] == "GRANT" and item["grant_sha256"] == grant_sha]
            if not grants:
                raise ProviderAuthorizationError("cannot revoke an unknown provider authorization")
            revocations = [item for item in records if item["action"] == "REVOKE" and item["grant_sha256"] == grant_sha]
            if revocations:
                if revocations[0]["revocation_reference"] != reference:
                    raise ProviderAuthorizationConflict("authorization revocation identity changed")
                return {**revocations[0], "idempotent": True}
            if records and recorded_text < records[-1]["recorded_at"]:
                raise ProviderAuthorizationError("authorization recorded_at moved backwards")
            identity = {
                "schema": PROVIDER_AUTHORIZATION_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": records[-1]["record_sha256"],
                "recorded_at": recorded_text,
                "action": "REVOKE",
                "grant_sha256": grant_sha,
                "grant": None,
                "revocation_reference": reference,
            }
            return {**self._append(identity), "idempotent": False}

    def resolve(
        self,
        grant_sha256: str,
        *,
        as_of: datetime | None = None,
    ) -> dict[str, Any] | None:
        grant_sha = _hash(grant_sha256, "grant_sha256")
        records = self._load_chain()
        if any(item["action"] == "REVOKE" and item["grant_sha256"] == grant_sha for item in records):
            return None
        registrations = [
            item
            for item in records
            if item["action"] == "GRANT" and item["grant_sha256"] == grant_sha
        ]
        if len(registrations) != 1:
            return None
        grant = dict(registrations[0]["grant"])
        moment = as_of or self._clock()
        if moment.tzinfo is None:
            raise ProviderAuthorizationError("authorization as_of must include a timezone")
        _, registered_at = _timestamp(
            registrations[0]["recorded_at"], "registered_at"
        )
        _, valid_from = _timestamp(grant["valid_from"], "valid_from")
        _, valid_until = _timestamp(grant["valid_until"], "valid_until")
        return grant if registered_at <= moment and valid_from <= moment <= valid_until else None

    def resolve_with_proof(
        self,
        grant_sha256: str,
        *,
        as_of: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Resolve one active grant and bind it to the exact chain snapshot read."""

        grant_sha = _hash(grant_sha256, "grant_sha256")
        records = self._load_chain()
        registrations = [
            item
            for item in records
            if item["action"] == "GRANT" and item["grant_sha256"] == grant_sha
        ]
        if len(registrations) != 1 or any(
            item["action"] == "REVOKE" and item["grant_sha256"] == grant_sha
            for item in records
        ):
            return None
        grant = dict(registrations[0]["grant"])
        moment = as_of or self._clock()
        resolved_text, resolved_at = _timestamp(moment, "as_of")
        registered_text, registered_at = _timestamp(
            registrations[0]["recorded_at"], "registered_at"
        )
        _, valid_from = _timestamp(grant["valid_from"], "valid_from")
        _, valid_until = _timestamp(grant["valid_until"], "valid_until")
        if not registered_at <= resolved_at or not valid_from <= resolved_at <= valid_until:
            return None
        return {
            "schema": PROVIDER_AUTHORIZATION_RESOLUTION_SCHEMA,
            "grant": grant,
            "grant_sha256": grant_sha,
            "registration_record_sequence": registrations[0]["sequence"],
            "registration_record_sha256": registrations[0]["record_sha256"],
            "registered_at": registered_text,
            "head_sequence": len(records),
            "head_record_sha256": records[-1]["record_sha256"],
            "valid_from": grant["valid_from"],
            "valid_until": grant["valid_until"],
            "revocation_status": "ACTIVE_AS_OF",
            "resolved_at": resolved_text,
        }

    def resolve_scope_with_proof(
        self,
        grant_sha256: str,
        *,
        authority: str,
        endpoint_id: str,
        data_kind: str,
        usage: str,
        as_of: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Resolve exactly one v2 authorization tuple and its chain proof."""

        resolved = self.resolve_with_proof(grant_sha256, as_of=as_of)
        if resolved is None:
            return None
        grant = resolved["grant"]
        if grant.get("schema") != PROVIDER_AUTHORIZATION_GRANT_V2_SCHEMA:
            return None
        expected_scope = {
            "authority": _identifier(authority, "authority"),
            "endpoint_id": _identifier(endpoint_id, "endpoint_id"),
            "data_kind": _identifier(data_kind, "data_kind"),
            "usage": _identifier(usage, "usage"),
        }
        scope = grant["scope"]
        actual_scope = {
            "authority": scope["authority"],
            "endpoint_id": scope["endpoint_id"],
            "data_kind": scope["data_kind"],
            "usage": grant["usage"],
        }
        if actual_scope != expected_scope:
            return None
        identity = {
            "schema": PROVIDER_AUTHORIZATION_SCOPE_RESOLUTION_SCHEMA,
            "grant": grant,
            "grant_sha256": resolved["grant_sha256"],
            "grant_id": grant["grant_id"],
            "source_id": grant["source_id"],
            "source_version": grant["source_version"],
            "scope": actual_scope,
            "entitlement_profile": grant["entitlement_profile"],
            "registration_record_sequence": resolved[
                "registration_record_sequence"
            ],
            "registration_record_sha256": resolved[
                "registration_record_sha256"
            ],
            "registered_at": resolved["registered_at"],
            "head_sequence": resolved["head_sequence"],
            "head_record_sha256": resolved["head_record_sha256"],
            "valid_from": resolved["valid_from"],
            "valid_until": resolved["valid_until"],
            "revocation_status": resolved["revocation_status"],
            "resolved_at": resolved["resolved_at"],
        }
        return {**identity, "scope_proof_sha256": sha256_digest(identity)}

    def fence_scope_proof(
        self,
        proof: Mapping[str, Any],
    ) -> bool:
        """Fence with the registry's trusted clock; callers cannot backdate it."""

        payload = dict(proof)
        digest = payload.pop("scope_proof_sha256", None)
        try:
            digest_matches = isinstance(digest, str) and sha256_digest(payload) == digest
        except (TypeError, ValueError):
            return False
        if payload.get("schema") != PROVIDER_AUTHORIZATION_SCOPE_RESOLUTION_SCHEMA or not digest_matches:
            return False
        scope = payload.get("scope")
        if not isinstance(scope, Mapping):
            return False
        try:
            current = self.resolve_scope_with_proof(
                str(payload.get("grant_sha256") or ""),
                authority=str(scope.get("authority") or ""),
                endpoint_id=str(scope.get("endpoint_id") or ""),
                data_kind=str(scope.get("data_kind") or ""),
                usage=str(scope.get("usage") or ""),
            )
        except ProviderAuthorizationError:
            return False
        if current is None:
            return False
        stable_fields = {
            "grant",
            "grant_sha256",
            "grant_id",
            "source_id",
            "source_version",
            "scope",
            "entitlement_profile",
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
            registered = {item["grant_sha256"] for item in records if item["action"] == "GRANT"}
            revoked = {item["grant_sha256"] for item in records if item["action"] == "REVOKE"}
            active = [digest for digest in registered - revoked if self.resolve(digest, as_of=as_of) is not None]
            return {
                "schema": PROVIDER_AUTHORIZATION_INSPECTION_SCHEMA,
                "status": "EMPTY" if not records else "READY",
                "error": None,
                "error_code": None,
                "real_orders": False,
                "record_count": len(records),
                "registered_grant_count": len(registered),
                "revoked_grant_count": len(revoked),
                "active_grant_count": len(active),
                "head_record_sha256": records[-1]["record_sha256"] if records else None,
            }
        except ProviderAuthorizationError as exc:
            return {
                "schema": PROVIDER_AUTHORIZATION_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "error": str(exc),
                "error_code": exc.error_code,
                "real_orders": False,
                "record_count": 0,
                "registered_grant_count": 0,
                "revoked_grant_count": 0,
                "active_grant_count": 0,
                "head_record_sha256": None,
            }
