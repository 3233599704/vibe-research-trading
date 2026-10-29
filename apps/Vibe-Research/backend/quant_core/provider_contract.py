"""Content-bound provider deliveries before data enters the research catalog.

The catalog proves that stored revisions do not change.  This module proves what
source bundle, endpoint, raw artifact and normalized data contract produced a
revision.  A provider tool's advertised feature list is never treated as proof
that a particular delivery has point-in-time coverage.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from .data_catalog import DataCatalog, DataCatalogError
from .datahub import POINT_IN_TIME_CAPABILITIES
from .provenance import sha256_digest
from .provider_rehearsal import (
    SYNTHETIC_PROVENANCE_FORBIDDEN,
    ProviderRehearsalError,
    forbid_synthetic_provenance,
)
from .provider_normalization import (
    CANONICAL_JSON_NORMALIZER_ID,
    PROVIDER_ENDPOINT_NORMALIZER_IDS,
    ProviderNormalizationError,
    build_provider_normalization_attestation,
    verify_provider_normalization_attestation,
)
from .provider_wire_capture import (
    PROVIDER_WIRE_CAPTURE_MEDIA_TYPE,
    ProviderWireCaptureError,
    provider_wire_capture_completed_at,
)
from .provider_authorization import (
    PROVIDER_AUTHORIZATION_GRANT_SCHEMA,
    ProviderAuthorizationError,
    ProviderAutomationAuthorizationRegistry,
)
from .provider_adapter_certification import (
    ProviderAdapterCertificationError,
    ProviderAdapterCertificationRegistry,
    provider_adapter_contract_sha256,
)
from .strict_contract_json import strict_json_file


PROVIDER_SOURCE_REGISTRY_SCHEMA = "quant-platform/provider-source-registry/v1"
PROVIDER_DELIVERY_ENVELOPE_SCHEMA = "quant-platform/provider-delivery-envelope/v1"
PROVIDER_DELIVERY_EVIDENCE_SCHEMA = "quant-core/provider-delivery-evidence/v1"
PROVIDER_PUBLICATION_RECEIPT_SCHEMA = "quant-core/provider-dataset-publication-receipt/v1"
PROVIDER_REVISION_LINEAGE_VERIFICATION_SCHEMA = (
    "quant-core/provider-revision-lineage-verification/v1"
)
PROVIDER_EVIDENCE_STATUS_SCHEMA = "quant-core/provider-evidence-status/v1"
EMPTY_PRODUCT_COVERAGE_SCHEMA = "quant-platform/empty-product-coverage/v1"
PROVIDER_SOURCE_REGISTRY_PATH = "config/data-quality/provider-source-registry-v1.json"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SOURCE_FIELDS = {
    "source_id",
    "version",
    "bundle_path",
    "bundle_sha256",
    "approval_status",
    "legal_status",
    "automation_authorization",
    "allowed_usages",
    "endpoints",
    "limitations",
}
_APPROVED_SOURCE_FIELDS = _SOURCE_FIELDS | {"adapter_certification"}
_AUTOMATION_AUTHORIZATION_FIELDS = {"status", "evidence_path", "evidence_sha256"}
_APPROVED_AUTOMATION_AUTHORIZATION_FIELDS = _AUTOMATION_AUTHORIZATION_FIELDS | {
    "registry_path",
    "grant_sha256",
}
_ADAPTER_CERTIFICATION_FIELDS = {"registry_path", "report_sha256"}
_ENDPOINT_FIELDS = {
    "endpoint_id",
    "authority",
    "data_kinds",
    "allowed_adjustments",
    "capability_ceiling",
    "normalizer_id",
    "normalizer_artifacts",
}
_NORMALIZER_ARTIFACT_FIELDS = {"path", "sha256"}
_ENVELOPE_FIELDS = {
    "schema",
    "source_id",
    "source_version",
    "endpoint_id",
    "usage",
    "dataset_id",
    "dataset_key",
    "provider_revision_id",
    "event_time",
    "published_at",
    "revision_time",
    "fetched_at",
    "available_at",
    "raw_artifact",
    "normalized_payload_sha256",
    "data_contract",
    "capabilities",
    "limitations",
    "normalizer_id",
}
_ARTIFACT_FIELDS = {"filename", "media_type", "byte_size", "sha256"}
_DATA_CONTRACT_FIELDS = {
    "kind",
    "market",
    "frequency",
    "adjustment",
    "primary_keys",
    "fields",
    "record_count",
    "period",
    "available_at_field",
}
_PERIOD_FIELDS = {"requested_start", "requested_end", "actual_start", "actual_end"}


class ProviderContractError(RuntimeError):
    """Raised when a provider delivery cannot be proven safely."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "PROVIDER_DATASET_DEGRADED",
    ) -> None:
        self.error_code = error_code
        super().__init__(message)


def _forbid_synthetic(value: Any) -> None:
    try:
        forbid_synthetic_provenance(value)
    except ProviderRehearsalError as exc:
        raise ProviderContractError(
            SYNTHETIC_PROVENANCE_FORBIDDEN,
            error_code=SYNTHETIC_PROVENANCE_FORBIDDEN,
        ) from exc


def _origin_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Classify whether archived bytes prove an endpoint-specific transport replay.

    A canonical JSON artifact proves content integrity but not upstream origin.  It
    must never be promoted to independent-source evidence merely because a source
    contract names a different authority.
    """

    envelope = dict(evidence.get("envelope") or {})
    artifact = dict(envelope.get("raw_artifact") or {})
    normalization = dict(evidence.get("normalization_attestation") or {})
    normalizer_id = str(normalization.get("normalizer_id") or "")
    transport_capture = bool(
        artifact.get("media_type") == PROVIDER_WIRE_CAPTURE_MEDIA_TYPE
        and normalization.get("media_type") == PROVIDER_WIRE_CAPTURE_MEDIA_TYPE
    )
    endpoint_specific = normalizer_id in PROVIDER_ENDPOINT_NORMALIZER_IDS
    replay_passed = bool(
        normalization.get("status") == "PASS"
        and normalizer_id == str(envelope.get("normalizer_id") or "")
    )
    transport_verified = transport_capture and endpoint_specific and replay_passed
    source_contract = dict(evidence.get("source_contract") or {})
    authorization = dict(source_contract.get("automation_authorization") or {})
    certification = dict(source_contract.get("adapter_certification") or {})
    authorized_certified_delivery = bool(
        authorization.get("status") == "APPROVED"
        and bool(str(authorization.get("grant_sha256") or ""))
        and bool(str(certification.get("report_sha256") or ""))
        and envelope.get("usage") == "forward_observation"
        and replay_passed
    )
    origin_verified = transport_verified or authorized_certified_delivery
    return {
        "origin_verified": origin_verified,
        "transport_capture_verified": transport_verified,
        "authorized_certified_delivery": authorized_certified_delivery,
        "transport_capture_present": transport_capture,
        "endpoint_specific_normalizer": endpoint_specific,
        "normalizer_id": normalizer_id,
        "raw_artifact_media_type": str(artifact.get("media_type") or ""),
        "classification": (
            "ENDPOINT_TRANSPORT_CAPTURE_REPLAYED"
            if transport_verified
            else "AUTHORIZED_CERTIFIED_PROVIDER_DELIVERY"
            if authorized_certified_delivery
            else "TRANSPORT_CAPTURE_NORMALIZER_UNVERIFIED"
            if transport_capture
            else "NORMALIZED_ARTIFACT_ORIGIN_UNVERIFIED"
        ),
    }


def _read_json(path: Path) -> Any:
    value = strict_json_file(path)
    _forbid_synthetic(value)
    return value


def _immutable_json(path: Path, payload: Mapping[str, Any]) -> None:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != encoded:
            raise ProviderContractError(f"immutable provider evidence collision: {path}")
        return
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temporary.write_text(encoded, encoding="utf-8")
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _immutable_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != content:
            raise ProviderContractError(f"immutable source-artifact collision: {path}")
        return
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temporary.write_bytes(content)
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ProviderContractError(
            f"{label} fields must exactly match the contract; "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
        )


def _nonempty(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ProviderContractError(f"{label} is required")
    return text


def _identifier(value: Any, label: str) -> str:
    original = _nonempty(value, label)
    text = original.lower()
    if original != text:
        raise ProviderContractError(f"{label} must already be lowercase")
    if not _ID_RE.fullmatch(text):
        raise ProviderContractError(f"{label} must be a lowercase stable identifier")
    return text


def _sha256(value: Any, label: str) -> str:
    digest = str(value or "").lower()
    if not _SHA256_RE.fullmatch(digest):
        raise ProviderContractError(f"{label} must be 64 lowercase hexadecimal characters")
    return digest


def _timestamp(value: Any, label: str, *, required: bool = True) -> datetime | None:
    if value is None and not required:
        return None
    text = _nonempty(value, label)
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProviderContractError(f"{label} must be an ISO-8601 timestamp") from exc
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ProviderContractError(f"{label} must include a timezone")
    return moment


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ProviderDeliveryStore:
    """Validate, archive and re-verify source deliveries for DataCatalog."""

    def __init__(
        self,
        *,
        platform_root: Path | str,
        catalog_root: Path | str,
        registry_path: Path | str | None = None,
        authorization_as_of: datetime | None = None,
        certification_as_of: datetime | None = None,
    ) -> None:
        self.platform_root = Path(platform_root).expanduser().resolve()
        self.catalog_root = Path(catalog_root).expanduser().resolve()
        candidate = Path(registry_path or PROVIDER_SOURCE_REGISTRY_PATH)
        self.registry_path = (
            candidate.resolve()
            if candidate.is_absolute()
            else (self.platform_root / candidate).resolve()
        )
        self.evidence_root = self.catalog_root / "provider-evidence"
        self.catalog = DataCatalog(self.catalog_root)
        if authorization_as_of is not None and authorization_as_of.tzinfo is None:
            raise ProviderContractError("authorization_as_of must include a timezone")
        if certification_as_of is not None and certification_as_of.tzinfo is None:
            raise ProviderContractError("certification_as_of must include a timezone")
        self.authorization_as_of = authorization_as_of
        self.certification_as_of = certification_as_of or authorization_as_of

    def _bundle_path(self, relative: str) -> Path:
        path = (self.platform_root / relative).resolve()
        try:
            path.relative_to(self.platform_root)
        except ValueError as exc:
            raise ProviderContractError("provider bundle_path escapes platform root") from exc
        return path

    def load_registry(self) -> dict[str, Any]:
        try:
            registry = _read_json(self.registry_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ProviderContractError(f"provider source registry is unreadable: {exc}") from exc
        if not isinstance(registry, dict):
            raise ProviderContractError("provider source registry must be an object")
        if set(registry) != {"schema", "registry_id", "sources", "registry_sha256"}:
            raise ProviderContractError("provider source registry fields are invalid")
        if registry.get("schema") != PROVIDER_SOURCE_REGISTRY_SCHEMA:
            raise ProviderContractError("unsupported provider source registry schema")
        identity = {key: value for key, value in registry.items() if key != "registry_sha256"}
        if sha256_digest(identity) != _sha256(
            registry.get("registry_sha256"), "registry_sha256"
        ):
            raise ProviderContractError("provider source registry digest mismatch")
        sources = list(registry.get("sources") or [])
        if not sources:
            raise ProviderContractError("provider source registry is empty")
        source_keys: set[tuple[str, str]] = set()
        normalized_sources: list[dict[str, Any]] = []
        for raw_source in sources:
            if not isinstance(raw_source, dict):
                raise ProviderContractError("provider source entry must be an object")
            authorization_hint = raw_source.get("automation_authorization")
            approved_hint = (
                isinstance(authorization_hint, dict)
                and authorization_hint.get("status") == "APPROVED"
            )
            _exact_fields(
                raw_source,
                _APPROVED_SOURCE_FIELDS if approved_hint else _SOURCE_FIELDS,
                "provider source",
            )
            source = dict(raw_source)
            source_id = _identifier(source.get("source_id"), "source_id")
            version = _nonempty(source.get("version"), "source version")
            if source.get("approval_status") != "CAPTURE_ONLY_NOT_PROMOTION_ELIGIBLE":
                raise ProviderContractError(
                    f"provider source may only be registered for capture: {source_id}"
                )
            _nonempty(source.get("legal_status"), "legal_status")
            authorization = dict(source.get("automation_authorization") or {})
            authorization_status = _nonempty(
                authorization.get("status"), "automation authorization status"
            )
            if authorization_status not in {"APPROVED", "NOT_APPROVED"}:
                raise ProviderContractError(
                    "automation authorization status must be APPROVED or NOT_APPROVED"
                )
            _exact_fields(
                authorization,
                (
                    _APPROVED_AUTOMATION_AUTHORIZATION_FIELDS
                    if authorization_status == "APPROVED"
                    else _AUTOMATION_AUTHORIZATION_FIELDS
                ),
                "provider automation authorization",
            )
            authorization_path_text = _nonempty(
                authorization.get("evidence_path"),
                "automation authorization evidence_path",
            )
            authorization_path = self._bundle_path(authorization_path_text)
            if not authorization_path.is_file():
                raise ProviderContractError(
                    f"automation authorization evidence is missing: {authorization_path}"
                )
            authorization_sha = _sha256(
                authorization.get("evidence_sha256"),
                "automation authorization evidence_sha256",
            )
            if _hash_file(authorization_path) != authorization_sha:
                raise ProviderContractError(
                    f"automation authorization evidence digest mismatch: {source_id}"
                )
            normalized_authorization = {
                "status": authorization_status,
                "evidence_path": authorization_path_text,
                "evidence_sha256": authorization_sha,
            }
            authorization_grant: dict[str, Any] | None = None
            if authorization_status == "APPROVED":
                registry_path_text = _nonempty(
                    authorization.get("registry_path"),
                    "authorization registry_path",
                ).replace("\\", "/")
                registry_root = self._bundle_path(registry_path_text)
                grant_sha = _sha256(
                    authorization.get("grant_sha256"),
                    "authorization grant_sha256",
                )
                try:
                    authorization_grant = ProviderAutomationAuthorizationRegistry(
                        registry_root,
                        platform_root=self.platform_root,
                    ).resolve(grant_sha, as_of=self.authorization_as_of)
                except ProviderAuthorizationError as exc:
                    raise ProviderContractError(
                        f"provider authorization registry is invalid: {source_id}: {exc}"
                    ) from exc
                if authorization_grant is None:
                    raise ProviderContractError(
                        f"provider authorization grant is missing, expired or revoked: {source_id}"
                    )
                if (
                    authorization_grant.get("source_id") != source_id
                    or authorization_grant.get("source_version") != version
                    or authorization_grant.get("evidence_path")
                    != authorization_path_text
                    or authorization_grant.get("evidence_sha256") != authorization_sha
                ):
                    raise ProviderContractError(
                        f"provider authorization grant identity mismatch: {source_id}"
                    )
                if authorization_grant.get("schema") != PROVIDER_AUTHORIZATION_GRANT_SCHEMA:
                    raise ProviderContractError(
                        "auxiliary authorization grants require exact runtime scope "
                        f"resolution and cannot enter the legacy delivery path: {source_id}"
                    )
                normalized_authorization.update(
                    registry_path=registry_path_text,
                    grant_sha256=grant_sha,
                )
            source["automation_authorization"] = normalized_authorization
            certification_reference: dict[str, str] | None = None
            if authorization_status == "APPROVED":
                raw_certification = source.get("adapter_certification")
                if not isinstance(raw_certification, dict):
                    raise ProviderContractError(
                        f"approved provider source lacks adapter certification: {source_id}"
                    )
                _exact_fields(
                    raw_certification,
                    _ADAPTER_CERTIFICATION_FIELDS,
                    "provider adapter certification",
                )
                certification_reference = {
                    "registry_path": _nonempty(
                        raw_certification.get("registry_path"),
                        "adapter certification registry_path",
                    ).replace("\\", "/"),
                    "report_sha256": _sha256(
                        raw_certification.get("report_sha256"),
                        "adapter certification report_sha256",
                    ),
                }
            limitations = [
                _nonempty(item, "source limitation")
                for item in list(source.get("limitations") or [])
            ]
            if not limitations:
                raise ProviderContractError(f"source limitations are required for {source_id}")
            key = (source_id, version)
            if key in source_keys:
                raise ProviderContractError(f"duplicate provider source version: {key}")
            source_keys.add(key)
            bundle_path = self._bundle_path(_nonempty(source.get("bundle_path"), "bundle_path"))
            if not bundle_path.is_file():
                raise ProviderContractError(f"provider bundle is missing: {bundle_path}")
            expected_bundle_sha = _sha256(source.get("bundle_sha256"), "bundle_sha256")
            if _hash_file(bundle_path) != expected_bundle_sha:
                raise ProviderContractError(f"provider bundle digest mismatch: {source_id}")
            allowed_usages = [_identifier(item, "allowed usage") for item in source["allowed_usages"]]
            if not allowed_usages or len(set(allowed_usages)) != len(allowed_usages):
                raise ProviderContractError(f"allowed usages are invalid for {source_id}")
            if (
                "forward_observation" in allowed_usages
                and authorization_status != "APPROVED"
            ):
                raise ProviderContractError(
                    f"forward_observation requires approved automation authorization: {source_id}"
                )
            endpoints: list[dict[str, Any]] = []
            endpoint_ids: set[str] = set()
            for raw_endpoint in list(source.get("endpoints") or []):
                if not isinstance(raw_endpoint, dict):
                    raise ProviderContractError("provider endpoint must be an object")
                _exact_fields(raw_endpoint, _ENDPOINT_FIELDS, "provider endpoint")
                endpoint = dict(raw_endpoint)
                endpoint_id = _identifier(endpoint.get("endpoint_id"), "endpoint_id")
                if endpoint_id in endpoint_ids:
                    raise ProviderContractError(
                        f"duplicate endpoint {endpoint_id} for {source_id}"
                    )
                endpoint_ids.add(endpoint_id)
                ceiling = dict(endpoint.get("capability_ceiling") or {})
                if set(ceiling) != set(POINT_IN_TIME_CAPABILITIES) or any(
                    not isinstance(value, bool) for value in ceiling.values()
                ):
                    raise ProviderContractError(
                        f"capability ceiling is incomplete for {source_id}/{endpoint_id}"
                    )
                endpoint["endpoint_id"] = endpoint_id
                endpoint["authority"] = _identifier(endpoint.get("authority"), "authority")
                endpoint["data_kinds"] = [
                    _identifier(item, "data kind") for item in endpoint["data_kinds"]
                ]
                endpoint["allowed_adjustments"] = [
                    _identifier(item, "allowed adjustment")
                    for item in endpoint["allowed_adjustments"]
                ]
                endpoint["normalizer_id"] = _nonempty(
                    endpoint.get("normalizer_id"), "normalizer_id"
                )
                if endpoint["normalizer_id"] not in {
                    CANONICAL_JSON_NORMALIZER_ID,
                    *PROVIDER_ENDPOINT_NORMALIZER_IDS,
                }:
                    raise ProviderContractError(
                        f"provider endpoint uses an unsupported normalizer: "
                        f"{source_id}/{endpoint_id}"
                    )
                normalizer_artifacts: list[dict[str, str]] = []
                artifact_paths: set[str] = set()
                for raw_artifact in list(endpoint.get("normalizer_artifacts") or []):
                    if not isinstance(raw_artifact, dict):
                        raise ProviderContractError(
                            "provider normalizer artifact must be an object"
                        )
                    _exact_fields(
                        raw_artifact,
                        _NORMALIZER_ARTIFACT_FIELDS,
                        "provider normalizer artifact",
                    )
                    relative_path = _nonempty(
                        raw_artifact.get("path"), "normalizer artifact path"
                    )
                    if relative_path in artifact_paths:
                        raise ProviderContractError(
                            f"duplicate normalizer artifact path: {relative_path}"
                        )
                    artifact_paths.add(relative_path)
                    artifact_path = self._bundle_path(relative_path)
                    if not artifact_path.is_file():
                        raise ProviderContractError(
                            f"provider normalizer artifact is missing: {artifact_path}"
                        )
                    expected_sha = _sha256(
                        raw_artifact.get("sha256"), "normalizer artifact sha256"
                    )
                    if _hash_file(artifact_path) != expected_sha:
                        raise ProviderContractError(
                            f"provider normalizer artifact digest mismatch: "
                            f"{source_id}/{endpoint_id}/{relative_path}"
                        )
                    normalizer_artifacts.append(
                        {"path": relative_path, "sha256": expected_sha}
                    )
                if not normalizer_artifacts:
                    raise ProviderContractError(
                        f"provider endpoint has no frozen normalizer artifacts: "
                        f"{source_id}/{endpoint_id}"
                    )
                endpoint["normalizer_artifacts"] = normalizer_artifacts
                if (
                    not endpoint["data_kinds"]
                    or len(set(endpoint["data_kinds"])) != len(endpoint["data_kinds"])
                    or not endpoint["allowed_adjustments"]
                    or len(set(endpoint["allowed_adjustments"]))
                    != len(endpoint["allowed_adjustments"])
                ):
                    raise ProviderContractError(
                        f"endpoint kinds/adjustments are invalid for {source_id}/{endpoint_id}"
                    )
                endpoints.append(endpoint)
            if not endpoints:
                raise ProviderContractError(f"provider source has no endpoints: {source_id}")
            if authorization_grant is not None:
                endpoint_ids = {str(item["endpoint_id"]) for item in endpoints}
                authorities = {str(item["authority"]) for item in endpoints}
                data_kinds = {
                    str(kind)
                    for item in endpoints
                    for kind in list(item["data_kinds"])
                }
                if (
                    not set(allowed_usages)
                    <= set(authorization_grant["allowed_usages"])
                    or not endpoint_ids <= set(authorization_grant["endpoint_ids"])
                    or not authorities <= set(authorization_grant["authorities"])
                    or not data_kinds <= set(authorization_grant["data_kinds"])
                ):
                    raise ProviderContractError(
                        f"provider source exceeds its structured authorization scope: {source_id}"
                    )
            source.update(
                {
                    "source_id": source_id,
                    "version": version,
                    "allowed_usages": allowed_usages,
                    "endpoints": endpoints,
                    "limitations": limitations,
                }
            )
            if certification_reference is not None:
                certification_root = self._bundle_path(
                    certification_reference["registry_path"]
                )
                try:
                    certification_report = ProviderAdapterCertificationRegistry(
                        certification_root,
                        platform_root=self.platform_root,
                    ).resolve(
                        certification_reference["report_sha256"],
                        as_of=self.certification_as_of,
                    )
                except ProviderAdapterCertificationError as exc:
                    raise ProviderContractError(
                        f"provider adapter certification registry is invalid: "
                        f"{source_id}: {exc}"
                    ) from exc
                if certification_report is None:
                    raise ProviderContractError(
                        f"provider adapter certification is missing, expired or revoked: "
                        f"{source_id}"
                    )
                endpoint_contract_sha = provider_adapter_contract_sha256(source)
                endpoint_normalizers = sorted(
                    (
                        {
                            "endpoint_id": str(item["endpoint_id"]),
                            "normalizer_id": str(item["normalizer_id"]),
                        }
                        for item in endpoints
                    ),
                    key=lambda item: item["endpoint_id"],
                )
                if (
                    certification_report.get("source_id") != source_id
                    or certification_report.get("source_version") != version
                    or certification_report.get("bundle_sha256")
                    != expected_bundle_sha
                    or certification_report.get("authorization_grant_sha256")
                    != normalized_authorization.get("grant_sha256")
                    or certification_report.get("endpoint_contract_sha256")
                    != endpoint_contract_sha
                    or certification_report.get("endpoints")
                    != endpoint_normalizers
                ):
                    raise ProviderContractError(
                        f"provider adapter certification identity mismatch: {source_id}"
                    )
                source["adapter_certification"] = certification_reference
            normalized_sources.append(source)
        return {**registry, "sources": normalized_sources}

    def _source_contract(
        self, registry: Mapping[str, Any], source_id: str, version: str, endpoint_id: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        matches = [
            item
            for item in registry["sources"]
            if item["source_id"] == source_id and item["version"] == version
        ]
        if len(matches) != 1:
            raise ProviderContractError("provider source/version is not in the approved registry")
        source = dict(matches[0])
        endpoints = [
            item for item in source["endpoints"] if item["endpoint_id"] == endpoint_id
        ]
        if len(endpoints) != 1:
            raise ProviderContractError("provider endpoint is not approved for this source")
        return source, dict(endpoints[0])

    @staticmethod
    def _validate_payload(
        payload: Mapping[str, Any], data_contract: Mapping[str, Any]
    ) -> list[dict[str, Any]]:
        if set(payload) != {"records", "metadata"}:
            raise ProviderContractError(
                "normalized payload must contain exactly records and metadata"
            )
        if not isinstance(payload.get("metadata"), dict):
            raise ProviderContractError("normalized payload metadata must be an object")
        records = list(payload.get("records") or [])
        if any(not isinstance(item, dict) for item in records):
            raise ProviderContractError("normalized payload records must be objects")
        if len(records) != int(data_contract["record_count"]):
            raise ProviderContractError("data contract record_count does not match payload")
        declared_fields = sorted(str(item) for item in data_contract["fields"])
        observed_fields = sorted({str(key) for item in records for key in item})
        if records and declared_fields != observed_fields:
            raise ProviderContractError("data contract fields do not match payload records")
        primary_keys = [str(item) for item in data_contract["primary_keys"]]
        if not primary_keys or any(key not in declared_fields for key in primary_keys):
            raise ProviderContractError("data contract primary_keys are invalid")
        identities: set[tuple[str, ...]] = set()
        for item in records:
            if any(item.get(key) is None for key in primary_keys):
                raise ProviderContractError("normalized record has a missing primary key")
            identity = tuple(str(item[key]) for key in primary_keys)
            if identity in identities:
                raise ProviderContractError("normalized payload contains duplicate primary keys")
            identities.add(identity)
        return records

    @staticmethod
    def _capability_checks(
        *,
        claimed: Mapping[str, Any],
        ceiling: Mapping[str, bool],
        data_contract: Mapping[str, Any],
        records: list[dict[str, Any]],
        metadata: Mapping[str, Any],
        delivery_available_at: datetime,
    ) -> list[dict[str, Any]]:
        if set(claimed) != set(POINT_IN_TIME_CAPABILITIES) or any(
            not isinstance(value, bool) for value in claimed.values()
        ):
            raise ProviderContractError("delivery capabilities must be a complete boolean map")
        checks: list[dict[str, Any]] = []
        kind = str(data_contract["kind"])
        adjustment = str(data_contract["adjustment"])
        fields = set(str(item) for item in data_contract["fields"])
        structural = {
            "raw_unadjusted_prices": kind == "market_bars"
            and adjustment == "raw"
            and {"open", "high", "low", "close", "volume"}.issubset(fields),
            "adjustment_factors": kind == "adjustment_factors"
            and {"effective_date", "factor"}.issubset(fields),
            "corporate_actions": kind == "corporate_actions"
            and {
                "asset_id",
                "event_type",
                "effective_date",
                "cash_per_share",
                "split_ratio",
                "economic_semantics",
                "announced_at",
                "available_at",
            }.issubset(fields),
            "historical_universe_membership": kind == "universe_membership"
            and (
                {"asset_id", "effective_from", "effective_to"}.issubset(fields)
                or {
                    "universe_id",
                    "asset_id",
                    "event_type",
                    "effective_date",
                    "announced_at",
                }.issubset(fields)
            ),
            "delisted_assets": kind == "security_master"
            and {"asset_id", "listing_status", "delisted_at"}.issubset(fields),
            "available_at_timestamps": False,
            "provider_revision_history": False,
        }
        available_field = data_contract.get("available_at_field")
        if available_field:
            try:
                row_times = [
                    _timestamp(item.get(str(available_field)), "record available_at")
                    for item in records
                ]
                structural["available_at_timestamps"] = bool(records) and all(
                    moment is not None and moment <= delivery_available_at
                    for moment in row_times
                )
            except ProviderContractError:
                structural["available_at_timestamps"] = False
        if not records and kind == "corporate_actions":
            assertion = dict(metadata.get("empty_coverage_assertion") or {})
            period = dict(data_contract.get("period") or {})
            try:
                if set(assertion) != {
                    "schema",
                    "product_kind",
                    "complete",
                    "requested_start",
                    "requested_end",
                    "asset_ids",
                    "available_at",
                }:
                    raise ProviderContractError("empty coverage assertion fields are invalid")
                asset_ids = [
                    _nonempty(item, "empty coverage asset_id")
                    for item in list(assertion.get("asset_ids") or [])
                ]
                assertion_available_at = _timestamp(
                    assertion.get("available_at"), "empty coverage available_at"
                )
                structural["available_at_timestamps"] = bool(
                    assertion.get("schema") == EMPTY_PRODUCT_COVERAGE_SCHEMA
                    and assertion.get("product_kind") == kind
                    and assertion.get("complete") is True
                    and assertion.get("requested_start") == period.get("requested_start")
                    and assertion.get("requested_end") == period.get("requested_end")
                    and asset_ids
                    and len(asset_ids) == len(set(asset_ids))
                    and assertion_available_at <= delivery_available_at
                )
            except (ProviderContractError, TypeError, ValueError):
                structural["available_at_timestamps"] = False
        for capability in POINT_IN_TIME_CAPABILITIES:
            requested = claimed[capability] is True
            passed = not requested or (
                ceiling[capability] is True and structural[capability] is True
            )
            checks.append(
                {
                    "capability": capability,
                    "claimed": requested,
                    "ceiling_allows": ceiling[capability] is True,
                    "structural_evidence": structural[capability] is True,
                    "passed": passed,
                }
            )
        if any(item["claimed"] and not item["passed"] for item in checks):
            failed = [item["capability"] for item in checks if item["claimed"] and not item["passed"]]
            raise ProviderContractError(f"delivery capability claim exceeds evidence: {failed}")
        return checks

    def _normalize_envelope(
        self,
        envelope: Mapping[str, Any],
        payload: Mapping[str, Any],
        raw_path: Path,
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        list[dict[str, Any]],
        bytes,
        dict[str, Any],
    ]:
        raw = dict(envelope)
        _exact_fields(raw, _ENVELOPE_FIELDS, "provider delivery envelope")
        if raw.get("schema") != PROVIDER_DELIVERY_ENVELOPE_SCHEMA:
            raise ProviderContractError("unsupported provider delivery envelope schema")
        source_id = _identifier(raw.get("source_id"), "source_id")
        source_version = _nonempty(raw.get("source_version"), "source_version")
        endpoint_id = _identifier(raw.get("endpoint_id"), "endpoint_id")
        usage = _identifier(raw.get("usage"), "usage")
        registry = self.load_registry()
        source, endpoint = self._source_contract(
            registry, source_id, source_version, endpoint_id
        )
        if usage not in source["allowed_usages"]:
            raise ProviderContractError("delivery usage is not approved for the source")

        artifact = dict(raw.get("raw_artifact") or {})
        _exact_fields(artifact, _ARTIFACT_FIELDS, "raw artifact")
        content = raw_path.read_bytes()
        actual_artifact_sha = hashlib.sha256(content).hexdigest()
        if Path(str(artifact.get("filename") or "")).name != raw_path.name:
            raise ProviderContractError("raw artifact filename does not match the supplied file")
        if int(artifact.get("byte_size") or -1) != len(content):
            raise ProviderContractError("raw artifact byte_size mismatch")
        if _sha256(artifact.get("sha256"), "raw artifact sha256") != actual_artifact_sha:
            raise ProviderContractError("raw artifact digest mismatch")

        payload_sha = sha256_digest(payload)
        if _sha256(raw.get("normalized_payload_sha256"), "normalized_payload_sha256") != payload_sha:
            raise ProviderContractError("normalized payload digest mismatch")
        normalizer_id = _nonempty(raw.get("normalizer_id"), "normalizer_id")
        if normalizer_id != endpoint["normalizer_id"]:
            raise ProviderContractError(
                "delivery normalizer differs from the frozen endpoint contract"
            )
        try:
            normalization = build_provider_normalization_attestation(
                content,
                payload,
                media_type=str(artifact.get("media_type") or ""),
                normalizer_id=normalizer_id,
            )
        except ProviderNormalizationError as exc:
            raise ProviderContractError(
                f"provider normalization replay failed: {exc}"
            ) from exc
        if normalization["status"] != "PASS":
            raise ProviderContractError(
                "provider normalization replay does not match supplied payload"
            )
        data_contract = dict(raw.get("data_contract") or {})
        _exact_fields(data_contract, _DATA_CONTRACT_FIELDS, "data contract")
        period = dict(data_contract.get("period") or {})
        _exact_fields(period, _PERIOD_FIELDS, "data contract period")
        data_contract["kind"] = _identifier(data_contract.get("kind"), "data kind")
        data_contract["market"] = _identifier(data_contract.get("market"), "market")
        data_contract["frequency"] = _identifier(data_contract.get("frequency"), "frequency")
        data_contract["adjustment"] = _identifier(data_contract.get("adjustment"), "adjustment")
        if data_contract["kind"] not in endpoint["data_kinds"]:
            raise ProviderContractError("delivery data kind is not approved for the endpoint")
        if data_contract["adjustment"] not in endpoint["allowed_adjustments"]:
            raise ProviderContractError("delivery adjustment is not approved for the endpoint")
        record_count = data_contract.get("record_count")
        if isinstance(record_count, bool) or not isinstance(record_count, int) or record_count < 0:
            raise ProviderContractError("data contract record_count must be a non-negative integer")
        if record_count == 0 and data_contract["kind"] != "corporate_actions":
            raise ProviderContractError(
                "only a complete corporate-action coverage assertion may be empty"
            )
        normalized_period: dict[str, str | None] = {}
        for key, value in period.items():
            normalized_period[key] = None if value is None else _nonempty(value, f"period.{key}")
        requested_start = normalized_period["requested_start"]
        requested_end = normalized_period["requested_end"]
        actual_start = normalized_period["actual_start"]
        actual_end = normalized_period["actual_end"]
        if (actual_start is None) != (actual_end is None):
            raise ProviderContractError("actual period boundaries must be supplied together")
        if record_count > 0 and actual_start is None:
            raise ProviderContractError("non-empty delivery requires an actual period")
        if record_count == 0 and actual_start is not None:
            raise ProviderContractError("empty delivery cannot declare an actual period")
        if requested_start and requested_end and requested_start > requested_end:
            raise ProviderContractError("requested period start is after end")
        if actual_start is not None and actual_start > actual_end:
            raise ProviderContractError("actual period start is after end")
        if requested_start and actual_start is not None and actual_start < requested_start:
            raise ProviderContractError("actual period starts before the requested period")
        if requested_end and actual_end is not None and actual_end > requested_end:
            raise ProviderContractError("actual period ends after the requested period")
        data_contract["period"] = normalized_period
        records = self._validate_payload(payload, data_contract)

        times = {
            "event_time": _timestamp(raw.get("event_time"), "event_time", required=False),
            "published_at": _timestamp(raw.get("published_at"), "published_at", required=False),
            "revision_time": _timestamp(raw.get("revision_time"), "revision_time", required=False),
            "fetched_at": _timestamp(raw.get("fetched_at"), "fetched_at"),
            "available_at": _timestamp(raw.get("available_at"), "available_at"),
        }
        if artifact.get("media_type") == PROVIDER_WIRE_CAPTURE_MEDIA_TYPE:
            try:
                capture_completed_at = _timestamp(
                    provider_wire_capture_completed_at(content),
                    "wire capture completed_at",
                )
            except ProviderWireCaptureError as exc:
                raise ProviderContractError(str(exc)) from exc
            if times["fetched_at"] != capture_completed_at:
                raise ProviderContractError(
                    "provider fetched_at must equal the wire capture completed_at"
                )
        ordered = [moment for moment in times.values() if moment is not None]
        if any(left > right for left, right in zip(ordered, ordered[1:])):
            raise ProviderContractError("provider delivery timestamps are out of order")
        checks = self._capability_checks(
            claimed=dict(raw.get("capabilities") or {}),
            ceiling=dict(endpoint["capability_ceiling"]),
            data_contract=data_contract,
            records=records,
            metadata=dict(payload.get("metadata") or {}),
            delivery_available_at=times["available_at"],
        )
        limitations = [
            _nonempty(item, "delivery limitation")
            for item in list(raw.get("limitations") or [])
        ]
        if not limitations:
            raise ProviderContractError("provider delivery limitations are required")
        normalized = {
            **raw,
            "source_id": source_id,
            "source_version": source_version,
            "endpoint_id": endpoint_id,
            "usage": usage,
            "dataset_id": _identifier(raw.get("dataset_id"), "dataset_id"),
            "dataset_key": _nonempty(raw.get("dataset_key"), "dataset_key"),
            "provider_revision_id": _nonempty(
                raw.get("provider_revision_id"), "provider_revision_id"
            ),
            "raw_artifact": {
                **artifact,
                "filename": raw_path.name,
                "media_type": _nonempty(artifact.get("media_type"), "raw artifact media_type"),
                "byte_size": len(content),
                "sha256": actual_artifact_sha,
            },
            "normalized_payload_sha256": payload_sha,
            "data_contract": data_contract,
            "capabilities": {
                key: bool(raw["capabilities"][key]) for key in POINT_IN_TIME_CAPABILITIES
            },
            "limitations": limitations,
            "normalizer_id": normalizer_id,
        }
        return normalized, source, checks, content, normalization

    def publish(
        self,
        *,
        envelope: Mapping[str, Any],
        normalized_payload: Mapping[str, Any],
        raw_artifact_path: Path | str,
    ) -> dict[str, Any]:
        _forbid_synthetic(envelope)
        _forbid_synthetic(normalized_payload)
        raw_path = Path(raw_artifact_path).expanduser().resolve()
        if not raw_path.is_file():
            raise ProviderContractError(f"raw artifact is missing: {raw_path}")
        normalized, source, checks, content, normalization = self._normalize_envelope(
            envelope, normalized_payload, raw_path
        )
        source_contract_sha = sha256_digest(source)
        evidence_identity = {
            "schema": PROVIDER_DELIVERY_EVIDENCE_SCHEMA,
            "envelope": normalized,
            "source_contract": source,
            "source_contract_sha256": source_contract_sha,
            "capability_checks": checks,
            "normalization_attestation": normalization,
        }
        delivery_sha = sha256_digest(evidence_identity)
        evidence = {**evidence_identity, "delivery_sha256": delivery_sha}
        artifact_sha = normalized["raw_artifact"]["sha256"]
        _immutable_bytes(
            self.evidence_root / "artifacts" / f"{artifact_sha}.bin", content
        )
        _immutable_json(
            self.evidence_root / "deliveries" / f"{delivery_sha}.json", evidence
        )
        try:
            manifest = self.catalog.publish(
                normalized["dataset_id"],
                normalized_payload,
                provider={
                    "name": normalized["source_id"],
                    "authority": next(
                        item["authority"]
                        for item in source["endpoints"]
                        if item["endpoint_id"] == normalized["endpoint_id"]
                    ),
                    "source_version": normalized["source_version"],
                    "endpoint_id": normalized["endpoint_id"],
                    "dataset_key": normalized["dataset_key"],
                    "revision_id": normalized["provider_revision_id"],
                    "source_sha256": artifact_sha,
                    "delivery_sha256": delivery_sha,
                },
                available_at=normalized["available_at"],
                metadata={
                    "provider_contract_schema": PROVIDER_DELIVERY_EVIDENCE_SCHEMA,
                    "provider_delivery_sha256": delivery_sha,
                    "source_contract_sha256": source_contract_sha,
                    "usage": normalized["usage"],
                    "data_contract": normalized["data_contract"],
                    "capabilities": normalized["capabilities"],
                    "limitations": [*source["limitations"], *normalized["limitations"]],
                    "raw_artifact": normalized["raw_artifact"],
                },
                declared_dataset_sha256=normalized["normalized_payload_sha256"],
            )
        except DataCatalogError as exc:
            raise ProviderContractError(
                f"provider delivery was staged but catalog publication failed: {exc}"
            ) from exc
        verification = self.verify_catalog_binding(
            normalized["dataset_id"], manifest["manifest_sha256"]
        )
        if not verification["verified"]:
            raise ProviderContractError(
                f"published provider delivery failed verification: {verification['errors']}"
            )
        receipt_identity = {
            "schema": PROVIDER_PUBLICATION_RECEIPT_SCHEMA,
            "dataset_id": normalized["dataset_id"],
            "manifest_sha256": manifest["manifest_sha256"],
            "payload_sha256": manifest["payload_sha256"],
            "delivery_sha256": delivery_sha,
            "source_contract_sha256": source_contract_sha,
        }
        receipt_sha = sha256_digest(receipt_identity)
        receipt = {**receipt_identity, "receipt_sha256": receipt_sha}
        _immutable_json(
            self.evidence_root / "publications" / f"{receipt_sha}.json", receipt
        )
        return {
            "schema": "quant-core/provider-dataset-publication/v1",
            "dataset_id": normalized["dataset_id"],
            "manifest": manifest,
            "delivery": evidence,
            "receipt": receipt,
            "verification": verification,
            "promotion_eligible": False,
        }

    def verify_delivery(self, delivery_sha256: str) -> dict[str, Any]:
        errors: list[str] = []
        error_code: str | None = None
        try:
            digest = _sha256(delivery_sha256, "delivery_sha256")
            path = self.evidence_root / "deliveries" / f"{digest}.json"
            evidence = _read_json(path)
            if not isinstance(evidence, dict):
                raise ProviderContractError("provider delivery evidence must be an object")
            identity = {key: value for key, value in evidence.items() if key != "delivery_sha256"}
            if evidence.get("schema") != PROVIDER_DELIVERY_EVIDENCE_SCHEMA:
                errors.append("unsupported provider delivery evidence schema")
            if evidence.get("delivery_sha256") != digest or sha256_digest(identity) != digest:
                errors.append("provider delivery evidence digest mismatch")
            source = dict(evidence.get("source_contract") or {})
            if sha256_digest(source) != str(evidence.get("source_contract_sha256") or ""):
                errors.append("provider source contract digest mismatch")
            registry = self.load_registry()
            current_source, _ = self._source_contract(
                registry,
                str(source.get("source_id") or ""),
                str(source.get("version") or ""),
                str(dict(evidence.get("envelope") or {}).get("endpoint_id") or ""),
            )
            if current_source != source:
                errors.append("provider source contract changed or was revoked")
            artifact = dict(dict(evidence.get("envelope") or {}).get("raw_artifact") or {})
            artifact_sha = _sha256(artifact.get("sha256"), "raw artifact sha256")
            artifact_path = self.evidence_root / "artifacts" / f"{artifact_sha}.bin"
            if not artifact_path.is_file():
                errors.append("archived raw artifact is missing")
            else:
                if artifact_path.stat().st_size != int(artifact.get("byte_size") or -1):
                    errors.append("archived raw artifact size mismatch")
                if _hash_file(artifact_path) != artifact_sha:
                    errors.append("archived raw artifact digest mismatch")
                normalization = verify_provider_normalization_attestation(
                    dict(evidence.get("normalization_attestation") or {}),
                    artifact_path.read_bytes(),
                    expected_payload_sha256=str(
                        dict(evidence.get("envelope") or {}).get(
                            "normalized_payload_sha256"
                        )
                        or ""
                    ),
                )
                if not normalization["verified"]:
                    errors.extend(normalization["errors"])
                envelope = dict(evidence.get("envelope") or {})
                if artifact.get("media_type") == PROVIDER_WIRE_CAPTURE_MEDIA_TYPE:
                    try:
                        capture_completed_at = _timestamp(
                            provider_wire_capture_completed_at(artifact_path.read_bytes()),
                            "wire capture completed_at",
                        )
                        if _timestamp(envelope.get("fetched_at"), "fetched_at") != capture_completed_at:
                            errors.append(
                                "provider fetched_at differs from wire capture completed_at"
                            )
                    except (ProviderWireCaptureError, ProviderContractError) as exc:
                        errors.append(str(exc))
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, ProviderContractError) as exc:
            errors.append(str(exc))
            error_code = (
                exc.error_code
                if isinstance(exc, ProviderContractError)
                else "PROVIDER_DELIVERY_INVALID"
            )
            evidence = None
            digest = str(delivery_sha256)
        if errors and error_code is None:
            error_code = "PROVIDER_DELIVERY_INVALID"
        return {
            "verified": not errors,
            "delivery_sha256": digest,
            "errors": errors,
            "error_code": error_code,
            "evidence": evidence,
            "origin_evidence": (
                _origin_evidence(evidence) if isinstance(evidence, dict) else None
            ),
        }

    def verify_catalog_binding(
        self, dataset_id: str, manifest_sha256: str
    ) -> dict[str, Any]:
        errors: list[str] = []
        error_code: str | None = None
        delivery: dict[str, Any] | None = None
        try:
            loaded = self.catalog.load(dataset_id, manifest_sha256)
            _forbid_synthetic(loaded)
            manifest = dict(loaded["manifest"])
            metadata = dict(manifest.get("metadata") or {})
            provider = dict(manifest.get("provider") or {})
            delivery_sha = _sha256(
                metadata.get("provider_delivery_sha256"), "provider_delivery_sha256"
            )
            delivery = self.verify_delivery(delivery_sha)
            if not delivery["verified"]:
                errors.extend(delivery["errors"])
                error_code = str(
                    delivery.get("error_code") or "PROVIDER_CATALOG_BINDING_INVALID"
                )
            evidence = dict(delivery.get("evidence") or {})
            envelope = dict(evidence.get("envelope") or {})
            expected_provider = {
                "name": envelope.get("source_id"),
                "authority": next(
                    (
                        item.get("authority")
                        for item in dict(evidence.get("source_contract") or {}).get("endpoints", [])
                        if item.get("endpoint_id") == envelope.get("endpoint_id")
                    ),
                    None,
                ),
                "source_version": envelope.get("source_version"),
                "endpoint_id": envelope.get("endpoint_id"),
                "dataset_key": envelope.get("dataset_key"),
                "revision_id": envelope.get("provider_revision_id"),
                "source_sha256": dict(envelope.get("raw_artifact") or {}).get("sha256"),
                "delivery_sha256": delivery_sha,
            }
            if provider != expected_provider:
                errors.append("catalog provider record does not match delivery evidence")
            if loaded["payload_sha256"] != envelope.get("normalized_payload_sha256"):
                errors.append("catalog payload does not match provider delivery")
            normalization = dict(evidence.get("normalization_attestation") or {})
            if normalization.get("supplied_payload_sha256") != loaded[
                "payload_sha256"
            ]:
                errors.append("catalog payload does not match normalization replay")
            if metadata.get("source_contract_sha256") != evidence.get("source_contract_sha256"):
                errors.append("catalog source contract does not match provider delivery")
            if metadata.get("data_contract") != envelope.get("data_contract"):
                errors.append("catalog data contract does not match provider delivery")
            if metadata.get("capabilities") != envelope.get("capabilities"):
                errors.append("catalog capabilities do not match provider delivery")
        except (DataCatalogError, ProviderContractError, KeyError, TypeError, ValueError) as exc:
            errors.append(str(exc))
            error_code = (
                exc.error_code
                if isinstance(exc, ProviderContractError)
                else "PROVIDER_CATALOG_BINDING_INVALID"
            )
            loaded = None
            delivery_sha = None
        if errors and error_code is None:
            error_code = "PROVIDER_CATALOG_BINDING_INVALID"
        return {
            "verified": not errors,
            "dataset_id": dataset_id,
            "manifest_sha256": manifest_sha256,
            "delivery_sha256": delivery_sha,
            "origin_evidence": (
                dict(delivery.get("origin_evidence") or {})
                if isinstance(delivery, dict)
                else {}
            ),
            "errors": errors,
            "error_code": error_code,
            "catalog": loaded,
        }

    def verify_revision_lineage(
        self,
        dataset_id: str,
        head_manifest_sha256: str,
        *,
        selected_manifest_sha256: str | None = None,
        minimum_revision_count: int = 2,
    ) -> dict[str, Any]:
        """Prove provider revision retention from replayable immutable evidence.

        A provider endpoint declaring revision-history support is only a ceiling.
        Formal admission additionally requires multiple distinct raw provider
        revisions to remain content-addressed, catalog-bound and selectable at
        their original availability times.  A delivery can never self-assert
        this property because it spans more than one publication.
        """

        errors: list[str] = []
        revisions: list[dict[str, Any]] = []
        try:
            if (
                isinstance(minimum_revision_count, bool)
                or not isinstance(minimum_revision_count, int)
                or minimum_revision_count < 2
            ):
                raise ProviderContractError(
                    "minimum_revision_count must be an integer of at least 2"
                )
            dataset = _identifier(dataset_id, "dataset_id")
            head_sha = _sha256(head_manifest_sha256, "head_manifest_sha256")
            selected_sha = (
                _sha256(selected_manifest_sha256, "selected_manifest_sha256")
                if selected_manifest_sha256 is not None
                else head_sha
            )
            history = self.catalog.history(dataset, head_sha)
            if history.get("verified") is not True:
                errors.extend(str(item) for item in history.get("errors") or [])
            manifests = [
                dict(item)
                for item in list(history.get("manifests") or [])
                if isinstance(item, Mapping)
            ]
            manifest_shas = {
                str(item.get("manifest_sha256") or "") for item in manifests
            }
            if selected_sha not in manifest_shas:
                errors.append("selected manifest is not reachable from the frozen catalog head")
            if len(manifests) < minimum_revision_count:
                errors.append(
                    "provider revision history requires at least "
                    f"{minimum_revision_count} immutable catalog revisions"
                )

            source_identity: dict[str, Any] | None = None
            revision_ids: set[str] = set()
            source_shas: set[str] = set()
            delivery_shas: set[str] = set()
            for manifest in manifests:
                manifest_sha = str(manifest.get("manifest_sha256") or "")
                provider = dict(manifest.get("provider") or {})
                current_identity = {
                    key: provider.get(key)
                    for key in (
                        "name",
                        "authority",
                        "source_version",
                        "endpoint_id",
                        "dataset_key",
                    )
                }
                if not all(str(value or "").strip() for value in current_identity.values()):
                    errors.append(
                        f"catalog revision {manifest.get('revision')} has incomplete provider identity"
                    )
                elif source_identity is None:
                    source_identity = current_identity
                elif current_identity != source_identity:
                    errors.append("provider identity changes inside one dataset revision chain")

                revision_id = str(provider.get("revision_id") or "").strip()
                source_sha = str(provider.get("source_sha256") or "").strip()
                delivery_sha = str(provider.get("delivery_sha256") or "").strip()
                try:
                    revision_id = _nonempty(revision_id, "provider revision_id")
                    source_sha = _sha256(source_sha, "provider source_sha256")
                    delivery_sha = _sha256(delivery_sha, "provider delivery_sha256")
                except ProviderContractError as exc:
                    errors.append(
                        f"catalog revision {manifest.get('revision')}: {exc}"
                    )
                if revision_id in revision_ids:
                    errors.append("provider revision_id is repeated across catalog revisions")
                if source_sha in source_shas:
                    errors.append("raw provider artifact is repeated across catalog revisions")
                if delivery_sha in delivery_shas:
                    errors.append("provider delivery is repeated across catalog revisions")
                revision_ids.add(revision_id)
                source_shas.add(source_sha)
                delivery_shas.add(delivery_sha)

                binding = self.verify_catalog_binding(dataset, manifest_sha)
                if binding.get("verified") is not True:
                    errors.extend(
                        f"revision {manifest.get('revision')}: {item}"
                        for item in binding.get("errors") or []
                    )
                try:
                    replay = self.catalog.resolve_as_of(
                        dataset,
                        str(manifest.get("available_at") or ""),
                        catalog_head_manifest_sha256=head_sha,
                    )
                    if replay.get("selected_manifest_sha256") != manifest_sha:
                        errors.append(
                            f"catalog revision {manifest.get('revision')} is not reproducible as-of its availability time"
                        )
                    replay_verification = self.catalog.verify_as_of(replay)
                    if replay_verification.get("verified") is not True:
                        errors.extend(
                            f"revision {manifest.get('revision')}: {item}"
                            for item in replay_verification.get("errors") or []
                        )
                except DataCatalogError as exc:
                    errors.append(f"revision {manifest.get('revision')}: {exc}")

                revisions.append(
                    {
                        "revision": manifest.get("revision"),
                        "manifest_sha256": manifest_sha or None,
                        "payload_sha256": manifest.get("payload_sha256"),
                        "available_at": manifest.get("available_at"),
                        "provider_revision_id": revision_id or None,
                        "source_sha256": source_sha or None,
                        "delivery_sha256": delivery_sha or None,
                        "catalog_binding_verified": binding.get("verified") is True,
                    }
                )
        except (
            DataCatalogError,
            ProviderContractError,
            TypeError,
            ValueError,
            KeyError,
        ) as exc:
            errors.append(str(exc))
            dataset = str(dataset_id)
            head_sha = str(head_manifest_sha256)
            selected_sha = str(selected_manifest_sha256 or head_manifest_sha256)
            history = None
            source_identity = None

        identity = {
            "schema": PROVIDER_REVISION_LINEAGE_VERIFICATION_SCHEMA,
            "dataset_id": dataset,
            "head_manifest_sha256": head_sha,
            "selected_manifest_sha256": selected_sha,
            "minimum_revision_count": minimum_revision_count,
            "source_identity": source_identity,
            "catalog_history_sha256": (
                history.get("history_sha256") if isinstance(history, Mapping) else None
            ),
            "revisions": revisions,
            "errors": list(dict.fromkeys(errors)),
        }
        return {
            **identity,
            "verified": not identity["errors"],
            "lineage_sha256": sha256_digest(identity),
        }

    def verify_publication(self, receipt_sha256: str) -> dict[str, Any]:
        errors: list[str] = []
        error_code: str | None = None
        try:
            digest = _sha256(receipt_sha256, "receipt_sha256")
            path = self.evidence_root / "publications" / f"{digest}.json"
            receipt = _read_json(path)
            if not isinstance(receipt, dict):
                raise ProviderContractError("provider publication receipt must be an object")
            identity = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
            if receipt.get("schema") != PROVIDER_PUBLICATION_RECEIPT_SCHEMA:
                errors.append("unsupported provider publication receipt schema")
            if receipt.get("receipt_sha256") != digest or sha256_digest(identity) != digest:
                errors.append("provider publication receipt digest mismatch")
            binding = self.verify_catalog_binding(
                str(receipt.get("dataset_id") or ""),
                str(receipt.get("manifest_sha256") or ""),
            )
            if not binding["verified"]:
                errors.extend(binding["errors"])
                error_code = str(
                    binding.get("error_code") or "PROVIDER_PUBLICATION_INVALID"
                )
            loaded = dict(binding.get("catalog") or {})
            if loaded:
                if loaded.get("payload_sha256") != receipt.get("payload_sha256"):
                    errors.append("publication receipt payload does not match catalog")
                manifest = dict(loaded.get("manifest") or {})
                metadata = dict(manifest.get("metadata") or {})
                if metadata.get("provider_delivery_sha256") != receipt.get("delivery_sha256"):
                    errors.append("publication receipt delivery does not match catalog")
                if metadata.get("source_contract_sha256") != receipt.get(
                    "source_contract_sha256"
                ):
                    errors.append("publication receipt source contract does not match catalog")
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            json.JSONDecodeError,
            ProviderContractError,
        ) as exc:
            errors.append(str(exc))
            error_code = (
                exc.error_code
                if isinstance(exc, ProviderContractError)
                else "PROVIDER_PUBLICATION_INVALID"
            )
            receipt = None
            binding = None
            digest = str(receipt_sha256)
        if errors and error_code is None:
            error_code = "PROVIDER_PUBLICATION_INVALID"
        return {
            "verified": not errors,
            "receipt_sha256": digest,
            "errors": errors,
            "error_code": error_code,
            "receipt": receipt,
            "binding": binding,
        }

    def status(self) -> dict[str, Any]:
        errors: list[str] = []
        error_codes: list[str] = []
        try:
            registry = self.load_registry()
            registry_verified = True
            registry_sha = registry["registry_sha256"]
            source_count = len(registry["sources"])
            authorized_sources = [
                item
                for item in registry["sources"]
                if dict(item.get("automation_authorization") or {}).get("status")
                == "APPROVED"
            ]
            authorization_grants = {
                str(dict(item["automation_authorization"])["grant_sha256"])
                for item in authorized_sources
            }
            authorization_gate = {
                "status": "NOT_REQUIRED" if not authorized_sources else "READY",
                "approved_source_count": len(authorized_sources),
                "active_grant_count": len(authorization_grants),
                "grant_sha256s": sorted(authorization_grants),
            }
            certification_reports = {
                str(dict(item["adapter_certification"])["report_sha256"])
                for item in authorized_sources
            }
            certification_gate = {
                "status": "NOT_REQUIRED" if not authorized_sources else "READY",
                "certified_source_count": len(authorized_sources),
                "active_report_count": len(certification_reports),
                "report_sha256s": sorted(certification_reports),
            }
        except ProviderContractError as exc:
            errors.append(str(exc))
            error_codes.append(exc.error_code)
            registry_verified = False
            registry_sha = None
            source_count = 0
            authorization_gate = {
                "status": "DEGRADED",
                "approved_source_count": 0,
                "active_grant_count": 0,
                "grant_sha256s": [],
            }
            certification_gate = {
                "status": "DEGRADED",
                "certified_source_count": 0,
                "active_report_count": 0,
                "report_sha256s": [],
            }
        deliveries: list[dict[str, Any]] = []
        delivery_root = self.evidence_root / "deliveries"
        if delivery_root.is_dir():
            for path in sorted(delivery_root.glob("*.json"), key=lambda item: item.name):
                deliveries.append(self.verify_delivery(path.stem))
        verified_count = sum(1 for item in deliveries if item["verified"])
        errors.extend(error for item in deliveries for error in item.get("errors", []))
        error_codes.extend(
            str(item["error_code"])
            for item in deliveries
            if item.get("error_code")
        )
        publications: list[dict[str, Any]] = []
        publication_root = self.evidence_root / "publications"
        if publication_root.is_dir():
            for path in sorted(publication_root.glob("*.json"), key=lambda item: item.name):
                publications.append(self.verify_publication(path.stem))
        verified_publications = sum(1 for item in publications if item["verified"])
        errors.extend(error for item in publications for error in item.get("errors", []))
        error_codes.extend(
            str(item["error_code"])
            for item in publications
            if item.get("error_code")
        )
        published_deliveries = {
            str(dict(item.get("receipt") or {}).get("delivery_sha256") or "")
            for item in publications
        }
        staged_delivery_count = sum(
            1
            for item in deliveries
            if str(item.get("delivery_sha256") or "") not in published_deliveries
        )
        delivery_by_sha = {
            str(item.get("delivery_sha256") or ""): item for item in deliveries
        }
        published_origins = [
            dict(
                delivery_by_sha.get(
                    str(dict(item.get("receipt") or {}).get("delivery_sha256") or ""),
                    {},
                ).get("origin_evidence")
                or {}
            )
            for item in publications
            if item.get("verified") is True
        ]
        transport_evidenced_publications = sum(
            item.get("transport_capture_verified") is True for item in published_origins
        )
        origin_verified_publications = sum(
            item.get("origin_verified") is True for item in published_origins
        )
        origin_evidence_gate = {
            "status": "EMPTY" if not published_origins else "RESEARCH_ONLY",
            "verified_publication_count": len(published_origins),
            "origin_verified_publication_count": origin_verified_publications,
            "transport_evidenced_publication_count": transport_evidenced_publications,
            "origin_unverified_publication_count": (
                len(published_origins) - origin_verified_publications
            ),
            "independent_source_admission_requires_provenance_evidence": True,
        }
        if errors:
            status = "DEGRADED"
        elif publications:
            status = "READY"
        else:
            status = "EMPTY"
        error_codes = list(dict.fromkeys(error_codes))
        error_code = None
        if errors:
            error_code = (
                SYNTHETIC_PROVENANCE_FORBIDDEN
                if SYNTHETIC_PROVENANCE_FORBIDDEN in error_codes
                else "PROVIDER_DATASET_DEGRADED"
            )
        return {
            "schema": PROVIDER_EVIDENCE_STATUS_SCHEMA,
            "status": status,
            "real_orders": False,
            "error_code": error_code,
            "error_codes": error_codes,
            "registry_verified": registry_verified,
            "registry_sha256": registry_sha,
            "source_count": source_count,
            "authorization_gate": authorization_gate,
            "adapter_certification_gate": certification_gate,
            "origin_evidence_gate": origin_evidence_gate,
            "delivery_count": len(deliveries),
            "verified_delivery_count": verified_count,
            "staged_delivery_count": staged_delivery_count,
            "publication_count": len(publications),
            "verified_publication_count": verified_publications,
            "promotion_eligible_delivery_count": 0,
            "errors": list(dict.fromkeys(errors)),
            "deliveries": deliveries,
            "publications": publications,
        }
