"""Authorized, credential-free intake for frozen provider certification samples.

Raw vendor samples are untrusted inputs.  Before an adapter certification may
reference them, this module verifies an active provider authorization, performs
a bounded high-confidence credential scan, stores bytes immutably, and records
submission plus independent acceptance/rejection in an append-only hash chain.
Accepted samples can later be revoked without deleting audit evidence.
"""

from __future__ import annotations

import hashlib
import csv
import io
import json
import math
import os
import re
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from .provenance import sha256_digest
from .provider_rehearsal import (
    SYNTHETIC_PROVENANCE_FORBIDDEN,
    ProviderRehearsalError,
    forbid_synthetic_provenance,
)
from .provider_authorization import (
    PROVIDER_AUTHORIZATION_GRANT_V2_SCHEMA,
    ProviderAuthorizationError,
    ProviderAutomationAuthorizationRegistry,
)
from .provider_wire_capture import (
    PROVIDER_WIRE_CAPTURE_MEDIA_TYPE,
    ProviderWireCaptureError,
    load_provider_wire_capture,
)
from .strict_contract_json import (
    StrictContractJSONError,
    strict_json_file_object,
    strict_json_loads,
)


PROVIDER_SAMPLE_CREDENTIAL_SCAN_SCHEMA = (
    "quant-platform/provider-sample-credential-scan/v1"
)
PROVIDER_SAMPLE_MANIFEST_SCHEMA = "quant-platform/provider-sample-manifest/v1"
PROVIDER_SAMPLE_REVIEW_RECEIPT_SCHEMA = (
    "quant-platform/provider-sample-review-receipt/v1"
)
PROVIDER_SAMPLE_INTAKE_RECORD_SCHEMA = (
    "quant-platform/provider-sample-intake-record/v1"
)
PROVIDER_SAMPLE_INTAKE_HEAD_SCHEMA = "quant-platform/provider-sample-intake-head/v1"
PROVIDER_SAMPLE_INTAKE_INSPECTION_SCHEMA = (
    "quant-platform/provider-sample-intake-inspection/v1"
)
PROVIDER_SAMPLE_SCANNER_VERSION = "high-confidence-text-v1"
PROVIDER_SAMPLE_MAX_BYTES = 64 * 1024 * 1024
PROVIDER_SAMPLE_ALLOWED_MEDIA_TYPES = {
    "application/json",
    "text/csv",
    PROVIDER_WIRE_CAPTURE_MEDIA_TYPE,
}
PROVIDER_SAMPLE_REQUIRED_ACCEPTANCE_CHECKS = {
    "artifact_hash_verified",
    "authorization_scope_reverified",
    "credential_scan_passed",
    "endpoint_identity_confirmed",
    "format_opened_offline",
    "retention_scope_confirmed",
}

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
_HIGH_CONFIDENCE_SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b(?:authorization|proxy-authorization|x-api-key|api[_-]?key|"
        r"access[_-]?token|refresh[_-]?token|client[_-]?secret|password|cookie)"
        r"\s*[:=]\s*[\"']?[^\s\"',;}]{8,}"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
)


class ProviderSampleIntakeError(RuntimeError):
    """Raised when a provider sample or its review history is unsafe."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str = "PROVIDER_SAMPLE_INTAKE_DEGRADED",
    ) -> None:
        self.error_code = error_code
        super().__init__(message)


class ProviderSampleIntakeConflict(ProviderSampleIntakeError):
    """Raised when immutable sample/review identity is reused inconsistently."""


def _forbid_synthetic(value: Any) -> None:
    try:
        forbid_synthetic_provenance(value)
    except ProviderRehearsalError as exc:
        raise ProviderSampleIntakeError(
            SYNTHETIC_PROVENANCE_FORBIDDEN,
            error_code=SYNTHETIC_PROVENANCE_FORBIDDEN,
        ) from exc


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _ID_RE.fullmatch(text):
        raise ProviderSampleIntakeError(f"{label} is invalid")
    return text


def _text(value: Any, label: str, *, maximum: int = 500) -> str:
    text = str(value or "").strip()
    if not text or len(text) > maximum:
        raise ProviderSampleIntakeError(f"{label} is invalid")
    return text


def _hash(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA_RE.fullmatch(text):
        raise ProviderSampleIntakeError(f"{label} must be a sha256 digest")
    return text


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError) as exc:
            raise ProviderSampleIntakeError(
                f"{label} must be an ISO timestamp"
            ) from exc
    if parsed.tzinfo is None:
        raise ProviderSampleIntakeError(f"{label} must include a timezone")
    canonical = parsed.isoformat()
    if not isinstance(value, datetime) and canonical != str(value):
        raise ProviderSampleIntakeError(f"{label} is not canonical ISO format")
    return canonical, parsed


def _relative_path(root: Path, value: Any, label: str) -> tuple[str, Path]:
    text = str(value or "").strip().replace("\\", "/")
    if not text or Path(text).is_absolute():
        raise ProviderSampleIntakeError(f"{label} must be a relative platform path")
    path = (root / text).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ProviderSampleIntakeError(f"{label} escapes platform root") from exc
    return text, path


def _validate_json_value(value: Any, path: str = "$") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ProviderSampleIntakeError(
            f"provider sample contains non-finite number at {path}"
        )
    if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ProviderSampleIntakeError(
            f"provider sample contains unpaired Unicode surrogate at {path}"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_json_value(key, f"{path}.<key>")
            _validate_json_value(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")


def _scan_text(text: str) -> None:
    for pattern in _HIGH_CONFIDENCE_SECRET_PATTERNS:
        if pattern.search(text):
            raise ProviderSampleIntakeError(
                "provider sample credential scan found a high-confidence secret"
            )


def scan_provider_sample_credentials(
    content: bytes,
    *,
    media_type: str,
) -> dict[str, Any]:
    """Validate safe offline formats and reject high-confidence credentials."""

    if not isinstance(content, bytes) or not 1 <= len(content) <= PROVIDER_SAMPLE_MAX_BYTES:
        raise ProviderSampleIntakeError("provider sample byte size is invalid")
    media = str(media_type or "").strip().lower()
    if media not in PROVIDER_SAMPLE_ALLOWED_MEDIA_TYPES:
        raise ProviderSampleIntakeError("provider sample media type is not allowed")
    scanned_segments: list[str] = []
    if media == PROVIDER_WIRE_CAPTURE_MEDIA_TYPE:
        try:
            capture = load_provider_wire_capture(content)
        except ProviderWireCaptureError as exc:
            raise ProviderSampleIntakeError(str(exc)) from exc
        scanned_segments.append(content.decode("utf-8", errors="strict"))
        for exchange in capture["exchanges"]:
            body = exchange["response"]["body_bytes"]
            try:
                scanned_segments.append(body.decode("utf-8", errors="strict"))
            except UnicodeDecodeError as exc:
                raise ProviderSampleIntakeError(
                    "provider wire sample contains a response body that cannot be credential-scanned as UTF-8"
                ) from exc
    else:
        try:
            text = content.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ProviderSampleIntakeError(
                "provider sample text is not strict UTF-8"
            ) from exc
        if "\x00" in text:
            raise ProviderSampleIntakeError("provider sample text contains NUL bytes")
        if media == "application/json":
            try:
                payload = strict_json_loads(text)
            except StrictContractJSONError as exc:
                raise ProviderSampleIntakeError(
                    f"provider sample JSON is invalid: {exc}"
                ) from exc
            _validate_json_value(payload)
        elif media == "text/csv":
            try:
                rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
            except csv.Error as exc:
                raise ProviderSampleIntakeError(
                    f"provider sample CSV is invalid: {exc}"
                ) from exc
            if not rows or not rows[0] or any(not column.strip() for column in rows[0]):
                raise ProviderSampleIntakeError(
                    "provider sample CSV header is empty or invalid"
                )
            if len(rows[0]) != len(set(rows[0])):
                raise ProviderSampleIntakeError(
                    "provider sample CSV header contains duplicate columns"
                )
            if any(len(row) != len(rows[0]) for row in rows[1:]):
                raise ProviderSampleIntakeError(
                    "provider sample CSV rows have inconsistent column counts"
                )
        scanned_segments.append(text)
    for segment in scanned_segments:
        _scan_text(segment)
    identity = {
        "schema": PROVIDER_SAMPLE_CREDENTIAL_SCAN_SCHEMA,
        "scanner_version": PROVIDER_SAMPLE_SCANNER_VERSION,
        "status": "PASS",
        "finding_count": 0,
        "scanned_byte_size": len(content),
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
    }
    return {**identity, "scan_sha256": sha256_digest(identity)}


def validate_provider_sample_credential_scan(
    value: Mapping[str, Any],
    content: bytes,
    *,
    media_type: str,
) -> dict[str, Any]:
    _forbid_synthetic(value)
    scan = dict(value)
    expected = scan_provider_sample_credentials(content, media_type=media_type)
    required = {
        "schema",
        "scanner_version",
        "status",
        "finding_count",
        "scanned_byte_size",
        "artifact_sha256",
        "scan_sha256",
    }
    if set(scan) != required or scan != expected:
        raise ProviderSampleIntakeError(
            "provider sample credential scan hash or canonical form mismatch"
        )
    return expected


def build_provider_sample_manifest(
    content: bytes,
    *,
    source_id: str,
    source_version: str,
    endpoint_id: str,
    authority: str,
    data_kind: str,
    usage: str,
    authorization_registry_path: str,
    authorization_grant_sha256: str,
    media_type: str,
    original_filename: str,
    provider_revision_id: str,
    observed_at: datetime,
    received_at: datetime,
    submitted_by: str,
    limitations: Sequence[str],
) -> dict[str, Any]:
    filename = str(original_filename or "").strip()
    if (
        not _SAFE_FILENAME_RE.fullmatch(filename)
        or Path(filename).name != filename
        or filename in {".", ".."}
    ):
        raise ProviderSampleIntakeError("provider sample original_filename is unsafe")
    observed_text, observed = _timestamp(observed_at, "observed_at")
    received_text, received = _timestamp(received_at, "received_at")
    if observed > received:
        raise ProviderSampleIntakeError("provider sample observed_at is after received_at")
    normalized_limitations = [
        _text(value, "sample limitation") for value in limitations
    ]
    if not normalized_limitations:
        raise ProviderSampleIntakeError("provider sample limitations are required")
    media = str(media_type or "").strip().lower()
    scan = scan_provider_sample_credentials(content, media_type=media)
    identity = {
        "schema": PROVIDER_SAMPLE_MANIFEST_SCHEMA,
        "purpose": "adapter_certification",
        "source_id": _identifier(source_id, "source_id"),
        "source_version": _text(source_version, "source_version", maximum=80),
        "endpoint_id": _identifier(endpoint_id, "endpoint_id"),
        "authority": _identifier(authority, "authority"),
        "data_kind": _identifier(data_kind, "data_kind"),
        "usage": _identifier(usage, "usage"),
        "authorization_registry_path": str(authorization_registry_path).replace(
            "\\", "/"
        ),
        "authorization_grant_sha256": _hash(
            authorization_grant_sha256, "authorization_grant_sha256"
        ),
        "media_type": media,
        "original_filename": filename,
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "byte_size": len(content),
        "provider_revision_id": _text(
            provider_revision_id, "provider_revision_id", maximum=160
        ),
        "observed_at": observed_text,
        "received_at": received_text,
        "submitted_by": _text(submitted_by, "submitted_by", maximum=256),
        "credential_scan": scan,
        "limitations": normalized_limitations,
        "real_orders": False,
    }
    return {**identity, "manifest_sha256": sha256_digest(identity)}


def validate_provider_sample_manifest(
    value: Mapping[str, Any],
    content: bytes,
) -> dict[str, Any]:
    _forbid_synthetic(value)
    manifest = dict(value)
    required = {
        "schema",
        "purpose",
        "source_id",
        "source_version",
        "endpoint_id",
        "authority",
        "data_kind",
        "usage",
        "authorization_registry_path",
        "authorization_grant_sha256",
        "media_type",
        "original_filename",
        "artifact_sha256",
        "byte_size",
        "provider_revision_id",
        "observed_at",
        "received_at",
        "submitted_by",
        "credential_scan",
        "limitations",
        "real_orders",
        "manifest_sha256",
    }
    if (
        set(manifest) != required
        or manifest.get("schema") != PROVIDER_SAMPLE_MANIFEST_SCHEMA
        or manifest.get("purpose") != "adapter_certification"
        or manifest.get("real_orders") is not False
    ):
        raise ProviderSampleIntakeError("provider sample manifest fields are invalid")
    filename = str(manifest.get("original_filename") or "")
    if not _SAFE_FILENAME_RE.fullmatch(filename) or Path(filename).name != filename:
        raise ProviderSampleIntakeError("provider sample original_filename is unsafe")
    observed_text, observed = _timestamp(manifest.get("observed_at"), "observed_at")
    received_text, received = _timestamp(manifest.get("received_at"), "received_at")
    if observed > received:
        raise ProviderSampleIntakeError("provider sample observed_at is after received_at")
    artifact_sha = _hash(manifest.get("artifact_sha256"), "artifact_sha256")
    byte_size = manifest.get("byte_size")
    if (
        isinstance(byte_size, bool)
        or not isinstance(byte_size, int)
        or byte_size != len(content)
        or artifact_sha != hashlib.sha256(content).hexdigest()
    ):
        raise ProviderSampleIntakeError("provider sample artifact identity mismatch")
    media = str(manifest.get("media_type") or "").strip().lower()
    scan = validate_provider_sample_credential_scan(
        dict(manifest.get("credential_scan") or {}), content, media_type=media
    )
    limitations = [
        _text(value, "sample limitation")
        for value in list(manifest.get("limitations") or [])
    ]
    if not limitations:
        raise ProviderSampleIntakeError("provider sample limitations are required")
    identity = {
        "schema": PROVIDER_SAMPLE_MANIFEST_SCHEMA,
        "purpose": "adapter_certification",
        "source_id": _identifier(manifest.get("source_id"), "source_id"),
        "source_version": _text(
            manifest.get("source_version"), "source_version", maximum=80
        ),
        "endpoint_id": _identifier(manifest.get("endpoint_id"), "endpoint_id"),
        "authority": _identifier(manifest.get("authority"), "authority"),
        "data_kind": _identifier(manifest.get("data_kind"), "data_kind"),
        "usage": _identifier(manifest.get("usage"), "usage"),
        "authorization_registry_path": str(
            manifest.get("authorization_registry_path") or ""
        ).replace("\\", "/"),
        "authorization_grant_sha256": _hash(
            manifest.get("authorization_grant_sha256"),
            "authorization_grant_sha256",
        ),
        "media_type": media,
        "original_filename": filename,
        "artifact_sha256": artifact_sha,
        "byte_size": byte_size,
        "provider_revision_id": _text(
            manifest.get("provider_revision_id"),
            "provider_revision_id",
            maximum=160,
        ),
        "observed_at": observed_text,
        "received_at": received_text,
        "submitted_by": _text(
            manifest.get("submitted_by"), "submitted_by", maximum=256
        ),
        "credential_scan": scan,
        "limitations": limitations,
        "real_orders": False,
    }
    normalized = {**identity, "manifest_sha256": sha256_digest(identity)}
    if normalized != manifest or _hash(
        manifest.get("manifest_sha256"), "manifest_sha256"
    ) != normalized["manifest_sha256"]:
        raise ProviderSampleIntakeError(
            "provider sample manifest hash or canonical form mismatch"
        )
    return normalized


def build_provider_sample_review_receipt(
    manifest: Mapping[str, Any],
    *,
    decision: str,
    reviewed_at: datetime,
    reviewed_by: str,
    review_reference: str,
    checks: Mapping[str, bool],
    review_notes: Sequence[str],
) -> dict[str, Any]:
    _forbid_synthetic(manifest)
    _forbid_synthetic(checks)
    normalized_decision = str(decision or "").strip().upper()
    if normalized_decision not in {"ACCEPT", "REJECT"}:
        raise ProviderSampleIntakeError("provider sample review decision is invalid")
    normalized_checks = dict(checks)
    if set(normalized_checks) != PROVIDER_SAMPLE_REQUIRED_ACCEPTANCE_CHECKS or any(
        not isinstance(value, bool) for value in normalized_checks.values()
    ):
        raise ProviderSampleIntakeError("provider sample review checks are invalid")
    if normalized_decision == "ACCEPT" and any(
        value is not True for value in normalized_checks.values()
    ):
        raise ProviderSampleIntakeError(
            "accepted provider sample has an incomplete review"
        )
    reviewer = _text(reviewed_by, "reviewed_by", maximum=256)
    if reviewer.casefold() == str(manifest.get("submitted_by") or "").casefold():
        raise ProviderSampleIntakeError(
            "provider sample submitter cannot approve or reject their own sample"
        )
    reviewed_text, reviewed = _timestamp(reviewed_at, "reviewed_at")
    _, received = _timestamp(manifest.get("received_at"), "received_at")
    if reviewed < received:
        raise ProviderSampleIntakeError("provider sample reviewed before receipt")
    notes = [_text(value, "review note") for value in review_notes]
    if not notes:
        raise ProviderSampleIntakeError("provider sample review notes are required")
    identity = {
        "schema": PROVIDER_SAMPLE_REVIEW_RECEIPT_SCHEMA,
        "manifest_sha256": _hash(
            manifest.get("manifest_sha256"), "manifest_sha256"
        ),
        "artifact_sha256": _hash(
            manifest.get("artifact_sha256"), "artifact_sha256"
        ),
        "source_id": _identifier(manifest.get("source_id"), "source_id"),
        "source_version": _text(
            manifest.get("source_version"), "source_version", maximum=80
        ),
        "endpoint_id": _identifier(manifest.get("endpoint_id"), "endpoint_id"),
        "authorization_grant_sha256": _hash(
            manifest.get("authorization_grant_sha256"),
            "authorization_grant_sha256",
        ),
        "decision": normalized_decision,
        "reviewed_at": reviewed_text,
        "reviewed_by": reviewer,
        "review_reference": _text(
            review_reference, "review_reference", maximum=256
        ),
        "checks": {key: normalized_checks[key] for key in sorted(normalized_checks)},
        "review_notes": notes,
        "real_orders": False,
    }
    return {**identity, "receipt_sha256": sha256_digest(identity)}


def validate_provider_sample_review_receipt(
    value: Mapping[str, Any],
    manifest: Mapping[str, Any],
) -> dict[str, Any]:
    _forbid_synthetic(value)
    _forbid_synthetic(manifest)
    receipt = dict(value)
    required = {
        "schema",
        "manifest_sha256",
        "artifact_sha256",
        "source_id",
        "source_version",
        "endpoint_id",
        "authorization_grant_sha256",
        "decision",
        "reviewed_at",
        "reviewed_by",
        "review_reference",
        "checks",
        "review_notes",
        "real_orders",
        "receipt_sha256",
    }
    if set(receipt) != required or receipt.get(
        "schema"
    ) != PROVIDER_SAMPLE_REVIEW_RECEIPT_SCHEMA:
        raise ProviderSampleIntakeError(
            "provider sample review receipt fields are invalid"
        )
    rebuilt = build_provider_sample_review_receipt(
        manifest,
        decision=str(receipt.get("decision") or ""),
        reviewed_at=receipt.get("reviewed_at"),
        reviewed_by=str(receipt.get("reviewed_by") or ""),
        review_reference=str(receipt.get("review_reference") or ""),
        checks=dict(receipt.get("checks") or {}),
        review_notes=list(receipt.get("review_notes") or []),
    )
    if rebuilt != receipt or _hash(
        receipt.get("receipt_sha256"), "receipt_sha256"
    ) != rebuilt["receipt_sha256"]:
        raise ProviderSampleIntakeError(
            "provider sample review receipt hash or canonical form mismatch"
        )
    return rebuilt


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = strict_json_file_object(path)
    except (OSError, StrictContractJSONError) as exc:
        raise ProviderSampleIntakeError(
            f"provider sample intake JSON is unreadable: {path}: {exc}"
        ) from exc
    _forbid_synthetic(value)
    return value


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
            raise ProviderSampleIntakeConflict(
                f"immutable provider sample intake conflict: {path}"
            )
        return
    _atomic_json(path, payload)


def _immutable_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        if path.read_bytes() != content:
            raise ProviderSampleIntakeConflict(
                f"immutable provider sample artifact conflict: {path}"
            )
        return
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class ProviderSampleIntakeRegistry:
    """Append-only sample submission, review and revocation registry."""

    def __init__(self, root: str | Path, *, platform_root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.platform_root = Path(platform_root).expanduser().resolve()

    @property
    def head_path(self) -> Path:
        return self.root / "head.json"

    def _artifact_path(self, digest: str) -> Path:
        return self.root / "artifacts" / f"{digest}.bin"

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
            raise ProviderSampleIntakeError(
                "provider sample intake registry is locked"
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

    def _authorization(
        self,
        manifest: Mapping[str, Any],
        *,
        as_of: datetime,
    ) -> dict[str, Any]:
        registry_text, registry_path = _relative_path(
            self.platform_root,
            manifest.get("authorization_registry_path"),
            "authorization_registry_path",
        )
        if registry_text != manifest.get("authorization_registry_path"):
            raise ProviderSampleIntakeError(
                "provider sample authorization registry path is not canonical"
            )
        try:
            grant = ProviderAutomationAuthorizationRegistry(
                registry_path, platform_root=self.platform_root
            ).resolve(
                str(manifest.get("authorization_grant_sha256") or ""),
                as_of=as_of,
            )
        except ProviderAuthorizationError as exc:
            raise ProviderSampleIntakeError(
                f"provider sample authorization registry is invalid: {exc}"
            ) from exc
        if grant is None:
            raise ProviderSampleIntakeError(
                "provider sample authorization is missing, expired or revoked"
            )
        if grant.get("schema") == PROVIDER_AUTHORIZATION_GRANT_V2_SCHEMA:
            raise ProviderSampleIntakeError(
                "auxiliary runtime authorization cannot persist certification samples"
            )
        authorized = (
            grant.get("source_id") == manifest.get("source_id")
            and grant.get("source_version") == manifest.get("source_version")
            and manifest.get("endpoint_id") in grant.get("endpoint_ids", [])
            and manifest.get("authority") in grant.get("authorities", [])
            and manifest.get("data_kind") in grant.get("data_kinds", [])
            and manifest.get("usage") in grant.get("allowed_usages", [])
        )
        if not authorized:
            raise ProviderSampleIntakeError(
                "provider sample exceeds structured authorization scope"
            )
        return grant

    def _load_chain(self) -> list[dict[str, Any]]:
        paths = sorted((self.root / "records").glob("*.json"))
        if not self.head_path.is_file():
            if paths:
                raise ProviderSampleIntakeError(
                    "provider sample intake head is missing while records exist"
                )
            return []
        head = _read_json(self.head_path)
        if (
            set(head) != {"schema", "sequence", "record_sha256"}
            or head.get("schema") != PROVIDER_SAMPLE_INTAKE_HEAD_SCHEMA
            or not paths
        ):
            raise ProviderSampleIntakeError("provider sample intake head is invalid")
        required = {
            "schema",
            "sequence",
            "previous_record_sha256",
            "recorded_at",
            "action",
            "manifest_sha256",
            "receipt_sha256",
            "manifest",
            "review_receipt",
            "revocation_reference",
            "record_sha256",
        }
        records: list[dict[str, Any]] = []
        previous_sha: str | None = None
        previous_time: datetime | None = None
        submissions: dict[str, dict[str, Any]] = {}
        reviews: dict[str, dict[str, Any]] = {}
        accepted_receipts: dict[str, str] = {}
        revoked: set[str] = set()
        for sequence, path in enumerate(paths, start=1):
            record = _read_json(path)
            identity = {
                key: value for key, value in record.items() if key != "record_sha256"
            }
            digest = _hash(record.get("record_sha256"), "record_sha256")
            recorded_text, recorded_at = _timestamp(
                record.get("recorded_at"), "recorded_at"
            )
            manifest_sha = _hash(record.get("manifest_sha256"), "manifest_sha256")
            if (
                set(record) != required
                or record.get("schema") != PROVIDER_SAMPLE_INTAKE_RECORD_SCHEMA
                or record.get("sequence") != sequence
                or record.get("previous_record_sha256") != previous_sha
                or sha256_digest(identity) != digest
                or path.name != self._record_path(sequence, digest).name
                or record.get("recorded_at") != recorded_text
                or (previous_time is not None and recorded_at < previous_time)
            ):
                raise ProviderSampleIntakeError(
                    "provider sample intake record chain broke"
                )
            if record.get("action") == "SUBMIT":
                if (
                    manifest_sha in submissions
                    or record.get("receipt_sha256") is not None
                    or not isinstance(record.get("manifest"), dict)
                    or record.get("review_receipt") is not None
                    or record.get("revocation_reference") is not None
                ):
                    raise ProviderSampleIntakeError(
                        "provider sample submission record is invalid"
                    )
                artifact_sha = _hash(
                    record["manifest"].get("artifact_sha256"), "artifact_sha256"
                )
                artifact_path = self._artifact_path(artifact_sha)
                if not artifact_path.is_file():
                    raise ProviderSampleIntakeError(
                        "provider sample artifact is missing"
                    )
                manifest = validate_provider_sample_manifest(
                    record["manifest"], artifact_path.read_bytes()
                )
                _, received = _timestamp(manifest["received_at"], "received_at")
                if manifest["manifest_sha256"] != manifest_sha or recorded_at != received:
                    raise ProviderSampleIntakeError(
                        "provider sample submission is misbound"
                    )
                submissions[manifest_sha] = manifest
            elif record.get("action") in {"ACCEPT", "REJECT"}:
                if (
                    manifest_sha not in submissions
                    or manifest_sha in reviews
                    or record.get("manifest") is not None
                    or not isinstance(record.get("review_receipt"), dict)
                    or record.get("revocation_reference") is not None
                ):
                    raise ProviderSampleIntakeError(
                        "provider sample review record is invalid"
                    )
                receipt = validate_provider_sample_review_receipt(
                    record["review_receipt"], submissions[manifest_sha]
                )
                receipt_sha = _hash(record.get("receipt_sha256"), "receipt_sha256")
                _, reviewed = _timestamp(receipt["reviewed_at"], "reviewed_at")
                if (
                    receipt["receipt_sha256"] != receipt_sha
                    or receipt["decision"] != record["action"]
                    or recorded_at != reviewed
                ):
                    raise ProviderSampleIntakeError(
                        "provider sample review is misbound"
                    )
                reviews[manifest_sha] = receipt
                if record["action"] == "ACCEPT":
                    if receipt_sha in accepted_receipts:
                        raise ProviderSampleIntakeError(
                            "provider sample acceptance receipt is duplicated"
                        )
                    accepted_receipts[receipt_sha] = manifest_sha
            elif record.get("action") == "REVOKE":
                receipt_sha = _hash(record.get("receipt_sha256"), "receipt_sha256")
                if (
                    receipt_sha not in accepted_receipts
                    or receipt_sha in revoked
                    or accepted_receipts[receipt_sha] != manifest_sha
                    or record.get("manifest") is not None
                    or record.get("review_receipt") is not None
                ):
                    raise ProviderSampleIntakeError(
                        "provider sample revocation record is invalid"
                    )
                _text(record.get("revocation_reference"), "revocation_reference")
                revoked.add(receipt_sha)
            else:
                raise ProviderSampleIntakeError(
                    "provider sample intake action is invalid"
                )
            records.append(record)
            previous_sha = digest
            previous_time = recorded_at
        if (
            head.get("sequence") != len(records)
            or _hash(head.get("record_sha256"), "head record_sha256")
            != records[-1]["record_sha256"]
        ):
            raise ProviderSampleIntakeError(
                "provider sample intake head does not match chain"
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
                "schema": PROVIDER_SAMPLE_INTAKE_HEAD_SCHEMA,
                "sequence": sequence,
                "record_sha256": digest,
            },
        )
        self._load_chain()
        return record

    def submit(
        self,
        manifest: Mapping[str, Any],
        content: bytes,
    ) -> dict[str, Any]:
        normalized = validate_provider_sample_manifest(manifest, content)
        _, received = _timestamp(normalized["received_at"], "received_at")
        self._authorization(normalized, as_of=received)
        with self._lock():
            records = self._load_chain()
            existing = [
                item
                for item in records
                if item["action"] == "SUBMIT"
                and item["manifest_sha256"] == normalized["manifest_sha256"]
            ]
            if existing:
                if existing[0]["manifest"] != normalized:
                    raise ProviderSampleIntakeConflict(
                        "provider sample submission identity changed"
                    )
                return {**existing[0], "idempotent": True}
            if records and normalized["received_at"] < records[-1]["recorded_at"]:
                raise ProviderSampleIntakeError(
                    "provider sample submission time moved backwards"
                )
            _immutable_bytes(
                self._artifact_path(normalized["artifact_sha256"]), content
            )
            identity = {
                "schema": PROVIDER_SAMPLE_INTAKE_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": (
                    records[-1]["record_sha256"] if records else None
                ),
                "recorded_at": normalized["received_at"],
                "action": "SUBMIT",
                "manifest_sha256": normalized["manifest_sha256"],
                "receipt_sha256": None,
                "manifest": normalized,
                "review_receipt": None,
                "revocation_reference": None,
            }
            return {**self._append(identity), "idempotent": False}

    def review(
        self,
        manifest_sha256: str,
        *,
        decision: str,
        reviewed_at: datetime,
        reviewed_by: str,
        review_reference: str,
        checks: Mapping[str, bool],
        review_notes: Sequence[str],
    ) -> dict[str, Any]:
        manifest_sha = _hash(manifest_sha256, "manifest_sha256")
        with self._lock():
            records = self._load_chain()
            submissions = [
                item
                for item in records
                if item["action"] == "SUBMIT"
                and item["manifest_sha256"] == manifest_sha
            ]
            if not submissions:
                raise ProviderSampleIntakeError(
                    "cannot review an unknown provider sample"
                )
            manifest = dict(submissions[0]["manifest"])
            receipt = build_provider_sample_review_receipt(
                manifest,
                decision=decision,
                reviewed_at=reviewed_at,
                reviewed_by=reviewed_by,
                review_reference=review_reference,
                checks=checks,
                review_notes=review_notes,
            )
            existing = [
                item
                for item in records
                if item["action"] in {"ACCEPT", "REJECT"}
                and item["manifest_sha256"] == manifest_sha
            ]
            if existing:
                if existing[0]["review_receipt"] != receipt:
                    raise ProviderSampleIntakeConflict(
                        "provider sample review identity changed"
                    )
                return {**existing[0], "idempotent": True}
            if receipt["decision"] == "ACCEPT":
                _, reviewed = _timestamp(receipt["reviewed_at"], "reviewed_at")
                self._authorization(manifest, as_of=reviewed)
                artifact_path = self._artifact_path(manifest["artifact_sha256"])
                if not artifact_path.is_file():
                    raise ProviderSampleIntakeError(
                        "provider sample artifact is missing during review"
                    )
                validate_provider_sample_manifest(manifest, artifact_path.read_bytes())
            if records and receipt["reviewed_at"] < records[-1]["recorded_at"]:
                raise ProviderSampleIntakeError(
                    "provider sample review time moved backwards"
                )
            identity = {
                "schema": PROVIDER_SAMPLE_INTAKE_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": records[-1]["record_sha256"],
                "recorded_at": receipt["reviewed_at"],
                "action": receipt["decision"],
                "manifest_sha256": manifest_sha,
                "receipt_sha256": receipt["receipt_sha256"],
                "manifest": None,
                "review_receipt": receipt,
                "revocation_reference": None,
            }
            return {**self._append(identity), "idempotent": False}

    def revoke(
        self,
        receipt_sha256: str,
        *,
        revocation_reference: str,
        recorded_at: datetime,
    ) -> dict[str, Any]:
        receipt_sha = _hash(receipt_sha256, "receipt_sha256")
        reference = _text(revocation_reference, "revocation_reference")
        recorded_text, _ = _timestamp(recorded_at, "recorded_at")
        with self._lock():
            records = self._load_chain()
            acceptances = [
                item
                for item in records
                if item["action"] == "ACCEPT"
                and item["receipt_sha256"] == receipt_sha
            ]
            if not acceptances:
                raise ProviderSampleIntakeError(
                    "cannot revoke an unknown provider sample acceptance"
                )
            existing = [
                item
                for item in records
                if item["action"] == "REVOKE"
                and item["receipt_sha256"] == receipt_sha
            ]
            if existing:
                if existing[0]["revocation_reference"] != reference:
                    raise ProviderSampleIntakeConflict(
                        "provider sample revocation identity changed"
                    )
                return {**existing[0], "idempotent": True}
            if records and recorded_text < records[-1]["recorded_at"]:
                raise ProviderSampleIntakeError(
                    "provider sample revocation time moved backwards"
                )
            identity = {
                "schema": PROVIDER_SAMPLE_INTAKE_RECORD_SCHEMA,
                "sequence": len(records) + 1,
                "previous_record_sha256": records[-1]["record_sha256"],
                "recorded_at": recorded_text,
                "action": "REVOKE",
                "manifest_sha256": acceptances[0]["manifest_sha256"],
                "receipt_sha256": receipt_sha,
                "manifest": None,
                "review_receipt": None,
                "revocation_reference": reference,
            }
            return {**self._append(identity), "idempotent": False}

    def resolve_acceptance(self, receipt_sha256: str) -> dict[str, Any] | None:
        receipt_sha = _hash(receipt_sha256, "receipt_sha256")
        records = self._load_chain()
        if any(
            item["action"] == "REVOKE" and item["receipt_sha256"] == receipt_sha
            for item in records
        ):
            return None
        acceptances = [
            item
            for item in records
            if item["action"] == "ACCEPT"
            and item["receipt_sha256"] == receipt_sha
        ]
        if not acceptances:
            return None
        acceptance = acceptances[0]
        submissions = [
            item
            for item in records
            if item["action"] == "SUBMIT"
            and item["manifest_sha256"] == acceptance["manifest_sha256"]
        ]
        if len(submissions) != 1:
            raise ProviderSampleIntakeError(
                "provider sample acceptance lost its submission"
            )
        manifest = dict(submissions[0]["manifest"])
        artifact_path = self._artifact_path(manifest["artifact_sha256"])
        if not artifact_path.is_file():
            raise ProviderSampleIntakeError(
                "accepted provider sample artifact is missing"
            )
        validate_provider_sample_manifest(manifest, artifact_path.read_bytes())
        return {
            "receipt": dict(acceptance["review_receipt"]),
            "manifest": manifest,
            "artifact_path": str(artifact_path),
        }

    def inspect(self) -> dict[str, Any]:
        try:
            records = self._load_chain()
            submitted = {
                item["manifest_sha256"]
                for item in records
                if item["action"] == "SUBMIT"
            }
            accepted = {
                item["receipt_sha256"]
                for item in records
                if item["action"] == "ACCEPT"
            }
            rejected = {
                item["receipt_sha256"]
                for item in records
                if item["action"] == "REJECT"
            }
            revoked = {
                item["receipt_sha256"]
                for item in records
                if item["action"] == "REVOKE"
            }
            reviewed_manifests = {
                item["manifest_sha256"]
                for item in records
                if item["action"] in {"ACCEPT", "REJECT"}
            }
            return {
                "schema": PROVIDER_SAMPLE_INTAKE_INSPECTION_SCHEMA,
                "status": "EMPTY" if not records else "READY",
                "error": None,
                "error_code": None,
                "real_orders": False,
                "record_count": len(records),
                "submitted_sample_count": len(submitted),
                "pending_review_count": len(submitted - reviewed_manifests),
                "accepted_sample_count": len(accepted),
                "rejected_sample_count": len(rejected),
                "revoked_sample_count": len(revoked),
                "active_acceptance_count": len(accepted - revoked),
                "head_record_sha256": (
                    records[-1]["record_sha256"] if records else None
                ),
            }
        except ProviderSampleIntakeError as exc:
            return {
                "schema": PROVIDER_SAMPLE_INTAKE_INSPECTION_SCHEMA,
                "status": "DEGRADED",
                "error": str(exc),
                "error_code": exc.error_code,
                "real_orders": False,
                "record_count": 0,
                "submitted_sample_count": 0,
                "pending_review_count": 0,
                "accepted_sample_count": 0,
                "rejected_sample_count": 0,
                "revoked_sample_count": 0,
                "active_acceptance_count": 0,
                "head_record_sha256": None,
            }
