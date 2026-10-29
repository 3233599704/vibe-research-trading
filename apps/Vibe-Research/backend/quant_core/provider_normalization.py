"""Deterministic replay from archived provider bytes to catalog payloads."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from typing import Any

from .provider_endpoint_normalizers import (
    EASTMONEY_P1_QFQ_SIGNAL_NORMALIZER_ID,
    TENCENT_P1_QFQ_SIGNAL_NORMALIZER_ID,
    ProviderEndpointNormalizationError,
    replay_p1_qfq_signal_capture,
)
from .provenance import sha256_digest


PROVIDER_NORMALIZATION_SCHEMA = "quant-core/provider-normalization-attestation/v1"
CANONICAL_JSON_NORMALIZER_ID = "canonical-json-object/v1"
PROVIDER_ENDPOINT_NORMALIZER_IDS = frozenset(
    {
        TENCENT_P1_QFQ_SIGNAL_NORMALIZER_ID,
        EASTMONEY_P1_QFQ_SIGNAL_NORMALIZER_ID,
    }
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ATTESTATION_FIELDS = {
    "schema",
    "normalizer_id",
    "media_type",
    "raw_artifact_sha256",
    "supplied_payload_sha256",
    "replayed_payload_sha256",
    "status",
    "promotion_eligible",
    "attestation_sha256",
}


class ProviderNormalizationError(RuntimeError):
    """Archived bytes cannot deterministically reproduce the supplied payload."""


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ProviderNormalizationError(
                f"provider JSON contains a duplicate object key: {key}"
            )
        output[key] = value
    return output


def _validate_json_value(value: Any, path: str = "$") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ProviderNormalizationError(
            f"provider JSON contains a non-finite number at {path}"
        )
    if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ProviderNormalizationError(
            f"provider JSON contains an unpaired Unicode surrogate at {path}"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_json_value(key, f"{path}.<key>")
            _validate_json_value(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")


def _payload_digest(value: Mapping[str, Any], label: str) -> str:
    try:
        return sha256_digest(dict(value))
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ProviderNormalizationError(
            f"{label} is not canonical JSON: {exc}"
        ) from exc


def replay_provider_normalization(
    raw_bytes: bytes,
    *,
    media_type: str,
    normalizer_id: str,
) -> dict[str, Any]:
    """Replay a frozen normalizer without consulting network or mutable state."""

    if normalizer_id in PROVIDER_ENDPOINT_NORMALIZER_IDS:
        try:
            return replay_p1_qfq_signal_capture(
                raw_bytes,
                media_type=media_type,
                normalizer_id=normalizer_id,
            )
        except ProviderEndpointNormalizationError as exc:
            raise ProviderNormalizationError(str(exc)) from exc
    if normalizer_id != CANONICAL_JSON_NORMALIZER_ID:
        raise ProviderNormalizationError(
            f"unsupported provider normalizer: {normalizer_id}"
        )
    if media_type != "application/json":
        raise ProviderNormalizationError(
            "canonical JSON normalizer requires application/json"
        )
    try:
        text = raw_bytes.decode("utf-8", errors="strict")
        payload = json.loads(
            text,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ProviderNormalizationError(
                    f"provider JSON contains a non-finite number: {constant}"
                )
            ),
        )
    except UnicodeDecodeError as exc:
        raise ProviderNormalizationError(
            "provider JSON artifact is not strict UTF-8"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ProviderNormalizationError(
            f"provider JSON artifact is invalid: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ProviderNormalizationError(
            "canonical JSON provider artifact must decode to an object"
        )
    _validate_json_value(payload)
    return payload


def build_provider_normalization_attestation(
    raw_bytes: bytes,
    supplied_payload: Mapping[str, Any],
    *,
    media_type: str,
    normalizer_id: str,
) -> dict[str, Any]:
    replayed = replay_provider_normalization(
        raw_bytes,
        media_type=media_type,
        normalizer_id=normalizer_id,
    )
    supplied_sha = _payload_digest(supplied_payload, "supplied provider payload")
    replayed_sha = _payload_digest(replayed, "replayed provider payload")
    identity = {
        "schema": PROVIDER_NORMALIZATION_SCHEMA,
        "normalizer_id": normalizer_id,
        "media_type": media_type,
        "raw_artifact_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "supplied_payload_sha256": supplied_sha,
        "replayed_payload_sha256": replayed_sha,
        "status": "PASS" if supplied_sha == replayed_sha else "FAIL",
        "promotion_eligible": False,
    }
    return {**identity, "attestation_sha256": sha256_digest(identity)}


def verify_provider_normalization_attestation(
    attestation: Mapping[str, Any],
    raw_bytes: bytes,
    *,
    expected_payload_sha256: str | None = None,
) -> dict[str, Any]:
    candidate = dict(attestation)
    digest = str(candidate.pop("attestation_sha256", ""))
    errors: list[str] = []
    if set(attestation) != _ATTESTATION_FIELDS:
        errors.append("provider normalization attestation fields are invalid")
    if candidate.get("schema") != PROVIDER_NORMALIZATION_SCHEMA:
        errors.append("unsupported provider normalization schema")
    try:
        computed_digest = sha256_digest(candidate)
    except (TypeError, ValueError, UnicodeEncodeError):
        computed_digest = ""
    if not SHA256_RE.fullmatch(digest) or digest != computed_digest:
        errors.append("provider normalization attestation digest mismatch")
    if candidate.get("promotion_eligible") is not False:
        errors.append("normalization evidence cannot authorize promotion")
    try:
        replayed = replay_provider_normalization(
            raw_bytes,
            media_type=str(candidate.get("media_type") or ""),
            normalizer_id=str(candidate.get("normalizer_id") or ""),
        )
        raw_sha = hashlib.sha256(raw_bytes).hexdigest()
        replayed_sha = _payload_digest(replayed, "replayed provider payload")
        if candidate.get("raw_artifact_sha256") != raw_sha:
            errors.append("provider normalization raw artifact digest mismatch")
        if candidate.get("replayed_payload_sha256") != replayed_sha:
            errors.append("provider normalization replayed payload digest mismatch")
        if candidate.get("supplied_payload_sha256") != replayed_sha:
            errors.append("provider normalization supplied payload differs from replay")
        if expected_payload_sha256 is not None and replayed_sha != str(
            expected_payload_sha256
        ):
            errors.append("provider normalization differs from catalog payload")
    except ProviderNormalizationError as exc:
        errors.append(str(exc))
        replayed_sha = None
    if candidate.get("status") != "PASS":
        errors.append("provider normalization did not pass")
    return {
        "verified": not errors,
        "attestation_sha256": digest,
        "replayed_payload_sha256": replayed_sha,
        "errors": errors,
        "attestation": dict(attestation),
    }
