"""Independent attestation for replaying a complete registered backtest."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .provenance import sha256_digest


CANONICAL_REPLAY_SCHEMA = "quant-core/canonical-backtest-replay/v1"
CANONICAL_REPLAY_SCOPE = (
    "period",
    "metrics",
    "curve",
    "monthly_returns",
    "yearly_returns",
    "holdings",
    "trades",
    "latest_ranking",
    "execution",
    "factor_validation",
    "bias_audit",
    "sample_validation",
    "walk_forward",
    "parameter_scan",
    "parameter_robustness",
    "research_statistics",
    "robustness_validation",
)


class CanonicalReplayError(RuntimeError):
    """A full-engine replay is unsupported, incomplete or mismatched."""


def build_canonical_replay_attestation(
    artifact: Mapping[str, Any],
    replayed: Mapping[str, Any],
    *,
    engine: Mapping[str, Any],
    catalog_payload_sha256: str,
    scope: Sequence[str] = CANONICAL_REPLAY_SCOPE,
) -> dict[str, Any]:
    fields = tuple(str(item) for item in scope)
    if not fields or len(fields) != len(set(fields)):
        raise CanonicalReplayError("canonical replay scope must be unique and non-empty")
    if any(field not in artifact or field not in replayed for field in fields):
        raise CanonicalReplayError("canonical replay scope is incomplete")
    artifact_scope = {field: artifact[field] for field in fields}
    replay_scope = {field: replayed[field] for field in fields}
    mismatches = [
        field
        for field in fields
        if sha256_digest(artifact_scope[field]) != sha256_digest(replay_scope[field])
    ]
    identity = {
        "schema": CANONICAL_REPLAY_SCHEMA,
        "engine": dict(engine),
        "catalog_payload_sha256": str(catalog_payload_sha256),
        "scope": list(fields),
        "scope_sha256": sha256_digest(list(fields)),
        "artifact_scope_sha256": sha256_digest(artifact_scope),
        "replayed_scope_sha256": sha256_digest(replay_scope),
        "mismatches": mismatches,
        "status": "PASS" if not mismatches else "FAIL",
    }
    return {**identity, "attestation_sha256": sha256_digest(identity)}


def verify_canonical_replay_attestation(
    attestation: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = dict(attestation)
    digest = str(candidate.pop("attestation_sha256", ""))
    errors: list[str] = []
    if candidate.get("schema") != CANONICAL_REPLAY_SCHEMA:
        errors.append("unsupported canonical replay schema")
    if digest != sha256_digest(candidate):
        errors.append("canonical replay digest mismatch")
    if candidate.get("scope") != list(CANONICAL_REPLAY_SCOPE):
        errors.append("canonical replay scope was changed")
    if candidate.get("scope_sha256") != sha256_digest(list(CANONICAL_REPLAY_SCOPE)):
        errors.append("canonical replay scope digest mismatch")
    if candidate.get("status") != "PASS" or candidate.get("mismatches") != []:
        errors.append("canonical replay did not reproduce the archived artifact")
    if candidate.get("artifact_scope_sha256") != candidate.get(
        "replayed_scope_sha256"
    ):
        errors.append("canonical replay output digest differs from artifact")
    return {
        "verified": not errors,
        "attestation_sha256": digest,
        "errors": errors,
        "attestation": dict(attestation),
    }
