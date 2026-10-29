"""Machine-verifiable evidence for a completed registered research run.

The experiment ledger must not trust a caller-supplied result hash.  This module
opens the actual run artifact and proves that its data, configuration, code and
execution semantics match the preregistration and the reserved attempt.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .factor_validation import (
    FACTOR_VALIDATION_ATTESTATION_SCHEMA,
    verify_factor_validation_attestation,
)
from .research_statistics import (
    HAC_TEST_ID,
    RESEARCH_STATISTICS_SCHEMA,
    verify_research_statistics,
)
from .canonical_replay import (
    CANONICAL_REPLAY_SCHEMA,
    verify_canonical_replay_attestation,
)
from .research_robustness import (
    RESEARCH_ROBUSTNESS_SCHEMA,
    verify_research_robustness_attestation,
)
from .provenance import RUN_MANIFEST_SCHEMA, canonical_json, sha256_digest


RESEARCH_RUN_EVIDENCE_SCHEMA = "quant-core/research-run-evidence/v3"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
OUTPUT_HASH_SCOPE = (
    "scientific payload excluding id, created_at, manifest and integrity hashes"
)


class ResearchRunEvidenceError(RuntimeError):
    """A run artifact cannot prove the registered experiment identity."""


def _sha(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not SHA256_RE.fullmatch(text):
        raise ResearchRunEvidenceError(f"{label} must be a lowercase sha256")
    return text


def _mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ResearchRunEvidenceError(f"{label} must be an object")
    return dict(value)


def _same(left: Any, right: Any, label: str) -> None:
    if sha256_digest(left) != sha256_digest(right):
        raise ResearchRunEvidenceError(f"{label} does not match the frozen registration")


def load_research_run_artifact(path: str | Path) -> dict[str, Any]:
    target = Path(path).expanduser().resolve()
    try:
        payload = json.loads(
            target.read_text(encoding="utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {constant}")
            ),
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ResearchRunEvidenceError(f"research run artifact unreadable: {target}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ResearchRunEvidenceError("research run artifact must be an object")
    return payload


def canonical_research_run_artifact_bytes(artifact: Mapping[str, Any]) -> bytes:
    return (canonical_json(dict(artifact)) + "\n").encode("utf-8")


def _scientific_output(artifact: Mapping[str, Any]) -> dict[str, Any]:
    output = {
        key: value
        for key, value in artifact.items()
        if key not in {"id", "created_at", "manifest"}
    }
    integrity = output.get("integrity")
    if isinstance(integrity, Mapping):
        output["integrity"] = {
            key: value
            for key, value in integrity.items()
            if key not in {"run_fingerprint", "output_sha256"}
        }
    return output


def inspect_research_run_artifact(
    artifact: Mapping[str, Any],
    *,
    parameter_names: Sequence[str],
) -> dict[str, Any]:
    """Validate a v2 run manifest and return preregistration binding values."""

    candidate = dict(artifact)
    manifest = _mapping(candidate.get("manifest"), "artifact.manifest")
    config = _mapping(candidate.get("config"), "artifact.config")
    data = _mapping(candidate.get("data"), "artifact.data")
    integrity = _mapping(candidate.get("integrity"), "artifact.integrity")
    factor_validation = _mapping(
        candidate.get("factor_validation"), "artifact.factor_validation"
    )
    research_statistics = _mapping(
        candidate.get("research_statistics"), "artifact.research_statistics"
    )
    robustness_validation = _mapping(
        candidate.get("robustness_validation"), "artifact.robustness_validation"
    )
    sample_validation = _mapping(
        candidate.get("sample_validation"), "artifact.sample_validation"
    )
    out_of_sample = _mapping(
        sample_validation.get("out_of_sample"),
        "artifact.sample_validation.out_of_sample",
    )
    statistics_curve = list(out_of_sample.get("curve") or [])
    snapshot = _mapping(data.get("snapshot"), "artifact.data.snapshot")
    catalog_as_of = _mapping(data.get("catalog_as_of"), "artifact.data.catalog_as_of")
    manifest_dataset = _mapping(manifest.get("dataset"), "artifact.manifest.dataset")
    manifest_code = _mapping(manifest.get("code"), "artifact.manifest.code")
    execution_semantics = _mapping(
        manifest.get("execution_semantics"), "artifact.manifest.execution_semantics"
    )
    engine = _mapping(manifest.get("engine"), "artifact.manifest.engine")

    if manifest.get("schema") != RUN_MANIFEST_SCHEMA:
        raise ResearchRunEvidenceError("completed run requires quant-core/run-manifest/v2")
    if manifest.get("output_hash_scope") != OUTPUT_HASH_SCOPE:
        raise ResearchRunEvidenceError("run manifest output hash scope changed")
    if not str(engine.get("name") or "").strip() or not str(engine.get("version") or "").strip():
        raise ResearchRunEvidenceError("run manifest engine name and version are required")

    config_sha = _sha(manifest.get("config_sha256"), "manifest.config_sha256")
    if config_sha != sha256_digest(config):
        raise ResearchRunEvidenceError("run artifact config digest mismatch")

    snapshot_sha = _sha(snapshot.get("content_sha256"), "data.snapshot.content_sha256")
    snapshot_identity = {
        key: value for key, value in snapshot.items() if key != "content_sha256"
    }
    if snapshot_sha != sha256_digest(snapshot_identity):
        raise ResearchRunEvidenceError("dataset snapshot digest mismatch")
    if manifest_dataset != snapshot:
        raise ResearchRunEvidenceError("run manifest dataset differs from artifact dataset")
    if _sha(manifest.get("dataset_sha256"), "manifest.dataset_sha256") != snapshot_sha:
        raise ResearchRunEvidenceError("run manifest dataset digest mismatch")

    code_sha = _sha(manifest.get("code_sha256"), "manifest.code_sha256")
    code_identity = {key: value for key, value in manifest_code.items() if key != "content_sha256"}
    if _sha(manifest_code.get("content_sha256"), "manifest.code.content_sha256") != sha256_digest(
        code_identity
    ):
        raise ResearchRunEvidenceError("code snapshot digest mismatch")
    if code_sha != manifest_code["content_sha256"]:
        raise ResearchRunEvidenceError("run manifest code digest mismatch")

    as_of_sha = _sha(catalog_as_of.get("as_of_sha256"), "catalog_as_of.as_of_sha256")
    as_of_identity = {
        key: value for key, value in catalog_as_of.items() if key != "as_of_sha256"
    }
    if as_of_sha != sha256_digest(as_of_identity):
        raise ResearchRunEvidenceError("catalog as-of digest mismatch")
    if manifest.get("catalog_as_of") != catalog_as_of:
        raise ResearchRunEvidenceError("run manifest catalog as-of evidence differs from artifact")
    if _sha(manifest.get("catalog_as_of_sha256"), "manifest.catalog_as_of_sha256") != as_of_sha:
        raise ResearchRunEvidenceError("run manifest catalog as-of digest mismatch")

    manifest_identity = {
        "schema": manifest["schema"],
        "engine": engine,
        "config_sha256": config_sha,
        "dataset_sha256": snapshot_sha,
        "code_sha256": code_sha,
        "execution_semantics": execution_semantics,
        "catalog_as_of_sha256": as_of_sha,
    }
    run_fingerprint = _sha(manifest.get("run_fingerprint"), "manifest.run_fingerprint")
    if run_fingerprint != sha256_digest(manifest_identity):
        raise ResearchRunEvidenceError("run fingerprint does not match manifest identity")
    if str(candidate.get("id") or "") != run_fingerprint[:16]:
        raise ResearchRunEvidenceError("run artifact id does not match its fingerprint")

    result_sha = _sha(manifest.get("output_sha256"), "manifest.output_sha256")
    if result_sha != sha256_digest(_scientific_output(candidate)):
        raise ResearchRunEvidenceError("scientific result digest mismatch")
    if integrity.get("run_fingerprint") != run_fingerprint:
        raise ResearchRunEvidenceError("integrity run fingerprint mismatch")
    if integrity.get("output_sha256") != result_sha:
        raise ResearchRunEvidenceError("integrity output digest mismatch")
    factor_verification = verify_factor_validation_attestation(
        factor_validation, require_reproduction=True
    )
    if not factor_verification["verified"]:
        raise ResearchRunEvidenceError(
            "factor validation attestation failed: "
            + "; ".join(str(item) for item in factor_verification["errors"])
        )
    if factor_validation.get("schema") != FACTOR_VALIDATION_ATTESTATION_SCHEMA:
        raise ResearchRunEvidenceError("unsupported factor validation attestation")
    if integrity.get("factor_fixture_passed") is not True:
        raise ResearchRunEvidenceError("artifact integrity does not confirm factor fixture")
    statistics_verification = verify_research_statistics(
        research_statistics, statistics_curve
    )
    if not statistics_verification["verified"]:
        raise ResearchRunEvidenceError(
            "research statistics attestation failed: "
            + "; ".join(str(item) for item in statistics_verification["errors"])
        )
    if research_statistics.get("schema") != RESEARCH_STATISTICS_SCHEMA:
        raise ResearchRunEvidenceError("unsupported research statistics attestation")
    if research_statistics.get("test_id") != HAC_TEST_ID:
        raise ResearchRunEvidenceError("unsupported research statistics test")
    if research_statistics.get("status") != "PASS":
        raise ResearchRunEvidenceError("research statistics evidence did not pass")
    if integrity.get("research_statistics_passed") is not True:
        raise ResearchRunEvidenceError(
            "artifact integrity does not confirm research statistics"
        )
    robustness_verification = verify_research_robustness_attestation(
        robustness_validation
    )
    if not robustness_verification["verified"]:
        raise ResearchRunEvidenceError(
            "research robustness attestation failed: "
            + "; ".join(
                str(item) for item in robustness_verification["errors"]
            )
        )
    if robustness_validation.get("schema") != RESEARCH_ROBUSTNESS_SCHEMA:
        raise ResearchRunEvidenceError("unsupported research robustness attestation")
    if integrity.get("research_robustness_passed") is not True:
        raise ResearchRunEvidenceError(
            "artifact integrity does not confirm research robustness"
        )

    names = [str(item) for item in parameter_names]
    if not names or len(names) != len(set(names)):
        raise ResearchRunEvidenceError("registered parameter names must be unique and non-empty")
    if any(name not in config for name in names):
        raise ResearchRunEvidenceError("run config is missing a registered parameter")
    parameters = {name: config[name] for name in names}
    fixed_config = {key: value for key, value in config.items() if key not in set(names)}
    provider_receipt = data.get("provider_publication_receipt_sha256")
    if provider_receipt is not None:
        provider_receipt = _sha(
            provider_receipt, "data.provider_publication_receipt_sha256"
        )

    return {
        "run_fingerprint": run_fingerprint,
        "result_sha256": result_sha,
        "artifact_sha256": sha256_digest(candidate),
        "config_sha256": config_sha,
        "fixed_config_sha256": sha256_digest(fixed_config),
        "parameters": parameters,
        "parameters_sha256": sha256_digest(parameters),
        "dataset_manifest_sha256": _sha(
            catalog_as_of.get("selected_manifest_sha256"),
            "catalog_as_of.selected_manifest_sha256",
        ),
        "dataset_snapshot_sha256": snapshot_sha,
        "catalog_as_of_sha256": as_of_sha,
        "provider_publication_receipt_sha256": provider_receipt,
        "code_sha256": code_sha,
        "execution_semantics_sha256": sha256_digest(execution_semantics),
        "engine": engine,
        "factor_id": str(factor_validation.get("factor_id") or ""),
        "factor_validation_attestation_sha256": _sha(
            factor_validation.get("attestation_sha256"),
            "factor_validation.attestation_sha256",
        ),
        "factor_lookback_sessions": int(factor_validation.get("lookback_sessions") or 0),
        "statistics_attestation_sha256": _sha(
            research_statistics.get("attestation_sha256"),
            "research_statistics.attestation_sha256",
        ),
        "statistical_test_id": str(research_statistics.get("test_id") or ""),
        "statistical_sample_scope": str(
            research_statistics.get("sample_scope") or ""
        ),
        "statistical_observation_count": int(
            research_statistics.get("observation_count") or 0
        ),
        "raw_one_sided_p_value": float(
            research_statistics.get("one_sided_p_value")
        ),
        "statistics_minimum_observations": int(
            research_statistics.get("minimum_observations") or 0
        ),
        "statistics_maximum_hac_lags": int(
            research_statistics.get("maximum_hac_lags") or 0
        ),
        "robustness_attestation_sha256": _sha(
            robustness_validation.get("attestation_sha256"),
            "robustness_validation.attestation_sha256",
        ),
    }


def build_research_run_evidence(
    artifact: Mapping[str, Any],
    *,
    run_id: str,
    registration: Mapping[str, Any],
    attempt: Mapping[str, Any],
    artifact_uri: str,
    provider_publication_verified: bool,
    canonical_replay_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    parameter_space = _mapping(registration.get("parameter_space"), "parameter_space")
    bindings = inspect_research_run_artifact(
        artifact, parameter_names=sorted(parameter_space)
    )
    reserved_parameters = _mapping(attempt.get("parameters"), "reserved parameters")
    _same(bindings["parameters"], reserved_parameters, "run parameters")
    if bindings["parameters_sha256"] != _sha(
        attempt.get("parameters_sha256"), "reserved parameters_sha256"
    ):
        raise ResearchRunEvidenceError("reserved parameter digest mismatch")
    for key in (
        "dataset_snapshot_sha256",
        "dataset_manifest_sha256",
        "catalog_as_of_sha256",
        "code_sha256",
    ):
        if bindings[key] != _sha(registration.get(key), key):
            raise ResearchRunEvidenceError(f"{key} does not match the frozen registration")
    run_contract = _mapping(registration.get("run_contract"), "run_contract")
    if run_contract.get("manifest_schema") != RUN_MANIFEST_SCHEMA:
        raise ResearchRunEvidenceError("registered run manifest schema is unsupported")
    if bindings["engine"] != run_contract.get("engine"):
        raise ResearchRunEvidenceError("run engine does not match the frozen registration")
    if bindings["execution_semantics_sha256"] != _sha(
        run_contract.get("execution_semantics_sha256"),
        "run_contract.execution_semantics_sha256",
    ):
        raise ResearchRunEvidenceError(
            "execution semantics do not match the frozen registration"
        )
    if bindings["fixed_config_sha256"] != _sha(
        run_contract.get("fixed_config_sha256"), "run_contract.fixed_config_sha256"
    ):
        raise ResearchRunEvidenceError("fixed run configuration changed")
    factor_contract = _mapping(registration.get("factor_contract"), "factor_contract")
    if bindings["factor_id"] != str(factor_contract.get("factor_id") or ""):
        raise ResearchRunEvidenceError("factor evaluator differs from registration")
    lookback_parameter = str(factor_contract.get("lookback_parameter") or "")
    if lookback_parameter not in bindings["parameters"]:
        raise ResearchRunEvidenceError("factor lookback parameter is not reserved")
    if bindings["factor_lookback_sessions"] != int(
        bindings["parameters"][lookback_parameter]
    ):
        raise ResearchRunEvidenceError(
            "factor fixture lookback differs from the reserved parameter"
        )
    statistical_contract = _mapping(
        registration.get("statistical_contract"), "statistical_contract"
    )
    for binding_key, contract_key in (
        ("statistical_test_id", "test_id"),
        ("statistical_sample_scope", "sample_scope"),
        ("statistics_minimum_observations", "minimum_observations"),
        ("statistics_maximum_hac_lags", "maximum_hac_lags"),
    ):
        if bindings[binding_key] != statistical_contract.get(contract_key):
            raise ResearchRunEvidenceError(
                f"{binding_key} differs from the statistical contract"
            )
    primary_metric_name = str(registration.get("primary_metric") or "")
    metrics = _mapping(artifact.get("metrics"), "artifact.metrics")
    try:
        primary_metric_value = float(metrics[primary_metric_name])
    except (KeyError, TypeError, ValueError) as exc:
        raise ResearchRunEvidenceError(
            "artifact does not contain the registered numeric primary metric"
        ) from exc
    if not math.isfinite(primary_metric_value):
        raise ResearchRunEvidenceError("registered primary metric must be finite")

    registered_receipt = registration.get("provider_publication_receipt_sha256")
    if registered_receipt is not None:
        registered_receipt = _sha(
            registered_receipt, "provider_publication_receipt_sha256"
        )
    if bindings["provider_publication_receipt_sha256"] != registered_receipt:
        raise ResearchRunEvidenceError(
            "provider publication receipt does not match the frozen registration"
        )
    if bool(provider_publication_verified) != (registered_receipt is not None):
        raise ResearchRunEvidenceError("provider publication verification state is invalid")
    replay_verification = verify_canonical_replay_attestation(
        canonical_replay_attestation
    )
    if not replay_verification["verified"]:
        raise ResearchRunEvidenceError(
            "canonical engine replay failed: "
            + "; ".join(str(item) for item in replay_verification["errors"])
        )
    if canonical_replay_attestation.get("schema") != CANONICAL_REPLAY_SCHEMA:
        raise ResearchRunEvidenceError("canonical replay attestation schema is unsupported")
    if canonical_replay_attestation.get("engine") != bindings["engine"]:
        raise ResearchRunEvidenceError("canonical replay used a different engine")

    identity = {
        "schema": RESEARCH_RUN_EVIDENCE_SCHEMA,
        "run_id": str(run_id),
        "run_fingerprint": bindings["run_fingerprint"],
        "result_sha256": bindings["result_sha256"],
        "artifact_sha256": bindings["artifact_sha256"],
        "artifact_uri": str(artifact_uri),
        "parameters_sha256": bindings["parameters_sha256"],
        "config_sha256": bindings["config_sha256"],
        "fixed_config_sha256": bindings["fixed_config_sha256"],
        "dataset_manifest_sha256": bindings["dataset_manifest_sha256"],
        "dataset_snapshot_sha256": bindings["dataset_snapshot_sha256"],
        "catalog_as_of_sha256": bindings["catalog_as_of_sha256"],
        "provider_publication_receipt_sha256": registered_receipt,
        "provider_publication_verified": bool(provider_publication_verified),
        "code_sha256": bindings["code_sha256"],
        "execution_semantics_sha256": bindings["execution_semantics_sha256"],
        "engine": bindings["engine"],
        "factor_id": bindings["factor_id"],
        "factor_validation_attestation_sha256": bindings[
            "factor_validation_attestation_sha256"
        ],
        "primary_metric_name": primary_metric_name,
        "primary_metric_value": primary_metric_value,
        "statistics_attestation_sha256": bindings[
            "statistics_attestation_sha256"
        ],
        "statistical_test_id": bindings["statistical_test_id"],
        "statistical_sample_scope": bindings["statistical_sample_scope"],
        "statistical_observation_count": bindings[
            "statistical_observation_count"
        ],
        "raw_one_sided_p_value": bindings["raw_one_sided_p_value"],
        "canonical_replay_attestation_sha256": _sha(
            canonical_replay_attestation.get("attestation_sha256"),
            "canonical replay attestation_sha256",
        ),
        "canonical_replay_scope_sha256": _sha(
            canonical_replay_attestation.get("scope_sha256"),
            "canonical replay scope_sha256",
        ),
        "robustness_attestation_sha256": bindings[
            "robustness_attestation_sha256"
        ],
    }
    return {**identity, "evidence_sha256": sha256_digest(identity)}


def verify_research_run_evidence(
    artifact: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    registration: Mapping[str, Any],
    attempt: Mapping[str, Any],
    canonical_replay_attestation: Mapping[str, Any],
) -> dict[str, Any]:
    recorded = dict(evidence)
    evidence_sha = _sha(recorded.pop("evidence_sha256", None), "evidence_sha256")
    if recorded.get("schema") != RESEARCH_RUN_EVIDENCE_SCHEMA:
        raise ResearchRunEvidenceError("unsupported research run evidence schema")
    if sha256_digest(recorded) != evidence_sha:
        raise ResearchRunEvidenceError("research run evidence digest mismatch")
    rebuilt = build_research_run_evidence(
        artifact,
        run_id=str(recorded.get("run_id") or ""),
        registration=registration,
        attempt=attempt,
        artifact_uri=str(recorded.get("artifact_uri") or ""),
        provider_publication_verified=recorded.get("provider_publication_verified") is True,
        canonical_replay_attestation=canonical_replay_attestation,
    )
    if rebuilt != dict(evidence):
        raise ResearchRunEvidenceError("research run evidence does not match archived artifact")
    return rebuilt
