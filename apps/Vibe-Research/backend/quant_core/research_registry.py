"""Read-only verifier for the legacy v5 research registry."""

from __future__ import annotations

import json
import math
import os
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .data_catalog import DataCatalog, DataCatalogError
from .ablation_validation import (
    ABLATION_PLAN_SCHEMA,
    AblationValidationError,
    ablation_variants,
    match_ablation_variant,
    validate_ablation_plan,
)
from .factor_validation import (
    FACTOR_VALIDATION_ATTESTATION_SCHEMA,
    REQUIRED_FACTOR_CHECKS,
)
from .research_statistics import (
    HAC_TEST_ID,
    MULTIPLICITY_REPORT_SCHEMA,
    PARAMETER_SURFACE_SCHEMA,
    RESEARCH_STATISTICS_SCHEMA,
    ResearchStatisticsError,
    build_holm_bonferroni_report,
    build_parameter_surface_report,
)
from .canonical_replay import verify_canonical_replay_attestation
from .provider_contract import ProviderDeliveryStore
from .provenance import RUN_MANIFEST_SCHEMA, sha256_digest
from .research_run_evidence import (
    RESEARCH_RUN_EVIDENCE_SCHEMA,
    ResearchRunEvidenceError,
    build_research_run_evidence,
    canonical_research_run_artifact_bytes,
    load_research_run_artifact,
    verify_research_run_evidence,
)


RESEARCH_EVENT_SCHEMA = "quant-platform/research-experiment-event/v5"
RESEARCH_REGISTRATION_SCHEMA = "quant-platform/research-experiment-registration/v5"
RESEARCH_REGISTRY_STATUS_SCHEMA = "quant-platform/research-registry-status/v5"
RESEARCH_GOVERNANCE_POLICY_PATH = "config/research/research-governance-policy-v1.json"
EXPERIMENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
REQUIRED_ADVERSARIAL_CHECKS = {
    "DATA_TIME_AND_REVISION_LINEAGE",
    "SAMPLE_LEAKAGE_AND_PURGING",
    "COMPLETE_EXPERIMENT_COUNT",
    "EXECUTION_AND_COST_STRESS",
    "NEGATIVE_CONTROLS_AND_ABLATIONS",
    "FAILURE_CONDITIONS_AND_KILL_CRITERIA",
}


class ResearchRegistryError(RuntimeError):
    """Fail-closed registry validation or transition error."""

    def __init__(self, message: str, *, code: str | None = None) -> None:
        self.code = code
        super().__init__(message)


def _timestamp(value: str) -> datetime:
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ResearchRegistryError(f"invalid registry timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ResearchRegistryError("registry timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _sha(value: Any, label: str) -> str:
    text = str(value).lower()
    if not SHA256_RE.fullmatch(text):
        raise ResearchRegistryError(f"{label} must be a lowercase sha256")
    return text


def _nonempty(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ResearchRegistryError(f"{label} is required")
    return text


def resolve_research_governance_policy(platform_root: str | Path) -> dict[str, Any]:
    root = Path(platform_root).expanduser().resolve()
    path = (root / RESEARCH_GOVERNANCE_POLICY_PATH).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ResearchRegistryError("research governance policy escapes platform root") from exc
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ResearchRegistryError(f"research governance policy unreadable: {exc}") from exc
    if not isinstance(policy, dict):
        raise ResearchRegistryError("research governance policy must be an object")
    if policy.get("policy_id") != "quant-platform/research-governance/v1":
        raise ResearchRegistryError("unsupported research governance policy")
    if policy.get("append_only_registry") is not True:
        raise ResearchRegistryError("research registry must be append-only")
    if int(policy.get("lockbox_maximum_opens") or 0) != 1:
        raise ResearchRegistryError("lockbox maximum opens must remain one")
    if policy.get("real_orders") is not False:
        raise ResearchRegistryError("research governance cannot enable real orders")
    for field in (
        "completed_run_requires_archived_artifact",
        "completed_run_recomputes_manifest_and_output_hashes",
        "completed_run_requires_canonical_engine_replay",
        "completed_run_requires_frozen_holdout_robustness",
        "completed_run_must_match_registered_data_code_parameters_and_execution_semantics",
        "completed_run_requires_factor_fixture_attestation",
        "factor_attestation_reproduced_by_canonical_engine",
        "single_variable_ablation_plan_required",
        "all_predeclared_variants_attempted_before_seal",
        "baseline_must_complete_before_seal",
        "completed_run_requires_reproducible_hac_statistics",
        "holm_bonferroni_required_for_complete_predeclared_family",
        "selected_hypothesis_must_survive_multiplicity_correction",
        "selected_parameter_requires_neighbor_support",
    ):
        if policy.get(field) is not True:
            raise ResearchRegistryError(f"research governance weakened: {field}")
    if policy.get("statistical_sample_scope") != "FROZEN_HOLDOUT_OUT_OF_SAMPLE":
        raise ResearchRegistryError("research statistical sample scope was changed")
    if int(policy.get("parameter_surface_minimum_levels") or 0) < 3:
        raise ResearchRegistryError("research parameter surface was weakened")
    if list(policy.get("factor_validation_required_checks") or []) != list(
        REQUIRED_FACTOR_CHECKS
    ):
        raise ResearchRegistryError("factor validation required checks were changed")
    configured_checks = set(
        dict(policy.get("adversarial_audit") or {}).get("required_checks") or []
    )
    if configured_checks != REQUIRED_ADVERSARIAL_CHECKS:
        raise ResearchRegistryError("adversarial audit required checks were changed")
    return {
        "policy_path": RESEARCH_GOVERNANCE_POLICY_PATH,
        "policy_sha256": sha256_digest(policy),
        "policy": policy,
    }


def _validate_parameter_space(space: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(space, Mapping) or not space:
        raise ResearchRegistryError("parameter_space must be a non-empty object")
    normalized: dict[str, dict[str, Any]] = {}
    for raw_name, raw_spec in space.items():
        name = _nonempty(raw_name, "parameter name")
        if not isinstance(raw_spec, Mapping):
            raise ResearchRegistryError(f"parameter specification must be an object: {name}")
        spec = dict(raw_spec)
        kind = str(spec.get("type") or "")
        if kind == "choice":
            values = list(spec.get("values") or [])
            if not values:
                raise ResearchRegistryError(f"choice parameter has no values: {name}")
            if len({sha256_digest(value) for value in values}) != len(values):
                raise ResearchRegistryError(f"choice parameter has duplicate values: {name}")
            normalized[name] = {"type": kind, "values": values}
        elif kind in {"integer", "number"}:
            try:
                minimum = float(spec["minimum"])
                maximum = float(spec["maximum"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ResearchRegistryError(f"numeric bounds invalid: {name}") from exc
            if not math.isfinite(minimum) or not math.isfinite(maximum) or minimum > maximum:
                raise ResearchRegistryError(f"numeric bounds invalid: {name}")
            if kind == "integer" and (
                not minimum.is_integer() or not maximum.is_integer()
            ):
                raise ResearchRegistryError(f"integer bounds must be exact integers: {name}")
            normalized[name] = {
                "type": kind,
                "minimum": int(minimum) if kind == "integer" else minimum,
                "maximum": int(maximum) if kind == "integer" else maximum,
            }
        elif kind == "fixed":
            if "value" not in spec:
                raise ResearchRegistryError(f"fixed parameter has no value: {name}")
            normalized[name] = {"type": kind, "value": spec["value"]}
        else:
            raise ResearchRegistryError(f"unsupported parameter type for {name}: {kind}")
    return normalized


def _validate_parameters(parameters: Mapping[str, Any], space: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(parameters, Mapping):
        raise ResearchRegistryError("run parameters must be an object")
    values = dict(parameters)
    if set(values) != set(space):
        raise ResearchRegistryError("run parameters must exactly match frozen parameter space")
    for name, spec in space.items():
        value = values[name]
        kind = spec["type"]
        if kind == "choice" and value not in spec["values"]:
            raise ResearchRegistryError(f"parameter is outside frozen choices: {name}")
        if kind == "fixed" and sha256_digest(value) != sha256_digest(spec["value"]):
            raise ResearchRegistryError(f"fixed parameter changed: {name}")
        if kind == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ResearchRegistryError(f"integer parameter required: {name}")
            if not spec["minimum"] <= value <= spec["maximum"]:
                raise ResearchRegistryError(f"parameter outside frozen range: {name}")
        if kind == "number":
            try:
                number = float(value)
            except (TypeError, ValueError) as exc:
                raise ResearchRegistryError(f"numeric parameter required: {name}") from exc
            if not math.isfinite(number) or not spec["minimum"] <= number <= spec["maximum"]:
                raise ResearchRegistryError(f"parameter outside frozen range: {name}")
    return values


def _registration(payload: Mapping[str, Any]) -> dict[str, Any]:
    raw = dict(payload)
    expected_fields = {
        "schema",
        "strategy_id",
        "hypothesis",
        "researcher_id",
        "code_sha256",
        "dataset_manifest_sha256",
        "dataset_snapshot_sha256",
        "catalog_as_of_sha256",
        "provider_publication_receipt_sha256",
        "run_contract",
        "factor_contract",
        "ablation_plan",
        "statistical_contract",
        "parameter_space",
        "maximum_attempts",
        "primary_metric",
        "acceptance_criteria",
        "split_plan",
        "lockbox",
    }
    if set(raw) != expected_fields:
        raise ResearchRegistryError(
            "research registration fields must exactly match the frozen schema"
        )
    if raw.get("schema") != RESEARCH_REGISTRATION_SCHEMA:
        raise ResearchRegistryError("unsupported research registration schema")
    space = _validate_parameter_space(raw.get("parameter_space") or {})
    maximum_attempts = int(raw.get("maximum_attempts") or 0)
    if maximum_attempts < 1:
        raise ResearchRegistryError("maximum_attempts must be predeclared and positive")
    split_plan = dict(raw.get("split_plan") or {})
    if split_plan.get("schema") != "quant-core/purged-walk-forward/v1":
        raise ResearchRegistryError("registration requires a purged walk-forward split plan")
    if split_plan.get("status") != "PASS":
        raise ResearchRegistryError("split plan must pass before registration")
    lockbox = dict(raw.get("lockbox") or {})
    if int(lockbox.get("maximum_opens") or 0) != 1:
        raise ResearchRegistryError("lockbox maximum opens must equal one")
    run_contract = dict(raw.get("run_contract") or {})
    if set(run_contract) != {
        "manifest_schema",
        "engine",
        "execution_semantics_sha256",
        "fixed_config_sha256",
    }:
        raise ResearchRegistryError("run_contract fields must exactly match the frozen schema")
    if run_contract.get("manifest_schema") != RUN_MANIFEST_SCHEMA:
        raise ResearchRegistryError("run_contract requires quant-core/run-manifest/v2")
    engine = dict(run_contract.get("engine") or {})
    if set(engine) != {"name", "version"}:
        raise ResearchRegistryError("run_contract.engine fields must be name and version")
    provider_receipt = raw.get("provider_publication_receipt_sha256")
    factor_contract = dict(raw.get("factor_contract") or {})
    if set(factor_contract) != {
        "attestation_schema",
        "factor_id",
        "lookback_parameter",
        "required_checks",
    }:
        raise ResearchRegistryError(
            "factor_contract fields must exactly match the frozen schema"
        )
    if factor_contract.get("attestation_schema") != FACTOR_VALIDATION_ATTESTATION_SCHEMA:
        raise ResearchRegistryError("factor_contract attestation schema is unsupported")
    lookback_parameter = _nonempty(
        factor_contract.get("lookback_parameter"),
        "factor_contract.lookback_parameter",
    )
    if lookback_parameter not in space:
        raise ResearchRegistryError(
            "factor lookback parameter must exist in the frozen parameter space"
        )
    if list(factor_contract.get("required_checks") or []) != list(
        REQUIRED_FACTOR_CHECKS
    ):
        raise ResearchRegistryError("factor_contract required checks were changed")
    try:
        ablation_plan = validate_ablation_plan(raw.get("ablation_plan") or {}, space)
    except AblationValidationError as exc:
        raise ResearchRegistryError(str(exc)) from exc
    planned_variants = ablation_variants(ablation_plan)
    if maximum_attempts != len(planned_variants):
        raise ResearchRegistryError(
            "maximum_attempts must equal the predeclared ablation family size"
        )
    statistical_contract = dict(raw.get("statistical_contract") or {})
    if set(statistical_contract) != {
        "attestation_schema",
        "test_id",
        "sample_scope",
        "minimum_observations",
        "maximum_hac_lags",
        "alpha",
        "multiplicity_method",
        "family_definition",
        "selected_hypothesis_must_pass",
        "parameter_surface",
    }:
        raise ResearchRegistryError(
            "statistical_contract fields must exactly match the frozen schema"
        )
    if statistical_contract.get("attestation_schema") != RESEARCH_STATISTICS_SCHEMA:
        raise ResearchRegistryError("statistical attestation schema is unsupported")
    if statistical_contract.get("test_id") != HAC_TEST_ID:
        raise ResearchRegistryError("statistical test is unsupported")
    if statistical_contract.get("sample_scope") != "FROZEN_HOLDOUT_OUT_OF_SAMPLE":
        raise ResearchRegistryError("formal statistics require the frozen holdout")
    try:
        minimum_observations = int(statistical_contract.get("minimum_observations"))
        maximum_hac_lags = int(statistical_contract.get("maximum_hac_lags"))
        alpha = float(statistical_contract.get("alpha"))
    except (TypeError, ValueError) as exc:
        raise ResearchRegistryError(
            "statistical observation/lag/alpha contract is invalid"
        ) from exc
    if minimum_observations < 40 or not 0 <= maximum_hac_lags <= 50:
        raise ResearchRegistryError("statistical observation/lag contract is weakened")
    if not math.isfinite(alpha) or not 0 < alpha <= 0.05:
        raise ResearchRegistryError("statistical alpha must be at most 0.05")
    if statistical_contract.get("multiplicity_method") != "HOLM_BONFERRONI":
        raise ResearchRegistryError("formal research requires Holm-Bonferroni correction")
    if statistical_contract.get("family_definition") != (
        "ALL_PREDECLARED_ABLATION_VARIANTS"
    ):
        raise ResearchRegistryError("statistical hypothesis family was changed")
    if statistical_contract.get("selected_hypothesis_must_pass") is not True:
        raise ResearchRegistryError("selected hypothesis significance gate was disabled")
    surface = dict(statistical_contract.get("parameter_surface") or {})
    if set(surface) != {
        "report_schema",
        "parameter_name",
        "ordered_values",
        "metric_name",
        "metric_direction",
        "maximum_neighbor_degradation",
        "selected_requires_neighbor_support",
    }:
        raise ResearchRegistryError("parameter_surface fields are invalid")
    if surface.get("report_schema") != PARAMETER_SURFACE_SCHEMA:
        raise ResearchRegistryError("parameter surface report schema is unsupported")
    parameter_name = _nonempty(
        surface.get("parameter_name"), "parameter_surface.parameter_name"
    )
    if parameter_name != lookback_parameter:
        raise ResearchRegistryError(
            "parameter surface must cover the registered factor lookback"
        )
    ordered_values = list(surface.get("ordered_values") or [])
    if len(ordered_values) < 3 or len(
        {sha256_digest(item) for item in ordered_values}
    ) != len(ordered_values):
        raise ResearchRegistryError("parameter surface requires three unique levels")
    if surface.get("metric_name") != str(raw.get("primary_metric") or ""):
        raise ResearchRegistryError("parameter surface metric must be the primary metric")
    if surface.get("metric_direction") != "MAXIMIZE":
        raise ResearchRegistryError("parameter surface metric direction is unsupported")
    try:
        maximum_neighbor_degradation = float(
            surface.get("maximum_neighbor_degradation")
        )
    except (TypeError, ValueError) as exc:
        raise ResearchRegistryError("neighbor degradation threshold is invalid") from exc
    if not math.isfinite(maximum_neighbor_degradation) or maximum_neighbor_degradation < 0:
        raise ResearchRegistryError("neighbor degradation threshold is invalid")
    if surface.get("selected_requires_neighbor_support") is not True:
        raise ResearchRegistryError("parameter neighbor support gate was disabled")
    planned_values = [item["parameters"][parameter_name] for item in planned_variants]
    if {sha256_digest(item) for item in planned_values} != {
        sha256_digest(item) for item in ordered_values
    }:
        raise ResearchRegistryError(
            "parameter surface levels must exactly match the ablation family"
        )
    if any(
        item.get("changed_parameter") not in {None, parameter_name}
        for item in planned_variants
    ):
        raise ResearchRegistryError(
            "formal parameter surface cannot mix different changed parameters"
        )
    normalized = {
        "schema": RESEARCH_REGISTRATION_SCHEMA,
        "strategy_id": _nonempty(raw.get("strategy_id"), "strategy_id"),
        "hypothesis": _nonempty(raw.get("hypothesis"), "hypothesis"),
        "researcher_id": _nonempty(raw.get("researcher_id"), "researcher_id"),
        "code_sha256": _sha(raw.get("code_sha256"), "code_sha256"),
        "dataset_manifest_sha256": _sha(
            raw.get("dataset_manifest_sha256"), "dataset_manifest_sha256"
        ),
        "dataset_snapshot_sha256": _sha(
            raw.get("dataset_snapshot_sha256"), "dataset_snapshot_sha256"
        ),
        "catalog_as_of_sha256": _sha(
            raw.get("catalog_as_of_sha256"), "catalog_as_of_sha256"
        ),
        "provider_publication_receipt_sha256": (
            _sha(provider_receipt, "provider_publication_receipt_sha256")
            if provider_receipt is not None
            else None
        ),
        "run_contract": {
            "manifest_schema": RUN_MANIFEST_SCHEMA,
            "engine": {
                "name": _nonempty(engine.get("name"), "run_contract.engine.name"),
                "version": _nonempty(engine.get("version"), "run_contract.engine.version"),
            },
            "execution_semantics_sha256": _sha(
                run_contract.get("execution_semantics_sha256"),
                "run_contract.execution_semantics_sha256",
            ),
            "fixed_config_sha256": _sha(
                run_contract.get("fixed_config_sha256"),
                "run_contract.fixed_config_sha256",
            ),
        },
        "factor_contract": {
            "attestation_schema": FACTOR_VALIDATION_ATTESTATION_SCHEMA,
            "factor_id": _nonempty(
                factor_contract.get("factor_id"), "factor_contract.factor_id"
            ),
            "lookback_parameter": lookback_parameter,
            "required_checks": list(REQUIRED_FACTOR_CHECKS),
        },
        "ablation_plan": ablation_plan,
        "statistical_contract": {
            "attestation_schema": RESEARCH_STATISTICS_SCHEMA,
            "test_id": HAC_TEST_ID,
            "sample_scope": "FROZEN_HOLDOUT_OUT_OF_SAMPLE",
            "minimum_observations": minimum_observations,
            "maximum_hac_lags": maximum_hac_lags,
            "alpha": alpha,
            "multiplicity_method": "HOLM_BONFERRONI",
            "family_definition": "ALL_PREDECLARED_ABLATION_VARIANTS",
            "selected_hypothesis_must_pass": True,
            "parameter_surface": {
                "report_schema": PARAMETER_SURFACE_SCHEMA,
                "parameter_name": parameter_name,
                "ordered_values": ordered_values,
                "metric_name": str(surface["metric_name"]),
                "metric_direction": "MAXIMIZE",
                "maximum_neighbor_degradation": maximum_neighbor_degradation,
                "selected_requires_neighbor_support": True,
            },
        },
        "parameter_space": space,
        "maximum_attempts": maximum_attempts,
        "primary_metric": _nonempty(raw.get("primary_metric"), "primary_metric"),
        "acceptance_criteria": dict(raw.get("acceptance_criteria") or {}),
        "split_plan": {
            "schema": split_plan["schema"],
            "plan_sha256": _sha(split_plan.get("plan_sha256"), "split_plan.plan_sha256"),
            "status": "PASS",
        },
        "lockbox": {
            "dataset_id": _nonempty(lockbox.get("dataset_id"), "lockbox.dataset_id"),
            "manifest_sha256": _sha(
                lockbox.get("manifest_sha256"), "lockbox.manifest_sha256"
            ),
            "maximum_opens": 1,
        },
    }
    if not normalized["acceptance_criteria"]:
        raise ResearchRegistryError("acceptance criteria must be frozen before runs")
    return normalized


def _recorded_run_evidence(
    value: Any,
    *,
    run_id: str,
    registration: Mapping[str, Any],
    attempt: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ResearchRegistryError("RUN_COMPLETED requires machine-verified run evidence")
    evidence = dict(value)
    expected_fields = {
        "schema",
        "run_id",
        "run_fingerprint",
        "result_sha256",
        "artifact_sha256",
        "artifact_uri",
        "parameters_sha256",
        "config_sha256",
        "fixed_config_sha256",
        "dataset_manifest_sha256",
        "dataset_snapshot_sha256",
        "catalog_as_of_sha256",
        "provider_publication_receipt_sha256",
        "provider_publication_verified",
        "code_sha256",
        "execution_semantics_sha256",
        "engine",
        "factor_id",
        "factor_validation_attestation_sha256",
        "primary_metric_name",
        "primary_metric_value",
        "statistics_attestation_sha256",
        "statistical_test_id",
        "statistical_sample_scope",
        "statistical_observation_count",
        "raw_one_sided_p_value",
        "canonical_replay_attestation_sha256",
        "canonical_replay_scope_sha256",
        "robustness_attestation_sha256",
        "evidence_sha256",
    }
    if set(evidence) != expected_fields:
        raise ResearchRegistryError("research run evidence fields are invalid")
    if evidence.get("schema") != RESEARCH_RUN_EVIDENCE_SCHEMA:
        raise ResearchRegistryError("unsupported research run evidence schema")
    if str(evidence.get("run_id") or "") != run_id:
        raise ResearchRegistryError("research run evidence references a different run")
    evidence_sha = _sha(evidence.get("evidence_sha256"), "evidence_sha256")
    identity = {key: item for key, item in evidence.items() if key != "evidence_sha256"}
    if sha256_digest(identity) != evidence_sha:
        raise ResearchRegistryError("research run evidence digest mismatch")
    for key in (
        "run_fingerprint",
        "result_sha256",
        "artifact_sha256",
        "parameters_sha256",
        "config_sha256",
        "fixed_config_sha256",
        "dataset_manifest_sha256",
        "dataset_snapshot_sha256",
        "catalog_as_of_sha256",
        "code_sha256",
        "execution_semantics_sha256",
        "factor_validation_attestation_sha256",
        "statistics_attestation_sha256",
        "canonical_replay_attestation_sha256",
        "canonical_replay_scope_sha256",
        "robustness_attestation_sha256",
    ):
        _sha(evidence.get(key), key)
    artifact_uri = _nonempty(evidence.get("artifact_uri"), "artifact_uri")
    expected_uri = f"artifacts/{evidence['artifact_sha256']}.json"
    if artifact_uri != expected_uri:
        raise ResearchRegistryError("research artifact URI is not content-addressed")
    if evidence["parameters_sha256"] != attempt["parameters_sha256"]:
        raise ResearchRegistryError("completed run parameters differ from reservation")
    for key in (
        "dataset_manifest_sha256",
        "dataset_snapshot_sha256",
        "catalog_as_of_sha256",
        "code_sha256",
    ):
        if evidence[key] != registration[key]:
            raise ResearchRegistryError(f"completed run {key} differs from registration")
    run_contract = registration["run_contract"]
    if evidence["fixed_config_sha256"] != run_contract["fixed_config_sha256"]:
        raise ResearchRegistryError("completed run fixed configuration differs from registration")
    if evidence["execution_semantics_sha256"] != run_contract[
        "execution_semantics_sha256"
    ]:
        raise ResearchRegistryError("completed run execution semantics differ from registration")
    if evidence.get("engine") != run_contract["engine"]:
        raise ResearchRegistryError("completed run engine differs from registration")
    if evidence.get("factor_id") != registration["factor_contract"]["factor_id"]:
        raise ResearchRegistryError("completed run factor evaluator differs from registration")
    statistical_contract = registration["statistical_contract"]
    if evidence.get("primary_metric_name") != registration["primary_metric"]:
        raise ResearchRegistryError("completed run primary metric name changed")
    try:
        primary_metric_value = float(evidence.get("primary_metric_value"))
        raw_p_value = float(evidence.get("raw_one_sided_p_value"))
    except (TypeError, ValueError) as exc:
        raise ResearchRegistryError("completed run statistical values are invalid") from exc
    if not math.isfinite(primary_metric_value):
        raise ResearchRegistryError("completed run primary metric is non-finite")
    if not math.isfinite(raw_p_value) or not 0 <= raw_p_value <= 1:
        raise ResearchRegistryError("completed run p-value is invalid")
    if evidence.get("statistical_test_id") != statistical_contract["test_id"]:
        raise ResearchRegistryError("completed run statistical test changed")
    if evidence.get("statistical_sample_scope") != statistical_contract["sample_scope"]:
        raise ResearchRegistryError("completed run statistical sample scope changed")
    if int(evidence.get("statistical_observation_count") or 0) < int(
        statistical_contract["minimum_observations"]
    ):
        raise ResearchRegistryError("completed run statistical sample is too short")
    registered_receipt = registration["provider_publication_receipt_sha256"]
    if evidence.get("provider_publication_receipt_sha256") != registered_receipt:
        raise ResearchRegistryError("completed run provider receipt differs from registration")
    if (evidence.get("provider_publication_verified") is True) != (
        registered_receipt is not None
    ):
        raise ResearchRegistryError("completed run provider verification state is invalid")
    return evidence


def _empty_state(registration: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "status": "REGISTERED",
        "registration": dict(registration),
        "attempts": {},
        "selected_run_id": None,
        "multiplicity_report": None,
        "parameter_surface_report": None,
        "audit": None,
        "lockbox_open": None,
        "lockbox_result": None,
    }


def _apply_event(states: dict[str, dict[str, Any]], event: Mapping[str, Any]) -> None:
    experiment_id = str(event["experiment_id"])
    event_type = str(event["event_type"])
    payload = dict(event["payload"])
    actor_id = str(event["actor_id"])
    if event_type == "EXPERIMENT_REGISTERED":
        if experiment_id in states:
            raise ResearchRegistryError(f"experiment already registered: {experiment_id}")
        normalized = _registration(payload)
        if actor_id != normalized["researcher_id"]:
            raise ResearchRegistryError("registration actor must be the declared researcher")
        states[experiment_id] = _empty_state(normalized)
        return
    if experiment_id not in states:
        raise ResearchRegistryError(f"event references unknown experiment: {experiment_id}")
    state = states[experiment_id]
    registration = state["registration"]
    researcher_id = registration["researcher_id"]

    if event_type == "RUN_RESERVED":
        if actor_id != researcher_id:
            raise ResearchRegistryError("only the declared researcher may reserve runs")
        if state["status"] not in {"REGISTERED", "RUNNING"}:
            raise ResearchRegistryError("development runs are closed")
        run_id = _nonempty(payload.get("run_id"), "run_id")
        if run_id in state["attempts"]:
            raise ResearchRegistryError(f"duplicate run_id: {run_id}")
        if len(state["attempts"]) >= registration["maximum_attempts"]:
            raise ResearchRegistryError("predeclared experiment attempt budget exhausted")
        parameters = _validate_parameters(
            payload.get("parameters") or {}, registration["parameter_space"]
        )
        try:
            ablation_variant_id = match_ablation_variant(
                registration["ablation_plan"], parameters
            )
        except AblationValidationError as exc:
            raise ResearchRegistryError(str(exc)) from exc
        if any(
            item["ablation_variant_id"] == ablation_variant_id
            for item in state["attempts"].values()
        ):
            raise ResearchRegistryError(
                "each predeclared ablation variant may be attempted exactly once"
            )
        state["attempts"][run_id] = {
            "status": "RESERVED",
            "parameters": parameters,
            "parameters_sha256": sha256_digest(parameters),
            "ablation_variant_id": ablation_variant_id,
            "reserved_by": actor_id,
        }
        state["status"] = "RUNNING"
        return

    if event_type in {"RUN_COMPLETED", "RUN_FAILED"}:
        run_id = _nonempty(payload.get("run_id"), "run_id")
        attempt = state["attempts"].get(run_id)
        if not attempt or attempt["status"] != "RESERVED":
            raise ResearchRegistryError("run must be reserved exactly once before outcome")
        if actor_id != attempt["reserved_by"]:
            raise ResearchRegistryError("run outcome actor must match its reservation")
        if event_type == "RUN_COMPLETED":
            if set(payload) != {"run_id", "evidence"}:
                raise ResearchRegistryError("RUN_COMPLETED payload fields are invalid")
            evidence = _recorded_run_evidence(
                payload.get("evidence"),
                run_id=run_id,
                registration=registration,
                attempt=attempt,
            )
            attempt.update(
                {
                    "status": "COMPLETED",
                    "result_sha256": evidence["result_sha256"],
                    "artifact_uri": evidence["artifact_uri"],
                    "run_evidence": evidence,
                }
            )
        else:
            attempt.update(
                {
                    "status": "FAILED",
                    "failure_code": _nonempty(
                        payload.get("failure_code"), "failure_code"
                    ),
                }
            )
        return

    if event_type == "DEVELOPMENT_SEALED":
        if actor_id != researcher_id:
            raise ResearchRegistryError("only the declared researcher may seal development")
        if state["status"] not in {"REGISTERED", "RUNNING"}:
            raise ResearchRegistryError("development is already sealed")
        if any(item["status"] == "RESERVED" for item in state["attempts"].values()):
            raise ResearchRegistryError("all reserved runs require an outcome before seal")
        planned_variants = {
            item["variant_id"]
            for item in ablation_variants(registration["ablation_plan"])
        }
        attempted_variants = {
            item["ablation_variant_id"] for item in state["attempts"].values()
        }
        if attempted_variants != planned_variants:
            missing = ", ".join(sorted(planned_variants - attempted_variants))
            raise ResearchRegistryError(
                f"all predeclared ablation variants require an outcome before seal: {missing}"
            )
        incomplete_variants = sorted(
            item["ablation_variant_id"]
            for item in state["attempts"].values()
            if item["status"] != "COMPLETED"
        )
        if incomplete_variants:
            raise ResearchRegistryError(
                "all ablation variants require valid statistical evidence before seal: "
                + ", ".join(incomplete_variants)
            )
        baseline_id = registration["ablation_plan"]["baseline_variant_id"]
        if not any(
            item["ablation_variant_id"] == baseline_id
            and item["status"] == "COMPLETED"
            for item in state["attempts"].values()
        ):
            raise ResearchRegistryError("ablation baseline must complete before seal")
        completed = {
            run_id
            for run_id, item in state["attempts"].items()
            if item["status"] == "COMPLETED"
        }
        selected = _nonempty(payload.get("selected_run_id"), "selected_run_id")
        if selected not in completed:
            raise ResearchRegistryError("selected run must be a recorded completed attempt")
        if int(payload.get("declared_total_attempts") or -1) != len(state["attempts"]):
            raise ResearchRegistryError("declared experiment count does not match ledger")
        statistical_contract = registration["statistical_contract"]
        try:
            multiplicity_report = build_holm_bonferroni_report(
                [
                    {
                        "hypothesis_id": item["ablation_variant_id"],
                        "raw_p_value": item["run_evidence"][
                            "raw_one_sided_p_value"
                        ],
                    }
                    for item in state["attempts"].values()
                ],
                alpha=float(statistical_contract["alpha"]),
            )
        except ResearchStatisticsError as exc:
            raise ResearchRegistryError(str(exc)) from exc
        selected_variant_id = state["attempts"][selected]["ablation_variant_id"]
        selected_hypothesis = next(
            item
            for item in multiplicity_report["hypotheses"]
            if item["hypothesis_id"] == selected_variant_id
        )
        if selected_hypothesis["rejected"] is not True:
            raise ResearchRegistryError(
                "selected run does not survive Holm-Bonferroni correction"
            )
        surface_contract = statistical_contract["parameter_surface"]
        parameter_name = surface_contract["parameter_name"]
        try:
            parameter_surface_report = build_parameter_surface_report(
                [
                    {
                        "value": item["parameters"][parameter_name],
                        "metric": item["run_evidence"]["primary_metric_value"],
                    }
                    for item in state["attempts"].values()
                ],
                parameter_name=parameter_name,
                metric_name=surface_contract["metric_name"],
                selected_value=state["attempts"][selected]["parameters"][
                    parameter_name
                ],
                sample_scope=statistical_contract["sample_scope"],
                maximum_neighbor_degradation=float(
                    surface_contract["maximum_neighbor_degradation"]
                ),
            )
        except ResearchStatisticsError as exc:
            raise ResearchRegistryError(str(exc)) from exc
        if parameter_surface_report["neighbor_supported"] is not True:
            raise ResearchRegistryError(
                "selected run is an unsupported isolated parameter spike"
            )
        state["selected_run_id"] = selected
        state["multiplicity_report"] = multiplicity_report
        state["parameter_surface_report"] = parameter_surface_report
        state["status"] = "SEALED_AWAITING_AUDIT"
        return

    if event_type == "ADVERSARIAL_AUDIT_RECORDED":
        if state["status"] != "SEALED_AWAITING_AUDIT":
            raise ResearchRegistryError("adversarial audit requires sealed development")
        if actor_id == researcher_id:
            raise ResearchRegistryError("researcher cannot approve their own adversarial audit")
        verdict = str(payload.get("verdict") or "")
        if verdict not in {"PASS", "FAIL", "NEEDS_WORK"}:
            raise ResearchRegistryError("unsupported adversarial audit verdict")
        checks = [dict(item) for item in list(payload.get("checks") or [])]
        if not checks:
            raise ResearchRegistryError("adversarial audit checks are required")
        normalized_checks: list[dict[str, Any]] = []
        for item in checks:
            if set(item) != {"code", "passed", "evidence"}:
                raise ResearchRegistryError("adversarial audit check fields are invalid")
            normalized_checks.append(
                {
                    "code": _nonempty(item.get("code"), "audit check code"),
                    "passed": item.get("passed") is True,
                    "evidence": _nonempty(
                        item.get("evidence"), "audit check evidence"
                    ),
                }
            )
        check_codes = {item["code"] for item in normalized_checks}
        if check_codes != REQUIRED_ADVERSARIAL_CHECKS:
            raise ResearchRegistryError("adversarial audit check set is incomplete")
        reviewed_head = _sha(
            payload.get("reviewed_registry_head_sha256"),
            "reviewed_registry_head_sha256",
        )
        if reviewed_head != str(event["previous_event_sha256"]):
            raise ResearchRegistryError("adversarial audit reviewed a different ledger head")
        if verdict == "PASS" and not all(item["passed"] for item in normalized_checks):
            raise ResearchRegistryError("passing audit cannot contain failed checks")
        state["audit"] = {
            "reviewer_id": actor_id,
            "verdict": verdict,
            "report_sha256": _sha(
                payload.get("report_sha256"), "report_sha256"
            ),
            "checks": normalized_checks,
            "reviewed_registry_head_sha256": reviewed_head,
        }
        state["status"] = "AUDIT_PASSED" if verdict == "PASS" else "AUDIT_FAILED"
        return

    if event_type == "LOCKBOX_OPENED":
        if state["status"] != "AUDIT_PASSED":
            raise ResearchRegistryError("lockbox requires an independent passing audit")
        if actor_id == researcher_id:
            raise ResearchRegistryError("researcher cannot open their own final lockbox")
        expected = registration["lockbox"]
        if str(payload.get("dataset_id") or "") != expected["dataset_id"]:
            raise ResearchRegistryError("lockbox dataset identity changed")
        manifest_sha = _sha(payload.get("manifest_sha256"), "manifest_sha256")
        if manifest_sha != expected["manifest_sha256"]:
            raise ResearchRegistryError("lockbox dataset manifest changed")
        state["lockbox_open"] = {
            "operator_id": actor_id,
            "dataset_id": expected["dataset_id"],
            "manifest_sha256": manifest_sha,
        }
        state["status"] = "LOCKBOX_OPEN"
        return

    if event_type == "LOCKBOX_RESULT_RECORDED":
        if state["status"] != "LOCKBOX_OPEN":
            raise ResearchRegistryError("lockbox result requires exactly one prior open")
        if actor_id != state["lockbox_open"]["operator_id"]:
            raise ResearchRegistryError("lockbox result operator must match the opener")
        decision = str(payload.get("decision") or "")
        if decision not in {"PASS", "FAIL"}:
            raise ResearchRegistryError("lockbox decision must be PASS or FAIL")
        state["lockbox_result"] = {
            "operator_id": actor_id,
            "decision": decision,
            "result_sha256": _sha(payload.get("result_sha256"), "result_sha256"),
            "report_sha256": _sha(payload.get("report_sha256"), "report_sha256"),
        }
        state["status"] = "LOCKBOX_PASSED" if decision == "PASS" else "LOCKBOX_FAILED"
        return

    raise ResearchRegistryError(f"unsupported research registry event: {event_type}")


def _summary(experiment_id: str, state: Mapping[str, Any]) -> dict[str, Any]:
    attempts = dict(state["attempts"])
    counts = {
        status.lower(): sum(item["status"] == status for item in attempts.values())
        for status in ("RESERVED", "COMPLETED", "FAILED")
    }
    completed_evidence = [
        item["run_evidence"]
        for item in attempts.values()
        if item["status"] == "COMPLETED"
    ]
    provider_bound = state["registration"][
        "provider_publication_receipt_sha256"
    ] is not None
    selected_evidence = (
        attempts.get(state["selected_run_id"], {}).get("run_evidence")
        if state["selected_run_id"]
        else None
    )
    planned_ablation_variants = ablation_variants(
        state["registration"]["ablation_plan"]
    )
    attempted_variant_ids = {
        item["ablation_variant_id"] for item in attempts.values()
    }
    return {
        "experiment_id": experiment_id,
        "strategy_id": state["registration"]["strategy_id"],
        "code_sha256": state["registration"]["code_sha256"],
        "dataset_manifest_sha256": state["registration"][
            "dataset_manifest_sha256"
        ],
        "dataset_snapshot_sha256": state["registration"][
            "dataset_snapshot_sha256"
        ],
        "catalog_as_of_sha256": state["registration"]["catalog_as_of_sha256"],
        "factor_id": state["registration"]["factor_contract"]["factor_id"],
        "factor_validation_required": True,
        "ablation_plan_schema": ABLATION_PLAN_SCHEMA,
        "ablation_plan_sha256": state["registration"]["ablation_plan"][
            "plan_sha256"
        ],
        "ablation_variant_count": len(planned_ablation_variants),
        "ablation_variants_attempted": len(attempted_variant_ids),
        "ablation_coverage_complete": attempted_variant_ids
        == {item["variant_id"] for item in planned_ablation_variants},
        "multiplicity_report_schema": MULTIPLICITY_REPORT_SCHEMA,
        "multiplicity_report": state["multiplicity_report"],
        "parameter_surface_report": state["parameter_surface_report"],
        "statistical_gate_passed": bool(
            state["multiplicity_report"]
            and state["parameter_surface_report"]
            and state["parameter_surface_report"]["neighbor_supported"] is True
        ),
        "data_evidence_mode": (
            "VERIFIED_PROVIDER_PUBLICATION"
            if provider_bound
            else "CATALOG_AS_OF_RESEARCH_ONLY"
        ),
        "provider_publication_verified": provider_bound and all(
            item["provider_publication_verified"] is True for item in completed_evidence
        ),
        "completed_run_evidence_verified": True,
        "canonical_engine_replay_verified": bool(completed_evidence)
        and all(
            bool(item.get("canonical_replay_attestation_sha256"))
            for item in completed_evidence
        ),
        "robustness_gate_passed": bool(completed_evidence)
        and all(
            bool(item.get("robustness_attestation_sha256"))
            for item in completed_evidence
        ),
        "purged_walk_forward_plan_sha256": state["registration"]["split_plan"][
            "plan_sha256"
        ],
        "status": state["status"],
        "maximum_attempts": state["registration"]["maximum_attempts"],
        "attempt_count": len(attempts),
        "attempt_counts": counts,
        "selected_run_id": state["selected_run_id"],
        "selected_run_evidence_sha256": (
            selected_evidence["evidence_sha256"] if selected_evidence else None
        ),
        "parameter_lockbox_sha256": sha256_digest(
            {
                "parameter_space": state["registration"]["parameter_space"],
                "maximum_attempts": state["registration"]["maximum_attempts"],
                "primary_metric": state["registration"]["primary_metric"],
                "acceptance_criteria": state["registration"]["acceptance_criteria"],
                "ablation_plan_sha256": state["registration"]["ablation_plan"][
                    "plan_sha256"
                ],
            }
        ),
        "adversarial_audit": state["audit"],
        "lockbox_open_count": 1 if state["lockbox_open"] else 0,
        "lockbox_result": state["lockbox_result"],
    }


class ResearchExperimentRegistry:
    """Read-only verifier for the legacy v5 JSONL ledger.

    V5 predates root family allocation and cannot create formal evidence.  Its
    replay/summary logic remains available for historical accounting, while
    every mutation path is permanently closed.  New studies use
    :class:`ResearchStudyLedgerV6`.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        platform_root: str | Path | None = None,
        provider_catalog_root: str | Path | None = None,
        canonical_replayers: Mapping[
            tuple[str, str], Callable[[dict[str, Any], Any, str], Mapping[str, Any]]
        ]
        | None = None,
    ):
        self.path = Path(path).expanduser().resolve()
        self.artifact_root = self.path.parent / "artifacts"
        self.platform_root = (
            Path(platform_root).expanduser().resolve()
            if platform_root is not None
            else None
        )
        self.provider_store: ProviderDeliveryStore | None = None
        self.catalog: DataCatalog | None = None
        self.canonical_replayers = dict(canonical_replayers or {})
        if self.platform_root is not None:
            catalog_root = (
                Path(provider_catalog_root).expanduser().resolve()
                if provider_catalog_root is not None
                else self.platform_root
                / "data"
                / "quant-lab"
                / "backtest-workbench"
                / "datahub"
            )
            self.provider_store = ProviderDeliveryStore(
                platform_root=self.platform_root,
                catalog_root=catalog_root,
            )
            self.catalog = self.provider_store.catalog

    @staticmethod
    def _states(events: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
        states: dict[str, dict[str, Any]] = {}
        for event in events:
            _apply_event(states, event)
        return states

    @staticmethod
    def _mutation_forbidden(action: str) -> None:
        raise ResearchRegistryError(
            f"LEGACY_V5_READ_ONLY: {action} is permanently forbidden",
            code="LEGACY_V5_READ_ONLY",
        )

    def _artifact_path(self, artifact_uri: str) -> Path:
        target = (self.path.parent / artifact_uri).resolve()
        try:
            target.relative_to(self.artifact_root.resolve())
        except ValueError as exc:
            raise ResearchRegistryError("research artifact escapes the registry evidence root") from exc
        return target

    def _verify_provider_publication(
        self, receipt_sha256: str | None, dataset_manifest_sha256: str
    ) -> bool:
        if receipt_sha256 is None:
            return False
        if self.provider_store is None:
            raise ResearchRegistryError(
                "provider-bound research verification requires platform_root"
            )
        verification = self.provider_store.verify_publication(receipt_sha256)
        if not verification["verified"]:
            raise ResearchRegistryError(
                "provider publication verification failed: "
                + "; ".join(str(item) for item in verification["errors"])
            )
        receipt = dict(verification.get("receipt") or {})
        if receipt.get("manifest_sha256") != dataset_manifest_sha256:
            raise ResearchRegistryError(
                "provider publication receipt references a different dataset manifest"
            )
        return True

    def _verify_catalog_selection(
        self, artifact: Mapping[str, Any], registration: Mapping[str, Any]
    ) -> dict[str, Any]:
        if self.catalog is None:
            raise ResearchRegistryError(
                "research run verification requires platform_root and DataCatalog"
            )
        data = dict(artifact.get("data") or {})
        snapshot = dict(data.get("snapshot") or {})
        if snapshot.get("content_sha256") != registration[
            "dataset_snapshot_sha256"
        ]:
            raise ResearchRegistryError(
                "artifact dataset_snapshot_sha256 differs from registration"
            )
        selection = dict(data.get("catalog_as_of") or {})
        try:
            verification = self.catalog.verify_as_of(selection)
        except (DataCatalogError, TypeError, ValueError) as exc:
            raise ResearchRegistryError(f"catalog as-of verification failed: {exc}") from exc
        if not verification["verified"]:
            raise ResearchRegistryError(
                "catalog as-of verification failed: "
                + "; ".join(str(item) for item in verification["errors"])
            )
        if selection.get("selected_manifest_sha256") != registration[
            "dataset_manifest_sha256"
        ]:
            raise ResearchRegistryError(
                "catalog dataset_manifest_sha256 differs from registration"
            )
        if selection.get("as_of_sha256") != registration["catalog_as_of_sha256"]:
            raise ResearchRegistryError(
                "catalog_as_of_sha256 differs from registration"
            )
        try:
            loaded = self.catalog.load(
                str(selection.get("dataset_id") or ""),
                str(selection.get("selected_manifest_sha256") or ""),
            )
        except (DataCatalogError, TypeError, ValueError) as exc:
            raise ResearchRegistryError(f"catalog dataset verification failed: {exc}") from exc
        manifest = dict(loaded.get("manifest") or {})
        if manifest.get("declared_dataset_sha256") != registration[
            "dataset_snapshot_sha256"
        ]:
            raise ResearchRegistryError(
                "catalog manifest does not bind the registered dataset snapshot"
            )
        if loaded.get("payload_sha256") != selection.get("selected_payload_sha256"):
            raise ResearchRegistryError("catalog payload differs from frozen as-of selection")
        return loaded

    def _replayer_for(
        self, engine: Mapping[str, Any]
    ) -> Callable[[dict[str, Any], Any, str], Mapping[str, Any]]:
        key = (str(engine.get("name") or ""), str(engine.get("version") or ""))
        if key in self.canonical_replayers:
            return self.canonical_replayers[key]
        try:
            from backtest_lab import (
                ENGINE_NAME,
                ENGINE_VERSION,
                replay_registered_backtest,
            )
        except (ImportError, RuntimeError) as exc:
            raise ResearchRegistryError(
                "canonical backtest replay engine is unavailable"
            ) from exc
        if key != (ENGINE_NAME, ENGINE_VERSION):
            raise ResearchRegistryError(
                f"formal research engine has no canonical replayer: {key[0]} {key[1]}"
            )
        return replay_registered_backtest

    def _canonical_replay(
        self,
        artifact: Mapping[str, Any],
        registration: Mapping[str, Any],
        catalog_entry: Mapping[str, Any],
    ) -> dict[str, Any]:
        engine = dict(registration["run_contract"]["engine"])
        replayer = self._replayer_for(engine)
        try:
            attestation = dict(
                replayer(
                    dict(artifact),
                    catalog_entry["payload"],
                    str(catalog_entry["payload_sha256"]),
                )
            )
        except Exception as exc:
            raise ResearchRegistryError(f"canonical engine replay failed: {exc}") from exc
        verification = verify_canonical_replay_attestation(attestation)
        if not verification["verified"]:
            raise ResearchRegistryError(
                "canonical engine replay failed: "
                + "; ".join(str(item) for item in verification["errors"])
            )
        if attestation.get("engine") != engine:
            raise ResearchRegistryError("canonical replay engine differs from registration")
        return attestation

    def _verify_completed_artifacts(
        self, states: Mapping[str, Mapping[str, Any]]
    ) -> None:
        for state in states.values():
            registration = state["registration"]
            provider_verified = self._verify_provider_publication(
                registration["provider_publication_receipt_sha256"],
                registration["dataset_manifest_sha256"],
            )
            for attempt in state["attempts"].values():
                if attempt["status"] != "COMPLETED":
                    continue
                evidence = attempt["run_evidence"]
                path = self._artifact_path(evidence["artifact_uri"])
                artifact = load_research_run_artifact(path)
                if sha256_digest(artifact) != evidence["artifact_sha256"]:
                    raise ResearchRegistryError("archived research artifact digest mismatch")
                catalog_entry = self._verify_catalog_selection(artifact, registration)
                replay_attestation = self._canonical_replay(
                    artifact, registration, catalog_entry
                )
                if evidence["provider_publication_verified"] is not provider_verified:
                    raise ResearchRegistryError(
                        "archived run provider verification state is stale"
                    )
                try:
                    verify_research_run_evidence(
                        artifact,
                        evidence,
                        registration=registration,
                        attempt=attempt,
                        canonical_replay_attestation=replay_attestation,
                    )
                except ResearchRunEvidenceError as exc:
                    raise ResearchRegistryError(str(exc)) from exc

    def _archive_artifact(self, artifact: Mapping[str, Any], artifact_uri: str) -> None:
        path = self._artifact_path(artifact_uri)
        content = canonical_research_run_artifact_bytes(artifact)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if path.read_bytes() != content:
                raise ResearchRegistryError("immutable research artifact collision")
            return
        temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
        temporary.write_bytes(content)
        try:
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ResearchRegistryError(f"research registry unreadable: {exc}") from exc
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                raise ResearchRegistryError(f"blank registry line: {line_number}")
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ResearchRegistryError(
                    f"invalid registry JSON at line {line_number}: {exc}"
                ) from exc
            if not isinstance(item, dict):
                raise ResearchRegistryError(f"registry event must be object: {line_number}")
            events.append(item)
        return events

    def verify(self) -> dict[str, Any]:
        events = self._read()
        states: dict[str, dict[str, Any]] = {}
        previous = "0" * 64
        previous_time: datetime | None = None
        for index, event in enumerate(events, 1):
            required = {
                "schema",
                "sequence",
                "event_type",
                "experiment_id",
                "recorded_at",
                "actor_id",
                "payload",
                "previous_event_sha256",
                "event_sha256",
            }
            if set(event) != required:
                raise ResearchRegistryError(f"registry event fields invalid at sequence {index}")
            if event["schema"] != RESEARCH_EVENT_SCHEMA or int(event["sequence"]) != index:
                raise ResearchRegistryError(f"registry sequence/schema invalid at {index}")
            experiment_id = str(event["experiment_id"])
            if not EXPERIMENT_ID_RE.fullmatch(experiment_id):
                raise ResearchRegistryError(f"invalid experiment_id at sequence {index}")
            _nonempty(event["actor_id"], "actor_id")
            recorded_at = _timestamp(str(event["recorded_at"]))
            if previous_time is not None and recorded_at < previous_time:
                raise ResearchRegistryError("registry timestamps are not monotonic")
            if str(event["previous_event_sha256"]) != previous:
                raise ResearchRegistryError(f"registry hash chain broken at sequence {index}")
            identity = {key: value for key, value in event.items() if key != "event_sha256"}
            actual = sha256_digest(identity)
            if str(event["event_sha256"]) != actual:
                raise ResearchRegistryError(f"registry event hash mismatch at sequence {index}")
            _apply_event(states, event)
            previous = actual
            previous_time = recorded_at
        self._verify_completed_artifacts(states)
        identity = {
            "schema": RESEARCH_REGISTRY_STATUS_SCHEMA,
            "verified": True,
            "registry_generation": "LEGACY_V5",
            "family_identity_status": "FAMILY_IDENTITY_INCOMPLETE",
            "evidence_use": "HISTORICAL_ACCOUNTING_ONLY",
            "mutation_allowed": False,
            "formal_admission_eligible": False,
            "event_count": len(events),
            "head_sha256": previous,
            "experiments": [
                _summary(experiment_id, states[experiment_id])
                for experiment_id in sorted(states)
            ],
        }
        return {**identity, "status_sha256": sha256_digest(identity)}

    def _append(
        self,
        event_type: str,
        experiment_id: str,
        actor_id: str,
        payload: Mapping[str, Any],
        *,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        raise ResearchRegistryError(
            "LEGACY_V5_READ_ONLY: v5 mutation is permanently forbidden",
            code="LEGACY_V5_READ_ONLY",
        )

    def register(
        self,
        experiment_id: str,
        registration: Mapping[str, Any],
        *,
        actor_id: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self._mutation_forbidden("v5 registration")
        normalized = _registration(registration)
        if self.catalog is None:
            raise ResearchRegistryError(
                "formal research registration requires platform_root and DataCatalog"
            )
        self._replayer_for(normalized["run_contract"]["engine"])
        self._verify_provider_publication(
            normalized["provider_publication_receipt_sha256"],
            normalized["dataset_manifest_sha256"],
        )
        return self._append(
            "EXPERIMENT_REGISTERED",
            experiment_id,
            actor_id,
            normalized,
            recorded_at=recorded_at,
        )

    def reserve_run(
        self,
        experiment_id: str,
        run_id: str,
        parameters: Mapping[str, Any],
        *,
        actor_id: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self._mutation_forbidden("v5 run reservation")
        return self._append(
            "RUN_RESERVED",
            experiment_id,
            actor_id,
            {"run_id": run_id, "parameters": dict(parameters)},
            recorded_at=recorded_at,
        )

    def complete_run(
        self,
        experiment_id: str,
        run_id: str,
        *,
        artifact_path: str | Path,
        actor_id: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self._mutation_forbidden("v5 run completion")
        events = self._read()
        self.verify()
        states = self._states(events)
        state = states.get(str(experiment_id))
        if state is None:
            raise ResearchRegistryError(f"unknown experiment: {experiment_id}")
        attempt = state["attempts"].get(str(run_id))
        if attempt is None or attempt["status"] != "RESERVED":
            raise ResearchRegistryError("run must be reserved before completion")
        if str(actor_id) != attempt["reserved_by"]:
            raise ResearchRegistryError("run outcome actor must match its reservation")
        registration = state["registration"]
        try:
            artifact = load_research_run_artifact(artifact_path)
            artifact_sha = sha256_digest(artifact)
            artifact_uri = f"artifacts/{artifact_sha}.json"
            provider_verified = self._verify_provider_publication(
                registration["provider_publication_receipt_sha256"],
                registration["dataset_manifest_sha256"],
            )
            catalog_entry = self._verify_catalog_selection(artifact, registration)
            replay_attestation = self._canonical_replay(
                artifact, registration, catalog_entry
            )
            evidence = build_research_run_evidence(
                artifact,
                run_id=run_id,
                registration=registration,
                attempt=attempt,
                artifact_uri=artifact_uri,
                provider_publication_verified=provider_verified,
                canonical_replay_attestation=replay_attestation,
            )
        except ResearchRunEvidenceError as exc:
            raise ResearchRegistryError(str(exc)) from exc
        self._archive_artifact(artifact, artifact_uri)
        return self._append(
            "RUN_COMPLETED",
            experiment_id,
            actor_id,
            {
                "run_id": run_id,
                "evidence": evidence,
            },
            recorded_at=recorded_at,
        )

    def fail_run(
        self,
        experiment_id: str,
        run_id: str,
        *,
        failure_code: str,
        actor_id: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self._mutation_forbidden("v5 run failure")
        return self._append(
            "RUN_FAILED",
            experiment_id,
            actor_id,
            {"run_id": run_id, "failure_code": failure_code},
            recorded_at=recorded_at,
        )

    def seal_development(
        self,
        experiment_id: str,
        *,
        selected_run_id: str,
        declared_total_attempts: int,
        actor_id: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self._mutation_forbidden("v5 development seal")
        return self._append(
            "DEVELOPMENT_SEALED",
            experiment_id,
            actor_id,
            {
                "selected_run_id": selected_run_id,
                "declared_total_attempts": int(declared_total_attempts),
            },
            recorded_at=recorded_at,
        )

    def record_adversarial_audit(
        self,
        experiment_id: str,
        *,
        verdict: str,
        report_sha256: str,
        checks: Sequence[Mapping[str, Any]],
        reviewed_registry_head_sha256: str,
        reviewer_id: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self._mutation_forbidden("v5 adversarial audit")
        return self._append(
            "ADVERSARIAL_AUDIT_RECORDED",
            experiment_id,
            reviewer_id,
            {
                "verdict": verdict,
                "report_sha256": report_sha256,
                "checks": [dict(item) for item in checks],
                "reviewed_registry_head_sha256": reviewed_registry_head_sha256,
            },
            recorded_at=recorded_at,
        )

    def open_lockbox(
        self,
        experiment_id: str,
        *,
        dataset_id: str,
        manifest_sha256: str,
        operator_id: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self._mutation_forbidden("v5 lockbox open")
        return self._append(
            "LOCKBOX_OPENED",
            experiment_id,
            operator_id,
            {"dataset_id": dataset_id, "manifest_sha256": manifest_sha256},
            recorded_at=recorded_at,
        )

    def record_lockbox_result(
        self,
        experiment_id: str,
        *,
        decision: str,
        result_sha256: str,
        report_sha256: str,
        operator_id: str,
        recorded_at: str | None = None,
    ) -> dict[str, Any]:
        self._mutation_forbidden("v5 lockbox result")
        return self._append(
            "LOCKBOX_RESULT_RECORDED",
            experiment_id,
            operator_id,
            {
                "decision": decision,
                "result_sha256": result_sha256,
                "report_sha256": report_sha256,
            },
            recorded_at=recorded_at,
        )
