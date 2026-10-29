"""Frozen baseline and single-variable ablation plans.

The plan is registered before computation.  Every permitted configuration is
explicit, differs from the baseline in exactly one declared parameter, and is
content-addressed so failed variants cannot quietly disappear.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .provenance import sha256_digest


ABLATION_PLAN_SCHEMA = "quant-core/single-variable-ablation-plan/v1"
ABLATION_COMPARISON_RULE = "SAME_DATA_CODE_SPLITS_EXECUTION"
VARIANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class AblationValidationError(ValueError):
    """An ablation plan is ambiguous, incomplete or permits hidden changes."""


def _same(left: Any, right: Any) -> bool:
    return sha256_digest(left) == sha256_digest(right)


def _allowed(value: Any, specification: Mapping[str, Any]) -> bool:
    kind = str(specification.get("type") or "")
    if kind == "choice":
        return any(_same(value, item) for item in specification.get("values") or [])
    if kind == "fixed":
        return _same(value, specification.get("value"))
    if kind == "integer":
        return (
            not isinstance(value, bool)
            and isinstance(value, int)
            and int(specification["minimum"]) <= value <= int(specification["maximum"])
        )
    if kind == "number":
        try:
            number = float(value)
        except (TypeError, ValueError):
            return False
        return (
            math.isfinite(number)
            and float(specification["minimum"])
            <= number
            <= float(specification["maximum"])
        )
    return False


def validate_ablation_plan(
    plan: Mapping[str, Any], parameter_space: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """Validate and normalize a first-order ablation plan."""

    raw = dict(plan)
    expected_fields = {
        "schema",
        "baseline_variant_id",
        "baseline_parameters",
        "variants",
        "comparison_rule",
        "interaction_variants_allowed",
        "plan_sha256",
    }
    if set(raw) != expected_fields:
        raise AblationValidationError("ablation plan fields do not match the frozen schema")
    digest = str(raw.pop("plan_sha256", ""))
    if raw.get("schema") != ABLATION_PLAN_SCHEMA:
        raise AblationValidationError("unsupported ablation plan schema")
    if digest != sha256_digest(raw):
        raise AblationValidationError("ablation plan digest mismatch")
    if raw.get("comparison_rule") != ABLATION_COMPARISON_RULE:
        raise AblationValidationError("ablation comparison rule was weakened")
    if raw.get("interaction_variants_allowed") is not False:
        raise AblationValidationError("first-order ablation cannot include interactions")

    parameter_names = set(parameter_space)
    baseline_id = str(raw.get("baseline_variant_id") or "")
    if not VARIANT_ID_RE.fullmatch(baseline_id):
        raise AblationValidationError("baseline variant id is invalid")
    baseline = dict(raw.get("baseline_parameters") or {})
    if set(baseline) != parameter_names:
        raise AblationValidationError("baseline parameters must cover the frozen parameter space")
    for name, value in baseline.items():
        if not _allowed(value, parameter_space[name]):
            raise AblationValidationError(f"baseline parameter is outside frozen space: {name}")

    variants = list(raw.get("variants") or [])
    if not variants:
        raise AblationValidationError("at least one ablation variant is required")
    normalized_variants: list[dict[str, Any]] = []
    variant_ids = {baseline_id}
    parameter_hashes = {sha256_digest(baseline)}
    for item in variants:
        if not isinstance(item, Mapping) or set(item) != {
            "variant_id",
            "parent_variant_id",
            "changed_parameter",
            "expected_effect",
            "parameters",
        }:
            raise AblationValidationError("ablation variant fields are invalid")
        variant_id = str(item.get("variant_id") or "")
        if not VARIANT_ID_RE.fullmatch(variant_id) or variant_id in variant_ids:
            raise AblationValidationError("ablation variant id is invalid or duplicated")
        if str(item.get("parent_variant_id") or "") != baseline_id:
            raise AblationValidationError("ablation variants must compare directly with baseline")
        parameters = dict(item.get("parameters") or {})
        if set(parameters) != parameter_names:
            raise AblationValidationError("variant parameters must cover the frozen parameter space")
        changed = [
            name for name in sorted(parameter_names) if not _same(parameters[name], baseline[name])
        ]
        declared = str(item.get("changed_parameter") or "")
        if changed != [declared]:
            raise AblationValidationError(
                "each ablation variant must change exactly its one declared parameter"
            )
        if str(parameter_space[declared].get("type") or "") == "fixed":
            raise AblationValidationError("ablation cannot change a fixed parameter")
        if not _allowed(parameters[declared], parameter_space[declared]):
            raise AblationValidationError(
                f"ablation parameter is outside frozen space: {declared}"
            )
        expected_effect = str(item.get("expected_effect") or "").strip()
        if not expected_effect:
            raise AblationValidationError("ablation expected effect must be predeclared")
        parameter_sha = sha256_digest(parameters)
        if parameter_sha in parameter_hashes:
            raise AblationValidationError("ablation parameter set is duplicated")
        parameter_hashes.add(parameter_sha)
        variant_ids.add(variant_id)
        normalized_variants.append(
            {
                "variant_id": variant_id,
                "parent_variant_id": baseline_id,
                "changed_parameter": declared,
                "expected_effect": expected_effect,
                "parameters": parameters,
            }
        )
    identity = {
        "schema": ABLATION_PLAN_SCHEMA,
        "baseline_variant_id": baseline_id,
        "baseline_parameters": baseline,
        "variants": normalized_variants,
        "comparison_rule": ABLATION_COMPARISON_RULE,
        "interaction_variants_allowed": False,
    }
    return {**identity, "plan_sha256": sha256_digest(identity)}


def build_ablation_plan(
    *,
    baseline_variant_id: str,
    baseline_parameters: Mapping[str, Any],
    variants: Sequence[Mapping[str, Any]],
    parameter_space: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    identity = {
        "schema": ABLATION_PLAN_SCHEMA,
        "baseline_variant_id": str(baseline_variant_id),
        "baseline_parameters": dict(baseline_parameters),
        "variants": [dict(item) for item in variants],
        "comparison_rule": ABLATION_COMPARISON_RULE,
        "interaction_variants_allowed": False,
    }
    return validate_ablation_plan(
        {**identity, "plan_sha256": sha256_digest(identity)}, parameter_space
    )


def ablation_variants(plan: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "variant_id": str(plan["baseline_variant_id"]),
            "parameters": dict(plan["baseline_parameters"]),
            "changed_parameter": None,
        },
        *[
            {
                "variant_id": str(item["variant_id"]),
                "parameters": dict(item["parameters"]),
                "changed_parameter": str(item["changed_parameter"]),
            }
            for item in plan["variants"]
        ],
    ]


def match_ablation_variant(plan: Mapping[str, Any], parameters: Mapping[str, Any]) -> str:
    matches = [
        item["variant_id"]
        for item in ablation_variants(plan)
        if _same(item["parameters"], dict(parameters))
    ]
    if len(matches) != 1:
        raise AblationValidationError(
            "reserved parameters do not match exactly one predeclared ablation variant"
        )
    return str(matches[0])
