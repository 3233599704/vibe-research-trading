"""Deterministic statistical evidence for frozen quantitative experiments."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .provenance import sha256_digest


RESEARCH_STATISTICS_SCHEMA = "quant-core/research-statistics/v1"
PARAMETER_SURFACE_SCHEMA = "quant-core/parameter-surface-report/v1"
MULTIPLICITY_REPORT_SCHEMA = "quant-core/holm-bonferroni-report/v1"
HAC_TEST_ID = "HAC_MEAN_EXCESS_RETURN_GREATER_THAN_ZERO"


class ResearchStatisticsError(ValueError):
    """Statistical evidence is non-finite, ambiguous or not reproducible."""


def _finite(value: Any, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ResearchStatisticsError(f"{label} must be numeric") from exc
    if not math.isfinite(number):
        raise ResearchStatisticsError(f"{label} must be finite")
    return number


def _rounded(value: float) -> float:
    return round(float(value), 12)


def _normalized_curve(curve: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    previous_date = ""
    for raw in curve:
        if not isinstance(raw, Mapping):
            raise ResearchStatisticsError("research statistics curve rows must be objects")
        feature_time = str(raw.get("date") or "")
        if not feature_time or feature_time <= previous_date:
            raise ResearchStatisticsError("research statistics curve dates must increase")
        strategy = _finite(raw.get("strategy"), "strategy value")
        benchmark = _finite(raw.get("benchmark"), "benchmark value")
        if strategy <= 0 or benchmark <= 0:
            raise ResearchStatisticsError("research statistics curve values must be positive")
        output.append(
            {"date": feature_time, "strategy": strategy, "benchmark": benchmark}
        )
        previous_date = feature_time
    return output


def build_hac_excess_return_test(
    curve: Sequence[Mapping[str, Any]],
    *,
    sample_scope: str,
    minimum_observations: int = 40,
    maximum_hac_lags: int = 10,
) -> dict[str, Any]:
    """One-sided Newey-West test of positive mean daily excess return."""

    scope = str(sample_scope or "").strip()
    if scope not in {"FROZEN_HOLDOUT_OUT_OF_SAMPLE", "PURGED_WALK_FORWARD"}:
        raise ResearchStatisticsError("unsupported research statistics sample scope")
    minimum = int(minimum_observations)
    maximum = int(maximum_hac_lags)
    if minimum < 20 or maximum < 0 or maximum > 50:
        raise ResearchStatisticsError("research statistics observation/lag contract is invalid")
    normalized = _normalized_curve(curve)
    excess_returns = [
        normalized[index]["strategy"] / normalized[index - 1]["strategy"]
        - normalized[index]["benchmark"] / normalized[index - 1]["benchmark"]
        for index in range(1, len(normalized))
    ]
    count = len(excess_returns)
    mean = sum(excess_returns) / count if count else 0.0
    selected_lags = min(
        maximum,
        max(0, int(math.floor(4 * (count / 100) ** (2 / 9)))) if count else 0,
        max(0, count - 1),
    )
    centered = [value - mean for value in excess_returns]
    long_run_variance = (
        sum(value * value for value in centered) / count if count else 0.0
    )
    for lag in range(1, selected_lags + 1):
        covariance = sum(
            centered[index] * centered[index - lag]
            for index in range(lag, count)
        ) / count
        weight = 1 - lag / (selected_lags + 1)
        long_run_variance += 2 * weight * covariance
    variance_of_mean = max(0.0, long_run_variance / count) if count else 0.0
    standard_error = math.sqrt(variance_of_mean)
    valid = count >= minimum and standard_error > 1e-15
    statistic = mean / standard_error if valid else None
    p_value = (
        0.5 * math.erfc(float(statistic) / math.sqrt(2))
        if statistic is not None
        else None
    )
    identity = {
        "schema": RESEARCH_STATISTICS_SCHEMA,
        "test_id": HAC_TEST_ID,
        "sample_scope": scope,
        "minimum_observations": minimum,
        "maximum_hac_lags": maximum,
        "selected_hac_lags": selected_lags,
        "observation_count": count,
        "source_curve_sha256": sha256_digest(normalized),
        "mean_daily_excess_return": _rounded(mean),
        "hac_standard_error": _rounded(standard_error),
        "test_statistic": _rounded(statistic) if statistic is not None else None,
        "one_sided_p_value": _rounded(p_value) if p_value is not None else None,
        "status": "PASS" if valid else "INSUFFICIENT_EVIDENCE",
    }
    return {**identity, "attestation_sha256": sha256_digest(identity)}


def verify_research_statistics(
    attestation: Mapping[str, Any], curve: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    candidate = dict(attestation)
    digest = str(candidate.pop("attestation_sha256", ""))
    errors: list[str] = []
    if candidate.get("schema") != RESEARCH_STATISTICS_SCHEMA:
        errors.append("unsupported research statistics schema")
    if digest != sha256_digest(candidate):
        errors.append("research statistics digest mismatch")
    try:
        rebuilt = build_hac_excess_return_test(
            curve,
            sample_scope=str(candidate.get("sample_scope") or ""),
            minimum_observations=int(candidate.get("minimum_observations")),
            maximum_hac_lags=int(candidate.get("maximum_hac_lags")),
        )
    except (ResearchStatisticsError, TypeError, ValueError) as exc:
        errors.append(f"research statistics reproduction failed: {exc}")
    else:
        if rebuilt != dict(attestation):
            errors.append("research statistics do not match curve reproduction")
    return {
        "verified": not errors,
        "attestation_sha256": digest,
        "errors": errors,
        "attestation": dict(attestation),
    }


def build_holm_bonferroni_report(
    hypotheses: Sequence[Mapping[str, Any]], *, alpha: float
) -> dict[str, Any]:
    threshold = _finite(alpha, "alpha")
    if not 0 < threshold < 1:
        raise ResearchStatisticsError("alpha must be between zero and one")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in hypotheses:
        hypothesis_id = str(raw.get("hypothesis_id") or "").strip()
        p_value = _finite(raw.get("raw_p_value"), "raw p-value")
        if not hypothesis_id or hypothesis_id in seen or not 0 <= p_value <= 1:
            raise ResearchStatisticsError("hypothesis ids/p-values are invalid")
        seen.add(hypothesis_id)
        normalized.append({"hypothesis_id": hypothesis_id, "raw_p_value": p_value})
    if len(normalized) < 2:
        raise ResearchStatisticsError("multiplicity correction requires at least two hypotheses")
    ordered = sorted(normalized, key=lambda item: (item["raw_p_value"], item["hypothesis_id"]))
    running_adjusted = 0.0
    rows: list[dict[str, Any]] = []
    family_size = len(ordered)
    for index, item in enumerate(ordered):
        adjusted = min(1.0, (family_size - index) * item["raw_p_value"])
        running_adjusted = max(running_adjusted, adjusted)
        rows.append(
            {
                "hypothesis_id": item["hypothesis_id"],
                "rank": index + 1,
                "raw_p_value": _rounded(item["raw_p_value"]),
                "adjusted_p_value": _rounded(running_adjusted),
                "rejected": running_adjusted <= threshold,
            }
        )
    identity = {
        "schema": MULTIPLICITY_REPORT_SCHEMA,
        "method": "HOLM_BONFERRONI",
        "family_definition": "ALL_PREDECLARED_ABLATION_VARIANTS",
        "family_size": family_size,
        "alpha": threshold,
        "hypotheses": rows,
    }
    return {**identity, "report_sha256": sha256_digest(identity)}


def build_parameter_surface_report(
    points: Sequence[Mapping[str, Any]],
    *,
    parameter_name: str,
    metric_name: str,
    selected_value: Any,
    sample_scope: str,
    maximum_neighbor_degradation: float,
) -> dict[str, Any]:
    """Detect whether a selected numeric parameter is an isolated metric spike."""

    tolerance = _finite(maximum_neighbor_degradation, "neighbor degradation")
    if tolerance < 0:
        raise ResearchStatisticsError("neighbor degradation cannot be negative")
    normalized: list[dict[str, Any]] = []
    seen: set[float] = set()
    for raw in points:
        value = _finite(raw.get("value"), "parameter value")
        metric = _finite(raw.get("metric"), "parameter metric")
        if value in seen:
            raise ResearchStatisticsError("parameter surface values must be unique")
        seen.add(value)
        normalized.append({"value": value, "metric": metric})
    normalized.sort(key=lambda item: item["value"])
    selected = _finite(selected_value, "selected parameter")
    selected_index = next(
        (index for index, item in enumerate(normalized) if item["value"] == selected),
        None,
    )
    neighbors: list[dict[str, Any]] = []
    if selected_index is not None:
        if selected_index > 0:
            neighbors.append(normalized[selected_index - 1])
        if selected_index + 1 < len(normalized):
            neighbors.append(normalized[selected_index + 1])
    selected_metric = (
        normalized[selected_index]["metric"] if selected_index is not None else None
    )
    degradations = (
        [float(selected_metric) - item["metric"] for item in neighbors]
        if selected_metric is not None
        else []
    )
    evaluated = len(normalized) >= 3 and selected_index is not None and bool(neighbors)
    supported = evaluated and any(value <= tolerance for value in degradations)
    identity = {
        "schema": PARAMETER_SURFACE_SCHEMA,
        "parameter_name": str(parameter_name),
        "metric_name": str(metric_name),
        "metric_direction": "MAXIMIZE",
        "sample_scope": str(sample_scope),
        "selected_value": selected,
        "selected_metric": _rounded(selected_metric) if selected_metric is not None else None,
        "maximum_neighbor_degradation": tolerance,
        "points": [
            {"value": _rounded(item["value"]), "metric": _rounded(item["metric"])}
            for item in normalized
        ],
        "neighbors": [
            {"value": _rounded(item["value"]), "metric": _rounded(item["metric"])}
            for item in neighbors
        ],
        "neighbor_supported": bool(supported),
        "isolated_spike": bool(evaluated and not supported),
        "status": "PASS" if supported else ("FAIL" if evaluated else "NOT_EVALUATED"),
        "promotion_eligible": False,
    }
    return {**identity, "report_sha256": sha256_digest(identity)}
