"""Deterministic frozen-holdout stress evidence for registered research."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

from .provenance import sha256_digest


RESEARCH_ROBUSTNESS_SCHEMA = "quant-core/research-robustness-attestation/v1"
REQUIRED_ROBUSTNESS_SCENARIOS = (
    "DOUBLE_TRADING_COSTS",
    "HALF_VOLUME_CAPACITY",
    "EXTRA_EXECUTION_DAY",
    "DETERMINISTIC_ASSET_GAPS",
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ResearchRobustnessError(RuntimeError):
    """Frozen robustness evidence is incomplete, non-finite or inconsistent."""


def _finite(value: Any, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ResearchRobustnessError(f"{label} must be numeric") from exc
    if not math.isfinite(number):
        raise ResearchRobustnessError(f"{label} must be finite")
    return number


def build_research_robustness_attestation(
    baseline_metrics: Mapping[str, Any],
    scenarios: Sequence[Mapping[str, Any]],
    *,
    sample_scope: str,
    maximum_return_degradation_pct: float = 10.0,
    maximum_drawdown_worsening_pct: float = 5.0,
) -> dict[str, Any]:
    if sample_scope != "FROZEN_HOLDOUT_OUT_OF_SAMPLE":
        raise ResearchRobustnessError("formal robustness requires the frozen holdout")
    max_return_loss = _finite(
        maximum_return_degradation_pct, "maximum return degradation"
    )
    max_drawdown_loss = _finite(
        maximum_drawdown_worsening_pct, "maximum drawdown worsening"
    )
    if max_return_loss < 0 or max_drawdown_loss < 0:
        raise ResearchRobustnessError("robustness thresholds cannot be negative")
    baseline_return = _finite(
        baseline_metrics.get("total_return_pct"), "baseline total return"
    )
    baseline_drawdown = _finite(
        baseline_metrics.get("max_drawdown_pct"), "baseline drawdown"
    )
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in scenarios:
        scenario_id = str(raw.get("scenario_id") or "")
        if scenario_id in seen or scenario_id not in REQUIRED_ROBUSTNESS_SCENARIOS:
            raise ResearchRobustnessError("robustness scenario id is invalid")
        seen.add(scenario_id)
        metrics = dict(raw.get("metrics") or {})
        stressed_return = _finite(
            metrics.get("total_return_pct"), f"{scenario_id} total return"
        )
        stressed_drawdown = _finite(
            metrics.get("max_drawdown_pct"), f"{scenario_id} drawdown"
        )
        reconciliation_failures = int(raw.get("reconciliation_failures") or 0)
        return_degradation = baseline_return - stressed_return
        drawdown_worsening = abs(stressed_drawdown) - abs(baseline_drawdown)
        passed = (
            return_degradation <= max_return_loss + 1e-12
            and drawdown_worsening <= max_drawdown_loss + 1e-12
            and reconciliation_failures == 0
        )
        rows.append(
            {
                "scenario_id": scenario_id,
                "contract": dict(raw.get("contract") or {}),
                "total_return_pct": round(stressed_return, 6),
                "max_drawdown_pct": round(stressed_drawdown, 6),
                "return_degradation_pct": round(return_degradation, 6),
                "drawdown_worsening_pct": round(drawdown_worsening, 6),
                "trade_count": int(metrics.get("trade_count") or 0),
                "reconciliation_failures": reconciliation_failures,
                "curve_sha256": str(raw.get("curve_sha256") or ""),
                "error": (
                    str(raw.get("error")) if raw.get("error") is not None else None
                ),
                "status": "PASS" if passed else "FAIL",
            }
        )
        if not SHA256_RE.fullmatch(rows[-1]["curve_sha256"]):
            raise ResearchRobustnessError(
                f"{scenario_id} curve_sha256 must be a lowercase sha256"
            )
        if rows[-1]["error"] is not None:
            rows[-1]["status"] = "FAIL"
    if seen != set(REQUIRED_ROBUSTNESS_SCENARIOS):
        missing = sorted(set(REQUIRED_ROBUSTNESS_SCENARIOS) - seen)
        raise ResearchRobustnessError(
            "robustness scenario family is incomplete: " + ", ".join(missing)
        )
    rows.sort(key=lambda item: REQUIRED_ROBUSTNESS_SCENARIOS.index(item["scenario_id"]))
    identity = {
        "schema": RESEARCH_ROBUSTNESS_SCHEMA,
        "sample_scope": sample_scope,
        "required_scenarios": list(REQUIRED_ROBUSTNESS_SCENARIOS),
        "maximum_return_degradation_pct": max_return_loss,
        "maximum_drawdown_worsening_pct": max_drawdown_loss,
        "baseline": {
            "total_return_pct": round(baseline_return, 6),
            "max_drawdown_pct": round(baseline_drawdown, 6),
        },
        "scenarios": rows,
        "status": "PASS" if all(row["status"] == "PASS" for row in rows) else "FAIL",
        "promotion_eligible": False,
    }
    return {**identity, "attestation_sha256": sha256_digest(identity)}


def verify_research_robustness_attestation(
    attestation: Mapping[str, Any],
) -> dict[str, Any]:
    candidate = dict(attestation)
    digest = str(candidate.pop("attestation_sha256", ""))
    errors: list[str] = []
    if candidate.get("schema") != RESEARCH_ROBUSTNESS_SCHEMA:
        errors.append("unsupported research robustness schema")
    if digest != sha256_digest(candidate):
        errors.append("research robustness digest mismatch")
    if candidate.get("required_scenarios") != list(REQUIRED_ROBUSTNESS_SCENARIOS):
        errors.append("research robustness scenario family changed")
    if candidate.get("sample_scope") != "FROZEN_HOLDOUT_OUT_OF_SAMPLE":
        errors.append("research robustness did not use the frozen holdout")
    if candidate.get("promotion_eligible") is not False:
        errors.append("standalone robustness evidence cannot authorize promotion")
    rows = candidate.get("scenarios")
    if not isinstance(rows, list) or len(rows) != len(REQUIRED_ROBUSTNESS_SCENARIOS):
        errors.append("research robustness scenario rows are incomplete")
    else:
        scenario_ids = [str(row.get("scenario_id") or "") for row in rows if isinstance(row, Mapping)]
        if scenario_ids != list(REQUIRED_ROBUSTNESS_SCENARIOS):
            errors.append("research robustness scenario order or identity changed")
        for row in rows:
            if not isinstance(row, Mapping):
                errors.append("research robustness scenario row is invalid")
                continue
            scenario_id = str(row.get("scenario_id") or "unknown")
            if row.get("status") != "PASS":
                errors.append(f"{scenario_id} robustness scenario did not pass")
            if int(row.get("reconciliation_failures") or 0) != 0:
                errors.append(f"{scenario_id} has reconciliation failures")
            if row.get("error") is not None:
                errors.append(f"{scenario_id} recorded an execution error")
            if not SHA256_RE.fullmatch(str(row.get("curve_sha256") or "")):
                errors.append(f"{scenario_id} curve digest is invalid")
            for field in (
                "total_return_pct",
                "max_drawdown_pct",
                "return_degradation_pct",
                "drawdown_worsening_pct",
            ):
                try:
                    if not math.isfinite(float(row.get(field))):
                        raise ValueError
                except (TypeError, ValueError):
                    errors.append(f"{scenario_id} {field} is not finite")
    if candidate.get("status") != "PASS":
        errors.append("research robustness gate did not pass")
    return {
        "verified": not errors,
        "attestation_sha256": digest,
        "errors": errors,
        "attestation": dict(attestation),
    }
