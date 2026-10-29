"""Deterministic, hand-computable factor fixtures.

Backtest performance is not evidence that factor code is correct.  These
fixtures exercise grouping, ordering, lag direction, missing history and future
isolation independently from portfolio construction and execution.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from datetime import date, timedelta
from typing import Any

from .provenance import sha256_digest


FACTOR_FIXTURE_SCHEMA = "quant-core/factor-fixture/v1"
FACTOR_VALIDATION_ATTESTATION_SCHEMA = (
    "quant-core/factor-validation-attestation/v1"
)
GROUPED_LAG_RETURN_EVALUATOR_ID = "quant-core/grouped-lag-return/v1"
REQUIRED_FACTOR_CHECKS = (
    "HAND_COMPUTED_EXPECTATIONS",
    "DETERMINISTIC_REPLAY",
    "INPUT_ORDER_INVARIANCE",
    "TEMPORAL_PREFIX_INVARIANCE",
    "CROSS_ASSET_ISOLATION",
    "INSUFFICIENT_HISTORY_NULL",
    "NON_FINITE_INPUT_REJECTED",
)


class FactorValidationError(ValueError):
    """A factor fixture or evaluator violates the deterministic contract."""


FactorEvaluator = Callable[[Sequence[Mapping[str, Any]]], list[dict[str, Any]]]


def _finite(value: Any, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise FactorValidationError(f"{label} must be numeric") from exc
    if not math.isfinite(number):
        raise FactorValidationError(f"{label} must be finite")
    return number


def lagged_return(current: Any, previous: Any) -> float:
    current_value = _finite(current, "current value")
    previous_value = _finite(previous, "lagged value")
    if current_value <= 0 or previous_value <= 0:
        raise FactorValidationError("lagged-return inputs must be positive")
    return current_value / previous_value - 1.0


def evaluate_grouped_lag_return(
    rows: Sequence[Mapping[str, Any]],
    *,
    lookback_sessions: int,
    group_field: str = "code",
    time_field: str = "date",
    value_field: str = "close",
) -> list[dict[str, Any]]:
    """Return one factor row per observation without crossing asset boundaries."""

    lookback = int(lookback_sessions)
    if lookback < 1:
        raise FactorValidationError("lookback_sessions must be positive")
    grouped: dict[str, list[dict[str, Any]]] = {}
    seen: set[tuple[str, str]] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise FactorValidationError("factor input row must be an object")
        row = dict(raw)
        code = str(row.get(group_field) or "").strip()
        feature_time = str(row.get(time_field) or "").strip()
        if not code or not feature_time:
            raise FactorValidationError("factor group and time fields are required")
        value = _finite(row.get(value_field), f"{code}:{feature_time}:{value_field}")
        if value <= 0:
            raise FactorValidationError("factor price-like input must be positive")
        identity = (code, feature_time)
        if identity in seen:
            raise FactorValidationError("factor input contains duplicate group/time rows")
        seen.add(identity)
        grouped.setdefault(code, []).append(
            {"code": code, "feature_time": feature_time, "value": value}
        )

    output: list[dict[str, Any]] = []
    for code in sorted(grouped):
        observations = sorted(grouped[code], key=lambda item: item["feature_time"])
        if [item["feature_time"] for item in observations] != sorted(
            {item["feature_time"] for item in observations}
        ):
            raise FactorValidationError("factor observation times must be unique")
        for index, item in enumerate(observations):
            value = (
                None
                if index < lookback
                else lagged_return(item["value"], observations[index - lookback]["value"])
            )
            output.append(
                {
                    "code": code,
                    "feature_time": item["feature_time"],
                    "value": value,
                }
            )
    return output


def build_grouped_lag_return_fixture(lookback_sessions: int) -> dict[str, Any]:
    """Create a two-asset fixture whose expected values are computed from the formula."""

    lookback = int(lookback_sessions)
    if lookback < 1 or lookback > 252:
        raise FactorValidationError("fixture lookback must be between 1 and 252")
    count = lookback + 3
    start = date(2024, 1, 2)
    days = [(start + timedelta(days=index)).isoformat() for index in range(count)]
    rows: list[dict[str, Any]] = []
    expected: list[dict[str, Any]] = []
    series = {
        "ASSET_A": [100.0 + index * 2.0 for index in range(count)],
        "ASSET_B": [200.0 - index * 1.5 for index in range(count)],
    }
    for code in sorted(series):
        values = series[code]
        for index, feature_time in enumerate(days):
            rows.append({"code": code, "date": feature_time, "close": values[index]})
            expected.append(
                {
                    "code": code,
                    "feature_time": feature_time,
                    "value": (
                        None
                        if index < lookback
                        else values[index] / values[index - lookback] - 1.0
                    ),
                }
            )
    # Deliberately scramble source order; a correct evaluator sorts within code.
    rows = list(reversed(rows[1::2])) + list(reversed(rows[::2]))
    identity = {
        "schema": FACTOR_FIXTURE_SCHEMA,
        "fixture_id": f"grouped-lag-return-{lookback}-sessions",
        "factor_id": GROUPED_LAG_RETURN_EVALUATOR_ID,
        "formula": "value(t) / value(t-lookback_sessions) - 1",
        "group_field": "code",
        "time_field": "date",
        "value_field": "close",
        "lookback_sessions": lookback,
        "missing_history_policy": "NULL_UNTIL_FULL_LOOKBACK",
        "value_tolerance": 1e-12,
        "input_rows": rows,
        "expected_rows": sorted(
            expected, key=lambda item: (item["code"], item["feature_time"])
        ),
    }
    return {**identity, "fixture_sha256": sha256_digest(identity)}


def _normalize_output(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for raw in rows:
        if not isinstance(raw, Mapping) or set(raw) != {"code", "feature_time", "value"}:
            raise FactorValidationError("factor output fields must be code, feature_time and value")
        code = str(raw.get("code") or "").strip()
        feature_time = str(raw.get("feature_time") or "").strip()
        if not code or not feature_time or (code, feature_time) in identities:
            raise FactorValidationError("factor output identities are invalid")
        identities.add((code, feature_time))
        value = raw.get("value")
        normalized.append(
            {
                "code": code,
                "feature_time": feature_time,
                "value": None if value is None else _finite(value, "factor output"),
            }
        )
    return sorted(normalized, key=lambda item: (item["code"], item["feature_time"]))


def _outputs_equal(
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
    tolerance: float,
) -> bool:
    lhs = _normalize_output(left)
    rhs = _normalize_output(right)
    if len(lhs) != len(rhs):
        return False
    for actual, expected in zip(lhs, rhs, strict=True):
        if (actual["code"], actual["feature_time"]) != (
            expected["code"],
            expected["feature_time"],
        ):
            return False
        if actual["value"] is None or expected["value"] is None:
            if actual["value"] is not None or expected["value"] is not None:
                return False
        elif abs(float(actual["value"]) - float(expected["value"])) > tolerance:
            return False
    return True


def validate_factor_fixture(
    fixture: Mapping[str, Any], evaluator: FactorEvaluator
) -> dict[str, Any]:
    """Run the full deterministic factor audit and return a self-hashed attestation."""

    candidate = dict(fixture)
    fixture_sha = str(candidate.pop("fixture_sha256", ""))
    if candidate.get("schema") != FACTOR_FIXTURE_SCHEMA:
        raise FactorValidationError("unsupported factor fixture schema")
    if fixture_sha != sha256_digest(candidate):
        raise FactorValidationError("factor fixture digest mismatch")
    inputs = [dict(item) for item in candidate.get("input_rows") or []]
    expected = [dict(item) for item in candidate.get("expected_rows") or []]
    if not inputs or not expected:
        raise FactorValidationError("factor fixture inputs and expectations are required")
    tolerance = _finite(candidate.get("value_tolerance"), "value_tolerance")
    if tolerance < 0:
        raise FactorValidationError("value_tolerance cannot be negative")

    failures: dict[str, str] = {}

    def evaluate(rows: Sequence[Mapping[str, Any]], label: str) -> list[dict[str, Any]]:
        try:
            return _normalize_output(evaluator(rows))
        except Exception as exc:  # noqa: BLE001 - captured as deterministic audit evidence
            failures.setdefault(label, f"{type(exc).__name__}: {exc}")
            return []

    actual = evaluate(inputs, "HAND_COMPUTED_EXPECTATIONS")
    check_results: dict[str, bool] = {
        "HAND_COMPUTED_EXPECTATIONS": _outputs_equal(actual, expected, tolerance),
        "DETERMINISTIC_REPLAY": _outputs_equal(
            actual, evaluate(inputs, "DETERMINISTIC_REPLAY"), tolerance
        ),
        "INPUT_ORDER_INVARIANCE": _outputs_equal(
            actual,
            evaluate(list(reversed(inputs)), "INPUT_ORDER_INVARIANCE"),
            tolerance,
        ),
    }

    times = sorted({str(item[candidate["time_field"]]) for item in inputs})
    cutoff = times[-2]
    prefix_inputs = [
        item for item in inputs if str(item[candidate["time_field"]]) <= cutoff
    ]
    prefix_expected = [item for item in actual if item["feature_time"] <= cutoff]
    check_results["TEMPORAL_PREFIX_INVARIANCE"] = _outputs_equal(
        prefix_expected,
        evaluate(prefix_inputs, "TEMPORAL_PREFIX_INVARIANCE"),
        tolerance,
    )

    codes = sorted({str(item[candidate["group_field"]]) for item in inputs})
    isolated_ok = len(codes) >= 2
    for code in codes:
        isolated_inputs = [
            item for item in inputs if str(item[candidate["group_field"]]) == code
        ]
        isolated_expected = [item for item in actual if item["code"] == code]
        isolated_ok = isolated_ok and _outputs_equal(
            isolated_expected,
            evaluate(isolated_inputs, "CROSS_ASSET_ISOLATION"),
            tolerance,
        )
    check_results["CROSS_ASSET_ISOLATION"] = isolated_ok
    check_results["INSUFFICIENT_HISTORY_NULL"] = bool(actual) and all(
        sum(
            item["value"] is None for item in actual if item["code"] == code
        )
        == int(candidate["lookback_sessions"])
        for code in codes
    )

    nonfinite_rows = [dict(item) for item in inputs]
    nonfinite_rows[0][candidate["value_field"]] = float("nan")
    try:
        evaluator(nonfinite_rows)
    except (FactorValidationError, ValueError, TypeError):
        nonfinite_rejected = True
    else:
        nonfinite_rejected = False
    check_results["NON_FINITE_INPUT_REJECTED"] = nonfinite_rejected

    checks = [
        {
            "code": code,
            "passed": check_results.get(code) is True,
            "evidence": failures.get(code) or (
                "deterministic comparison passed"
                if check_results.get(code) is True
                else "deterministic comparison failed"
            ),
        }
        for code in REQUIRED_FACTOR_CHECKS
    ]
    identity = {
        "schema": FACTOR_VALIDATION_ATTESTATION_SCHEMA,
        "fixture_id": candidate["fixture_id"],
        "fixture_sha256": fixture_sha,
        "factor_id": candidate["factor_id"],
        "lookback_sessions": int(candidate["lookback_sessions"]),
        "input_row_count": len(inputs),
        "output_sha256": sha256_digest(actual),
        "checks": checks,
        "status": "PASS" if all(item["passed"] for item in checks) else "FAIL",
    }
    return {**identity, "attestation_sha256": sha256_digest(identity)}


def validate_grouped_lag_return_factor(lookback_sessions: int) -> dict[str, Any]:
    fixture = build_grouped_lag_return_fixture(lookback_sessions)
    return validate_factor_fixture(
        fixture,
        lambda rows: evaluate_grouped_lag_return(
            rows, lookback_sessions=int(lookback_sessions)
        ),
    )


def verify_factor_validation_attestation(
    attestation: Mapping[str, Any],
    *,
    fixture: Mapping[str, Any] | None = None,
    require_reproduction: bool = False,
) -> dict[str, Any]:
    candidate = dict(attestation)
    digest = str(candidate.pop("attestation_sha256", ""))
    errors: list[str] = []
    if candidate.get("schema") != FACTOR_VALIDATION_ATTESTATION_SCHEMA:
        errors.append("unsupported factor validation attestation schema")
    if digest != sha256_digest(candidate):
        errors.append("factor validation attestation digest mismatch")
    checks = list(candidate.get("checks") or [])
    if [item.get("code") for item in checks] != list(REQUIRED_FACTOR_CHECKS):
        errors.append("factor validation check set is incomplete or reordered")
    if any(item.get("passed") is not True for item in checks):
        errors.append("factor validation contains failed checks")
    if candidate.get("status") != "PASS":
        errors.append("factor validation status is not PASS")
    if fixture is not None:
        fixture_candidate = dict(fixture)
        fixture_sha = str(fixture_candidate.pop("fixture_sha256", ""))
        if fixture_sha != sha256_digest(fixture_candidate):
            errors.append("factor fixture digest mismatch")
        if candidate.get("fixture_sha256") != fixture_sha:
            errors.append("factor attestation references a different fixture")
    if require_reproduction and not errors:
        factor_id = str(candidate.get("factor_id") or "")
        if factor_id != GROUPED_LAG_RETURN_EVALUATOR_ID:
            errors.append("factor evaluator is not reproducible by this engine")
        else:
            try:
                reproduced = validate_grouped_lag_return_factor(
                    int(candidate.get("lookback_sessions") or 0)
                )
            except (FactorValidationError, TypeError, ValueError) as exc:
                errors.append(f"factor attestation reproduction failed: {exc}")
            else:
                if reproduced != dict(attestation):
                    errors.append("factor attestation does not match engine reproduction")
    return {
        "verified": not errors,
        "attestation_sha256": digest,
        "errors": errors,
        "attestation": dict(attestation),
    }
