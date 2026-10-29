"""Deterministic forward-only signal engines.

The engines in this module make no historical performance claim. They consume
content-addressed, point-in-time inputs and return a decision that can be
recomputed exactly from the frozen strategy and catalog revisions.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Mapping, Sequence

from .forward_paper import (
    FORWARD_SIGNAL_SCHEMA,
    ForwardDataError,
    ForwardPaperRunner,
)


DIVERSIFIED_ETF_TREND_ENGINE = "quant-platform/diversified-etf-trend/v1"
FORWARD_MULTIFACTOR_ENGINE = (
    "quant-platform/forward-only-multifactor-risk-overlay/v1"
)
ETF_QFQ_INPUT_SCHEMA = (
    "quant-platform/point-in-time-etf-qfq-close-proxy/v1"
)
ETF_TREND_DECISION_SCHEMA = "quant-platform/diversified-etf-trend-decision/v1"
STOCK_FACTOR_INPUT_SCHEMA = (
    "quant-platform/point-in-time-stock-multifactor-input/v1"
)
STOCK_FACTOR_DECISION_SCHEMA = (
    "quant-platform/forward-only-multifactor-risk-overlay-decision/v1"
)
MULTIHORIZON_VOLATILITY_BRAKE_ENGINE = (
    "quant-platform/multi-horizon-volatility-brake/v1"
)
ETF_MULTIHORIZON_INPUT_SCHEMA = (
    "quant-platform/point-in-time-etf-multihorizon-input/v1"
)
MULTIHORIZON_VOLATILITY_BRAKE_DECISION_SCHEMA = (
    "quant-platform/multi-horizon-volatility-brake-decision/v1"
)
I7_FACTOR_DEFINITIONS = {
    "trend": "qfq_close_t / mean(qfq_close_t_minus_119_to_t) - 1",
    "momentum_6_1": "qfq_close_t_minus_20 / qfq_close_t_minus_125 - 1",
    "value_cheap": "latest_book_to_price_published_and_available_before_signal_cutoff",
    "low_volatility": "negative_sample_std_of_last_60_daily_qfq_returns_times_sqrt_252",
    "liquidity": "natural_log_of_last_20_session_mean_amount",
    "risk_control": "negative_maximum_drawdown_of_last_60_qfq_closes",
}
I7_FACTOR_WEIGHTS = {
    "trend": 0.20,
    "momentum_6_1": 0.20,
    "value_cheap": 0.20,
    "low_volatility": 0.25,
    "liquidity": 0.05,
    "risk_control": 0.10,
}


def _day(value: Any) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ForwardDataError(f"invalid ISO date in signal input: {value}") from exc


def _timestamp(value: str | datetime) -> datetime:
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise ForwardDataError(f"invalid signal-generation timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ForwardDataError("signal-generation timestamp must include a timezone")
    return parsed


def _finite_positive(value: Any, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ForwardDataError(f"{label} must be numeric") from exc
    if not math.isfinite(number) or number <= 0:
        raise ForwardDataError(f"{label} must be finite and positive")
    return number


def _finite(value: Any, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ForwardDataError(f"{label} must be numeric") from exc
    if not math.isfinite(number):
        raise ForwardDataError(f"{label} must be finite")
    return number


@dataclass(frozen=True)
class ForwardTargetDecision:
    target_codes: tuple[str, ...]
    target_weights: dict[str, float]
    evidence: dict[str, Any]


def _series_closes(
    *,
    code: str,
    rows: Sequence[Mapping[str, Any]],
    price_field: str,
    required_dates: Sequence[date],
) -> list[float]:
    parsed_dates: list[date] = []
    closes: list[float] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping):
            raise ForwardDataError(f"series row must be an object: {code}[{index}]")
        if set(raw) != {"date", price_field}:
            raise ForwardDataError(
                f"series row fields do not match the frozen schema: {code}[{index}]"
            )
        parsed_dates.append(_day(raw.get("date")))
        closes.append(_finite_positive(raw.get(price_field), f"{code}.{price_field}"))
    if parsed_dates != sorted(parsed_dates) or len(parsed_dates) != len(set(parsed_dates)):
        raise ForwardDataError(f"series dates must be unique and sorted for {code}")
    window = list(required_dates)
    if parsed_dates[-len(window) :] != window:
        raise ForwardDataError(
            f"series does not cover the exact required trading sessions for {code}"
        )
    return closes[-len(window) :]


def build_diversified_etf_trend_decision(
    strategy_config: Mapping[str, Any],
    signal_input: Mapping[str, Any],
    calendar: Mapping[str, Any],
    *,
    signal_date: str | date,
) -> ForwardTargetDecision:
    """Build P1 targets without using any state or post-signal information."""
    day = _day(signal_date)
    engine = dict(strategy_config.get("signal_engine") or {})
    if engine.get("id") != DIVERSIFIED_ETF_TREND_ENGINE:
        raise ForwardDataError("strategy does not use the supported P1 signal engine")
    if signal_input.get("schema") != ETF_QFQ_INPUT_SCHEMA:
        raise ForwardDataError("unsupported point-in-time ETF qfq signal input schema")
    if _day(signal_input.get("as_of_date")) != day:
        raise ForwardDataError("ETF signal input as_of_date mismatch")
    if _day(signal_input.get("max_event_date")) > day:
        raise ForwardDataError("ETF signal input contains future events")

    calendar_dates = sorted(
        {_day(value) for value in list(calendar.get("trading_dates") or [])}
    )
    if day not in calendar_dates:
        raise ForwardDataError("signal date is absent from the approved calendar")
    horizons = tuple(int(value) for value in engine.get("return_horizons_trading_days") or ())
    moving_average = int(engine.get("moving_average_trading_days") or 0)
    volatility_window = int(engine.get("volatility_trading_days") or 0)
    if horizons != (60, 120) or moving_average != 120 or volatility_window != 20:
        raise ForwardDataError("P1 signal horizons drifted from the frozen design")
    required_observations = max(max(horizons) + 1, moving_average, volatility_window + 1)
    available_dates = [value for value in calendar_dates if value <= day]
    if len(available_dates) < required_observations:
        raise ForwardDataError("approved calendar has insufficient P1 lookback")
    required_dates = available_dates[-required_observations:]

    universe = list(strategy_config.get("universe") or [])
    expected_codes = [str(item.get("code") or "") for item in universe]
    if not expected_codes or len(expected_codes) != len(set(expected_codes)):
        raise ForwardDataError("P1 universe is empty or contains duplicates")
    if any(str(item.get("risk_group") or "") == "" for item in universe):
        raise ForwardDataError("every P1 asset needs a risk group")
    series = dict(signal_input.get("series") or {})
    if set(series) != set(expected_codes):
        raise ForwardDataError("ETF signal input must contain exactly the frozen universe")

    price_field = str(engine.get("price_field") or "")
    volatility_floor = _finite_positive(
        engine.get("volatility_floor"), "volatility_floor"
    )
    rankings: list[dict[str, Any]] = []
    for item in universe:
        code = str(item["code"])
        closes = _series_closes(
            code=code,
            rows=list(series[code] or []),
            price_field=price_field,
            required_dates=required_dates,
        )
        latest = closes[-1]
        returns = {
            horizon: latest / closes[-horizon - 1] - 1.0 for horizon in horizons
        }
        average = statistics.fmean(closes[-moving_average:])
        daily_returns = [
            closes[index] / closes[index - 1] - 1.0
            for index in range(len(closes) - volatility_window, len(closes))
        ]
        volatility = statistics.stdev(daily_returns)
        if not math.isfinite(volatility) or volatility < 0:
            raise ForwardDataError(f"invalid trailing volatility for {code}")
        reasons: list[str] = []
        if any(value <= 0 for value in returns.values()):
            reasons.append("NONPOSITIVE_ABSOLUTE_MOMENTUM")
        if latest <= average:
            reasons.append("BELOW_MOVING_AVERAGE")
        score = min(returns.values()) / max(volatility, volatility_floor)
        rankings.append(
            {
                "code": code,
                "risk_group": str(item["risk_group"]),
                "eligible": not reasons,
                "rejection_reasons": reasons,
                "return_60": round(returns[60], 10),
                "return_120": round(returns[120], 10),
                "moving_average_120": round(average, 10),
                "latest_qfq_close_proxy": round(latest, 10),
                "daily_volatility_20": round(volatility, 10),
                "score": round(score, 10),
            }
        )
    rankings.sort(key=lambda item: (-float(item["score"]), str(item["code"])))

    best_by_group: dict[str, dict[str, Any]] = {}
    for item in rankings:
        if item["eligible"] and item["risk_group"] not in best_by_group:
            best_by_group[str(item["risk_group"])] = item
    group_candidates = sorted(
        best_by_group.values(),
        key=lambda item: (-float(item["score"]), str(item["code"])),
    )
    selection = dict(strategy_config.get("selection") or {})
    top_k = int(selection.get("top_k") or 0)
    minimum_groups = int(selection.get("minimum_eligible_risk_groups") or 0)
    if top_k != 2 or minimum_groups != 2 or not selection.get("unique_risk_group"):
        raise ForwardDataError("P1 diversification rule drifted from the frozen design")
    selected = group_candidates[:top_k] if len(group_candidates) >= minimum_groups else []

    position_rules = dict(strategy_config.get("position_rules") or {})
    weight = _finite_positive(
        position_rules.get("target_weight_per_asset"), "target_weight_per_asset"
    )
    if abs(weight - 0.35) > 1e-12 or top_k * weight > 0.7 + 1e-12:
        raise ForwardDataError("P1 target weights drifted from the frozen design")
    target_codes = tuple(sorted(str(item["code"]) for item in selected))
    target_weights = {code: weight for code in target_codes}
    evidence = {
        "schema": ETF_TREND_DECISION_SCHEMA,
        "engine_id": DIVERSIFIED_ETF_TREND_ENGINE,
        "signal_date": day.isoformat(),
        "required_observation_count": required_observations,
        "eligible_risk_group_count": len(group_candidates),
        "insufficient_eligible_action_applied": not selected,
        "rankings": rankings,
        "selected_codes": list(target_codes),
        "target_weights": target_weights,
    }
    return ForwardTargetDecision(target_codes, target_weights, evidence)


def _sample_covariance_matrix(
    returns_by_code: Mapping[str, Sequence[float]],
    codes: Sequence[str],
    *,
    annualization: int,
) -> list[list[float]]:
    observations = [list(returns_by_code[code]) for code in codes]
    lengths = {len(values) for values in observations}
    if len(lengths) != 1 or next(iter(lengths), 0) < 2:
        raise ForwardDataError("S3 covariance windows are incomplete")
    means = [statistics.fmean(values) for values in observations]
    count = len(observations[0])
    covariance: list[list[float]] = []
    for left, left_values in enumerate(observations):
        row: list[float] = []
        for right, right_values in enumerate(observations):
            value = sum(
                (left_values[index] - means[left])
                * (right_values[index] - means[right])
                for index in range(count)
            ) / (count - 1)
            value *= annualization
            if not math.isfinite(value):
                raise ForwardDataError("S3 covariance contains non-finite values")
            row.append(value)
        covariance.append(row)
    return covariance


def _matrix_vector(
    matrix: Sequence[Sequence[float]], values: Sequence[float]
) -> list[float]:
    return [
        sum(float(cell) * float(values[index]) for index, cell in enumerate(row))
        for row in matrix
    ]


def _portfolio_volatility(
    weights: Sequence[float], covariance: Sequence[Sequence[float]]
) -> float:
    product = _matrix_vector(covariance, weights)
    variance = sum(
        float(weight) * product[index] for index, weight in enumerate(weights)
    )
    return math.sqrt(max(0.0, variance))


def _s3_erc_proportions(
    covariance: Sequence[Sequence[float]],
    *,
    cycles: int,
    numerical_floor: float,
) -> tuple[list[float], list[float], float]:
    count = len(covariance)
    if count < 2 or any(len(row) != count for row in covariance):
        raise ForwardDataError("S3 covariance shape is invalid")
    diagonal = [float(covariance[index][index]) for index in range(count)]
    if any(not math.isfinite(value) or value <= numerical_floor for value in diagonal):
        raise ForwardDataError("S3 requires positive sleeve variance")
    volatilities = [math.sqrt(value) for value in diagonal]
    inverse = [1.0 / value for value in volatilities]
    inverse_sum = sum(inverse)
    solution = [value / inverse_sum for value in inverse]
    budgets = [1.0 / count] * count
    for _ in range(cycles):
        for index in range(count):
            variance = diagonal[index]
            cross = (
                sum(
                    float(covariance[index][column]) * solution[column]
                    for column in range(count)
                )
                - variance * solution[index]
            )
            discriminant = cross * cross + 4.0 * variance * budgets[index]
            solution[index] = max(
                numerical_floor,
                (-cross + math.sqrt(max(0.0, discriminant))) / (2.0 * variance),
            )
    total = sum(solution)
    solution = [value / total for value in solution]
    product = _matrix_vector(covariance, solution)
    portfolio_variance = sum(
        solution[index] * product[index] for index in range(count)
    )
    if portfolio_variance <= numerical_floor:
        raise ForwardDataError("S3 ERC portfolio variance is not positive")
    contributions = [
        solution[index] * product[index] / portfolio_variance
        for index in range(count)
    ]
    spread = max(
        abs(contributions[index] - budgets[index]) for index in range(count)
    )
    return solution, contributions, spread


def _s3_constrained_weights(
    proportions: Sequence[float],
    covariance: Sequence[Sequence[float]],
    *,
    cap: float,
    maximum_gross: float,
    target_volatility: float,
    iterations: int,
) -> tuple[list[float], float, float, list[str]]:
    def state(multiplier: float) -> tuple[list[float], float, float, bool]:
        weights = [min(cap, multiplier * value) for value in proportions]
        gross = sum(weights)
        volatility = _portfolio_volatility(weights, covariance)
        all_capped = all(weight >= cap - 1e-12 for weight in weights)
        return weights, gross, volatility, all_capped

    def feasible(multiplier: float) -> bool:
        _, gross, volatility, _ = state(multiplier)
        return gross <= maximum_gross and volatility <= target_volatility

    low = 0.0
    high = 1.0
    high_state = state(high)
    while feasible(high) and not high_state[3]:
        low = high
        high *= 2.0
        if high > 1e12:
            raise ForwardDataError("S3 exposure multiplier bracketing failed")
        high_state = state(high)
    if feasible(high) and high_state[3]:
        low = high
    else:
        for _ in range(iterations):
            middle = (low + high) / 2.0
            if feasible(middle):
                low = middle
            else:
                high = middle
    weights, gross, volatility, all_capped = state(low)
    binding: list[str] = []
    if abs(gross - maximum_gross) <= 1e-8:
        binding.append("gross")
    if abs(volatility - target_volatility) <= 1e-8:
        binding.append("volatility")
    if all_capped:
        binding.append("all_sleeves_capped")
    if not binding:
        raise ForwardDataError("S3 constrained allocator has no binding constraint")
    return weights, low, volatility, binding


def build_multihorizon_volatility_brake_decision(
    strategy_config: Mapping[str, Any],
    signal_input: Mapping[str, Any],
    calendar: Mapping[str, Any],
    *,
    signal_date: str | date,
) -> ForwardTargetDecision:
    """Recompute the frozen S3 monthly decision from point-in-time inputs."""

    day = _day(signal_date)
    engine = dict(strategy_config.get("signal_engine") or {})
    expected = {
        "id": MULTIHORIZON_VOLATILITY_BRAKE_ENGINE,
        "input_schema": ETF_MULTIHORIZON_INPUT_SCHEMA,
        "strategic_covariance_lookback_sessions": 126,
        "strategic_refresh_months": [3, 6, 9, 12],
        "volatility_brake_horizons_sessions": [21, 63, 126],
        "annualization_sessions": 252,
        "target_annualized_volatility": 0.08,
        "maximum_single_asset_weight": 0.4,
        "maximum_gross_exposure": 1.0,
        "erc_solver_cycles": 200,
        "erc_numerical_floor": 1e-12,
        "exposure_solver_iterations": 100,
        "signal_price_field": "qfq_close_proxy",
    }
    if engine != expected:
        raise ForwardDataError("S3 signal-engine parameters drifted from the frozen design")
    boundary = dict(strategy_config.get("research_boundary") or {})
    if (
        strategy_config.get("real_orders") is not False
        or boundary.get("formal_forward_evidence") is not False
        or boundary.get("promotion_eligible") is not False
        or boundary.get("historical_backfill_allowed") is not False
        or boundary.get("real_orders") is not False
    ):
        raise ForwardDataError("S3 research boundary was weakened")
    if signal_input.get("schema") != ETF_MULTIHORIZON_INPUT_SCHEMA:
        raise ForwardDataError("unsupported S3 point-in-time input schema")
    if _day(signal_input.get("as_of_date")) != day:
        raise ForwardDataError("S3 signal input as_of_date mismatch")
    if _day(signal_input.get("max_event_date")) > day:
        raise ForwardDataError("S3 signal input contains future events")

    raw_calendar = [_day(value) for value in list(calendar.get("trading_dates") or [])]
    if raw_calendar != sorted(raw_calendar) or len(raw_calendar) != len(set(raw_calendar)):
        raise ForwardDataError("S3 approved calendar must be unique and sorted")
    if day not in raw_calendar:
        raise ForwardDataError("S3 signal date is absent from the approved calendar")
    signal_index = raw_calendar.index(day)
    if signal_index + 1 >= len(raw_calendar):
        raise ForwardDataError("S3 approved calendar lacks the next execution session")
    if raw_calendar[signal_index + 1].month == day.month:
        raise ForwardDataError("S3 signals are allowed only on a month-end session")

    month_end_indices = [
        index
        for index in range(0, signal_index + 1)
        if index + 1 < len(raw_calendar)
        and raw_calendar[index + 1].month != raw_calendar[index].month
    ]
    strategic_candidates = [
        index
        for index in month_end_indices
        if raw_calendar[index].month in {3, 6, 9, 12}
        and index <= signal_index
    ]
    if not strategic_candidates:
        raise ForwardDataError("S3 calendar lacks a prior quarterly strategic refresh")
    strategic_index = strategic_candidates[-1]
    lookback = 126
    first_required_index = min(strategic_index, signal_index) - lookback
    if first_required_index < 0:
        raise ForwardDataError("S3 approved calendar has insufficient covariance history")
    required_dates = raw_calendar[first_required_index : signal_index + 1]

    universe = list(strategy_config.get("universe") or [])
    codes = [str(item.get("code") or "") for item in universe]
    if codes != ["510300", "513100", "511010", "518880"]:
        raise ForwardDataError("S3 universe drifted from the frozen four ETFs")
    series = dict(signal_input.get("series") or {})
    if set(series) != set(codes):
        raise ForwardDataError("S3 signal input must contain exactly four frozen ETFs")
    closes_by_code = {
        code: _series_closes(
            code=code,
            rows=list(series[code] or []),
            price_field="qfq_close_proxy",
            required_dates=required_dates,
        )
        for code in codes
    }

    def covariance_at(calendar_index: int, horizon: int) -> list[list[float]]:
        local_end = calendar_index - first_required_index
        if local_end - horizon < 0:
            raise ForwardDataError("S3 covariance history is incomplete")
        returns_by_code: dict[str, list[float]] = {}
        for code in codes:
            closes = closes_by_code[code]
            window = closes[local_end - horizon : local_end + 1]
            returns_by_code[code] = [
                window[index] / window[index - 1] - 1.0
                for index in range(1, len(window))
            ]
        return _sample_covariance_matrix(
            returns_by_code, codes, annualization=252
        )

    strategic_covariance = covariance_at(strategic_index, lookback)
    erc, contribution_shares, contribution_spread = _s3_erc_proportions(
        strategic_covariance,
        cycles=200,
        numerical_floor=1e-12,
    )
    strategic_weights, multiplier, strategic_volatility, binding = (
        _s3_constrained_weights(
            erc,
            strategic_covariance,
            cap=0.4,
            maximum_gross=1.0,
            target_volatility=0.08,
            iterations=100,
        )
    )
    forecasts = {
        str(horizon): _portfolio_volatility(
            strategic_weights, covariance_at(signal_index, horizon)
        )
        for horizon in (21, 63, 126)
    }
    maximum_forecast = max(forecasts.values())
    scalar = min(1.0, 0.08 / maximum_forecast) if maximum_forecast > 0 else 1.0
    final_weights = {
        code: strategic_weights[index] * scalar
        for index, code in enumerate(codes)
        if strategic_weights[index] * scalar > 1e-12
    }
    target_codes = tuple(sorted(final_weights))
    evidence = {
        "schema": MULTIHORIZON_VOLATILITY_BRAKE_DECISION_SCHEMA,
        "engine_id": MULTIHORIZON_VOLATILITY_BRAKE_ENGINE,
        "signal_date": day.isoformat(),
        "execute_on": raw_calendar[signal_index + 1].isoformat(),
        "strategic_signal_date": raw_calendar[strategic_index].isoformat(),
        "strategic_refresh": strategic_index == signal_index,
        "erc_proportions": {
            code: erc[index] for index, code in enumerate(codes)
        },
        "erc_risk_contribution_shares": {
            code: contribution_shares[index] for index, code in enumerate(codes)
        },
        "erc_relative_risk_contribution_spread": contribution_spread,
        "strategic_exposure_multiplier": multiplier,
        "strategic_predicted_volatility": strategic_volatility,
        "strategic_binding_constraints": binding,
        "pre_brake_weights": {
            code: strategic_weights[index] for index, code in enumerate(codes)
        },
        "volatility_forecasts": forecasts,
        "maximum_pre_brake_predicted_volatility": maximum_forecast,
        "brake_scalar": scalar,
        "predicted_post_brake_volatility": maximum_forecast * scalar,
        "target_weights": final_weights,
        "target_gross_exposure": sum(final_weights.values()),
        "target_cash_weight": 1.0 - sum(final_weights.values()),
        "formal_forward_evidence": False,
        "promotion_eligible": False,
        "real_orders": False,
    }
    return ForwardTargetDecision(target_codes, final_weights, evidence)


def _cross_sectional_midrank(values: Mapping[str, float]) -> dict[str, float]:
    """Map ascending midranks to [-1, 1] with deterministic code tie breaks."""
    if not values:
        return {}
    ordered = sorted(
        ((float(value), str(code)) for code, value in values.items()),
        key=lambda item: (item[0], item[1]),
    )
    count = len(ordered)
    if count == 1:
        return {ordered[0][1]: 0.0}
    result: dict[str, float] = {}
    start = 0
    while start < count:
        end = start + 1
        while end < count and ordered[end][0] == ordered[start][0]:
            end += 1
        midrank = ((start + 1) + end) / 2.0
        score = 2.0 * (midrank - 1.0) / (count - 1.0) - 1.0
        for _, code in ordered[start:end]:
            result[code] = score
        start = end
    return result


def _stock_series(
    *,
    code: str,
    rows: Sequence[Mapping[str, Any]],
    required_dates: Sequence[date],
) -> tuple[list[float], list[float]]:
    parsed_dates: list[date] = []
    closes: list[float] = []
    amounts: list[float] = []
    required_fields = {"date", "qfq_close_proxy", "amount"}
    for index, raw in enumerate(rows):
        if not isinstance(raw, Mapping) or set(raw) != required_fields:
            raise ForwardDataError(
                f"stock series row fields do not match the frozen schema: {code}[{index}]"
            )
        parsed_dates.append(_day(raw.get("date")))
        closes.append(
            _finite_positive(raw.get("qfq_close_proxy"), f"{code}.qfq_close_proxy")
        )
        amounts.append(_finite_positive(raw.get("amount"), f"{code}.amount"))
    if parsed_dates != sorted(parsed_dates) or len(parsed_dates) != len(set(parsed_dates)):
        raise ForwardDataError(f"stock series dates must be unique and sorted for {code}")
    window = list(required_dates)
    if parsed_dates[-len(window) :] != window:
        raise ForwardDataError(
            f"stock series does not cover the exact required trading sessions for {code}"
        )
    return closes[-len(window) :], amounts[-len(window) :]


def _maximum_drawdown(values: Sequence[float]) -> float:
    peak = float(values[0])
    maximum = 0.0
    for value in values:
        peak = max(peak, float(value))
        maximum = max(maximum, 1.0 - float(value) / peak)
    return maximum


def build_forward_multifactor_decision(
    strategy_config: Mapping[str, Any],
    signal_input: Mapping[str, Any],
    calendar: Mapping[str, Any],
    *,
    signal_date: str | date,
) -> ForwardTargetDecision:
    """Build I7 targets exclusively from timestamped point-in-time inputs."""
    day = _day(signal_date)
    model = dict(strategy_config.get("factor_model") or {})
    if model.get("engine_id") != FORWARD_MULTIFACTOR_ENGINE:
        raise ForwardDataError("strategy does not use the supported I7 signal engine")
    if (
        model.get("input_schema") != STOCK_FACTOR_INPUT_SCHEMA
        or int(model.get("required_observations") or 0) != 126
        or model.get("cross_sectional_transform")
        != "ascending_midrank_mapped_to_minus_one_plus_one"
        or dict(model.get("factor_definitions") or {}) != I7_FACTOR_DEFINITIONS
    ):
        raise ForwardDataError("I7 factor definitions drifted from the frozen design")
    if signal_input.get("schema") != STOCK_FACTOR_INPUT_SCHEMA:
        raise ForwardDataError("unsupported point-in-time stock multifactor input schema")
    if _day(signal_input.get("as_of_date")) != day:
        raise ForwardDataError("stock factor input as_of_date mismatch")
    if _day(signal_input.get("max_event_date")) > day:
        raise ForwardDataError("stock factor input contains future events")
    cutoff = _timestamp(str(signal_input.get("signal_cutoff_at") or ""))

    calendar_dates = sorted(
        {_day(value) for value in list(calendar.get("trading_dates") or [])}
    )
    if day not in calendar_dates:
        raise ForwardDataError("signal date is absent from the approved calendar")
    available_dates = [value for value in calendar_dates if value <= day]
    required_observations = 126
    if len(available_dates) < required_observations:
        raise ForwardDataError("approved calendar has insufficient I7 lookback")
    required_dates = available_dates[-required_observations:]

    pool = dict(strategy_config.get("candidate_pool") or {})
    membership = [dict(item) for item in list(signal_input.get("official_membership") or [])]
    membership_codes = [str(item.get("code") or "") for item in membership]
    expected_count = int(pool.get("expected_count") or 0)
    if (
        expected_count <= 0
        or len(membership_codes) != expected_count
        or len(set(membership_codes)) != expected_count
        or any(not code for code in membership_codes)
    ):
        raise ForwardDataError("official membership snapshot is incomplete or duplicated")
    for item in membership:
        if set(item) != {"code", "available_at"}:
            raise ForwardDataError("official membership fields do not match the frozen schema")
        if _timestamp(str(item["available_at"])) > cutoff:
            raise ForwardDataError("official membership was unavailable at signal cutoff")

    required_asset_fields = {
        "industry_id",
        "correlation_cluster",
        "listing_status",
        "st_status",
        "suspension_status",
        "delisting_status",
        "available_at",
        "fundamental",
        "series",
    }
    assets = dict(signal_input.get("assets") or {})
    current_holdings = [
        str(code) for code in list(signal_input.get("current_holdings") or [])
    ]
    if len(current_holdings) != len(set(current_holdings)):
        raise ForwardDataError("current holdings contain duplicates")
    if not set(current_holdings).issubset(assets):
        raise ForwardDataError("current holdings lack point-in-time risk metadata")
    unexpected = set(assets) - set(membership_codes) - set(current_holdings)
    if unexpected:
        raise ForwardDataError("stock factor input contains unrelated non-member assets")
    risk_metadata: dict[str, dict[str, str]] = {}
    for code in sorted(set(membership_codes) | set(current_holdings)):
        if code not in assets:
            if code in current_holdings:
                raise ForwardDataError(
                    f"current holding lacks point-in-time risk metadata: {code}"
                )
            continue
        raw = dict(assets.get(code) or {})
        unexpected_fields = set(raw) - required_asset_fields
        if unexpected_fields:
            raise ForwardDataError(
                f"risk metadata contains unsupported fields: {code}"
            )
        if not required_asset_fields.issubset(raw):
            raise ForwardDataError(f"risk metadata is incomplete: {code}")
        if _timestamp(str(raw.get("available_at") or "")) > cutoff:
            raise ForwardDataError(f"risk metadata was unavailable at signal cutoff: {code}")
        industry = str(raw.get("industry_id") or "")
        cluster = str(raw.get("correlation_cluster") or "")
        if not industry or not cluster:
            raise ForwardDataError(f"risk metadata groups are missing: {code}")
        risk_metadata[code] = {
            "sector": industry,
            "correlation_cluster": cluster,
            "available_at": str(raw["available_at"]),
        }
    raw_factors: dict[str, dict[str, float]] = {}
    asset_details: dict[str, dict[str, Any]] = {}
    missing_codes: list[str] = []
    for code in membership_codes:
        if code not in assets:
            missing_codes.append(code)
            continue
        raw = dict(assets[code] or {})
        if set(raw) != required_asset_fields:
            missing_codes.append(code)
            continue
        if _timestamp(str(raw.get("available_at") or "")) > cutoff:
            raise ForwardDataError(f"risk metadata was unavailable at signal cutoff: {code}")
        fundamental = dict(raw.get("fundamental") or {})
        if set(fundamental) != {"book_to_price", "published_at", "available_at"}:
            missing_codes.append(code)
            continue
        if (
            _timestamp(str(fundamental.get("published_at") or "")) > cutoff
            or _timestamp(str(fundamental.get("available_at") or "")) > cutoff
        ):
            raise ForwardDataError(f"fundamental data was unavailable at signal cutoff: {code}")
        if _timestamp(str(fundamental["available_at"])) < _timestamp(
            str(fundamental["published_at"])
        ):
            raise ForwardDataError(
                f"fundamental available_at predates published_at: {code}"
            )
        closes, amounts = _stock_series(
            code=code,
            rows=list(raw.get("series") or []),
            required_dates=required_dates,
        )
        daily_returns = [
            closes[index] / closes[index - 1] - 1.0
            for index in range(1, len(closes))
        ]
        volatility_60 = statistics.stdev(daily_returns[-60:]) * math.sqrt(252.0)
        adv20 = statistics.fmean(amounts[-20:])
        adv60 = statistics.fmean(amounts[-60:])
        factor_values = {
            "trend": closes[-1] / statistics.fmean(closes[-120:]) - 1.0,
            "momentum_6_1": closes[-21] / closes[-126] - 1.0,
            "value_cheap": _finite(fundamental.get("book_to_price"), f"{code}.book_to_price"),
            "low_volatility": -volatility_60,
            "liquidity": math.log(adv20),
            "risk_control": -_maximum_drawdown(closes[-60:]),
        }
        raw_factors[code] = factor_values
        asset_details[code] = {
            "industry_id": str(raw.get("industry_id") or ""),
            "correlation_cluster": str(raw.get("correlation_cluster") or ""),
            "listing_status": str(raw.get("listing_status") or ""),
            "st_status": bool(raw.get("st_status")),
            "suspension_status": bool(raw.get("suspension_status")),
            "delisting_status": bool(raw.get("delisting_status")),
            "adv20": adv20,
            "adv60": adv60,
            "signal_day_return": daily_returns[-1],
            "daily_returns_20": daily_returns[-20:],
        }

    coverage = len(raw_factors) / expected_count
    if coverage + 1e-12 < 0.95:
        raise ForwardDataError("I7 usable universe coverage is below 95 percent")

    weights = {str(key): float(value) for key, value in dict(model.get("factor_weights") or {}).items()}
    required_factors = {
        "trend", "momentum_6_1", "value_cheap", "low_volatility", "liquidity", "risk_control"
    }
    if weights != I7_FACTOR_WEIGHTS:
        raise ForwardDataError("I7 factor weights drifted from the frozen design")
    ranked_factors = {
        factor: _cross_sectional_midrank(
            {code: values[factor] for code, values in raw_factors.items()}
        )
        for factor in sorted(required_factors)
    }
    selection = dict(strategy_config.get("selection") or {})
    minimum_amount = _finite_positive(
        selection.get("minimum_20d_average_amount"), "minimum_20d_average_amount"
    )
    maximum_day_move = _finite_positive(
        selection.get("maximum_absolute_signal_day_pct_change"),
        "maximum_absolute_signal_day_pct_change",
    ) / 100.0
    rankings: list[dict[str, Any]] = []
    for code in raw_factors:
        details = asset_details[code]
        reasons: list[str] = []
        if not details["industry_id"] or not details["correlation_cluster"]:
            reasons.append("MISSING_RISK_METADATA")
        if details["listing_status"] != "LISTED":
            reasons.append("NOT_LISTED")
        if details["st_status"]:
            reasons.append("ST_SECURITY")
        if details["suspension_status"]:
            reasons.append("SUSPENDED")
        if details["delisting_status"]:
            reasons.append("DELISTING")
        if details["adv20"] < minimum_amount:
            reasons.append("INSUFFICIENT_LIQUIDITY")
        if abs(details["signal_day_return"]) > maximum_day_move:
            reasons.append("EXCESSIVE_SIGNAL_DAY_MOVE")
        composite = sum(
            weights[factor] * ranked_factors[factor][code]
            for factor in required_factors
        )
        rankings.append(
            {
                "code": code,
                "industry_id": details["industry_id"],
                "correlation_cluster": details["correlation_cluster"],
                "eligible": not reasons,
                "rejection_reasons": reasons,
                "raw_factors": {
                    key: round(value, 10) for key, value in raw_factors[code].items()
                },
                "rank_scores": {
                    key: round(ranked_factors[key][code], 10)
                    for key in sorted(required_factors)
                },
                "composite_score": round(composite, 10),
            }
        )
    rankings.sort(key=lambda item: (-float(item["composite_score"]), str(item["code"])))

    top_k = int(selection.get("top_k") or 0)
    rank_buffer = int(selection.get("rank_buffer") or 0)
    maximum_per_industry = int(selection.get("maximum_per_industry") or 0)
    minimum_positions = int(selection.get("minimum_effective_positions_when_invested") or 0)
    if (top_k, rank_buffer, maximum_per_industry, minimum_positions) != (5, 7, 2, 4):
        raise ForwardDataError("I7 selection contract drifted from the frozen design")
    eligible = [item for item in rankings if item["eligible"]]
    eligible_by_code = {str(item["code"]): item for item in eligible}
    buffer_codes = {str(item["code"]) for item in eligible[:rank_buffer]}
    retained = [
        eligible_by_code[code]
        for code in current_holdings
        if code in buffer_codes
    ]
    retained.sort(key=lambda item: (-float(item["composite_score"]), str(item["code"])))
    candidates = retained + [item for item in eligible if item not in retained]
    selected: list[dict[str, Any]] = []
    industry_counts: dict[str, int] = {}
    for item in candidates:
        if len(selected) >= top_k:
            break
        industry = str(item["industry_id"])
        if industry_counts.get(industry, 0) >= maximum_per_industry:
            continue
        selected.append(item)
        industry_counts[industry] = industry_counts.get(industry, 0) + 1
    if len(selected) < minimum_positions:
        selected = []

    position = dict(strategy_config.get("position_rules") or {})
    target_volatility = _finite_positive(
        position.get("target_annualized_volatility"), "target_annualized_volatility"
    )
    minimum_exposure = _finite_positive(position.get("minimum_exposure"), "minimum_exposure")
    maximum_exposure = _finite_positive(position.get("maximum_exposure"), "maximum_exposure")
    maximum_weight = _finite_positive(
        position.get("maximum_single_asset_weight"), "maximum_single_asset_weight"
    )
    maximum_industry_weight = _finite_positive(
        selection.get("maximum_industry_weight"), "maximum_industry_weight"
    )
    target_weights: dict[str, float] = {}
    exposure = 0.0
    basket_volatility = 0.0
    if selected:
        basket_returns = [
            statistics.fmean(
                asset_details[str(item["code"])]["daily_returns_20"][index]
                for item in selected
            )
            for index in range(20)
        ]
        basket_volatility = statistics.stdev(basket_returns) * math.sqrt(252.0)
        raw_exposure = maximum_exposure if basket_volatility == 0 else target_volatility / basket_volatility
        exposure = min(max(raw_exposure, minimum_exposure), maximum_exposure)
        base_weight = min(exposure / len(selected), maximum_weight)
        by_industry: dict[str, list[str]] = {}
        for item in selected:
            by_industry.setdefault(str(item["industry_id"]), []).append(str(item["code"]))
        for codes in by_industry.values():
            allocated = min(base_weight, maximum_industry_weight / len(codes))
            for code in codes:
                target_weights[code] = round(allocated, 10)
    target_codes = tuple(sorted(target_weights))
    evidence = {
        "schema": STOCK_FACTOR_DECISION_SCHEMA,
        "engine_id": FORWARD_MULTIFACTOR_ENGINE,
        "signal_date": day.isoformat(),
        "signal_cutoff_at": cutoff.isoformat(),
        "required_observation_count": required_observations,
        "official_membership_count": expected_count,
        "usable_factor_count": len(raw_factors),
        "usable_factor_coverage": round(coverage, 10),
        "missing_codes": sorted(missing_codes),
        "eligible_count": len(eligible),
        "insufficient_eligible_action_applied": not selected,
        "basket_annualized_volatility_20": round(basket_volatility, 10),
        "target_gross_exposure_before_caps": round(exposure, 10),
        "actual_gross_exposure": round(sum(target_weights.values()), 10),
        "rankings": rankings,
        "risk_metadata": risk_metadata,
        "selected_codes": list(target_codes),
        "target_weights": target_weights,
        "real_orders": False,
    }
    return ForwardTargetDecision(target_codes, target_weights, evidence)


class ForwardSignalFactory:
    """Generate a frozen signal from already-approved catalog revisions."""

    def __init__(self, runner: ForwardPaperRunner):
        self.runner = runner

    def generate(
        self,
        strategy_id: str,
        *,
        signal_date: str,
        generated_at: str | datetime,
        data_refs: Mapping[str, Any],
    ) -> dict[str, Any]:
        spec = self.runner._experiment(strategy_id)
        moment = _timestamp(generated_at)
        day = _day(signal_date)
        formal_builder = getattr(
            self.runner, "_formal_signal_materialization", None
        )
        formal = (
            formal_builder(
                spec=spec,
                strategy_id=strategy_id,
                signal_date=day,
                cutoff_at=moment,
                data_refs={
                    key: dict(value) if isinstance(value, Mapping) else value
                    for key, value in data_refs.items()
                },
            )
            if callable(formal_builder)
            else None
        )
        if formal is not None:
            calendar_payload = dict(formal["payloads"]["calendar"])
            signal_payload = dict(formal["payloads"]["signal"])
            calendar_dates = sorted(
                {_day(value) for value in list(calendar_payload.get("trading_dates") or [])}
            )
            following = [value for value in calendar_dates if value > day]
            if not following:
                raise ForwardDataError("formal calendar has no next execution session")
            engine_id = str(
                dict(spec["strategy_config"].get("signal_engine") or {}).get("id")
                or dict(spec["strategy_config"].get("factor_model") or {}).get("engine_id")
                or ""
            )
            if engine_id == DIVERSIFIED_ETF_TREND_ENGINE:
                decision = build_diversified_etf_trend_decision(
                    spec["strategy_config"], signal_payload, calendar_payload,
                    signal_date=day,
                )
            elif engine_id == FORWARD_MULTIFACTOR_ENGINE:
                decision = build_forward_multifactor_decision(
                    spec["strategy_config"], signal_payload, calendar_payload,
                    signal_date=day,
                )
            else:
                raise ForwardDataError("strategy signal engine is unsupported")
            return {
                "schema": FORWARD_SIGNAL_SCHEMA,
                "strategy_id": strategy_id,
                "signal_date": day.isoformat(),
                "execute_on": following[0].isoformat(),
                "signal_generated_at": moment.isoformat(),
                "strategy_config_sha256": spec["strategy_config_sha256"],
                "code_snapshot_sha256": spec["code_snapshot_sha256"],
                "target_codes": list(decision.target_codes),
                "target_weights": decision.target_weights,
                "decision_evidence": decision.evidence,
                "materialization_sha256": formal["evidence"][
                    "materialization_sha256"
                ],
                "data_refs": {
                    key: dict(value) if isinstance(value, Mapping) else value
                    for key, value in data_refs.items()
                },
                "real_orders": False,
            }
        calendar = self.runner._approved_dataset(
            spec, dict(data_refs.get("calendar") or {}), "calendar"
        )
        signal_input = self.runner._approved_dataset(
            spec, dict(data_refs.get("signal") or {}), "signal"
        )
        if calendar["available_at"] > moment or signal_input["available_at"] > moment:
            raise ForwardDataError("signal inputs were unavailable at generation time")
        calendar_dates = sorted(
            {_day(value) for value in list(calendar["payload"].get("trading_dates") or [])}
        )
        following = [value for value in calendar_dates if value > day]
        if not following:
            raise ForwardDataError("approved calendar has no next execution session")
        engine_id = str(
            dict(spec["strategy_config"].get("signal_engine") or {}).get("id")
            or dict(spec["strategy_config"].get("factor_model") or {}).get("engine_id")
            or ""
        )
        if engine_id == DIVERSIFIED_ETF_TREND_ENGINE:
            decision = build_diversified_etf_trend_decision(
                spec["strategy_config"],
                signal_input["payload"],
                calendar["payload"],
                signal_date=day,
            )
        elif engine_id == FORWARD_MULTIFACTOR_ENGINE:
            decision = build_forward_multifactor_decision(
                spec["strategy_config"],
                signal_input["payload"],
                calendar["payload"],
                signal_date=day,
            )
        else:
            raise ForwardDataError("strategy signal engine is unsupported")
        return {
            "schema": FORWARD_SIGNAL_SCHEMA,
            "strategy_id": strategy_id,
            "signal_date": day.isoformat(),
            "execute_on": following[0].isoformat(),
            "signal_generated_at": moment.isoformat(),
            "strategy_config_sha256": spec["strategy_config_sha256"],
            "code_snapshot_sha256": spec["code_snapshot_sha256"],
            "target_codes": list(decision.target_codes),
            "target_weights": decision.target_weights,
            "decision_evidence": decision.evidence,
            "data_refs": {
                key: dict(value) if isinstance(value, Mapping) else value
                for key, value in data_refs.items()
            },
            "real_orders": False,
        }

    def generate_and_register(
        self,
        strategy_id: str,
        *,
        signal_date: str,
        generated_at: str | datetime,
        recorded_at: str | datetime,
        data_refs: Mapping[str, Any],
    ) -> dict[str, Any]:
        signal = self.generate(
            strategy_id,
            signal_date=signal_date,
            generated_at=generated_at,
            data_refs=data_refs,
        )
        return self.runner.register_signal(
            strategy_id, signal, recorded_at=recorded_at
        )
