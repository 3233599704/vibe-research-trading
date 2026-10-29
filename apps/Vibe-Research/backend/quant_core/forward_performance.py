"""Deterministic performance evidence from formal forward-paper sessions only."""

from __future__ import annotations

import math
import statistics
from datetime import date
from typing import Any, Mapping, Sequence

from .provenance import sha256_digest


FORWARD_PERFORMANCE_SCHEMA = "quant-platform/forward-performance-evidence/v1"


class ForwardPerformanceError(ValueError):
    pass


def _finite(value: Any, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ForwardPerformanceError(f"{label} must be numeric") from exc
    if not math.isfinite(number):
        raise ForwardPerformanceError(f"{label} must be finite")
    return number


def _rounded(value: float | None, digits: int = 6) -> float | None:
    return None if value is None else round(value, digits)


def _return(left: float, right: float, label: str) -> float:
    try:
        value = left / right - 1.0
    except (ArithmeticError, OverflowError) as exc:
        raise ForwardPerformanceError(f"{label} is not finite") from exc
    if not math.isfinite(value):
        raise ForwardPerformanceError(f"{label} is not finite")
    return value


def _thresholds(gate: Mapping[str, Any]) -> dict[str, float]:
    fields = {
        "minimum_total_return_pct": (0.0, 1000.0),
        "minimum_annualized_return_pct": (0.0, 1000.0),
        "minimum_sharpe_ratio": (0.0, 20.0),
        "minimum_positive_month_ratio": (0.0, 1.0),
        "maximum_performance_drawdown_pct": (0.0, 100.0),
        "maximum_annualized_volatility_pct": (0.0, 1000.0),
        "annual_risk_free_rate_pct": (0.0, 100.0),
    }
    values: dict[str, float] = {}
    for field, (lower, upper) in fields.items():
        if field not in gate:
            raise ForwardPerformanceError(f"prospective gate is missing {field}")
        number = _finite(gate[field], field)
        if field.startswith("maximum_") and number <= lower:
            raise ForwardPerformanceError(f"{field} must be positive")
        if number < lower or number > upper:
            raise ForwardPerformanceError(f"{field} is outside its allowed range")
        values[field] = number
    return values


def calculate_forward_performance(
    sessions: Sequence[Mapping[str, Any]],
    *,
    initial_cash: float,
    prospective_gate: Mapping[str, Any],
) -> dict[str, Any]:
    """Calculate predeclared metrics without historical or benchmark substitution."""
    starting_equity = _finite(initial_cash, "initial_cash")
    if starting_equity <= 0:
        raise ForwardPerformanceError("initial_cash must be positive")
    thresholds = _thresholds(prospective_gate)

    dates: list[date] = []
    equities: list[float] = []
    for index, raw in enumerate(sessions):
        if not isinstance(raw, Mapping):
            raise ForwardPerformanceError(f"session {index} must be an object")
        try:
            session_date = date.fromisoformat(str(raw.get("trade_date")))
        except (TypeError, ValueError) as exc:
            raise ForwardPerformanceError(f"session {index} has an invalid trade_date") from exc
        equity = _finite(raw.get("equity"), f"session {index} equity")
        if equity <= 0:
            raise ForwardPerformanceError(f"session {index} equity must be positive")
        dates.append(session_date)
        equities.append(equity)
    if dates != sorted(dates) or len(dates) != len(set(dates)):
        raise ForwardPerformanceError("forward sessions must be unique and sorted")

    daily_returns: list[float] = []
    previous = starting_equity
    for equity in equities:
        daily_returns.append(_return(equity, previous, "daily return"))
        previous = equity

    total_return_pct = (
        _return(equities[-1], starting_equity, "total return") * 100
        if equities
        else None
    )
    annualized_return_pct: float | None = None
    if equities:
        try:
            annualized_return_pct = (
                (equities[-1] / starting_equity) ** (252 / len(equities)) - 1.0
            ) * 100
        except (ArithmeticError, OverflowError) as exc:
            raise ForwardPerformanceError("annualized return is not finite") from exc
        if not math.isfinite(annualized_return_pct):
            raise ForwardPerformanceError("annualized return is not finite")
    annualized_volatility_pct: float | None = None
    sharpe_ratio: float | None = None
    if len(daily_returns) >= 2:
        try:
            daily_volatility = statistics.stdev(daily_returns)
            annualized_volatility_pct = daily_volatility * math.sqrt(252) * 100
        except (ArithmeticError, OverflowError, statistics.StatisticsError) as exc:
            raise ForwardPerformanceError("annualized volatility is not finite") from exc
        if not math.isfinite(annualized_volatility_pct):
            raise ForwardPerformanceError("annualized volatility is not finite")
        daily_risk_free = (
            (1 + thresholds["annual_risk_free_rate_pct"] / 100) ** (1 / 252) - 1
        )
        if daily_volatility > 1e-15:
            sharpe_ratio = (
                (statistics.fmean(daily_returns) - daily_risk_free)
                / daily_volatility
                * math.sqrt(252)
            )
            if not math.isfinite(sharpe_ratio):
                raise ForwardPerformanceError("sharpe ratio is not finite")

    peak = starting_equity
    max_drawdown_pct = 0.0
    drawdown_duration = 0
    longest_drawdown_days = 0
    for equity in equities:
        peak = max(peak, equity)
        drawdown = (peak - equity) / peak * 100
        max_drawdown_pct = max(max_drawdown_pct, drawdown)
        if drawdown > 1e-12:
            drawdown_duration += 1
            longest_drawdown_days = max(longest_drawdown_days, drawdown_duration)
        else:
            drawdown_duration = 0

    month_ends: list[float] = []
    current_month: tuple[int, int] | None = None
    for session_date, equity in zip(dates, equities, strict=True):
        month = (session_date.year, session_date.month)
        if month != current_month:
            month_ends.append(equity)
            current_month = month
        else:
            month_ends[-1] = equity
    monthly_returns: list[float] = []
    previous = starting_equity
    for equity in month_ends:
        monthly_returns.append(_return(equity, previous, "monthly return"))
        previous = equity
    positive_month_ratio = (
        sum(value > 0 for value in monthly_returns) / len(monthly_returns)
        if monthly_returns
        else None
    )

    metrics = {
        "session_count": len(equities),
        "month_count": len(monthly_returns),
        "ending_equity": _rounded(equities[-1] if equities else starting_equity),
        "total_return_pct": _rounded(total_return_pct),
        "annualized_return_pct": _rounded(annualized_return_pct),
        "annualized_volatility_pct": _rounded(annualized_volatility_pct),
        "sharpe_ratio": _rounded(sharpe_ratio),
        "max_drawdown_pct": _rounded(max_drawdown_pct),
        "longest_drawdown_days": longest_drawdown_days,
        "positive_month_ratio": _rounded(positive_month_ratio),
        "best_month_pct": _rounded(max(monthly_returns) * 100) if monthly_returns else None,
        "worst_month_pct": _rounded(min(monthly_returns) * 100) if monthly_returns else None,
    }

    def at_least(metric: str, threshold: str) -> bool:
        value = metrics[metric]
        return value is not None and float(value) >= thresholds[threshold] - 1e-12

    def at_most(metric: str, threshold: str) -> bool:
        value = metrics[metric]
        return value is not None and float(value) <= thresholds[threshold] + 1e-12

    checks = [
        {
            "code": "MINIMUM_TOTAL_RETURN",
            "passed": at_least("total_return_pct", "minimum_total_return_pct"),
        },
        {
            "code": "MINIMUM_ANNUALIZED_RETURN",
            "passed": at_least(
                "annualized_return_pct", "minimum_annualized_return_pct"
            ),
        },
        {
            "code": "MINIMUM_SHARPE_RATIO",
            "passed": at_least("sharpe_ratio", "minimum_sharpe_ratio"),
        },
        {
            "code": "MINIMUM_POSITIVE_MONTH_RATIO",
            "passed": at_least(
                "positive_month_ratio", "minimum_positive_month_ratio"
            ),
        },
        {
            "code": "MAXIMUM_PERFORMANCE_DRAWDOWN",
            "passed": at_most(
                "max_drawdown_pct", "maximum_performance_drawdown_pct"
            ),
        },
        {
            "code": "MAXIMUM_ANNUALIZED_VOLATILITY",
            "passed": at_most(
                "annualized_volatility_pct", "maximum_annualized_volatility_pct"
            ),
        },
    ]
    identity = {
        "schema": FORWARD_PERFORMANCE_SCHEMA,
        "source": "FORMAL_FORWARD_SESSIONS_ONLY",
        "initial_cash": round(starting_equity, 6),
        "first_session": dates[0].isoformat() if dates else None,
        "last_session": dates[-1].isoformat() if dates else None,
        "thresholds": thresholds,
        "metrics": metrics,
        "checks": checks,
        "passed": bool(checks) and all(item["passed"] for item in checks),
    }
    return {**identity, "evidence_sha256": sha256_digest(identity)}
