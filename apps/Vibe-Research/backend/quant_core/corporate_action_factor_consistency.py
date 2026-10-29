"""Cross-product consistency for raw prices, factors and corporate actions."""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any

from .corporate_actions import (
    CorporateActionEconomicsError,
    validate_corporate_action_economics,
)
from .provenance import sha256_digest


CORPORATE_ACTION_FACTOR_CONSISTENCY_SCHEMA = (
    "quant-core/corporate-action-factor-consistency/v1"
)
DEFAULT_REFERENCE_PRICE_ABSOLUTE_TOLERANCE = 0.011
DEFAULT_REFERENCE_PRICE_RELATIVE_TOLERANCE = 0.0001


def _day(value: Any, field: str) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be an ISO date") from exc


def _positive(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a finite positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{field} must be a finite positive number")
    return result


def build_corporate_action_factor_consistency(
    *,
    raw_price_records: Sequence[Mapping[str, Any]],
    adjustment_factor_records: Sequence[Mapping[str, Any]],
    corporate_action_records: Sequence[Mapping[str, Any]],
    reference_price_absolute_tolerance: float = (
        DEFAULT_REFERENCE_PRICE_ABSOLUTE_TOLERANCE
    ),
    reference_price_relative_tolerance: float = (
        DEFAULT_REFERENCE_PRICE_RELATIVE_TOLERANCE
    ),
) -> dict[str, Any]:
    """Reconcile each economic event against the factor transition it implies.

    If ``F_before`` and ``F_after`` are qfq multipliers, continuity implies
    ``previous_close * F_before / F_after == (previous_close - cash) / split``.
    Factor rebasing cancels out, so independent providers may use different
    absolute anchors without weakening this check.
    """

    absolute = float(reference_price_absolute_tolerance)
    relative = float(reference_price_relative_tolerance)
    if not math.isfinite(absolute) or not math.isfinite(relative):
        raise ValueError("corporate-action factor tolerances must be finite")
    if absolute < 0 or relative < 0:
        raise ValueError("corporate-action factor tolerances cannot be negative")

    errors: list[str] = []
    raw_by_asset: dict[str, dict[date, float]] = defaultdict(dict)
    for raw in raw_price_records:
        asset = str(raw.get("asset_id") or "").strip()
        try:
            session = _day(raw.get("trade_date"), "raw trade_date")
            close = _positive(raw.get("close"), "raw close")
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not asset:
            errors.append("raw price has a blank asset_id")
        elif session in raw_by_asset[asset]:
            errors.append(f"duplicate raw price: {asset}@{session.isoformat()}")
        else:
            raw_by_asset[asset][session] = close

    factors_by_asset: dict[str, dict[date, float]] = defaultdict(dict)
    for raw in adjustment_factor_records:
        asset = str(raw.get("asset_id") or "").strip()
        try:
            effective = _day(raw.get("effective_date"), "factor effective_date")
            factor = _positive(raw.get("factor"), "adjustment factor")
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if str(raw.get("factor_semantics") or "") != "qfq_multiplier":
            errors.append(f"unsupported factor semantics: {asset}@{effective.isoformat()}")
        elif not asset:
            errors.append("adjustment factor has a blank asset_id")
        elif effective in factors_by_asset[asset]:
            errors.append(f"duplicate adjustment factor: {asset}@{effective.isoformat()}")
        else:
            factors_by_asset[asset][effective] = factor

    grouped_actions: dict[tuple[str, date], list[dict[str, Any]]] = defaultdict(list)
    skipped_delisting_recoveries = 0
    for raw in corporate_action_records:
        try:
            economics = validate_corporate_action_economics(raw)
            effective = _day(
                raw.get("effective_date"), "corporate-action effective_date"
            )
        except (CorporateActionEconomicsError, ValueError) as exc:
            errors.append(str(exc))
            continue
        asset = str(raw.get("asset_id") or "").strip()
        if not asset:
            errors.append("corporate action has a blank asset_id")
            continue
        if economics["event_type"] == "delisting_cash_recovery":
            skipped_delisting_recoveries += 1
            continue
        grouped_actions[(asset, effective)].append(economics)

    checks: list[dict[str, Any]] = []
    skipped_pre_window_event_dates = 0
    for (asset, effective), actions in sorted(grouped_actions.items()):
        raw_rows = raw_by_asset.get(asset, {})
        factor_rows = factors_by_asset.get(asset, {})
        raw_dates = sorted(raw_rows)
        if raw_dates and effective < raw_dates[0]:
            skipped_pre_window_event_dates += 1
            continue
        check_errors: list[str] = []
        previous_dates = [session for session in raw_dates if session < effective]
        if not previous_dates:
            check_errors.append("event has no previous raw trading session")
        if effective not in raw_rows:
            check_errors.append("event has no event-session raw price")
        previous_factor_dates = [day for day in factor_rows if day < effective]
        if not previous_factor_dates:
            check_errors.append("event has no pre-event qfq factor")
        if effective not in factor_rows:
            check_errors.append("event has no qfq factor effective on event date")
        event_types = sorted(item["event_type"] for item in actions)
        if check_errors:
            label = f"{asset}@{effective.isoformat()}"
            errors.extend(f"{label}: {message}" for message in check_errors)
            checks.append(
                {
                    "asset_id": asset,
                    "effective_date": effective.isoformat(),
                    "event_types": event_types,
                    "passed": False,
                    "errors": check_errors,
                }
            )
            continue

        previous_date = max(previous_dates)
        factor_before_date = max(previous_factor_dates)
        previous_close = raw_rows[previous_date]
        factor_before = factor_rows[factor_before_date]
        factor_after = factor_rows[effective]
        cash = sum(
            float(item["cash_per_share"] or 0.0)
            for item in actions
            if item["event_type"] == "cash_distribution"
        )
        split = math.prod(
            float(item["split_ratio"] or 1.0)
            for item in actions
            if item["event_type"] == "split"
        )
        theoretical = (previous_close - cash) / split
        implied = previous_close * factor_before / factor_after
        tolerance = absolute + relative * abs(theoretical)
        difference = abs(implied - theoretical)
        passed = theoretical > 0 and difference <= tolerance
        check = {
            "asset_id": asset,
            "effective_date": effective.isoformat(),
            "event_types": event_types,
            "previous_trade_date": previous_date.isoformat(),
            "factor_before_date": factor_before_date.isoformat(),
            "previous_close": previous_close,
            "cash_per_share_total": cash,
            "split_ratio_total": split,
            "factor_before": factor_before,
            "factor_after": factor_after,
            "theoretical_ex_reference_price": theoretical,
            "factor_implied_ex_reference_price": implied,
            "absolute_difference": difference,
            "allowed_tolerance": tolerance,
            "passed": passed,
            "errors": [],
        }
        if theoretical <= 0:
            check["errors"].append("declared actions imply a non-positive ex reference")
        elif not passed:
            check["errors"].append(
                "factor transition contradicts corporate-action economics"
            )
        if check["errors"]:
            errors.extend(
                f"{asset}@{effective.isoformat()}: {message}"
                for message in check["errors"]
            )
        checks.append(check)

    identity = {
        "schema": CORPORATE_ACTION_FACTOR_CONSISTENCY_SCHEMA,
        "reference_price_absolute_tolerance": absolute,
        "reference_price_relative_tolerance": relative,
        "checked_event_date_count": len(checks),
        "passed_event_date_count": sum(item["passed"] for item in checks),
        "skipped_pre_window_event_date_count": skipped_pre_window_event_dates,
        "skipped_delisting_recovery_count": skipped_delisting_recoveries,
        "checks": checks,
        "errors": errors,
        "passed": not errors,
        "real_orders": False,
    }
    return {**identity, "report_sha256": sha256_digest(identity)}
