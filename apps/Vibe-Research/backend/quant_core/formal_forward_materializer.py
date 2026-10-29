"""Deterministic strategy inputs derived from verified formal provider products.

The formal P2/I7 runners never trust a locally prepared calendar, signal file or
market-session snapshot.  They re-load the exact dual-authority provider
revisions, reconcile them, and build the runner payload in memory with this
frozen materializer.  The payload hashes and source-bundle hash are bound into
the immutable forward receipts.
"""

from __future__ import annotations

import math
from datetime import date, datetime
from typing import Any, Iterable, Mapping, Sequence
from zoneinfo import ZoneInfo

from .corporate_actions import (
    CANONICAL_CORPORATE_ACTION_EVENT_TYPES,
    CorporateActionEconomicsError,
    validate_corporate_action_economics,
)
from .corporate_action_factor_consistency import (
    DEFAULT_REFERENCE_PRICE_ABSOLUTE_TOLERANCE,
    DEFAULT_REFERENCE_PRICE_RELATIVE_TOLERANCE,
    build_corporate_action_factor_consistency,
)
from .formal_forward_data import (
    FormalForwardDataError,
    load_verified_formal_forward_products,
)
from .provider_contract import ProviderDeliveryStore
from .provider_readiness import (
    ProviderReadinessError,
    resolve_formal_data_readiness_policy,
)
from .provenance import sha256_digest


FORMAL_FORWARD_MATERIALIZATION_SCHEMA = (
    "quant-platform/formal-forward-materialization/v1"
)
FORMAL_FORWARD_MATERIALIZER_ID = (
    "quant_core.formal_forward_materializer/v1"
)
P2_STRATEGY_ID = "diversified_etf_trend_p2"
I7_STRATEGY_ID = "independent_multifactor_i7_forward_only"
FORMAL_STRATEGIES = {P2_STRATEGY_ID, I7_STRATEGY_ID}
ETF_QFQ_INPUT_SCHEMA = "quant-platform/point-in-time-etf-qfq-close-proxy/v1"
STOCK_FACTOR_INPUT_SCHEMA = (
    "quant-platform/point-in-time-stock-multifactor-input/v1"
)
MARKET_SESSION_SCHEMA = "quant-platform/market-session/v2"
CANONICAL_INDUSTRY_TAXONOMY = "platform-industry-crosswalk-v1"

ACTIVE_MEMBERSHIP_EVENTS = {
    "add",
    "added",
    "enter",
    "include",
    "included",
    "member",
    "active",
    "update",
}
INACTIVE_MEMBERSHIP_EVENTS = {
    "remove",
    "removed",
    "exit",
    "exclude",
    "excluded",
    "inactive",
}
SUSPEND_EVENTS = {"suspend", "suspended", "trading_suspension"}
RESUME_EVENTS = {"resume", "resumed", "trading_resume"}
ST_ENTER_EVENTS = {
    "st",
    "st_enter",
    "special_treatment",
    "risk_warning",
}
ST_EXIT_EVENTS = {"st_exit", "remove_st", "special_treatment_removed"}
DELIST_EVENTS = {
    "delist",
    "delisted",
    "delisting",
    "delisting_risk",
    "terminate_listing",
}
LISTED_EVENTS = {"listed", "listing", "resume_listing"}
SUPPORTED_CORPORATE_ACTIONS = set(CANONICAL_CORPORATE_ACTION_EVENT_TYPES)


class FormalForwardMaterializationError(RuntimeError):
    """Raised when verified provider rows cannot form an exact runner input."""


def _day(value: Any, label: str) -> date:
    try:
        return value if isinstance(value, date) else date.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise FormalForwardMaterializationError(f"{label} must be an ISO date") from exc


def _timestamp(value: Any, label: str) -> datetime:
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise FormalForwardMaterializationError(
            f"{label} must be an ISO timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise FormalForwardMaterializationError(f"{label} must include a timezone")
    return parsed


def _number(value: Any, label: str, *, positive: bool = False) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError) as exc:
        raise FormalForwardMaterializationError(f"{label} must be numeric") from exc
    if not math.isfinite(result) or (positive and result <= 0):
        qualifier = "positive and " if positive else ""
        raise FormalForwardMaterializationError(
            f"{label} must be {qualifier}finite"
        )
    return result


def _event_name(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _records(products: Mapping[str, Any], product_id: str) -> list[dict[str, Any]]:
    rows = products.get(product_id)
    if not isinstance(rows, list):
        raise FormalForwardMaterializationError(
            f"verified product is missing: {product_id}"
        )
    return [dict(item) for item in rows]


def _calendar_dates(
    products: Mapping[str, Any], *, must_include: date, history: int
) -> tuple[list[date], list[date]]:
    dates = sorted(
        {
            _day(item.get("trade_date"), "calendar.trade_date")
            for item in _records(products, "calendar")
        }
    )
    if must_include not in dates:
        raise FormalForwardMaterializationError(
            "formal calendar omits the requested session"
        )
    prior = [item for item in dates if item <= must_include]
    if len(prior) < history:
        raise FormalForwardMaterializationError(
            f"formal calendar requires at least {history} sessions through the requested date"
        )
    return dates, prior[-history:]


def _asset_date_rows(
    rows: Sequence[Mapping[str, Any]], *, date_field: str
) -> dict[tuple[str, date], dict[str, Any]]:
    result: dict[tuple[str, date], dict[str, Any]] = {}
    for raw in rows:
        item = dict(raw)
        key = (
            str(item.get("asset_id") or ""),
            _day(item.get(date_field), f"{date_field}"),
        )
        if not key[0] or key in result:
            raise FormalForwardMaterializationError(
                f"duplicate or blank asset/date row in {date_field} product"
            )
        result[key] = item
    return result


def _factor_rows(
    products: Mapping[str, Any], *, cutoff_date: date
) -> dict[str, list[tuple[date, float]]]:
    result: dict[str, list[tuple[date, float]]] = {}
    for item in _records(products, "adjustment_factors"):
        code = str(item.get("asset_id") or "")
        effective = _day(item.get("effective_date"), "factor.effective_date")
        semantics = _event_name(item.get("factor_semantics"))
        if not code or semantics != "qfq_multiplier":
            raise FormalForwardMaterializationError(
                "formal adjustment factors must use qfq_multiplier semantics"
            )
        if effective <= cutoff_date:
            result.setdefault(code, []).append(
                (effective, _number(item.get("factor"), f"{code}.factor", positive=True))
            )
    for code, rows in result.items():
        rows.sort(key=lambda item: item[0])
        if len({item[0] for item in rows}) != len(rows):
            raise FormalForwardMaterializationError(
                f"duplicate adjustment-factor effective date for {code}"
            )
    return result


def _factor_at(
    factors: Mapping[str, Sequence[tuple[date, float]]], code: str, session: date
) -> float:
    eligible = [value for effective, value in factors.get(code, ()) if effective <= session]
    if not eligible:
        raise FormalForwardMaterializationError(
            f"no qfq multiplier is effective for {code} on {session}"
        )
    return float(eligible[-1])


def _master_rows(products: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in _records(products, "security_master"):
        item = dict(raw)
        code = str(item.get("asset_id") or "")
        if not code or code in result:
            raise FormalForwardMaterializationError(
                "formal security master contains duplicate or blank assets"
            )
        result[code] = item
    return result


def _effective_events(
    rows: Iterable[Mapping[str, Any]], *, as_of: date, cutoff: datetime
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for raw in rows:
        item = dict(raw)
        code = str(item.get("asset_id") or "")
        effective = _day(item.get("effective_date"), "event.effective_date")
        announced = _timestamp(item.get("announced_at"), "event.announced_at")
        available = _timestamp(item.get("available_at"), "event.available_at")
        if available < announced:
            raise FormalForwardMaterializationError(
                f"event available_at predates announced_at for {code}"
            )
        if effective <= as_of and announced <= cutoff and available <= cutoff:
            item["_effective"] = effective
            item["_announced"] = announced
            item["_available"] = available
            result.setdefault(code, []).append(item)
    for values in result.values():
        values.sort(
            key=lambda item: (
                item["_effective"], item["_announced"], item["_available"],
                _event_name(item.get("event_type")),
            )
        )
    return result


def _status_snapshot(
    products: Mapping[str, Any], *, as_of: date, cutoff: datetime
) -> dict[str, dict[str, Any]]:
    events = _effective_events(
        _records(products, "security_status_events"), as_of=as_of, cutoff=cutoff
    )
    result: dict[str, dict[str, Any]] = {}
    recognized = (
        SUSPEND_EVENTS
        | RESUME_EVENTS
        | ST_ENTER_EVENTS
        | ST_EXIT_EVENTS
        | DELIST_EVENTS
        | LISTED_EVENTS
    )
    for code, rows in events.items():
        state = {
            "suspended": False,
            "is_st": False,
            "delisting": False,
            "available_at": None,
        }
        for item in rows:
            event = _event_name(item.get("event_type"))
            if event not in recognized:
                raise FormalForwardMaterializationError(
                    f"unsupported security-status event for {code}: {event}"
                )
            if event in SUSPEND_EVENTS:
                state["suspended"] = True
            elif event in RESUME_EVENTS:
                state["suspended"] = False
            elif event in ST_ENTER_EVENTS:
                state["is_st"] = True
            elif event in ST_EXIT_EVENTS:
                state["is_st"] = False
            elif event in DELIST_EVENTS:
                state["delisting"] = True
            elif event in LISTED_EVENTS:
                state["delisting"] = False
            state["available_at"] = item["_available"].isoformat()
        result[code] = state
    return result


def _corporate_action_state(
    products: Mapping[str, Any], *, as_of: date, cutoff: datetime
) -> dict[str, list[dict[str, Any]]]:
    records = _records(products, "corporate_actions")
    for item in records:
        try:
            validate_corporate_action_economics(item)
        except CorporateActionEconomicsError as exc:
            raise FormalForwardMaterializationError(
                f"invalid formal corporate-action economics: {exc}"
            ) from exc
        effective = _day(
            item.get("effective_date"), "corporate_action.effective_date"
        )
        announced = _timestamp(
            item.get("announced_at"), "corporate_action.announced_at"
        )
        if announced.astimezone(ZoneInfo("Asia/Shanghai")).date() > effective:
            raise FormalForwardMaterializationError(
                "formal corporate action was announced after its effective date"
            )
    return _effective_events(records, as_of=as_of, cutoff=cutoff)


def _corporate_action_factor_consistency(
    products: Mapping[str, Any],
    *,
    as_of: date,
    cutoff: datetime,
    numeric_tolerances: Mapping[str, Any],
) -> dict[str, Any]:
    actions = _corporate_action_state(products, as_of=as_of, cutoff=cutoff)
    report = build_corporate_action_factor_consistency(
        raw_price_records=_records(products, "execution_prices"),
        adjustment_factor_records=_records(products, "adjustment_factors"),
        corporate_action_records=[
            item for rows in actions.values() for item in rows
        ],
        reference_price_absolute_tolerance=float(
            numeric_tolerances.get("corporate_action_reference_price_absolute")
            if numeric_tolerances.get("corporate_action_reference_price_absolute")
            is not None
            else DEFAULT_REFERENCE_PRICE_ABSOLUTE_TOLERANCE
        ),
        reference_price_relative_tolerance=float(
            numeric_tolerances.get("corporate_action_reference_price_relative")
            if numeric_tolerances.get("corporate_action_reference_price_relative")
            is not None
            else DEFAULT_REFERENCE_PRICE_RELATIVE_TOLERANCE
        ),
    )
    if report["passed"] is not True:
        raise FormalForwardMaterializationError(
            "corporate-action/factor consistency failed: "
            + "; ".join(str(item) for item in report["errors"][:3])
        )
    return report


def _listing_state(
    master: Mapping[str, Any], *, code: str, as_of: date, cutoff: datetime
) -> tuple[str, date, bool]:
    item = dict(master.get(code) or {})
    if not item:
        raise FormalForwardMaterializationError(
            f"security master is missing required asset {code}"
        )
    listed_at = _day(item.get("listed_at"), f"{code}.listed_at")
    if _timestamp(item.get("available_at"), f"{code}.master.available_at") > cutoff:
        raise FormalForwardMaterializationError(
            f"security master was unavailable at cutoff for {code}"
        )
    announced = item.get("delisting_announced_at")
    if announced not in (None, "") and _timestamp(
        announced, f"{code}.delisting_announced_at"
    ) > cutoff:
        raise FormalForwardMaterializationError(
            f"security master contains a future delisting announcement for {code}"
        )
    listing_status = str(item.get("listing_status") or "").strip().upper()
    last_trading = item.get("last_trading_date")
    delisted_at = item.get("delisted_at")
    inactive = listing_status != "LISTED" or listed_at > as_of
    if last_trading not in (None, "") and _day(last_trading, f"{code}.last_trading_date") < as_of:
        inactive = True
    if delisted_at not in (None, "") and _day(delisted_at, f"{code}.delisted_at") <= as_of:
        inactive = True
    return listing_status, listed_at, inactive


def _check_adjusted_prices(
    *,
    adjusted: Mapping[tuple[str, date], Mapping[str, Any]],
    raw: Mapping[tuple[str, date], Mapping[str, Any]],
    factors: Mapping[str, Sequence[tuple[date, float]]],
    codes: Sequence[str],
    dates: Sequence[date],
    price_abs: float,
    price_rel: float,
) -> None:
    for code in codes:
        for session in dates:
            left = dict(adjusted.get((code, session)) or {})
            right = dict(raw.get((code, session)) or {})
            if not left or not right:
                raise FormalForwardMaterializationError(
                    f"adjusted/raw price coverage is incomplete for {code} on {session}"
                )
            factor = _factor_at(factors, code, session)
            for field in ("open", "high", "low", "close"):
                adjusted_value = _number(
                    left.get(field), f"adjusted {code}.{field}", positive=True
                )
                raw_value = _number(
                    right.get(field), f"raw {code}.{field}", positive=True
                )
                if not math.isclose(
                    adjusted_value,
                    raw_value * factor,
                    rel_tol=price_rel,
                    abs_tol=price_abs,
                ):
                    raise FormalForwardMaterializationError(
                        f"adjusted price/factor identity failed for {code} {session} {field}"
                    )


def _materialize_p2_signal(
    *,
    strategy_config: Mapping[str, Any],
    products: Mapping[str, Any],
    signal_date: date,
    cutoff: datetime,
    price_abs: float,
    price_rel: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    calendar_dates, required_dates = _calendar_dates(
        products, must_include=signal_date, history=121
    )
    if not any(item > signal_date for item in calendar_dates):
        raise FormalForwardMaterializationError(
            "formal calendar has no next execution session"
        )
    codes = [str(item.get("code") or "") for item in strategy_config.get("universe") or []]
    if len(codes) != 5 or len(set(codes)) != len(codes) or any(not code for code in codes):
        raise FormalForwardMaterializationError("frozen P2 universe is invalid")
    adjusted = _asset_date_rows(
        _records(products, "signal_prices"), date_field="trade_date"
    )
    raw = _asset_date_rows(
        _records(products, "execution_prices"), date_field="trade_date"
    )
    factors = _factor_rows(products, cutoff_date=signal_date)
    _check_adjusted_prices(
        adjusted=adjusted,
        raw=raw,
        factors=factors,
        codes=codes,
        dates=required_dates,
        price_abs=price_abs,
        price_rel=price_rel,
    )
    master = _master_rows(products)
    statuses = _status_snapshot(products, as_of=signal_date, cutoff=cutoff)
    actions = _corporate_action_state(products, as_of=signal_date, cutoff=cutoff)
    series: dict[str, list[dict[str, Any]]] = {}
    for code in codes:
        _, _, inactive = _listing_state(
            master, code=code, as_of=signal_date, cutoff=cutoff
        )
        status = statuses.get(code, {})
        if inactive or status.get("suspended") or status.get("delisting"):
            raise FormalForwardMaterializationError(
                f"P2 asset is not safely tradable at the signal cutoff: {code}"
            )
        unsupported = sorted(
            {
                _event_name(item.get("event_type"))
                for item in actions.get(code, [])
                if _event_name(item.get("event_type"))
                not in SUPPORTED_CORPORATE_ACTIONS
            }
        )
        if unsupported:
            raise FormalForwardMaterializationError(
                f"unsupported P2 corporate action for {code}: {', '.join(unsupported)}"
            )
        series[code] = [
            {
                "date": session.isoformat(),
                "qfq_close_proxy": _number(
                    adjusted[(code, session)].get("close"),
                    f"{code}.qfq_close_proxy",
                    positive=True,
                ),
            }
            for session in required_dates
        ]
    calendar = {"trading_dates": [item.isoformat() for item in calendar_dates]}
    signal = {
        "schema": ETF_QFQ_INPUT_SCHEMA,
        "as_of_date": signal_date.isoformat(),
        "max_event_date": signal_date.isoformat(),
        "series": series,
    }
    return calendar, signal


def _membership_snapshot(
    *,
    products: Mapping[str, Any],
    universe_id: str,
    as_of: date,
    cutoff: datetime,
) -> dict[str, dict[str, Any]]:
    rows = [
        item
        for item in _records(products, "current_official_universe_membership")
        if str(item.get("universe_id") or "").upper() == universe_id.upper()
    ]
    events = _effective_events(rows, as_of=as_of, cutoff=cutoff)
    result: dict[str, dict[str, Any]] = {}
    recognized = ACTIVE_MEMBERSHIP_EVENTS | INACTIVE_MEMBERSHIP_EVENTS
    for code, values in events.items():
        active = False
        available_at = None
        for item in values:
            event = _event_name(item.get("event_type"))
            if event not in recognized:
                raise FormalForwardMaterializationError(
                    f"unsupported universe-membership event for {code}: {event}"
                )
            active = event in ACTIVE_MEMBERSHIP_EVENTS
            available_at = item["_available"].isoformat()
        if active:
            result[code] = {"code": code, "available_at": available_at}
    return result


def _industry_snapshot(
    *, products: Mapping[str, Any], as_of: date, cutoff: datetime
) -> dict[str, dict[str, Any]]:
    events = _effective_events(
        _records(products, "industry_membership"), as_of=as_of, cutoff=cutoff
    )
    result: dict[str, dict[str, Any]] = {}
    recognized = ACTIVE_MEMBERSHIP_EVENTS | INACTIVE_MEMBERSHIP_EVENTS
    for code, values in events.items():
        current: dict[str, Any] | None = None
        for item in values:
            event = _event_name(item.get("event_type"))
            if event not in recognized:
                raise FormalForwardMaterializationError(
                    f"unsupported industry-membership event for {code}: {event}"
                )
            current = item if event in ACTIVE_MEMBERSHIP_EVENTS else None
        if current is not None:
            industry = str(current.get("industry_id") or "")
            taxonomy = str(current.get("industry_taxonomy") or "")
            if not industry or taxonomy != CANONICAL_INDUSTRY_TAXONOMY:
                raise FormalForwardMaterializationError(
                    f"canonical industry identity is missing or unapproved for {code}"
                )
            result[code] = {
                "industry_id": industry,
                "industry_taxonomy": taxonomy,
                "available_at": current["_available"].isoformat(),
            }
    return result


def _fundamental_snapshot(
    *, products: Mapping[str, Any], as_of: date, cutoff: datetime
) -> dict[str, dict[str, Any]]:
    candidates: dict[str, list[dict[str, Any]]] = {}
    for raw in _records(products, "fundamental_publications"):
        item = dict(raw)
        code = str(item.get("asset_id") or "")
        report = _day(item.get("report_period"), "fundamental.report_period")
        published = _timestamp(item.get("published_at"), "fundamental.published_at")
        revised = _timestamp(item.get("revision_time"), "fundamental.revision_time")
        available = _timestamp(item.get("available_at"), "fundamental.available_at")
        if not published <= revised <= available:
            raise FormalForwardMaterializationError(
                f"fundamental time order is invalid for {code}"
            )
        if report <= as_of and available <= cutoff:
            item["_report"] = report
            item["_published"] = published
            item["_revised"] = revised
            item["_available"] = available
            candidates.setdefault(code, []).append(item)
    result: dict[str, dict[str, Any]] = {}
    for code, values in candidates.items():
        latest = max(
            values,
            key=lambda item: (
                item["_report"], item["_published"], item["_revised"], item["_available"]
            ),
        )
        result[code] = {
            "book_to_price": _number(
                latest.get("book_to_price"), f"{code}.book_to_price"
            ),
            "published_at": latest["_published"].isoformat(),
            "available_at": latest["_available"].isoformat(),
        }
    return result


def _materialize_i7_signal(
    *,
    strategy_config: Mapping[str, Any],
    products: Mapping[str, Any],
    signal_date: date,
    cutoff: datetime,
    current_holdings: Sequence[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    calendar_dates, required_dates = _calendar_dates(
        products, must_include=signal_date, history=126
    )
    if not any(item > signal_date for item in calendar_dates):
        raise FormalForwardMaterializationError(
            "formal calendar has no next execution session"
        )
    pool = dict(strategy_config.get("candidate_pool") or {})
    universe_id = str(pool.get("index") or "")
    expected_count = int(pool.get("expected_count") or 0)
    membership = _membership_snapshot(
        products=products,
        universe_id=universe_id,
        as_of=signal_date,
        cutoff=cutoff,
    )
    if expected_count != 300 or len(membership) != expected_count:
        raise FormalForwardMaterializationError(
            "official I7 membership is not an exact 300-asset snapshot"
        )
    holdings = sorted({str(item) for item in current_holdings if str(item)})
    raw = _asset_date_rows(
        _records(products, "execution_prices"), date_field="trade_date"
    )
    indicators = _asset_date_rows(
        _records(products, "daily_market_indicators"), date_field="trade_date"
    )
    factors = _factor_rows(products, cutoff_date=signal_date)
    master = _master_rows(products)
    statuses = _status_snapshot(products, as_of=signal_date, cutoff=cutoff)
    industries = _industry_snapshot(
        products=products, as_of=signal_date, cutoff=cutoff
    )
    fundamentals = _fundamental_snapshot(
        products=products, as_of=signal_date, cutoff=cutoff
    )
    actions = _corporate_action_state(products, as_of=signal_date, cutoff=cutoff)
    assets: dict[str, dict[str, Any]] = {}
    for code in sorted(set(membership) | set(holdings)):
        _, _, inactive = _listing_state(
            master, code=code, as_of=signal_date, cutoff=cutoff
        )
        industry = dict(industries.get(code) or {})
        fundamental = dict(fundamentals.get(code) or {})
        if not industry or not fundamental:
            raise FormalForwardMaterializationError(
                f"I7 point-in-time metadata is incomplete for {code}"
            )
        series: list[dict[str, Any]] = []
        availability = [
            _timestamp(master[code].get("available_at"), f"{code}.master.available_at"),
            _timestamp(industry.get("available_at"), f"{code}.industry.available_at"),
            _timestamp(fundamental.get("available_at"), f"{code}.fundamental.available_at"),
        ]
        for session in required_dates:
            bar = dict(raw.get((code, session)) or {})
            indicator = dict(indicators.get((code, session)) or {})
            if not bar or not indicator:
                raise FormalForwardMaterializationError(
                    f"I7 market/factor coverage is incomplete for {code} on {session}"
                )
            for field in ("pe_ttm", "pb_mrq", "turnover"):
                _number(indicator.get(field), f"{code}.{field}")
            factor = _factor_at(factors, code, session)
            series.append(
                {
                    "date": session.isoformat(),
                    "qfq_close_proxy": _number(
                        bar.get("close"), f"{code}.close", positive=True
                    )
                    * factor,
                    "amount": _number(
                        bar.get("amount"), f"{code}.amount", positive=True
                    ),
                }
            )
            availability.extend(
                [
                    _timestamp(bar.get("available_at"), f"{code}.bar.available_at"),
                    _timestamp(
                        indicator.get("available_at"),
                        f"{code}.indicator.available_at",
                    ),
                ]
            )
        status = statuses.get(code, {})
        if status.get("available_at"):
            availability.append(
                _timestamp(status["available_at"], f"{code}.status.available_at")
            )
        unsupported_actions = {
            _event_name(item.get("event_type"))
            for item in actions.get(code, [])
            if _event_name(item.get("event_type")) not in SUPPORTED_CORPORATE_ACTIONS
        }
        assets[code] = {
            "industry_id": str(industry["industry_id"]),
            "correlation_cluster": f"INDUSTRY:{industry['industry_id']}",
            "listing_status": "DELISTING" if inactive else "LISTED",
            "st_status": bool(status.get("is_st")),
            "suspension_status": bool(status.get("suspended")),
            "delisting_status": bool(
                inactive or status.get("delisting") or unsupported_actions
            ),
            "available_at": max(availability).isoformat(),
            "fundamental": fundamental,
            "series": series,
        }
    calendar = {"trading_dates": [item.isoformat() for item in calendar_dates]}
    signal = {
        "schema": STOCK_FACTOR_INPUT_SCHEMA,
        "as_of_date": signal_date.isoformat(),
        "max_event_date": signal_date.isoformat(),
        "signal_cutoff_at": cutoff.isoformat(),
        "official_membership": [membership[code] for code in sorted(membership)],
        "assets": assets,
        "current_holdings": holdings,
    }
    return calendar, signal


def _materialize_market(
    *,
    strategy_id: str,
    strategy_config: Mapping[str, Any],
    products: Mapping[str, Any],
    trade_date: date,
    cutoff: datetime,
    required_codes: Sequence[str],
) -> dict[str, Any]:
    calendar_dates, history = _calendar_dates(
        products, must_include=trade_date, history=60
    )
    raw = _asset_date_rows(
        _records(products, "execution_prices"), date_field="trade_date"
    )
    if strategy_id == P2_STRATEGY_ID:
        codes = [
            str(item.get("code") or "")
            for item in strategy_config.get("universe") or []
        ]
    else:
        codes = sorted({str(item) for item in required_codes if str(item)})
        if not codes:
            codes = sorted(
                code for code, session in raw if session == trade_date and code
            )
    if not codes or len(codes) != len(set(codes)):
        raise FormalForwardMaterializationError(
            "market materialization has no exact required asset set"
        )
    master = _master_rows(products)
    statuses = _status_snapshot(products, as_of=trade_date, cutoff=cutoff)
    actions = _corporate_action_state(products, as_of=trade_date, cutoff=cutoff)
    # Valuation requires the adjustment/corporate-action products to be usable,
    # even though the execution snapshot deliberately uses raw prices.
    factors = _factor_rows(products, cutoff_date=trade_date)
    bars: dict[str, dict[str, Any]] = {}
    marks: dict[str, float] = {}
    for code in codes:
        _, listed_at, inactive = _listing_state(
            master, code=code, as_of=trade_date, cutoff=cutoff
        )
        _factor_at(factors, code, trade_date)
        current = dict(raw.get((code, trade_date)) or {})
        if not current:
            raise FormalForwardMaterializationError(
                f"final raw execution bar is missing for {code}"
            )
        liquidity: list[dict[str, Any]] = []
        for session in history:
            item = dict(raw.get((code, session)) or {})
            if not item:
                raise FormalForwardMaterializationError(
                    f"60-session liquidity history is incomplete for {code} on {session}"
                )
            liquidity.append(
                {
                    "date": session.isoformat(),
                    "volume": _number(item.get("volume"), f"{code}.volume"),
                }
            )
        status = statuses.get(code, {})
        relevant_actions = [
            item
            for item in actions.get(code, [])
            if item["_effective"] == trade_date
        ]
        unsupported = any(
            _event_name(item.get("event_type")) not in SUPPORTED_CORPORATE_ACTIONS
            for item in relevant_actions
        )
        trading_days_since_listing = sum(
            1 for session in calendar_dates if listed_at <= session <= trade_date
        )
        bar = {
            field: _number(current.get(field), f"{code}.{field}", positive=True)
            for field in ("open", "high", "low", "close", "preclose")
        }
        bar.update(
            {
                "volume": _number(current.get("volume"), f"{code}.volume"),
                "suspended": bool(status.get("suspended")),
                "is_st": bool(status.get("is_st")),
                "trading_days_since_listing": trading_days_since_listing,
                "unsupported_corporate_action": bool(
                    inactive or status.get("delisting") or unsupported
                ),
                "liquidity_history": liquidity,
            }
        )
        bars[code] = bar
        marks[code] = float(bar["close"])
    return {
        "schema": MARKET_SESSION_SCHEMA,
        "trade_date": trade_date.isoformat(),
        "as_of_time": cutoff.isoformat(),
        "max_event_date": trade_date.isoformat(),
        "bars": bars,
        "valuation_marks": marks,
    }


def materialize_formal_forward_inputs(
    *,
    strategy_id: str,
    strategy_config: Mapping[str, Any],
    phase: str,
    as_of_date: str | date,
    cutoff_at: str | datetime,
    products: Mapping[str, Any],
    source_bundle: Mapping[str, Any],
    current_holdings: Sequence[str] = (),
    required_codes: Sequence[str] = (),
    numeric_tolerances: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Pure deterministic transform used by runtime and focused unit tests."""

    strategy = str(strategy_id)
    if strategy not in FORMAL_STRATEGIES or phase not in {"signal", "market"}:
        raise FormalForwardMaterializationError(
            "formal materialization supports only P2/I7 signal or market phases"
        )
    cutoff = _timestamp(cutoff_at, "cutoff_at")
    day = _day(as_of_date, "as_of_date")
    if cutoff.date() != day:
        raise FormalForwardMaterializationError(
            "formal materialization cutoff must be on as_of_date"
        )
    if source_bundle.get("strategy_id") != strategy or source_bundle.get("phase") != phase:
        raise FormalForwardMaterializationError(
            "source-bundle identity does not match materialization"
        )
    tolerances = dict(numeric_tolerances or {})
    corporate_action_factor_report = _corporate_action_factor_consistency(
        products,
        as_of=day,
        cutoff=cutoff,
        numeric_tolerances=tolerances,
    )
    payloads: dict[str, Any]
    holdings = sorted({str(item) for item in current_holdings if str(item)})
    required = sorted({str(item) for item in required_codes if str(item)})
    if phase == "signal":
        if strategy == P2_STRATEGY_ID:
            calendar, signal = _materialize_p2_signal(
                strategy_config=strategy_config,
                products=products,
                signal_date=day,
                cutoff=cutoff,
                price_abs=float(tolerances.get("price_absolute") or 0),
                price_rel=float(tolerances.get("price_relative") or 0),
            )
        else:
            calendar, signal = _materialize_i7_signal(
                strategy_config=strategy_config,
                products=products,
                signal_date=day,
                cutoff=cutoff,
                current_holdings=holdings,
            )
        payloads = {"calendar": calendar, "signal": signal}
    else:
        payloads = {
            "market": _materialize_market(
                strategy_id=strategy,
                strategy_config=strategy_config,
                products=products,
                trade_date=day,
                cutoff=cutoff,
                required_codes=required,
            )
        }
    payload_hashes = {
        key: sha256_digest(value) for key, value in sorted(payloads.items())
    }
    identity = {
        "schema": FORMAL_FORWARD_MATERIALIZATION_SCHEMA,
        "materializer_id": FORMAL_FORWARD_MATERIALIZER_ID,
        "strategy_id": strategy,
        "phase": phase,
        "as_of_date": day.isoformat(),
        "cutoff_at": cutoff.isoformat(),
        "source_bundle_sha256": str(source_bundle.get("source_bundle_sha256") or ""),
        "policy_sha256": str(source_bundle.get("policy_sha256") or ""),
        "current_holdings": holdings,
        "required_codes": required,
        "payload_sha256s": payload_hashes,
        "corporate_action_factor_consistency": corporate_action_factor_report,
        "real_orders": False,
    }
    evidence = {
        **identity,
        "materialization_sha256": sha256_digest(identity),
    }
    return {
        "evidence": evidence,
        "source_bundle": dict(source_bundle),
        "payloads": payloads,
    }


def load_and_materialize_formal_forward_inputs(
    *,
    platform_root: str,
    strategy_id: str,
    strategy_config: Mapping[str, Any],
    phase: str,
    as_of_date: str | date,
    cutoff_at: str | datetime,
    product_references: Mapping[str, Any],
    approved_datasets: list[Mapping[str, Any]],
    current_holdings: Sequence[str] = (),
    required_codes: Sequence[str] = (),
    provider_store: ProviderDeliveryStore | None = None,
) -> dict[str, Any]:
    """Re-load exact provider revisions, reconcile, then materialize inputs."""

    try:
        verified = load_verified_formal_forward_products(
            platform_root=platform_root,
            strategy_id=strategy_id,
            phase=phase,
            cutoff_at=cutoff_at,
            product_references=product_references,
            approved_datasets=approved_datasets,
            provider_store=provider_store,
        )
        policy = resolve_formal_data_readiness_policy(platform_root)["policy"]
    except (FormalForwardDataError, ProviderReadinessError) as exc:
        raise FormalForwardMaterializationError(str(exc)) from exc
    return materialize_formal_forward_inputs(
        strategy_id=strategy_id,
        strategy_config=strategy_config,
        phase=phase,
        as_of_date=as_of_date,
        cutoff_at=cutoff_at,
        products=dict(verified["records"]),
        source_bundle=dict(verified["evidence"]),
        current_holdings=current_holdings,
        required_codes=required_codes,
        numeric_tolerances=dict(policy.get("numeric_tolerances") or {}),
    )
