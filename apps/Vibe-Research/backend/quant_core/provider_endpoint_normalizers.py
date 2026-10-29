"""Frozen endpoint-specific replay rules for public P1 signal observations."""

from __future__ import annotations

import json
import math
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

from .provider_wire_capture import (
    PROVIDER_WIRE_CAPTURE_MEDIA_TYPE,
    ProviderWireCaptureError,
    load_provider_wire_capture,
)


TENCENT_P1_QFQ_SIGNAL_NORMALIZER_ID = "tencent-p1-qfq-signal/v1"
EASTMONEY_P1_QFQ_SIGNAL_NORMALIZER_ID = "eastmoney-p1-qfq-signal/v1"
P1_SIGNAL_CODES = ("510300", "510500", "511010", "512100", "518880")
P1_SIGNAL_SESSIONS = 121
P1_BINDING_SCHEMA = "quant-platform/provider-p1-normalized-payload/v1"
P1_SIGNAL_PAYLOAD_SCHEMA = "quant-platform/point-in-time-etf-qfq-close-proxy/v1"

_TENCENT_URL = "https://web.ifzq.gtimg.cn/appstock/app/fqkline/get"
_EASTMONEY_URL = "https://push2his.eastmoney.com/api/qt/stock/kline/get"
_EASTMONEY_FIELDS1 = "f1,f2,f3,f4,f5,f6"
_EASTMONEY_FIELDS2 = "f51,f52,f53,f54,f55,f56,f57,f58,f59,f60,f61"
_EASTMONEY_UT = "7eea3edcaed734bea9cbfc24409ed989"


class ProviderEndpointNormalizationError(RuntimeError):
    """A frozen endpoint response cannot produce the promised P1 payload."""


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ProviderEndpointNormalizationError(
                f"endpoint JSON contains a duplicate object key: {key}"
            )
        output[key] = value
    return output


def _json_body(exchange: dict[str, Any]) -> dict[str, Any]:
    content_type = str(exchange["response"]["headers"].get("content-type") or "")
    if content_type and "json" not in content_type.lower():
        raise ProviderEndpointNormalizationError(
            "endpoint response content-type is not JSON"
        )
    body = exchange["response"]["body_bytes"]
    try:
        payload = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object_pairs,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ProviderEndpointNormalizationError(
                    f"endpoint JSON contains a non-finite number: {constant}"
                )
            ),
        )
    except UnicodeDecodeError as exc:
        raise ProviderEndpointNormalizationError(
            "endpoint response is not strict UTF-8"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ProviderEndpointNormalizationError(
            f"endpoint response is invalid JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ProviderEndpointNormalizationError("endpoint response must be a JSON object")
    return payload


def _query(exchange: dict[str, Any]) -> dict[str, str]:
    return {item["name"]: item["value"] for item in exchange["request"]["query"]}


def _iso_date(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ProviderEndpointNormalizationError(f"{label} must be an ISO date")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ProviderEndpointNormalizationError(f"{label} must be an ISO date") from exc
    if parsed.isoformat() != value:
        raise ProviderEndpointNormalizationError(f"{label} must use YYYY-MM-DD")
    return value


def _compact_date(value: str, label: str) -> str:
    if len(value) != 8 or not value.isdigit():
        raise ProviderEndpointNormalizationError(f"{label} must use YYYYMMDD")
    return _iso_date(f"{value[:4]}-{value[4:6]}-{value[6:]}", label)


def _number(value: Any, label: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (str, int, float, Decimal)):
        raise ProviderEndpointNormalizationError(f"{label} is not numeric")
    try:
        decimal = Decimal(str(value))
    except InvalidOperation as exc:
        raise ProviderEndpointNormalizationError(f"{label} is not numeric") from exc
    number = float(decimal)
    if not decimal.is_finite() or not math.isfinite(number):
        raise ProviderEndpointNormalizationError(f"{label} is not finite")
    if positive and number <= 0:
        raise ProviderEndpointNormalizationError(f"{label} must be positive")
    if not positive and number < 0:
        raise ProviderEndpointNormalizationError(f"{label} must be non-negative")
    return number


def _symbol(code: str) -> str:
    return ("sh" if code.startswith(("5", "6", "9")) else "sz") + code


def _secid(code: str) -> str:
    return ("1." if code.startswith(("5", "6", "9")) else "0.") + code


def _validate_row_values(values: list[Any], *, label: str) -> tuple[str, float]:
    if len(values) < 6:
        raise ProviderEndpointNormalizationError(f"{label} has fewer than six fields")
    trading_date = _iso_date(values[0], f"{label}.date")
    open_price = _number(values[1], f"{label}.open", positive=True)
    close_price = _number(values[2], f"{label}.close", positive=True)
    high_price = _number(values[3], f"{label}.high", positive=True)
    low_price = _number(values[4], f"{label}.low", positive=True)
    _number(values[5], f"{label}.volume")
    if high_price < max(open_price, close_price, low_price) or low_price > min(
        open_price, close_price, high_price
    ):
        raise ProviderEndpointNormalizationError(f"{label} has inconsistent OHLC values")
    return trading_date, close_price


def _parse_tencent_exchange(
    exchange: dict[str, Any],
) -> tuple[str, str, str, dict[str, float]]:
    request = exchange["request"]
    if request["url"] != _TENCENT_URL:
        raise ProviderEndpointNormalizationError("Tencent request URL drifted")
    query = _query(exchange)
    if set(query) != {"param"}:
        raise ProviderEndpointNormalizationError("Tencent query contract drifted")
    parts = query["param"].split(",")
    if len(parts) != 6 or parts[1] != "day" or parts[4:] != ["500", "qfq"]:
        raise ProviderEndpointNormalizationError(
            "Tencent query must request 500 qfq daily rows"
        )
    symbol, start, end = parts[0], _iso_date(parts[2], "Tencent start"), _iso_date(
        parts[3], "Tencent end"
    )
    code = symbol[2:] if symbol[:2] in {"sh", "sz"} else ""
    if code not in P1_SIGNAL_CODES or symbol != _symbol(code):
        raise ProviderEndpointNormalizationError("Tencent symbol is outside frozen P1 universe")
    if start > end:
        raise ProviderEndpointNormalizationError("Tencent request start is after end")
    payload = _json_body(exchange)
    if payload.get("code") != 0:
        raise ProviderEndpointNormalizationError("Tencent endpoint reported a failure")
    data = payload.get("data")
    if not isinstance(data, dict) or set(data) != {symbol}:
        raise ProviderEndpointNormalizationError("Tencent response symbol does not match request")
    stock = data[symbol]
    if not isinstance(stock, dict) or not isinstance(stock.get("qfqday"), list):
        raise ProviderEndpointNormalizationError("Tencent qfqday rows are missing")
    rows: dict[str, float] = {}
    for index, values in enumerate(stock["qfqday"]):
        if not isinstance(values, list):
            raise ProviderEndpointNormalizationError("Tencent qfqday row must be an array")
        trading_date, close_price = _validate_row_values(
            values, label=f"Tencent {code} row {index}"
        )
        if not start <= trading_date <= end:
            raise ProviderEndpointNormalizationError("Tencent row is outside requested period")
        if trading_date in rows:
            raise ProviderEndpointNormalizationError("Tencent response has a duplicate date")
        rows[trading_date] = close_price
    return code, start, end, rows


def _parse_eastmoney_exchange(
    exchange: dict[str, Any],
) -> tuple[str, str, str, dict[str, float]]:
    request = exchange["request"]
    if request["url"] != _EASTMONEY_URL:
        raise ProviderEndpointNormalizationError("Eastmoney request URL drifted")
    query = _query(exchange)
    expected_names = {"fields1", "fields2", "ut", "klt", "fqt", "beg", "end", "secid"}
    if set(query) != expected_names:
        raise ProviderEndpointNormalizationError("Eastmoney query contract drifted")
    if (
        query["fields1"] != _EASTMONEY_FIELDS1
        or query["fields2"] != _EASTMONEY_FIELDS2
        or query["ut"] != _EASTMONEY_UT
        or query["klt"] != "101"
        or query["fqt"] != "1"
    ):
        raise ProviderEndpointNormalizationError(
            "Eastmoney query must request qfq daily rows with frozen fields"
        )
    start = _compact_date(query["beg"], "Eastmoney start")
    end = _compact_date(query["end"], "Eastmoney end")
    if start > end:
        raise ProviderEndpointNormalizationError("Eastmoney request start is after end")
    code = query["secid"].split(".", 1)[1] if "." in query["secid"] else ""
    if code not in P1_SIGNAL_CODES or query["secid"] != _secid(code):
        raise ProviderEndpointNormalizationError(
            "Eastmoney symbol is outside frozen P1 universe"
        )
    payload = _json_body(exchange)
    if payload.get("rc") != 0:
        raise ProviderEndpointNormalizationError("Eastmoney endpoint reported a failure")
    data = payload.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("klines"), list):
        raise ProviderEndpointNormalizationError("Eastmoney kline rows are missing")
    response_code = data.get("code")
    if response_code is not None and str(response_code) != code:
        raise ProviderEndpointNormalizationError(
            "Eastmoney response symbol does not match request"
        )
    rows: dict[str, float] = {}
    for index, raw_row in enumerate(data["klines"]):
        if not isinstance(raw_row, str):
            raise ProviderEndpointNormalizationError("Eastmoney kline row must be a string")
        values = raw_row.split(",")
        if len(values) < 7:
            raise ProviderEndpointNormalizationError(
                f"Eastmoney {code} row {index} has fewer than seven fields"
            )
        trading_date, close_price = _validate_row_values(
            values[:6], label=f"Eastmoney {code} row {index}"
        )
        _number(values[6], f"Eastmoney {code} row {index}.amount")
        if not start <= trading_date <= end:
            raise ProviderEndpointNormalizationError("Eastmoney row is outside requested period")
        if trading_date in rows:
            raise ProviderEndpointNormalizationError("Eastmoney response has a duplicate date")
        rows[trading_date] = close_price
    return code, start, end, rows


def replay_p1_qfq_signal_capture(
    raw_bytes: bytes,
    *,
    media_type: str,
    normalizer_id: str,
) -> dict[str, Any]:
    """Turn five frozen endpoint responses into exactly 121 common P1 sessions."""

    if media_type != PROVIDER_WIRE_CAPTURE_MEDIA_TYPE:
        raise ProviderEndpointNormalizationError(
            "endpoint normalizer requires the provider wire capture media type"
        )
    if normalizer_id == TENCENT_P1_QFQ_SIGNAL_NORMALIZER_ID:
        parser = _parse_tencent_exchange
    elif normalizer_id == EASTMONEY_P1_QFQ_SIGNAL_NORMALIZER_ID:
        parser = _parse_eastmoney_exchange
    else:
        raise ProviderEndpointNormalizationError(
            f"unsupported endpoint normalizer: {normalizer_id}"
        )
    try:
        capture = load_provider_wire_capture(raw_bytes)
    except ProviderWireCaptureError as exc:
        raise ProviderEndpointNormalizationError(str(exc)) from exc
    if len(capture["exchanges"]) != len(P1_SIGNAL_CODES):
        raise ProviderEndpointNormalizationError(
            "P1 signal capture must contain exactly one exchange per frozen asset"
        )
    series: dict[str, dict[str, float]] = {}
    requested_periods: set[tuple[str, str]] = set()
    for exchange in capture["exchanges"]:
        code, start, end, rows = parser(exchange)
        if code in series:
            raise ProviderEndpointNormalizationError("P1 signal capture duplicates an asset")
        if len(rows) < P1_SIGNAL_SESSIONS:
            raise ProviderEndpointNormalizationError(
                f"P1 signal capture has fewer than {P1_SIGNAL_SESSIONS} rows for {code}"
            )
        series[code] = rows
        requested_periods.add((start, end))
    if set(series) != set(P1_SIGNAL_CODES):
        raise ProviderEndpointNormalizationError("P1 signal capture universe is incomplete")
    if len(requested_periods) != 1:
        raise ProviderEndpointNormalizationError(
            "P1 signal exchanges must use the same requested period"
        )
    common_dates = sorted(set.intersection(*(set(rows) for rows in series.values())))
    if len(common_dates) < P1_SIGNAL_SESSIONS:
        raise ProviderEndpointNormalizationError(
            "P1 signal capture has fewer than 121 common trading sessions"
        )
    selected_dates = common_dates[-P1_SIGNAL_SESSIONS:]
    records = [
        {
            "code": code,
            "date": trading_date,
            "qfq_close_proxy": series[code][trading_date],
        }
        for code in P1_SIGNAL_CODES
        for trading_date in selected_dates
    ]
    as_of_date = selected_dates[-1]
    return {
        "records": records,
        "metadata": {
            "binding_schema": P1_BINDING_SCHEMA,
            "p1_kind": "signal",
            "payload_schema": P1_SIGNAL_PAYLOAD_SCHEMA,
            "as_of_date": as_of_date,
            "max_event_date": as_of_date,
        },
    }
