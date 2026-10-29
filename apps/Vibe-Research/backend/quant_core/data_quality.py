"""Deterministic, content-bound quality and time evidence for P1 data."""

from __future__ import annotations

import hashlib
import json
import math
import re
import statistics
from collections.abc import Sequence
from datetime import date, datetime, time
from pathlib import Path
from typing import Any, Mapping

from .data_catalog import DataCatalog, DataCatalogError
from .provenance import sha256_digest
from .provider_contract import ProviderDeliveryStore


DATA_QUALITY_SCHEMA = "quant-core/data-quality/v1"
REQUIRED_FIELDS = ("date", "open", "high", "low", "close", "volume")
P1_DATA_QUALITY_POLICY_SCHEMA = "quant-platform/p1-forward-data-quality-policy/v1"
P1_DATA_QUALITY_ATTESTATION_SCHEMA = "quant-platform/p1-data-quality-attestation/v2"
P1_DATA_TIME_CONTRACT_SCHEMA = "quant-platform/p1-data-time-contract/v1"
P1_PROVIDER_PAYLOAD_SCHEMA = "quant-platform/provider-p1-normalized-payload/v1"
P1_DATA_QUALITY_POLICY_PATH = "config/data-quality/p1-forward-data-quality-v1.json"
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
SOURCE_PROVIDER_FIELDS = {
    "name",
    "authority",
    "provider_source_id",
    "provider_source_version",
    "provider_endpoint_id",
    "dataset_key",
    "source_sha256",
    "event_time",
    "published_at",
    "revision_id",
    "revision_time",
    "fetched_at",
    "provider_publication_receipt_sha256",
}

_P1_PAYLOAD_SCHEMAS = {
    "calendar": "quant-platform/cn-trading-calendar-forward/v1",
    "signal": "quant-platform/point-in-time-etf-qfq-close-proxy/v1",
    "market": "quant-platform/market-session/v2",
}
_P1_PROVIDER_METADATA_FIELDS = {
    "calendar": {
        "binding_schema",
        "p1_kind",
        "payload_schema",
        "max_known_date",
    },
    "signal": {
        "binding_schema",
        "p1_kind",
        "payload_schema",
        "as_of_date",
        "max_event_date",
    },
    "market": {
        "binding_schema",
        "p1_kind",
        "payload_schema",
        "trade_date",
        "as_of_time",
        "max_event_date",
    },
}
_P1_PROVIDER_RECORD_FIELDS = {
    "calendar": {"trading_date"},
    "signal": {"code", "date", "qfq_close_proxy"},
    "market": {
        "code",
        "open",
        "high",
        "low",
        "close",
        "preclose",
        "volume",
        "liquidity_history",
        "suspended",
        "is_st",
        "trading_days_since_listing",
        "unsupported_corporate_action",
        "valuation_mark",
    },
}


class DataQualityError(RuntimeError):
    """Raised when source corroboration or its evidence is unsafe."""


class DataQualityGateError(ValueError):
    """Raised when a market-data batch contains unsafe observations."""

    def __init__(self, report: Mapping[str, Any]) -> None:
        self.report = dict(report)
        blocking = [
            issue
            for issue in self.report.get("issues", [])
            if issue.get("severity") == "error"
        ]
        detail = blocking[0]["message"] if blocking else "market data failed quality checks"
        super().__init__(detail)


def _issue(
    code: str,
    rule: str,
    severity: str,
    message: str,
    day: str | None = None,
) -> dict[str, Any]:
    item = {"code": code, "rule": rule, "severity": severity, "message": message}
    if day is not None:
        item["date"] = day
    return item


def _number(value: Any, field: str, code: str, day: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{code} {day} 的 {field} 不是数值") from exc
    if not math.isfinite(number):
        raise ValueError(f"{code} {day} 的 {field} 不是有限数值")
    return number


def normalize_market_dataset(
    bars_by_code: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    requested_start: str,
    requested_end: str,
    simulation_start: str,
    benchmark_code: str,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Normalize daily bars and return deterministic quality evidence.

    Unsafe schema/value errors block the batch. Coverage and zero-volume issues
    are retained as degradations because they may represent valid listings,
    suspensions or holidays and must be handled by the execution model.
    """
    start_day = date.fromisoformat(requested_start)
    end_day = date.fromisoformat(requested_end)
    normalized: dict[str, list[dict[str, Any]]] = {}
    issues: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    for raw_code in sorted(bars_by_code, key=str):
        code = str(raw_code)
        rows = bars_by_code[raw_code]
        by_date: dict[str, dict[str, Any]] = {}
        zero_volume_days = 0
        for raw_row in rows:
            missing = [field for field in REQUIRED_FIELDS if field not in raw_row]
            if missing:
                issues.append(
                    _issue(
                        code,
                        "MISSING_REQUIRED_FIELD",
                        "error",
                        f"缺少字段：{', '.join(missing)}",
                    )
                )
                continue
            raw_day = str(raw_row.get("date"))
            try:
                parsed_day = date.fromisoformat(raw_day)
            except ValueError:
                issues.append(_issue(code, "INVALID_DATE", "error", f"非法交易日期：{raw_day}"))
                continue
            if parsed_day < start_day or parsed_day > end_day:
                issues.append(
                    _issue(
                        code,
                        "OUT_OF_REQUEST_RANGE",
                        "error",
                        f"{raw_day} 超出请求区间 {requested_start} 至 {requested_end}",
                        day=raw_day,
                    )
                )
                continue
            try:
                open_price = _number(raw_row["open"], "open", code, raw_day)
                high = _number(raw_row["high"], "high", code, raw_day)
                low = _number(raw_row["low"], "low", code, raw_day)
                close = _number(raw_row["close"], "close", code, raw_day)
                volume = _number(raw_row["volume"], "volume", code, raw_day)
                amount = _number(raw_row.get("amount", 0), "amount", code, raw_day)
            except ValueError as exc:
                issues.append(_issue(code, "INVALID_NUMBER", "error", str(exc), day=raw_day))
                continue
            if min(open_price, high, low, close) <= 0:
                issues.append(
                    _issue(
                        code,
                        "NON_POSITIVE_PRICE",
                        "error",
                        "OHLC 价格必须大于零",
                        day=raw_day,
                    )
                )
                continue
            if high < max(open_price, low, close) or low > min(open_price, high, close):
                issues.append(
                    _issue(
                        code,
                        "INVALID_OHLC",
                        "error",
                        "最高价/最低价与开收盘价矛盾",
                        day=raw_day,
                    )
                )
                continue
            if volume < 0 or amount < 0:
                issues.append(
                    _issue(
                        code,
                        "NEGATIVE_LIQUIDITY",
                        "error",
                        "成交量和成交额不能为负",
                        day=raw_day,
                    )
                )
                continue
            if raw_day in by_date:
                issues.append(
                    _issue(
                        code,
                        "DUPLICATE_DATE",
                        "error",
                        "同一证券出现重复交易日期",
                        day=raw_day,
                    )
                )
                continue
            if volume == 0:
                zero_volume_days += 1
            by_date[raw_day] = {
                **dict(raw_row),
                "date": raw_day,
                "open": open_price,
                "high": high,
                "low": low,
                "close": close,
                "volume": volume,
                "amount": amount,
            }
        ordered = [by_date[day] for day in sorted(by_date)]
        normalized[code] = ordered
        first_day = ordered[0]["date"] if ordered else None
        last_day = ordered[-1]["date"] if ordered else None
        if not ordered:
            issues.append(_issue(code, "EMPTY_SERIES", "error", "没有有效行情记录"))
        elif first_day > requested_start:
            issues.append(
                _issue(
                    code,
                    "LATE_COVERAGE_START",
                    "warning",
                    f"数据从 {first_day} 才开始，晚于请求起点 {requested_start}",
                )
            )
        if ordered and last_day < simulation_start:
            issues.append(
                _issue(
                    code,
                    "STALE_SERIES",
                    "error",
                    f"最新数据 {last_day} 早于回测起点 {simulation_start}",
                )
            )
        if zero_volume_days:
            issues.append(
                _issue(
                    code,
                    "ZERO_VOLUME",
                    "warning",
                    f"发现 {zero_volume_days} 个零成交量交易日",
                )
            )
        assets.append(
            {
                "code": code,
                "rows": len(ordered),
                "start": first_day,
                "end": last_day,
                "zero_volume_days": zero_volume_days,
            }
        )

    benchmark_dates = {
        row["date"]
        for row in normalized.get(benchmark_code, [])
        if simulation_start <= row["date"] <= requested_end
    }
    alignment: list[dict[str, Any]] = []
    if not benchmark_dates:
        issues.append(
            _issue(
                benchmark_code,
                "MISSING_BENCHMARK_CALENDAR",
                "error",
                "基准没有可用回测交易日",
            )
        )
    else:
        for code in sorted(normalized):
            asset_dates = {
                row["date"]
                for row in normalized[code]
                if simulation_start <= row["date"] <= requested_end
            }
            missing = sorted(benchmark_dates - asset_dates)
            ratio = len(missing) / len(benchmark_dates)
            alignment.append(
                {
                    "code": code,
                    "benchmark_days": len(benchmark_dates),
                    "missing_days": len(missing),
                    "missing_ratio_pct": round(ratio * 100, 4),
                    "sample_missing_dates": missing[:5],
                }
            )
            if missing:
                issues.append(
                    _issue(
                        code,
                        "MISSING_BENCHMARK_DATES",
                        "warning",
                        f"相对基准缺少 {len(missing)}/{len(benchmark_dates)} 个交易日",
                    )
                )
    issues.sort(key=lambda item: (item["severity"], item["code"], item["rule"], item.get("date", "")))
    error_count = sum(item["severity"] == "error" for item in issues)
    warning_count = sum(item["severity"] == "warning" for item in issues)
    report = {
        "schema": DATA_QUALITY_SCHEMA,
        "status": "BLOCKED" if error_count else ("DEGRADED" if warning_count else "READY"),
        "error_count": error_count,
        "warning_count": warning_count,
        "assets": assets,
        "alignment": alignment,
        "issues": issues,
    }
    if error_count:
        raise DataQualityGateError(report)
    return normalized, report


def _strict_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise DataQualityError(f"data-quality policy is unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise DataQualityError("data-quality policy must be an object")
    return payload


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _timestamp(value: Any, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise DataQualityError(f"{label} must be a timezone-aware timestamp") from exc
    if parsed.tzinfo is None:
        raise DataQualityError(f"{label} must include a timezone")
    return parsed


def _finite(value: Any, label: str, *, positive: bool = False) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise DataQualityError(f"{label} must be numeric") from exc
    if not math.isfinite(number) or (positive and number <= 0):
        raise DataQualityError(f"{label} must be finite" + (" and positive" if positive else ""))
    return number


def _inside(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise DataQualityError("data-quality policy path escapes platform root") from exc
    return path


def resolve_p1_data_quality_policy(
    platform_root: str | Path,
    relative_path: str = P1_DATA_QUALITY_POLICY_PATH,
) -> dict[str, Any]:
    root = Path(platform_root).expanduser().resolve()
    path = _inside(root, str(relative_path))
    policy = _strict_json(path)
    if (
        policy.get("schema") != P1_DATA_QUALITY_POLICY_SCHEMA
        or policy.get("policy_id") != "p1-forward-data-quality-v1"
        or policy.get("approved_ingest_provider_name") != "reviewed-p1-ingest"
        or int(policy.get("minimum_independent_sources") or 0) < 2
        or policy.get("real_orders") is not False
    ):
        raise DataQualityError("invalid or weakened P1 data-quality policy")
    requirements = dict(policy.get("requirements") or {})
    if set(requirements) != {"calendar", "signal", "market"}:
        raise DataQualityError("P1 data-quality requirements are incomplete")
    for kind in ("calendar", "signal", "market"):
        if _finite(
            dict(requirements[kind]).get("max_source_age_minutes"),
            f"{kind}.max_source_age_minutes",
            positive=True,
        ) <= 0:
            raise DataQualityError(f"invalid {kind} source-age threshold")
    return {
        "policy": policy,
        "policy_path": path.relative_to(root).as_posix(),
        "policy_sha256": _file_sha256(path),
    }


def normalize_source_provider(
    raw: Mapping[str, Any],
    *,
    available_at: str | datetime,
    kind: str,
    policy: Mapping[str, Any],
) -> dict[str, Any]:
    value = dict(raw)
    if set(value) != SOURCE_PROVIDER_FIELDS:
        missing = sorted(SOURCE_PROVIDER_FIELDS - set(value))
        extra = sorted(set(value) - SOURCE_PROVIDER_FIELDS)
        raise DataQualityError(
            "source provider fields mismatch "
            f"(missing={','.join(missing) or '-'}; extra={','.join(extra) or '-'})"
        )
    if value.get("name") != policy.get("approved_ingest_provider_name"):
        raise DataQualityError("source provider is not the frozen reviewed ingest boundary")
    for field in (
        "authority",
        "provider_source_id",
        "provider_source_version",
        "provider_endpoint_id",
        "dataset_key",
        "revision_id",
    ):
        if not str(value.get(field) or "").strip():
            raise DataQualityError(f"source provider {field} is required")
    source_sha = str(value.get("source_sha256") or "").lower()
    if not HASH_RE.fullmatch(source_sha):
        raise DataQualityError("source provider source_sha256 is required")
    receipt_sha = str(
        value.get("provider_publication_receipt_sha256") or ""
    ).lower()
    if not HASH_RE.fullmatch(receipt_sha):
        raise DataQualityError(
            "source provider provider_publication_receipt_sha256 is required"
        )
    event = _timestamp(value.get("event_time"), "provider.event_time")
    published = _timestamp(value.get("published_at"), "provider.published_at")
    revised = _timestamp(value.get("revision_time"), "provider.revision_time")
    fetched = _timestamp(value.get("fetched_at"), "provider.fetched_at")
    available = _timestamp(available_at, "available_at")
    if not event <= published <= revised <= fetched <= available:
        raise DataQualityError(
            "source time order must be event <= published <= revision <= fetched <= available"
        )
    requirement = dict(dict(policy.get("requirements") or {}).get(kind) or {})
    maximum_age = _finite(
        requirement.get("max_source_age_minutes"),
        f"{kind}.max_source_age_minutes",
        positive=True,
    )
    age_minutes = (available - fetched).total_seconds() / 60.0
    if age_minutes > maximum_age + 1e-9:
        raise DataQualityError(f"{kind} source is stale at publication")
    return {
        **value,
        "source_sha256": source_sha,
        "provider_publication_receipt_sha256": receipt_sha,
        "event_time": event.isoformat(),
        "published_at": published.isoformat(),
        "revision_time": revised.isoformat(),
        "fetched_at": fetched.isoformat(),
    }


def _exact_p1_fields(
    value: Mapping[str, Any], expected: set[str], label: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = ",".join(sorted(expected - actual)) or "-"
        extra = ",".join(sorted(actual - expected)) or "-"
        raise DataQualityError(
            f"{label} fields mismatch (missing={missing}; extra={extra})"
        )


def rebuild_p1_payload_from_provider(
    kind: str, provider_payload: Mapping[str, Any]
) -> dict[str, Any]:
    """Deterministically map a receipt-bound provider payload into a P1 input."""

    if kind not in _P1_PAYLOAD_SCHEMAS:
        raise DataQualityError(f"unsupported P1 provider payload kind: {kind}")
    payload = dict(provider_payload)
    _exact_p1_fields(payload, {"records", "metadata"}, "P1 provider payload")
    records = payload.get("records")
    metadata = payload.get("metadata")
    if not isinstance(records, list) or not isinstance(metadata, Mapping):
        raise DataQualityError("P1 provider records and metadata must be structured JSON")
    meta = dict(metadata)
    _exact_p1_fields(
        meta,
        _P1_PROVIDER_METADATA_FIELDS[kind],
        f"P1 provider {kind} metadata",
    )
    if (
        meta.get("binding_schema") != P1_PROVIDER_PAYLOAD_SCHEMA
        or meta.get("p1_kind") != kind
        or meta.get("payload_schema") != _P1_PAYLOAD_SCHEMAS[kind]
    ):
        raise DataQualityError("P1 provider payload identity mismatch")

    normalized_records: list[dict[str, Any]] = []
    for index, raw_record in enumerate(records):
        if not isinstance(raw_record, Mapping):
            raise DataQualityError(f"P1 provider record {index} must be an object")
        record = dict(raw_record)
        _exact_p1_fields(
            record,
            _P1_PROVIDER_RECORD_FIELDS[kind],
            f"P1 provider {kind} record {index}",
        )
        normalized_records.append(record)
    if not normalized_records:
        raise DataQualityError("P1 provider payload records cannot be empty")

    if kind == "calendar":
        dates = [str(item["trading_date"]) for item in normalized_records]
        if len(set(dates)) != len(dates):
            raise DataQualityError("P1 provider calendar contains duplicate dates")
        return {
            "schema": meta["payload_schema"],
            "trading_dates": sorted(dates),
            "max_known_date": str(meta["max_known_date"]),
        }

    if kind == "signal":
        identities: set[tuple[str, str]] = set()
        series: dict[str, list[dict[str, Any]]] = {}
        for record in sorted(
            normalized_records,
            key=lambda item: (str(item["code"]), str(item["date"])),
        ):
            code = str(record["code"])
            day = str(record["date"])
            identity = (code, day)
            if identity in identities:
                raise DataQualityError(
                    f"P1 provider signal contains duplicate code/date: {code}/{day}"
                )
            identities.add(identity)
            series.setdefault(code, []).append(
                {"date": day, "qfq_close_proxy": record["qfq_close_proxy"]}
            )
        return {
            "schema": meta["payload_schema"],
            "as_of_date": str(meta["as_of_date"]),
            "max_event_date": str(meta["max_event_date"]),
            "series": series,
        }

    bars: dict[str, dict[str, Any]] = {}
    marks: dict[str, Any] = {}
    for record in sorted(normalized_records, key=lambda item: str(item["code"])):
        code = str(record["code"])
        if code in bars:
            raise DataQualityError(f"P1 provider market contains duplicate code: {code}")
        bars[code] = {
            key: value
            for key, value in record.items()
            if key not in {"code", "valuation_mark"}
        }
        marks[code] = record["valuation_mark"]
    return {
        "schema": meta["payload_schema"],
        "trade_date": str(meta["trade_date"]),
        "as_of_time": str(meta["as_of_time"]),
        "max_event_date": str(meta["max_event_date"]),
        "bars": bars,
        "valuation_marks": marks,
    }


def verify_p1_provider_publication(
    *,
    provider_store: ProviderDeliveryStore,
    kind: str,
    p1_payload: Mapping[str, Any],
    provider: Mapping[str, Any],
    approved_ingest_provider_name: str,
) -> dict[str, Any]:
    """Reverify a Provider receipt and bind its content to one P1 payload."""

    source = dict(provider)
    receipt_sha = str(
        source.get("provider_publication_receipt_sha256") or ""
    ).lower()
    if not HASH_RE.fullmatch(receipt_sha):
        raise DataQualityError("P1 source provider receipt digest is missing")
    publication = provider_store.verify_publication(receipt_sha)
    if not publication.get("verified"):
        raise DataQualityError(
            "P1 Provider publication receipt verification failed: "
            + "; ".join(str(item) for item in publication.get("errors", []))
        )
    receipt = dict(publication.get("receipt") or {})
    binding = dict(publication.get("binding") or {})
    provider_catalog = dict(binding.get("catalog") or {})
    provider_manifest = dict(provider_catalog.get("manifest") or {})
    provider_identity = dict(provider_manifest.get("provider") or {})
    rebuilt = rebuild_p1_payload_from_provider(
        kind, dict(provider_catalog.get("payload") or {})
    )
    rebuilt_sha = sha256_digest(rebuilt)
    supplied_sha = sha256_digest(dict(p1_payload))
    if rebuilt_sha != supplied_sha:
        raise DataQualityError(
            "P1 payload does not reproduce from the receipt-bound Provider payload"
        )

    delivery_sha = str(receipt.get("delivery_sha256") or "").lower()
    delivery = provider_store.verify_delivery(delivery_sha)
    if not delivery.get("verified"):
        raise DataQualityError(
            "P1 Provider delivery verification failed: "
            + "; ".join(str(item) for item in delivery.get("errors", []))
        )
    envelope = dict(dict(delivery.get("evidence") or {}).get("envelope") or {})
    if envelope.get("usage") != "forward_observation":
        raise DataQualityError(
            "P1 Provider publication is not approved for forward observation"
        )
    origin_evidence = dict(delivery.get("origin_evidence") or {})
    if origin_evidence.get("origin_verified") is not True:
        raise DataQualityError(
            "P1 Provider publication lacks verified upstream provenance evidence"
        )
    expected_provider = {
        "name": str(approved_ingest_provider_name),
        "authority": provider_identity.get("authority"),
        "provider_source_id": envelope.get("source_id"),
        "provider_source_version": envelope.get("source_version"),
        "provider_endpoint_id": envelope.get("endpoint_id"),
        "dataset_key": envelope.get("dataset_key"),
        "source_sha256": dict(envelope.get("raw_artifact") or {}).get("sha256"),
        "event_time": _timestamp(
            envelope.get("event_time"), "provider receipt event_time"
        ).isoformat(),
        "published_at": _timestamp(
            envelope.get("published_at"), "provider receipt published_at"
        ).isoformat(),
        "revision_id": envelope.get("provider_revision_id"),
        "revision_time": _timestamp(
            envelope.get("revision_time"), "provider receipt revision_time"
        ).isoformat(),
        "fetched_at": _timestamp(
            envelope.get("fetched_at"), "provider receipt fetched_at"
        ).isoformat(),
        "provider_publication_receipt_sha256": receipt_sha,
    }
    if source != expected_provider:
        raise DataQualityError(
            "P1 source provider identity does not match its publication receipt"
        )
    return {
        "verified": True,
        "receipt_sha256": receipt_sha,
        "delivery_sha256": delivery_sha,
        "provider_dataset_id": provider_catalog.get("dataset_id"),
        "provider_manifest_sha256": provider_catalog.get("manifest_sha256"),
        "provider_payload_sha256": provider_catalog.get("payload_sha256"),
        "p1_payload_sha256": supplied_sha,
        "origin_evidence": origin_evidence,
    }


def _relative_difference(left: float, right: float) -> float:
    scale = max(abs(left), abs(right))
    return 0.0 if scale == 0 else abs(left - right) / scale


def _check(code: str, passed: bool, **metrics: Any) -> dict[str, Any]:
    return {"code": code, "passed": bool(passed), **metrics}


def evaluate_p1_quality(
    kind: str,
    primary: Mapping[str, Any],
    corroboration: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Recompute source agreement; callers must reject any failed check."""
    requirements = dict(policy.get("requirements") or {})
    rule = dict(requirements.get(kind) or {})
    checks: list[dict[str, Any]] = []
    if kind == "calendar":
        left_dates = list(primary.get("trading_dates") or [])
        right_dates = list(corroboration.get("trading_dates") or [])
        exact = (
            primary.get("schema") == corroboration.get("schema")
            and primary.get("max_known_date") == corroboration.get("max_known_date")
            and left_dates == right_dates
        )
        checks.append(
            _check(
                "CALENDAR_DATES_EXACT",
                exact and rule.get("require_exact_dates") is True,
                primary_session_count=len(left_dates),
                corroboration_session_count=len(right_dates),
            )
        )
    elif kind == "signal":
        left_series = dict(primary.get("series") or {})
        right_series = dict(corroboration.get("series") or {})
        identity_match = (
            primary.get("schema") == corroboration.get("schema")
            and primary.get("as_of_date") == corroboration.get("as_of_date")
            and primary.get("max_event_date") == corroboration.get("max_event_date")
            and set(left_series) == set(right_series)
        )
        checks.append(_check("SIGNAL_IDENTITY_EXACT", identity_match))
        minimum = int(rule.get("minimum_common_sessions") or 0)
        maximum_return = _finite(
            rule.get("max_absolute_daily_return"), "signal.max_absolute_daily_return", positive=True
        )
        maximum_difference = _finite(
            rule.get("max_absolute_daily_return_difference"),
            "signal.max_absolute_daily_return_difference",
            positive=True,
        )
        maximum_median = _finite(
            rule.get("max_median_absolute_daily_return_difference"),
            "signal.max_median_absolute_daily_return_difference",
            positive=True,
        )
        differences: list[float] = []
        source_returns: list[float] = []
        dates_match = identity_match
        for code in sorted(set(left_series) | set(right_series)):
            left_rows = list(left_series.get(code) or [])
            right_rows = list(right_series.get(code) or [])
            if len(left_rows) < minimum or len(right_rows) < minimum:
                dates_match = False
                continue
            left_rows = left_rows[-minimum:]
            right_rows = right_rows[-minimum:]
            left_dates = [str(item.get("date") or "") for item in left_rows]
            right_dates = [str(item.get("date") or "") for item in right_rows]
            if left_dates != right_dates:
                dates_match = False
                continue
            left_prices = [
                _finite(item.get("qfq_close_proxy"), f"{code}.primary", positive=True)
                for item in left_rows
            ]
            right_prices = [
                _finite(item.get("qfq_close_proxy"), f"{code}.corroboration", positive=True)
                for item in right_rows
            ]
            for index in range(1, minimum):
                left_return = left_prices[index] / left_prices[index - 1] - 1.0
                right_return = right_prices[index] / right_prices[index - 1] - 1.0
                source_returns.extend((left_return, right_return))
                differences.append(abs(left_return - right_return))
        observed_max_return = max((abs(value) for value in source_returns), default=math.inf)
        observed_max_difference = max(differences, default=math.inf)
        observed_median = statistics.median(differences) if differences else math.inf
        checks.extend(
            [
                _check(
                    "SIGNAL_COMMON_SESSIONS_EXACT",
                    dates_match and bool(differences),
                    required_sessions=minimum,
                ),
                _check(
                    "SIGNAL_RETURN_SANITY",
                    observed_max_return <= maximum_return,
                    observed_max_absolute_daily_return=round(observed_max_return, 12),
                    threshold=maximum_return,
                ),
                _check(
                    "SIGNAL_RETURN_CROSS_SOURCE_MAX",
                    observed_max_difference <= maximum_difference,
                    observed_max_absolute_difference=round(observed_max_difference, 12),
                    threshold=maximum_difference,
                ),
                _check(
                    "SIGNAL_RETURN_CROSS_SOURCE_MEDIAN",
                    observed_median <= maximum_median,
                    observed_median_absolute_difference=round(observed_median, 12),
                    threshold=maximum_median,
                ),
            ]
        )
    elif kind == "market":
        left_bars = dict(primary.get("bars") or {})
        right_bars = dict(corroboration.get("bars") or {})
        left_marks = dict(primary.get("valuation_marks") or {})
        right_marks = dict(corroboration.get("valuation_marks") or {})
        identity_match = (
            primary.get("schema") == corroboration.get("schema")
            and primary.get("trade_date") == corroboration.get("trade_date")
            and primary.get("max_event_date") == corroboration.get("max_event_date")
            and set(left_bars) == set(right_bars)
            and set(left_marks) == set(right_marks)
        )
        checks.append(_check("MARKET_IDENTITY_EXACT", identity_match))
        price_differences: list[float] = []
        volume_differences: list[float] = []
        close_returns: list[float] = []
        mark_differences: list[float] = []
        statuses_equal = identity_match
        liquidity_dates_equal = identity_match
        status_fields = (
            "suspended",
            "is_st",
            "trading_days_since_listing",
            "unsupported_corporate_action",
        )
        for code in sorted(set(left_bars) | set(right_bars)):
            left = dict(left_bars.get(code) or {})
            right = dict(right_bars.get(code) or {})
            if not left or not right:
                statuses_equal = False
                continue
            for field in ("open", "high", "low", "close", "preclose"):
                left_value = _finite(left.get(field), f"{code}.primary.{field}", positive=True)
                right_value = _finite(right.get(field), f"{code}.corroboration.{field}", positive=True)
                price_differences.append(_relative_difference(left_value, right_value))
            left_volume = _finite(left.get("volume"), f"{code}.primary.volume")
            right_volume = _finite(right.get("volume"), f"{code}.corroboration.volume")
            volume_differences.append(_relative_difference(left_volume, right_volume))
            left_history = list(left.get("liquidity_history") or [])
            right_history = list(right.get("liquidity_history") or [])
            left_dates = [str(item.get("date") or "") for item in left_history]
            right_dates = [str(item.get("date") or "") for item in right_history]
            liquidity_dates_equal = (
                liquidity_dates_equal
                and len(left_history) >= 60
                and left_dates == right_dates
            )
            if left_dates == right_dates:
                for index, (left_row, right_row) in enumerate(
                    zip(left_history, right_history)
                ):
                    left_history_volume = _finite(
                        left_row.get("volume"),
                        f"{code}.primary.liquidity_history.{index}.volume",
                    )
                    right_history_volume = _finite(
                        right_row.get("volume"),
                        f"{code}.corroboration.liquidity_history.{index}.volume",
                    )
                    volume_differences.append(
                        _relative_difference(
                            left_history_volume, right_history_volume
                        )
                    )
            close_returns.extend(
                (
                    _finite(left.get("close"), "close", positive=True)
                    / _finite(left.get("preclose"), "preclose", positive=True)
                    - 1.0,
                    _finite(right.get("close"), "close", positive=True)
                    / _finite(right.get("preclose"), "preclose", positive=True)
                    - 1.0,
                )
            )
            statuses_equal = statuses_equal and all(
                left.get(field) == right.get(field) for field in status_fields
            )
            left_mark = _finite(left_marks.get(code), f"{code}.primary.mark", positive=True)
            right_mark = _finite(right_marks.get(code), f"{code}.corroboration.mark", positive=True)
            price_differences.append(_relative_difference(left_mark, right_mark))
            mark_differences.extend(
                (
                    _relative_difference(left_mark, _finite(left.get("close"), "close", positive=True)),
                    _relative_difference(right_mark, _finite(right.get("close"), "close", positive=True)),
                )
            )
        maximum_price = _finite(
            rule.get("max_relative_price_difference"),
            "market.max_relative_price_difference",
            positive=True,
        )
        maximum_volume = _finite(
            rule.get("max_relative_volume_difference"),
            "market.max_relative_volume_difference",
            positive=True,
        )
        maximum_return = _finite(
            rule.get("max_absolute_close_return"),
            "market.max_absolute_close_return",
            positive=True,
        )
        observed_price = max(price_differences, default=math.inf)
        observed_volume = max(volume_differences, default=math.inf)
        observed_return = max((abs(value) for value in close_returns), default=math.inf)
        observed_mark = max(mark_differences, default=math.inf)
        checks.extend(
            [
                _check(
                    "MARKET_PRICE_CROSS_SOURCE",
                    observed_price <= maximum_price,
                    observed_max_relative_difference=round(observed_price, 12),
                    threshold=maximum_price,
                ),
                _check(
                    "MARKET_VOLUME_CROSS_SOURCE",
                    observed_volume <= maximum_volume,
                    observed_max_relative_difference=round(observed_volume, 12),
                    threshold=maximum_volume,
                ),
                _check(
                    "MARKET_LIQUIDITY_WINDOWS_EXACT",
                    liquidity_dates_equal,
                    minimum_sessions=60,
                ),
                _check(
                    "MARKET_STATUS_EXACT",
                    statuses_equal and rule.get("require_status_equality") is True,
                ),
                _check(
                    "MARKET_CLOSE_RETURN_SANITY",
                    observed_return <= maximum_return,
                    observed_max_absolute_return=round(observed_return, 12),
                    threshold=maximum_return,
                ),
                _check(
                    "MARKET_CLOSE_MARK_CONSISTENCY",
                    observed_mark <= maximum_price
                    and rule.get("require_close_mark_consistency") is True,
                    observed_max_relative_difference=round(observed_mark, 12),
                    threshold=maximum_price,
                ),
            ]
        )
    else:
        raise DataQualityError(f"unsupported P1 data-quality kind: {kind}")
    return checks


def build_p1_time_contract(
    *,
    kind: str,
    payload: Mapping[str, Any],
    provider: Mapping[str, Any],
    available_at: str | datetime,
    earliest_trade_time: str | None,
) -> dict[str, Any]:
    available = _timestamp(available_at, "available_at")
    if kind == "signal":
        feature = _timestamp(f"{payload.get('as_of_date')}T15:00:00+08:00", "feature_time")
        earliest = _timestamp(earliest_trade_time, "earliest_trade_time")
        if earliest <= available or earliest.date() <= feature.date():
            raise DataQualityError("signal earliest_trade_time must be a future session after availability")
        earliest_value: str | None = earliest.isoformat()
    elif kind == "market":
        feature = _timestamp(payload.get("as_of_time"), "feature_time")
        earliest_value = None
    elif kind == "calendar":
        feature = _timestamp(provider.get("published_at"), "feature_time")
        earliest_value = None
    else:
        raise DataQualityError(f"unsupported P1 time-contract kind: {kind}")
    if feature > available:
        raise DataQualityError("feature_time is after catalog availability")
    identity = {
        "schema": P1_DATA_TIME_CONTRACT_SCHEMA,
        "kind": kind,
        "source_event_time": str(provider["event_time"]),
        "source_published_at": str(provider["published_at"]),
        "source_revision_id": str(provider["revision_id"]),
        "source_revision_time": str(provider["revision_time"]),
        "source_fetched_at": str(provider["fetched_at"]),
        "catalog_available_at": available.isoformat(),
        "feature_time": feature.isoformat(),
        "earliest_trade_time": earliest_value,
        "point_in_time_rule": "event_and_revision_available_no_later_than_catalog_available_at",
    }
    return {**identity, "time_contract_sha256": sha256_digest(identity)}


def build_p1_quality_attestation(
    *,
    kind: str,
    primary_payload: Mapping[str, Any],
    primary_provider: Mapping[str, Any],
    corroboration_payload: Mapping[str, Any],
    corroboration_provider: Mapping[str, Any],
    corroboration_manifest: Mapping[str, Any],
    policy: Mapping[str, Any],
    policy_sha256: str,
) -> dict[str, Any]:
    if primary_provider.get("authority") == corroboration_provider.get("authority"):
        raise DataQualityError("P1 corroboration requires independent source authorities")
    if primary_provider.get("provider_source_id") == corroboration_provider.get(
        "provider_source_id"
    ):
        raise DataQualityError("P1 corroboration requires independent registered sources")
    if primary_provider.get("source_sha256") == corroboration_provider.get("source_sha256"):
        raise DataQualityError("P1 corroboration cannot reuse the same source artifact")
    checks = evaluate_p1_quality(kind, primary_payload, corroboration_payload, policy)
    failed = [str(item["code"]) for item in checks if item.get("passed") is not True]
    if failed:
        raise DataQualityError("P1 cross-source checks failed: " + ", ".join(failed))
    identity = {
        "schema": P1_DATA_QUALITY_ATTESTATION_SCHEMA,
        "kind": kind,
        "policy_id": policy["policy_id"],
        "policy_sha256": str(policy_sha256).lower(),
        "minimum_independent_sources": int(policy["minimum_independent_sources"]),
        "primary": {
            "authority": primary_provider["authority"],
            "provider_source_id": primary_provider["provider_source_id"],
            "provider_source_version": primary_provider["provider_source_version"],
            "provider_endpoint_id": primary_provider["provider_endpoint_id"],
            "dataset_key": primary_provider["dataset_key"],
            "source_sha256": primary_provider["source_sha256"],
            "provider_publication_receipt_sha256": primary_provider[
                "provider_publication_receipt_sha256"
            ],
            "payload_sha256": sha256_digest(primary_payload),
        },
        "corroboration": {
            "dataset_id": corroboration_manifest["dataset_id"],
            "manifest_sha256": corroboration_manifest["manifest_sha256"],
            "authority": corroboration_provider["authority"],
            "provider_source_id": corroboration_provider["provider_source_id"],
            "provider_source_version": corroboration_provider[
                "provider_source_version"
            ],
            "provider_endpoint_id": corroboration_provider[
                "provider_endpoint_id"
            ],
            "dataset_key": corroboration_provider["dataset_key"],
            "source_sha256": corroboration_provider["source_sha256"],
            "provider_publication_receipt_sha256": corroboration_provider[
                "provider_publication_receipt_sha256"
            ],
            "payload_sha256": corroboration_manifest["payload_sha256"],
        },
        "checks": checks,
        "passed": True,
    }
    return {**identity, "attestation_sha256": sha256_digest(identity)}


def verify_p1_quality_attestation(
    *,
    catalog: DataCatalog,
    provider_store: ProviderDeliveryStore,
    loaded: Mapping[str, Any],
    policy: Mapping[str, Any],
    policy_sha256: str,
    minimum_independent_sources: int,
) -> dict[str, Any]:
    manifest = dict(loaded.get("manifest") or {})
    metadata = dict(manifest.get("metadata") or {})
    attestation = dict(metadata.get("quality_attestation") or {})
    digest = str(attestation.get("attestation_sha256") or "").lower()
    if not HASH_RE.fullmatch(digest):
        raise DataQualityError("P1 data quality attestation digest is missing")
    identity = {key: value for key, value in attestation.items() if key != "attestation_sha256"}
    if sha256_digest(identity) != digest:
        raise DataQualityError("P1 data quality attestation digest mismatch")
    if (
        attestation.get("schema") != P1_DATA_QUALITY_ATTESTATION_SCHEMA
        or attestation.get("passed") is not True
        or str(attestation.get("policy_sha256") or "").lower() != str(policy_sha256).lower()
        or int(attestation.get("minimum_independent_sources") or 0)
        < int(minimum_independent_sources)
    ):
        raise DataQualityError("P1 data quality attestation policy mismatch")
    kind = str(attestation.get("kind") or "")
    primary_provider = normalize_source_provider(
        dict(manifest.get("provider") or {}),
        available_at=str(manifest.get("available_at") or ""),
        kind=kind,
        policy=policy,
    )
    primary_receipt = verify_p1_provider_publication(
        provider_store=provider_store,
        kind=kind,
        p1_payload=dict(loaded.get("payload") or {}),
        provider=primary_provider,
        approved_ingest_provider_name=str(policy["approved_ingest_provider_name"]),
    )
    primary_identity = dict(attestation.get("primary") or {})
    if primary_identity != {
        "authority": primary_provider["authority"],
        "provider_source_id": primary_provider["provider_source_id"],
        "provider_source_version": primary_provider["provider_source_version"],
        "provider_endpoint_id": primary_provider["provider_endpoint_id"],
        "dataset_key": primary_provider["dataset_key"],
        "source_sha256": primary_provider["source_sha256"],
        "provider_publication_receipt_sha256": primary_provider[
            "provider_publication_receipt_sha256"
        ],
        "payload_sha256": loaded.get("payload_sha256"),
    }:
        raise DataQualityError("P1 primary source binding mismatch")
    corroboration_identity = dict(attestation.get("corroboration") or {})
    try:
        corroboration = catalog.load(
            str(corroboration_identity.get("dataset_id") or ""),
            str(corroboration_identity.get("manifest_sha256") or ""),
        )
    except DataCatalogError as exc:
        raise DataQualityError(f"P1 corroboration snapshot is unavailable: {exc}") from exc
    corroboration_manifest = dict(corroboration.get("manifest") or {})
    corroboration_provider = normalize_source_provider(
        dict(corroboration_manifest.get("provider") or {}),
        available_at=str(corroboration_manifest.get("available_at") or ""),
        kind=kind,
        policy=policy,
    )
    corroboration_receipt = verify_p1_provider_publication(
        provider_store=provider_store,
        kind=kind,
        p1_payload=dict(corroboration.get("payload") or {}),
        provider=corroboration_provider,
        approved_ingest_provider_name=str(policy["approved_ingest_provider_name"]),
    )
    if corroboration_identity != {
        "dataset_id": corroboration.get("dataset_id"),
        "manifest_sha256": corroboration.get("manifest_sha256"),
        "authority": corroboration_provider["authority"],
        "provider_source_id": corroboration_provider["provider_source_id"],
        "provider_source_version": corroboration_provider["provider_source_version"],
        "provider_endpoint_id": corroboration_provider["provider_endpoint_id"],
        "dataset_key": corroboration_provider["dataset_key"],
        "source_sha256": corroboration_provider["source_sha256"],
        "provider_publication_receipt_sha256": corroboration_provider[
            "provider_publication_receipt_sha256"
        ],
        "payload_sha256": corroboration.get("payload_sha256"),
    }:
        raise DataQualityError("P1 corroboration source binding mismatch")
    if primary_provider["authority"] == corroboration_provider["authority"]:
        raise DataQualityError("P1 data sources are not independent")
    if primary_provider["provider_source_id"] == corroboration_provider[
        "provider_source_id"
    ]:
        raise DataQualityError("P1 registered provider sources are not independent")
    recomputed = evaluate_p1_quality(
        kind,
        dict(loaded.get("payload") or {}),
        dict(corroboration.get("payload") or {}),
        policy,
    )
    if recomputed != list(attestation.get("checks") or []) or any(
        item.get("passed") is not True for item in recomputed
    ):
        raise DataQualityError("P1 cross-source checks do not reproduce")
    contract = dict(metadata.get("time_contract") or {})
    rebuilt_contract = build_p1_time_contract(
        kind=kind,
        payload=dict(loaded.get("payload") or {}),
        provider=primary_provider,
        available_at=str(manifest.get("available_at") or ""),
        earliest_trade_time=contract.get("earliest_trade_time"),
    )
    if contract != rebuilt_contract:
        raise DataQualityError("P1 data time contract does not reproduce")
    return {
        "verified": True,
        "kind": kind,
        "attestation_sha256": digest,
        "time_contract_sha256": contract["time_contract_sha256"],
        "independent_authorities": sorted(
            {primary_provider["authority"], corroboration_provider["authority"]}
        ),
        "independent_provider_sources": sorted(
            {
                primary_provider["provider_source_id"],
                corroboration_provider["provider_source_id"],
            }
        ),
        "provider_publication_receipts": sorted(
            {
                primary_receipt["receipt_sha256"],
                corroboration_receipt["receipt_sha256"],
            }
        ),
    }
