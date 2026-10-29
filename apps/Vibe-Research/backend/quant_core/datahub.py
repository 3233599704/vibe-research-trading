"""Versioned market-data contracts and promotion-readiness evidence.

The current workbench can use public adjusted bars for research, but a stable
content hash alone does not make those bars point-in-time safe.  This module
keeps the distinction explicit: a dataset may be reproducible for the current
run while still being unsuitable for historical constituent replay or live
promotion.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from .provenance import sha256_digest


DATAHUB_MANIFEST_SCHEMA = "quant-core/datahub-manifest/v4"

POINT_IN_TIME_CAPABILITIES = (
    "raw_unadjusted_prices",
    "adjustment_factors",
    "corporate_actions",
    "historical_universe_membership",
    "delisted_assets",
    "available_at_timestamps",
    "provider_revision_history",
)

CAPABILITY_BLOCKERS = {
    "raw_unadjusted_prices": (
        "NO_RAW_PRICE_LEDGER",
        "缺少未复权原始行情，无法独立复算历史价格口径。",
    ),
    "adjustment_factors": (
        "NO_ADJUSTMENT_FACTOR_LEDGER",
        "缺少独立复权因子版本，无法识别上游回溯修改。",
    ),
    "corporate_actions": (
        "NO_CORPORATE_ACTION_LEDGER",
        "缺少分红、送转、配股等公司行动事件账本。",
    ),
    "historical_universe_membership": (
        "NO_HISTORICAL_UNIVERSE",
        "缺少当时可知的历史资产池或指数成分关系。",
    ),
    "delisted_assets": (
        "NO_DELISTED_ASSETS",
        "数据集未明确覆盖退市和终止上市资产，存在幸存者偏差风险。",
    ),
    "available_at_timestamps": (
        "NO_AVAILABLE_AT_TIMESTAMPS",
        "字段没有实际可见时间，无法证明历史时点当时已经可知。",
    ),
    "provider_revision_history": (
        "NO_PROVIDER_REVISION_HISTORY",
        "未保存供应商历史版本，无法审计其后续回溯修订。",
    ),
}


def build_datahub_manifest(
    dataset_snapshot: Mapping[str, Any],
    *,
    market: str,
    frequency: str,
    adjustment: str,
    as_of: str,
    providers: Sequence[Mapping[str, Any] | str],
    capabilities: Mapping[str, bool],
    quality: Mapping[str, Any] | None = None,
    catalog_verification: Mapping[str, Any] | None = None,
    provider_delivery_verification: Mapping[str, Any] | None = None,
    require_catalog: bool = False,
) -> dict[str, Any]:
    """Build an immutable data contract and state its safe usage boundary.

    Unknown capability keys are retained as evidence, while every required
    point-in-time capability defaults to ``False``.  This makes the assessment
    fail closed when a new provider has not declared its semantics.
    """

    normalized_capabilities = {
        key: bool(capabilities.get(key, False))
        for key in POINT_IN_TIME_CAPABILITIES
    }
    normalized_capabilities.update(
        {
            str(key): bool(value)
            for key, value in capabilities.items()
            if str(key) not in normalized_capabilities
        }
    )

    blockers = [
        {"code": CAPABILITY_BLOCKERS[key][0], "message": CAPABILITY_BLOCKERS[key][1]}
        for key in POINT_IN_TIME_CAPABILITIES
        if not normalized_capabilities[key]
    ]
    quality_status = str((quality or {}).get("status") or "UNKNOWN")
    assets = list(dataset_snapshot.get("assets") or [])
    if not assets:
        blockers.insert(
            0,
            {"code": "EMPTY_DATASET", "message": "数据快照没有任何资产，不能用于研究或交易验证。"},
        )
    if quality_status == "BLOCKED":
        blockers.insert(
            0,
            {"code": "DATA_QUALITY_BLOCKED", "message": "数据质量门禁已阻断该数据集。"},
        )

    catalog_evidence = {
        "required_for_point_in_time": True,
        "caller_required": bool(require_catalog),
        "verified": bool((catalog_verification or {}).get("verified")),
        "dataset_id": (catalog_verification or {}).get("dataset_id"),
        "revision": (catalog_verification or {}).get("revision"),
        "manifest_sha256": (catalog_verification or {}).get("manifest_sha256"),
        "payload_sha256": (catalog_verification or {}).get("payload_sha256"),
        "errors": list((catalog_verification or {}).get("errors") or []),
    }
    if not catalog_evidence["verified"]:
        blockers.insert(
            0,
            {
                "code": "DATA_CATALOG_UNVERIFIED",
                "message": "数据快照未写入并通过版本化目录校验，不能晋级或与既有实验合并。",
            },
        )

    provider_origin = dict(
        (provider_delivery_verification or {}).get("origin_evidence") or {}
    )
    provider_evidence = {
        "required_for_point_in_time": True,
        "verified": bool((provider_delivery_verification or {}).get("verified")),
        "origin_verified": provider_origin.get("origin_verified") is True,
        "origin_classification": provider_origin.get("classification"),
        "dataset_id": (provider_delivery_verification or {}).get("dataset_id"),
        "manifest_sha256": (provider_delivery_verification or {}).get("manifest_sha256"),
        "delivery_sha256": (provider_delivery_verification or {}).get("delivery_sha256"),
        "errors": list((provider_delivery_verification or {}).get("errors") or []),
    }
    if not provider_evidence["verified"]:
        blockers.insert(
            0,
            {
                "code": "PROVIDER_DELIVERY_UNVERIFIED",
                "message": "数据没有通过来源代码版本、原始文件、供应商修订和用途契约复验，不能声明历史时点完备。",
            },
        )
    elif not provider_evidence["origin_verified"]:
        blockers.insert(
            0,
            {
                "code": "PROVIDER_ORIGIN_UNVERIFIED",
                "message": "Provider 交付虽已内容绑定，但缺少端点传输证据或有效的授权与适配器认证，不能进入 Point-in-Time 就绪状态。",
            },
        )

    point_in_time_ready = not blockers
    research_ready = bool(assets) and quality_status != "BLOCKED"
    if point_in_time_ready:
        readiness = "POINT_IN_TIME_READY"
    elif research_ready:
        readiness = "RESEARCH_ONLY"
    else:
        readiness = "BLOCKED"

    identity = {
        "schema": DATAHUB_MANIFEST_SCHEMA,
        "dataset_sha256": str(dataset_snapshot.get("content_sha256") or ""),
        "market": str(market),
        "frequency": str(frequency),
        "adjustment": str(adjustment),
        "as_of": str(as_of),
        "providers": [
            dict(item) if isinstance(item, Mapping) else {"name": str(item)}
            for item in providers
        ],
        "capabilities": normalized_capabilities,
        "quality_sha256": sha256_digest(quality or {}),
        "catalog": catalog_evidence,
        "provider_delivery": provider_evidence,
    }
    return {
        **identity,
        "manifest_sha256": sha256_digest(identity),
        "readiness": readiness,
        "research_ready": research_ready,
        "point_in_time_ready": point_in_time_ready,
        # Data provenance can admit a dataset into formal research.  It can
        # never, by itself, promote a strategy or authorize an order path.
        "formal_data_admission_eligible": point_in_time_ready,
        "strategy_promotion_eligible": False,
        "promotion_eligible": False,
        "real_orders": False,
        "blockers": blockers,
    }
