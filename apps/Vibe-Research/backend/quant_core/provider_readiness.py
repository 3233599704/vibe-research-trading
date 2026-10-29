"""Machine-verifiable admission posture for complete market-data supply chains."""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Any, Mapping

from .datahub import POINT_IN_TIME_CAPABILITIES
from .provenance import sha256_digest
from .provider_contract import ProviderContractError, ProviderDeliveryStore
from .provider_rehearsal import SYNTHETIC_PROVENANCE_FORBIDDEN
from .strict_contract_json import StrictContractJSONError, strict_json_file_object


FORMAL_DATA_READINESS_POLICY_SCHEMA = "quant-platform/formal-data-readiness-policy/v2"
FORMAL_DATA_READINESS_POLICY_PATH = "config/data-quality/formal-data-readiness-v2.json"
FORMAL_DATA_READINESS_SCHEMA = "quant-platform/formal-data-readiness/v2"

REQUIRED_TIME_CONTRACT = (
    "event_time",
    "published_at",
    "revision_time",
    "fetched_at",
    "available_at",
    "feature_time",
    "earliest_trade_time",
)

_EXPECTED_STRATEGY_REQUIREMENTS = {
    "diversified_etf_trend_p2": {
        "strategy_config_path": "config/strategies/diversified-etf-trend-p2.json",
        "required_products": {
            "calendar",
            "signal_prices",
            "execution_prices",
            "adjustment_factors",
            "corporate_actions",
            "security_master",
            "security_status_events",
        },
        "strategy_data_products": {
            "trading_calendar",
            "adjusted_prices",
            "raw_prices",
            "adjustment_factors",
            "corporate_actions",
            "security_master",
            "security_status_events",
        },
    },
    "independent_multifactor_i7_forward_only": {
        "strategy_config_path": (
            "config/strategies/independent-multifactor-i7-forward-only.json"
        ),
        "required_products": {
            "calendar",
            "execution_prices",
            "adjustment_factors",
            "corporate_actions",
            "current_official_universe_membership",
            "security_master",
            "security_status_events",
            "industry_membership",
            "fundamental_publications",
            "daily_market_indicators",
        },
        "strategy_data_products": {
            "trading_calendar",
            "raw_prices",
            "adjustment_factors",
            "corporate_actions",
            "current_official_universe_membership",
            "security_master",
            "security_status_events",
            "industry_membership",
            "fundamental_publications",
            "daily_market_indicators",
        },
    },
}

_EXPECTED_TRACK_PRODUCTS = {
    "formal_forward": {
        "calendar",
        "signal_prices",
        "execution_prices",
        "adjustment_factors",
        "corporate_actions",
        "current_official_universe_membership",
        "security_master",
        "security_status_events",
        "industry_membership",
        "fundamental_publications",
        "daily_market_indicators",
    },
    "historical_backtest": {
        "trading_calendar",
        "raw_prices",
        "adjustment_factors",
        "corporate_actions",
        "historical_universe",
        "security_master",
        "security_status_events",
        "industry_membership",
        "fundamental_publications",
        "daily_market_indicators",
    },
}

_EXPECTED_NUMERIC_TOLERANCES = {
    "price_absolute": 0.000001,
    "price_relative": 0.000001,
    "volume_absolute": 1.0,
    "volume_relative": 0.0001,
    "factor_absolute": 0.0000000001,
    "factor_relative": 0.00000001,
    "cash_absolute": 0.00000001,
    "cash_relative": 0.000001,
    "split_absolute": 0.00000001,
    "split_relative": 0.000001,
    "corporate_action_reference_price_absolute": 0.011,
    "corporate_action_reference_price_relative": 0.0001,
}

_EXPECTED_SOURCE_ROLES = {
    "primary": {
        "source_id": "rqdata-a-share-primary",
        "authority": "ricequant-rqdata",
    },
    "corroborators": [
        {
            "source_id": "jqdata-a-share-corroboration",
            "authority": "joinquant-jqdata",
        }
    ],
}

_EXPECTED_RECONCILIATION_PRODUCTS = set().union(*_EXPECTED_TRACK_PRODUCTS.values())
_RECONCILIATION_MODES = {
    "exact_fields",
    "numeric_fields",
    "rebased_factor",
    "corporate_action_economics",
}


class ProviderReadinessError(RuntimeError):
    """Raised when the frozen provider-readiness policy cannot be trusted."""


def _structured_error_codes(value: Any) -> list[str]:
    """Collect only explicit error-code fields; never infer from messages."""

    codes: list[str] = []
    if isinstance(value, Mapping):
        code = value.get("error_code")
        if isinstance(code, str) and code:
            codes.append(code)
        listed = value.get("error_codes")
        if isinstance(listed, list):
            codes.extend(item for item in listed if isinstance(item, str) and item)
        for item in value.values():
            codes.extend(_structured_error_codes(item))
    elif isinstance(value, list):
        for item in value:
            codes.extend(_structured_error_codes(item))
    return list(dict.fromkeys(codes))


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = strict_json_file_object(path)
    except (OSError, StrictContractJSONError) as exc:
        raise ProviderReadinessError(
            f"provider readiness policy is unreadable: {exc}"
        ) from exc
    return value


def _unique_nonempty_strings(
    value: Any, label: str, *, allow_empty: bool = False
) -> list[str]:
    if not isinstance(value, list):
        raise ProviderReadinessError(f"{label} must be a list")
    result = [str(item) for item in value]
    if (
        (not result and not allow_empty)
        or any(not item for item in result)
        or len(result) != len(set(result))
    ):
        raise ProviderReadinessError(f"{label} must contain unique non-empty strings")
    return result


def _resolve_bound_file(root: Path, relative_path: str) -> Path:
    if not relative_path or Path(relative_path).is_absolute():
        raise ProviderReadinessError("strategy config path must be relative")
    resolved = (root / relative_path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ProviderReadinessError("strategy config path escapes platform root") from exc
    if not resolved.is_file():
        raise ProviderReadinessError(f"strategy config is missing: {relative_path}")
    return resolved


def resolve_formal_data_readiness_policy(platform_root: str | Path) -> dict[str, Any]:
    root = Path(platform_root).expanduser().resolve()
    path = root / FORMAL_DATA_READINESS_POLICY_PATH
    policy = _read_json(path)
    if set(policy) != {
        "schema",
        "policy_id",
        "required_time_contract",
        "numeric_tolerances",
        "source_roles",
        "reconciliation_rules",
        "strategy_requirements",
        "tracks",
        "akshare_role",
        "strategy_promotion_eligible",
        "real_orders",
    }:
        raise ProviderReadinessError("provider readiness policy fields are invalid")
    if (
        policy.get("schema") != FORMAL_DATA_READINESS_POLICY_SCHEMA
        or policy.get("policy_id") != "formal-data-readiness-v2"
        or policy.get("akshare_role") != "RESEARCH_DIAGNOSTIC_ONLY"
        or policy.get("strategy_promotion_eligible") is not False
        or policy.get("real_orders") is not False
        or tuple(policy.get("required_time_contract") or ())
        != REQUIRED_TIME_CONTRACT
        or policy.get("numeric_tolerances") != _EXPECTED_NUMERIC_TOLERANCES
        or policy.get("source_roles") != _EXPECTED_SOURCE_ROLES
    ):
        raise ProviderReadinessError("provider readiness policy identity is invalid")

    reconciliation_rules = dict(policy.get("reconciliation_rules") or {})
    if set(reconciliation_rules) != _EXPECTED_RECONCILIATION_PRODUCTS:
        raise ProviderReadinessError(
            "provider reconciliation product coverage is invalid"
        )
    for product_id, raw_rule in reconciliation_rules.items():
        rule = dict(raw_rule or {})
        if set(rule) != {
            "mode",
            "coverage",
            "primary_keys",
            "compared_fields",
            "exact_fields",
            "field_tolerances",
        }:
            raise ProviderReadinessError(
                f"provider reconciliation rule fields are invalid: {product_id}"
            )
        primary_keys = _unique_nonempty_strings(
            rule.get("primary_keys"), f"reconciliation primary keys: {product_id}"
        )
        compared_fields = _unique_nonempty_strings(
            rule.get("compared_fields"),
            f"reconciliation compared fields: {product_id}",
            allow_empty=True,
        )
        exact_fields = _unique_nonempty_strings(
            rule.get("exact_fields"),
            f"reconciliation exact fields: {product_id}",
            allow_empty=True,
        )
        tolerances = dict(rule.get("field_tolerances") or {})
        if (
            rule.get("mode") not in _RECONCILIATION_MODES
            or rule.get("coverage") != "exact"
            or "available_at" in set(primary_keys + compared_fields + exact_fields)
            or set(primary_keys) & set(compared_fields + exact_fields)
            or set(compared_fields) & set(exact_fields)
            or set(tolerances) != set(compared_fields)
            or any(
                set(dict(value or {})) != {"absolute", "relative"}
                or isinstance(dict(value or {}).get("absolute"), bool)
                or isinstance(dict(value or {}).get("relative"), bool)
                or not isinstance(dict(value or {}).get("absolute"), (int, float))
                or not isinstance(dict(value or {}).get("relative"), (int, float))
                or not math.isfinite(float(dict(value)["absolute"]))
                or not math.isfinite(float(dict(value)["relative"]))
                or float(dict(value)["absolute"]) < 0
                or float(dict(value)["relative"]) < 0
                for value in tolerances.values()
            )
            or (rule.get("mode") == "exact_fields" and compared_fields)
            or (
                rule.get("mode")
                in {
                    "numeric_fields",
                    "rebased_factor",
                    "corporate_action_economics",
                }
                and not compared_fields
            )
            or (
                rule.get("mode") == "rebased_factor"
                and (
                    primary_keys != ["asset_id", "effective_date"]
                    or compared_fields != ["factor"]
                    or exact_fields != ["factor_semantics"]
                )
            )
            or (
                product_id == "corporate_actions"
                and (
                    rule.get("mode") != "corporate_action_economics"
                    or primary_keys
                    != ["asset_id", "effective_date", "event_type"]
                    or compared_fields != ["cash_per_share", "split_ratio"]
                    or exact_fields != ["announced_at", "economic_semantics"]
                )
            )
            or (
                product_id != "corporate_actions"
                and rule.get("mode") == "corporate_action_economics"
            )
        ):
            raise ProviderReadinessError(
                f"provider reconciliation rule is invalid: {product_id}"
            )

    requirements = dict(policy.get("strategy_requirements") or {})
    if set(requirements) != set(_EXPECTED_STRATEGY_REQUIREMENTS):
        raise ProviderReadinessError("provider readiness strategy requirements are invalid")
    for strategy_id, expected in _EXPECTED_STRATEGY_REQUIREMENTS.items():
        requirement = dict(requirements.get(strategy_id) or {})
        if set(requirement) != {
            "strategy_config_path",
            "strategy_config_sha256",
            "track",
            "required_products",
        }:
            raise ProviderReadinessError(
                f"provider readiness strategy requirement fields are invalid: {strategy_id}"
            )
        config_path = str(requirement.get("strategy_config_path") or "")
        config_file = _resolve_bound_file(root, config_path)
        required_products = set(
            _unique_nonempty_strings(
                requirement.get("required_products"),
                f"strategy required products: {strategy_id}",
            )
        )
        if (
            config_path != expected["strategy_config_path"]
            or requirement.get("track") != "formal_forward"
            or required_products != expected["required_products"]
            or str(requirement.get("strategy_config_sha256") or "")
            != _file_sha256(config_file)
        ):
            raise ProviderReadinessError(
                f"provider readiness strategy requirement binding is invalid: {strategy_id}"
            )
        strategy = _read_json(config_file)
        data_policy = dict(strategy.get("data_policy") or {})
        if (
            strategy.get("strategy_id") != strategy_id
            or strategy.get("forward_only") is not True
            or strategy.get("real_orders") is not False
            or tuple(data_policy.get("required_time_contract") or ())
            != REQUIRED_TIME_CONTRACT
            or int(data_policy.get("minimum_independent_authorities") or 0) < 2
        ):
            raise ProviderReadinessError(
                f"bound strategy data policy is invalid: {strategy_id}"
            )
        expected_strategy_products = expected["strategy_data_products"]
        if expected_strategy_products is not None and set(
            data_policy.get("required_products") or []
        ) != expected_strategy_products:
            raise ProviderReadinessError(
                f"bound strategy data products drifted: {strategy_id}"
            )

    tracks = dict(policy.get("tracks") or {})
    if set(tracks) != {"formal_forward", "historical_backtest"}:
        raise ProviderReadinessError("provider readiness tracks are incomplete")
    for track_id, raw_track in tracks.items():
        track = dict(raw_track or {})
        if set(track) != {"required_usage", "products"} or track.get(
            "required_usage"
        ) != "forward_observation":
            raise ProviderReadinessError(f"provider readiness track is invalid: {track_id}")
        products = dict(track.get("products") or {})
        if set(products) != _EXPECTED_TRACK_PRODUCTS[track_id]:
            raise ProviderReadinessError(
                f"provider readiness track products are invalid: {track_id}"
            )
        for product_id, raw_product in products.items():
            product = dict(raw_product or {})
            if set(product) != {
                "data_kinds",
                "adjustments",
                "required_fields",
                "runner_usages",
                "semantics_version",
                "minimum_independent_authorities",
                "required_endpoint_capabilities",
                "required_delivery_capabilities",
            }:
                raise ProviderReadinessError(
                    f"provider readiness product fields are invalid: {track_id}/{product_id}"
                )
            kinds = _unique_nonempty_strings(
                product.get("data_kinds"), f"data kinds: {track_id}/{product_id}"
            )
            adjustments = _unique_nonempty_strings(
                product.get("adjustments"),
                f"adjustments: {track_id}/{product_id}",
            )
            required_fields = _unique_nonempty_strings(
                product.get("required_fields"),
                f"required fields: {track_id}/{product_id}",
            )
            runner_usages = _unique_nonempty_strings(
                product.get("runner_usages"),
                f"runner usages: {track_id}/{product_id}",
            )
            endpoint_capabilities = _unique_nonempty_strings(
                product.get("required_endpoint_capabilities"),
                f"endpoint capabilities: {track_id}/{product_id}",
            )
            delivery_capabilities = _unique_nonempty_strings(
                product.get("required_delivery_capabilities"),
                f"delivery capabilities: {track_id}/{product_id}",
            )
            if (
                "available_at" not in required_fields
                or not runner_usages
                or not str(product.get("semantics_version") or "")
                or int(product.get("minimum_independent_authorities") or 0) != 2
                or not set(endpoint_capabilities) <= set(POINT_IN_TIME_CAPABILITIES)
                or not set(delivery_capabilities) <= set(POINT_IN_TIME_CAPABILITIES)
            ):
                raise ProviderReadinessError(
                    f"provider readiness product is invalid: {track_id}/{product_id}"
                )
            rule = dict(reconciliation_rules[product_id])
            reconciled_fields = set(rule["primary_keys"]) | set(
                rule["compared_fields"]
            ) | set(rule["exact_fields"])
            if not reconciled_fields <= set(required_fields):
                raise ProviderReadinessError(
                    f"provider reconciliation fields drifted: {track_id}/{product_id}"
                )
    return {
        "policy": policy,
        "policy_path": FORMAL_DATA_READINESS_POLICY_PATH,
        "policy_sha256": _file_sha256(path),
    }


def _matches_contract_identity(
    data_contract: Mapping[str, Any], product: Mapping[str, Any]
) -> bool:
    return (
        str(data_contract.get("kind") or "") in set(product["data_kinds"])
        and str(data_contract.get("adjustment") or "")
        in set(product["adjustments"])
    )


def _matches_product(
    data_contract: Mapping[str, Any], product: Mapping[str, Any]
) -> bool:
    if not _matches_contract_identity(data_contract, product):
        return False
    declared_fields = {str(item) for item in data_contract.get("fields") or []}
    required_fields = {str(item) for item in product.get("required_fields") or []}
    available_at_field = str(data_contract.get("available_at_field") or "")
    record_count = data_contract.get("record_count")
    return (
        isinstance(record_count, int)
        and not isinstance(record_count, bool)
        and record_count > 0
        and required_fields <= declared_fields
        and (
            "available_at" not in required_fields
            or available_at_field == "available_at"
        )
    )


def _endpoint_capabilities_ready(
    endpoint: Mapping[str, Any], product: Mapping[str, Any]
) -> bool:
    ceiling = dict(endpoint.get("capability_ceiling") or {})
    return all(
        ceiling.get(capability) is True
        for capability in product["required_endpoint_capabilities"]
    )


def _publication_rows(
    provider_status: Mapping[str, Any],
    provider_store: ProviderDeliveryStore,
) -> list[dict[str, Any]]:
    deliveries = {
        str(item.get("delivery_sha256") or ""): dict(item)
        for item in list(provider_status.get("deliveries") or [])
        if isinstance(item, Mapping)
    }
    rows: list[dict[str, Any]] = []
    for raw_publication in list(provider_status.get("publications") or []):
        if not isinstance(raw_publication, Mapping) or raw_publication.get("verified") is not True:
            continue
        publication = dict(raw_publication)
        receipt = dict(publication.get("receipt") or {})
        delivery = deliveries.get(str(receipt.get("delivery_sha256") or ""), {})
        if delivery.get("verified") is not True:
            continue
        origin = dict(delivery.get("origin_evidence") or {})
        evidence = dict(delivery.get("evidence") or {})
        envelope = dict(evidence.get("envelope") or {})
        source_contract = dict(evidence.get("source_contract") or {})
        endpoint = next(
            (
                dict(item)
                for item in list(source_contract.get("endpoints") or [])
                if str(item.get("endpoint_id") or "")
                == str(envelope.get("endpoint_id") or "")
            ),
            {},
        )
        dataset_id = str(receipt.get("dataset_id") or "")
        manifest_sha256 = str(receipt.get("manifest_sha256") or "")
        try:
            revision_lineage = provider_store.verify_revision_lineage(
                dataset_id,
                manifest_sha256,
                selected_manifest_sha256=manifest_sha256,
            )
        except (ProviderContractError, TypeError, ValueError) as exc:
            revision_lineage = {
                "verified": False,
                "errors": [str(exc)],
                "lineage_sha256": None,
            }
        rows.append(
            {
                "receipt_sha256": publication.get("receipt_sha256"),
                "delivery_sha256": delivery.get("delivery_sha256"),
                "dataset_id": dataset_id or None,
                "manifest_sha256": manifest_sha256 or None,
                "payload_sha256": receipt.get("payload_sha256"),
                "source_id": envelope.get("source_id"),
                "authority": endpoint.get("authority"),
                "usage": envelope.get("usage"),
                "data_contract": dict(envelope.get("data_contract") or {}),
                "capabilities": dict(envelope.get("capabilities") or {}),
                "origin_verified": origin.get("origin_verified") is True,
                "revision_lineage_verified": revision_lineage.get("verified") is True,
                "revision_lineage_sha256": revision_lineage.get("lineage_sha256"),
                "revision_lineage_errors": list(
                    revision_lineage.get("errors") or []
                ),
            }
        )
    return rows


def _provider_procurement_gate(
    platform_root: Path,
    procurement_status: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Require the independently frozen RQData/JQData trial before admission."""

    if procurement_status is None:
        try:
            from .provider_procurement import assess_provider_procurement

            assessment = dict(assess_provider_procurement(platform_root))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            return {
                "ready": False,
                "status": "DEGRADED",
                "error_code": "PROVIDER_PROCUREMENT_ASSESSMENT_INVALID",
                "error_codes": ["PROVIDER_PROCUREMENT_ASSESSMENT_INVALID"],
                "assessment_sha256": None,
                "trial_accepted_candidate_count": 0,
                "candidate_count": 0,
                "candidates": [],
                "blockers": ["PROVIDER_PROCUREMENT_ASSESSMENT_INVALID"],
                "errors": [str(exc)],
            }
    else:
        assessment = dict(procurement_status)

    assessment_error_codes = _structured_error_codes(assessment)
    inspection_errors: list[str] = []
    for inspection in dict(assessment.get("registry_inspections") or {}).values():
        if not isinstance(inspection, Mapping) or inspection.get("status") != "DEGRADED":
            continue
        error = inspection.get("error")
        if isinstance(error, str) and error:
            inspection_errors.append(error)
        inspection_errors.extend(
            str(item) for item in list(inspection.get("errors") or [])
        )
    if assessment.get("status") == "DEGRADED" and not assessment_error_codes:
        assessment_error_codes.append("PROVIDER_PROCUREMENT_DEGRADED")

    candidates = [
        dict(item)
        for item in list(assessment.get("candidates") or [])
        if isinstance(item, Mapping)
    ]
    expected_candidates = {
        (
            "rqdata",
            "PRIMARY",
            "rqdata-a-share-primary",
            "ricequant-rqdata",
        ),
        (
            "jqdata",
            "CORROBORATION",
            "jqdata-a-share-corroboration",
            "joinquant-jqdata",
        ),
    }
    observed_candidates = {
        (
            str(item.get("candidate_id") or ""),
            str(item.get("role") or ""),
            str(item.get("source_id") or ""),
            str(item.get("authority") or ""),
        )
        for item in candidates
    }
    candidate_trials_ready = bool(candidates) and all(
        item.get("trial_accepted") is True
        and dict(item.get("checks") or {}).get("observation_window_complete") is True
        and isinstance(item.get("minimum_trial_trading_days"), int)
        and not isinstance(item.get("minimum_trial_trading_days"), bool)
        and int(item["minimum_trial_trading_days"]) >= 20
        and isinstance(item.get("observed_trading_day_count"), int)
        and not isinstance(item.get("observed_trading_day_count"), bool)
        and int(item["observed_trading_day_count"])
        >= int(item["minimum_trial_trading_days"])
        and item.get("real_orders") is False
        for item in candidates
    )
    assessment_sha256 = str(assessment.get("assessment_sha256") or "").lower()
    assessment_identity = {
        key: value for key, value in assessment.items() if key != "assessment_sha256"
    }
    digest_ready = (
        len(assessment_sha256) == 64
        and sha256_digest(assessment_identity) == assessment_sha256
    )
    ready = bool(
        assessment.get("schema")
        == "quant-platform/provider-procurement-status/v1"
        and assessment.get("status") == "TRIAL_ACCEPTED"
        and assessment.get("procurement_acceptance_ready") is True
        and assessment.get("candidate_count") == 2
        and assessment.get("trial_accepted_candidate_count") == 2
        and assessment.get("minimum_independent_authorities") == 2
        and observed_candidates == expected_candidates
        and candidate_trials_ready
        and digest_ready
        and not list(assessment.get("blockers") or [])
        and assessment.get("strategy_promotion_eligible") is False
        and assessment.get("real_orders") is False
    )
    blockers = [] if ready else ["PROVIDER_PROCUREMENT_ACCEPTANCE_INCOMPLETE"]
    if not digest_ready:
        blockers.append("PROVIDER_PROCUREMENT_ASSESSMENT_DIGEST_INVALID")
    return {
        "ready": ready,
        "status": assessment.get("status"),
        "error_code": (
            SYNTHETIC_PROVENANCE_FORBIDDEN
            if SYNTHETIC_PROVENANCE_FORBIDDEN in assessment_error_codes
            else assessment_error_codes[0]
            if assessment_error_codes
            else None
        ),
        "error_codes": assessment_error_codes,
        "assessment_sha256": assessment_sha256 or None,
        "trial_accepted_candidate_count": assessment.get(
            "trial_accepted_candidate_count", 0
        ),
        "candidate_count": assessment.get("candidate_count", 0),
        "candidates": [
            {
                "candidate_id": item.get("candidate_id"),
                "role": item.get("role"),
                "source_id": item.get("source_id"),
                "authority": item.get("authority"),
                "trial_accepted": item.get("trial_accepted") is True,
                "observed_trading_day_count": item.get(
                    "observed_trading_day_count", 0
                ),
                "minimum_trial_trading_days": item.get(
                    "minimum_trial_trading_days", 0
                ),
            }
            for item in candidates
        ],
        "blockers": list(dict.fromkeys(blockers)),
        "errors": list(
            dict.fromkeys(
                [
                    *list(assessment.get("formal_source_role_binding_errors") or []),
                    *inspection_errors,
                ]
            )
        ),
    }


def assess_formal_data_readiness(
    platform_root: str | Path,
    *,
    source_registry: Mapping[str, Any] | None = None,
    provider_status: Mapping[str, Any] | None = None,
    provider_store: ProviderDeliveryStore | None = None,
    procurement_status: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess registry coverage and observed evidence without enabling promotion."""

    root = Path(platform_root).expanduser().resolve()
    errors: list[str] = []
    error_codes: list[str] = []
    try:
        resolved = resolve_formal_data_readiness_policy(root)
        policy = dict(resolved["policy"])
    except ProviderReadinessError as exc:
        return {
            "schema": FORMAL_DATA_READINESS_SCHEMA,
            "status": "DEGRADED",
            "error_code": "READINESS_POLICY_INVALID",
            "error_codes": ["READINESS_POLICY_INVALID"],
            "policy_id": None,
            "policy_path": FORMAL_DATA_READINESS_POLICY_PATH,
            "policy_sha256": None,
            "registry_verified": False,
            "tracks": {},
            "strategy_readiness": {},
            "formal_forward_ready_strategy_ids": [],
            "formal_forward_ready": False,
            "historical_backtest_ready": False,
            "provider_procurement_acceptance_ready": False,
            "provider_procurement_gate": {
                "ready": False,
                "status": "DEGRADED",
                "error_code": "READINESS_POLICY_INVALID",
                "error_codes": ["READINESS_POLICY_INVALID"],
                "assessment_sha256": None,
                "trial_accepted_candidate_count": 0,
                "candidate_count": 0,
                "candidates": [],
                "blockers": ["READINESS_POLICY_INVALID"],
                "errors": [str(exc)],
            },
            "blockers": ["READINESS_POLICY_INVALID"],
            "errors": [str(exc)],
            "strategy_promotion_eligible": False,
            "real_orders": False,
        }

    procurement_gate = _provider_procurement_gate(root, procurement_status)
    error_codes.extend(str(item) for item in procurement_gate.get("error_codes", []))
    errors.extend(str(item) for item in procurement_gate.get("errors", []))
    store = provider_store or ProviderDeliveryStore(
        platform_root=root,
        catalog_root=root / "data/quant-lab/backtest-workbench/datahub",
    )
    try:
        registry = (
            dict(source_registry)
            if source_registry is not None
            else dict(store.load_registry())
        )
        sources = [dict(item) for item in list(registry.get("sources") or [])]
        registry_verified = True
    except (ProviderContractError, TypeError, ValueError) as exc:
        sources = []
        registry_verified = False
        errors.append(str(exc))
        error_codes.append(
            exc.error_code
            if isinstance(exc, ProviderContractError)
            else "PROVIDER_REGISTRY_INVALID"
        )
    try:
        status = dict(provider_status) if provider_status is not None else dict(store.status())
    except (ProviderContractError, TypeError, ValueError) as exc:
        status = {
            "status": "DEGRADED",
            "error_code": (
                exc.error_code
                if isinstance(exc, ProviderContractError)
                else "PROVIDER_DATASET_DEGRADED"
            ),
            "error_codes": [],
            "deliveries": [],
            "publications": [],
        }
        errors.append(str(exc))
    if status.get("status") == "DEGRADED":
        errors.extend(str(item) for item in list(status.get("errors") or []))
        error_codes.extend(_structured_error_codes(status))

    publication_rows = _publication_rows(status, store)
    primary_role = dict(policy["source_roles"]["primary"])
    corroborating_roles = [
        dict(item) for item in policy["source_roles"]["corroborators"]
    ]
    primary_identity = (
        str(primary_role["source_id"]),
        str(primary_role["authority"]),
    )
    corroborating_identities = {
        (str(item["source_id"]), str(item["authority"]))
        for item in corroborating_roles
    }
    required_source_identities = {primary_identity} | corroborating_identities
    tracks: dict[str, Any] = {}
    blockers: list[str] = []
    for track_id, raw_track in dict(policy["tracks"]).items():
        track = dict(raw_track)
        usage = str(track["required_usage"])
        product_results: dict[str, Any] = {}
        for product_id, raw_product in dict(track["products"]).items():
            product = dict(raw_product)
            registry_authorities: set[str] = set()
            eligible_source_ids: set[str] = set()
            eligible_source_authorities: set[tuple[str, str]] = set()
            for source in sources:
                authorization = dict(source.get("automation_authorization") or {})
                if (
                    authorization.get("status") != "APPROVED"
                    or usage not in set(source.get("allowed_usages") or [])
                    or not isinstance(source.get("adapter_certification"), Mapping)
                ):
                    continue
                for endpoint in list(source.get("endpoints") or []):
                    if not isinstance(endpoint, Mapping):
                        continue
                    endpoint_value = dict(endpoint)
                    endpoint_contract = {
                        "kind": next(
                            (
                                kind
                                for kind in product["data_kinds"]
                                if kind in set(endpoint_value.get("data_kinds") or [])
                            ),
                            "",
                        ),
                        "adjustment": next(
                            (
                                adjustment
                                for adjustment in product["adjustments"]
                                if adjustment
                                in set(endpoint_value.get("allowed_adjustments") or [])
                            ),
                            "",
                        ),
                    }
                    if (
                        _matches_contract_identity(endpoint_contract, product)
                        and _endpoint_capabilities_ready(endpoint_value, product)
                    ):
                        source_id = str(source.get("source_id") or "")
                        authority = str(endpoint_value.get("authority") or "")
                        if (
                            source_id
                            and authority
                            and (source_id, authority) in required_source_identities
                        ):
                            registry_authorities.add(authority)
                            eligible_source_ids.add(source_id)
                            eligible_source_authorities.add((source_id, authority))
            origin_observed = [
                row
                for row in publication_rows
                if row["usage"] == usage
                and row["origin_verified"] is True
                and _matches_contract_identity(row["data_contract"], product)
                and all(
                    row["capabilities"].get(capability) is True
                    for capability in product["required_delivery_capabilities"]
                )
            ]
            qualified_origin = [
                row
                for row in origin_observed
                if (
                    str(row.get("source_id") or ""),
                    str(row.get("authority") or ""),
                )
                in eligible_source_authorities
            ]
            field_observed = [
                row
                for row in qualified_origin
                if _matches_product(row["data_contract"], product)
            ]
            revision_history_required = "provider_revision_history" in set(
                product["required_endpoint_capabilities"]
            )
            observed = [
                row
                for row in field_observed
                if not revision_history_required
                or row["revision_lineage_verified"] is True
            ]
            origin_authorities = {
                str(item["authority"])
                for item in qualified_origin
            }
            field_authorities = {
                str(item["authority"])
                for item in field_observed
            }
            observed_authorities = {
                str(item["authority"])
                for item in observed
            }
            observed_identities = {
                (
                    str(item.get("source_id") or ""),
                    str(item.get("authority") or ""),
                )
                for item in observed
            }
            minimum = int(product["minimum_independent_authorities"])
            registry_ready = len(registry_authorities) >= minimum
            origin_evidence_ready = len(origin_authorities) >= minimum
            field_contract_ready = len(field_authorities) >= minimum
            evidence_ready = len(observed_authorities) >= minimum
            primary_registry_ready = primary_identity in eligible_source_authorities
            corroborator_registry_ready = corroborating_identities <= (
                eligible_source_authorities
            )
            primary_evidence_ready = primary_identity in observed_identities
            corroborator_evidence_ready = corroborating_identities <= (
                observed_identities
            )
            source_roles_ready = (
                primary_registry_ready
                and corroborator_registry_ready
                and primary_evidence_ready
                and corroborator_evidence_ready
            )
            product_blockers: list[str] = []
            prefix = f"{track_id}_{product_id}".upper()
            if not primary_registry_ready:
                product_blockers.append(f"{prefix}_PRIMARY_SOURCE_REGISTRY_INCOMPLETE")
            if not corroborator_registry_ready:
                product_blockers.append(
                    f"{prefix}_CORROBORATING_SOURCE_REGISTRY_INCOMPLETE"
                )
            if not registry_ready:
                product_blockers.append(f"{prefix}_REGISTRY_COVERAGE_INCOMPLETE")
            if not origin_evidence_ready:
                product_blockers.append(f"{prefix}_ORIGIN_EVIDENCE_INCOMPLETE")
            elif not field_contract_ready:
                product_blockers.append(f"{prefix}_FIELD_CONTRACT_INCOMPLETE")
            elif not evidence_ready:
                product_blockers.append(
                    f"{prefix}_REVISION_LINEAGE_EVIDENCE_INCOMPLETE"
                )
            if primary_registry_ready and not primary_evidence_ready:
                product_blockers.append(f"{prefix}_PRIMARY_SOURCE_EVIDENCE_INCOMPLETE")
            if corroborator_registry_ready and not corroborator_evidence_ready:
                product_blockers.append(
                    f"{prefix}_CORROBORATING_SOURCE_EVIDENCE_INCOMPLETE"
                )
            blockers.extend(product_blockers)
            product_results[product_id] = {
                "ready": registry_ready and evidence_ready and source_roles_ready,
                "minimum_independent_authorities": minimum,
                "primary_source_id": primary_identity[0],
                "primary_authority": primary_identity[1],
                "primary_source_ready": primary_registry_ready
                and primary_evidence_ready,
                "corroborating_sources": [dict(item) for item in corroborating_roles],
                "corroborating_sources_ready": corroborator_registry_ready
                and corroborator_evidence_ready,
                "reconciliation_rule": dict(
                    policy["reconciliation_rules"][product_id]
                ),
                "reconciliation_rule_sha256": sha256_digest(
                    policy["reconciliation_rules"][product_id]
                ),
                "required_fields": list(product["required_fields"]),
                "runner_usages": list(product["runner_usages"]),
                "semantics_version": product["semantics_version"],
                "registry_authorities": sorted(registry_authorities),
                "origin_observed_authorities": sorted(origin_authorities),
                "field_contract_observed_authorities": sorted(field_authorities),
                "observed_authorities": sorted(observed_authorities),
                "eligible_source_ids": sorted(eligible_source_ids),
                "origin_verified_publication_count": len(qualified_origin),
                "field_contract_verified_publication_count": len(field_observed),
                "revision_lineage_verified_publication_count": len(observed),
                "revision_lineage_evidence": [
                    {
                        "dataset_id": row.get("dataset_id"),
                        "manifest_sha256": row.get("manifest_sha256"),
                        "payload_sha256": row.get("payload_sha256"),
                        "authority": row.get("authority"),
                        "verified": row.get("revision_lineage_verified") is True,
                        "lineage_sha256": row.get("revision_lineage_sha256"),
                        "errors": row.get("revision_lineage_errors"),
                    }
                    for row in field_observed
                ],
                "approved_publication_evidence": [
                    {
                        "receipt_sha256": row.get("receipt_sha256"),
                        "delivery_sha256": row.get("delivery_sha256"),
                        "dataset_id": row.get("dataset_id"),
                        "manifest_sha256": row.get("manifest_sha256"),
                        "payload_sha256": row.get("payload_sha256"),
                        "source_id": row.get("source_id"),
                        "authority": row.get("authority"),
                        "source_role": (
                            "PRIMARY"
                            if (
                                str(row.get("source_id") or ""),
                                str(row.get("authority") or ""),
                            )
                            == primary_identity
                            else "CORROBORATION"
                        ),
                        "revision_lineage_sha256": row.get(
                            "revision_lineage_sha256"
                        ),
                    }
                    for row in observed
                ],
                "blockers": product_blockers,
            }
        tracks[track_id] = {
            "ready": bool(product_results)
            and all(item["ready"] for item in product_results.values()),
            "required_usage": usage,
            "products": product_results,
        }

    strategy_readiness: dict[str, Any] = {}
    ready_strategy_ids: list[str] = []
    for strategy_id, raw_requirement in dict(policy["strategy_requirements"]).items():
        requirement = dict(raw_requirement)
        track_id = str(requirement["track"])
        track_products = dict(tracks.get(track_id, {}).get("products") or {})
        required_product_ids = [str(item) for item in requirement["required_products"]]
        required_results = {
            product_id: dict(track_products.get(product_id) or {})
            for product_id in required_product_ids
        }
        strategy_blockers = list(
            dict.fromkeys(
                blocker
                for product in required_results.values()
                for blocker in list(product.get("blockers") or [])
            )
        )
        strategy_blockers.extend(procurement_gate["blockers"])
        strategy_blockers = list(dict.fromkeys(strategy_blockers))
        ready = (
            procurement_gate["ready"] is True
            and bool(required_results)
            and all(
                product.get("ready") is True
                for product in required_results.values()
            )
        )
        if ready and not errors and registry_verified:
            ready_strategy_ids.append(strategy_id)
        strategy_readiness[strategy_id] = {
            "ready": ready and not errors and registry_verified,
            "track": track_id,
            "strategy_config_path": requirement["strategy_config_path"],
            "strategy_config_sha256": requirement["strategy_config_sha256"],
            "required_products": required_product_ids,
            "ready_products": sorted(
                product_id
                for product_id, result in required_results.items()
                if result.get("ready") is True
            ),
            "required_product_count": len(required_product_ids),
            "ready_product_count": sum(
                result.get("ready") is True for result in required_results.values()
            ),
            "blockers": strategy_blockers,
            "strategy_promotion_eligible": False,
            "real_orders": False,
        }

    formal_ready = bool(strategy_readiness) and all(
        item["ready"] for item in strategy_readiness.values()
    )
    historical_ready = bool(tracks.get("historical_backtest", {}).get("ready"))
    lineage_verified_publications = sum(
        row["origin_verified"] is True
        and row["revision_lineage_verified"] is True
        for row in publication_rows
    )
    lineage_incomplete_publications = sum(
        row["origin_verified"] is True
        and row["revision_lineage_verified"] is not True
        for row in publication_rows
    )
    if not registry_verified:
        blockers.insert(0, "PROVIDER_REGISTRY_INVALID")
    if errors:
        blockers.insert(0, "PROVIDER_EVIDENCE_DEGRADED")
    blockers.extend(procurement_gate["blockers"])
    error_codes = list(dict.fromkeys(error_codes))
    upstream_degraded = bool(
        not registry_verified
        or status.get("status") == "DEGRADED"
        or procurement_gate.get("status") == "DEGRADED"
        or error_codes
    )
    readiness_status = (
        "DEGRADED"
        if upstream_degraded
        else "READY"
        if formal_ready and historical_ready
        else "BLOCKED"
    )
    readiness_error_code = (
        SYNTHETIC_PROVENANCE_FORBIDDEN
        if SYNTHETIC_PROVENANCE_FORBIDDEN in error_codes
        else "FORMAL_DATA_READINESS_DEGRADED"
        if upstream_degraded
        else None
    )
    identity = {
        "schema": FORMAL_DATA_READINESS_SCHEMA,
        "status": readiness_status,
        "error_code": readiness_error_code,
        "error_codes": error_codes,
        "policy_id": policy["policy_id"],
        "policy_path": resolved["policy_path"],
        "policy_sha256": resolved["policy_sha256"],
        "registry_verified": registry_verified,
        "registry_sha256": registry.get("registry_sha256") if registry_verified else None,
        "tracks": tracks,
        "strategy_readiness": strategy_readiness,
        "formal_forward_ready_strategy_ids": sorted(ready_strategy_ids),
        "formal_forward_ready": formal_ready and not errors,
        "historical_backtest_ready": historical_ready and not errors,
        "provider_procurement_acceptance_ready": procurement_gate["ready"],
        "provider_procurement_gate": procurement_gate,
        "verified_publication_count": len(publication_rows),
        "revision_lineage_required": True,
        "revision_lineage_verified_publication_count": lineage_verified_publications,
        "revision_lineage_incomplete_publication_count": lineage_incomplete_publications,
        "blockers": list(dict.fromkeys(blockers)),
        "errors": list(dict.fromkeys(errors)),
        "akshare_role": policy["akshare_role"],
        "strategy_promotion_eligible": False,
        "real_orders": False,
    }
    return {**identity, "assessment_sha256": sha256_digest(identity)}
