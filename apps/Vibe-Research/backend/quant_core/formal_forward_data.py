"""Runtime verification for dual-authority formal-forward product bundles.

Admission proves that approved source contracts exist.  This module proves that
the exact revisions consumed by one signal or market observation still satisfy
those contracts, were available at the decision cutoff, and reconcile across
independent authorities.  It deliberately returns evidence only; transforming
the verified products into strategy inputs is a separate deterministic step.
"""

from __future__ import annotations

import math
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .corporate_actions import (
    CorporateActionEconomicsError,
    validate_corporate_action_economics,
)
from .provider_contract import ProviderContractError, ProviderDeliveryStore
from .provider_readiness import (
    ProviderReadinessError,
    resolve_formal_data_readiness_policy,
)
from .provenance import sha256_digest


FORMAL_SOURCE_BUNDLE_SCHEMA = "quant-platform/formal-forward-source-bundle/v1"
FORMAL_STRATEGIES = {
    "diversified_etf_trend_p2",
    "independent_multifactor_i7_forward_only",
}
PHASE_USAGES = {
    "signal": {"calendar", "signal", "universe", "risk"},
    "market": {"execution", "valuation", "risk"},
}


class FormalForwardDataError(RuntimeError):
    """Raised when exact runtime data cannot support a formal-forward action."""


def _timestamp(value: Any, label: str) -> datetime:
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise FormalForwardDataError(f"{label} must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise FormalForwardDataError(f"{label} must include a timezone")
    return parsed


def _product_matches(data_contract: Mapping[str, Any], product: Mapping[str, Any]) -> bool:
    declared = {str(item) for item in data_contract.get("fields") or []}
    required = {str(item) for item in product.get("required_fields") or []}
    return (
        str(data_contract.get("kind") or "") in set(product["data_kinds"])
        and str(data_contract.get("adjustment") or "")
        in set(product["adjustments"])
        and required <= declared
        and (
            "available_at" not in required
            or str(data_contract.get("available_at_field") or "") == "available_at"
        )
    )


def _numeric_values_equal(
    left: Any, right: Any, tolerance: Mapping[str, Any]
) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return False
    if not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
        return False
    a = float(left)
    b = float(right)
    if not math.isfinite(a) or not math.isfinite(b):
        return False
    return math.isclose(
        a,
        b,
        rel_tol=float(tolerance["relative"]),
        abs_tol=float(tolerance["absolute"]),
    )


def _record_map(
    records: list[dict[str, Any]], primary_keys: list[str], label: str
) -> dict[tuple[str, ...], dict[str, Any]]:
    result: dict[tuple[str, ...], dict[str, Any]] = {}
    for record in records:
        if any(record.get(key) is None for key in primary_keys):
            raise FormalForwardDataError(f"{label} has a missing primary key")
        key = tuple(str(record[key]) for key in primary_keys)
        if key in result:
            raise FormalForwardDataError(f"{label} has duplicate primary keys")
        result[key] = record
    return result


def _compare_sources(
    *,
    product_id: str,
    primary: Mapping[str, Any],
    corroborating: Mapping[str, Any],
    reconciliation_rule: Mapping[str, Any],
) -> dict[str, Any]:
    rule = dict(reconciliation_rule)
    primary_keys = [str(item) for item in rule["primary_keys"]]
    if (
        list(primary["primary_keys"]) != primary_keys
        or list(corroborating["primary_keys"]) != primary_keys
    ):
        raise FormalForwardDataError(
            f"{product_id} source primary-key contract drifted"
        )
    left = _record_map(list(primary["records"]), primary_keys, product_id)
    right = _record_map(list(corroborating["records"]), primary_keys, product_id)
    if set(left) != set(right):
        raise FormalForwardDataError(
            f"{product_id} independent sources have different record coverage"
        )
    compared_fields = [str(item) for item in rule["compared_fields"]]
    exact_fields = [str(item) for item in rule["exact_fields"]]
    tolerances = {
        str(key): dict(value)
        for key, value in dict(rule["field_tolerances"]).items()
    }
    mode = str(rule["mode"])
    factor_anchors: dict[str, tuple[float, float]] = {}
    if mode == "corporate_action_economics":
        for source_label, records in (("primary", left), ("corroborating", right)):
            for key, record in records.items():
                try:
                    validate_corporate_action_economics(record)
                except CorporateActionEconomicsError as exc:
                    raise FormalForwardDataError(
                        f"{product_id} {source_label} record "
                        f"{'/'.join(key)} has invalid economics: {exc}"
                    ) from exc
    if mode == "rebased_factor":
        assets = sorted({key[0] for key in left})
        for asset_id in assets:
            keys = sorted(key for key in left if key[0] == asset_id)
            anchor_key = keys[-1]
            left_anchor = left[anchor_key].get("factor")
            right_anchor = right[anchor_key].get("factor")
            if (
                isinstance(left_anchor, bool)
                or isinstance(right_anchor, bool)
                or not isinstance(left_anchor, (int, float))
                or not isinstance(right_anchor, (int, float))
                or not math.isfinite(float(left_anchor))
                or not math.isfinite(float(right_anchor))
                or float(left_anchor) <= 0
                or float(right_anchor) <= 0
            ):
                raise FormalForwardDataError(
                    f"{product_id} has an invalid rebasing anchor for {asset_id}"
                )
            factor_anchors[asset_id] = (
                float(left_anchor),
                float(right_anchor),
            )
    mismatches: list[dict[str, Any]] = []
    for key in sorted(left):
        for field in exact_fields:
            if left[key].get(field) != right[key].get(field):
                mismatches.append({"primary_key": list(key), "field": field})
                if len(mismatches) >= 20:
                    break
        if len(mismatches) >= 20:
            break
        for field in compared_fields:
            left_value = left[key].get(field)
            right_value = right[key].get(field)
            if mode == "rebased_factor" and field == "factor":
                left_anchor, right_anchor = factor_anchors[key[0]]
                if (
                    isinstance(left_value, bool)
                    or isinstance(right_value, bool)
                    or not isinstance(left_value, (int, float))
                    or not isinstance(right_value, (int, float))
                ):
                    equal = False
                else:
                    equal = _numeric_values_equal(
                        float(left_value) / left_anchor,
                        float(right_value) / right_anchor,
                        tolerances[field],
                    )
            else:
                equal = (
                    mode == "corporate_action_economics"
                    and left_value is None
                    and right_value is None
                ) or _numeric_values_equal(
                    left_value, right_value, tolerances[field]
                )
            if not equal:
                mismatches.append({"primary_key": list(key), "field": field})
                if len(mismatches) >= 20:
                    break
        if len(mismatches) >= 20:
            break
    if mismatches:
        raise FormalForwardDataError(
            f"{product_id} independent sources differ beyond tolerance: "
            + ", ".join(
                f"{'/'.join(item['primary_key'])}.{item['field']}"
                for item in mismatches[:5]
            )
        )
    identity = {
        "product_id": product_id,
        "reconciliation_mode": mode,
        "reconciliation_rule_sha256": sha256_digest(rule),
        "primary_source_id": primary["source_id"],
        "primary_authority": primary["authority"],
        "corroborating_source_id": corroborating["source_id"],
        "corroborating_authority": corroborating["authority"],
        "primary_manifest_sha256": primary["manifest_sha256"],
        "corroborating_manifest_sha256": corroborating["manifest_sha256"],
        "record_count": len(left),
        "primary_keys": primary_keys,
        "compared_fields": compared_fields + exact_fields,
        "rebased_asset_count": len(factor_anchors),
        "passed": True,
    }
    return {**identity, "comparison_sha256": sha256_digest(identity)}


def _verify_formal_forward_source_bundle(
    *,
    platform_root: str,
    strategy_id: str,
    phase: str,
    cutoff_at: str | datetime,
    product_references: Mapping[str, Any],
    approved_datasets: list[Mapping[str, Any]],
    provider_store: ProviderDeliveryStore | None = None,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    """Verify and hash every exact provider revision needed by one runtime phase."""

    strategy = str(strategy_id)
    if strategy not in FORMAL_STRATEGIES:
        raise FormalForwardDataError("runtime source bundles are only valid for P2/I7")
    if phase not in PHASE_USAGES:
        raise FormalForwardDataError("unsupported formal-forward data phase")
    cutoff = _timestamp(cutoff_at, "cutoff_at")
    try:
        resolved = resolve_formal_data_readiness_policy(platform_root)
    except ProviderReadinessError as exc:
        raise FormalForwardDataError(str(exc)) from exc
    policy = dict(resolved["policy"])
    primary_role = dict(policy["source_roles"]["primary"])
    corroborating_roles = [
        dict(item) for item in policy["source_roles"]["corroborators"]
    ]
    primary_identity = (
        str(primary_role["source_id"]),
        str(primary_role["authority"]),
    )
    corroborating_identities = [
        (str(item["source_id"]), str(item["authority"]))
        for item in corroborating_roles
    ]
    required_source_identities = [primary_identity, *corroborating_identities]
    requirement = dict(policy["strategy_requirements"][strategy])
    products = dict(policy["tracks"][requirement["track"]]["products"])
    usages = PHASE_USAGES[phase]
    required_product_ids = {
        product_id
        for product_id in requirement["required_products"]
        if set(products[product_id]["runner_usages"]) & usages
    }
    supplied = {str(key) for key in product_references}
    if supplied != required_product_ids:
        missing = sorted(required_product_ids - supplied)
        extra = sorted(supplied - required_product_ids)
        raise FormalForwardDataError(
            f"{phase} product bundle coverage mismatch: missing={missing}, extra={extra}"
        )

    store = provider_store or ProviderDeliveryStore(
        platform_root=platform_root,
        catalog_root=Path(platform_root)
        / "data/quant-lab/backtest-workbench/datahub",
    )
    approved = [dict(item) for item in approved_datasets]
    product_evidence: dict[str, Any] = {}
    primary_records: dict[str, list[dict[str, Any]]] = {}
    all_authorities: set[str] = set()
    all_sources: set[str] = set()
    for product_id in sorted(required_product_ids):
        contract = dict(products[product_id])
        reconciliation_rule = dict(policy["reconciliation_rules"][product_id])
        raw_refs = product_references.get(product_id)
        if not isinstance(raw_refs, list) or not raw_refs:
            raise FormalForwardDataError(f"{product_id} references must be a non-empty list")
        refs = [dict(item) for item in raw_refs if isinstance(item, Mapping)]
        if len(refs) != len(raw_refs):
            raise FormalForwardDataError(f"{product_id} references must be objects")
        loaded_sources: list[dict[str, Any]] = []
        for reference in refs:
            if set(reference) != {"dataset_id", "manifest_sha256"}:
                raise FormalForwardDataError(
                    f"{product_id} reference fields do not match the contract"
                )
            dataset_id = str(reference.get("dataset_id") or "")
            manifest_sha = str(reference.get("manifest_sha256") or "").lower()
            policies = [
                item
                for item in approved
                if item.get("dataset_id") == dataset_id
                and item.get("product_id") == product_id
            ]
            if len(policies) != 1:
                raise FormalForwardDataError(
                    f"{dataset_id} is not approved for formal product {product_id}"
                )
            approval = policies[0]
            try:
                binding = store.verify_catalog_binding(dataset_id, manifest_sha)
            except (ProviderContractError, TypeError, ValueError) as exc:
                raise FormalForwardDataError(str(exc)) from exc
            if binding.get("verified") is not True:
                raise FormalForwardDataError(
                    f"provider publication binding failed for {dataset_id}: "
                    + ", ".join(str(item) for item in binding.get("errors") or [])
                )
            origin = dict(binding.get("origin_evidence") or {})
            if origin.get("origin_verified") is not True:
                raise FormalForwardDataError(
                    f"provider origin is not verified for {dataset_id}"
                )
            loaded = dict(binding.get("catalog") or {})
            manifest = dict(loaded.get("manifest") or {})
            provider = dict(manifest.get("provider") or {})
            metadata = dict(manifest.get("metadata") or {})
            data_contract = dict(metadata.get("data_contract") or {})
            authority = str(provider.get("authority") or "")
            source_id = str(provider.get("name") or "")
            if (
                source_id not in set(str(item) for item in approval.get("providers") or [])
                or authority != str(approval.get("authority") or "")
                or not _product_matches(data_contract, contract)
            ):
                raise FormalForwardDataError(
                    f"runtime provider contract drifted for {dataset_id}"
                )
            available_at = _timestamp(manifest.get("available_at"), "manifest.available_at")
            if available_at > cutoff:
                raise FormalForwardDataError(
                    f"{dataset_id} was unavailable at the {phase} cutoff"
                )
            payload = loaded.get("payload")
            if not isinstance(payload, Mapping) or set(payload) != {"records", "metadata"}:
                raise FormalForwardDataError(
                    f"{dataset_id} payload is not a normalized provider publication"
                )
            payload_sha = sha256_digest(payload)
            if (
                payload_sha != str(loaded.get("payload_sha256") or "")
                or payload_sha != str(manifest.get("payload_sha256") or "")
            ):
                raise FormalForwardDataError(
                    f"{dataset_id} payload does not match its content address"
                )
            records = [dict(item) for item in list(payload.get("records") or [])]
            required_fields = set(str(item) for item in contract["required_fields"])
            if any(not required_fields <= set(record) for record in records):
                raise FormalForwardDataError(
                    f"{dataset_id} records omit required product fields"
                )
            if any(
                _timestamp(record.get("available_at"), "record.available_at") > cutoff
                for record in records
            ):
                raise FormalForwardDataError(
                    f"{dataset_id} contains records unavailable at the {phase} cutoff"
                )
            primary_keys = [str(item) for item in data_contract.get("primary_keys") or []]
            if primary_keys != list(reconciliation_rule["primary_keys"]):
                raise FormalForwardDataError(
                    f"{dataset_id} primary-key contract drifted for {product_id}"
                )
            loaded_sources.append(
                {
                    "dataset_id": dataset_id,
                    "manifest_sha256": manifest_sha,
                    "payload_sha256": payload_sha,
                    "delivery_sha256": provider.get("delivery_sha256"),
                    "source_id": source_id,
                    "authority": authority,
                    "available_at": available_at.isoformat(),
                    "primary_keys": primary_keys,
                    "required_fields": sorted(required_fields),
                    "records": records,
                }
            )
        authorities = {item["authority"] for item in loaded_sources}
        sources = {item["source_id"] for item in loaded_sources}
        minimum = int(contract["minimum_independent_authorities"])
        if len(authorities) < minimum or len(sources) < minimum:
            raise FormalForwardDataError(
                f"{product_id} lacks independent runtime authorities and sources"
            )
        by_identity: dict[tuple[str, str], dict[str, Any]] = {}
        for item in loaded_sources:
            identity = (str(item["source_id"]), str(item["authority"]))
            if identity in by_identity:
                raise FormalForwardDataError(
                    f"{product_id} supplies more than one revision for source role {identity[0]}"
                )
            by_identity[identity] = item
        if set(by_identity) != set(required_source_identities):
            raise FormalForwardDataError(
                f"{product_id} runtime sources do not match the frozen primary/corroborator roles"
            )
        primary = by_identity[primary_identity]
        corroborating_sources = [
            by_identity[identity] for identity in corroborating_identities
        ]
        loaded_sources = [primary, *corroborating_sources]
        comparisons = [
            _compare_sources(
                product_id=product_id,
                primary=primary,
                corroborating=item,
                reconciliation_rule=reconciliation_rule,
            )
            for item in corroborating_sources
        ]
        all_authorities.update(authorities)
        all_sources.update(sources)
        product_evidence[product_id] = {
            "minimum_independent_authorities": minimum,
            "authorities": sorted(authorities),
            "sources": sorted(sources),
            "primary_dataset_id": primary["dataset_id"],
            "primary_source_id": primary["source_id"],
            "primary_authority": primary["authority"],
            "reconciliation_mode": reconciliation_rule["mode"],
            "reconciliation_rule_sha256": sha256_digest(reconciliation_rule),
            "revisions": [
                {key: item[key] for key in (
                    "dataset_id",
                    "manifest_sha256",
                    "payload_sha256",
                    "delivery_sha256",
                    "source_id",
                    "authority",
                    "available_at",
                )}
                for item in loaded_sources
            ],
            "comparisons": comparisons,
            "reconciled": True,
        }
        primary_records[product_id] = [dict(item) for item in primary["records"]]
    identity = {
        "schema": FORMAL_SOURCE_BUNDLE_SCHEMA,
        "strategy_id": strategy,
        "phase": phase,
        "cutoff_at": cutoff.isoformat(),
        "policy_path": resolved["policy_path"],
        "policy_sha256": resolved["policy_sha256"],
        "required_products": sorted(required_product_ids),
        "products": product_evidence,
        "authorities": sorted(all_authorities),
        "sources": sorted(all_sources),
        "real_orders": False,
    }
    evidence = {**identity, "source_bundle_sha256": sha256_digest(identity)}
    return evidence, primary_records


def verify_formal_forward_source_bundle(
    *,
    platform_root: str,
    strategy_id: str,
    phase: str,
    cutoff_at: str | datetime,
    product_references: Mapping[str, Any],
    approved_datasets: list[Mapping[str, Any]],
    provider_store: ProviderDeliveryStore | None = None,
) -> dict[str, Any]:
    evidence, _ = _verify_formal_forward_source_bundle(
        platform_root=platform_root,
        strategy_id=strategy_id,
        phase=phase,
        cutoff_at=cutoff_at,
        product_references=product_references,
        approved_datasets=approved_datasets,
        provider_store=provider_store,
    )
    return evidence


def load_verified_formal_forward_products(
    *,
    platform_root: str,
    strategy_id: str,
    phase: str,
    cutoff_at: str | datetime,
    product_references: Mapping[str, Any],
    approved_datasets: list[Mapping[str, Any]],
    provider_store: ProviderDeliveryStore | None = None,
) -> dict[str, Any]:
    """Return private canonical records only after emitting verified evidence."""

    evidence, records = _verify_formal_forward_source_bundle(
        platform_root=platform_root,
        strategy_id=strategy_id,
        phase=phase,
        cutoff_at=cutoff_at,
        product_references=product_references,
        approved_datasets=approved_datasets,
        provider_store=provider_store,
    )
    return {"evidence": evidence, "records": records}
