"""Shared-capital supervision across independently simulated strategies.

The strategy ledgers remain isolated for attribution and recovery.  This module
adds the missing parent-account view: every strategy proposal is translated to
notional exposure, aggregated, and checked before any child ledger is changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Mapping, Sequence

from .provenance import sha256_digest


PLATFORM_PORTFOLIO_POLICY_SCHEMA = "quant-platform/platform-portfolio-policy/v1"
PLATFORM_PORTFOLIO_ASSESSMENT_SCHEMA = "quant-platform/platform-portfolio-assessment/v2"
EXPOSURE_ATTRIBUTION_METHODOLOGY = (
    "quant-platform/deterministic-long-only-exposure-attribution/v1"
)


def _decimal(value: Any, label: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except Exception as exc:  # pragma: no cover - Decimal uses several subclasses
        raise ValueError(f"{label} must be numeric") from exc
    if not result.is_finite():
        raise ValueError(f"{label} must be finite")
    return result


def _percent(config: Mapping[str, Any], key: str) -> Decimal:
    value = _decimal(config.get(key), key)
    if value < 0 or value > 100:
        raise ValueError(f"{key} must be between 0 and 100")
    return value


def _number(value: Decimal) -> float:
    return round(float(value), 8)


@dataclass(frozen=True)
class PlatformPortfolioPolicy:
    policy_id: str
    max_gross_exposure_pct: Decimal
    max_asset_pct: Decimal
    max_sector_pct: Decimal
    max_correlation_cluster_pct: Decimal
    minimum_cash_pct: Decimal
    minimum_effective_assets: Decimal
    max_active_strategies: int
    unknown_asset_action: str
    require_consistent_asset_metadata: bool
    require_complete_registry_batch: bool
    allow_reduce_only_recovery: bool

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "PlatformPortfolioPolicy":
        required = {
            "schema_version",
            "policy_id",
            "mode",
            "real_orders",
            "max_gross_exposure_pct",
            "max_asset_pct",
            "max_sector_pct",
            "max_correlation_cluster_pct",
            "minimum_cash_pct",
            "minimum_effective_assets",
            "max_active_strategies",
            "unknown_asset_action",
            "require_consistent_asset_metadata",
            "require_complete_registry_batch",
            "allow_reduce_only_recovery",
        }
        missing = sorted(required - set(config))
        if missing:
            raise ValueError(
                "platform portfolio policy is missing fields: " + ", ".join(missing)
            )
        unexpected = sorted(set(config) - required)
        if unexpected:
            raise ValueError(
                "platform portfolio policy has unexpected fields: "
                + ", ".join(unexpected)
            )
        if int(config["schema_version"]) != 1:
            raise ValueError("unsupported platform portfolio policy schema")
        if config["mode"] != "PAPER" or config["real_orders"] is not False:
            raise ValueError("platform portfolio policy must be PAPER-only")
        policy_id = str(config["policy_id"]).strip()
        if not policy_id:
            raise ValueError("platform portfolio policy_id is required")
        maximum_gross = _percent(config, "max_gross_exposure_pct")
        minimum_cash = _percent(config, "minimum_cash_pct")
        if maximum_gross + minimum_cash > 100:
            raise ValueError("maximum gross exposure plus minimum cash cannot exceed 100%")
        minimum_effective = _decimal(
            config["minimum_effective_assets"], "minimum_effective_assets"
        )
        if minimum_effective < 1:
            raise ValueError("minimum_effective_assets must be at least 1")
        maximum_strategies = config["max_active_strategies"]
        if (
            not isinstance(maximum_strategies, int)
            or isinstance(maximum_strategies, bool)
            or maximum_strategies < 1
        ):
            raise ValueError("max_active_strategies must be a positive integer")
        unknown_action = str(config["unknown_asset_action"])
        if unknown_action != "REJECT":
            raise ValueError("unknown assets must fail closed with REJECT")
        boolean_fields = (
            "require_consistent_asset_metadata",
            "require_complete_registry_batch",
            "allow_reduce_only_recovery",
        )
        if any(not isinstance(config[field], bool) for field in boolean_fields):
            raise ValueError("platform portfolio policy switches must be booleans")
        if not config["require_consistent_asset_metadata"]:
            raise ValueError("asset metadata consistency cannot be disabled")
        if not config["require_complete_registry_batch"]:
            raise ValueError("complete-registry daily batches cannot be disabled")
        max_asset = _percent(config, "max_asset_pct")
        max_sector = _percent(config, "max_sector_pct")
        max_cluster = _percent(config, "max_correlation_cluster_pct")
        if (
            maximum_gross > Decimal("90")
            or minimum_cash < Decimal("10")
            or max_asset > Decimal("35")
            or max_sector > Decimal("50")
            or max_cluster > Decimal("60")
            or minimum_effective < Decimal("2")
            or maximum_strategies > 8
        ):
            raise ValueError(
                "platform portfolio policy weakens the non-bypassable governance bounds"
            )
        return cls(
            policy_id=policy_id,
            max_gross_exposure_pct=maximum_gross,
            max_asset_pct=max_asset,
            max_sector_pct=max_sector,
            max_correlation_cluster_pct=max_cluster,
            minimum_cash_pct=minimum_cash,
            minimum_effective_assets=minimum_effective,
            max_active_strategies=maximum_strategies,
            unknown_asset_action=unknown_action,
            require_consistent_asset_metadata=True,
            require_complete_registry_batch=True,
            allow_reduce_only_recovery=bool(config["allow_reduce_only_recovery"]),
        )

    def evidence(self) -> dict[str, Any]:
        identity = {
            "schema": PLATFORM_PORTFOLIO_POLICY_SCHEMA,
            "policy_id": self.policy_id,
            "mode": "PAPER",
            "real_orders": False,
            "max_gross_exposure_pct": str(self.max_gross_exposure_pct),
            "max_asset_pct": str(self.max_asset_pct),
            "max_sector_pct": str(self.max_sector_pct),
            "max_correlation_cluster_pct": str(
                self.max_correlation_cluster_pct
            ),
            "minimum_cash_pct": str(self.minimum_cash_pct),
            "minimum_effective_assets": str(self.minimum_effective_assets),
            "max_active_strategies": self.max_active_strategies,
            "unknown_asset_action": self.unknown_asset_action,
            "require_consistent_asset_metadata": True,
            "require_complete_registry_batch": True,
            "allow_reduce_only_recovery": self.allow_reduce_only_recovery,
        }
        return {**identity, "policy_sha256": sha256_digest(identity)}


class PlatformPortfolioSupervisor:
    """Deterministic pre-trade gate for a collection of virtual subaccounts."""

    def __init__(self, policy: PlatformPortfolioPolicy) -> None:
        self.policy = policy

    @staticmethod
    def _notionals(value: Any, *, strategy_id: str, label: str) -> dict[str, Decimal]:
        if not isinstance(value, Mapping):
            raise ValueError(f"{strategy_id} {label} must be an object")
        result: dict[str, Decimal] = {}
        for raw_code, raw_notional in value.items():
            code = str(raw_code).strip()
            if not code:
                raise ValueError(f"{strategy_id} {label} contains an empty symbol")
            notional = _decimal(raw_notional, f"{strategy_id} {label} {code}")
            if notional < 0:
                raise ValueError(f"{strategy_id} {label} {code} cannot be negative")
            if notional > 0:
                result[code] = notional
        return result

    @staticmethod
    def _metadata(
        value: Any, *, strategy_id: str, required_codes: set[str]
    ) -> dict[str, dict[str, str]]:
        if not isinstance(value, Mapping):
            raise ValueError(f"{strategy_id} asset_metadata must be an object")
        result: dict[str, dict[str, str]] = {}
        for code in sorted(required_codes):
            raw = value.get(code)
            if not isinstance(raw, Mapping):
                raise ValueError(f"unknown platform risk metadata for {code}")
            sector = str(raw.get("sector") or "").strip()
            cluster = str(raw.get("correlation_cluster") or "").strip()
            if not sector or not cluster or "UNCLASSIFIED" in {sector, cluster}:
                raise ValueError(f"unknown platform risk metadata for {code}")
            result[code] = {
                "sector": sector,
                "correlation_cluster": cluster,
            }
        return result

    @staticmethod
    def _aggregate(
        portfolios: Sequence[dict[str, Any]], key: str
    ) -> dict[str, Decimal]:
        result: dict[str, Decimal] = {}
        for portfolio in portfolios:
            for code, notional in portfolio[key].items():
                result[code] = result.get(code, Decimal("0")) + notional
        return result

    def _metrics(
        self,
        notionals: Mapping[str, Decimal],
        *,
        total_equity: Decimal,
        metadata: Mapping[str, Mapping[str, str]],
        active_strategies: int,
    ) -> dict[str, Any]:
        gross = sum(notionals.values(), Decimal("0"))
        cash = total_equity - gross
        asset_pct = {
            code: value / total_equity * Decimal("100")
            for code, value in notionals.items()
        }
        sector_pct: dict[str, Decimal] = {}
        cluster_pct: dict[str, Decimal] = {}
        for code, value in notionals.items():
            sector = str(metadata[code]["sector"])
            cluster = str(metadata[code]["correlation_cluster"])
            pct = value / total_equity * Decimal("100")
            sector_pct[sector] = sector_pct.get(sector, Decimal("0")) + pct
            cluster_pct[cluster] = cluster_pct.get(cluster, Decimal("0")) + pct
        normalized = [value / gross for value in notionals.values()] if gross > 0 else []
        effective_assets = (
            Decimal("1") / sum((weight * weight for weight in normalized), Decimal("0"))
            if normalized
            else Decimal("0")
        )
        return {
            "gross": gross,
            "cash": cash,
            "gross_exposure_pct": gross / total_equity * Decimal("100"),
            "cash_pct": cash / total_equity * Decimal("100"),
            "asset_weights_pct": asset_pct,
            "sector_weights_pct": sector_pct,
            "correlation_cluster_weights_pct": cluster_pct,
            "effective_assets": effective_assets,
            "active_strategies": active_strategies,
        }

    def _breaches(self, metrics: Mapping[str, Any]) -> list[str]:
        tolerance = Decimal("0.00000001")
        breaches: list[str] = []
        if metrics["gross_exposure_pct"] > self.policy.max_gross_exposure_pct + tolerance:
            breaches.append("PLATFORM_GROSS_EXPOSURE_LIMIT")
        if metrics["cash_pct"] + tolerance < self.policy.minimum_cash_pct:
            breaches.append("PLATFORM_MINIMUM_CASH_LIMIT")
        if metrics["asset_weights_pct"] and max(
            metrics["asset_weights_pct"].values()
        ) > self.policy.max_asset_pct + tolerance:
            breaches.append("PLATFORM_ASSET_CONCENTRATION_LIMIT")
        if metrics["sector_weights_pct"] and max(
            metrics["sector_weights_pct"].values()
        ) > self.policy.max_sector_pct + tolerance:
            breaches.append("PLATFORM_SECTOR_CONCENTRATION_LIMIT")
        if metrics["correlation_cluster_weights_pct"] and max(
            metrics["correlation_cluster_weights_pct"].values()
        ) > self.policy.max_correlation_cluster_pct + tolerance:
            breaches.append("PLATFORM_CORRELATION_CLUSTER_LIMIT")
        if (
            metrics["gross"] > 0
            and metrics["effective_assets"] + tolerance
            < self.policy.minimum_effective_assets
        ):
            breaches.append("PLATFORM_MINIMUM_EFFECTIVE_ASSETS")
        if metrics["active_strategies"] > self.policy.max_active_strategies:
            breaches.append("PLATFORM_ACTIVE_STRATEGY_LIMIT")
        return sorted(breaches)

    @staticmethod
    def _exposure_attribution(
        portfolios: Sequence[dict[str, Any]],
        *,
        side: str,
        total_equity: Decimal,
        metadata: Mapping[str, Mapping[str, str]],
        metrics: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Allocate long-only gross exposure without claiming covariance risk.

        Every view is calculated from the same unrounded notionals.  The
        reconciliation is deliberately fail-closed so an attribution table can
        never disagree with the aggregate exposure that drives the gate.
        """
        asset_notionals = PlatformPortfolioSupervisor._aggregate(portfolios, side)
        sector_notionals: dict[str, Decimal] = {}
        cluster_notionals: dict[str, Decimal] = {}
        for code, notional in asset_notionals.items():
            sector = str(metadata[code]["sector"])
            cluster = str(metadata[code]["correlation_cluster"])
            sector_notionals[sector] = (
                sector_notionals.get(sector, Decimal("0")) + notional
            )
            cluster_notionals[cluster] = (
                cluster_notionals.get(cluster, Decimal("0")) + notional
            )
        strategy_notionals = {
            str(portfolio["strategy_id"]): sum(
                portfolio[side].values(), Decimal("0")
            )
            for portfolio in portfolios
        }
        gross = sum(asset_notionals.values(), Decimal("0"))

        def platform_pct(value: Decimal) -> Decimal:
            return value / total_equity * Decimal("100")

        def gross_share(value: Decimal) -> Decimal:
            return (
                value / gross * Decimal("100")
                if gross > 0
                else Decimal("0")
            )

        asset_rows: list[dict[str, Any]] = []
        asset_hhi = Decimal("0")
        for code, notional in sorted(
            asset_notionals.items(), key=lambda item: (-item[1], item[0])
        ):
            normalized = notional / gross if gross > 0 else Decimal("0")
            hhi_contribution = normalized * normalized
            asset_hhi += hhi_contribution
            asset_rows.append(
                {
                    "code": code,
                    "sector": str(metadata[code]["sector"]),
                    "correlation_cluster": str(
                        metadata[code]["correlation_cluster"]
                    ),
                    "notional": _number(notional),
                    "platform_equity_pct": _number(platform_pct(notional)),
                    "gross_share_pct": _number(gross_share(notional)),
                    "concentration_hhi_contribution": _number(hhi_contribution),
                }
            )

        def grouped_rows(
            values: Mapping[str, Decimal], *, key_name: str
        ) -> list[dict[str, Any]]:
            return [
                {
                    key_name: key,
                    "notional": _number(notional),
                    "platform_equity_pct": _number(platform_pct(notional)),
                    "gross_share_pct": _number(gross_share(notional)),
                }
                for key, notional in sorted(
                    values.items(), key=lambda item: (-item[1], item[0])
                )
            ]

        totals = {
            "asset": sum(asset_notionals.values(), Decimal("0")),
            "strategy": sum(strategy_notionals.values(), Decimal("0")),
            "sector": sum(sector_notionals.values(), Decimal("0")),
            "cluster": sum(cluster_notionals.values(), Decimal("0")),
        }
        amount_tolerance = Decimal("0.00000001")
        ratio_tolerance = Decimal("0.000000000000000001")
        if any(abs(value - gross) > amount_tolerance for value in totals.values()):
            raise ValueError("platform exposure attribution does not reconcile")
        expected_effective_assets = (
            Decimal("1") / asset_hhi if asset_hhi > 0 else Decimal("0")
        )
        if (
            abs(expected_effective_assets - metrics["effective_assets"])
            > ratio_tolerance
        ):
            raise ValueError("platform concentration attribution does not reconcile")

        gross_share_total = sum(
            (value / gross * Decimal("100") for value in asset_notionals.values()),
            Decimal("0"),
        ) if gross > 0 else Decimal("0")
        expected_gross_share_total = Decimal("100") if gross > 0 else Decimal("0")
        if abs(gross_share_total - expected_gross_share_total) > ratio_tolerance:
            raise ValueError("platform gross-share attribution does not reconcile")

        return {
            "methodology": EXPOSURE_ATTRIBUTION_METHODOLOGY,
            "asset_contributions": asset_rows,
            "strategy_contributions": grouped_rows(
                strategy_notionals, key_name="strategy_id"
            ),
            "sector_contributions": grouped_rows(
                sector_notionals, key_name="sector"
            ),
            "correlation_cluster_contributions": grouped_rows(
                cluster_notionals, key_name="correlation_cluster"
            ),
            "reconciliation": {
                "status": "PASS",
                "gross_notional": _number(gross),
                "asset_notional_total": _number(totals["asset"]),
                "strategy_notional_total": _number(totals["strategy"]),
                "sector_notional_total": _number(totals["sector"]),
                "correlation_cluster_notional_total": _number(totals["cluster"]),
                "platform_equity_pct_total": _number(platform_pct(gross)),
                "gross_share_pct_total": _number(gross_share_total),
                "asset_hhi": _number(asset_hhi),
                "effective_assets_from_hhi": _number(expected_effective_assets),
            },
        }

    @staticmethod
    def _serialized_metrics(metrics: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "gross_exposure_pct": _number(metrics["gross_exposure_pct"]),
            "cash_pct": _number(metrics["cash_pct"]),
            "asset_weights_pct": {
                key: _number(value)
                for key, value in sorted(metrics["asset_weights_pct"].items())
            },
            "sector_weights_pct": {
                key: _number(value)
                for key, value in sorted(metrics["sector_weights_pct"].items())
            },
            "correlation_cluster_weights_pct": {
                key: _number(value)
                for key, value in sorted(
                    metrics["correlation_cluster_weights_pct"].items()
                )
            },
            "effective_assets": _number(metrics["effective_assets"]),
            "active_strategies": int(metrics["active_strategies"]),
        }

    @staticmethod
    def _breach_measure(code: str, metrics: Mapping[str, Any]) -> Decimal:
        if code == "PLATFORM_GROSS_EXPOSURE_LIMIT":
            return metrics["gross_exposure_pct"]
        if code == "PLATFORM_MINIMUM_CASH_LIMIT":
            return -metrics["cash_pct"]
        if code == "PLATFORM_ASSET_CONCENTRATION_LIMIT":
            return max(metrics["asset_weights_pct"].values(), default=Decimal("0"))
        if code == "PLATFORM_SECTOR_CONCENTRATION_LIMIT":
            return max(metrics["sector_weights_pct"].values(), default=Decimal("0"))
        if code == "PLATFORM_CORRELATION_CLUSTER_LIMIT":
            return max(
                metrics["correlation_cluster_weights_pct"].values(),
                default=Decimal("0"),
            )
        if code == "PLATFORM_MINIMUM_EFFECTIVE_ASSETS":
            return -metrics["effective_assets"]
        if code == "PLATFORM_ACTIVE_STRATEGY_LIMIT":
            return Decimal(int(metrics["active_strategies"]))
        raise ValueError(f"unsupported platform breach: {code}")

    def assess(
        self,
        strategies: Sequence[Mapping[str, Any]],
        *,
        expected_strategy_ids: Sequence[str] | None = None,
    ) -> dict[str, Any]:
        rows = [dict(item) for item in strategies]
        ids = [str(item.get("strategy_id") or "").strip() for item in rows]
        if not rows or any(not item for item in ids) or len(ids) != len(set(ids)):
            raise ValueError("platform assessment requires unique non-empty strategies")
        if expected_strategy_ids is not None:
            expected = sorted(str(item) for item in expected_strategy_ids)
            if sorted(ids) != expected:
                raise ValueError("daily batch must cover the complete formal strategy registry")

        portfolios: list[dict[str, Any]] = []
        canonical_metadata: dict[str, dict[str, str]] = {}
        strategy_summary: list[dict[str, Any]] = []
        safety_breaches: list[str] = []
        risk_restrictions: list[str] = []
        total_equity = Decimal("0")
        for strategy_id, raw in sorted(zip(ids, rows), key=lambda item: item[0]):
            equity = _decimal(raw.get("equity"), f"{strategy_id} equity")
            cash = _decimal(raw.get("cash"), f"{strategy_id} cash")
            if equity <= 0 or cash < 0 or cash > equity:
                raise ValueError(f"{strategy_id} equity/cash is invalid")
            current = self._notionals(
                raw.get("current_positions_notional"),
                strategy_id=strategy_id,
                label="current_positions_notional",
            )
            proposed = self._notionals(
                raw.get("proposed_positions_notional"),
                strategy_id=strategy_id,
                label="proposed_positions_notional",
            )
            if sum(current.values(), Decimal("0")) > equity + Decimal("0.01"):
                raise ValueError(f"{strategy_id} current exposure exceeds equity")
            if abs(
                cash + sum(current.values(), Decimal("0")) - equity
            ) > Decimal("0.01"):
                raise ValueError(
                    f"{strategy_id} cash plus marked positions does not reconcile to equity"
                )
            if sum(proposed.values(), Decimal("0")) > equity + Decimal("0.01"):
                raise ValueError(f"{strategy_id} proposed exposure exceeds equity")
            required_codes = set(current) | set(proposed)
            metadata = self._metadata(
                raw.get("asset_metadata"),
                strategy_id=strategy_id,
                required_codes=required_codes,
            )
            for code, classification in metadata.items():
                previous = canonical_metadata.get(code)
                if previous is not None and previous != classification:
                    raise ValueError(f"conflicting platform risk metadata for {code}")
                canonical_metadata[code] = classification
            mode = str(raw.get("risk_mode") or "")
            if mode not in {"NORMAL", "REDUCE_ONLY", "HALTED_REDUCE_ONLY"}:
                raise ValueError(f"{strategy_id} has an invalid risk mode")
            loss_budget_intact = raw.get("loss_budget_intact")
            if not isinstance(loss_budget_intact, bool):
                raise ValueError(f"{strategy_id} loss_budget_intact must be boolean")
            risk_increased = any(
                proposed.get(code, Decimal("0")) > current.get(code, Decimal("0"))
                for code in set(current) | set(proposed)
            )
            if mode != "NORMAL" and risk_increased:
                safety_breaches.append(f"STRATEGY_NOT_NORMAL:{strategy_id}")
            elif mode != "NORMAL":
                risk_restrictions.append(f"STRATEGY_NOT_NORMAL:{strategy_id}")
            if not loss_budget_intact and risk_increased:
                safety_breaches.append(f"STRATEGY_LOSS_BUDGET_EXHAUSTED:{strategy_id}")
            elif not loss_budget_intact:
                risk_restrictions.append(
                    f"STRATEGY_LOSS_BUDGET_EXHAUSTED:{strategy_id}"
                )
            portfolios.append(
                {
                    "strategy_id": strategy_id,
                    "equity": equity,
                    "cash": cash,
                    "current": current,
                    "proposed": proposed,
                }
            )
            total_equity += equity
            strategy_summary.append(
                {
                    "strategy_id": strategy_id,
                    "equity": _number(equity),
                    "current_gross": _number(sum(current.values(), Decimal("0"))),
                    "proposed_gross": _number(sum(proposed.values(), Decimal("0"))),
                    "risk_mode": mode,
                    "loss_budget_intact": loss_budget_intact,
                }
            )

        for summary, portfolio in zip(strategy_summary, portfolios):
            summary["capital_share_pct"] = _number(
                portfolio["equity"] / total_equity * Decimal("100")
            )

        current_notionals = self._aggregate(portfolios, "current")
        proposed_notionals = self._aggregate(portfolios, "proposed")
        current_active = sum(1 for item in portfolios if item["current"])
        proposed_active = sum(1 for item in portfolios if item["proposed"])
        current_metrics = self._metrics(
            current_notionals,
            total_equity=total_equity,
            metadata=canonical_metadata,
            active_strategies=current_active,
        )
        proposed_metrics = self._metrics(
            proposed_notionals,
            total_equity=total_equity,
            metadata=canonical_metadata,
            active_strategies=proposed_active,
        )
        current_attribution = self._exposure_attribution(
            portfolios,
            side="current",
            total_equity=total_equity,
            metadata=canonical_metadata,
            metrics=current_metrics,
        )
        proposed_attribution = self._exposure_attribution(
            portfolios,
            side="proposed",
            total_equity=total_equity,
            metadata=canonical_metadata,
            metrics=proposed_metrics,
        )
        current_breaches = self._breaches(current_metrics)
        proposed_breaches = self._breaches(proposed_metrics)
        risk_reducing = bool(proposed_breaches) and all(
            code in current_breaches
            and self._breach_measure(code, proposed_metrics)
            <= self._breach_measure(code, current_metrics)
            for code in proposed_breaches
        ) and any(
            self._breach_measure(code, proposed_metrics)
            < self._breach_measure(code, current_metrics)
            for code in proposed_breaches
        )
        unchanged = current_notionals == proposed_notionals
        current_to_compliant_reduction = (
            bool(current_breaches)
            and not proposed_breaches
            and not unchanged
            and proposed_metrics["gross"] <= current_metrics["gross"]
        )
        aggregate_gross_reduced = (
            proposed_metrics["gross"] < current_metrics["gross"]
        )
        if risk_restrictions and aggregate_gross_reduced:
            risk_reducing = True
        if safety_breaches:
            decision = "BLOCKED"
        elif risk_restrictions and aggregate_gross_reduced:
            decision = "REDUCE_ONLY"
        elif current_to_compliant_reduction:
            decision = "REDUCE_ONLY"
            risk_reducing = True
        elif risk_restrictions:
            decision = "MONITOR_ONLY"
        elif not proposed_breaches:
            decision = "PASS"
        elif self.policy.allow_reduce_only_recovery and risk_reducing:
            decision = "REDUCE_ONLY"
        elif unchanged:
            # Daily valuation and reconciliation must remain available while a
            # concentration breach is being repaired.  This mode permits only
            # an exposure-neutral observation; the batch layer suppresses new
            # signals and all risk-increasing execution.
            decision = "MONITOR_ONLY"
        else:
            decision = "BLOCKED"
        breaches = sorted(
            set(proposed_breaches + safety_breaches + risk_restrictions)
        )
        identity = {
            "schema": PLATFORM_PORTFOLIO_ASSESSMENT_SCHEMA,
            "policy": self.policy.evidence(),
            "decision": decision,
            "total_equity": _number(total_equity),
            "strategy_count": len(portfolios),
            "strategies": strategy_summary,
            "current": {
                **self._serialized_metrics(current_metrics),
                "exposure_attribution": current_attribution,
                "breaches": current_breaches,
            },
            "proposed": {
                **self._serialized_metrics(proposed_metrics),
                "exposure_attribution": proposed_attribution,
                "breaches": breaches,
            },
            "risk_reducing": risk_reducing,
            "real_orders": False,
        }
        return {**identity, "assessment_sha256": sha256_digest(identity)}
