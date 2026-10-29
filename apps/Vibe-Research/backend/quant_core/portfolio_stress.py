"""Deterministic multi-strategy price and liquidity stress testing."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Mapping, Sequence

from .liquidity import LIQUIDITY_EVIDENCE_SCHEMA, LIQUIDITY_WINDOW_SESSIONS
from .provenance import sha256_digest


PORTFOLIO_STRESS_POLICY_SCHEMA = "quant-platform/portfolio-stress-policy/v1"
PORTFOLIO_STRESS_ASSESSMENT_SCHEMA = "quant-platform/portfolio-stress-assessment/v2"
STRESS_ATTRIBUTION_METHODOLOGY = (
    "quant-platform/deterministic-scenario-loss-attribution/v1"
)
MANDATORY_SCENARIOS = {
    "CN_EQUITY_GAP_DOWN",
    "CORRELATION_CONVERGENCE",
    "LIQUIDITY_FREEZE",
    "COMBINED_CRISIS",
}


def _decimal(value: Any, label: str) -> Decimal:
    try:
        result = Decimal(str(value))
    except Exception as exc:  # pragma: no cover - Decimal raises several subclasses
        raise ValueError(f"{label} must be numeric") from exc
    if not result.is_finite():
        raise ValueError(f"{label} must be finite")
    return result


def _pct(value: Any, label: str, *, minimum: Decimal, maximum: Decimal) -> Decimal:
    result = _decimal(value, label)
    if result < minimum or result > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return result


def _number(value: Decimal) -> float:
    return round(float(value), 8)


@dataclass(frozen=True)
class StressScenario:
    scenario_id: str
    default_shock_pct: Decimal
    cluster_shocks_pct: dict[str, Decimal]
    asset_shocks_pct: dict[str, Decimal]
    liquidity_haircut_pct: Decimal

    def shock(self, code: str, cluster: str) -> Decimal:
        return self.asset_shocks_pct.get(
            code, self.cluster_shocks_pct.get(cluster, self.default_shock_pct)
        )

    def evidence(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "default_shock_pct": str(self.default_shock_pct),
            "cluster_shocks_pct": {
                key: str(value)
                for key, value in sorted(self.cluster_shocks_pct.items())
            },
            "asset_shocks_pct": {
                key: str(value)
                for key, value in sorted(self.asset_shocks_pct.items())
            },
            "liquidity_haircut_pct": str(self.liquidity_haircut_pct),
        }


@dataclass(frozen=True)
class PortfolioStressPolicy:
    policy_id: str
    max_platform_stress_loss_pct: Decimal
    max_strategy_stress_loss_pct: Decimal
    max_liquidation_days: Decimal
    max_daily_liquidation_participation_pct: Decimal
    allow_reduce_only_recovery: bool
    scenarios: tuple[StressScenario, ...]

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "PortfolioStressPolicy":
        required = {
            "schema_version",
            "policy_id",
            "mode",
            "real_orders",
            "max_platform_stress_loss_pct",
            "max_strategy_stress_loss_pct",
            "max_liquidation_days",
            "max_daily_liquidation_participation_pct",
            "allow_reduce_only_recovery",
            "required_scenario_ids",
            "scenarios",
        }
        if set(config) != required:
            missing = sorted(required - set(config))
            extra = sorted(set(config) - required)
            raise ValueError(
                "portfolio stress policy fields mismatch"
                + (f"; missing: {', '.join(missing)}" if missing else "")
                + (f"; unexpected: {', '.join(extra)}" if extra else "")
            )
        if int(config["schema_version"]) != 1:
            raise ValueError("unsupported portfolio stress policy schema")
        if config["mode"] != "PAPER" or config["real_orders"] is not False:
            raise ValueError("portfolio stress policy must be PAPER-only")
        policy_id = str(config["policy_id"]).strip()
        if not policy_id:
            raise ValueError("portfolio stress policy_id is required")
        platform_loss = _pct(
            config["max_platform_stress_loss_pct"],
            "max_platform_stress_loss_pct",
            minimum=Decimal("0.01"),
            maximum=Decimal("15"),
        )
        strategy_loss = _pct(
            config["max_strategy_stress_loss_pct"],
            "max_strategy_stress_loss_pct",
            minimum=Decimal("0.01"),
            maximum=Decimal("20"),
        )
        if strategy_loss < platform_loss:
            raise ValueError(
                "strategy stress loss limit cannot be below the parent-account limit"
            )
        liquidation_days = _decimal(
            config["max_liquidation_days"], "max_liquidation_days"
        )
        if liquidation_days <= 0 or liquidation_days > Decimal("10"):
            raise ValueError("max_liquidation_days must be within (0, 10]")
        participation = _pct(
            config["max_daily_liquidation_participation_pct"],
            "max_daily_liquidation_participation_pct",
            minimum=Decimal("0.01"),
            maximum=Decimal("5"),
        )
        if not isinstance(config["allow_reduce_only_recovery"], bool):
            raise ValueError("allow_reduce_only_recovery must be boolean")
        if config["allow_reduce_only_recovery"] is not True:
            raise ValueError("reduce-only stress recovery cannot be disabled")
        required_ids = [str(item) for item in list(config["required_scenario_ids"])]
        if set(required_ids) != MANDATORY_SCENARIOS or len(required_ids) != len(
            MANDATORY_SCENARIOS
        ):
            raise ValueError("mandatory stress scenarios cannot be removed or duplicated")
        scenarios: list[StressScenario] = []
        raw_scenarios = list(config["scenarios"])
        if not raw_scenarios:
            raise ValueError("portfolio stress policy requires scenarios")
        for raw_value in raw_scenarios:
            if not isinstance(raw_value, Mapping):
                raise ValueError("stress scenario must be an object")
            raw = dict(raw_value)
            expected = {
                "scenario_id",
                "default_shock_pct",
                "cluster_shocks_pct",
                "asset_shocks_pct",
                "liquidity_haircut_pct",
            }
            if set(raw) != expected:
                raise ValueError("stress scenario fields do not match the schema")
            scenario_id = str(raw["scenario_id"]).strip()
            if not scenario_id:
                raise ValueError("stress scenario_id is required")

            def shocks(value: Any, label: str) -> dict[str, Decimal]:
                if not isinstance(value, Mapping):
                    raise ValueError(f"{label} must be an object")
                result: dict[str, Decimal] = {}
                for raw_key, raw_shock in value.items():
                    key = str(raw_key).strip()
                    if not key:
                        raise ValueError(f"{label} contains an empty key")
                    result[key] = _pct(
                        raw_shock,
                        f"{label}.{key}",
                        minimum=Decimal("-100"),
                        maximum=Decimal("0"),
                    )
                return result

            scenarios.append(
                StressScenario(
                    scenario_id=scenario_id,
                    default_shock_pct=_pct(
                        raw["default_shock_pct"],
                        f"{scenario_id}.default_shock_pct",
                        minimum=Decimal("-100"),
                        maximum=Decimal("0"),
                    ),
                    cluster_shocks_pct=shocks(
                        raw["cluster_shocks_pct"],
                        f"{scenario_id}.cluster_shocks_pct",
                    ),
                    asset_shocks_pct=shocks(
                        raw["asset_shocks_pct"],
                        f"{scenario_id}.asset_shocks_pct",
                    ),
                    liquidity_haircut_pct=_pct(
                        raw["liquidity_haircut_pct"],
                        f"{scenario_id}.liquidity_haircut_pct",
                        minimum=Decimal("0"),
                        maximum=Decimal("100"),
                    ),
                )
            )
        ids = [item.scenario_id for item in scenarios]
        if len(ids) != len(set(ids)) or not MANDATORY_SCENARIOS <= set(ids):
            raise ValueError("stress scenarios are duplicate or incomplete")
        by_id = {item.scenario_id: item for item in scenarios}

        def most_severe(item: StressScenario) -> Decimal:
            return min(
                [
                    item.default_shock_pct,
                    *item.cluster_shocks_pct.values(),
                    *item.asset_shocks_pct.values(),
                ]
            )

        hard_bounds = {
            "CN_EQUITY_GAP_DOWN": (Decimal("-5"), Decimal("-20"), Decimal("50")),
            "CORRELATION_CONVERGENCE": (
                Decimal("-12"),
                Decimal("-20"),
                Decimal("70"),
            ),
            "LIQUIDITY_FREEZE": (Decimal("-5"), Decimal("-10"), Decimal("95")),
            "COMBINED_CRISIS": (Decimal("-12"), Decimal("-30"), Decimal("90")),
        }
        for scenario_id, (maximum_default, required_tail, minimum_haircut) in hard_bounds.items():
            item = by_id[scenario_id]
            if (
                item.default_shock_pct > maximum_default
                or most_severe(item) > required_tail
                or item.liquidity_haircut_pct < minimum_haircut
            ):
                raise ValueError(
                    f"{scenario_id} weakens the non-bypassable stress severity"
                )
        return cls(
            policy_id=policy_id,
            max_platform_stress_loss_pct=platform_loss,
            max_strategy_stress_loss_pct=strategy_loss,
            max_liquidation_days=liquidation_days,
            max_daily_liquidation_participation_pct=participation,
            allow_reduce_only_recovery=True,
            scenarios=tuple(sorted(scenarios, key=lambda item: item.scenario_id)),
        )

    def evidence(self) -> dict[str, Any]:
        identity = {
            "schema": PORTFOLIO_STRESS_POLICY_SCHEMA,
            "policy_id": self.policy_id,
            "mode": "PAPER",
            "real_orders": False,
            "max_platform_stress_loss_pct": str(
                self.max_platform_stress_loss_pct
            ),
            "max_strategy_stress_loss_pct": str(
                self.max_strategy_stress_loss_pct
            ),
            "max_liquidation_days": str(self.max_liquidation_days),
            "max_daily_liquidation_participation_pct": str(
                self.max_daily_liquidation_participation_pct
            ),
            "allow_reduce_only_recovery": True,
            "required_scenario_ids": sorted(MANDATORY_SCENARIOS),
            "scenarios": [item.evidence() for item in self.scenarios],
        }
        return {**identity, "policy_sha256": sha256_digest(identity)}


class PortfolioStressSupervisor:
    """Apply frozen price/liquidity shocks to current and proposed holdings."""

    def __init__(self, policy: PortfolioStressPolicy) -> None:
        self.policy = policy

    @staticmethod
    def _positions(value: Any, strategy_id: str, label: str) -> dict[str, Decimal]:
        if not isinstance(value, Mapping):
            raise ValueError(f"{strategy_id} {label} must be an object")
        result: dict[str, Decimal] = {}
        for raw_code, raw_value in value.items():
            code = str(raw_code).strip()
            notional = _decimal(raw_value, f"{strategy_id} {label}.{code}")
            if not code or notional < 0:
                raise ValueError(f"{strategy_id} {label} is invalid")
            if notional > 0:
                result[code] = notional
        return result

    def _evaluate_side(
        self,
        portfolios: Sequence[dict[str, Any]],
        *,
        side: str,
        total_equity: Decimal,
        metadata: Mapping[str, Mapping[str, str]],
        liquidity: Mapping[str, Mapping[str, Any]],
    ) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        measures: dict[str, Decimal] = {}
        breaches: list[str] = []
        for scenario in self.policy.scenarios:
            platform_loss = Decimal("0")
            strategy_losses: dict[str, Decimal] = {}
            strategy_loss_amounts: dict[str, Decimal] = {}
            aggregate: dict[str, Decimal] = {}
            asset_losses: dict[str, Decimal] = {}
            sector_losses: dict[str, Decimal] = {}
            cluster_losses: dict[str, Decimal] = {}
            applied_shocks: dict[str, Decimal] = {}
            for portfolio in portfolios:
                loss = Decimal("0")
                for code, notional in portfolio[side].items():
                    cluster = str(metadata[code]["correlation_cluster"])
                    sector = str(metadata[code]["sector"])
                    shock = scenario.shock(code, cluster)
                    position_loss = notional * (-shock) / Decimal("100")
                    if position_loss < 0:
                        raise ValueError("stress scenario produced a negative loss")
                    loss += position_loss
                    aggregate[code] = aggregate.get(code, Decimal("0")) + notional
                    asset_losses[code] = (
                        asset_losses.get(code, Decimal("0")) + position_loss
                    )
                    sector_losses[sector] = (
                        sector_losses.get(sector, Decimal("0")) + position_loss
                    )
                    cluster_losses[cluster] = (
                        cluster_losses.get(cluster, Decimal("0")) + position_loss
                    )
                    previous_shock = applied_shocks.get(code)
                    if previous_shock is not None and previous_shock != shock:
                        raise ValueError(
                            f"stress shock conflicts across strategies for {code}"
                        )
                    applied_shocks[code] = shock
                strategy_losses[portfolio["strategy_id"]] = (
                    loss / portfolio["equity"] * Decimal("100")
                )
                strategy_loss_amounts[portfolio["strategy_id"]] = loss
                platform_loss += loss
            platform_loss_pct = platform_loss / total_equity * Decimal("100")

            attribution_totals = {
                "asset": sum(asset_losses.values(), Decimal("0")),
                "strategy": sum(strategy_loss_amounts.values(), Decimal("0")),
                "sector": sum(sector_losses.values(), Decimal("0")),
                "cluster": sum(cluster_losses.values(), Decimal("0")),
            }
            amount_tolerance = Decimal("0.00000001")
            ratio_tolerance = Decimal("0.000000000000000001")
            if any(
                abs(value - platform_loss) > amount_tolerance
                for value in attribution_totals.values()
            ):
                raise ValueError("stress loss attribution does not reconcile")

            def platform_loss_pct_of(value: Decimal) -> Decimal:
                return value / total_equity * Decimal("100")

            def loss_share(value: Decimal) -> Decimal:
                return (
                    value / platform_loss * Decimal("100")
                    if platform_loss > 0
                    else Decimal("0")
                )

            asset_contributions = [
                {
                    "code": code,
                    "sector": str(metadata[code]["sector"]),
                    "correlation_cluster": str(
                        metadata[code]["correlation_cluster"]
                    ),
                    "notional": _number(aggregate[code]),
                    "applied_shock_pct": _number(applied_shocks[code]),
                    "loss_amount": _number(loss),
                    "platform_loss_contribution_pct": _number(
                        platform_loss_pct_of(loss)
                    ),
                    "scenario_loss_share_pct": _number(loss_share(loss)),
                }
                for code, loss in sorted(
                    asset_losses.items(), key=lambda item: (-item[1], item[0])
                )
            ]
            strategy_equity = {
                str(portfolio["strategy_id"]): portfolio["equity"]
                for portfolio in portfolios
            }
            strategy_contributions = [
                {
                    "strategy_id": strategy_id,
                    "loss_amount": _number(loss),
                    "own_equity_loss_pct": _number(
                        loss / strategy_equity[strategy_id] * Decimal("100")
                    ),
                    "platform_loss_contribution_pct": _number(
                        platform_loss_pct_of(loss)
                    ),
                    "scenario_loss_share_pct": _number(loss_share(loss)),
                }
                for strategy_id, loss in sorted(
                    strategy_loss_amounts.items(),
                    key=lambda item: (-item[1], item[0]),
                )
            ]

            def grouped_contributions(
                values: Mapping[str, Decimal], *, key_name: str
            ) -> list[dict[str, Any]]:
                return [
                    {
                        key_name: key,
                        "loss_amount": _number(loss),
                        "platform_loss_contribution_pct": _number(
                            platform_loss_pct_of(loss)
                        ),
                        "scenario_loss_share_pct": _number(loss_share(loss)),
                    }
                    for key, loss in sorted(
                        values.items(), key=lambda item: (-item[1], item[0])
                    )
                ]

            loss_share_total = sum(
                (loss_share(value) for value in asset_losses.values()),
                Decimal("0"),
            )
            expected_share_total = (
                Decimal("100") if platform_loss > 0 else Decimal("0")
            )
            if abs(loss_share_total - expected_share_total) > ratio_tolerance:
                raise ValueError("stress scenario loss shares do not reconcile")

            platform_code = f"STRESS_PLATFORM_LOSS:{scenario.scenario_id}"
            measures[platform_code] = platform_loss_pct
            if platform_loss_pct > self.policy.max_platform_stress_loss_pct:
                breaches.append(platform_code)
            for strategy_id, loss_pct in strategy_losses.items():
                code = f"STRESS_STRATEGY_LOSS:{scenario.scenario_id}:{strategy_id}"
                measures[code] = loss_pct
                if loss_pct > self.policy.max_strategy_stress_loss_pct:
                    breaches.append(code)
            liquidation_days: dict[str, Decimal | None] = {}
            capacity_factor = (
                self.policy.max_daily_liquidation_participation_pct
                / Decimal("100")
                * (Decimal("1") - scenario.liquidity_haircut_pct / Decimal("100"))
            )
            for code, notional in aggregate.items():
                traded_value = (
                    liquidity[code]["price"]
                    * liquidity[code]["conservative_volume"]
                )
                capacity = traded_value * capacity_factor
                days = notional / capacity if capacity > 0 else None
                liquidation_days[code] = days
                breach_code = (
                    f"STRESS_LIQUIDATION_HORIZON:{scenario.scenario_id}:{code}"
                )
                measure = days if days is not None else Decimal("Infinity")
                measures[breach_code] = measure
                if days is None or days > self.policy.max_liquidation_days:
                    breaches.append(breach_code)
            results.append(
                {
                    "scenario_id": scenario.scenario_id,
                    "platform_loss_pct": _number(platform_loss_pct),
                    "strategy_loss_pct": {
                        key: _number(value)
                        for key, value in sorted(strategy_losses.items())
                    },
                    "loss_attribution": {
                        "methodology": STRESS_ATTRIBUTION_METHODOLOGY,
                        "asset_contributions": asset_contributions,
                        "strategy_contributions": strategy_contributions,
                        "sector_contributions": grouped_contributions(
                            sector_losses, key_name="sector"
                        ),
                        "correlation_cluster_contributions": grouped_contributions(
                            cluster_losses, key_name="correlation_cluster"
                        ),
                        "reconciliation": {
                            "status": "PASS",
                            "platform_loss_amount": _number(platform_loss),
                            "asset_loss_total": _number(
                                attribution_totals["asset"]
                            ),
                            "strategy_loss_total": _number(
                                attribution_totals["strategy"]
                            ),
                            "sector_loss_total": _number(
                                attribution_totals["sector"]
                            ),
                            "correlation_cluster_loss_total": _number(
                                attribution_totals["cluster"]
                            ),
                            "platform_loss_pct": _number(platform_loss_pct),
                            "asset_contribution_pct_total": _number(
                                platform_loss_pct_of(attribution_totals["asset"])
                            ),
                            "strategy_contribution_pct_total": _number(
                                platform_loss_pct_of(
                                    attribution_totals["strategy"]
                                )
                            ),
                            "sector_contribution_pct_total": _number(
                                platform_loss_pct_of(attribution_totals["sector"])
                            ),
                            "correlation_cluster_contribution_pct_total": _number(
                                platform_loss_pct_of(attribution_totals["cluster"])
                            ),
                            "scenario_loss_share_pct_total": _number(
                                loss_share_total
                            ),
                        },
                    },
                    "liquidation_days": {
                        key: (_number(value) if value is not None else None)
                        for key, value in sorted(liquidation_days.items())
                    },
                    "breaches": sorted(
                        code
                        for code in breaches
                        if f":{scenario.scenario_id}" in code
                    ),
                }
            )
        finite_measures = {
            key: (value if value.is_finite() else Decimal("1E999"))
            for key, value in measures.items()
        }
        return {
            "scenarios": results,
            "breaches": sorted(set(breaches)),
            "measures": finite_measures,
            "worst_platform_loss_pct": max(
                (Decimal(str(item["platform_loss_pct"])) for item in results),
                default=Decimal("0"),
            ),
            "worst_liquidation_days": max(
                (
                    Decimal(str(value))
                    for item in results
                    for value in item["liquidation_days"].values()
                    if value is not None
                ),
                default=Decimal("0"),
            ),
            "has_infinite_liquidation": any(
                value is None
                for item in results
                for value in item["liquidation_days"].values()
            ),
        }

    def assess(self, strategies: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        rows = [dict(item) for item in strategies]
        ids = [str(item.get("strategy_id") or "").strip() for item in rows]
        if not rows or any(not item for item in ids) or len(ids) != len(set(ids)):
            raise ValueError("stress assessment requires unique non-empty strategies")
        portfolios: list[dict[str, Any]] = []
        metadata: dict[str, dict[str, str]] = {}
        liquidity: dict[str, dict[str, Any]] = {}
        total_equity = Decimal("0")
        for strategy_id, raw in sorted(zip(ids, rows), key=lambda item: item[0]):
            equity = _decimal(raw.get("equity"), f"{strategy_id} equity")
            if equity <= 0:
                raise ValueError(f"{strategy_id} equity must be positive")
            current = self._positions(
                raw.get("current_positions_notional"), strategy_id, "current"
            )
            proposed = self._positions(
                raw.get("proposed_positions_notional"), strategy_id, "proposed"
            )
            required_codes = set(current) | set(proposed)
            raw_metadata = raw.get("asset_metadata")
            raw_liquidity = raw.get("liquidity")
            if not isinstance(raw_metadata, Mapping) or not isinstance(
                raw_liquidity, Mapping
            ):
                raise ValueError(f"{strategy_id} stress metadata/liquidity is missing")
            for code in sorted(required_codes):
                classification = raw_metadata.get(code)
                source = raw_liquidity.get(code)
                if not isinstance(classification, Mapping):
                    raise ValueError(f"stress metadata is missing for {code}")
                cluster = str(classification.get("correlation_cluster") or "").strip()
                sector = str(classification.get("sector") or "").strip()
                if not cluster or not sector or "UNCLASSIFIED" in {cluster, sector}:
                    raise ValueError(f"stress metadata is invalid for {code}")
                candidate_metadata = {
                    "sector": sector,
                    "correlation_cluster": cluster,
                }
                if code in metadata and metadata[code] != candidate_metadata:
                    raise ValueError(f"stress metadata conflicts for {code}")
                metadata[code] = candidate_metadata
                if not isinstance(source, Mapping):
                    raise ValueError(f"stress liquidity is missing for {code}")
                evidence_fields = {
                    "schema",
                    "trade_date",
                    "window_start",
                    "window_end",
                    "window_sessions",
                    "source_observation_count",
                    "current_volume",
                    "adv20_volume",
                    "adv60_volume",
                    "median20_volume",
                    "conservative_volume",
                    "zero_volume_sessions",
                    "history_sha256",
                }
                if set(source) != evidence_fields | {"price", "evidence_sha256"}:
                    raise ValueError(f"stress liquidity evidence fields are invalid for {code}")
                raw_identity = {key: source[key] for key in evidence_fields}
                if (
                    source.get("schema") != LIQUIDITY_EVIDENCE_SCHEMA
                    or source.get("window_sessions") != LIQUIDITY_WINDOW_SESSIONS
                    or not isinstance(source.get("source_observation_count"), int)
                    or int(source["source_observation_count"])
                    < LIQUIDITY_WINDOW_SESSIONS
                    or sha256_digest(raw_identity) != source.get("evidence_sha256")
                ):
                    raise ValueError(f"stress liquidity evidence is invalid for {code}")
                volumes = {
                    key: _decimal(source.get(key), f"{code} liquidity {key}")
                    for key in (
                        "current_volume",
                        "adv20_volume",
                        "adv60_volume",
                        "median20_volume",
                        "conservative_volume",
                    )
                }
                candidate_liquidity = {
                    "price": _decimal(source.get("price"), f"{code} liquidity price"),
                    **volumes,
                    "evidence_sha256": str(source["evidence_sha256"]),
                    "history_sha256": str(source["history_sha256"]),
                }
                if (
                    candidate_liquidity["price"] <= 0
                    or any(value < 0 for value in volumes.values())
                    or volumes["conservative_volume"] != min(
                        volumes["current_volume"],
                        volumes["adv20_volume"],
                        volumes["adv60_volume"],
                        volumes["median20_volume"],
                    )
                    or len(candidate_liquidity["history_sha256"]) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in candidate_liquidity["history_sha256"].lower()
                    )
                ):
                    raise ValueError(f"stress liquidity is invalid for {code}")
                if code in liquidity and liquidity[code] != candidate_liquidity:
                    raise ValueError(f"stress liquidity conflicts for {code}")
                liquidity[code] = candidate_liquidity
            portfolios.append(
                {
                    "strategy_id": strategy_id,
                    "equity": equity,
                    "current": current,
                    "proposed": proposed,
                }
            )
            total_equity += equity
        current = self._evaluate_side(
            portfolios,
            side="current",
            total_equity=total_equity,
            metadata=metadata,
            liquidity=liquidity,
        )
        proposed = self._evaluate_side(
            portfolios,
            side="proposed",
            total_equity=total_equity,
            metadata=metadata,
            liquidity=liquidity,
        )
        risk_reducing = bool(proposed["breaches"]) and all(
            code in current["breaches"]
            and proposed["measures"][code] <= current["measures"][code]
            for code in proposed["breaches"]
        ) and any(
            proposed["measures"][code] < current["measures"][code]
            for code in proposed["breaches"]
        )
        current_positions = {
            (item["strategy_id"], code): value
            for item in portfolios
            for code, value in item["current"].items()
        }
        proposed_positions = {
            (item["strategy_id"], code): value
            for item in portfolios
            for code, value in item["proposed"].items()
        }
        unchanged = current_positions == proposed_positions
        current_to_compliant_reduction = (
            bool(current["breaches"])
            and not proposed["breaches"]
            and not unchanged
            and sum(proposed_positions.values(), Decimal("0"))
            <= sum(current_positions.values(), Decimal("0"))
        )
        if current_to_compliant_reduction:
            decision = "REDUCE_ONLY"
            risk_reducing = True
        elif not proposed["breaches"]:
            decision = "PASS"
        elif self.policy.allow_reduce_only_recovery and risk_reducing:
            decision = "REDUCE_ONLY"
        elif unchanged:
            decision = "MONITOR_ONLY"
        else:
            decision = "BLOCKED"

        def public(value: Mapping[str, Any]) -> dict[str, Any]:
            return {
                "scenarios": list(value["scenarios"]),
                "breaches": list(value["breaches"]),
                "worst_platform_loss_pct": _number(
                    value["worst_platform_loss_pct"]
                ),
                "worst_liquidation_days": (
                    None
                    if value["has_infinite_liquidation"]
                    else _number(value["worst_liquidation_days"])
                ),
                "has_infinite_liquidation": bool(
                    value["has_infinite_liquidation"]
                ),
            }

        identity = {
            "schema": PORTFOLIO_STRESS_ASSESSMENT_SCHEMA,
            "policy": self.policy.evidence(),
            "decision": decision,
            "total_equity": _number(total_equity),
            "strategy_count": len(portfolios),
            "current": public(current),
            "proposed": public(proposed),
            "risk_reducing": risk_reducing,
            "real_orders": False,
        }
        return {**identity, "assessment_sha256": sha256_digest(identity)}
