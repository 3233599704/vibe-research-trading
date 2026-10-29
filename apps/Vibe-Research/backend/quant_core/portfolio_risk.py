"""Versioned portfolio-level pre-trade limits and drawdown circuit breakers."""

from __future__ import annotations

import math
from dataclasses import dataclass
from decimal import Decimal, ROUND_FLOOR
from typing import Any, Mapping

from .provenance import sha256_digest


PORTFOLIO_RISK_SCHEMA = "quant-core/portfolio-risk/v1"


def _decimal(value: Any) -> Decimal:
    return Decimal(str(value))


def _bounded_percent(config: Mapping[str, Any], key: str, default: float) -> Decimal:
    value = _decimal(config.get(key, default))
    if value < 0 or value > 100:
        raise ValueError(f"{key} must be between 0 and 100")
    return value


@dataclass(frozen=True)
class PortfolioRiskPolicy:
    policy_id: str
    max_gross_exposure_pct: Decimal
    max_asset_pct: Decimal
    max_sector_pct: Decimal
    max_correlation_cluster_pct: Decimal
    minimum_cash_pct: Decimal
    soft_drawdown_pct: Decimal
    hard_drawdown_pct: Decimal
    minimum_effective_positions: Decimal
    asset_metadata: dict[str, dict[str, str]]
    asset_metadata_source: str | None

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> "PortfolioRiskPolicy":
        soft = _bounded_percent(config, "soft_drawdown_pct", 8)
        hard = _bounded_percent(config, "hard_drawdown_pct", 12)
        if soft <= 0 or hard <= soft:
            raise ValueError("drawdown limits require 0 < soft_drawdown_pct < hard_drawdown_pct")
        minimum_cash = _bounded_percent(config, "minimum_cash_pct", 5)
        max_gross = _bounded_percent(config, "max_gross_exposure_pct", 95)
        if max_gross + minimum_cash > 100:
            raise ValueError("max gross exposure plus minimum cash cannot exceed 100%")
        min_effective = _decimal(config.get("minimum_effective_positions", 2))
        if min_effective < 1:
            raise ValueError("minimum_effective_positions must be at least 1")
        metadata: dict[str, dict[str, str]] = {}
        for raw_code, raw in dict(config.get("asset_metadata") or {}).items():
            if not isinstance(raw, Mapping):
                raise ValueError(f"asset metadata must be an object: {raw_code}")
            metadata[str(raw_code)] = {
                "sector": str(raw.get("sector") or "UNCLASSIFIED"),
                "correlation_cluster": str(raw.get("correlation_cluster") or "UNCLASSIFIED"),
            }
        metadata_source = config.get("asset_metadata_source")
        if metadata_source is not None:
            metadata_source = str(metadata_source)
            if metadata_source != "SIGNAL_DECISION_EVIDENCE":
                raise ValueError("unsupported asset_metadata_source")
        return cls(
            policy_id=str(config.get("policy_id") or config.get("version") or "portfolio-risk-v1"),
            max_gross_exposure_pct=max_gross,
            max_asset_pct=_bounded_percent(config, "max_asset_pct", 35),
            max_sector_pct=_bounded_percent(config, "max_sector_pct", 50),
            max_correlation_cluster_pct=_bounded_percent(config, "max_correlation_cluster_pct", 60),
            minimum_cash_pct=minimum_cash,
            soft_drawdown_pct=soft,
            hard_drawdown_pct=hard,
            minimum_effective_positions=min_effective,
            asset_metadata=metadata,
            asset_metadata_source=metadata_source,
        )

    def evidence(self) -> dict[str, Any]:
        identity = {
            "schema": PORTFOLIO_RISK_SCHEMA,
            "policy_id": self.policy_id,
            "max_gross_exposure_pct": str(self.max_gross_exposure_pct),
            "max_asset_pct": str(self.max_asset_pct),
            "max_sector_pct": str(self.max_sector_pct),
            "max_correlation_cluster_pct": str(self.max_correlation_cluster_pct),
            "minimum_cash_pct": str(self.minimum_cash_pct),
            "soft_drawdown_pct": str(self.soft_drawdown_pct),
            "hard_drawdown_pct": str(self.hard_drawdown_pct),
            "minimum_effective_positions": str(self.minimum_effective_positions),
            "asset_metadata": self.asset_metadata,
        }
        if self.asset_metadata_source is not None:
            identity["asset_metadata_source"] = self.asset_metadata_source
        return {**identity, "policy_sha256": sha256_digest(identity)}


class PortfolioRiskController:
    """Stateful risk controller; sells remain available in every safety state."""

    def __init__(self, policy: PortfolioRiskPolicy, initial_equity: float | Decimal) -> None:
        self.policy = policy
        self.initial_equity = _decimal(initial_equity)
        if self.initial_equity <= 0:
            raise ValueError("initial equity must be positive")
        self.peak_equity = self.initial_equity
        self.mode = "NORMAL"
        self.halted = False
        self.halt_reasons: list[str] = []
        self.events: list[dict[str, Any]] = []
        self.latest_assessment: dict[str, Any] | None = None

    def _metadata(self, code: str) -> dict[str, str]:
        return self.policy.asset_metadata.get(
            code,
            {"sector": "UNCLASSIFIED", "correlation_cluster": "UNCLASSIFIED"},
        )

    @staticmethod
    def _position_values(positions: Mapping[str, int], marks: Mapping[str, float]) -> dict[str, Decimal]:
        missing = sorted(code for code, quantity in positions.items() if quantity and code not in marks)
        if missing:
            raise ValueError(f"missing risk marks for positions: {', '.join(missing)}")
        return {
            code: _decimal(marks[code]) * int(quantity)
            for code, quantity in positions.items()
            if int(quantity) > 0
        }

    def limit_buy_quantity(
        self,
        *,
        code: str,
        requested_quantity: int,
        price: Decimal,
        equity: Decimal,
        positions: Mapping[str, int],
        marks: Mapping[str, float],
    ) -> tuple[int, list[str]]:
        if self.halted:
            return 0, ["PORTFOLIO_RISK_HALTED"]
        if self.mode == "REDUCE_ONLY":
            return 0, ["DRAWDOWN_REDUCE_ONLY"]
        if equity <= 0 or price <= 0:
            return 0, ["INVALID_RISK_EQUITY"]
        values = self._position_values(positions, marks)
        metadata = self._metadata(code)
        current_asset = values.get(code, Decimal("0"))
        gross = sum(values.values(), Decimal("0"))
        sector_value = sum(
            value for asset, value in values.items()
            if self._metadata(asset)["sector"] == metadata["sector"]
        )
        cluster_value = sum(
            value for asset, value in values.items()
            if self._metadata(asset)["correlation_cluster"] == metadata["correlation_cluster"]
        )
        limits = {
            "GROSS_EXPOSURE_LIMIT": equity * self.policy.max_gross_exposure_pct / Decimal("100") - gross,
            "ASSET_WEIGHT_LIMIT": equity * self.policy.max_asset_pct / Decimal("100") - current_asset,
            "SECTOR_WEIGHT_LIMIT": equity * self.policy.max_sector_pct / Decimal("100") - sector_value,
            "CORRELATION_CLUSTER_LIMIT": (
                equity * self.policy.max_correlation_cluster_pct / Decimal("100") - cluster_value
            ),
        }
        allowed_notional = min(limits.values())
        raw_allowed = max(0, int((allowed_notional / price).to_integral_value(rounding=ROUND_FLOOR)))
        allowed = min(max(0, int(requested_quantity)), raw_allowed)
        reasons = sorted(code_name for code_name, remaining in limits.items() if remaining < price * requested_quantity)
        return allowed, reasons

    def assess(
        self,
        *,
        equity: float | Decimal,
        cash: float | Decimal,
        positions: Mapping[str, int],
        marks: Mapping[str, float],
    ) -> dict[str, Any]:
        total_equity = _decimal(equity)
        values = self._position_values(positions, marks)
        gross = sum(values.values(), Decimal("0"))
        weights = {
            code: float(value / total_equity * 100) if total_equity > 0 else math.inf
            for code, value in values.items()
        }
        invested = sum(values.values(), Decimal("0"))
        normalized = [float(value / invested) for value in values.values()] if invested > 0 else []
        effective_positions = 1 / sum(weight * weight for weight in normalized) if normalized else 0.0
        sector_weights: dict[str, float] = {}
        cluster_weights: dict[str, float] = {}
        for code, value in values.items():
            metadata = self._metadata(code)
            sector_weights[metadata["sector"]] = sector_weights.get(metadata["sector"], 0.0) + (
                float(value / total_equity * 100) if total_equity > 0 else math.inf
            )
            cluster = metadata["correlation_cluster"]
            cluster_weights[cluster] = cluster_weights.get(cluster, 0.0) + (
                float(value / total_equity * 100) if total_equity > 0 else math.inf
            )
        breaches: list[str] = []
        tolerance = 1e-8
        if float(gross / total_equity * 100) > float(self.policy.max_gross_exposure_pct) + tolerance:
            breaches.append("GROSS_EXPOSURE_LIMIT")
        if weights and max(weights.values()) > float(self.policy.max_asset_pct) + tolerance:
            breaches.append("ASSET_WEIGHT_LIMIT")
        if sector_weights and max(sector_weights.values()) > float(self.policy.max_sector_pct) + tolerance:
            breaches.append("SECTOR_WEIGHT_LIMIT")
        if cluster_weights and max(cluster_weights.values()) > float(self.policy.max_correlation_cluster_pct) + tolerance:
            breaches.append("CORRELATION_CLUSTER_LIMIT")
        cash_pct = float(_decimal(cash) / total_equity * 100) if total_equity > 0 else -math.inf
        if cash_pct + tolerance < float(self.policy.minimum_cash_pct):
            breaches.append("MINIMUM_CASH_LIMIT")
        if positions and effective_positions + tolerance < float(self.policy.minimum_effective_positions):
            breaches.append("MINIMUM_EFFECTIVE_POSITIONS")
        assessment = {
            "equity": round(float(total_equity), 6),
            "cash_pct": round(cash_pct, 4),
            "gross_exposure_pct": round(float(gross / total_equity * 100), 4) if total_equity > 0 else None,
            "asset_weights_pct": {key: round(value, 4) for key, value in sorted(weights.items())},
            "sector_weights_pct": {key: round(value, 4) for key, value in sorted(sector_weights.items())},
            "correlation_cluster_weights_pct": {
                key: round(value, 4) for key, value in sorted(cluster_weights.items())
            },
            "effective_positions": round(effective_positions, 4),
            "breaches": sorted(set(breaches)),
            "compliant": not breaches,
        }
        self.latest_assessment = assessment
        return assessment

    def observe_session(
        self,
        *,
        trade_date: str,
        equity: float | Decimal | None,
        reconciliation_ok: bool,
        data_integrity_ok: bool,
    ) -> dict[str, Any]:
        reasons: list[str] = []
        drawdown_pct: float | None = None
        if not data_integrity_ok:
            reasons.append("DATA_INTEGRITY_FAILURE")
        if not reconciliation_ok:
            reasons.append("LEDGER_RECONCILIATION_FAILURE")
        if equity is not None:
            current = _decimal(equity)
            if current <= 0:
                reasons.append("NONPOSITIVE_EQUITY")
            else:
                self.peak_equity = max(self.peak_equity, current)
                drawdown = (self.peak_equity - current) / self.peak_equity * Decimal("100")
                drawdown_pct = round(float(drawdown), 4)
                if drawdown >= self.policy.hard_drawdown_pct:
                    reasons.append("HARD_DRAWDOWN_LIMIT")
                elif drawdown >= self.policy.soft_drawdown_pct:
                    reasons.append("SOFT_DRAWDOWN_LIMIT")
        hard = any(reason != "SOFT_DRAWDOWN_LIMIT" for reason in reasons)
        if hard:
            self.halted = True
            self.mode = "HALTED_REDUCE_ONLY"
            self.halt_reasons = sorted(set(self.halt_reasons + reasons))
        elif reasons:
            self.mode = "REDUCE_ONLY"
        elif not self.halted:
            self.mode = "NORMAL"
        event = {
            "date": trade_date,
            "mode": self.mode,
            "halted": self.halted,
            "drawdown_pct": drawdown_pct,
            "reasons": sorted(set(reasons)),
        }
        if reasons or not self.events or self.events[-1]["mode"] != self.mode:
            self.events.append(event)
        return event

    def report(self) -> dict[str, Any]:
        return {
            "policy": self.policy.evidence(),
            "mode": self.mode,
            "halted": self.halted,
            "halt_reasons": list(self.halt_reasons),
            "peak_equity": round(float(self.peak_equity), 6),
            "latest_assessment": self.latest_assessment,
            "events": list(self.events),
        }
