"""Deterministic in-memory paper execution and double-entry-style reconciliation.

This is the historical backtest adapter of the future persistent paper ledger.  It
keeps orders, fills, lots and audit events separate from strategy decisions, and
it has no network or real-broker capability.
"""

from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, ROUND_FLOOR
import re
from typing import Any

from .market_rules import ExchangeRules
from .portfolio_risk import PortfolioRiskController, PortfolioRiskPolicy
from .provenance import sha256_digest
from .versioned_trading_calendar import (
    TradingCalendarError,
    VersionedTradingCalendar,
)


EXECUTION_SCHEMA = "quant-core/execution-ledger/v2"
EXECUTION_SNAPSHOT_SCHEMA = "quant-core/execution-snapshot/v2"
LEGACY_EXECUTION_SNAPSHOT_SCHEMA = "quant-core/execution-snapshot/v1"
MONEY_QUANTUM = Decimal("0.000001")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _decimal(value: Any) -> Decimal:
    return Decimal(str(value))


def _money(value: Decimal) -> Decimal:
    return value.quantize(MONEY_QUANTUM)


def _float(value: Decimal, digits: int = 6) -> float:
    return round(float(value), digits)


def _date(value: str | date) -> date:
    return value if isinstance(value, date) else date.fromisoformat(str(value))


@dataclass(frozen=True)
class DatedRate:
    effective_date: date
    rate: Decimal


@dataclass(frozen=True)
class CostBreakdown:
    commission: Decimal
    stamp_tax: Decimal
    transfer_fee: Decimal

    @property
    def cash_fees(self) -> Decimal:
        return _money(self.commission + self.stamp_tax + self.transfer_fee)


@dataclass(frozen=True)
class TerminalValuation:
    market_value_equity: float
    hypothetical_liquidation_equity: float
    hypothetical_liquidation_cost: float


@dataclass(frozen=True)
class CostPolicy:
    commission_bps: Decimal
    minimum_commission: Decimal
    slippage_bps: Decimal
    sell_stamp_tax_bps: Decimal = Decimal("0")
    transfer_fee_bps: Decimal = Decimal("0")
    stamp_tax_schedule: tuple[DatedRate, ...] = ()
    transfer_fee_schedule: tuple[DatedRate, ...] = ()
    policy_id: str = "cn_etf_research_cost_v1"
    asset_class: str = "exchange_traded_fund"

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "CostPolicy":
        def schedule(key: str) -> tuple[DatedRate, ...]:
            rows = list(config.get(key) or [])
            values = tuple(
                DatedRate(
                    effective_date=_date(str(item["effective_date"])),
                    rate=_decimal(item["rate"]),
                )
                for item in rows
            )
            if values != tuple(sorted(values, key=lambda item: item.effective_date)):
                raise ValueError(f"{key} must be sorted by effective_date")
            if any(item.rate < 0 for item in values):
                raise ValueError(f"{key} contains a negative rate")
            return values

        return cls(
            commission_bps=_decimal(config["commission_bps"]),
            minimum_commission=_decimal(config["min_commission"]),
            slippage_bps=_decimal(config["slippage_bps"]),
            sell_stamp_tax_bps=_decimal(config.get("sell_stamp_tax_bps", 0)),
            transfer_fee_bps=_decimal(config.get("transfer_fee_bps", 0)),
            stamp_tax_schedule=schedule("stamp_tax_schedule"),
            transfer_fee_schedule=schedule("transfer_fee_schedule"),
            policy_id=str(
                config.get("cost_policy_id")
                or config.get("version")
                or "cn_etf_research_cost_v1"
            ),
            asset_class=str(config.get("asset_class") or "exchange_traded_fund"),
        )

    def execution_price(self, side: str, reference_price: Decimal) -> Decimal:
        direction = Decimal("1") if side == "buy" else Decimal("-1")
        return _money(reference_price * (Decimal("1") + direction * self.slippage_bps / Decimal("10000")))

    @staticmethod
    def _scheduled_rate(day: str | date | None, schedule: tuple[DatedRate, ...]) -> Decimal:
        if day is None:
            raise ValueError("trade_date is required by the dated fee schedule")
        parsed = _date(day)
        eligible = [item.rate for item in schedule if item.effective_date <= parsed]
        if not eligible:
            raise ValueError(f"no fee rate is configured for {parsed.isoformat()}")
        return eligible[-1]

    def cost_breakdown(
        self,
        side: str,
        price: Decimal,
        quantity: int,
        trade_date: str | date | None = None,
    ) -> CostBreakdown:
        notional = price * quantity
        commission = max(self.minimum_commission, notional * self.commission_bps / Decimal("10000"))
        stamp_rate = (
            self._scheduled_rate(trade_date, self.stamp_tax_schedule)
            if self.stamp_tax_schedule
            else self.sell_stamp_tax_bps / Decimal("10000")
        )
        transfer_rate = (
            self._scheduled_rate(trade_date, self.transfer_fee_schedule)
            if self.transfer_fee_schedule
            else self.transfer_fee_bps / Decimal("10000")
        )
        stamp_tax = (
            notional * stamp_rate if side == "sell" else Decimal("0")
        )
        transfer_fee = notional * transfer_rate
        return CostBreakdown(
            commission=_money(commission),
            stamp_tax=_money(stamp_tax),
            transfer_fee=_money(transfer_fee),
        )

    def charges(
        self,
        side: str,
        price: Decimal,
        quantity: int,
        trade_date: str | date | None = None,
    ) -> tuple[Decimal, Decimal]:
        """Legacy two-field API retained for existing callers."""
        costs = self.cost_breakdown(side, price, quantity, trade_date)
        return costs.commission, costs.stamp_tax

    def evidence(self) -> dict[str, Any]:
        values = {
            "policy_id": self.policy_id,
            "commission_bps": str(self.commission_bps),
            "minimum_commission": str(self.minimum_commission),
            "slippage_bps": str(self.slippage_bps),
            "sell_stamp_tax_bps": str(self.sell_stamp_tax_bps),
            "transfer_fee_bps": str(self.transfer_fee_bps),
            "stamp_tax_schedule": [
                {"effective_date": item.effective_date.isoformat(), "rate": str(item.rate)}
                for item in self.stamp_tax_schedule
            ],
            "transfer_fee_schedule": [
                {"effective_date": item.effective_date.isoformat(), "rate": str(item.rate)}
                for item in self.transfer_fee_schedule
            ],
            "asset_class": self.asset_class,
        }
        return {**values, "policy_sha256": sha256_digest(values)}


@dataclass
class PositionLot:
    lot_id: str
    code: str
    quantity: int
    acquired_on: str
    unit_cost: Decimal


class SimulationLedger:
    """Atomic next-open execution ledger with deterministic IDs and audit events."""

    def __init__(self, initial_cash: float, config: dict[str, Any], names: dict[str, str]) -> None:
        self.initial_cash = _decimal(initial_cash)
        self.cash = self.initial_cash
        self.config = deepcopy(config)
        self.names = deepcopy(names)
        calendar_binding = self.config.get("trading_calendar")
        if self.config.get("t_plus_one_calendar_required") is True and not calendar_binding:
            raise TradingCalendarError(
                "CALENDAR_BINDING_REQUIRED",
                "T+1 ledger requires a versioned trading calendar",
            )
        self.trading_calendar = (
            VersionedTradingCalendar.from_binding(dict(calendar_binding))
            if calendar_binding
            else None
        )
        if self.trading_calendar is not None:
            if self.config.get("t_plus_one") is not True:
                raise TradingCalendarError(
                    "CALENDAR_BINDING_UNUSED",
                    "calendar-bound ledger must enable T+1",
                )
            if self.config.get("market") != self.trading_calendar.market:
                raise TradingCalendarError(
                    "CALENDAR_MARKET_MISMATCH",
                    "ledger market does not match trading calendar",
                )
        self.cost_policy = CostPolicy.from_config(self.config)
        self.exchange_rules = (
            ExchangeRules(dict(self.config["exchange_rules"]))
            if self.config.get("exchange_rules")
            else None
        )
        self.portfolio_risk = (
            PortfolioRiskController(
                PortfolioRiskPolicy.from_config(dict(self.config["portfolio_risk_policy"])),
                self.initial_cash,
            )
            if self.config.get("portfolio_risk_policy")
            else None
        )
        self.lots: list[PositionLot] = []
        self.orders: list[dict[str, Any]] = []
        self.pending_orders: dict[str, dict[str, Any]] = {}
        self.fills: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.reconciliations: list[dict[str, Any]] = []
        self.total_cost = Decimal("0")
        self.total_commission = Decimal("0")
        self.total_stamp_tax = Decimal("0")
        self.total_transfer_fee = Decimal("0")
        self.turnover = Decimal("0")
        self.realized_pnl = Decimal("0")
        self.total_slippage = Decimal("0")
        self.total_cash_distributions = Decimal("0")
        self.total_terminal_recoveries = Decimal("0")
        self.total_terminal_write_off_cost_basis = Decimal("0")
        self.cash_distributions: list[dict[str, Any]] = []
        self.corporate_actions: list[dict[str, Any]] = []
        self.terminal_events: list[dict[str, Any]] = []
        self._cash_movements: list[Decimal] = []
        self._fee_movements: list[Decimal] = []
        self._sequence = 0
        self._legacy_snapshot: dict[str, Any] | None = None
        self._event("ACCOUNT_CREATED", "account", "paper", {"initial_cash": _float(self.initial_cash, 2)})

    @property
    def position_quantities(self) -> dict[str, int]:
        output: dict[str, int] = {}
        for lot in self.lots:
            output[lot.code] = output.get(lot.code, 0) + lot.quantity
        return {code: quantity for code, quantity in output.items() if quantity > 0}

    def bind_point_in_time_asset_metadata(
        self,
        metadata: dict[str, dict[str, str]],
        *,
        evidence_sha256: str,
    ) -> dict[str, Any]:
        """Bind data-derived risk groups without changing frozen thresholds."""

        if not self.portfolio_risk or not self.config.get("portfolio_risk_policy"):
            raise ValueError("portfolio risk policy is required for metadata binding")
        configured = dict(self.config["portfolio_risk_policy"])
        if configured.get("asset_metadata_source") != "SIGNAL_DECISION_EVIDENCE":
            raise ValueError("execution profile does not permit dynamic risk metadata")
        digest = str(evidence_sha256 or "").lower()
        if not SHA256_RE.fullmatch(digest):
            raise ValueError("metadata evidence_sha256 must be a SHA-256 digest")
        normalized: dict[str, dict[str, str]] = {}
        for raw_code, raw in sorted(dict(metadata).items()):
            code = str(raw_code or "")
            item = dict(raw or {})
            sector = str(item.get("sector") or "")
            cluster = str(item.get("correlation_cluster") or "")
            if (
                not code
                or not sector
                or not cluster
                or sector == "UNCLASSIFIED"
                or cluster == "UNCLASSIFIED"
            ):
                raise ValueError(
                    f"dynamic risk metadata is incomplete: {code or '<empty>'}"
                )
            normalized[code] = {
                "sector": sector,
                "correlation_cluster": cluster,
            }
        if not normalized:
            raise ValueError("dynamic risk metadata cannot be empty")

        configured["asset_metadata"] = normalized
        configured["asset_metadata_binding_sha256"] = digest
        self.config = {**self.config, "portfolio_risk_policy": configured}
        old = self.portfolio_risk
        controller = PortfolioRiskController(
            PortfolioRiskPolicy.from_config(configured), old.initial_equity
        )
        controller.peak_equity = old.peak_equity
        controller.mode = old.mode
        controller.halted = old.halted
        controller.halt_reasons = deepcopy(old.halt_reasons)
        controller.events = deepcopy(old.events)
        controller.latest_assessment = deepcopy(old.latest_assessment)
        self.portfolio_risk = controller
        identity = {
            "schema": "quant-core/point-in-time-risk-metadata-binding/v1",
            "asset_count": len(normalized),
            "asset_metadata": normalized,
            "evidence_sha256": digest,
            "real_orders": False,
        }
        binding = {**identity, "binding_sha256": sha256_digest(identity)}
        self._event(
            "POINT_IN_TIME_RISK_METADATA_BOUND",
            "risk_metadata",
            binding["binding_sha256"],
            binding,
        )
        return binding

    def available_to_sell(self, code: str, trade_date: str) -> int:
        if not self.config.get("t_plus_one", True):
            return self.position_quantities.get(code, 0)
        if self.trading_calendar is None:
            return sum(
                lot.quantity
                for lot in self.lots
                if lot.code == code and lot.acquired_on < trade_date
            )
        self.trading_calendar.require_session(trade_date)
        return sum(
            lot.quantity
            for lot in self.lots
            if lot.code == code
            and self.trading_calendar.is_t1_eligible(
                acquired_on=lot.acquired_on,
                candidate_session=trade_date,
            )
        )

    def assert_trading_calendar_binding(self, binding: dict[str, Any]) -> dict[str, Any]:
        """Reject calendar revisions instead of silently re-dating existing lots."""

        if self.trading_calendar is None:
            raise TradingCalendarError(
                "CALENDAR_BINDING_REQUIRED",
                "ledger has no versioned trading calendar",
            )
        self.trading_calendar.assert_same_binding(binding)
        return self.trading_calendar.evidence()

    def apply_cash_distribution(
        self,
        code: str,
        trade_date: str,
        amount_per_share: float,
    ) -> dict[str, Any] | None:
        """Credit a point-in-time cash distribution to shares held before the open."""

        quantity = self.position_quantities.get(str(code), 0)
        per_share = _decimal(amount_per_share)
        if quantity <= 0:
            return None
        if per_share <= 0 or not per_share.is_finite():
            raise ValueError("cash distribution per share must be positive and finite")
        amount = _money(per_share * quantity)
        self.cash = _money(self.cash + amount)
        self._cash_movements.append(amount)
        self.total_cash_distributions = _money(self.total_cash_distributions + amount)
        event = {
            "date": str(trade_date),
            "code": str(code),
            "quantity": quantity,
            "amount_per_share": _float(per_share, 6),
            "cash_amount": _float(amount, 2),
        }
        self.cash_distributions.append(event)
        self._event("CASH_DISTRIBUTION_APPLIED", "asset", str(code), event)
        return deepcopy(event)

    def apply_split(self, code: str, trade_date: str, ratio: float) -> dict[str, Any] | None:
        """Apply a fund unit split before the session opens without creating P&L."""

        split_ratio = _decimal(ratio)
        if split_ratio <= 0 or not split_ratio.is_finite():
            raise ValueError("split ratio must be positive and finite")
        affected = [lot for lot in self.lots if lot.code == str(code) and lot.quantity > 0]
        if not affected:
            return None
        before_quantity = sum(lot.quantity for lot in affected)
        adjustments: list[tuple[PositionLot, int, Decimal]] = []
        for lot in affected:
            adjusted = _decimal(lot.quantity) * split_ratio
            adjusted_quantity = int(adjusted)
            if adjusted != adjusted_quantity or adjusted_quantity <= 0:
                raise ValueError("split creates unsupported fractional ETF units")
            adjustments.append((lot, adjusted_quantity, lot.unit_cost / split_ratio))
        for lot, adjusted_quantity, adjusted_unit_cost in adjustments:
            lot.quantity = adjusted_quantity
            lot.unit_cost = adjusted_unit_cost
        event = {
            "date": str(trade_date),
            "code": str(code),
            "ratio": _float(split_ratio, 8),
            "before_quantity": before_quantity,
            "after_quantity": sum(lot.quantity for lot in affected),
        }
        self.corporate_actions.append(event)
        self._event("UNIT_SPLIT_APPLIED", "asset", str(code), event)
        return deepcopy(event)

    def apply_terminal_event(
        self,
        code: str,
        trade_date: str,
        *,
        recovery_per_share: float = 0.0,
        reason: str,
        evidence_sha256: str,
    ) -> dict[str, Any] | None:
        """Terminate a position using only an authoritative lifecycle event.

        A missing authoritative recovery is represented by an explicit zero
        recovery, never by carrying the last stale market price.  Pending
        orders for the asset are cancelled before the lots are removed.
        """

        asset = str(code).strip()
        terminal_reason = str(reason).strip().upper()
        evidence = str(evidence_sha256).strip().lower()
        if not asset or not terminal_reason:
            raise ValueError("terminal event identity is incomplete")
        if not SHA256_RE.fullmatch(evidence):
            raise ValueError("terminal event requires canonical sha256 evidence")
        recovery = _decimal(recovery_per_share)
        if not recovery.is_finite() or recovery < 0:
            raise ValueError("terminal recovery per share must be finite and nonnegative")
        affected = [lot for lot in self.lots if lot.code == asset and lot.quantity > 0]
        if not affected:
            return None
        for order_id, pending in list(self.pending_orders.items()):
            if str(pending.get("code")) == asset:
                self.cancel_order(order_id, "ASSET_TERMINATED", str(trade_date))
        quantity = sum(lot.quantity for lot in affected)
        cost_basis = _money(sum(lot.unit_cost * lot.quantity for lot in affected))
        recovery_cash = _money(recovery * quantity)
        self.lots = [lot for lot in self.lots if lot.code != asset]
        if recovery_cash:
            self.cash = _money(self.cash + recovery_cash)
            self._cash_movements.append(recovery_cash)
        self.total_terminal_recoveries = _money(
            self.total_terminal_recoveries + recovery_cash
        )
        self.total_terminal_write_off_cost_basis = _money(
            self.total_terminal_write_off_cost_basis + cost_basis
        )
        self.realized_pnl = _money(self.realized_pnl + recovery_cash - cost_basis)
        event = {
            "date": str(trade_date),
            "code": asset,
            "quantity": quantity,
            "recovery_per_share": _float(recovery, 8),
            "recovery_cash": _float(recovery_cash, 2),
            "cost_basis": _float(cost_basis, 2),
            "realized_pnl": _float(recovery_cash - cost_basis, 2),
            "reason": terminal_reason,
            "evidence_sha256": evidence,
        }
        self.terminal_events.append(event)
        self._event("POSITION_TERMINATED", "asset", asset, event)
        return deepcopy(event)

    def _event(self, event_type: str, entity_type: str, entity_id: str, payload: dict[str, Any]) -> None:
        self._legacy_snapshot = None
        self.events.append(
            {
                "sequence": len(self.events) + 1,
                "event_type": event_type,
                "entity_type": entity_type,
                "entity_id": entity_id,
                "payload": payload,
            }
        )

    def _next_id(self, trade_date: str, side: str, code: str) -> str:
        self._sequence += 1
        return f"{trade_date}-{self._sequence:04d}-{side}-{code}"

    def equity(self, marks: dict[str, float]) -> Decimal:
        missing = sorted(set(self.position_quantities) - set(marks))
        if missing:
            raise ValueError(f"missing valuation marks for positions: {', '.join(missing)}")
        market_value = sum(_decimal(marks[code]) * quantity for code, quantity in self.position_quantities.items())
        return _money(self.cash + market_value)

    def _reject(
        self,
        *,
        order_id: str,
        signal_date: str,
        trade_date: str,
        code: str,
        side: str,
        quantity: int,
        reason: str,
        filled_quantity: int = 0,
    ) -> dict[str, Any]:
        existing = next((item for item in self.orders if item["id"] == order_id), None)
        attempts = list((existing or {}).get("attempts") or [])
        attempts.append({"date": trade_date, "status": "REJECTED", "reason": reason})
        order = {
            "id": order_id,
            "signal_date": signal_date,
            "date": trade_date,
            "side": side,
            "code": code,
            "name": self.names.get(code, code),
            "requested_quantity": quantity,
            "filled_quantity": filled_quantity,
            "status": "REJECTED",
            "reject_reason": reason,
            "attempts": attempts,
        }
        self._record_order(order)
        self.pending_orders.pop(order_id, None)
        self._event("ORDER_REJECTED", "order", order_id, {"reason": reason})
        return order

    def _record_order(self, order: dict[str, Any]) -> None:
        for index, existing in enumerate(self.orders):
            if existing["id"] == order["id"]:
                self.orders[index] = order
                return
        self.orders.append(order)

    def _defer(
        self,
        *,
        order_id: str,
        signal_date: str,
        trade_date: str,
        code: str,
        side: str,
        quantity: int,
        filled_quantity: int,
        status: str,
        reason: str,
    ) -> dict[str, Any]:
        existing = next((item for item in self.orders if item["id"] == order_id), None)
        attempts = list((existing or {}).get("attempts") or [])
        attempts.append({"date": trade_date, "status": status, "reason": reason})
        order = {
            "id": order_id,
            "signal_date": signal_date,
            "date": trade_date,
            "side": side,
            "code": code,
            "name": self.names.get(code, code),
            "requested_quantity": quantity,
            "filled_quantity": filled_quantity,
            "remaining_quantity": max(0, quantity - filled_quantity),
            "status": status,
            "reject_reason": reason,
            "attempts": attempts,
        }
        self._record_order(order)
        self.pending_orders[order_id] = order
        self._event(f"ORDER_{status}", "order", order_id, {"reason": reason})
        return order

    def _consume_lots(self, code: str, quantity: int, trade_date: str, price: Decimal, fees: Decimal) -> None:
        remaining = quantity
        consumed_cost = Decimal("0")
        retained: list[PositionLot] = []
        for lot in self.lots:
            eligible = lot.code == code and (
                not self.config.get("t_plus_one", True)
                or (
                    self.trading_calendar.is_t1_eligible(
                        acquired_on=lot.acquired_on,
                        candidate_session=trade_date,
                    )
                    if self.trading_calendar is not None
                    else lot.acquired_on < trade_date
                )
            )
            if eligible and remaining > 0:
                used = min(lot.quantity, remaining)
                consumed_cost += lot.unit_cost * used
                lot.quantity -= used
                remaining -= used
            if lot.quantity > 0:
                retained.append(lot)
        if remaining:
            raise RuntimeError("ledger attempted to consume unavailable position lots")
        self.lots = retained
        self.realized_pnl += price * quantity - consumed_cost - fees

    def _maximum_cash_quantity(self, code: str, requested: int, price: Decimal, trade_date: str) -> int:
        minimum, increment = self._lot_spec(code)
        reserve = self.initial_cash * _decimal(self.config.get("cash_reserve_pct", 0)) / Decimal("100")
        quantity = requested
        while quantity >= minimum:
            costs = self.cost_policy.cost_breakdown("buy", price, quantity, trade_date)
            if price * quantity + costs.cash_fees <= self.cash - reserve:
                return quantity
            quantity -= increment
        return 0

    def _lot_spec(self, code: str) -> tuple[int, int]:
        if self.exchange_rules is not None and code:
            return self.exchange_rules.lot_spec(code)
        lot_size = int(self.config.get("lot_size", 100))
        return lot_size, lot_size

    def _normalized_buy_quantity(self, code: str, quantity: int | float) -> int:
        if self.exchange_rules is not None:
            return self.exchange_rules.normalized_buy_quantity(code, quantity)
        lot_size = int(self.config.get("lot_size", 100))
        normalized = max(0, int(quantity))
        return normalized - normalized % lot_size

    def _maximum_risk_quantity(
        self,
        code: str,
        requested: int,
        price: Decimal,
        open_marks: dict[str, float],
    ) -> tuple[int, list[str]]:
        reasons: list[str] = []
        positions = self.position_quantities
        if code not in positions and len(positions) >= int(self.config.get("max_positions", len(self.names))):
            return 0, ["MAX_POSITIONS_LIMIT"]
        max_ratio = _decimal(self.config.get("max_position_pct", 100)) / Decimal("100")
        equity = self.equity(open_marks)
        current_value = _decimal(open_marks.get(code, float(price))) * positions.get(code, 0)
        allowance = max(Decimal("0"), equity * max_ratio - current_value)
        raw_allowed = int((allowance / price).to_integral_value(rounding=ROUND_FLOOR))
        allowed = self._normalized_buy_quantity(code, raw_allowed)
        if allowed < requested:
            reasons.append("ASSET_WEIGHT_LIMIT")
        allowed = min(requested, max(0, allowed))
        if self.portfolio_risk is not None:
            portfolio_allowed, portfolio_reasons = self.portfolio_risk.limit_buy_quantity(
                code=code,
                requested_quantity=allowed,
                price=price,
                equity=equity,
                positions=positions,
                marks=open_marks,
            )
            normalized = self._normalized_buy_quantity(code, portfolio_allowed)
            if normalized < allowed:
                reasons.extend(portfolio_reasons or ["PORTFOLIO_RISK_LIMIT"])
            allowed = normalized
        return allowed, sorted(set(reasons))

    def submit_and_fill(
        self,
        *,
        signal_date: str,
        trade_date: str,
        code: str,
        side: str,
        requested_quantity: int,
        bar: dict[str, Any] | None,
        open_marks: dict[str, float],
        _order_id: str | None = None,
        _original_quantity: int | None = None,
        _filled_before: int = 0,
    ) -> dict[str, Any]:
        order_id = _order_id or self._next_id(trade_date, side, code)
        original_quantity = int(_original_quantity or requested_quantity)
        if _order_id is None:
            self._event(
                "ORDER_CREATED",
                "order",
                order_id,
                {"code": code, "side": side, "requested_quantity": requested_quantity, "signal_date": signal_date},
            )
        else:
            self._event(
                "ORDER_RETRY",
                "order",
                order_id,
                {"trade_date": trade_date, "remaining_quantity": requested_quantity},
            )

        def reject(reason: str) -> dict[str, Any]:
            return self._reject(
                order_id=order_id, signal_date=signal_date, trade_date=trade_date, code=code,
                side=side, quantity=original_quantity, reason=reason,
                filled_quantity=_filled_before,
            )

        def block(status: str, reason: str) -> dict[str, Any]:
            if not bool(self.config.get("retry_blocked_orders", False)):
                return reject(reason)
            return self._defer(
                order_id=order_id, signal_date=signal_date, trade_date=trade_date,
                code=code, side=side, quantity=original_quantity,
                filled_quantity=_filled_before, status=status, reason=reason,
            )

        if self.trading_calendar is not None:
            try:
                self.trading_calendar.require_session(trade_date)
            except TradingCalendarError as exc:
                reason = (
                    "NON_TRADING_SESSION"
                    if exc.code == "NON_TRADING_SESSION"
                    else "TRADING_CALENDAR_UNAVAILABLE"
                )
                return reject(reason)

        minimum, increment = self._lot_spec(code)
        if requested_quantity <= 0 or (
            side == "buy" and self._normalized_buy_quantity(code, requested_quantity) != requested_quantity
        ):
            return reject("INVALID_LOT")
        if (
            bool(self.config.get("enforce_next_session", False))
            and _date(trade_date) <= _date(signal_date)
        ):
            return reject("SAME_SESSION_EXECUTION_FORBIDDEN")
        if bar is not None and bool(bar.get("unsupported_corporate_action")):
            return block("PENDING", "UNSUPPORTED_CORPORATE_ACTION")
        if bar is None or bool(bar.get("suspended")) or _decimal(bar.get("volume", 0)) <= 0:
            return block("SUSPENDED", "SUSPENDED_OR_NO_VOLUME")
        rules_locked = (
            self.exchange_rules.is_locked(side, code, trade_date, bar)
            if self.exchange_rules is not None
            else False
        )
        if side == "buy" and (bool(bar.get("limit_up_locked")) or rules_locked):
            return block("LIMIT_LOCKED", "LIMIT_UP_LOCKED")
        if side == "sell" and (bool(bar.get("limit_down_locked")) or rules_locked):
            return block("LIMIT_LOCKED", "LIMIT_DOWN_LOCKED")

        reference_price = _decimal(bar["open"])
        execution_price = self.cost_policy.execution_price(side, reference_price)
        capacity_ratio = _decimal(self.config.get("max_volume_participation_pct", 10)) / Decimal("100")
        raw_capacity = int((_decimal(bar["volume"]) * capacity_ratio).to_integral_value(rounding=ROUND_FLOOR))
        capacity = self._normalized_buy_quantity(code, raw_capacity)
        fill_quantity = min(requested_quantity, capacity)
        reduction_reasons: list[str] = []
        if fill_quantity < requested_quantity:
            reduction_reasons.append("VOLUME_CAPACITY")

        if side == "sell":
            available = self.available_to_sell(code, trade_date)
            if available <= 0:
                reason = "T1_POSITION_UNAVAILABLE" if self.position_quantities.get(code, 0) else "POSITION_NOT_FOUND"
                return block("PENDING", reason) if reason == "T1_POSITION_UNAVAILABLE" else reject(reason)
            fill_quantity = min(fill_quantity, available)
            if fill_quantity < requested_quantity:
                reduction_reasons.append("AVAILABLE_POSITION")
        else:
            risk_quantity, risk_reasons = self._maximum_risk_quantity(
                code, fill_quantity, execution_price, open_marks,
            )
            if risk_quantity < fill_quantity:
                reduction_reasons.extend(risk_reasons or ["POSITION_RISK_LIMIT"])
            fill_quantity = risk_quantity
            cash_quantity = self._maximum_cash_quantity(code, fill_quantity, execution_price, trade_date)
            if cash_quantity < fill_quantity:
                reduction_reasons.append("AVAILABLE_CASH")
            fill_quantity = cash_quantity

        if fill_quantity <= 0:
            return reject(reduction_reasons[-1] if reduction_reasons else "NO_EXECUTABLE_QUANTITY")
        if side == "sell":
            held = self.position_quantities.get(code, 0)
            if self.exchange_rules is not None:
                fill_quantity = self.exchange_rules.valid_sell_quantity(code, fill_quantity, held)
            elif fill_quantity % increment and fill_quantity != held:
                fill_quantity -= fill_quantity % increment
        if fill_quantity <= 0:
            return reject("INVALID_SELL_LOT")

        costs = self.cost_policy.cost_breakdown(side, execution_price, fill_quantity, trade_date)
        commission = costs.commission
        stamp_tax = costs.stamp_tax
        transfer_fee = costs.transfer_fee
        fees = costs.cash_fees
        notional = execution_price * fill_quantity
        self._event("ORDER_VALIDATED", "order", order_id, {"reference_price": _float(reference_price)})
        self._event("ORDER_SUBMITTED", "order", order_id, {"reserved_quantity": fill_quantity})
        if side == "buy":
            cash_delta = -notional - fees
            self.cash = _money(self.cash + cash_delta)
            self.lots.append(
                PositionLot(
                    lot_id=f"lot-{order_id}", code=code, quantity=fill_quantity,
                    acquired_on=trade_date, unit_cost=(notional + fees) / fill_quantity,
                )
            )
        else:
            self._consume_lots(code, fill_quantity, trade_date, execution_price, fees)
            cash_delta = notional - fees
            self.cash = _money(self.cash + cash_delta)
        self._cash_movements.append(_money(cash_delta))
        self._fee_movements.append(_money(fees))
        self.total_cost += fees
        self.total_commission += commission
        self.total_stamp_tax += stamp_tax
        self.total_transfer_fee += transfer_fee
        slippage_cost = abs(execution_price - reference_price) * fill_quantity
        self.total_slippage += slippage_cost
        self.turnover += notional
        total_filled = _filled_before + fill_quantity
        status = "FILLED" if total_filled == original_quantity else "PARTIALLY_FILLED"
        existing = next((item for item in self.orders if item["id"] == order_id), None)
        attempts = list((existing or {}).get("attempts") or [])
        attempts.append({
            "date": trade_date,
            "status": status,
            "reason": "FILLED" if status == "FILLED" else "PARTIAL_FILL",
            "quantity": fill_quantity,
        })
        order = {
            "id": order_id,
            "signal_date": signal_date,
            "date": trade_date,
            "side": side,
            "code": code,
            "name": self.names.get(code, code),
            "requested_quantity": original_quantity,
            "filled_quantity": total_filled,
            "remaining_quantity": max(0, original_quantity - total_filled),
            "status": status,
            "reject_reason": None,
            "reduction_reasons": sorted(set(reduction_reasons)),
            "attempts": attempts,
        }
        fill = {
            "id": f"fill-{order_id}-{len([item for item in self.fills if item['order_id'] == order_id]) + 1}",
            "order_id": order_id,
            "signal_date": signal_date,
            "date": trade_date,
            "side": side,
            "code": code,
            "name": self.names.get(code, code),
            "quantity": fill_quantity,
            "price": _float(execution_price, 4),
            "reference_price": _float(reference_price, 4),
            "notional": _float(notional, 2),
            "commission": _float(commission, 2),
            "stamp_tax": _float(stamp_tax, 2),
            "transfer_fee": _float(transfer_fee, 2),
            "cost": _float(fees, 2),
            "slippage_cost": _float(slippage_cost, 2),
            "status": status,
            "fee_policy_id": self.cost_policy.policy_id,
        }
        self._record_order(order)
        self.fills.append(fill)
        retry_partial = bool(
            self.config.get(
                "retry_partial_orders",
                self.config.get("retry_blocked_orders", False),
            )
        )
        if status == "PARTIALLY_FILLED" and retry_partial:
            self.pending_orders[order_id] = order
        else:
            self.pending_orders.pop(order_id, None)
        self._event("ORDER_PARTIALLY_FILLED" if status == "PARTIALLY_FILLED" else "ORDER_FILLED", "order", order_id, fill)
        return order

    def apply_allocated_broker_fill(
        self,
        *,
        settlement_sha256: str,
        fill_allocation_sha256: str,
        allocation_plan_sha256: str,
        intent_id: str,
        strategy_id: str,
        signal_date: str,
        trade_date: str,
        code: str,
        side: str,
        requested_quantity: int,
        quantity: int,
        average_price: Any | None,
        fee_fen: int,
        settlement_status: str,
        recorded_on: str | None = None,
    ) -> dict[str, Any]:
        """Apply one frozen incremental broker allocation without re-simulating it."""

        hashes = {
            "settlement_sha256": str(settlement_sha256).lower(),
            "fill_allocation_sha256": str(fill_allocation_sha256).lower(),
            "allocation_plan_sha256": str(allocation_plan_sha256).lower(),
        }
        if any(not SHA256_RE.fullmatch(value) for value in hashes.values()):
            raise ValueError("allocated broker fill requires canonical sha256 bindings")
        intent_id = str(intent_id).strip()
        strategy_id = str(strategy_id).strip()
        code = str(code).strip()
        side = str(side).strip().lower()
        if not intent_id or not strategy_id or not code:
            raise ValueError("allocated broker fill identity is incomplete")
        if side not in {"buy", "sell"}:
            raise ValueError("allocated broker fill side is invalid")
        signal_day = _date(signal_date)
        trade_day = _date(trade_date)
        if self.trading_calendar is not None:
            self.trading_calendar.require_session(trade_day)
            if recorded_on is not None:
                recorded_day = self.trading_calendar.require_session(recorded_on)
                if recorded_day < trade_day:
                    raise TradingCalendarError(
                        "FILL_RECORDED_BEFORE_TRADE",
                        "fill record date predates its trade session",
                    )
                if recorded_day > trade_day:
                    raise TradingCalendarError(
                        "LATE_FILL_REQUIRES_SETTLEMENT_WATERMARK",
                        "late fill cannot auto-settle without an explicit watermark",
                    )
        if trade_day < signal_day:
            raise ValueError("allocated broker fill predates its signal")
        if isinstance(requested_quantity, bool) or not isinstance(
            requested_quantity, int
        ) or requested_quantity <= 0:
            raise ValueError("allocated broker requested quantity must be positive")
        if isinstance(quantity, bool) or not isinstance(quantity, int) or quantity < 0:
            raise ValueError("allocated broker fill quantity must be nonnegative")
        if isinstance(fee_fen, bool) or not isinstance(fee_fen, int) or fee_fen < 0:
            raise ValueError("allocated broker fee_fen must be nonnegative")
        if quantity == 0 and fee_fen == 0:
            raise ValueError("allocated broker increment cannot be empty")
        if quantity > 0:
            price = _decimal(average_price)
            if not price.is_finite() or price <= 0:
                raise ValueError("allocated broker average_price must be positive")
        elif average_price is not None:
            raise ValueError("fee-only broker increment cannot contain average_price")
        else:
            price = Decimal("0")
        normalized_status = str(settlement_status).strip().upper()
        if normalized_status not in {
            "PARTIALLY_FILLED",
            "FILLED",
            "CANCELLED",
        }:
            raise ValueError("allocated broker settlement status is unsupported")

        existing_source = [
            item
            for item in self.fills
            if item.get("source_settlement_sha256")
            == hashes["settlement_sha256"]
            and item.get("intent_id") == intent_id
        ]
        expected_source = {
            "source_settlement_sha256": hashes["settlement_sha256"],
            "source_fill_allocation_sha256": hashes["fill_allocation_sha256"],
            "source_allocation_plan_sha256": hashes["allocation_plan_sha256"],
            "intent_id": intent_id,
            "strategy_id": strategy_id,
            "date": trade_day.isoformat(),
            "code": code,
            "side": side,
            "quantity": quantity,
            "price": _float(price, 6) if quantity > 0 else None,
            "fee_fen": fee_fen,
        }
        if existing_source:
            if len(existing_source) != 1 or any(
                existing_source[0].get(field) != value
                for field, value in expected_source.items()
            ):
                raise RuntimeError(
                    "allocated broker settlement conflicts with existing ledger fill"
                )
            return {
                "schema": "quant-core/allocated-broker-fill-application/v1",
                "order_id": existing_source[0]["order_id"],
                "fill_id": existing_source[0]["id"],
                **hashes,
                "intent_id": intent_id,
                "strategy_id": strategy_id,
                "idempotent": True,
            }

        order_id = "broker-child-" + sha256_digest(
            {
                "allocation_plan_sha256": hashes["allocation_plan_sha256"],
                "intent_id": intent_id,
                "strategy_id": strategy_id,
            }
        )[:24]
        existing_order = next(
            (item for item in self.orders if item["id"] == order_id), None
        )
        if existing_order is not None:
            if (
                existing_order.get("intent_id") != intent_id
                or existing_order.get("strategy_id") != strategy_id
                or existing_order.get("code") != code
                or existing_order.get("side") != side
                or int(existing_order.get("requested_quantity") or 0)
                != requested_quantity
            ):
                raise RuntimeError(
                    "allocated broker order identity conflicts with ledger state"
                )
            filled_before = int(existing_order.get("filled_quantity") or 0)
        else:
            if quantity == 0:
                raise RuntimeError(
                    "fee-only broker allocation has no prior ledger fill"
                )
            filled_before = 0
            self._event(
                "BROKER_ALLOCATED_ORDER_CREATED",
                "order",
                order_id,
                {
                    "intent_id": intent_id,
                    "strategy_id": strategy_id,
                    "allocation_plan_sha256": hashes[
                        "allocation_plan_sha256"
                    ],
                },
            )
        total_filled = filled_before + quantity
        if total_filled > requested_quantity:
            raise RuntimeError("allocated broker fill exceeds child intent quantity")
        fee = Decimal(fee_fen) / Decimal("100")
        notional = price * quantity
        if side == "buy":
            cash_delta = -notional - fee
            if self.cash + cash_delta < 0:
                raise RuntimeError("allocated broker buy exceeds child ledger cash")
            if quantity > 0:
                self.lots.append(
                    PositionLot(
                        lot_id=(
                            "broker-lot-"
                            + hashes["settlement_sha256"][:16]
                            + "-"
                            + sha256_digest(intent_id)[:8]
                        ),
                        code=code,
                        quantity=quantity,
                        acquired_on=trade_day.isoformat(),
                        unit_cost=(notional + fee) / quantity,
                    )
                )
        else:
            if quantity > self.available_to_sell(code, trade_day.isoformat()):
                raise RuntimeError(
                    "allocated broker sell exceeds available child ledger position"
                )
            if quantity > 0:
                self._consume_lots(
                    code, quantity, trade_day.isoformat(), price, fee
                )
            cash_delta = notional - fee
        cash_delta = _money(cash_delta)
        self.cash = _money(self.cash + cash_delta)
        self._cash_movements.append(cash_delta)
        self._fee_movements.append(_money(fee))
        self.total_cost += fee
        self.turnover += notional
        if total_filled == requested_quantity:
            order_status = "FILLED"
        elif normalized_status == "CANCELLED":
            order_status = "CANCELLED"
        else:
            order_status = "PARTIALLY_FILLED"
        attempts = list((existing_order or {}).get("attempts") or [])
        attempts.append(
            {
                "date": trade_day.isoformat(),
                "status": order_status,
                "reason": "BROKER_ALLOCATED_FILL",
                "quantity": quantity,
                "fee_fen": fee_fen,
                "settlement_sha256": hashes["settlement_sha256"],
            }
        )
        order = {
            "id": order_id,
            "signal_date": signal_day.isoformat(),
            "date": trade_day.isoformat(),
            "side": side,
            "code": code,
            "name": self.names.get(code, code),
            "requested_quantity": requested_quantity,
            "filled_quantity": total_filled,
            "remaining_quantity": max(0, requested_quantity - total_filled),
            "status": order_status,
            "reject_reason": None,
            "attempts": attempts,
            "external_broker_allocation": True,
            "intent_id": intent_id,
            "strategy_id": strategy_id,
            "allocation_plan_sha256": hashes["allocation_plan_sha256"],
        }
        fill_id = (
            "broker-fill-"
            + hashes["settlement_sha256"][:16]
            + "-"
            + sha256_digest(intent_id)[:8]
        )
        fill = {
            "id": fill_id,
            "order_id": order_id,
            "signal_date": signal_day.isoformat(),
            "date": trade_day.isoformat(),
            "side": side,
            "code": code,
            "name": self.names.get(code, code),
            "quantity": quantity,
            "price": _float(price, 6) if quantity > 0 else None,
            "reference_price": None,
            "notional": _float(notional, 6),
            "commission": 0.0,
            "stamp_tax": 0.0,
            "transfer_fee": 0.0,
            "cost": _float(fee, 2),
            "fee_fen": fee_fen,
            "fee_classification": "BROKER_TOTAL_UNCLASSIFIED",
            "slippage_cost": 0.0,
            "status": order_status,
            "fee_policy_id": "broker-allocated-unclassified/v1",
            "external_broker_allocation": True,
            **expected_source,
        }
        self._record_order(order)
        self.fills.append(fill)
        self._event(
            "BROKER_ALLOCATED_FILL_APPLIED",
            "order",
            order_id,
            fill,
        )
        return {
            "schema": "quant-core/allocated-broker-fill-application/v1",
            "order_id": order_id,
            "fill_id": fill_id,
            **hashes,
            "intent_id": intent_id,
            "strategy_id": strategy_id,
            "idempotent": False,
        }

    def retry_pending(
        self,
        trade_date: str,
        bars: dict[str, dict[str, Any] | None],
        open_marks: dict[str, float],
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for pending in list(self.pending_orders.values()):
            remaining = int(pending["requested_quantity"]) - int(pending["filled_quantity"])
            if remaining <= 0:
                self.pending_orders.pop(str(pending["id"]), None)
                continue
            results.append(self.submit_and_fill(
                signal_date=str(pending["signal_date"]),
                trade_date=trade_date,
                code=str(pending["code"]),
                side=str(pending["side"]),
                requested_quantity=remaining,
                bar=bars.get(str(pending["code"])),
                open_marks=open_marks,
                _order_id=str(pending["id"]),
                _original_quantity=int(pending["requested_quantity"]),
                _filled_before=int(pending["filled_quantity"]),
            ))
        return results

    def cancel_order(self, order_id: str, reason: str, trade_date: str) -> dict[str, Any] | None:
        pending = self.pending_orders.pop(order_id, None)
        if pending is None:
            return None
        order = {
            **pending,
            "date": trade_date,
            "status": "CANCELLED",
            "reject_reason": reason,
            "attempts": [
                *list(pending.get("attempts") or []),
                {"date": trade_date, "status": "CANCELLED", "reason": reason},
            ],
        }
        self._record_order(order)
        self._event("ORDER_CANCELLED", "order", order_id, {"reason": reason})
        return order

    def rebalance(
        self,
        *,
        signal_date: str,
        trade_date: str,
        target_codes: list[str],
        bars: dict[str, dict[str, Any] | None],
        valuation_marks: dict[str, float] | None = None,
        target_weights: dict[str, float] | None = None,
    ) -> dict[str, Any]:
        before_cost = self.total_cost
        before_turnover = self.turnover
        open_marks = valuation_marks or {
            code: float(bar["open"])
            for code, bar in bars.items()
            if bar is not None and bar.get("open") is not None
        }
        open_equity = self.equity(open_marks)
        if target_weights is not None:
            if set(target_weights) != set(target_codes):
                raise ValueError("target_weights must exactly match target_codes")
            normalized_weights = {code: _decimal(target_weights[code]) for code in target_codes}
            if any(weight <= 0 for weight in normalized_weights.values()):
                raise ValueError("target weights must be positive")
            total_target_weight = sum(normalized_weights.values(), Decimal("0"))
            if total_target_weight > Decimal("1.000000000001"):
                raise ValueError("target weights cannot exceed 100% gross exposure")
            if total_target_weight > Decimal("1"):
                normalized_weights = {
                    code: weight / total_target_weight
                    for code, weight in normalized_weights.items()
                }
        else:
            equal_weight = Decimal("1") / len(target_codes) if target_codes else Decimal("0")
            normalized_weights = {code: equal_weight for code in target_codes}
        target_quantities: dict[str, int] = {}
        for code in target_codes:
            bar = bars.get(code)
            if not bar:
                target_quantities[code] = self.position_quantities.get(code, 0)
                if target_quantities[code] == 0:
                    order_id = self._next_id(trade_date, "buy", code)
                    self._event(
                        "ORDER_CREATED", "order", order_id,
                        {"code": code, "side": "buy", "requested_quantity": 0, "signal_date": signal_date},
                    )
                    self._reject(
                        order_id=order_id, signal_date=signal_date, trade_date=trade_date,
                        code=code, side="buy", quantity=0, reason="TARGET_ASSET_UNAVAILABLE",
                    )
                continue
            target_value = open_equity * normalized_weights[code]
            estimated_price = self.cost_policy.execution_price("buy", _decimal(bar["open"]))
            raw_quantity = int((target_value / estimated_price).to_integral_value(rounding=ROUND_FLOOR))
            target_quantities[code] = self._normalized_buy_quantity(code, raw_quantity)

        for code in sorted(set(self.position_quantities) | set(target_quantities)):
            current = self.position_quantities.get(code, 0)
            target = target_quantities.get(code, 0)
            if current > target:
                self.submit_and_fill(
                    signal_date=signal_date, trade_date=trade_date, code=code, side="sell",
                    requested_quantity=current - target, bar=bars.get(code), open_marks=open_marks,
                )
        for code in target_codes:
            desired = max(0, target_quantities.get(code, 0) - self.position_quantities.get(code, 0))
            if desired:
                self.submit_and_fill(
                    signal_date=signal_date, trade_date=trade_date, code=code, side="buy",
                    requested_quantity=desired, bar=bars.get(code), open_marks=open_marks,
                )
        return {
            "cost": _float(self.total_cost - before_cost, 2),
            "turnover": _float(self.turnover - before_turnover, 2),
        }

    def reconcile(
        self,
        trade_date: str,
        marks: dict[str, float] | None = None,
        *,
        data_integrity_ok: bool = True,
    ) -> dict[str, Any]:
        self._legacy_snapshot = None
        expected_cash = self.initial_cash + sum(self._cash_movements, Decimal("0"))
        expected_positions: dict[str, int] = {}
        # Rebuild from source history on every audit so later mutations remain
        # detectable. Group once instead of rescanning every list for each day;
        # retain both the within-list order and split -> fill -> terminal order.
        events_by_date = defaultdict(lambda: ([], [], []))
        for phase, history in enumerate((self.corporate_actions, self.fills, self.terminal_events)):
            for item in history:
                events_by_date[str(item["date"])][phase].append(item)
        for event_date in sorted(events_by_date):
            actions, fills, terminals = events_by_date[event_date]
            for action in actions:
                code = str(action["code"])
                expected_positions[code] = int(
                    _decimal(expected_positions.get(code, 0)) * _decimal(action["ratio"])
                )
            for fill in fills:
                quantity = int(fill["quantity"])
                direction = 1 if fill["side"] == "buy" else -1
                expected_positions[fill["code"]] = expected_positions.get(fill["code"], 0) + direction * quantity
            for terminal in terminals:
                code = str(terminal["code"])
                expected_positions[code] = expected_positions.get(code, 0) - int(
                    terminal["quantity"]
                )
        expected_positions = {code: quantity for code, quantity in expected_positions.items() if quantity}
        cash_difference = _money(self.cash - expected_cash)
        position_ok = expected_positions == self.position_quantities
        fees_ok = abs(sum(self._fee_movements, Decimal("0")) - self.total_cost) <= Decimal("0.000001")
        report = {
            "date": trade_date,
            "ok": abs(cash_difference) <= Decimal("0.02") and position_ok and fees_ok and self.cash >= 0,
            "cash_ok": abs(cash_difference) <= Decimal("0.02"),
            "positions_ok": position_ok,
            "fees_ok": fees_ok,
            "nonnegative_cash_ok": self.cash >= 0,
            "cash_difference": _float(cash_difference, 6),
            "order_count": len(self.orders),
            "fill_count": len(self.fills),
        }
        if self.portfolio_risk is not None:
            risk_assessment = None
            risk_equity: Decimal | None = None
            if marks is not None:
                risk_equity = self.equity(marks)
                risk_assessment = self.portfolio_risk.assess(
                    equity=risk_equity,
                    cash=self.cash,
                    positions=self.position_quantities,
                    marks=marks,
                )
            risk_event = self.portfolio_risk.observe_session(
                trade_date=trade_date,
                equity=risk_equity,
                reconciliation_ok=bool(report["ok"]),
                data_integrity_ok=data_integrity_ok,
            )
            report["portfolio_risk_compliant"] = (
                risk_assessment["compliant"] if risk_assessment is not None else None
            )
            report["portfolio_risk_mode"] = risk_event["mode"]
            if risk_event["reasons"]:
                self._event("PORTFOLIO_RISK_STATE_CHANGED", "account", "paper", risk_event)
        self.reconciliations.append(report)
        if not report["ok"]:
            self._event("RECONCILIATION_FAILED", "account", "paper", report)
        return report

    def terminal_valuation(
        self,
        trade_date: str,
        marks: dict[str, float],
    ) -> TerminalValuation:
        market_equity = self.equity(marks)
        liquidation_cost = Decimal("0")
        for code, quantity in self.position_quantities.items():
            reference_price = _decimal(marks[code])
            execution_price = self.cost_policy.execution_price("sell", reference_price)
            costs = self.cost_policy.cost_breakdown("sell", execution_price, quantity, trade_date)
            slippage = abs(reference_price - execution_price) * quantity
            liquidation_cost += costs.cash_fees + slippage
        liquidation_cost = _money(liquidation_cost)
        return TerminalValuation(
            market_value_equity=_float(market_equity, 2),
            hypothetical_liquidation_equity=_float(market_equity - liquidation_cost, 2),
            hypothetical_liquidation_cost=_float(liquidation_cost, 2),
        )

    def report(self) -> dict[str, Any]:
        rejected = [order for order in self.orders if order["status"] == "REJECTED"]
        partial = [order for order in self.orders if order["status"] == "PARTIALLY_FILLED"]
        cancelled = [order for order in self.orders if order["status"] == "CANCELLED"]
        failures = [item for item in self.reconciliations if not item["ok"]]
        report = {
            "schema": EXECUTION_SCHEMA,
            "fee_policy": self.cost_policy.evidence(),
            "exchange_rules": self.exchange_rules.evidence() if self.exchange_rules else None,
            "portfolio_risk": self.portfolio_risk.report() if self.portfolio_risk else None,
            "trading_calendar": (
                self.trading_calendar.evidence()
                if self.trading_calendar is not None
                else None
            ),
            "summary": {
                "order_count": len(self.orders),
                "fill_count": len(self.fills),
                "rejected_order_count": len(rejected),
                "partial_fill_count": len(partial),
                "pending_order_count": len(self.pending_orders),
                "cancelled_order_count": len(cancelled),
                "total_cost": _float(self.total_cost, 2),
                "commission": _float(self.total_commission, 2),
                "stamp_tax": _float(self.total_stamp_tax, 2),
                "transfer_fee": _float(self.total_transfer_fee, 2),
                "unclassified_broker_fee": _float(
                    self.total_cost
                    - self.total_commission
                    - self.total_stamp_tax
                    - self.total_transfer_fee,
                    2,
                ),
                "slippage_cost": _float(self.total_slippage, 2),
                "estimated_total_trading_cost": _float(self.total_cost + self.total_slippage, 2),
                "turnover": _float(self.turnover, 2),
                "realized_pnl": _float(self.realized_pnl, 2),
                "cash_distributions": _float(self.total_cash_distributions, 2),
                "terminal_recoveries": _float(self.total_terminal_recoveries, 2),
                "terminal_write_off_cost_basis": _float(
                    self.total_terminal_write_off_cost_basis, 2
                ),
                "terminal_event_count": len(self.terminal_events),
                "reconciliation_days": len(self.reconciliations),
                "reconciliation_failures": len(failures),
            },
            "orders": self.orders,
            "rejections": rejected,
            "pending_orders": list(self.pending_orders.values()),
            "cancelled_orders": cancelled,
            "cash_distribution_events": self.cash_distributions,
            "corporate_actions": self.corporate_actions,
            "terminal_events": self.terminal_events,
            "events": self.events,
            "latest_reconciliation": self.reconciliations[-1] if self.reconciliations else None,
            "reconciliation_failures": failures,
        }
        return deepcopy(report)

    def snapshot(self) -> dict[str, Any]:
        """Return a deterministic, complete restart snapshot of the paper ledger."""
        if self._legacy_snapshot is not None:
            return deepcopy(self._legacy_snapshot)
        identity = {
            "schema": EXECUTION_SNAPSHOT_SCHEMA,
            "initial_cash": str(self.initial_cash),
            "cash": str(self.cash),
            "config": self.config,
            "names": self.names,
            "lots": [
                {
                    "lot_id": lot.lot_id,
                    "code": lot.code,
                    "quantity": lot.quantity,
                    "acquired_on": lot.acquired_on,
                    "unit_cost": str(lot.unit_cost),
                }
                for lot in self.lots
            ],
            "orders": self.orders,
            "pending_orders": self.pending_orders,
            "fills": self.fills,
            "events": self.events,
            "reconciliations": self.reconciliations,
            "totals": {
                "total_cost": str(self.total_cost),
                "total_commission": str(self.total_commission),
                "total_stamp_tax": str(self.total_stamp_tax),
                "total_transfer_fee": str(self.total_transfer_fee),
                "turnover": str(self.turnover),
                "realized_pnl": str(self.realized_pnl),
                "total_slippage": str(self.total_slippage),
                "total_cash_distributions": str(self.total_cash_distributions),
                "total_terminal_recoveries": str(self.total_terminal_recoveries),
                "total_terminal_write_off_cost_basis": str(
                    self.total_terminal_write_off_cost_basis
                ),
            },
            "cash_distributions": self.cash_distributions,
            "corporate_actions": self.corporate_actions,
            "terminal_events": self.terminal_events,
            "cash_movements": [str(item) for item in self._cash_movements],
            "fee_movements": [str(item) for item in self._fee_movements],
            "sequence": self._sequence,
            "portfolio_risk_state": (
                {
                    "peak_equity": str(self.portfolio_risk.peak_equity),
                    "mode": self.portfolio_risk.mode,
                    "halted": self.portfolio_risk.halted,
                    "halt_reasons": self.portfolio_risk.halt_reasons,
                    "events": self.portfolio_risk.events,
                    "latest_assessment": self.portfolio_risk.latest_assessment,
                }
                if self.portfolio_risk else None
            ),
        }
        identity = deepcopy(identity)
        return {**identity, "snapshot_sha256": sha256_digest(identity)}

    @classmethod
    def from_snapshot(cls, snapshot: dict[str, Any]) -> "SimulationLedger":
        """Restore only a self-consistent snapshot; unknown/missing state fails closed."""
        snapshot_schema = snapshot.get("schema")
        if snapshot_schema not in {
            EXECUTION_SNAPSHOT_SCHEMA,
            LEGACY_EXECUTION_SNAPSHOT_SCHEMA,
        }:
            raise ValueError("unsupported execution snapshot schema")
        expected = str(snapshot.get("snapshot_sha256") or "")
        identity = {key: value for key, value in snapshot.items() if key != "snapshot_sha256"}
        if not expected or sha256_digest(identity) != expected:
            raise ValueError("execution snapshot hash mismatch")
        ledger = cls(float(snapshot["initial_cash"]), dict(snapshot["config"]), dict(snapshot["names"]))
        ledger.initial_cash = _decimal(snapshot["initial_cash"])
        ledger.cash = _decimal(snapshot["cash"])
        ledger.lots = [
            PositionLot(
                lot_id=str(item["lot_id"]),
                code=str(item["code"]),
                quantity=int(item["quantity"]),
                acquired_on=str(item["acquired_on"]),
                unit_cost=_decimal(item["unit_cost"]),
            )
            for item in list(snapshot.get("lots") or [])
        ]
        ledger.orders = [dict(item) for item in list(snapshot.get("orders") or [])]
        ledger.pending_orders = {
            str(key): dict(value) for key, value in dict(snapshot.get("pending_orders") or {}).items()
        }
        ledger.fills = [dict(item) for item in list(snapshot.get("fills") or [])]
        ledger.events = [dict(item) for item in list(snapshot.get("events") or [])]
        ledger.reconciliations = [dict(item) for item in list(snapshot.get("reconciliations") or [])]
        totals = dict(snapshot.get("totals") or {})
        for field in (
            "total_cost", "total_commission", "total_stamp_tax", "total_transfer_fee",
            "turnover", "realized_pnl", "total_slippage", "total_cash_distributions",
        ):
            if field not in totals:
                raise ValueError(f"execution snapshot missing total: {field}")
            setattr(ledger, field, _decimal(totals[field]))
        for field in (
            "total_terminal_recoveries",
            "total_terminal_write_off_cost_basis",
        ):
            setattr(ledger, field, _decimal(totals.get(field, "0")))
        ledger._cash_movements = [_decimal(item) for item in list(snapshot.get("cash_movements") or [])]
        ledger.cash_distributions = [dict(item) for item in list(snapshot.get("cash_distributions") or [])]
        ledger.corporate_actions = [dict(item) for item in list(snapshot.get("corporate_actions") or [])]
        ledger.terminal_events = [
            dict(item) for item in list(snapshot.get("terminal_events") or [])
        ]
        ledger._fee_movements = [_decimal(item) for item in list(snapshot.get("fee_movements") or [])]
        ledger._sequence = int(snapshot.get("sequence") or 0)
        risk_state = snapshot.get("portfolio_risk_state")
        if risk_state is not None:
            if ledger.portfolio_risk is None:
                raise ValueError("snapshot has portfolio risk state but config has no risk policy")
            ledger.portfolio_risk.peak_equity = _decimal(risk_state["peak_equity"])
            ledger.portfolio_risk.mode = str(risk_state["mode"])
            ledger.portfolio_risk.halted = bool(risk_state["halted"])
            ledger.portfolio_risk.halt_reasons = [str(item) for item in risk_state.get("halt_reasons") or []]
            ledger.portfolio_risk.events = [dict(item) for item in risk_state.get("events") or []]
            ledger.portfolio_risk.latest_assessment = (
                dict(risk_state["latest_assessment"])
                if risk_state.get("latest_assessment") is not None else None
            )
        elif ledger.portfolio_risk is not None:
            raise ValueError("risk-enabled config is missing portfolio risk state")
        if snapshot_schema == LEGACY_EXECUTION_SNAPSHOT_SCHEMA:
            ledger._legacy_snapshot = deepcopy(snapshot)
        restored_snapshot = ledger.snapshot()
        if (
            snapshot_schema == EXECUTION_SNAPSHOT_SCHEMA
            and restored_snapshot.get("snapshot_sha256") != expected
        ):
            raise ValueError("restored execution snapshot differs from committed state")
        return ledger
