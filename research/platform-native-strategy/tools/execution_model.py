from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
import json
import math
from pathlib import Path
from typing import Any, Iterable


EXECUTION_MODEL_VERSION = "platform-native-research-execution/v2"


class OrderSide(str, Enum):
    BUY = "buy"
    SELL = "sell"


class OrderStatus(str, Enum):
    PENDING = "pending"
    FILLED = "filled"
    PARTIALLY_FILLED = "partially_filled"
    REJECTED = "rejected"
    SUSPENDED = "suspended"
    LIMIT_LOCKED = "limit_locked"
    CANCELLED = "cancelled"


RETRYABLE_ORDER_STATUSES = {
    OrderStatus.PENDING,
    OrderStatus.PARTIALLY_FILLED,
    OrderStatus.SUSPENDED,
    OrderStatus.LIMIT_LOCKED,
}


@dataclass(frozen=True)
class MarketBar:
    open: float
    high: float
    low: float
    close: float
    preclose: float
    tradestatus: int = 1
    is_st: bool = False
    listing_date: date | None = None
    trading_days_since_listing: int | None = None
    available_quantity: int | None = None
    unsupported_corporate_action: bool = False


@dataclass
class Position:
    code: str
    quantity: int
    average_cost: float
    last_price: float
    t1_locked_quantity: int = 0
    t1_locked_on: date | None = None

    @property
    def market_value(self) -> float:
        return self.quantity * self.last_price

    def sellable_quantity(self, day: date) -> int:
        locked = (
            max(0, min(int(self.t1_locked_quantity), int(self.quantity)))
            if self.t1_locked_on == day
            else 0
        )
        return max(0, int(self.quantity) - locked)


@dataclass
class Order:
    order_id: str
    code: str
    side: OrderSide
    quantity: int
    created_at: date
    status: OrderStatus = OrderStatus.PENDING
    filled_quantity: int = 0
    reason: str = ""
    attempts: list[dict[str, Any]] = field(default_factory=list)

    @property
    def remaining_quantity(self) -> int:
        return max(0, self.quantity - self.filled_quantity)


@dataclass(frozen=True)
class CostBreakdown:
    commission: float
    stamp_tax: float
    transfer_fee: float
    slippage: float

    @property
    def cash_fees(self) -> float:
        return self.commission + self.stamp_tax + self.transfer_fee

    @property
    def total(self) -> float:
        return self.cash_fees + self.slippage

    def as_dict(self) -> dict[str, float]:
        return {
            "commission": self.commission,
            "stamp_tax": self.stamp_tax,
            "transfer_fee": self.transfer_fee,
            "slippage": self.slippage,
            "total": self.total,
        }


@dataclass(frozen=True)
class Fill:
    fill_id: str
    order_id: str
    code: str
    side: OrderSide
    quantity: int
    trade_date: date
    reference_price: float
    execution_price: float
    notional: float
    costs: CostBreakdown


@dataclass(frozen=True)
class ExecutionResult:
    order_id: str
    status: OrderStatus
    reason: str
    fill: Fill | None = None


@dataclass(frozen=True)
class TerminalValuation:
    market_value_equity: float
    hypothetical_liquidation_equity: float
    hypothetical_liquidation_cost: float


@dataclass(frozen=True)
class DatedRate:
    effective_date: date
    rate: float


@dataclass(frozen=True)
class CostModel:
    version: str
    commission_rate: float
    minimum_commission: float
    slippage_rate: float
    stamp_tax_schedule: tuple[DatedRate, ...]
    transfer_fee_schedule: tuple[DatedRate, ...]

    @classmethod
    def default(cls) -> "CostModel":
        return cls.from_json(
            Path(__file__).resolve().parent.parent
            / "configs" / "trading" / "cost-model-v1.json"
        )

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CostModel":
        required = {
            "version", "commission_rate", "minimum_commission", "slippage_rate",
            "stamp_tax_schedule", "transfer_fee_schedule",
        }
        missing = required - set(payload)
        unknown = set(payload) - required
        if missing or unknown:
            raise ValueError(
                f"Invalid cost model keys; missing={sorted(missing)}, unknown={sorted(unknown)}"
            )

        def schedule(name: str) -> tuple[DatedRate, ...]:
            raw = payload[name]
            if not isinstance(raw, list) or not raw:
                raise ValueError(f"{name} must be a non-empty list")
            values = tuple(
                DatedRate(date.fromisoformat(str(item["effective_date"])), float(item["rate"]))
                for item in raw
            )
            if tuple(sorted(values, key=lambda item: item.effective_date)) != values:
                raise ValueError(f"{name} must be sorted by effective_date")
            if any(item.rate < 0 for item in values):
                raise ValueError(f"{name} contains a negative rate")
            return values

        model = cls(
            version=str(payload["version"]),
            commission_rate=float(payload["commission_rate"]),
            minimum_commission=float(payload["minimum_commission"]),
            slippage_rate=float(payload["slippage_rate"]),
            stamp_tax_schedule=schedule("stamp_tax_schedule"),
            transfer_fee_schedule=schedule("transfer_fee_schedule"),
        )
        if not model.version or min(
            model.commission_rate, model.minimum_commission, model.slippage_rate,
        ) < 0:
            raise ValueError("Cost model rates and version must be valid")
        return model

    @classmethod
    def from_json(cls, path: str | Path) -> "CostModel":
        with Path(path).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError("Cost model JSON must contain an object")
        return cls.from_dict(payload)

    @staticmethod
    def _rate_for(day: date, schedule: tuple[DatedRate, ...]) -> float:
        eligible = [item.rate for item in schedule if item.effective_date <= day]
        if not eligible:
            raise ValueError(f"No fee rate is configured for {day.isoformat()}")
        return eligible[-1]

    def calculate(self, side: OrderSide, reference_notional: float, day: date) -> CostBreakdown:
        notional = max(0.0, float(reference_notional))
        commission = max(notional * self.commission_rate, self.minimum_commission) if notional else 0.0
        stamp_tax = (
            notional * self._rate_for(day, self.stamp_tax_schedule)
            if side == OrderSide.SELL else 0.0
        )
        transfer_fee = notional * self._rate_for(day, self.transfer_fee_schedule)
        slippage = notional * self.slippage_rate
        return CostBreakdown(commission, stamp_tax, transfer_fee, slippage)

    def execution_price(self, side: OrderSide, reference_price: float) -> float:
        multiplier = 1 + self.slippage_rate if side == OrderSide.BUY else 1 - self.slippage_rate
        return float(reference_price) * multiplier


class PriceLimitRules:
    def __init__(self, payload: dict[str, Any] | None = None):
        configured = payload or self._load_default_payload()
        self.version = str(configured["version"])
        self.price_limits = dict(configured["price_limits"])
        self.no_initial_limit = dict(configured["no_initial_limit"])

    @staticmethod
    def _default_path() -> Path:
        return Path(__file__).resolve().parent.parent / "configs" / "trading" / "exchange-rules-v1.json"

    @classmethod
    def _load_default_payload(cls) -> dict[str, Any]:
        with cls._default_path().open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError("Exchange rules JSON must contain an object")
        return payload

    @classmethod
    def default(cls) -> "PriceLimitRules":
        return cls(cls._load_default_payload())

    @classmethod
    def from_json(cls, path: str | Path) -> "PriceLimitRules":
        with Path(path).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError("Exchange rules JSON must contain an object")
        return cls(payload)

    @staticmethod
    def board(code: str) -> str:
        normalized = str(code).lower()
        digits = normalized.split(".")[-1]
        if digits.startswith(("688", "689")):
            return "star"
        if digits.startswith(("300", "301", "302")):
            return "chinext"
        if normalized.startswith("bj.") or digits.startswith(("4", "8", "920")):
            return "beijing"
        return "main"

    @staticmethod
    def _scheduled_rate(day: date, schedule: list[dict[str, Any]]) -> float:
        eligible = [
            float(item["rate"])
            for item in schedule
            if date.fromisoformat(str(item["effective_date"])) <= day
        ]
        if not eligible:
            raise ValueError(f"No price-limit rule is configured for {day.isoformat()}")
        return eligible[-1]

    def _has_no_initial_limit(
        self, board: str, day: date, trading_days_since_listing: int | None,
    ) -> bool:
        rule = self.no_initial_limit.get(board)
        if rule is None or trading_days_since_listing is None:
            return False
        effective = date.fromisoformat(str(rule["effective_date"]))
        return day >= effective and trading_days_since_listing <= int(rule["trading_days"])

    def limit_rate(
        self,
        code: str,
        day: date,
        is_st: bool,
        listing_date: date | None = None,
        trading_days_since_listing: int | None = None,
    ) -> float | None:
        del listing_date
        board = self.board(code)
        if self._has_no_initial_limit(board, day, trading_days_since_listing):
            return None
        rules = dict(self.price_limits[board])
        schedule = rules.get("st" if is_st else "normal") or rules["normal"]
        return self._scheduled_rate(day, list(schedule))

    @staticmethod
    def _limit_price(preclose: float, rate: float, direction: int) -> float:
        raw = Decimal(str(preclose)) * (
            Decimal("1") + Decimal(direction) * Decimal(str(rate))
        )
        return float(raw.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))

    def is_locked(self, side: OrderSide, code: str, day: date, bar: MarketBar) -> bool:
        rate = self.limit_rate(
            code, day, bar.is_st, bar.listing_date, bar.trading_days_since_listing,
        )
        if rate is None or bar.preclose <= 0:
            return False
        direction = 1 if side == OrderSide.BUY else -1
        limit_price = self._limit_price(bar.preclose, rate, direction)
        if side == OrderSide.BUY:
            return bar.open >= limit_price - 0.000001
        return bar.open <= limit_price + 0.000001


class SecurityRules:
    def __init__(
        self,
        price_limits: PriceLimitRules | None = None,
        lot_rules: dict[str, dict[str, int]] | None = None,
    ):
        self.price_limits = price_limits or PriceLimitRules.default()
        payload = PriceLimitRules._load_default_payload()
        self.lot_rules = lot_rules or dict(payload["lot_rules"])

    @classmethod
    def default(cls) -> "SecurityRules":
        return cls.from_json(PriceLimitRules._default_path())

    @classmethod
    def from_json(cls, path: str | Path) -> "SecurityRules":
        with Path(path).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError("Exchange rules JSON must contain an object")
        lots = {
            str(board): {"minimum": int(rule["minimum"]), "increment": int(rule["increment"])}
            for board, rule in dict(payload["lot_rules"]).items()
        }
        return cls(PriceLimitRules(payload), lots)

    def _normalized_quantity(self, code: str, desired_quantity: float) -> int:
        quantity = max(0, int(desired_quantity))
        rule = self.lot_rules[self.price_limits.board(code)]
        minimum = int(rule["minimum"])
        increment = int(rule["increment"])
        if quantity < minimum:
            return 0
        return minimum + ((quantity - minimum) // increment) * increment

    def buy_quantity(self, code: str, desired_quantity: float) -> int:
        return self._normalized_quantity(code, desired_quantity)

    def valid_sell_quantity(self, code: str, desired: int, held: int) -> int:
        quantity = max(0, min(int(desired), int(held)))
        if quantity == held:
            return quantity
        return self._normalized_quantity(code, quantity)


def next_trading_day(signal_day: date, trading_days: Iterable[date]) -> date:
    later = sorted(day for day in trading_days if day > signal_day)
    if not later:
        raise ValueError(f"No trading day exists after {signal_day.isoformat()}")
    return later[0]


class Portfolio:
    def __init__(
        self,
        cash: float,
        positions: dict[str, Position] | None = None,
        cost_model: CostModel | None = None,
        security_rules: SecurityRules | None = None,
        max_positions: int | None = None,
        max_position_pct: float | None = None,
    ):
        self.cash = float(cash)
        self.positions = dict(positions or {})
        self.cost_model = cost_model or CostModel.default()
        self.security_rules = security_rules or SecurityRules.default()
        self.max_positions = int(max_positions) if max_positions is not None else None
        self.max_position_pct = (
            float(max_position_pct) if max_position_pct is not None else None
        )
        if self.max_positions is not None and self.max_positions <= 0:
            raise ValueError("max_positions must be positive")
        if self.max_position_pct is not None and not (
            0 < self.max_position_pct <= 1
        ):
            raise ValueError("max_position_pct must be in (0, 1]")
        self.pending_orders: dict[str, Order] = {}
        self.fills: list[Fill] = []
        self.events: list[dict[str, Any]] = []
        self.reconciliations: list[dict[str, Any]] = []
        self._opening_cash = float(cash)
        self._opening_quantities = {
            str(code): int(position.quantity)
            for code, position in self.positions.items()
        }

    def apply_cash_distribution(
        self, code: str, amount_per_share: float, day: date,
    ) -> dict[str, Any] | None:
        """Credit an ETF distribution before the session open.

        The forward adapters use raw prices for execution and valuation, so a
        distribution must be represented as cash instead of disappearing at
        the ex-date price gap.
        """

        position = self.positions.get(str(code))
        amount = float(amount_per_share)
        if position is None or position.quantity <= 0:
            return None
        if not math.isfinite(amount) or amount <= 0:
            raise ValueError("cash distribution per share must be positive and finite")
        cash_amount = position.quantity * amount
        self.cash += cash_amount
        event = {
            "event_type": "cash_distribution_applied",
            "code": str(code),
            "date": day.isoformat(),
            "quantity": int(position.quantity),
            "amount_per_share": amount,
            "cash_amount": cash_amount,
        }
        self.events.append(event)
        return event

    def apply_split(self, code: str, ratio: float, day: date) -> dict[str, Any] | None:
        """Apply an integral ETF unit split without manufacturing P&L."""

        position = self.positions.get(str(code))
        split_ratio = float(ratio)
        if position is None or position.quantity <= 0:
            return None
        if not math.isfinite(split_ratio) or split_ratio <= 0:
            raise ValueError("split ratio must be positive and finite")
        adjusted = position.quantity * split_ratio
        adjusted_quantity = int(round(adjusted))
        if abs(adjusted - adjusted_quantity) > 0.000001 or adjusted_quantity <= 0:
            raise ValueError("split creates unsupported fractional ETF units")
        before_quantity = int(position.quantity)
        position.quantity = adjusted_quantity
        position.average_cost /= split_ratio
        if position.t1_locked_on == day and position.t1_locked_quantity:
            adjusted_locked = position.t1_locked_quantity * split_ratio
            rounded_locked = int(round(adjusted_locked))
            if abs(adjusted_locked - rounded_locked) > 0.000001:
                raise ValueError("split creates unsupported fractional T+1 quantity")
            position.t1_locked_quantity = rounded_locked
        event = {
            "event_type": "unit_split_applied",
            "code": str(code),
            "date": day.isoformat(),
            "ratio": split_ratio,
            "before_quantity": before_quantity,
            "after_quantity": adjusted_quantity,
        }
        self.events.append(event)
        return event

    def affordable_buy_quantity(
        self, code: str, reference_price: float, day: date, budget: float,
    ) -> int:
        if reference_price <= 0 or budget <= 0:
            return 0
        execution_price = self.cost_model.execution_price(OrderSide.BUY, reference_price)
        quantity = self.security_rules.buy_quantity(code, budget / execution_price)
        quantity = min(
            quantity,
            self._risk_buy_quantity(code, execution_price),
        )
        board = self.security_rules.price_limits.board(code)
        step = 1 if board in {"star", "beijing"} else 100
        while quantity > 0:
            costs = self.cost_model.calculate(OrderSide.BUY, reference_price * quantity, day)
            if execution_price * quantity + costs.cash_fees <= budget + 0.000001:
                return quantity
            quantity = self.security_rules.buy_quantity(code, quantity - step)
        return 0

    def _risk_buy_quantity(self, code: str, execution_price: float) -> int:
        if execution_price <= 0 or not math.isfinite(execution_price):
            return 0
        current = self.positions.get(str(code))
        if (
            current is None
            and self.max_positions is not None
            and len(self.positions) >= self.max_positions
        ):
            return 0
        if self.max_position_pct is None:
            return 2**31 - 1
        equity = self.cash + sum(
            position.quantity
            * (execution_price if position.code == str(code) else position.last_price)
            for position in self.positions.values()
        )
        if not math.isfinite(equity) or equity <= 0:
            return 0
        current_quantity = current.quantity if current is not None else 0
        maximum_value = equity * self.max_position_pct
        available_value = maximum_value - current_quantity * execution_price
        return self.security_rules.buy_quantity(
            str(code), max(0.0, available_value) / execution_price
        )

    def _event(self, order: Order, day: date, **extra: Any) -> None:
        self.events.append({
            "order_id": order.order_id,
            "code": order.code,
            "date": day.isoformat(),
            "status": order.status.value,
            "reason": order.reason,
            **extra,
        })

    def cancel_order(self, order_id: str, reason: str, day: date) -> ExecutionResult | None:
        order = self.pending_orders.pop(order_id, None)
        if order is None:
            return None
        order.status = OrderStatus.CANCELLED
        order.reason = reason
        order.attempts.append({"date": day.isoformat(), "status": order.status.value, "reason": reason})
        self._event(order, day)
        return ExecutionResult(order.order_id, order.status, reason)

    def _blocked(
        self, order: Order, status: OrderStatus, reason: str, day: date,
    ) -> ExecutionResult:
        order.status = status
        order.reason = reason
        order.attempts.append({"date": day.isoformat(), "status": status.value, "reason": reason})
        self.pending_orders[order.order_id] = order
        self._event(order, day)
        return ExecutionResult(order.order_id, status, reason)

    def _rejected(self, order: Order, reason: str, day: date) -> ExecutionResult:
        order.status = OrderStatus.REJECTED
        order.reason = reason
        order.attempts.append({"date": day.isoformat(), "status": order.status.value, "reason": reason})
        self.pending_orders.pop(order.order_id, None)
        self._event(order, day)
        return ExecutionResult(order.order_id, order.status, reason)

    def process_order(self, order: Order, bar: MarketBar | None, day: date) -> ExecutionResult:
        if order.status == OrderStatus.CANCELLED:
            return ExecutionResult(order.order_id, order.status, order.reason)
        if bar is None:
            return self._blocked(order, OrderStatus.PENDING, "missing_market_data", day)
        if bar.unsupported_corporate_action:
            return self._blocked(order, OrderStatus.PENDING, "unsupported_corporate_action", day)
        if bar.tradestatus != 1:
            return self._blocked(order, OrderStatus.SUSPENDED, "suspended", day)
        if self.security_rules.price_limits.is_locked(order.side, order.code, day, bar):
            reason = "limit_up_locked" if order.side == OrderSide.BUY else "limit_down_locked"
            return self._blocked(order, OrderStatus.LIMIT_LOCKED, reason, day)

        remaining = order.remaining_quantity
        if remaining <= 0:
            return self._rejected(order, "empty_order", day)
        if order.side == OrderSide.BUY:
            executable = self.security_rules.buy_quantity(order.code, remaining)
            if executable <= 0:
                return self._rejected(order, "invalid_buy_lot", day)
            if (
                order.code not in self.positions
                and self.max_positions is not None
                and len(self.positions) >= self.max_positions
            ):
                return self._rejected(order, "max_positions_exceeded", day)
        else:
            position = self.positions.get(order.code)
            if position is None or position.quantity <= 0:
                return self._rejected(order, "position_not_found", day)
            sellable = position.sellable_quantity(day)
            if sellable <= 0:
                return self._blocked(
                    order,
                    OrderStatus.PENDING,
                    "T1_POSITION_UNAVAILABLE",
                    day,
                )
            executable = self.security_rules.valid_sell_quantity(
                order.code, remaining, sellable,
            )
            if executable <= 0:
                return self._rejected(order, "invalid_sell_lot", day)
        if bar.available_quantity is not None:
            executable = min(executable, max(0, int(bar.available_quantity)))
        if executable <= 0:
            return self._blocked(order, OrderStatus.PENDING, "no_available_quantity", day)

        reference_price = float(bar.open)
        reference_notional = reference_price * executable
        costs = self.cost_model.calculate(order.side, reference_notional, day)
        execution_price = self.cost_model.execution_price(order.side, reference_price)
        execution_notional = execution_price * executable
        if order.side == OrderSide.BUY:
            maximum_risk_quantity = self._risk_buy_quantity(
                order.code, execution_price
            )
            if executable > maximum_risk_quantity:
                return self._rejected(order, "max_position_pct_exceeded", day)
            required_cash = execution_notional + costs.cash_fees
            if required_cash > self.cash + 0.000001:
                return self._rejected(order, "insufficient_cash", day)
            current = self.positions.get(order.code)
            old_quantity = current.quantity if current else 0
            old_book = current.average_cost * old_quantity if current else 0.0
            new_quantity = old_quantity + executable
            existing_locked = (
                int(current.t1_locked_quantity)
                if current is not None and current.t1_locked_on == day
                else 0
            )
            self.positions[order.code] = Position(
                order.code, new_quantity, (old_book + required_cash) / new_quantity, float(bar.close),
                existing_locked + executable, day,
            )
            self.cash -= required_cash
        else:
            position = self.positions[order.code]
            self.cash += execution_notional - costs.cash_fees
            position.quantity -= executable
            position.last_price = float(bar.close)
            if position.quantity <= 0:
                self.positions.pop(order.code, None)

        order.filled_quantity += executable
        partial = order.remaining_quantity > 0
        order.status = OrderStatus.PARTIALLY_FILLED if partial else OrderStatus.FILLED
        order.reason = "partial_fill" if partial else "filled"
        fill = Fill(
            fill_id=f"{order.order_id}:{len(self.fills) + 1}",
            order_id=order.order_id,
            code=order.code,
            side=order.side,
            quantity=executable,
            trade_date=day,
            reference_price=reference_price,
            execution_price=execution_price,
            notional=execution_notional,
            costs=costs,
        )
        self.fills.append(fill)
        order.attempts.append({
            "date": day.isoformat(), "status": order.status.value,
            "reason": order.reason, "quantity": executable,
        })
        if partial:
            self.pending_orders[order.order_id] = order
        else:
            self.pending_orders.pop(order.order_id, None)
        self._event(order, day, quantity=executable, fill_id=fill.fill_id)
        return ExecutionResult(order.order_id, order.status, order.reason, fill)

    def retry_pending(
        self, day: date, market: dict[str, MarketBar | None],
    ) -> list[ExecutionResult]:
        results: list[ExecutionResult] = []
        for order in list(self.pending_orders.values()):
            if order.status not in RETRYABLE_ORDER_STATUSES:
                continue
            order.status = OrderStatus.PENDING
            results.append(self.process_order(order, market.get(order.code), day))
        return results

    def mark_to_market(self, closing_prices: dict[str, float]) -> float:
        missing = sorted(set(self.positions) - set(closing_prices))
        invalid = sorted(
            code
            for code in self.positions
            if code in closing_prices
            and (
                not math.isfinite(float(closing_prices[code]))
                or float(closing_prices[code]) <= 0
            )
        )
        if missing or invalid:
            raise ValueError(
                "missing or invalid closing marks: "
                f"missing={missing}, invalid={invalid}"
            )
        for code, position in self.positions.items():
            position.last_price = float(closing_prices[code])
        return self.cash + sum(position.market_value for position in self.positions.values())

    def reconcile(self, day: date) -> dict[str, Any]:
        """Reconcile the session's cash, quantities and fee movements."""

        expected_cash = self._opening_cash
        expected_quantities = dict(self._opening_quantities)
        for event in self.events:
            if event.get("event_type") == "cash_distribution_applied":
                expected_cash += float(event["cash_amount"])
            elif event.get("event_type") == "unit_split_applied":
                code = str(event["code"])
                expected_quantities[code] = int(event["after_quantity"])
        cash_fees = 0.0
        slippage = 0.0
        for fill in self.fills:
            cash_fees += float(fill.costs.cash_fees)
            slippage += float(fill.costs.slippage)
            if fill.side == OrderSide.BUY:
                expected_cash -= float(fill.notional) + float(fill.costs.cash_fees)
                expected_quantities[fill.code] = (
                    expected_quantities.get(fill.code, 0) + int(fill.quantity)
                )
            else:
                expected_cash += float(fill.notional) - float(fill.costs.cash_fees)
                expected_quantities[fill.code] = (
                    expected_quantities.get(fill.code, 0) - int(fill.quantity)
                )
        expected_quantities = {
            code: quantity
            for code, quantity in expected_quantities.items()
            if quantity != 0
        }
        actual_quantities = {
            code: int(position.quantity)
            for code, position in self.positions.items()
            if int(position.quantity) != 0
        }
        position_differences = {
            code: {
                "expected": int(expected_quantities.get(code, 0)),
                "actual": int(actual_quantities.get(code, 0)),
            }
            for code in sorted(set(expected_quantities) | set(actual_quantities))
            if expected_quantities.get(code, 0) != actual_quantities.get(code, 0)
        }
        cash_difference = float(self.cash) - expected_cash
        report = {
            "schema": "quant-platform/research-execution-reconciliation/v1",
            "date": day.isoformat(),
            "ok": abs(cash_difference) <= 0.000001 and not position_differences,
            "opening_cash": self._opening_cash,
            "expected_cash": expected_cash,
            "actual_cash": float(self.cash),
            "cash_difference": cash_difference,
            "position_differences": position_differences,
            "cash_fees": cash_fees,
            "slippage": slippage,
            "fill_count": len(self.fills),
            "corporate_action_count": sum(
                event.get("event_type")
                in {"cash_distribution_applied", "unit_split_applied"}
                for event in self.events
            ),
        }
        prior = [
            item for item in self.reconciliations if item.get("date") == day.isoformat()
        ]
        if prior and prior[-1] != report:
            raise RuntimeError("non-idempotent execution reconciliation")
        if not prior:
            self.reconciliations.append(report)
        return report

    def terminal_valuation(
        self, day: date, closing_prices: dict[str, float],
    ) -> TerminalValuation:
        market_equity = self.mark_to_market(closing_prices)
        liquidation_cost = sum(
            self.cost_model.calculate(
                OrderSide.SELL, position.quantity * position.last_price, day,
            ).total
            for position in self.positions.values()
        )
        return TerminalValuation(
            market_value_equity=market_equity,
            hypothetical_liquidation_equity=market_equity - liquidation_cost,
            hypothetical_liquidation_cost=liquidation_cost,
        )
