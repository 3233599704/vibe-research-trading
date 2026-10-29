"""Versioned exchange microstructure rules used by every execution adapter.

The rule payload is injected by the caller and is therefore auditable and
replaceable.  No live exchange rule is silently hard-coded in this module.
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal, ROUND_HALF_UP
from typing import Any


def _date(value: str | date) -> date:
    return value if isinstance(value, date) else date.fromisoformat(str(value))


class ExchangeRules:
    def __init__(self, payload: dict[str, Any]) -> None:
        required = {"version", "price_limits", "no_initial_limit", "lot_rules"}
        missing = required - set(payload)
        if missing:
            raise ValueError(f"exchange rules missing keys: {sorted(missing)}")
        self.version = str(payload["version"])
        self.price_limits = dict(payload["price_limits"])
        self.no_initial_limit = dict(payload["no_initial_limit"])
        self.lot_rules = {
            str(board): {
                "minimum": int(rule["minimum"]),
                "increment": int(rule["increment"]),
            }
            for board, rule in dict(payload["lot_rules"]).items()
        }
        if not self.version:
            raise ValueError("exchange rules require a non-empty version")
        for board in {"main", "chinext", "star", "beijing"}:
            if board not in self.price_limits or board not in self.lot_rules:
                raise ValueError(f"exchange rules missing board: {board}")
            rule = self.lot_rules[board]
            if rule["minimum"] <= 0 or rule["increment"] <= 0:
                raise ValueError(f"invalid lot rule for board: {board}")

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
    def _scheduled_rate(day: date, schedule: list[dict[str, Any]]) -> Decimal:
        eligible = [
            Decimal(str(item["rate"]))
            for item in schedule
            if _date(str(item["effective_date"])) <= day
        ]
        if not eligible:
            raise ValueError(f"no price-limit rule is configured for {day.isoformat()}")
        return eligible[-1]

    def limit_rate(
        self,
        code: str,
        day: str | date,
        *,
        is_st: bool,
        trading_days_since_listing: int | None,
    ) -> Decimal | None:
        parsed = _date(day)
        board = self.board(code)
        initial_rule = self.no_initial_limit.get(board)
        if initial_rule is not None and trading_days_since_listing is not None:
            effective = _date(str(initial_rule["effective_date"]))
            if parsed >= effective and trading_days_since_listing <= int(initial_rule["trading_days"]):
                return None
        board_rules = dict(self.price_limits[board])
        schedule = list(board_rules.get("st" if is_st else "normal") or board_rules["normal"])
        return self._scheduled_rate(parsed, schedule)

    @staticmethod
    def _limit_price(preclose: Decimal, rate: Decimal, direction: int) -> Decimal:
        return (preclose * (Decimal("1") + Decimal(direction) * rate)).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP,
        )

    def is_locked(
        self,
        side: str,
        code: str,
        day: str | date,
        bar: dict[str, Any],
    ) -> bool:
        if side == "buy" and "limit_up_locked" in bar:
            return bool(bar["limit_up_locked"])
        if side == "sell" and "limit_down_locked" in bar:
            return bool(bar["limit_down_locked"])
        if bar.get("preclose") is None:
            raise ValueError("preclose is required when limit-lock flags are absent")
        rate = self.limit_rate(
            code,
            day,
            is_st=bool(bar.get("is_st", False)),
            trading_days_since_listing=(
                int(bar["trading_days_since_listing"])
                if bar.get("trading_days_since_listing") is not None
                else None
            ),
        )
        if rate is None:
            return False
        direction = 1 if side == "buy" else -1
        limit_price = self._limit_price(Decimal(str(bar["preclose"])), rate, direction)
        open_price = Decimal(str(bar["open"]))
        return open_price >= limit_price if side == "buy" else open_price <= limit_price

    def lot_spec(self, code: str) -> tuple[int, int]:
        rule = self.lot_rules[self.board(code)]
        return int(rule["minimum"]), int(rule["increment"])

    def normalized_buy_quantity(self, code: str, desired_quantity: int | float) -> int:
        quantity = max(0, int(desired_quantity))
        minimum, increment = self.lot_spec(code)
        if quantity < minimum:
            return 0
        return minimum + ((quantity - minimum) // increment) * increment

    def valid_sell_quantity(self, code: str, desired: int, held: int) -> int:
        quantity = max(0, min(int(desired), int(held)))
        if quantity == held:
            return quantity
        return self.normalized_buy_quantity(code, quantity)

    def evidence(self) -> dict[str, Any]:
        return {"version": self.version, "boards": sorted(self.price_limits)}
