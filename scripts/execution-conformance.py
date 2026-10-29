"""Run normalized execution-contract checks against both local engines.

This tool is read-only.  It deliberately reports unsupported semantics as
failures instead of coercing two different implementations into looking equal.
"""

from __future__ import annotations

from dataclasses import asdict
from datetime import date
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "apps" / "Vibe-Research" / "backend"
RESEARCH_MODEL = ROOT / "research" / "platform-native-strategy" / "tools" / "execution_model.py"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from quant_core import CostPolicy, SimulationLedger, sha256_digest  # noqa: E402


def _research_module():
    spec = importlib.util.spec_from_file_location("platform_native_execution_model", RESEARCH_MODEL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load research execution model: {RESEARCH_MODEL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _bar(price: float = 10.0, volume: int = 100_000, **overrides: Any) -> dict[str, Any]:
    return {
        "open": price,
        "high": price,
        "low": price,
        "close": price,
        "preclose": 10.0,
        "volume": volume,
        "trading_days_since_listing": 100,
        **overrides,
    }


def _quant_config(**overrides: Any) -> dict[str, Any]:
    return {
        **_json(ROOT / "config" / "execution" / "cn-a-share-cost-v1.json"),
        "exchange_rules": _json(ROOT / "config" / "execution" / "cn-a-share-exchange-rules-v1.json"),
        "max_volume_participation_pct": 10,
        "max_position_pct": 100,
        "cash_reserve_pct": 0,
        "max_positions": 3,
        "lot_size": 100,
        "t_plus_one": True,
        "enforce_next_session": True,
        "retry_blocked_orders": True,
        "retry_partial_orders": True,
        **overrides,
    }


def _check(func: Callable[[], tuple[bool, str]]) -> dict[str, Any]:
    try:
        passed, evidence = func()
        return {"status": "PASS" if passed else "FAIL", "evidence": evidence}
    except Exception as exc:  # fail closed: audit failures are evidence, not crashes
        return {"status": "FAIL", "evidence": f"{type(exc).__name__}: {exc}"}


def _quant_core_checks() -> dict[str, dict[str, Any]]:
    def next_open():
        ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
        order = ledger.submit_and_fill(
            signal_date="2025-01-02", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=100, bar=_bar(), open_marks={"600001": 10.0},
        )
        return order["reject_reason"] == "SAME_SESSION_EXECUTION_FORBIDDEN", order["reject_reason"]

    def t1():
        ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
        ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=100, bar=_bar(), open_marks={"600001": 10.0},
        )
        order = ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="sell",
            requested_quantity=100, bar=_bar(), open_marks={"600001": 10.0},
        )
        return order["status"] == "PENDING" and order["reject_reason"] == "T1_POSITION_UNAVAILABLE", str(order)

    def retry():
        ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
        blocked = ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=100, bar=_bar(volume=0), open_marks={"600001": 10.0},
        )
        completed = ledger.retry_pending(
            "2025-01-03", {"600001": _bar()}, {"600001": 10.0},
        )[0]
        return blocked["id"] == completed["id"] and completed["status"] == "FILLED", str(completed)

    def limit_lock():
        ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
        order = ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=100, bar=_bar(price=11.0), open_marks={"600001": 11.0},
        )
        return order["status"] == "LIMIT_LOCKED", str(order)

    def partial():
        ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
        order = ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=500, bar=_bar(volume=2_000), open_marks={"600001": 10.0},
        )
        return order["status"] == "PARTIALLY_FILLED" and order["remaining_quantity"] == 300, str(order)

    def lots():
        ledger = SimulationLedger(100_000, _quant_config(), {"688001": "科创板测试"})
        order = ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="688001", side="buy",
            requested_quantity=237, bar=_bar(), open_marks={"688001": 10.0},
        )
        return order["filled_quantity"] == 237, str(order)

    def fees():
        policy = CostPolicy.from_config(_json(ROOT / "config" / "execution" / "cn-a-share-cost-v1.json"))
        old = policy.cost_breakdown("sell", policy.execution_price("sell", 10), 10_000, "2022-04-28")
        new = policy.cost_breakdown("sell", policy.execution_price("sell", 10), 10_000, "2023-08-28")
        return old.transfer_fee > new.transfer_fee and old.stamp_tax > new.stamp_tax, f"old={old}, new={new}"

    def risk_limits():
        ledger = SimulationLedger(
            100_000,
            _quant_config(max_position_pct=10, max_positions=1),
            {"600001": "A", "600002": "B"},
        )
        first = ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=2_000, bar=_bar(), open_marks={"600001": 10.0, "600002": 10.0},
        )
        second = ledger.submit_and_fill(
            signal_date="2025-01-02", trade_date="2025-01-03", code="600002", side="buy",
            requested_quantity=100, bar=_bar(), open_marks={"600001": 10.0, "600002": 10.0},
        )
        return first["filled_quantity"] <= 1_000 and second["status"] == "REJECTED", f"first={first}, second={second}"

    def corporate_action():
        ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
        order = ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=100, bar=_bar(unsupported_corporate_action=True), open_marks={"600001": 10.0},
        )
        return order["status"] == "PENDING" and not ledger.position_quantities, str(order)

    def missing_mark():
        ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
        ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=100, bar=_bar(), open_marks={"600001": 10.0},
        )
        try:
            ledger.equity({})
        except ValueError as exc:
            return True, str(exc)
        return False, "missing mark did not fail"

    def terminal():
        ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
        ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=100, bar=_bar(), open_marks={"600001": 10.0},
        )
        value = ledger.terminal_valuation("2025-01-02", {"600001": 10.0})
        return value.market_value_equity > value.hypothetical_liquidation_equity, str(value)

    def reconcile():
        ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
        ledger.submit_and_fill(
            signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
            requested_quantity=100, bar=_bar(), open_marks={"600001": 10.0},
        )
        report = ledger.reconcile("2025-01-02")
        return report["ok"], str(report)

    def idempotent():
        def run():
            ledger = SimulationLedger(100_000, _quant_config(), {"600001": "测试股票"})
            ledger.submit_and_fill(
                signal_date="2025-01-01", trade_date="2025-01-02", code="600001", side="buy",
                requested_quantity=100, bar=_bar(), open_marks={"600001": 10.0},
            )
            ledger.reconcile("2025-01-02")
            return ledger.report()
        return run() == run(), "two clean-ledger replays produced identical reports"

    checks = {
        "NEXT_OPEN_NO_SAME_BAR_FILL": next_open,
        "T1_SAME_DAY_SELL_BLOCKED": t1,
        "SUSPENDED_ORDER_RETRY": retry,
        "LIMIT_UP_BUY_AND_LIMIT_DOWN_SELL": limit_lock,
        "PARTIAL_FILL_AND_VOLUME_CAPACITY": partial,
        "LOT_AND_ODD_LOT_RULES": lots,
        "DATED_FEE_SCHEDULE": fees,
        "CASH_AND_POSITION_RISK_LIMITS": risk_limits,
        "CORPORATE_ACTION_FAIL_CLOSED": corporate_action,
        "MISSING_MARK_FAIL_CLOSED": missing_mark,
        "TERMINAL_LIQUIDATION_VALUATION": terminal,
        "DOUBLE_ENTRY_RECONCILIATION": reconcile,
        "IDEMPOTENT_REPLAY": idempotent,
    }
    return {scenario: _check(check) for scenario, check in checks.items()}


def _research_checks() -> dict[str, dict[str, Any]]:
    model = _research_module()

    def next_open():
        mapped = model.next_trading_day(
            date(2025, 1, 2), [date(2025, 1, 2), date(2025, 1, 3)],
        )
        return mapped == date(2025, 1, 3), mapped.isoformat()

    def retry():
        portfolio = model.Portfolio(cash=10_000)
        order = model.Order("buy-1", "sh.600001", model.OrderSide.BUY, 100, date(2025, 1, 2))
        portfolio.process_order(
            order, model.MarketBar(10, 10, 10, 10, 10, tradestatus=0), date(2025, 1, 2),
        )
        result = portfolio.retry_pending(
            date(2025, 1, 3), {"sh.600001": model.MarketBar(10, 10, 10, 10, 10)},
        )[0]
        return result.status == model.OrderStatus.FILLED, str(result)

    def t1():
        portfolio = model.Portfolio(cash=20_000)
        portfolio.process_order(
            model.Order("buy-1", "sh.600001", model.OrderSide.BUY, 100, date(2025, 1, 2)),
            model.MarketBar(10, 10, 10, 10, 10),
            date(2025, 1, 2),
        )
        result = portfolio.process_order(
            model.Order("sell-1", "sh.600001", model.OrderSide.SELL, 100, date(2025, 1, 2)),
            model.MarketBar(10, 10, 10, 10, 10),
            date(2025, 1, 2),
        )
        return result.status == model.OrderStatus.PENDING and result.reason == "T1_POSITION_UNAVAILABLE", str(result)

    def limit_lock():
        portfolio = model.Portfolio(cash=20_000)
        order = model.Order("buy-1", "sh.600001", model.OrderSide.BUY, 100, date(2025, 1, 2))
        result = portfolio.process_order(
            order, model.MarketBar(11, 11, 11, 11, 10), date(2025, 1, 2),
        )
        return result.status == model.OrderStatus.LIMIT_LOCKED, str(result)

    def partial():
        portfolio = model.Portfolio(
            cash=0,
            positions={"sh.600001": model.Position("sh.600001", 100, 10, 10)},
        )
        order = model.Order("sell-1", "sh.600001", model.OrderSide.SELL, 100, date(2025, 1, 2))
        result = portfolio.process_order(
            order, model.MarketBar(10, 10, 10, 10, 10, available_quantity=40), date(2025, 1, 2),
        )
        return result.status == model.OrderStatus.PARTIALLY_FILLED and order.remaining_quantity == 60, str(result)

    def lots():
        rules = model.SecurityRules.default()
        return rules.buy_quantity("sh.688001", 237) == 237 and rules.buy_quantity("sh.688001", 199) == 0, "STAR 200+1 lot rule"

    def fees():
        policy = model.CostModel.default()
        old = policy.calculate(model.OrderSide.SELL, 100_000, date(2022, 4, 28))
        new = policy.calculate(model.OrderSide.SELL, 100_000, date(2023, 8, 28))
        return old.transfer_fee > new.transfer_fee and old.stamp_tax > new.stamp_tax, f"old={old}, new={new}"

    def corporate_action():
        portfolio = model.Portfolio(cash=20_000)
        order = model.Order("buy-1", "sh.600001", model.OrderSide.BUY, 100, date(2025, 1, 2))
        result = portfolio.process_order(
            order,
            model.MarketBar(10, 10, 10, 10, 10, unsupported_corporate_action=True),
            date(2025, 1, 2),
        )
        return result.reason == "unsupported_corporate_action" and not portfolio.positions, str(result)

    def risk_limits():
        portfolio = model.Portfolio(
            cash=100_000, max_positions=1, max_position_pct=0.10,
        )
        allowed = portfolio.affordable_buy_quantity(
            "sh.600001", 10, date(2025, 1, 2), 100_000,
        )
        first = portfolio.process_order(
            model.Order("buy-1", "sh.600001", model.OrderSide.BUY, allowed, date(2025, 1, 2)),
            model.MarketBar(10, 10, 10, 10, 10),
            date(2025, 1, 2),
        )
        second = portfolio.process_order(
            model.Order("buy-2", "sh.600002", model.OrderSide.BUY, 100, date(2025, 1, 2)),
            model.MarketBar(10, 10, 10, 10, 10),
            date(2025, 1, 2),
        )
        return first.status == model.OrderStatus.FILLED and allowed <= 1_000 and second.reason == "max_positions_exceeded", f"first={first}, second={second}"

    def missing_mark():
        portfolio = model.Portfolio(
            cash=1_000,
            positions={"sh.600001": model.Position("sh.600001", 100, 10, 10)},
        )
        try:
            portfolio.mark_to_market({})
        except ValueError as exc:
            return True, str(exc)
        return False, "missing mark did not fail"

    def reconcile():
        portfolio = model.Portfolio(cash=20_000)
        portfolio.process_order(
            model.Order("buy-1", "sh.600001", model.OrderSide.BUY, 100, date(2025, 1, 2)),
            model.MarketBar(10, 10, 10, 10, 10),
            date(2025, 1, 2),
        )
        report = portfolio.reconcile(date(2025, 1, 2))
        return report["ok"] and not report["position_differences"], str(report)

    def terminal():
        portfolio = model.Portfolio(
            cash=1_000,
            positions={"sh.600001": model.Position("sh.600001", 100, 10, 10)},
        )
        value = portfolio.terminal_valuation(date(2025, 1, 2), {"sh.600001": 10})
        return value.market_value_equity > value.hypothetical_liquidation_equity, str(value)

    def idempotent():
        def run():
            portfolio = model.Portfolio(cash=20_000)
            order = model.Order("buy-1", "sh.600001", model.OrderSide.BUY, 100, date(2025, 1, 2))
            result = portfolio.process_order(
                order, model.MarketBar(10, 10, 10, 10, 10), date(2025, 1, 2),
            )
            return asdict(result), list(portfolio.events)
        return run() == run(), "two clean-portfolio replays produced identical results"

    checks: dict[str, Callable[[], tuple[bool, str]]] = {
        "NEXT_OPEN_NO_SAME_BAR_FILL": next_open,
        "T1_SAME_DAY_SELL_BLOCKED": t1,
        "SUSPENDED_ORDER_RETRY": retry,
        "LIMIT_UP_BUY_AND_LIMIT_DOWN_SELL": limit_lock,
        "PARTIAL_FILL_AND_VOLUME_CAPACITY": partial,
        "LOT_AND_ODD_LOT_RULES": lots,
        "DATED_FEE_SCHEDULE": fees,
        "CASH_AND_POSITION_RISK_LIMITS": risk_limits,
        "CORPORATE_ACTION_FAIL_CLOSED": corporate_action,
        "MISSING_MARK_FAIL_CLOSED": missing_mark,
        "TERMINAL_LIQUIDATION_VALUATION": terminal,
        "DOUBLE_ENTRY_RECONCILIATION": reconcile,
        "IDEMPOTENT_REPLAY": idempotent,
    }
    results = {scenario: _check(check) for scenario, check in checks.items()}
    return results


def build_report() -> dict[str, Any]:
    contract = _json(ROOT / "config" / "execution-semantics-v1.json")
    scenario_ids = [str(item["id"]) for item in contract["required_scenarios"]]
    adapters = {
        "quant_core": _quant_core_checks(),
        "platform_native_research": _research_checks(),
    }
    for results in adapters.values():
        missing = set(scenario_ids) - set(results)
        for scenario in missing:
            results[scenario] = {"status": "FAIL", "evidence": "scenario was not executed"}
    summaries = {
        adapter: {
            "passed": sum(result["status"] == "PASS" for result in results.values()),
            "required": len(scenario_ids),
            "all_required_scenarios_pass": all(
                results[scenario]["status"] == "PASS" for scenario in scenario_ids
            ),
        }
        for adapter, results in adapters.items()
    }
    common_passed = [
        scenario
        for scenario in scenario_ids
        if all(results[scenario]["status"] == "PASS" for results in adapters.values())
    ]
    input_paths = (
        "config/execution-semantics-v1.json",
        "config/execution/cn-a-share-cost-v1.json",
        "config/execution/cn-a-share-exchange-rules-v1.json",
        "apps/Vibe-Research/backend/quant_core/execution.py",
        "research/platform-native-strategy/tools/execution_model.py",
        "research/platform-native-strategy/configs/trading/cost-model-v1.json",
        "research/platform-native-strategy/configs/trading/exchange-rules-v1.json",
        "scripts/execution-conformance.py",
    )
    identity = {
        "schema": "quant-platform/execution-conformance-report/v1",
        "contract_id": contract["contract_id"],
        "contract_sha256": _file_sha256(ROOT / input_paths[0]),
        "inputs": [
            {"path": path, "sha256": _file_sha256(ROOT / path)}
            for path in input_paths
        ],
        "real_orders": False,
        "adapters": adapters,
        "summaries": summaries,
        "common_passed": common_passed,
        "canonical_eligible": summaries["quant_core"][
            "all_required_scenarios_pass"
        ],
        "promotion_eligible": all(item["all_required_scenarios_pass"] for item in summaries.values()),
    }
    return {**identity, "report_sha256": sha256_digest(identity)}


if __name__ == "__main__":
    print(json.dumps(build_report(), ensure_ascii=False, indent=2))
