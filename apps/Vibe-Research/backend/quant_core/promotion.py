"""Fail-closed lifecycle gate from research evidence to controlled live readiness."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

from .provenance import sha256_digest


PROMOTION_GATE_SCHEMA = "quant-core/promotion-gate/v1"


def _boolean(evidence: Mapping[str, Any], path: str) -> bool:
    current: Any = evidence
    for component in path.split("."):
        if not isinstance(current, Mapping) or component not in current:
            return False
        current = current[component]
    return current is True


def _number(evidence: Mapping[str, Any], path: str) -> float | None:
    current: Any = evidence
    for component in path.split("."):
        if not isinstance(current, Mapping) or component not in current:
            return None
        current = current[component]
    try:
        value = float(current)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _check(
    checks: list[dict[str, Any]],
    *,
    code: str,
    scope: str,
    passed: bool,
    message: str,
) -> None:
    checks.append({"code": code, "scope": scope, "passed": bool(passed), "message": message})


def evaluate_promotion(
    strategy_id: str,
    evidence: Mapping[str, Any],
    *,
    policy_id: str = "quant-platform/promotion-policy/v1",
) -> dict[str, Any]:
    """Evaluate all lifecycle gates without inferring missing evidence as success."""
    checks: list[dict[str, Any]] = []
    forward_only = _boolean(evidence, "research.forward_only")
    _check(checks, code="STRATEGY_ARTIFACT_FROZEN", scope="research", passed=_boolean(evidence, "research.strategy_artifact_frozen"), message="策略规则与配置必须冻结并绑定内容哈希。")
    _check(checks, code="CLEAN_CODE_COMMIT", scope="research", passed=_boolean(evidence, "research.clean_code_commit"), message="正式实验必须绑定干净且可读取的代码提交。")
    _check(checks, code="VERSIONED_DATA_CATALOG", scope="research", passed=_boolean(evidence, "research.data_catalog_verified"), message="研究数据必须进入版本化目录并通过内容校验。")
    _check(checks, code="TEMPORAL_BIAS_AUDIT", scope="research", passed=_boolean(evidence, "research.temporal_bias_passed"), message="信号前视与预热稳定性审计必须通过。")
    _check(
        checks,
        code="COMPLETE_EXPERIMENT_LEDGER_OR_FORWARD_ONLY",
        scope="research",
        passed=forward_only or _boolean(evidence, "research.experiment_ledger_verified"),
        message="历史研究必须预登记全部成功、失败和中断尝试；严格前向策略可由未来不可补录证据替代。",
    )
    _check(
        checks,
        code="PARAMETER_LOCKBOX_OR_FORWARD_ONLY",
        scope="research",
        passed=forward_only or _boolean(evidence, "research.parameter_lockbox_verified"),
        message="参数空间、尝试预算、主指标和否定条件必须在首轮历史实验前锁定。",
    )
    _check(
        checks,
        code="PURGED_WALK_FORWARD_OR_FORWARD_ONLY",
        scope="research",
        passed=forward_only or _boolean(evidence, "research.purged_walk_forward_passed"),
        message="历史样本外验证必须按标签区间执行 purging，并显式声明信息 embargo；严格前向验证可替代历史门槛。",
    )
    _check(
        checks,
        code="STATISTICAL_RESEARCH_GATE_OR_FORWARD_ONLY",
        scope="research",
        passed=forward_only or _boolean(evidence, "research.statistical_gate_passed"),
        message=(
            "历史研究必须使用冻结样本外曲线复算 HAC 统计证明，对完整预声明家族执行 "
            "Holm-Bonferroni 校正，并确认所选参数获得相邻参数支持；严格前向验证可替代历史统计门槛。"
        ),
    )
    _check(
        checks,
        code="ROBUSTNESS_STRESS_GATE_OR_FORWARD_ONLY",
        scope="research",
        passed=forward_only or _boolean(evidence, "research.robustness_gate_passed"),
        message=(
            "Historical research must pass the frozen holdout stress family for doubled "
            "costs, halved capacity, delayed execution and deterministic asset gaps; "
            "strict forward-only validation may substitute for this historical gate."
        ),
    )
    _check(
        checks,
        code="ADVERSARIAL_RESEARCH_AUDIT_OR_FORWARD_ONLY",
        scope="research",
        passed=forward_only or _boolean(evidence, "research.adversarial_audit_passed"),
        message="使用历史结果晋级前必须由不同责任主体完成敌对审计；纯前向候选可先进入模拟观察。",
    )
    _check(
        checks,
        code="POINT_IN_TIME_OR_FORWARD_ONLY_DATA",
        scope="research",
        passed=_boolean(evidence, "research.point_in_time_ready") or (
            forward_only and _boolean(evidence, "paper.approved_forward_data")
        ),
        message="历史结论需要点时数据；否则只能使用实际记录时点之后的前向数据。",
    )
    _check(checks, code="EXECUTION_CONFORMANCE", scope="research", passed=_boolean(evidence, "research.execution_conformant"), message="策略执行器必须通过统一执行金样本。")
    _check(checks, code="PORTFOLIO_RISK_POLICY", scope="research", passed=_boolean(evidence, "research.portfolio_risk_compliant"), message="组合集中度、现金、相关簇与熔断策略必须启用且无违规。")
    research_checks = [item for item in checks if item["scope"] == "research"]
    research_ready = all(item["passed"] for item in research_checks)

    _check(checks, code="FORMAL_FORWARD_REGISTRATION", scope="paper_activation", passed=_boolean(evidence, "paper.formally_registered"), message="前向实验必须在开始前登记。")
    _check(checks, code="PAPER_ONLY_MODE", scope="paper_activation", passed=_boolean(evidence, "paper.paper_only") and not _boolean(evidence, "paper.real_orders"), message="研究与前向阶段必须永久禁止真实订单。")
    _check(checks, code="APPROVAL_PRECEDES_FORWARD_START", scope="paper_activation", passed=_boolean(evidence, "paper.approval_precedes_start"), message="审批和冻结必须早于首个正式前向观测。")
    _check(checks, code="APPROVED_FORWARD_DATA", scope="paper_activation", passed=_boolean(evidence, "paper.approved_forward_data"), message="前向信号、执行、估值数据用途必须在数据源注册表中获准。")
    _check(checks, code="RECOVERY_DRILL_PASSED", scope="paper_activation", passed=_boolean(evidence, "paper.recovery_drill_passed"), message="必须先证明断点、校验和、幂等重放与只读降级可恢复。")
    _check(checks, code="SHARED_CAPITAL_POLICY_BOUND", scope="paper_activation", passed=_boolean(evidence, "paper.platform_portfolio_policy_bound"), message="正式前向必须绑定平台级共享资金、集中度与统一熔断政策。")
    _check(checks, code="PORTFOLIO_STRESS_POLICY_BOUND", scope="paper_activation", passed=_boolean(evidence, "paper.portfolio_stress_policy_bound"), message="正式前向必须冻结价格跳空、相关性趋同和流动性枯竭压力场景。")
    _check(checks, code="PARENT_ORDER_ALLOCATION_BOUND", scope="paper_activation", passed=_boolean(evidence, "paper.parent_order_allocation_bound"), message="正式前向必须冻结父账户净单、内部对冲与子策略分摊合同。")
    _check(checks, code="PRETRADE_EXECUTION_BOUND", scope="paper_activation", passed=_boolean(evidence, "paper.pretrade_execution_bound"), message="正式前向必须冻结交易前预演、父单编排与提交校验合同。")
    activation_checks = [item for item in checks if item["scope"] == "paper_activation"]
    paper_activation_ready = research_ready and all(item["passed"] for item in activation_checks)

    observed_days = _number(evidence, "paper.observed_trading_days")
    minimum_days = _number(evidence, "paper.minimum_trading_days")
    observations = _number(evidence, "paper.observation_count")
    minimum_observations = _number(evidence, "paper.minimum_observation_count")
    _check(checks, code="MINIMUM_FORWARD_DURATION", scope="paper_completion", passed=(observed_days is not None and minimum_days is not None and observed_days >= minimum_days), message="正式前向交易日必须达到预注册最短周期。")
    _check(checks, code="MINIMUM_FORWARD_OBSERVATIONS", scope="paper_completion", passed=(observations is not None and minimum_observations is not None and observations >= minimum_observations), message="独立信号/调仓观测数必须达到预注册下限。")
    performance = {
        field: _number(evidence, f"paper.performance.{field}")
        for field in (
            "total_return_pct",
            "minimum_total_return_pct",
            "annualized_return_pct",
            "minimum_annualized_return_pct",
            "sharpe_ratio",
            "minimum_sharpe_ratio",
            "positive_month_ratio",
            "minimum_positive_month_ratio",
            "max_drawdown_pct",
            "maximum_performance_drawdown_pct",
            "annualized_volatility_pct",
            "maximum_annualized_volatility_pct",
        )
    }

    def at_least(value: str, threshold: str) -> bool:
        return (
            performance[value] is not None
            and performance[threshold] is not None
            and float(performance[value]) >= float(performance[threshold]) - 1e-12
        )

    def at_most(value: str, threshold: str) -> bool:
        return (
            performance[value] is not None
            and performance[threshold] is not None
            and float(performance[value]) <= float(performance[threshold]) + 1e-12
        )

    _check(checks, code="PROSPECTIVE_PERFORMANCE_ONLY", scope="paper_completion", passed=_boolean(evidence, "paper.performance.prospective_only"), message="绩效结论只能来自正式批准后的不可补录前向权益序列。")
    _check(checks, code="MINIMUM_TOTAL_RETURN", scope="paper_completion", passed=at_least("total_return_pct", "minimum_total_return_pct"), message="扣除实际模拟成本后的累计收益必须达到预注册下限。")
    _check(checks, code="MINIMUM_ANNUALIZED_RETURN", scope="paper_completion", passed=at_least("annualized_return_pct", "minimum_annualized_return_pct"), message="前向年化收益必须达到预注册收益门槛。")
    _check(checks, code="MINIMUM_SHARPE_RATIO", scope="paper_completion", passed=at_least("sharpe_ratio", "minimum_sharpe_ratio"), message="前向风险调整收益必须达到预注册夏普门槛。")
    _check(checks, code="MINIMUM_POSITIVE_MONTH_RATIO", scope="paper_completion", passed=at_least("positive_month_ratio", "minimum_positive_month_ratio"), message="正收益月份占比必须达到预注册稳定性门槛。")
    _check(checks, code="MAXIMUM_PERFORMANCE_DRAWDOWN", scope="paper_completion", passed=at_most("max_drawdown_pct", "maximum_performance_drawdown_pct"), message="前向权益最大回撤不得超过预注册上限。")
    _check(checks, code="MAXIMUM_ANNUALIZED_VOLATILITY", scope="paper_completion", passed=at_most("annualized_volatility_pct", "maximum_annualized_volatility_pct"), message="前向年化波动率不得超过预注册上限。")
    _check(checks, code="LOSS_BUDGET_INTACT", scope="paper_completion", passed=_boolean(evidence, "paper.loss_budget_intact"), message="虚拟损失预算不得超限。")
    _check(checks, code="ZERO_RECONCILIATION_FAILURES", scope="paper_completion", passed=_boolean(evidence, "paper.zero_reconciliation_failures"), message="前向账本必须每日守恒且无未解释差异。")
    _check(checks, code="ZERO_DATA_INTEGRITY_FAILURES", scope="paper_completion", passed=_boolean(evidence, "paper.zero_data_integrity_failures"), message="前向期间不得出现未关闭的数据完整性故障。")
    _check(checks, code="ZERO_PORTFOLIO_RISK_BREACHES", scope="paper_completion", passed=_boolean(evidence, "paper.zero_portfolio_risk_breaches"), message="组合级硬门槛不得被突破。")
    _check(checks, code="ZERO_PLATFORM_PORTFOLIO_BREACHES", scope="paper_completion", passed=_boolean(evidence, "paper.zero_platform_portfolio_breaches"), message="多策略父账户在完整前向期内不得出现共享资金或跨策略集中度违规。")
    _check(checks, code="ZERO_PORTFOLIO_STRESS_BREACHES", scope="paper_completion", passed=_boolean(evidence, "paper.zero_portfolio_stress_breaches"), message="完整前向期内所有冻结价格与流动性压力场景必须持续通过。")
    _check(checks, code="PARENT_ORDER_ALLOCATION_COMPLETE", scope="paper_completion", passed=_boolean(evidence, "paper.parent_order_allocation_complete"), message="每份子策略成交必须进入可复算的父账户净单与分摊计划，且不得存在损坏或孤立意图。")
    _check(checks, code="PRETRADE_EXECUTION_COMPLETE", scope="paper_completion", passed=_boolean(evidence, "paper.pretrade_execution_complete"), message="每次账本提交必须逐笔匹配事前冻结的预演成交、快照和父订单计划。")
    _check(checks, code="NO_POST_FREEZE_RULE_DRIFT", scope="paper_completion", passed=_boolean(evidence, "paper.no_rule_drift"), message="冻结后策略、数据语义、费用和风控不得漂移。")
    _check(
        checks,
        code="INDEPENDENT_ADVERSARIAL_AUDIT",
        scope="paper_completion",
        passed=_boolean(evidence, "paper.adversarial_audit_passed"),
        message="前向观察完成后仍须由非策略研究者复核数据泄漏、试验次数、执行偏差和否定条件，方可进入实盘门槛。",
    )
    completion_checks = [item for item in checks if item["scope"] == "paper_completion"]
    paper_complete = paper_activation_ready and all(item["passed"] for item in completion_checks)

    live_requirements = (
        ("BROKER_ADAPTER_CONFORMANT", "broker.adapter_conformant", "券商适配器必须通过统一订单状态和对账契约。"),
        ("BROKER_READ_ONLY_SHADOW_PASSED", "broker.read_only_shadow_passed", "必须先完成券商只读账户与成交回报影子对账。"),
        ("BROKER_PAPER_OR_SANDBOX_PASSED", "broker.paper_or_sandbox_passed", "券商仿真或沙箱订单生命周期必须通过。"),
        ("ACCOUNT_PERMISSION_MINIMIZED", "broker.minimum_permissions", "账户/API 权限必须最小化并禁止出金能力。"),
        ("SECRETS_HEALTHY", "broker.secrets_healthy", "密钥只能来自安全存储，且轮换/失效检查通过。"),
        ("KILL_SWITCH_DRILL_PASSED", "broker.kill_switch_drill_passed", "人工和自动总开关必须完成演练。"),
        ("DISASTER_RECOVERY_PASSED", "broker.disaster_recovery_passed", "断网、重复回报、进程崩溃与重启恢复必须通过。"),
        ("LIVE_CAPITAL_CAP_CONFIGURED", "broker.capital_cap_configured", "受控实盘必须配置不可绕过的资金上限。"),
        ("MANUAL_LIVE_APPROVAL", "broker.manual_live_approval", "最终实盘启用必须由用户单独明确批准。"),
    )
    for code, path, message in live_requirements:
        _check(checks, code=code, scope="controlled_live", passed=_boolean(evidence, path), message=message)
    live_checks = [item for item in checks if item["scope"] == "controlled_live"]
    controlled_live_ready = paper_complete and all(item["passed"] for item in live_checks)

    paper_active = _boolean(evidence, "paper.active")
    if controlled_live_ready:
        stage = "CONTROLLED_LIVE_READY"
    elif paper_complete:
        stage = "PAPER_GATE_PASSED"
    elif paper_activation_ready and paper_active:
        stage = "PAPER_ACTIVE"
    elif paper_activation_ready:
        stage = "PAPER_ACTIVATION_READY"
    elif research_ready:
        stage = "RESEARCH_EVIDENCE_READY"
    else:
        stage = "RESEARCH_ONLY"

    blockers = [item for item in checks if not item["passed"]]
    identity = {
        "schema": PROMOTION_GATE_SCHEMA,
        "policy_id": policy_id,
        "strategy_id": str(strategy_id),
        "stage": stage,
        "checks": checks,
    }
    return {
        **identity,
        "assessment_sha256": sha256_digest(identity),
        "eligibility": {
            "research_evidence_ready": research_ready,
            "paper_activation_ready": paper_activation_ready,
            "paper_gate_passed": paper_complete,
            "controlled_live_ready": controlled_live_ready,
        },
        "blockers": blockers,
        "next_gate": (
            "NONE" if controlled_live_ready else
            "CONTROLLED_LIVE" if paper_complete else
            "PAPER_COMPLETION" if paper_activation_ready else
            "PAPER_ACTIVATION" if research_ready else
            "RESEARCH_EVIDENCE"
        ),
        "real_orders_allowed": controlled_live_ready,
    }


def platform_promotion_summary(
    assessments: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    rows = [dict(item) for item in assessments]
    stage_counts: dict[str, int] = {}
    for item in rows:
        stage = str(item.get("stage") or "UNKNOWN")
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
    live_ready = [item for item in rows if item.get("real_orders_allowed") is True]
    return {
        "schema": "quant-core/promotion-summary/v1",
        "strategy_count": len(rows),
        "stage_counts": dict(sorted(stage_counts.items())),
        "paper_activation_ready_count": sum(
            item.get("eligibility", {}).get("paper_activation_ready") is True for item in rows
        ),
        "paper_gate_passed_count": sum(
            item.get("eligibility", {}).get("paper_gate_passed") is True for item in rows
        ),
        "controlled_live_ready_count": len(live_ready),
        "real_orders_globally_allowed": bool(rows) and len(live_ready) == len(rows),
        "assessments": rows,
    }
