"""Content-addressed execution-conformance evidence for formal paper runs."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

from .provenance import sha256_digest


EXECUTION_CONFORMANCE_SCHEMA = "quant-platform/execution-conformance-report/v1"
EXECUTION_CONFORMANCE_SCRIPT = "scripts/execution-conformance.py"
EXECUTION_CONFORMANCE_SNAPSHOT_PATHS = {
    "apps/Vibe-Research/backend/quant_core/execution.py",
    "apps/Vibe-Research/backend/quant_core/execution_conformance.py",
    "research/platform-native-strategy/tools/execution_model.py",
    "research/platform-native-strategy/configs/trading/cost-model-v1.json",
    "research/platform-native-strategy/configs/trading/exchange-rules-v1.json",
    "scripts/execution-conformance.py",
    "config/execution-semantics-v1.json",
    "config/execution/cn-a-share-cost-v1.json",
    "config/execution/cn-a-share-exchange-rules-v1.json",
    "config/strategy-lab/execution-conformance-report.schema.json",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ExecutionConformanceError(RuntimeError):
    pass


def _inside(root: Path, relative: str) -> Path:
    path = (root / str(relative)).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ExecutionConformanceError(
            f"execution-conformance path escapes platform root: {relative}"
        ) from exc
    return path


def _file_sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ExecutionConformanceError(
            f"execution-conformance input is unreadable: {path}"
        ) from exc


def _strict_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {constant}")
            ),
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ExecutionConformanceError(
            f"execution-conformance record is unreadable: {path}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise ExecutionConformanceError(
            "execution-conformance record must be an object"
        )
    return value


def validate_execution_conformance_report(
    value: Mapping[str, Any],
    *,
    platform_root: str | Path,
) -> dict[str, Any]:
    root = Path(platform_root).resolve()
    report = dict(value)
    required = {
        "schema",
        "contract_id",
        "contract_sha256",
        "inputs",
        "real_orders",
        "adapters",
        "summaries",
        "common_passed",
        "canonical_eligible",
        "promotion_eligible",
        "report_sha256",
    }
    if set(report) != required or report.get("schema") != EXECUTION_CONFORMANCE_SCHEMA:
        raise ExecutionConformanceError(
            "execution-conformance report fields do not match contract"
        )
    if report.get("real_orders") is not False:
        raise ExecutionConformanceError(
            "execution-conformance evidence must be PAPER-only"
        )
    expected_report_sha = str(report.get("report_sha256") or "").lower()
    identity = {
        key: item for key, item in report.items() if key != "report_sha256"
    }
    if not SHA256_RE.fullmatch(expected_report_sha) or sha256_digest(
        identity
    ) != expected_report_sha:
        raise ExecutionConformanceError(
            "execution-conformance internal hash mismatch"
        )

    contract_path = _inside(root, "config/execution-semantics-v1.json")
    contract = _strict_json(contract_path)
    contract_sha = _file_sha256(contract_path)
    if (
        report.get("contract_id") != contract.get("contract_id")
        or report.get("contract_sha256") != contract_sha
        or contract.get("canonical_adapter_id") != "quant_core"
        or contract.get("new_strategy_runs_must_use_canonical_adapter") is not True
    ):
        raise ExecutionConformanceError(
            "execution-conformance contract identity mismatch"
        )
    contract_adapters = {
        str(item.get("id") or ""): dict(item)
        for item in list(contract.get("adapters") or [])
    }
    if (
        set(contract_adapters) != {"quant_core", "platform_native_research"}
        or contract_adapters["quant_core"].get("status") != "CONFORMANT"
        or contract_adapters["quant_core"].get("new_runs_allowed") is not True
        or contract_adapters["platform_native_research"].get("status")
        != "LEGACY_REPRODUCTION_ONLY"
        or contract_adapters["platform_native_research"].get(
            "new_runs_allowed"
        )
        is not False
        or contract_adapters["platform_native_research"].get(
            "promotion_allowed"
        )
        is not False
    ):
        raise ExecutionConformanceError(
            "execution-conformance adapter policy was weakened"
        )
    promotion_gate = dict(contract.get("promotion_gate") or {})
    if promotion_gate != {
        "canonical_adapter_required": True,
        "canonical_adapter_all_required_scenarios_pass": True,
        "legacy_adapters_promotion_allowed": False,
        "zero_unexplained_cash_difference": True,
        "zero_unexplained_position_difference": True,
        "golden_report_sha256_required": True,
        "registration_requires_fresh_replay": True,
    }:
        raise ExecutionConformanceError(
            "execution-conformance promotion gate was weakened"
        )

    raw_inputs = list(report.get("inputs") or [])
    input_paths = [str(item.get("path") or "") for item in raw_inputs]
    if (
        not raw_inputs
        or len(input_paths) != len(set(input_paths))
        or set(input_paths) != {
            "config/execution-semantics-v1.json",
            "config/execution/cn-a-share-cost-v1.json",
            "config/execution/cn-a-share-exchange-rules-v1.json",
            "apps/Vibe-Research/backend/quant_core/execution.py",
            "research/platform-native-strategy/tools/execution_model.py",
            "research/platform-native-strategy/configs/trading/cost-model-v1.json",
            "research/platform-native-strategy/configs/trading/exchange-rules-v1.json",
            "scripts/execution-conformance.py",
        }
    ):
        raise ExecutionConformanceError(
            "execution-conformance input coverage is incomplete"
        )
    for item in raw_inputs:
        path = _inside(root, str(item.get("path") or ""))
        expected = str(item.get("sha256") or "").lower()
        if not SHA256_RE.fullmatch(expected) or _file_sha256(path) != expected:
            raise ExecutionConformanceError(
                f"execution-conformance input drift: {path.name}"
            )

    scenario_ids = [
        str(item.get("id") or "")
        for item in list(contract.get("required_scenarios") or [])
    ]
    if not scenario_ids or len(scenario_ids) != len(set(scenario_ids)):
        raise ExecutionConformanceError(
            "execution-conformance scenario contract is invalid"
        )
    adapters = dict(report.get("adapters") or {})
    summaries = dict(report.get("summaries") or {})
    if set(adapters) != {"quant_core", "platform_native_research"} or set(
        summaries
    ) != set(adapters):
        raise ExecutionConformanceError(
            "execution-conformance adapter coverage is invalid"
        )
    for adapter, raw_results in adapters.items():
        results = dict(raw_results or {})
        if set(results) != set(scenario_ids):
            raise ExecutionConformanceError(
                f"execution-conformance scenarios are incomplete for {adapter}"
            )
        if any(
            dict(result or {}).get("status") not in {"PASS", "FAIL"}
            or not str(dict(result or {}).get("evidence") or "").strip()
            for result in results.values()
        ):
            raise ExecutionConformanceError(
                f"execution-conformance result is invalid for {adapter}"
            )
        summary = dict(summaries.get(adapter) or {})
        passed = sum(
            dict(result)["status"] == "PASS" for result in results.values()
        )
        expected_all_passed = passed == len(scenario_ids)
        if summary != {
            "passed": passed,
            "required": len(scenario_ids),
            "all_required_scenarios_pass": expected_all_passed,
        }:
            raise ExecutionConformanceError(
                f"execution-conformance summary mismatch for {adapter}"
            )
    canonical_passed = bool(
        dict(summaries["quant_core"])["all_required_scenarios_pass"]
    )
    all_passed = all(
        bool(dict(summary)["all_required_scenarios_pass"])
        for summary in summaries.values()
    )
    if report.get("canonical_eligible") is not canonical_passed or report.get(
        "promotion_eligible"
    ) is not all_passed:
        raise ExecutionConformanceError(
            "execution-conformance eligibility summary mismatch"
        )
    expected_common = [
        scenario
        for scenario in scenario_ids
        if all(
            dict(dict(adapters[adapter])[scenario])["status"] == "PASS"
            for adapter in adapters
        )
    ]
    if list(report.get("common_passed") or []) != expected_common:
        raise ExecutionConformanceError(
            "execution-conformance common scenario summary mismatch"
        )
    if not canonical_passed:
        raise ExecutionConformanceError(
            "canonical quant_core did not pass every execution scenario"
        )
    return report


def build_execution_conformance_report(
    platform_root: str | Path,
) -> dict[str, Any]:
    root = Path(platform_root).resolve()
    script = _inside(root, EXECUTION_CONFORMANCE_SCRIPT)
    module_name = "_quant_execution_conformance_" + hashlib.sha256(
        str(script).encode("utf-8")
    ).hexdigest()[:16]
    spec = importlib.util.spec_from_file_location(module_name, script)
    if spec is None or spec.loader is None:
        raise ExecutionConformanceError(
            "execution-conformance runner cannot be loaded"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
        builder = getattr(module, "build_report", None)
        if not callable(builder):
            raise ExecutionConformanceError(
                "execution-conformance runner lacks build_report"
            )
        report = builder()
    except ExecutionConformanceError:
        raise
    except Exception as exc:
        raise ExecutionConformanceError(
            f"execution-conformance run failed: {type(exc).__name__}: {exc}"
        ) from exc
    finally:
        sys.modules.pop(module_name, None)
    return validate_execution_conformance_report(
        report, platform_root=root
    )


def verify_execution_conformance_evidence(
    platform_root: str | Path,
    evidence_path: str | Path,
    expected_file_sha256: str,
) -> dict[str, Any]:
    root = Path(platform_root).resolve()
    path = _inside(root, str(evidence_path))
    expected = str(expected_file_sha256 or "").lower()
    if not SHA256_RE.fullmatch(expected) or _file_sha256(path) != expected:
        raise ExecutionConformanceError(
            "execution-conformance evidence file hash mismatch"
        )
    stored = validate_execution_conformance_report(
        _strict_json(path), platform_root=root
    )
    fresh = build_execution_conformance_report(root)
    if stored != fresh:
        raise ExecutionConformanceError(
            "execution-conformance evidence differs from a fresh deterministic replay"
        )
    return stored
