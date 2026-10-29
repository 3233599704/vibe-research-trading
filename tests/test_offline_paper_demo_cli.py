from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "offline-paper-demo.py"
LF_ATTRIBUTE_LINES = [
    "config/strategy-lab/offline-paper-demo-fixture-v1.schema.json text eol=lf",
    "config/strategy-lab/qmt-compat-sandbox-fixture-v1.schema.json text eol=lf",
    "docs/strategy_lab/QMT_COMPAT_SANDBOX_DEMO.md text eol=lf",
    "research/strategy_lab/offline_paper_demo.py text eol=lf",
    "research/strategy_lab/test/test_offline_paper_demo.py text eol=lf",
    "scripts/offline-paper-demo.py text eol=lf",
    "tests/test_offline_paper_demo_cli.py text eol=lf",
    "config/broker/parent-order-allocation-plan.schema.json text eol=lf",
    "config/broker/parent-fill-allocation.schema.json text eol=lf",
    "config/strategy-lab/pretrade-child-execution-receipt.schema.json text eol=lf",
    "config/strategy-lab/pretrade-execution-batch.schema.json text eol=lf",
    "config/research/research-governance-policy-v1.json text eol=lf",
    "scripts/execution-conformance.py text eol=lf",
    "config/execution-semantics-v1.json text eol=lf",
    "config/strategy-lab/execution-conformance-report.schema.json text eol=lf",
]


def _run(cwd: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [sys.executable, "-B", str(SCRIPT), *arguments],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _assert_path_and_identity_free(output: str) -> None:
    assert str(ROOT).lower() not in output.lower()
    assert re.search(r"[A-Za-z]:\\", output) is None
    username = str(os.environ.get("USERNAME") or "").strip()
    if username:
        assert username.lower() not in output.lower()
    assert "PosixPath(" not in output
    assert "WindowsPath(" not in output
    assert "Traceback" not in output


def _assert_authority_false(result: dict) -> None:
    assert all(
        result[field] is False
        for field in (
            "authoritative_for_execution",
            "demo_authority",
            "formal_admission_eligible",
            "formal_forward_evidence",
            "promotion_eligible",
            "real_orders",
        )
    )
    assert result["broker_accessed"] is False
    assert result["network_accessed"] is False


def test_cli_is_one_line_deterministic_json_from_different_working_directories() -> None:
    first = _run(ROOT)
    second = _run(ROOT / "research")

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout
    assert hashlib.sha256(first.stdout.encode("utf-8")).hexdigest() == (
        # Public edition binds the synthetic versioned T+1 calendar.
        "127b6cc718e9748b474a35ac1ff5d594b62153a8feefaf9807b2caeb7633aa69"
    )
    assert first.stdout.count("\n") == 1
    result = json.loads(first.stdout)
    assert result["ok"] is True
    _assert_authority_false(result)
    assert result["execution_conformance"] == {
        "adapter_reproduction_all_passed": True,
        "authority_mapping": False,
    }
    assert result["cleanup_failed"] is False
    assert result["workspace_cleaned"] is True
    assert result["evidence"]["workspace_cleaned"] is True
    _assert_path_and_identity_free(first.stdout)


def test_cli_rejects_every_argument_with_specific_path_free_error() -> None:
    for argument in ("--keep-output", "output.json", "--real-orders=true"):
        completed = _run(ROOT / "docs", argument)
        assert completed.returncode == 2
        assert completed.stderr == ""
        assert completed.stdout.count("\n") == 1
        result = json.loads(completed.stdout)
        assert result["ok"] is False
        _assert_authority_false(result)
        assert result["error"] == {
            "code": "ARGUMENT_ERROR",
            "message": "offline demo accepts no arguments",
        }
        assert result["cleanup_failed"] is False
        assert result["workspace_cleaned"] is True
        _assert_path_and_identity_free(completed.stdout)


def test_qmt_compat_cli_is_deterministic_reconciled_and_permanently_paper() -> None:
    first = _run(ROOT, "--broker", "QMT_COMPAT_SANDBOX")
    second = _run(ROOT / "research", "--broker", "QMT_COMPAT_SANDBOX")

    assert first.returncode == second.returncode == 0
    assert first.stderr == second.stderr == ""
    assert first.stdout == second.stdout
    assert first.stdout.count("\n") == 1
    result = json.loads(first.stdout)
    assert result["ok"] is True
    _assert_authority_false(result)
    assert result["broker"] == "QMT_COMPAT_SANDBOX"
    assert result["sandbox_adapter_exercised"] is True
    assert result["execution_binding"] == (
        "SHADOW_RECONCILED_NOT_PRIMARY_EXECUTION"
    )
    assert result["real_broker_accessed"] is False
    assert result["qmt_runtime_accessed"] is False
    assert result["xtquant_imported"] is False
    assert result["live_order_capability_exposed"] is False
    assert result["qmt_vendor_certified"] is False
    assert result["certification_status"] == "NOT_RUN_REAL_QMT"
    qmt = result["qmt_compat"]
    assert qmt["main_parent_count"] == qmt["main_filled_order_count"] == 2
    assert qmt["main_fill_quantity_by_code"] == {"510300": 3500, "518880": 3500}
    assert qmt["ledger_reconciled"] is True
    assert qmt["cancel_scenario"] == "CANCELLED"
    assert qmt["reject_scenario"] == "REJECTED"
    assert qmt["out_of_order_buffer_count"] == 2
    assert qmt["duplicate_callback_idempotent"] is True
    assert qmt["disconnect_reconnect_exercised"] is True
    assert qmt["restart_recovered_without_resubmit"] is True
    assert qmt["live_submit_rejected_without_write"] is True
    assert qmt["atomic_snapshot"]["degraded"] is False
    assert qmt["daily_usage"] == {
        "conservative": True,
        "notional": "72000",
        "order_count": 4,
    }
    assert result["cleanup_failed"] is False
    assert result["workspace_cleaned"] is True
    _assert_path_and_identity_free(first.stdout)


def test_demo_text_files_have_explicit_lf_attributes() -> None:
    lines = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert lines[-len(LF_ATTRIBUTE_LINES) :] == LF_ATTRIBUTE_LINES
