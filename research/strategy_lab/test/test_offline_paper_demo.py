from __future__ import annotations

import base64
import builtins
import gzip
import hashlib
import http.client
import importlib
import inspect
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import types

import pytest

from research.strategy_lab import offline_paper_demo as demo


def _write_fixture(
    path: Path,
    mutate,
    *,
    refresh_hash: bool,
    canonical: bool = True,
) -> Path:
    value = json.loads(demo.DEFAULT_FIXTURE.read_text(encoding="utf-8"))
    mutate(value)
    if refresh_hash:
        identity = {key: item for key, item in value.items() if key != "fixture_sha256"}
        value["fixture_sha256"] = hashlib.sha256(
            demo._canonical_bytes(identity)
        ).hexdigest()
    payload = demo._canonical_bytes(value)
    path.write_bytes(payload if canonical else payload + b" ")
    return path


def _controlled_workspace(
    monkeypatch: pytest.MonkeyPatch, temp_root: Path, token: str = "a"
) -> Path:
    workspace = temp_root / f"{demo._WORKSPACE_PREFIX}{token * 32}"
    monkeypatch.setattr(demo, "_workspace_candidate", lambda: (temp_root, workspace))
    return workspace


def _assert_demo_only(value: dict) -> None:
    assert all(
        value[field] is False
        for field in (
            "authoritative_for_execution",
            "demo_authority",
            "formal_admission_eligible",
            "formal_forward_evidence",
            "promotion_eligible",
            "real_orders",
        )
    )
    assert value["broker_accessed"] is False
    assert value["network_accessed"] is False


def test_real_forward_signal_batch_execution_and_d2_valuation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _controlled_workspace(monkeypatch, tmp_path)
    result = demo._run_demo()

    assert result["ok"] is True
    _assert_demo_only(result)
    assert result["classification"] == "DEMO_ONLY_NOT_FORMAL_EVIDENCE"
    assert result["network_isolation_scope"] == (
        "FRESH_CLI_NEW_CONNECTIONS_AND_SUBPROCESSES"
    )
    assert result["preexisting_socket_handles_covered"] is False
    assert result["strategy"] == {
        "engine_id": "quant-platform/diversified-etf-trend/v1",
        "engine_reuse_only": True,
        "source_candidate_status": "FALSIFIED_REDESIGN_REQUIRED",
        "strategy_id": "demo-only-etf-trend-v1",
    }
    assert result["signal"]["target_codes"] == ["510300", "518880"]
    assert result["signal"]["target_weights"] == {
        "510300": 0.35,
        "518880": 0.35,
    }
    assert result["execution"] == {
        "child_intent_count": 2,
        "child_receipt_count": 1,
        "fill_count": 2,
        "parent_order_count": 2,
        "platform_preflight": "PASS",
        "pretrade_status": "PREPARED",
    }
    assert result["ledger"]["checkpoint_count"] == 4
    assert result["ledger"]["positions"] == {"510300": 3500, "518880": 3500}
    assert result["ledger"]["mark_to_market_pnl"] == -3500.0
    assert result["ledger"]["reconciliation_ok"] is True
    assert result["risk"] == {
        "compliant": True,
        "decision": "PASS",
        "mode": "NORMAL",
    }
    assert all(result["idempotency"].values())
    assert result["cleanup_failed"] is False
    assert result["workspace_cleaned"] is True
    assert result["evidence"]["canonical_source_unchanged"] is True
    assert result["evidence"]["workspace_cleaned"] is True
    assert not os.path.lexists(workspace)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        (b'\xef\xbb\xbf{"x":1}', "INVALID_JSON"),
        (b'{"x":NaN}', "NONFINITE_NUMBER"),
        (b'{"x":Infinity}', "NONFINITE_NUMBER"),
        (b'{"x":"\\ud800"}', "INVALID_UNICODE_SCALAR"),
        (b'{"x":1,"x":2}', "DUPLICATE_JSON_KEY"),
        (
            ('{"x":"e\u0301"}').encode("utf-8"),
            "NON_NFC_STRING",
        ),
    ],
)
def test_strict_raw_fixture_rejections(
    tmp_path: Path, payload: bytes, code: str
) -> None:
    path = tmp_path / "bad.json"
    path.write_bytes(payload)
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_fixture(path)
    assert raised.value.code == code


def test_fixture_canonical_depth_size_and_bool_integer_boundaries(
    tmp_path: Path,
) -> None:
    for name, payload in {
        "crlf": demo.DEFAULT_FIXTURE.read_bytes().replace(b"\n", b"\r\n"),
        "multi-lf": demo.DEFAULT_FIXTURE.read_bytes() + b"\n",
    }.items():
        path = tmp_path / f"{name}.json"
        path.write_bytes(payload)
        with pytest.raises(demo.OfflinePaperDemoError) as raised:
            demo._load_fixture(path)
        assert raised.value.code == "FIXTURE_NOT_CANONICAL"

    deep = tmp_path / "deep.json"
    deep.write_bytes(b'{"x":' + b"[" * 129 + b"0" + b"]" * 129 + b"}")
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_fixture(deep)
    assert raised.value.code == "JSON_TOO_DEEP"

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (demo.MAX_FIXTURE_BYTES + 1))
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_fixture(oversized)
    assert raised.value.code == "FIXTURE_TOO_LARGE"

    bool_integer = _write_fixture(
        tmp_path / "bool-integer.json",
        lambda value: value["market"].update({"volume": True}),
        refresh_hash=True,
    )
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_fixture(bool_integer)
    assert raised.value.code == "FIXTURE_SCHEMA_INVALID"


def test_fixture_self_hash_schema_and_all_authority_fields(tmp_path: Path) -> None:
    tampered = _write_fixture(
        tmp_path / "tampered.json",
        lambda value: value["market"].update({"volume": 999999}),
        refresh_hash=False,
    )
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_fixture(tampered)
    assert raised.value.code == "FIXTURE_HASH_MISMATCH"

    for field in demo._AUTHORITY_FIELDS - {"real_orders_enabled"}:
        authority = _write_fixture(
            tmp_path / f"{field}.json",
            lambda value, field=field: value.update({field: True}),
            refresh_hash=True,
        )
        with pytest.raises(demo.OfflinePaperDemoError) as raised:
            demo._load_fixture(authority)
        assert raised.value.code == "DEMO_BOUNDARY_VIOLATION"

    extra_field = _write_fixture(
        tmp_path / "extra-field.json",
        lambda value: value.update({"unexpected": "smuggled"}),
        refresh_hash=True,
    )
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_fixture(extra_field)
    assert raised.value.code == "FIXTURE_SCHEMA_INVALID"

    noncanonical = _write_fixture(
        tmp_path / "noncanonical.json",
        lambda _value: None,
        refresh_hash=False,
        canonical=False,
    )
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_fixture(noncanonical)
    assert raised.value.code == "FIXTURE_NOT_CANONICAL"


def test_snapshot_identity_repackaging_head_and_compressed_drift(
    tmp_path: Path,
) -> None:
    fixture = json.loads(demo.DEFAULT_FIXTURE.read_text(encoding="utf-8"))
    snapshot = dict(fixture["compatibility_snapshot"])

    changed_head = {**snapshot, "source_repository_head": "0" * 40}
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._decode_execution_snapshot(changed_head)
    assert raised.value.code == "COMPATIBILITY_SNAPSHOT_INVALID"

    replacement = b"print('different valid python')\n"
    replacement_gzip = gzip.compress(replacement, mtime=0)
    repacked = {
        **snapshot,
        "execution_model_gzip_base64": base64.b64encode(replacement_gzip).decode(),
        "execution_model_gzip_sha256": hashlib.sha256(replacement_gzip).hexdigest(),
        "execution_model_sha256": hashlib.sha256(replacement).hexdigest(),
    }
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._decode_execution_snapshot(repacked)
    assert raised.value.code == "COMPATIBILITY_SNAPSHOT_INVALID"

    compressed = bytearray(base64.b64decode(snapshot["execution_model_gzip_base64"]))
    compressed[-1] ^= 1
    drift = {
        **snapshot,
        "execution_model_gzip_base64": base64.b64encode(compressed).decode(),
    }
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._decode_execution_snapshot(drift)
    assert raised.value.code == "COMPATIBILITY_SNAPSHOT_INVALID"

    strict_base64 = {
        **snapshot,
        "execution_model_gzip_base64": (
            snapshot["execution_model_gzip_base64"] + "\n"
        ),
    }
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._decode_execution_snapshot(strict_base64)
    assert raised.value.code == "COMPATIBILITY_SNAPSHOT_INVALID"

    repacked_path = _write_fixture(
        tmp_path / "repacked.json",
        lambda value: value.update({"compatibility_snapshot": repacked}),
        refresh_hash=True,
    )
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_fixture(repacked_path)
    assert raised.value.code == "FIXTURE_SCHEMA_INVALID"


@pytest.mark.parametrize("kind", ["trailing", "multi-member", "truncated"])
def test_snapshot_rejects_non_single_complete_gzip_member(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    fixture = json.loads(demo.DEFAULT_FIXTURE.read_text(encoding="utf-8"))
    snapshot = dict(fixture["compatibility_snapshot"])
    original = base64.b64decode(snapshot["execution_model_gzip_base64"])
    if kind == "trailing":
        changed = original + b"trailing"
    elif kind == "multi-member":
        changed = original + gzip.compress(b"second", mtime=0)
    else:
        changed = original[:-8]
    changed_sha = hashlib.sha256(changed).hexdigest()
    monkeypatch.setattr(demo, "ALLOWED_EXECUTION_COMPRESSED_SHA256", changed_sha)
    snapshot["execution_model_gzip_sha256"] = changed_sha
    snapshot["execution_model_gzip_base64"] = base64.b64encode(changed).decode()
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._decode_execution_snapshot(snapshot)
    assert raised.value.code == "COMPATIBILITY_SNAPSHOT_INVALID"


def test_snapshot_compressed_and_decompressed_size_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = json.loads(demo.DEFAULT_FIXTURE.read_text(encoding="utf-8"))
    snapshot = dict(fixture["compatibility_snapshot"])

    compressed = b"x" * (demo.MAX_COMPRESSED_SNAPSHOT_BYTES + 1)
    compressed_sha = hashlib.sha256(compressed).hexdigest()
    monkeypatch.setattr(demo, "ALLOWED_EXECUTION_COMPRESSED_SHA256", compressed_sha)
    oversized_compressed = {
        **snapshot,
        "execution_model_gzip_base64": base64.b64encode(compressed).decode(),
        "execution_model_gzip_sha256": compressed_sha,
    }
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._decode_execution_snapshot(oversized_compressed)
    assert raised.value.code == "COMPATIBILITY_SNAPSHOT_INVALID"

    bomb = gzip.compress(b"x" * (demo.MAX_EXECUTION_PAYLOAD_BYTES + 1), mtime=0)
    bomb_sha = hashlib.sha256(bomb).hexdigest()
    monkeypatch.setattr(demo, "ALLOWED_EXECUTION_COMPRESSED_SHA256", bomb_sha)
    oversized_payload = {
        **snapshot,
        "execution_model_gzip_base64": base64.b64encode(bomb).decode(),
        "execution_model_gzip_sha256": bomb_sha,
    }
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._decode_execution_snapshot(oversized_payload)
    assert raised.value.code == "COMPATIBILITY_SNAPSHOT_INVALID"


def test_schema_importerror_path_is_strict_and_unknown_keywords_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_import = builtins.__import__

    def import_without_jsonschema(name, *args, **kwargs):
        if name == "jsonschema":
            raise ImportError("forced missing jsonschema")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_jsonschema)
    assert demo._external_draft_validator() is None
    assert demo._load_fixture()["schema"] == demo.FIXTURE_SCHEMA

    schema = json.loads(demo.FIXTURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    schema["not"] = {}
    changed_schema = tmp_path / "unknown-keyword.schema.json"
    changed_schema.write_bytes(demo._canonical_bytes(schema))
    monkeypatch.setattr(demo, "FIXTURE_SCHEMA_PATH", changed_schema)
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_fixture()
    assert raised.value.code == "SCHEMA_UNSUPPORTED"


def test_network_and_subprocess_guard_blocks_and_restores() -> None:
    originals = (
        socket.socket,
        socket.SocketType,
        socket.create_connection,
        subprocess.Popen,
        os.system,
    )
    with demo.network_poison_guard():
        with pytest.raises(demo.NetworkPoisonError):
            socket.create_connection(("127.0.0.1", 9), timeout=0.01)
        with pytest.raises(demo.NetworkPoisonError):
            http.client.HTTPConnection("127.0.0.1", 9, timeout=0.01).connect()
        with pytest.raises(demo.SubprocessPoisonError):
            subprocess.run(["not-executed"], check=False)
        with pytest.raises(demo.SubprocessPoisonError):
            os.system("not-executed")
    assert (
        socket.socket,
        socket.SocketType,
        socket.create_connection,
        subprocess.Popen,
        os.system,
    ) == originals


def test_private_fresh_cli_surface_has_no_temp_path_argument() -> None:
    assert not hasattr(demo, "run_demo")
    assert list(inspect.signature(demo._run_demo).parameters) == []


def test_mkdir_post_create_exception_is_cleaned_without_residue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _controlled_workspace(monkeypatch, tmp_path)
    original_mkdir = Path.mkdir

    def create_then_fail(path: Path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        if path == workspace:
            raise RuntimeError("PRIMARY_FAILURE")
        return result

    monkeypatch.setattr(Path, "mkdir", create_then_fail)
    with pytest.raises(RuntimeError, match="PRIMARY_FAILURE"):
        demo._run_demo()
    assert not os.path.lexists(workspace)


def test_primary_error_survives_cleanup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _controlled_workspace(monkeypatch, tmp_path)

    def primary(*_args, **_kwargs):
        raise demo.OfflinePaperDemoError("PRIMARY_FAILURE", "primary")

    def cleanup_failure(*_args, **_kwargs):
        raise PermissionError("cleanup failed")

    monkeypatch.setattr(demo, "_execute", primary)
    monkeypatch.setattr(demo, "_cleanup_workspace", cleanup_failure)
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._run_demo()
    assert raised.value.code == "PRIMARY_FAILURE"
    assert "workspace cleanup also failed" in getattr(raised.value, "__notes__", [])
    failure = demo.failure_document(raised.value)
    assert failure["error"] == {"code": "PRIMARY_FAILURE", "message": "primary"}
    assert failure["cleanup_failed"] is True
    assert failure["workspace_cleaned"] is False
    line = demo.canonical_json_line(failure)
    assert line.count("\n") == 0
    assert str(workspace) not in line
    assert "PermissionError" not in line
    assert os.path.lexists(workspace)
    shutil.rmtree(workspace)


def test_primary_error_with_successful_cleanup_reports_clean_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _controlled_workspace(monkeypatch, tmp_path)

    def primary(*_args, **_kwargs):
        raise demo.OfflinePaperDemoError("PRIMARY_FAILURE", "primary")

    monkeypatch.setattr(demo, "_execute", primary)
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._run_demo()
    failure = demo.failure_document(raised.value)
    assert failure["error"] == {"code": "PRIMARY_FAILURE", "message": "primary"}
    assert failure["cleanup_failed"] is False
    assert failure["workspace_cleaned"] is True
    assert not os.path.lexists(workspace)


def test_cleanup_only_error_reports_unclean_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _controlled_workspace(monkeypatch, tmp_path)

    monkeypatch.setattr(demo, "_execute", lambda *_args, **_kwargs: {"evidence": {}})
    monkeypatch.setattr(
        demo,
        "_cleanup_workspace",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError("cleanup")),
    )
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._run_demo()
    failure = demo.failure_document(raised.value)
    assert failure["error"] == {
        "code": "CLEANUP_FAILED",
        "message": "demo workspace cleanup failed",
    }
    assert failure["cleanup_failed"] is True
    assert failure["workspace_cleaned"] is False
    assert os.path.lexists(workspace)
    shutil.rmtree(workspace)


def test_keyboard_interrupt_is_cleaned_and_not_swallowed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _controlled_workspace(monkeypatch, tmp_path)

    def interrupted(*_args, **_kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(demo, "_execute", interrupted)
    with pytest.raises(KeyboardInterrupt):
        demo._run_demo()
    assert not os.path.lexists(workspace)


def test_source_mutation_has_priority_and_chains_primary_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    temp_root = tmp_path / "temp"
    temp_root.mkdir()
    workspace = _controlled_workspace(monkeypatch, temp_root)
    fake_root = tmp_path / "source"
    registry = fake_root / "config" / "strategy-lab"
    registry.mkdir(parents=True)
    canonical = registry / "canonical-forward-runner-registry.json"
    test_registry = registry / "forward-test-registry.json"
    canonical.write_text("before", encoding="utf-8")
    test_registry.write_text("unchanged", encoding="utf-8")
    monkeypatch.setattr(demo, "ROOT", fake_root)

    def primary(*_args, **_kwargs):
        canonical.write_text("after", encoding="utf-8")
        raise demo.OfflinePaperDemoError("PRIMARY_FAILURE", "primary")

    monkeypatch.setattr(demo, "_execute", primary)
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._run_demo()
    assert raised.value.code == "CANONICAL_SOURCE_MUTATED"
    assert isinstance(raised.value.__cause__, demo.OfflinePaperDemoError)
    assert raised.value.__cause__.code == "PRIMARY_FAILURE"
    assert not os.path.lexists(workspace)


def test_source_state_records_nested_empty_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protected = tmp_path / "data" / "quant-lab"
    protected.mkdir(parents=True)
    monkeypatch.setattr(demo, "_PROTECTED_SOURCE_PATHS", ("data/quant-lab",))
    before = demo._source_state(tmp_path)
    (protected / "empty" / "nested").mkdir(parents=True)
    after = demo._source_state(tmp_path)
    assert before != after


def test_unified_boundary_preflight_runs_before_runner_or_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = demo._load_fixture()
    api = demo._product_api()
    runner_calls = 0
    commit_calls = 0

    class ForbiddenRunner:
        def __init__(self, *args, **kwargs) -> None:
            nonlocal runner_calls
            runner_calls += 1

    api.ForwardPaperRunner = ForbiddenRunner
    original_commit = api.PersistentLedgerStore.commit

    def counted_commit(*args, **kwargs):
        nonlocal commit_calls
        commit_calls += 1
        return original_commit(*args, **kwargs)

    monkeypatch.setattr(api.PersistentLedgerStore, "commit", counted_commit)
    monkeypatch.setattr(demo, "_product_api", lambda: api)
    original_policy = demo._platform_policy

    def authority_policy() -> dict:
        return {**original_policy(), "authoritative_for_execution": True}

    monkeypatch.setattr(demo, "_platform_policy", authority_policy)
    workspace = tmp_path / "preflight"
    workspace.mkdir()
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._execute(workspace, fixture)
    assert raised.value.code == "DEMO_BOUNDARY_VIOLATION"
    assert runner_calls == 0
    assert commit_calls == 0
    assert not (workspace / "runtime" / demo.STRATEGY_ID / "ledger").exists()
    assert not (workspace / "runtime" / "_daily_batches").exists()


def test_daily_request_authority_is_rejected_before_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = demo._load_fixture()
    api = demo._product_api()
    runner_calls = 0
    commit_calls = 0

    class ForbiddenRunner:
        def __init__(self, *args, **kwargs) -> None:
            nonlocal runner_calls
            runner_calls += 1

    original_commit = api.PersistentLedgerStore.commit

    def counted_commit(*args, **kwargs):
        nonlocal commit_calls
        commit_calls += 1
        return original_commit(*args, **kwargs)

    api.ForwardPaperRunner = ForbiddenRunner
    monkeypatch.setattr(api.PersistentLedgerStore, "commit", counted_commit)
    monkeypatch.setattr(demo, "_product_api", lambda: api)
    original_requests = demo._daily_requests

    def authority_requests(*args, **kwargs):
        signal, execution, valuation = original_requests(*args, **kwargs)
        execution["real_orders_enabled"] = True
        return signal, execution, valuation

    monkeypatch.setattr(demo, "_daily_requests", authority_requests)
    workspace = tmp_path / "request-preflight"
    workspace.mkdir()
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._execute(workspace, fixture)
    assert raised.value.code == "DEMO_BOUNDARY_VIOLATION"
    assert runner_calls == 0
    assert commit_calls == 0
    assert not (workspace / "runtime" / demo.STRATEGY_ID / "ledger").exists()


@pytest.mark.parametrize(
    ("label", "field"),
    [
        ("registry", "real_orders"),
        ("binding", "demo_authority"),
        ("recovery_evidence", "formal_forward_evidence"),
        ("temporal_evidence", "promotion_eligible"),
    ],
)
def test_generated_authority_fields_are_rejected_before_persistent_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    field: str,
) -> None:
    fixture = demo._load_fixture()
    api = demo._product_api()
    runner_calls = 0
    commit_calls = 0

    class ForbiddenRunner:
        def __init__(self, *args, **kwargs) -> None:
            nonlocal runner_calls
            runner_calls += 1

    original_commit = api.PersistentLedgerStore.commit

    def counted_commit(*args, **kwargs):
        nonlocal commit_calls
        commit_calls += 1
        return original_commit(*args, **kwargs)

    api.ForwardPaperRunner = ForbiddenRunner
    monkeypatch.setattr(api.PersistentLedgerStore, "commit", counted_commit)
    monkeypatch.setattr(demo, "_product_api", lambda: api)
    original_materialize = demo._materialize_platform

    def tainted_materialize(*args, **kwargs):
        paths = original_materialize(*args, **kwargs)
        paths["boundary_documents"][label][field] = True
        return paths

    monkeypatch.setattr(demo, "_materialize_platform", tainted_materialize)
    workspace = tmp_path / f"preflight-{label}"
    workspace.mkdir()
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._execute(workspace, fixture)
    assert raised.value.code == "DEMO_BOUNDARY_VIOLATION"
    assert runner_calls == 0
    assert commit_calls == 0
    assert not (workspace / "runtime" / demo.STRATEGY_ID / "ledger").exists()


def test_execution_conformance_drift_is_rejected_by_fresh_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = demo._load_fixture()
    api = demo._product_api()
    paths = demo._materialize_platform(tmp_path, fixture, api)
    module = importlib.import_module("quant_core.execution_conformance")
    stored = dict(paths["execution_conformance"])

    def drifted_fresh(_root):
        return {**stored, "promotion_eligible": not stored["promotion_eligible"]}

    monkeypatch.setattr(module, "build_execution_conformance_report", drifted_fresh)
    relative = "demo/evidence/execution-conformance.json"
    evidence_path = paths["platform"] / relative
    with pytest.raises(
        module.ExecutionConformanceError,
        match="fresh deterministic replay",
    ):
        module.verify_execution_conformance_evidence(
            paths["platform"], relative, demo._file_sha256(evidence_path)
        )


def test_false_technical_conformance_is_rejected_before_runner_or_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = demo._load_fixture()
    api = demo._product_api()
    runner_calls = 0
    commit_calls = 0

    class ForbiddenRunner:
        def __init__(self, *args, **kwargs) -> None:
            nonlocal runner_calls
            runner_calls += 1

    original_commit = api.PersistentLedgerStore.commit

    def counted_commit(*args, **kwargs):
        nonlocal commit_calls
        commit_calls += 1
        return original_commit(*args, **kwargs)

    api.ForwardPaperRunner = ForbiddenRunner
    monkeypatch.setattr(api.PersistentLedgerStore, "commit", counted_commit)
    monkeypatch.setattr(demo, "_product_api", lambda: api)
    original_materialize = demo._materialize_platform

    def false_conformance(*args, **kwargs):
        paths = original_materialize(*args, **kwargs)
        paths["execution_conformance"]["promotion_eligible"] = False
        return paths

    monkeypatch.setattr(demo, "_materialize_platform", false_conformance)
    workspace = tmp_path / "false-conformance-preflight"
    workspace.mkdir()
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._execute(workspace, fixture)
    assert raised.value.code == "DEMO_BOUNDARY_VIOLATION"
    assert runner_calls == 0
    assert commit_calls == 0
    assert not (workspace / "runtime" / demo.STRATEGY_ID / "ledger").exists()


def test_conformance_technical_true_never_maps_to_demo_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _controlled_workspace(monkeypatch, tmp_path, token="b")
    result = demo._run_demo()
    assert result["execution_conformance"] == {
        "adapter_reproduction_all_passed": True,
        "authority_mapping": False,
    }
    _assert_demo_only(result)


def test_qmt_fixture_has_raw_logical_and_draft_202012_identity() -> None:
    raw = demo.QMT_FIXTURE.read_bytes()
    fixture = demo._load_qmt_fixture()
    assert hashlib.sha256(raw).hexdigest() == demo.QMT_FIXTURE_RAW_SHA256
    identity = {
        key: value for key, value in fixture.items() if key != "fixture_sha256"
    }
    assert hashlib.sha256(demo._canonical_bytes(identity)).hexdigest() == fixture[
        "fixture_sha256"
    ]
    assert fixture["broker"] == "QMT_COMPAT_SANDBOX"
    assert sorted(item["sequence"] for item in fixture["callbacks"]) == list(
        range(1, 13)
    )
    schema = json.loads(demo.QMT_FIXTURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_qmt_fixture_raw_drift_fails_closed(tmp_path: Path) -> None:
    changed = tmp_path / "changed-qmt-fixture.json"
    value = json.loads(demo.QMT_FIXTURE.read_text(encoding="utf-8"))
    value["callbacks"][0]["traded_volume"] = 1
    changed.write_bytes(demo._canonical_bytes(value))
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._load_qmt_fixture(changed)
    assert raised.value.code == "FIXTURE_RAW_HASH_MISMATCH"


def test_qmt_runtime_import_is_poisoned_and_restored() -> None:
    original = builtins.__import__
    with demo.qmt_runtime_poison_guard():
        with pytest.raises(demo.OfflinePaperDemoError) as raised:
            __import__("xtquant")
        assert raised.value.code == "QMT_RUNTIME_FORBIDDEN"
        assert __import__("json") is json
    assert builtins.__import__ is original


@pytest.mark.parametrize(
    ("module_name", "token"),
    [("xtquant", "d"), ("xtquant.xttrader", "e")],
)
def test_preloaded_qmt_runtime_blocks_demo_and_failure_document_is_honest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    module_name: str,
    token: str,
) -> None:
    workspace = _controlled_workspace(monkeypatch, tmp_path, token=token)
    monkeypatch.setitem(sys.modules, module_name, types.ModuleType(module_name))
    with pytest.raises(demo.OfflinePaperDemoError) as raised:
        demo._run_qmt_compat_demo()
    assert raised.value.code == "QMT_RUNTIME_PRELOADED"
    failure = demo.failure_document(
        raised.value, broker="QMT_COMPAT_SANDBOX"
    )
    assert failure["xtquant_imported"] is True
    assert failure["qmt_runtime_accessed"] is True
    assert failure["platform_durability_certified"] is False
    assert failure["durability_certification_status"] == "NOT_POWER_LOSS_CERTIFIED"
    assert failure["real_orders"] is False
    assert failure["workspace_cleaned"] is True
    assert not os.path.lexists(workspace)


def test_qmt_compat_demo_reconciles_shadow_and_cleans_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _controlled_workspace(monkeypatch, tmp_path, token="c")
    result = demo._run_qmt_compat_demo()
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
    assert result["platform_durability_certified"] is False
    assert result["durability_certification_status"] == "NOT_POWER_LOSS_CERTIFIED"
    assert result["qmt_compat"]["ledger_reconciled"] is True
    assert result["qmt_compat"]["restart_recovered_without_resubmit"] is True
    assert result["qmt_compat"]["atomic_snapshot"]["degraded"] is False
    _assert_demo_only(result)
    assert result["cleanup_failed"] is False
    assert result["workspace_cleaned"] is True
    assert not os.path.lexists(workspace)
    assert list(tmp_path.iterdir()) == []


def test_qmt_shadow_failure_path_closes_every_registered_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    closed: list[str] = []

    class _AdapterContext:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback) -> None:
            del exc_type, exc, traceback
            closed.append("closed")

    def fail_after_register(api, workspace, qmt_fixture, allocation, ledger, adapters):
        del api, workspace, qmt_fixture, allocation, ledger
        adapters.enter_context(_AdapterContext())
        raise RuntimeError("fault-injected shadow failure")

    monkeypatch.setattr(demo, "_qmt_compat_shadow_managed", fail_after_register)
    with pytest.raises(RuntimeError, match="fault-injected"):
        demo._qmt_compat_shadow(None, tmp_path, {}, {}, None)
    assert closed == ["closed"]
