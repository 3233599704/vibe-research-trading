"""Formal, recoverable forward-paper runner built on the canonical ledger.

This module consumes already-frozen strategy decisions.  It never generates a
signal, contacts a broker, or permits historical backfill.  Inputs must be
content-addressed DataCatalog revisions and every state transition is either
immutable or an atomic pointer to immutable content.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time as time_module
from contextlib import contextmanager
from datetime import date, datetime, time
from functools import wraps
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .data_catalog import DataCatalog, DataCatalogError
from .data_quality import (
    DataQualityError,
    resolve_p1_data_quality_policy,
    verify_p1_quality_attestation,
)
from .execution import SimulationLedger
from .forward_performance import calculate_forward_performance
from .forward_admission import (
    I7_STRATEGY_ID,
    P1_STRATEGY_ID,
    SUPPORTED_FORMAL_ADMISSION_STRATEGIES,
    ForwardAdmissionError,
    verify_forward_admission,
)
from .formal_forward_materializer import (
    FormalForwardMaterializationError,
    load_and_materialize_formal_forward_inputs,
)
from .provider_readiness import (
    ProviderReadinessError,
    resolve_formal_data_readiness_policy,
)
from .persistence import LedgerPersistenceError, LedgerReadOnlyError, PersistentLedgerStore
from .platform_portfolio import (
    PLATFORM_PORTFOLIO_ASSESSMENT_SCHEMA,
    PlatformPortfolioPolicy,
    PlatformPortfolioSupervisor,
)
from .portfolio_stress import (
    PORTFOLIO_STRESS_ASSESSMENT_SCHEMA,
    PortfolioStressPolicy,
    PortfolioStressSupervisor,
)
from .provider_contract import ProviderDeliveryStore
from .liquidity import derive_liquidity_evidence
from .order_allocation import (
    OrderAllocationError,
    PARENT_ORDER_PLAN_SCHEMA,
    validate_parent_order_plan,
)
from .execution_orchestrator import (
    PRETRADE_BATCH_SCHEMA,
    ExecutionOrchestrationError,
    build_pretrade_child_receipt,
    validate_pretrade_child_receipt,
    validate_pretrade_execution_batch,
)
from .execution_conformance import (
    EXECUTION_CONFORMANCE_SNAPSHOT_PATHS,
    ExecutionConformanceError,
    verify_execution_conformance_evidence,
)
from .portfolio_risk import PortfolioRiskPolicy
from .promotion import evaluate_promotion
from .research_registry import (
    ResearchRegistryError,
    resolve_research_governance_policy,
)
from .provenance import sha256_digest


FORWARD_SIGNAL_SCHEMA = "quant-platform/forward-signal/v1"
FORWARD_SIGNAL_RECORD_SCHEMA = "quant-platform/forward-signal-record/v1"
FORWARD_RUN_RECEIPT_SCHEMA = "quant-platform/forward-run-receipt/v5"
FORWARD_OBSERVATION_RECEIPT_SCHEMA = "quant-platform/forward-observation-receipt/v3"
FORWARD_STATUS_SCHEMA = "quant-platform/forward-paper-status/v1"
MARKET_SESSION_SCHEMA = "quant-platform/market-session/v2"
SHANGHAI = ZoneInfo("Asia/Shanghai")
HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
STRATEGY_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
EVIDENCE_SCHEMAS = {
    "recovery_drill": "quant-platform/recovery-drill/v1",
    "temporal_bias_audit": "quant-platform/temporal-bias-audit/v1",
}
REQUIRED_RECOVERY_DRILL_CHECKS = {
    "ACTIVATION_COMMITTED",
    "EXECUTION_RECONCILED",
    "PRE_FAILURE_READY",
    "SNAPSHOT_ISOLATED_FROM_LIVE_MUTATION",
    "OLD_OPERATION_RETRY_DID_NOT_REWIND",
    "UNCOMMITTED_ORPHAN_IGNORED",
    "ORPHAN_REPLAY_CONTENT_IDEMPOTENT",
    "CORRUPTION_DETECTED",
    "FALLBACK_IS_READ_ONLY",
    "WRITE_BLOCKED_BEFORE_ACK",
    "EXACT_CHECKPOINT_SELECTED",
    "EXACT_SNAPSHOT_RESTORED",
    "ACKNOWLEDGED_TO_READY",
}
REQUIRED_TEMPORAL_AUDIT_CHECKS = {
    "DETERMINISTIC_REPEAT",
    "STARTUP_HISTORY_INVARIANCE",
    "FUTURE_ROW_REJECTED",
    "MISSING_SESSION_REJECTED",
    "SCHEMA_SMUGGLING_REJECTED",
    "FUTURE_EVENT_DATE_REJECTED",
}
CANONICAL_FORWARD_REGISTRY_PATH = (
    "config/strategy-lab/canonical-forward-runner-registry.json"
)
PLATFORM_PORTFOLIO_POLICY_PATH = "config/risk/platform-portfolio-policy-v1.json"
PORTFOLIO_STRESS_POLICY_PATH = "config/risk/portfolio-stress-policy-v1.json"
PARENT_ORDER_ALLOCATION_SNAPSHOT_PATHS = {
    "apps/Vibe-Research/backend/quant_core/order_allocation.py",
    "config/broker/parent-order-allocation-plan.schema.json",
    "config/broker/parent-fill-allocation.schema.json",
}
PRETRADE_ORCHESTRATION_SNAPSHOT_PATHS = {
    "apps/Vibe-Research/backend/quant_core/execution_orchestrator.py",
    "config/strategy-lab/pretrade-child-execution-receipt.schema.json",
    "config/strategy-lab/pretrade-execution-batch.schema.json",
}
FORWARD_ADMISSION_SNAPSHOT_PATHS = {
    "apps/Vibe-Research/backend/quant_core/forward_admission.py",
    "scripts/approve-forward-candidate.py",
    "scripts/approve-p1-forward-candidate.py",
    "config/strategy-lab/formal-forward-admission.schema.json",
}
PLATFORM_PORTFOLIO_PREFLIGHT_SCHEMA = "quant-platform/platform-portfolio-preflight/v5"


class ForwardPaperError(RuntimeError):
    pass


class ForwardRegistrationError(ForwardPaperError):
    pass


class ForwardDataError(ForwardPaperError):
    pass


class ForwardConflictError(ForwardPaperError):
    pass


class ForwardHaltedError(ForwardPaperError):
    pass


def _locked_mutation(method):
    @wraps(method)
    def wrapped(self, strategy_id: str, *args, **kwargs):
        normalized = str(strategy_id).strip().lower()
        if not STRATEGY_ID_RE.fullmatch(normalized):
            raise ForwardRegistrationError("invalid strategy_id")
        with self._mutation_lock(normalized):
            return method(self, normalized, *args, **kwargs)

    return wrapped


def _timestamp(value: str | datetime) -> datetime:
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
    except (TypeError, ValueError) as exc:
        raise ForwardPaperError(f"invalid timezone-aware timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise ForwardPaperError("timestamps must include a timezone")
    return parsed


def _day(value: Any) -> date:
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ForwardPaperError(f"invalid ISO date: {value}") from exc


def _hash(value: Any, label: str) -> str:
    normalized = str(value or "").lower()
    if not HASH_RE.fullmatch(normalized):
        raise ForwardRegistrationError(f"{label} must be a SHA-256 digest")
    return normalized


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _portable_source_sha256(path: Path) -> str:
    payload = path.read_bytes()
    if b"\x00" not in payload:
        payload = payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(payload).hexdigest()


def _signal_risk_metadata(
    spec: dict[str, Any],
    signal: dict[str, Any],
    *,
    required_codes: set[str],
) -> dict[str, dict[str, str]]:
    policy = dict(dict(spec["execution_config"])["portfolio_risk_policy"])
    if policy.get("asset_metadata_source") != "SIGNAL_DECISION_EVIDENCE":
        metadata = {
            str(code): {
                "sector": str(dict(item).get("sector") or "UNCLASSIFIED"),
                "correlation_cluster": str(
                    dict(item).get("correlation_cluster") or "UNCLASSIFIED"
                ),
            }
            for code, item in dict(policy.get("asset_metadata") or {}).items()
        }
    else:
        evidence = dict(signal.get("decision_evidence") or {})
        if (
            evidence.get("schema")
            != "quant-platform/forward-only-multifactor-risk-overlay-decision/v1"
            or evidence.get("engine_id")
            != "quant-platform/forward-only-multifactor-risk-overlay/v1"
        ):
            raise ForwardDataError("dynamic risk metadata lacks I7 decision evidence")
        cutoff = _timestamp(str(evidence.get("signal_cutoff_at") or ""))
        metadata = {}
        for raw_code, raw in dict(evidence.get("risk_metadata") or {}).items():
            code = str(raw_code or "")
            item = dict(raw or {})
            if set(item) != {"sector", "correlation_cluster", "available_at"}:
                raise ForwardDataError(
                    f"dynamic risk metadata fields are invalid: {code or '<empty>'}"
                )
            sector = str(item.get("sector") or "")
            cluster = str(item.get("correlation_cluster") or "")
            if (
                not code
                or not sector
                or not cluster
                or sector == "UNCLASSIFIED"
                or cluster == "UNCLASSIFIED"
                or _timestamp(str(item.get("available_at") or "")) > cutoff
            ):
                raise ForwardDataError(
                    f"dynamic risk metadata is missing or unavailable: {code or '<empty>'}"
                )
            metadata[code] = {
                "sector": sector,
                "correlation_cluster": cluster,
            }
    missing = sorted(required_codes - set(metadata))
    if missing:
        raise ForwardDataError(
            "risk metadata is missing for target/held assets: " + ", ".join(missing)
        )
    return metadata


def _bind_signal_risk_metadata(
    spec: dict[str, Any], ledger: SimulationLedger, signal: dict[str, Any]
) -> dict[str, Any] | None:
    policy = dict(dict(spec["execution_config"])["portfolio_risk_policy"])
    if policy.get("asset_metadata_source") != "SIGNAL_DECISION_EVIDENCE":
        return None
    metadata = _signal_risk_metadata(
        spec,
        signal,
        required_codes=set(signal.get("target_codes") or [])
        | set(ledger.position_quantities),
    )
    return ledger.bind_point_in_time_asset_metadata(
        metadata,
        evidence_sha256=_hash(
            signal.get("signal_sha256"), "dynamic risk metadata signal_sha256"
        ),
    )


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(
            payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
        ),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _immutable_json(path: Path, payload: Any) -> None:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_text(encoding="utf-8") != encoded:
            raise ForwardConflictError(f"immutable forward record conflict: {path}")
        return
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temporary.write_text(encoded, encoding="utf-8")
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {constant}")
            ),
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise ForwardPaperError(f"JSON record is unreadable: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ForwardPaperError(f"JSON record must be an object: {path}")
    return value


def _hashed_record(path: Path, hash_field: str) -> dict[str, Any]:
    payload = _read_json(path)
    expected = str(payload.get(hash_field) or "")
    identity = {key: value for key, value in payload.items() if key != hash_field}
    if not expected or sha256_digest(identity) != expected:
        raise ForwardPaperError(f"record hash mismatch: {path}")
    return payload


class ForwardPaperRunner:
    """Canonical daily paper runner for formally registered strategies."""

    def __init__(
        self,
        *,
        platform_root: str | Path,
        runtime_root: str | Path,
        catalog_root: str | Path,
        registry_path: str | Path | None = None,
        canonical_replayers: dict[tuple[str, str], Any] | None = None,
    ) -> None:
        self.platform_root = Path(platform_root).expanduser().resolve()
        self.runtime_root = Path(runtime_root).expanduser().resolve()
        self.catalog = DataCatalog(catalog_root)
        self.provider_store = ProviderDeliveryStore(
            platform_root=self.platform_root,
            catalog_root=self.catalog.root,
        )
        self.canonical_replayers = dict(canonical_replayers or {})
        self.registry_path = (
            Path(registry_path).expanduser().resolve()
            if registry_path is not None
            else self.platform_root / CANONICAL_FORWARD_REGISTRY_PATH
        )

    def _inside_platform(self, relative: str) -> Path:
        path = (self.platform_root / relative).resolve()
        try:
            path.relative_to(self.platform_root)
        except ValueError as exc:
            raise ForwardRegistrationError(f"registered path escapes platform root: {relative}") from exc
        return path

    def _registry(self) -> dict[str, Any]:
        registry = _read_json(self.registry_path)
        expected_fields = {
            "schema_version",
            "registry_id",
            "runner",
            "mode",
            "real_orders",
            "registration_status",
            "registration_note",
            "experiments",
        }
        if set(registry) != expected_fields:
            raise ForwardRegistrationError(
                "canonical forward registry fields do not match its schema"
            )
        if int(registry.get("schema_version") or 0) != 1:
            raise ForwardRegistrationError("unsupported forward registry schema")
        if (
            registry.get("registry_id") != "canonical-forward-runner-registry-v1"
            or registry.get("runner") != "quant_core.forward_paper/v1"
            or registry.get("mode") != "PAPER"
            or registry.get("real_orders") is not False
        ):
            raise ForwardRegistrationError("forward registry must be PAPER-only")
        experiments = list(registry.get("experiments") or [])
        registration_status = str(registry.get("registration_status") or "")
        if registration_status not in {
            "WAITING_FOR_CLEAN_FROZEN_EVIDENCE",
            "READY_FOR_OPERATOR_APPROVAL",
            "HAS_ACTIVE_EXPERIMENTS",
        } or not str(registry.get("registration_note") or "").strip():
            raise ForwardRegistrationError("canonical forward registry status is invalid")
        if experiments and registration_status != "HAS_ACTIVE_EXPERIMENTS":
            raise ForwardRegistrationError(
                "non-empty canonical registry must declare HAS_ACTIVE_EXPERIMENTS"
            )
        if not experiments and registration_status == "HAS_ACTIVE_EXPERIMENTS":
            raise ForwardRegistrationError(
                "empty canonical registry cannot declare active experiments"
            )
        ids = [str(item.get("strategy_id") or "") for item in experiments]
        if any(not STRATEGY_ID_RE.fullmatch(item) for item in ids) or len(ids) != len(set(ids)):
            raise ForwardRegistrationError("forward registry contains invalid or duplicate strategy ids")
        return registry

    def _experiment(self, strategy_id: str) -> dict[str, Any]:
        strategy_id = str(strategy_id).strip().lower()
        registry = self._registry()
        matches = [
            dict(item)
            for item in list(registry.get("experiments") or [])
            if str(item.get("strategy_id")) == strategy_id
        ]
        if len(matches) != 1:
            raise ForwardRegistrationError(f"strategy is not formally registered: {strategy_id}")
        spec = matches[0]
        spec["registry_sha256"] = sha256_digest(registry)
        try:
            return self._validate_spec(spec)
        except ForwardPaperError:
            raise
        except (KeyError, TypeError, ValueError, ArithmeticError, OSError) as exc:
            raise ForwardRegistrationError(
                f"registered strategy failed validation: {type(exc).__name__}: {exc}"
            ) from exc

    def _validate_spec(self, spec: dict[str, Any]) -> dict[str, Any]:
        strategy_id = str(spec.get("strategy_id") or "")
        if not STRATEGY_ID_RE.fullmatch(strategy_id):
            raise ForwardRegistrationError("invalid strategy_id")
        historical_gate = str(spec.get("historical_research_gate") or "")
        if historical_gate == "REGISTERED_HISTORICAL_EVIDENCE":
            raise ForwardRegistrationError(
                "LEGACY_V5_FORMAL_ADMISSION_FORBIDDEN: v5 evidence is "
                "historical-accounting only"
            )
        if historical_gate == "ALLOCATED_V6_STUDY":
            raise ForwardRegistrationError(
                "SELECTION_BRIDGE_REQUIRED: allocation alone cannot create "
                "formal forward evidence"
            )
        if spec.get("approval_status") != "ACTIVE":
            raise ForwardRegistrationError(f"{strategy_id} is not ACTIVE")
        expected_code_state = (
            "CLEAN_FROZEN_SCOPE"
            if strategy_id in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
            and strategy_id != P1_STRATEGY_ID
            else "CLEAN_COMMIT"
        )
        if (
            spec.get("frozen") is not True
            or spec.get("code_state") != expected_code_state
        ):
            raise ForwardRegistrationError(f"{strategy_id} is not frozen at a clean commit")
        if spec.get("real_orders") is not False:
            raise ForwardRegistrationError(f"{strategy_id} must explicitly disable real orders")
        if spec.get("execution_adapter_id") != "quant_core":
            raise ForwardRegistrationError(f"{strategy_id} must use the canonical quant_core adapter")
        if strategy_id in SUPPORTED_FORMAL_ADMISSION_STRATEGIES:
            try:
                verify_forward_admission(self.platform_root, spec)
            except ForwardAdmissionError as exc:
                raise ForwardRegistrationError(
                    f"{strategy_id} admission evidence is invalid: {exc}"
                ) from exc

        contract = _read_json(self.platform_root / "config" / "execution-semantics-v1.json")
        if (
            contract.get("canonical_adapter_id") != "quant_core"
            or contract.get("new_strategy_runs_must_use_canonical_adapter") is not True
        ):
            raise ForwardRegistrationError("canonical execution contract is not active")
        try:
            execution_conformance = verify_execution_conformance_evidence(
                self.platform_root,
                str(spec.get("execution_conformance_path") or ""),
                str(spec.get("execution_conformance_sha256") or ""),
            )
        except ExecutionConformanceError as exc:
            raise ForwardRegistrationError(str(exc)) from exc

        approved_at = _timestamp(str(spec.get("approved_at") or ""))
        first_allowed = _day(spec.get("first_allowed_signal_date"))
        if first_allowed <= approved_at.astimezone(SHANGHAI).date():
            raise ForwardRegistrationError(
                "first_allowed_signal_date must be strictly after approval"
            )
        initial_cash = float(spec.get("initial_cash") or 0)
        if not math.isfinite(initial_cash) or initial_cash <= 0:
            raise ForwardRegistrationError("initial_cash must be positive")
        if int(spec.get("minimum_trading_days") or 0) <= 0:
            raise ForwardRegistrationError("minimum_trading_days must be positive")
        if int(spec.get("minimum_observation_count") or 0) <= 0:
            raise ForwardRegistrationError("minimum_observation_count must be positive")
        if str(spec.get("signal_frequency") or "") not in {"daily", "weekly", "monthly"}:
            raise ForwardRegistrationError("signal_frequency must be daily, weekly or monthly")
        for label in ("recovery_drill", "temporal_bias_audit"):
            evidence_path = self._inside_platform(str(spec.get(f"{label}_path") or ""))
            evidence_sha = _hash(spec.get(f"{label}_sha256"), f"{label}_sha256")
            if not evidence_path.is_file() or _file_sha256(evidence_path) != evidence_sha:
                raise ForwardRegistrationError(f"{label} evidence hash mismatch")
            evidence = _read_json(evidence_path)
            if (
                evidence.get("schema") != EVIDENCE_SCHEMAS[label]
                or evidence.get("passed") is not True
            ):
                raise ForwardRegistrationError(f"{label} evidence did not pass")
            engine_field = (
                "drill_engine" if label == "recovery_drill" else "audit_engine"
            )
            digest_field = (
                "drill_sha256" if label == "recovery_drill" else "audit_sha256"
            )
            if not str(evidence.get(engine_field) or "").strip():
                raise ForwardRegistrationError(f"{label} evidence engine is missing")
            checks = [dict(item) for item in list(evidence.get("checks") or [])]
            check_codes = [str(item.get("code") or "") for item in checks]
            if (
                not checks
                or any(not code for code in check_codes)
                or len(check_codes) != len(set(check_codes))
                or any(item.get("passed") is not True for item in checks)
            ):
                raise ForwardRegistrationError(
                    f"{label} evidence checks are incomplete or did not pass"
                )
            required_checks = (
                REQUIRED_RECOVERY_DRILL_CHECKS
                if label == "recovery_drill"
                else REQUIRED_TEMPORAL_AUDIT_CHECKS
            )
            missing_checks = sorted(required_checks - set(check_codes))
            if missing_checks:
                raise ForwardRegistrationError(
                    f"{label} evidence is missing mandatory checks: "
                    + ", ".join(missing_checks)
                )
            expected_recovery_engine = (
                "quant-platform/i7-dynamic-risk-persistent-ledger-recovery-drill/v1"
                if strategy_id == I7_STRATEGY_ID
                else "quant-platform/persistent-ledger-recovery-drill/v2"
            )
            if label == "recovery_drill" and evidence.get(
                "drill_engine"
            ) != expected_recovery_engine:
                raise ForwardRegistrationError(
                    "recovery_drill evidence must use the crash-safe v2 engine"
                )
            internal_digest = _hash(evidence.get(digest_field), digest_field)
            evidence_identity = {
                key: value for key, value in evidence.items() if key != digest_field
            }
            if sha256_digest(evidence_identity) != internal_digest:
                raise ForwardRegistrationError(f"{label} internal evidence hash mismatch")
            if evidence.get("strategy_id") != strategy_id:
                raise ForwardRegistrationError(f"{label} evidence strategy mismatch")
            if str(evidence.get("strategy_config_sha256") or "").lower() != str(
                spec.get("strategy_config_sha256") or ""
            ).lower():
                raise ForwardRegistrationError(
                    f"{label} evidence strategy config mismatch"
                )
            if str(evidence.get("code_snapshot_sha256") or "").lower() != str(
                spec.get("code_snapshot_sha256") or ""
            ).lower():
                raise ForwardRegistrationError(f"{label} evidence code snapshot mismatch")
            if label == "recovery_drill" and str(
                evidence.get("execution_config_sha256") or ""
            ).lower() != str(spec.get("execution_config_sha256") or "").lower():
                raise ForwardRegistrationError(
                    "recovery_drill evidence execution config mismatch"
                )

        strategy_path = self._inside_platform(str(spec.get("strategy_config_path") or ""))
        expected_strategy_sha = _hash(
            spec.get("strategy_config_sha256"), "strategy_config_sha256"
        )
        if not strategy_path.is_file() or _file_sha256(strategy_path) != expected_strategy_sha:
            raise ForwardRegistrationError("frozen strategy config hash mismatch")
        strategy_config = _read_json(strategy_path)
        if (
            strategy_config.get("strategy_id") != strategy_id
            or strategy_config.get("real_orders") is not False
        ):
            raise ForwardRegistrationError("strategy artifact identity or real-order flag is invalid")
        prospective_gate = dict(
            dict(strategy_config.get("activation") or {}).get("prospective_gate")
            or {}
        )
        if prospective_gate:
            if int(spec.get("minimum_trading_days") or 0) != int(
                prospective_gate.get("minimum_trading_days") or 0
            ):
                raise ForwardRegistrationError(
                    "formal minimum_trading_days drifted from the frozen prospective gate"
                )
            if int(spec.get("minimum_observation_count") or 0) != int(
                prospective_gate.get("minimum_signal_observations") or 0
            ):
                raise ForwardRegistrationError(
                    "formal minimum_observation_count drifted from the frozen prospective gate"
                )
            if float(dict(spec.get("loss_budget") or {}).get("maximum_loss_pct") or 0) != float(
                prospective_gate.get("maximum_loss_pct") or 0
            ):
                raise ForwardRegistrationError(
                    "formal loss budget drifted from the frozen prospective gate"
                )
            if not all(
                prospective_gate.get(field) is True
                for field in (
                    "zero_reconciliation_failures",
                    "zero_data_integrity_failures",
                    "zero_portfolio_risk_breaches",
                )
            ) or prospective_gate.get("allow_post_freeze_rule_drift") is not False:
                raise ForwardRegistrationError("frozen prospective safety gates are incomplete")
            # Empty sessions still validate every frozen performance threshold.
            calculate_forward_performance(
                [], initial_cash=initial_cash, prospective_gate=prospective_gate
            )

        code_snapshot = dict(spec.get("code_snapshot") or {})
        code_commit = str(spec.get("code_commit") or "").lower()
        if not COMMIT_RE.fullmatch(code_commit):
            raise ForwardRegistrationError("code_commit must be a full 40-character commit id")
        if str(code_snapshot.get("commit") or "").lower() != code_commit:
            raise ForwardRegistrationError("code snapshot is not bound to code_commit")
        files = list(code_snapshot.get("files") or [])
        if not files:
            raise ForwardRegistrationError("code_snapshot must contain at least one file")
        snapshot_paths = {str(item.get("path") or "") for item in files}
        required_snapshot_paths = (
            {
                PLATFORM_PORTFOLIO_POLICY_PATH,
                PORTFOLIO_STRESS_POLICY_PATH,
            }
            | PARENT_ORDER_ALLOCATION_SNAPSHOT_PATHS
            | PRETRADE_ORCHESTRATION_SNAPSHOT_PATHS
            | EXECUTION_CONFORMANCE_SNAPSHOT_PATHS
        )
        if strategy_id in SUPPORTED_FORMAL_ADMISSION_STRATEGIES:
            required_snapshot_paths |= FORWARD_ADMISSION_SNAPSHOT_PATHS
        missing_parent_policies = sorted(required_snapshot_paths - snapshot_paths)
        if missing_parent_policies:
            raise ForwardRegistrationError(
                "code snapshot must bind all parent-account policies: "
                + ", ".join(missing_parent_policies)
            )
        expected_code_sha = _hash(spec.get("code_snapshot_sha256"), "code_snapshot_sha256")
        if sha256_digest(code_snapshot) != expected_code_sha:
            raise ForwardRegistrationError("code snapshot identity mismatch")
        for item in files:
            path = self._inside_platform(str(item.get("path") or ""))
            expected = _hash(item.get("sha256"), f"code snapshot {path.name}")
            materialization = str(item.get("hash_materialization") or "")
            if materialization not in {"", "NORMALIZED_LF_OR_BINARY_RAW"}:
                raise ForwardRegistrationError(
                    f"unsupported code snapshot materialization: {path.name}"
                )
            if not path.is_file():
                raise ForwardRegistrationError(f"code snapshot file drift: {path.name}")
            actual = (
                _portable_source_sha256(path)
                if materialization == "NORMALIZED_LF_OR_BINARY_RAW"
                else _file_sha256(path)
            )
            if actual != expected:
                raise ForwardRegistrationError(f"code snapshot file drift: {path.name}")

        execution_config = dict(spec.get("execution_config") or {})
        expected_execution_sha = _hash(
            spec.get("execution_config_sha256"), "execution_config_sha256"
        )
        if sha256_digest(execution_config) != expected_execution_sha:
            raise ForwardRegistrationError("execution config identity mismatch")
        if execution_config.get("real_orders") is not False:
            raise ForwardRegistrationError("execution config must explicitly disable real orders")
        if execution_config.get("enforce_next_session") is not True:
            raise ForwardRegistrationError("formal forward execution must enforce next-session fills")
        if execution_config.get("t_plus_one") is not True:
            raise ForwardRegistrationError("formal A-share/ETF execution must enable T+1 lots")
        if (
            execution_config.get("t_plus_one_calendar_required") is not True
            or not execution_config.get("trading_calendar")
            or execution_config.get("market") != "SSE_SZSE"
        ):
            raise ForwardRegistrationError(
                "formal T+1 execution requires a versioned mainland trading calendar"
            )
        if not execution_config.get("exchange_rules"):
            raise ForwardRegistrationError("versioned exchange rules are required")
        if not execution_config.get("portfolio_risk_policy"):
            raise ForwardRegistrationError("canonical portfolio risk policy is required")
        configured_risk = PortfolioRiskPolicy.from_config(
            dict(execution_config["portfolio_risk_policy"])
        ).evidence()
        global_risk = PortfolioRiskPolicy.from_config(
            _read_json(self.platform_root / "config" / "risk" / "portfolio-risk-policy-v1.json")
        ).evidence()
        expected_risk_sha = _hash(
            spec.get("portfolio_risk_policy_sha256"), "portfolio_risk_policy_sha256"
        )
        if (
            configured_risk["policy_sha256"] != expected_risk_sha
            or any(
                float(configured_risk[field]) > float(global_risk[field])
                for field in (
                    "max_gross_exposure_pct",
                    "max_asset_pct",
                    "max_sector_pct",
                    "max_correlation_cluster_pct",
                    "soft_drawdown_pct",
                    "hard_drawdown_pct",
                )
            )
            or float(configured_risk["minimum_cash_pct"])
            < float(global_risk["minimum_cash_pct"])
            or float(configured_risk["minimum_effective_positions"])
            < float(global_risk["minimum_effective_positions"])
        ):
            raise ForwardRegistrationError(
                "execution config weakens the global risk thresholds or has the wrong identity"
            )
        platform_risk = self._platform_policy()
        self._portfolio_stress_policy()
        if (
            float(platform_risk.max_gross_exposure_pct)
            > float(global_risk["max_gross_exposure_pct"])
            or float(platform_risk.max_asset_pct)
            > float(global_risk["max_asset_pct"])
            or float(platform_risk.max_sector_pct)
            > float(global_risk["max_sector_pct"])
            or float(platform_risk.max_correlation_cluster_pct)
            > float(global_risk["max_correlation_cluster_pct"])
            or float(platform_risk.minimum_cash_pct)
            < float(global_risk["minimum_cash_pct"])
            or float(platform_risk.minimum_effective_assets)
            < float(global_risk["minimum_effective_positions"])
        ):
            raise ForwardRegistrationError(
                "platform shared-capital policy weakens the global risk baseline"
            )
        if float(execution_config.get("max_position_pct") or 100) > float(
            configured_risk["max_asset_pct"]
        ):
            raise ForwardRegistrationError("ledger asset cap is weaker than the portfolio risk policy")
        if float(execution_config.get("cash_reserve_pct") or 0) < float(
            configured_risk["minimum_cash_pct"]
        ):
            raise ForwardRegistrationError("ledger cash reserve is weaker than the portfolio risk policy")
        if int(execution_config.get("max_positions") or 0) < int(
            float(configured_risk["minimum_effective_positions"])
        ):
            raise ForwardRegistrationError("max_positions cannot satisfy minimum effective positions")
        maximum_loss_pct = float(dict(spec.get("loss_budget") or {}).get("maximum_loss_pct") or 0)
        if maximum_loss_pct <= 0 or maximum_loss_pct > float(configured_risk["hard_drawdown_pct"]):
            raise ForwardRegistrationError("loss budget must be positive and no weaker than hard drawdown")
        # Instantiation validates dated fees, exchange rules and all ledger-required fields.
        SimulationLedger(initial_cash, execution_config, {})

        required_research = (
            "research_governance_policy_path",
            "research_governance_policy_sha256",
            "historical_research_gate",
            "independent_adversarial_audit_required_before_paper_completion",
        )
        if any(spec.get(field) is None for field in required_research):
            raise ForwardRegistrationError(
                "formal registration must bind the research-governance policy"
            )
        try:
            resolved_research = resolve_research_governance_policy(
                self.platform_root
            )
        except ResearchRegistryError as exc:
            raise ForwardRegistrationError(str(exc)) from exc
        if str(spec["research_governance_policy_path"]) != str(
            resolved_research["policy_path"]
        ):
            raise ForwardRegistrationError("research-governance policy path mismatch")
        if _hash(
            spec["research_governance_policy_sha256"],
            "research_governance_policy_sha256",
        ) != str(resolved_research["policy_sha256"]).lower():
            raise ForwardRegistrationError("research-governance policy hash mismatch")
        if spec.get(
            "independent_adversarial_audit_required_before_paper_completion"
        ) is not True:
            raise ForwardRegistrationError(
                "final independent adversarial audit requirement was weakened"
            )

        research_evidence_verified = False
        if historical_gate in {
            "STRICT_FORWARD_ONLY_SUBSTITUTION",
            "STRICT_FORWARD_ONLY_NO_INHERITED_ALPHA",
        }:
            if strategy_config.get("forward_only") is not True or strategy_config.get(
                "historical_results_may_support_promotion"
            ) is not False:
                raise ForwardRegistrationError(
                    "strict forward-only substitution conflicts with strategy config"
                )
        else:
            raise ForwardRegistrationError("unsupported historical research gate")

        approved_datasets = list(spec.get("approved_datasets") or [])
        if not approved_datasets:
            raise ForwardRegistrationError("approved_datasets cannot be empty")
        dataset_ids = [str(item.get("dataset_id") or "") for item in approved_datasets]
        if len(dataset_ids) != len(set(dataset_ids)):
            raise ForwardRegistrationError("approved dataset ids must be unique")
        required_usages = {"calendar", "signal", "execution", "valuation"}
        formal_product_contracts: dict[str, dict[str, Any]] | None = None
        required_product_ids: set[str] = set()
        if (
            strategy_id in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
            and strategy_id != P1_STRATEGY_ID
        ):
            try:
                readiness_policy = resolve_formal_data_readiness_policy(
                    self.platform_root
                )["policy"]
                strategy_requirement = dict(
                    readiness_policy["strategy_requirements"][strategy_id]
                )
                formal_products = dict(
                    readiness_policy["tracks"][strategy_requirement["track"]][
                        "products"
                    ]
                )
                required_product_ids = {
                    str(product_id)
                    for product_id in strategy_requirement["required_products"]
                }
                formal_product_contracts = {
                    product_id: dict(formal_products[product_id])
                    for product_id in required_product_ids
                }
                required_usages = {
                    str(usage)
                    for product_id in required_product_ids
                    for usage in formal_product_contracts[product_id]["runner_usages"]
                }
            except (ProviderReadinessError, KeyError, TypeError, ValueError) as exc:
                raise ForwardRegistrationError(
                    f"formal data usage contract is invalid: {exc}"
                ) from exc
        available_usages = {
            str(usage)
            for item in approved_datasets
            for usage in list(item.get("usages") or [])
        }
        if not required_usages <= available_usages:
            raise ForwardRegistrationError("approved datasets do not cover all runner usages")
        authorities_by_product: dict[str, set[str]] = {
            product_id: set() for product_id in required_product_ids
        }
        for item in approved_datasets:
            if not item.get("dataset_id") or not list(item.get("providers") or []):
                raise ForwardRegistrationError("each approved dataset needs id and providers")
            if not list(item.get("usages") or []):
                raise ForwardRegistrationError("each approved dataset needs at least one usage")
            if not str(item.get("semantics_version") or "").strip():
                raise ForwardRegistrationError(
                    "each approved dataset needs an explicit semantics_version"
                )
            if formal_product_contracts is not None:
                product_id = str(item.get("product_id") or "")
                authority = str(item.get("authority") or "")
                contract = formal_product_contracts.get(product_id)
                if contract is None or not authority:
                    raise ForwardRegistrationError(
                        "formal approved datasets need a required product_id and authority"
                    )
                if (
                    set(str(value) for value in item.get("usages") or [])
                    != set(str(value) for value in contract["runner_usages"])
                    or str(item.get("semantics_version") or "")
                    != str(contract["semantics_version"])
                    or len(list(item.get("providers") or [])) != 1
                ):
                    raise ForwardRegistrationError(
                        f"formal dataset contract drifted for {product_id}"
                    )
                authorities_by_product[product_id].add(authority)
            quality_fields = (
                "quality_policy_path",
                "quality_policy_sha256",
                "minimum_independent_sources",
            )
            has_quality_field = any(item.get(field) is not None for field in quality_fields)
            requires_p1_quality = strategy_id == P1_STRATEGY_ID
            if requires_p1_quality or has_quality_field:
                if any(item.get(field) is None for field in quality_fields):
                    raise ForwardRegistrationError(
                        "corroborated datasets require a policy path, hash and source count"
                    )
                quality_path = str(item.get("quality_policy_path") or "")
                quality_sha = _hash(
                    item.get("quality_policy_sha256"), "quality_policy_sha256"
                )
                try:
                    resolved_quality = resolve_p1_data_quality_policy(
                        self.platform_root, quality_path
                    )
                except DataQualityError as exc:
                    raise ForwardRegistrationError(str(exc)) from exc
                if str(resolved_quality["policy_sha256"]).lower() != quality_sha:
                    raise ForwardRegistrationError("data-quality policy hash mismatch")
                minimum_sources = int(item.get("minimum_independent_sources") or 0)
                if minimum_sources < 2 or minimum_sources != int(
                    resolved_quality["policy"]["minimum_independent_sources"]
                ):
                    raise ForwardRegistrationError(
                        "data-quality source-count requirement was weakened"
                    )
                approved_ingest = str(
                    resolved_quality["policy"]["approved_ingest_provider_name"]
                )
                if approved_ingest not in [str(value) for value in item["providers"]]:
                    raise ForwardRegistrationError(
                        "approved dataset omits the frozen reviewed ingest provider"
                    )
        if formal_product_contracts is not None:
            incomplete_products = sorted(
                product_id
                for product_id, contract in formal_product_contracts.items()
                if len(authorities_by_product[product_id])
                < int(contract["minimum_independent_authorities"])
            )
            if incomplete_products:
                raise ForwardRegistrationError(
                    "formal approved datasets lack independent-authority coverage: "
                    + ", ".join(incomplete_products)
                )

        fixed_symbols = list(spec.get("allowed_symbols") or [])
        fixed_codes = [str(item.get("code") or "") for item in fixed_symbols]
        if fixed_codes and (any(not code for code in fixed_codes) or len(fixed_codes) != len(set(fixed_codes))):
            raise ForwardRegistrationError("allowed_symbols contains invalid or duplicate codes")
        if not fixed_codes and "universe" not in available_usages:
            raise ForwardRegistrationError("dynamic universes require an approved universe dataset")

        normalized = {
            **spec,
            "approved_at": approved_at.isoformat(),
            "first_allowed_signal_date": first_allowed.isoformat(),
            "strategy_config": strategy_config,
            "execution_config": execution_config,
            "execution_conformance": execution_conformance,
            "research_evidence_verified": research_evidence_verified,
            "spec_sha256": sha256_digest(
                {key: value for key, value in spec.items() if key != "registry_sha256"}
            ),
        }
        return normalized

    def _strategy_root(self, strategy_id: str) -> Path:
        return self.runtime_root / str(strategy_id)

    @contextmanager
    def _mutation_lock(self, strategy_id: str, timeout_seconds: float = 10.0):
        """Serialize all writes for one strategy across scheduler processes."""
        lock_path = self.runtime_root / "_locks" / f"{strategy_id}.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+b")
        acquired = False
        deadline = time_module.monotonic() + max(0.0, float(timeout_seconds))
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            while not acquired:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:  # pragma: no cover - the deployed platform is Windows
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                except OSError as exc:
                    if time_module.monotonic() >= deadline:
                        raise ForwardConflictError(
                            f"another forward mutation is active for {strategy_id}"
                        ) from exc
                    time_module.sleep(0.05)
            yield
        finally:
            if acquired:
                handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:  # pragma: no cover - the deployed platform is Windows
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()

    def _ledger_store(self, strategy_id: str) -> PersistentLedgerStore:
        return PersistentLedgerStore(self._strategy_root(strategy_id) / "ledger")

    def _safety_state(self, strategy_id: str) -> dict[str, Any]:
        path = self._strategy_root(strategy_id) / "safety" / "state.json"
        return _read_json(path) if path.is_file() else {"status": "CLEAR", "event_sha256": None}

    def _halt(self, strategy_id: str, reason: str, context: dict[str, Any]) -> dict[str, Any]:
        identity = {
            "schema": "quant-platform/forward-halt-event/v1",
            "strategy_id": strategy_id,
            "reason": str(reason),
            "context": context,
        }
        event = {**identity, "event_sha256": sha256_digest(identity)}
        root = self._strategy_root(strategy_id) / "safety"
        _immutable_json(root / "events" / f"{event['event_sha256']}.json", event)
        _atomic_json(
            root / "state.json",
            {"status": "OPEN", "event_sha256": event["event_sha256"], "reason": str(reason)},
        )
        return event

    def _platform_policy(self) -> PlatformPortfolioPolicy:
        path = self.platform_root / PLATFORM_PORTFOLIO_POLICY_PATH
        if not path.is_file():
            raise ForwardRegistrationError("platform portfolio policy is missing")
        try:
            return PlatformPortfolioPolicy.from_config(_read_json(path))
        except (ForwardPaperError, TypeError, ValueError, KeyError) as exc:
            raise ForwardRegistrationError(
                f"platform portfolio policy is invalid: {exc}"
            ) from exc

    def _portfolio_stress_policy(self) -> PortfolioStressPolicy:
        path = self.platform_root / PORTFOLIO_STRESS_POLICY_PATH
        if not path.is_file():
            raise ForwardRegistrationError("portfolio stress policy is missing")
        try:
            return PortfolioStressPolicy.from_config(_read_json(path))
        except (ForwardPaperError, TypeError, ValueError, KeyError) as exc:
            raise ForwardRegistrationError(
                f"portfolio stress policy is invalid: {exc}"
            ) from exc

    def _platform_safety_state(self) -> dict[str, Any]:
        path = self.runtime_root / "_platform_portfolio" / "safety" / "state.json"
        return (
            _read_json(path)
            if path.is_file()
            else {"status": "CLEAR", "event_sha256": None}
        )

    def _halt_platform_portfolio(
        self, reason: str, context: dict[str, Any]
    ) -> dict[str, Any]:
        identity = {
            "schema": "quant-platform/platform-portfolio-halt-event/v1",
            "reason": str(reason),
            "context": context,
        }
        event = {**identity, "event_sha256": sha256_digest(identity)}
        root = self.runtime_root / "_platform_portfolio" / "safety"
        _immutable_json(root / "events" / f"{event['event_sha256']}.json", event)
        _atomic_json(
            root / "state.json",
            {
                "status": "OPEN",
                "event_sha256": event["event_sha256"],
                "reason": str(reason),
            },
        )
        return event

    def acknowledge_platform_portfolio_halt(
        self, authorization_reference: str
    ) -> dict[str, Any]:
        """Clear the parent-account latch; the next batch is still re-assessed."""
        reference = str(authorization_reference).strip()
        if not reference:
            raise ForwardHaltedError("operator authorization reference is required")
        with self._mutation_lock("platform-portfolio-acknowledgement"):
            state = self._platform_safety_state()
            if state.get("status") != "OPEN":
                raise ForwardHaltedError("platform portfolio has no open halt")
            registry = self._registry()
            degraded = [
                str(item["strategy_id"])
                for item in list(registry.get("experiments") or [])
                if self._ledger_store(str(item["strategy_id"])).inspect()["status"]
                != "READY"
            ]
            if degraded:
                raise ForwardHaltedError(
                    "all child ledgers must be READY before acknowledgement: "
                    + ", ".join(sorted(degraded))
                )
            identity = {
                "schema": "quant-platform/platform-portfolio-halt-acknowledgement/v1",
                "halt_event_sha256": state.get("event_sha256"),
                "authorization_reference": reference,
                "registry_sha256": sha256_digest(registry),
                "policy_sha256": self._platform_policy().evidence()["policy_sha256"],
            }
            acknowledgement = {
                **identity,
                "acknowledgement_sha256": sha256_digest(identity),
            }
            root = self.runtime_root / "_platform_portfolio" / "safety"
            _immutable_json(
                root
                / "acknowledgements"
                / f"{acknowledgement['acknowledgement_sha256']}.json",
                acknowledgement,
            )
            _atomic_json(
                root / "state.json",
                {
                    "status": "CLEAR",
                    "event_sha256": state.get("event_sha256"),
                    "acknowledgement_sha256": acknowledgement[
                        "acknowledgement_sha256"
                    ],
                },
            )
            return acknowledgement

    def platform_portfolio_status(self) -> dict[str, Any]:
        policy = self._platform_policy().evidence()
        stress_policy = self._portfolio_stress_policy().evidence()
        root = self.runtime_root / "_platform_portfolio"
        latest_path = root / "preflights" / "latest.json"
        latest: dict[str, Any] | None = None
        if latest_path.is_file():
            pointer = _read_json(latest_path)
            digest = _hash(pointer.get("preflight_sha256"), "platform preflight")
            latest = _hashed_record(
                root / "preflights" / "records" / f"{digest}.json",
                "preflight_sha256",
            )
        registry = self._registry()
        allocation_root = self.runtime_root / "_parent_order_allocation" / "plans"
        allocation_records = sorted((allocation_root / "records").glob("*.json"))
        allocation_errors: list[str] = []
        validated_allocations: dict[str, dict[str, Any]] = {}
        for allocation_path in allocation_records:
            try:
                allocation_record = _hashed_record(
                    allocation_path, "allocation_plan_sha256"
                )
                validated = validate_parent_order_plan(allocation_record)
                validated_allocations[
                    str(validated["allocation_plan_sha256"])
                ] = validated
            except (ForwardPaperError, OrderAllocationError, KeyError) as exc:
                allocation_errors.append(str(exc))
        latest_allocation: dict[str, Any] | None = None
        allocation_latest_path = allocation_root / "latest.json"
        if allocation_latest_path.is_file():
            try:
                allocation_pointer = _read_json(allocation_latest_path)
                allocation_sha = _hash(
                    allocation_pointer.get("allocation_plan_sha256"),
                    "parent order allocation plan",
                )
                latest_allocation = validated_allocations.get(allocation_sha)
                if latest_allocation is None:
                    raise ForwardPaperError(
                        "latest parent allocation pointer has no valid record"
                    )
            except (ForwardPaperError, OrderAllocationError, KeyError) as exc:
                allocation_errors.append(str(exc))
        pretrade_root = self.runtime_root / "_pretrade_execution_batches"
        pretrade_paths = sorted((pretrade_root / "records").glob("*.json"))
        pretrade_errors: list[str] = []
        validated_pretrades: dict[str, dict[str, Any]] = {}
        for pretrade_path in pretrade_paths:
            try:
                prepared = validate_pretrade_execution_batch(
                    _hashed_record(pretrade_path, "pretrade_batch_sha256")
                )
                plan = dict(prepared["parent_order_allocation_plan"])
                if validated_allocations.get(plan["allocation_plan_sha256"]) != plan:
                    raise ForwardPaperError(
                        "pretrade batch has no matching independent allocation plan"
                    )
                if (
                    dict(
                        prepared["prepared_portfolio_assessment"].get("policy")
                        or {}
                    ).get("policy_sha256")
                    != policy["policy_sha256"]
                    or dict(
                        prepared["prepared_stress_assessment"].get("policy")
                        or {}
                    ).get("policy_sha256")
                    != stress_policy["policy_sha256"]
                ):
                    raise ForwardPaperError(
                        "pretrade batch risk policy binding is stale"
                    )
                validated_pretrades[
                    str(prepared["pretrade_batch_sha256"])
                ] = prepared
            except (
                ForwardPaperError,
                ExecutionOrchestrationError,
                KeyError,
            ) as exc:
                pretrade_errors.append(str(exc))
        latest_pretrade: dict[str, Any] | None = None
        pretrade_latest_path = pretrade_root / "latest.json"
        if pretrade_latest_path.is_file():
            try:
                pretrade_pointer = _read_json(pretrade_latest_path)
                pretrade_sha = _hash(
                    pretrade_pointer.get("pretrade_batch_sha256"),
                    "pretrade execution batch",
                )
                latest_pretrade = validated_pretrades.get(pretrade_sha)
                if latest_pretrade is None:
                    raise ForwardPaperError(
                        "latest pretrade pointer has no valid record"
                    )
            except (
                ForwardPaperError,
                ExecutionOrchestrationError,
                KeyError,
            ) as exc:
                pretrade_errors.append(str(exc))
        return {
            "configured": True,
            "policy": policy,
            "stress_policy": stress_policy,
            "safety": self._platform_safety_state(),
            "registered_strategy_count": len(
                list(registry.get("experiments") or [])
            ),
            "latest_preflight": latest,
            "order_allocation": {
                "schema": "quant-core/parent-order-allocation-status/v1",
                "plan_schema": PARENT_ORDER_PLAN_SCHEMA,
                "status": (
                    "INVALID"
                    if allocation_errors
                    else "VALID"
                    if latest_allocation is not None
                    else "EMPTY"
                ),
                "mode": "PAPER",
                "plan_count": len(allocation_records),
                "latest_plan": latest_allocation,
                "errors": allocation_errors,
                "direct_broker_submission_allowed": False,
                "real_orders": False,
            },
            "pretrade_execution": {
                "schema": "quant-platform/pretrade-execution-status/v1",
                "batch_schema": PRETRADE_BATCH_SCHEMA,
                "status": (
                    "INVALID"
                    if pretrade_errors
                    else "PREPARED"
                    if latest_pretrade is not None
                    else "EMPTY"
                ),
                "mode": "PAPER",
                "batch_count": len(pretrade_paths),
                "latest_batch": latest_pretrade,
                "errors": pretrade_errors,
                "commit_requires_preparation": True,
                "real_orders": False,
            },
            "real_orders": False,
        }

    @_locked_mutation
    def acknowledge_halt(self, strategy_id: str, authorization_reference: str) -> dict[str, Any]:
        spec = self._experiment(strategy_id)
        state = self._safety_state(strategy_id)
        reference = str(authorization_reference).strip()
        if state.get("status") != "OPEN":
            raise ForwardHaltedError("strategy has no open halt")
        if not reference:
            raise ForwardHaltedError("operator authorization reference is required")
        inspection = self._ledger_store(strategy_id).inspect()
        if inspection["status"] != "READY":
            raise ForwardHaltedError(
                "ledger must be restored to READY before a halt can be acknowledged"
            )
        identity = {
            "schema": "quant-platform/forward-halt-acknowledgement/v1",
            "strategy_id": strategy_id,
            "halt_event_sha256": state.get("event_sha256"),
            "authorization_reference": reference,
            "spec_sha256": spec["spec_sha256"],
        }
        acknowledgement = {**identity, "acknowledgement_sha256": sha256_digest(identity)}
        root = self._strategy_root(strategy_id) / "safety"
        _immutable_json(
            root / "acknowledgements" / f"{acknowledgement['acknowledgement_sha256']}.json",
            acknowledgement,
        )
        _atomic_json(
            root / "state.json",
            {
                "status": "CLEAR",
                "event_sha256": state.get("event_sha256"),
                "acknowledgement_sha256": acknowledgement["acknowledgement_sha256"],
            },
        )
        return acknowledgement

    @_locked_mutation
    def recover_ledger(
        self,
        strategy_id: str,
        *,
        checkpoint_sha256: str,
        authorization_reference: str,
    ) -> dict[str, Any]:
        """Repair a degraded pointer only after an operator approves the exact fallback."""
        self._experiment(strategy_id)
        if self._safety_state(strategy_id).get("status") != "OPEN":
            raise ForwardHaltedError("ledger recovery requires an open safety halt")
        checkpoint = _hash(checkpoint_sha256, "recovery checkpoint")
        reference = str(authorization_reference).strip()
        if not reference:
            raise ForwardHaltedError("operator authorization reference is required")
        store = self._ledger_store(strategy_id)
        if store.inspect()["status"] != "DEGRADED":
            raise ForwardHaltedError("ledger is not degraded")
        try:
            _, report = store.recover()
            if report.get("selected_checkpoint_sha256") != checkpoint:
                raise ForwardConflictError(
                    "requested recovery checkpoint does not match the verified fallback"
                )
            acknowledgement = store.acknowledge_recovery(checkpoint, reference)
        except (LedgerPersistenceError, ValueError, KeyError) as exc:
            raise ForwardHaltedError(f"ledger recovery failed: {exc}") from exc
        return {
            "schema": "quant-platform/forward-ledger-recovery/v1",
            "strategy_id": strategy_id,
            "recovery_report": report,
            "acknowledgement": acknowledgement,
            "ledger_status": store.inspect(),
            "safety_status": self._safety_state(strategy_id),
            "halt_remains_open": True,
            "real_orders": False,
        }

    def _approved_dataset(
        self,
        spec: dict[str, Any],
        reference: dict[str, Any],
        usage: str,
    ) -> dict[str, Any]:
        dataset_id = str(reference.get("dataset_id") or "")
        manifest_sha = _hash(reference.get("manifest_sha256"), "dataset manifest")
        policies = [
            item
            for item in list(spec.get("approved_datasets") or [])
            if str(item.get("dataset_id")) == dataset_id and usage in list(item.get("usages") or [])
        ]
        if len(policies) != 1:
            raise ForwardDataError(f"dataset {dataset_id} is not approved for {usage}")
        try:
            loaded = self.catalog.load(dataset_id, manifest_sha)
        except DataCatalogError as exc:
            raise ForwardDataError(str(exc)) from exc
        manifest = dict(loaded["manifest"])
        provider = dict(manifest.get("provider") or {})
        if str(provider.get("name") or "") not in [str(item) for item in policies[0]["providers"]]:
            raise ForwardDataError(f"dataset provider is not approved for {dataset_id}")
        expected_semantics = str(policies[0]["semantics_version"])
        if manifest.get("metadata", {}).get("semantics_version") != expected_semantics:
            raise ForwardDataError(f"dataset semantics drift for {dataset_id}")
        policy = policies[0]
        if policy.get("quality_policy_path") is not None:
            try:
                resolved_quality = resolve_p1_data_quality_policy(
                    self.platform_root, str(policy["quality_policy_path"])
                )
                if str(resolved_quality["policy_sha256"]).lower() != str(
                    policy["quality_policy_sha256"]
                ).lower():
                    raise DataQualityError("data-quality policy hash mismatch")
                loaded["quality_verification"] = verify_p1_quality_attestation(
                    catalog=self.catalog,
                    provider_store=self.provider_store,
                    loaded=loaded,
                    policy=dict(resolved_quality["policy"]),
                    policy_sha256=str(resolved_quality["policy_sha256"]),
                    minimum_independent_sources=int(
                        policy["minimum_independent_sources"]
                    ),
                )
            except (DataQualityError, KeyError, TypeError, ValueError) as exc:
                raise ForwardDataError(
                    f"dataset quality verification failed for {dataset_id}: {exc}"
                ) from exc
        loaded["available_at"] = _timestamp(str(manifest.get("available_at") or ""))
        loaded["usage"] = usage
        return loaded

    def _formal_runtime_materialization(
        self,
        *,
        spec: dict[str, Any],
        strategy_id: str,
        phase: str,
        as_of_date: date,
        cutoff_at: datetime,
        reference_container: dict[str, Any],
        current_holdings: list[str] | None = None,
        required_codes: list[str] | None = None,
    ) -> dict[str, Any] | None:
        """Rebuild successor inputs from the exact verified provider revisions."""

        if (
            strategy_id not in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
            or strategy_id == P1_STRATEGY_ID
        ):
            return None
        if set(reference_container) != {"source_products"}:
            raise ForwardDataError(
                "formal P2/I7 references must contain only source_products"
            )
        try:
            return load_and_materialize_formal_forward_inputs(
                platform_root=str(self.platform_root),
                strategy_id=strategy_id,
                strategy_config=dict(spec["strategy_config"]),
                phase=phase,
                as_of_date=as_of_date,
                cutoff_at=cutoff_at,
                product_references=dict(
                    reference_container.get("source_products") or {}
                ),
                approved_datasets=list(spec.get("approved_datasets") or []),
                current_holdings=list(current_holdings or []),
                required_codes=list(required_codes or []),
                provider_store=self.provider_store,
            )
        except FormalForwardMaterializationError as exc:
            raise ForwardDataError(
                f"formal {phase} materialization failed: {exc}"
            ) from exc

    def _formal_current_holdings(self, strategy_id: str) -> list[str]:
        store = self._ledger_store(strategy_id)
        if store.inspect()["status"] != "READY":
            raise ForwardHaltedError(
                "formal paper ledger must be READY before data materialization"
            )
        try:
            ledger, recovery = store.recover()
        except LedgerPersistenceError as exc:
            raise ForwardHaltedError(str(exc)) from exc
        if recovery.get("read_only"):
            raise ForwardHaltedError(
                "formal paper ledger recovery is read-only"
            )
        return sorted(ledger.position_quantities)

    def _formal_signal_materialization(
        self,
        *,
        spec: dict[str, Any],
        strategy_id: str,
        signal_date: date,
        cutoff_at: datetime,
        data_refs: dict[str, Any],
    ) -> dict[str, Any] | None:
        if (
            strategy_id not in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
            or strategy_id == P1_STRATEGY_ID
        ):
            return None
        return self._formal_runtime_materialization(
            spec=spec,
            strategy_id=strategy_id,
            phase="signal",
            as_of_date=signal_date,
            cutoff_at=cutoff_at,
            reference_container=data_refs,
            current_holdings=self._formal_current_holdings(strategy_id),
        )

    def _formal_market_snapshot(
        self,
        *,
        spec: dict[str, Any],
        strategy_id: str,
        trade_date: date,
        cutoff_at: datetime,
        market_reference: dict[str, Any],
        required_codes: list[str] | None = None,
    ) -> dict[str, Any] | None:
        if (
            strategy_id not in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
            or strategy_id == P1_STRATEGY_ID
        ):
            return None
        materialized = self._formal_runtime_materialization(
            spec=spec,
            strategy_id=strategy_id,
            phase="market",
            as_of_date=trade_date,
            cutoff_at=cutoff_at,
            reference_container=market_reference,
            current_holdings=self._formal_current_holdings(strategy_id),
            required_codes=required_codes,
        )
        if materialized is None:
            return None
        evidence = dict(materialized["evidence"])
        return {
            "dataset_id": f"formal-{strategy_id}-market",
            "payload": dict(materialized["payloads"]["market"]),
            "manifest_sha256": str(evidence["materialization_sha256"]),
            "payload_sha256": str(evidence["payload_sha256s"]["market"]),
            "available_at": cutoff_at,
            "source_bundle": dict(materialized["source_bundle"]),
            "materialization": evidence,
        }

    def _formal_market_required_codes(
        self,
        *,
        strategy_id: str,
        trade_date: date,
        include_due_signal: bool,
    ) -> list[str]:
        codes = set(self._formal_current_holdings(strategy_id))
        if include_due_signal:
            signal = self._due_signal_record(strategy_id, trade_date)
            codes.update(str(item) for item in signal.get("target_codes") or [])
        return sorted(item for item in codes if item)

    @staticmethod
    def _extract_universe_codes(payload: Any) -> set[str]:
        if not isinstance(payload, dict):
            raise ForwardDataError("universe payload must be an object")
        values = payload.get("codes")
        if values is None:
            values = [item.get("code") for item in list(payload.get("stocks") or [])]
        codes = {str(item) for item in list(values or []) if str(item)}
        if not codes:
            raise ForwardDataError("universe dataset contains no codes")
        return codes

    @_locked_mutation
    def initialize(self, strategy_id: str, *, recorded_at: str | datetime) -> dict[str, Any]:
        spec = self._experiment(strategy_id)
        moment = _timestamp(recorded_at)
        if moment < _timestamp(spec["approved_at"]):
            raise ForwardRegistrationError("paper account cannot be initialized before approval")
        store = self._ledger_store(strategy_id)
        operation_key = f"initialize:{strategy_id}:{spec['spec_sha256']}"
        existing = store.committed_operation(operation_key)
        receipt_path = self._strategy_root(strategy_id) / "activation.json"
        if existing is not None:
            inspection = store.inspect()
            if inspection["status"] != "READY":
                raise ForwardHaltedError("initialized ledger is degraded")
            if receipt_path.is_file():
                receipt = _hashed_record(receipt_path, "activation_sha256")
                return {**receipt, "idempotent": True}
            identity = {
                "schema": "quant-platform/forward-activation/v1",
                "strategy_id": strategy_id,
                "recorded_at": moment.isoformat(),
                "approved_at": spec["approved_at"],
                "first_allowed_signal_date": spec["first_allowed_signal_date"],
                "spec_sha256": spec["spec_sha256"],
                "registry_sha256": spec["registry_sha256"],
                "checkpoint_sha256": existing["checkpoint_sha256"],
                "execution_adapter_id": "quant_core",
                "recovered_after_activation_interruption": True,
                "real_orders": False,
            }
            receipt = {**identity, "activation_sha256": sha256_digest(identity)}
            _immutable_json(receipt_path, receipt)
            return {**receipt, "idempotent": True}
        inspection = store.inspect()
        if inspection["status"] != "EMPTY":
            raise ForwardConflictError("ledger exists without the registered initialization operation")
        names = {
            str(item["code"]): str(item.get("name") or item["code"])
            for item in list(spec.get("allowed_symbols") or [])
        }
        ledger = SimulationLedger(
            float(spec["initial_cash"]), dict(spec["execution_config"]), names
        )
        committed = store.commit(ledger, operation_key)
        identity = {
            "schema": "quant-platform/forward-activation/v1",
            "strategy_id": strategy_id,
            "recorded_at": moment.isoformat(),
            "approved_at": spec["approved_at"],
            "first_allowed_signal_date": spec["first_allowed_signal_date"],
            "spec_sha256": spec["spec_sha256"],
            "registry_sha256": spec["registry_sha256"],
            "checkpoint_sha256": committed["checkpoint_sha256"],
            "execution_adapter_id": "quant_core",
            "recovered_after_activation_interruption": False,
            "real_orders": False,
        }
        receipt = {**identity, "activation_sha256": sha256_digest(identity)}
        _immutable_json(receipt_path, receipt)
        return {**receipt, "idempotent": False}

    @_locked_mutation
    def register_signal(
        self,
        strategy_id: str,
        signal: dict[str, Any],
        *,
        recorded_at: str | datetime,
    ) -> dict[str, Any]:
        spec = self._experiment(strategy_id)
        if signal.get("schema") != FORWARD_SIGNAL_SCHEMA:
            raise ForwardDataError("unsupported forward signal schema")
        if signal.get("strategy_id") != strategy_id or signal.get("real_orders") is not False:
            raise ForwardDataError("signal strategy identity or real-order flag is invalid")
        if str(signal.get("strategy_config_sha256") or "").lower() != str(
            spec["strategy_config_sha256"]
        ).lower():
            raise ForwardDataError("signal strategy config identity mismatch")
        if str(signal.get("code_snapshot_sha256") or "").lower() != str(
            spec["code_snapshot_sha256"]
        ).lower():
            raise ForwardDataError("signal code snapshot identity mismatch")

        signal_date = _day(signal.get("signal_date"))
        execute_on = _day(signal.get("execute_on"))
        generated_at = _timestamp(str(signal.get("signal_generated_at") or ""))
        moment = _timestamp(recorded_at)
        signal_day_path = self._strategy_root(strategy_id) / "signals" / "by-date" / f"{signal_date}.json"
        try:
            request_sha = sha256_digest(signal)
        except (TypeError, ValueError) as exc:
            raise ForwardDataError(f"signal is not canonical JSON: {exc}") from exc
        if signal_day_path.is_file():
            pointer = _read_json(signal_day_path)
            if pointer.get("signal_request_sha256") != request_sha:
                raise ForwardConflictError("a different signal is already frozen for this date")
            existing = _hashed_record(
                self._strategy_root(strategy_id) / "signals" / "records" / f"{pointer['signal_sha256']}.json",
                "signal_sha256",
            )
            execution_pointer = (
                self._strategy_root(strategy_id)
                / "signals"
                / "by-execution"
                / f"{existing['execute_on']}.json"
            )
            if execution_pointer.is_file():
                execution_state = _read_json(execution_pointer)
                if execution_state.get("signal_sha256") != existing["signal_sha256"]:
                    raise ForwardConflictError(
                        "execution pointer conflicts with the frozen signal"
                    )
            else:
                _atomic_json(execution_pointer, pointer)
            return {**existing, "idempotent": True}

        if self._safety_state(strategy_id).get("status") == "OPEN":
            raise ForwardHaltedError("strategy is halted until operator acknowledgement")
        if self._ledger_store(strategy_id).inspect()["status"] != "READY":
            raise ForwardHaltedError("formal paper ledger must be initialized before signals")

        if signal_date < _day(spec["first_allowed_signal_date"]):
            raise ForwardDataError("signal predates the registered activation boundary")
        if moment.astimezone(SHANGHAI).date() != signal_date:
            raise ForwardDataError("formal forward signals cannot be backfilled")
        if generated_at.astimezone(SHANGHAI).date() != signal_date:
            raise ForwardDataError("signal generation timestamp does not match signal date")
        if generated_at.astimezone(SHANGHAI).time() < time(15, 0):
            raise ForwardDataError("close signal was generated before the market close cutoff")
        if generated_at > moment or generated_at < _timestamp(spec["approved_at"]):
            raise ForwardDataError("signal generation timestamp is outside the approved window")
        if execute_on <= signal_date:
            raise ForwardDataError("execute_on must be strictly after signal_date")

        data_refs = dict(signal.get("data_refs") or {})
        formal_materialized = self._formal_signal_materialization(
            spec=spec,
            strategy_id=strategy_id,
            signal_date=signal_date,
            cutoff_at=generated_at,
            data_refs=data_refs,
        )
        if formal_materialized is not None:
            formal_evidence = dict(formal_materialized["evidence"])
            if str(signal.get("materialization_sha256") or "").lower() != str(
                formal_evidence["materialization_sha256"]
            ).lower():
                raise ForwardDataError(
                    "signal materialization identity does not match verified provider inputs"
                )
            source_bundle = dict(formal_materialized["source_bundle"])
            calendar = {
                "payload": dict(formal_materialized["payloads"]["calendar"]),
                "available_at": generated_at,
                "usage": "calendar",
                "dataset_id": f"formal-{strategy_id}-calendar",
                "manifest_sha256": formal_evidence["materialization_sha256"],
                "payload_sha256": formal_evidence["payload_sha256s"]["calendar"],
            }
            signal_input = {
                "payload": dict(formal_materialized["payloads"]["signal"]),
                "available_at": generated_at,
                "usage": "signal",
                "dataset_id": f"formal-{strategy_id}-signal",
                "manifest_sha256": formal_evidence["materialization_sha256"],
                "payload_sha256": formal_evidence["payload_sha256s"]["signal"],
            }
            # Registration independently replays the frozen decision.  A caller
            # cannot pair authentic source hashes with arbitrary target weights.
            from .forward_signals import (
                DIVERSIFIED_ETF_TREND_ENGINE,
                FORWARD_MULTIFACTOR_ENGINE,
                build_diversified_etf_trend_decision,
                build_forward_multifactor_decision,
            )

            engine_id = str(
                dict(spec["strategy_config"].get("signal_engine") or {}).get("id")
                or dict(spec["strategy_config"].get("factor_model") or {}).get(
                    "engine_id"
                )
                or ""
            )
            if engine_id == DIVERSIFIED_ETF_TREND_ENGINE:
                replayed = build_diversified_etf_trend_decision(
                    spec["strategy_config"],
                    signal_input["payload"],
                    calendar["payload"],
                    signal_date=signal_date,
                )
            elif engine_id == FORWARD_MULTIFACTOR_ENGINE:
                replayed = build_forward_multifactor_decision(
                    spec["strategy_config"],
                    signal_input["payload"],
                    calendar["payload"],
                    signal_date=signal_date,
                )
            else:
                raise ForwardDataError("strategy signal engine is unsupported")
            if (
                list(replayed.target_codes) != list(signal.get("target_codes") or [])
                or dict(replayed.target_weights)
                != dict(signal.get("target_weights") or {})
                or dict(replayed.evidence)
                != dict(signal.get("decision_evidence") or {})
            ):
                raise ForwardDataError(
                    "formal signal decision does not replay from verified provider inputs"
                )
        else:
            formal_evidence = None
            source_bundle = None
            calendar = self._approved_dataset(
                spec, dict(data_refs.get("calendar") or {}), "calendar"
            )
            signal_input = self._approved_dataset(
                spec, dict(data_refs.get("signal") or {}), "signal"
            )
        for loaded in (calendar, signal_input):
            if loaded["available_at"] > generated_at:
                raise ForwardDataError("signal references data that was unavailable when generated")
        calendar_dates = sorted({_day(item) for item in list(calendar["payload"].get("trading_dates") or [])})
        if signal_date not in calendar_dates:
            raise ForwardDataError("signal_date is not an approved trading session")
        next_dates = [item for item in calendar_dates if item > signal_date]
        if not next_dates or next_dates[0] != execute_on:
            raise ForwardDataError("execute_on is not the next approved trading session")
        frequency = str(spec["signal_frequency"])
        if frequency == "weekly" and signal_date.isocalendar()[:2] == execute_on.isocalendar()[:2]:
            raise ForwardDataError("weekly signal is not on the final trading session of its week")
        if frequency == "monthly" and (signal_date.year, signal_date.month) == (
            execute_on.year,
            execute_on.month,
        ):
            raise ForwardDataError("monthly signal is not on the final trading session of its month")
        input_payload = signal_input["payload"]
        if not isinstance(input_payload, dict):
            raise ForwardDataError("signal input payload must be an object")
        if _day(input_payload.get("as_of_date")) != signal_date:
            raise ForwardDataError("signal input as_of_date does not match signal_date")
        if _day(input_payload.get("max_event_date")) > signal_date:
            raise ForwardDataError("signal input contains future events")

        target_codes = [str(item) for item in list(signal.get("target_codes") or [])]
        if len(target_codes) != len(set(target_codes)):
            raise ForwardDataError("target_codes contains duplicates")
        maximum_positions = int(spec["execution_config"].get("max_positions") or 0)
        if maximum_positions <= 0 or len(target_codes) > maximum_positions:
            raise ForwardDataError("signal exceeds the frozen maximum position count")
        raw_weights = dict(signal.get("target_weights") or {})
        if set(raw_weights) != set(target_codes):
            raise ForwardDataError("target_weights must exactly match target_codes")
        target_weights = {code: float(raw_weights[code]) for code in target_codes}
        if any(
            not math.isfinite(weight) or weight <= 0
            for weight in target_weights.values()
        ):
            raise ForwardDataError("target weights must be positive")
        risk_policy = PortfolioRiskPolicy.from_config(
            dict(spec["execution_config"]["portfolio_risk_policy"])
        )
        risk_metadata = _signal_risk_metadata(
            spec, signal, required_codes=set(target_codes)
        )
        gross_weight = sum(target_weights.values())
        if gross_weight > float(risk_policy.max_gross_exposure_pct) / 100 + 1e-12:
            raise ForwardDataError("target weights exceed gross exposure policy")
        if any(
            weight > float(risk_policy.max_asset_pct) / 100 + 1e-12
            for weight in target_weights.values()
        ):
            raise ForwardDataError("target weights exceed single-asset policy")
        if target_weights:
            normalized = [weight / gross_weight for weight in target_weights.values()]
            effective_positions = 1 / sum(weight * weight for weight in normalized)
            if effective_positions + 1e-12 < float(risk_policy.minimum_effective_positions):
                raise ForwardDataError("target weights fail minimum effective positions")
        else:
            effective_positions = 0.0
        for metadata_key, limit, label in (
            ("sector", float(risk_policy.max_sector_pct) / 100, "sector"),
            (
                "correlation_cluster",
                float(risk_policy.max_correlation_cluster_pct) / 100,
                "correlation cluster",
            ),
        ):
            grouped: dict[str, float] = {}
            for code, weight in target_weights.items():
                metadata = risk_metadata.get(
                    code,
                    {"sector": "UNCLASSIFIED", "correlation_cluster": "UNCLASSIFIED"},
                )
                group = metadata[metadata_key]
                grouped[group] = grouped.get(group, 0.0) + weight
            if any(weight > limit + 1e-12 for weight in grouped.values()):
                raise ForwardDataError(f"target weights exceed {label} policy")
        fixed_codes = {str(item["code"]) for item in list(spec.get("allowed_symbols") or [])}
        verified_refs = [calendar, signal_input]
        if fixed_codes:
            allowed_codes = fixed_codes
        elif formal_materialized is not None:
            allowed_codes = {
                str(item.get("code") or "")
                for item in list(
                    signal_input["payload"].get("official_membership") or []
                )
            }
            allowed_codes.discard("")
            if not allowed_codes:
                raise ForwardDataError(
                    "formal materialized universe contains no approved codes"
                )
        else:
            universe = self._approved_dataset(
                spec, dict(data_refs.get("universe") or {}), "universe"
            )
            if universe["available_at"] > generated_at:
                raise ForwardDataError("universe was unavailable when the signal was generated")
            allowed_codes = self._extract_universe_codes(universe["payload"])
            verified_refs.append(universe)
        if not set(target_codes) <= allowed_codes:
            raise ForwardDataError("signal targets codes outside the approved universe")

        ref_evidence = [
            {
                "usage": item["usage"],
                "dataset_id": item["dataset_id"],
                "manifest_sha256": item["manifest_sha256"],
                "payload_sha256": item["payload_sha256"],
                "available_at": item["available_at"].isoformat(),
            }
            for item in verified_refs
        ]
        identity = {
            "schema": FORWARD_SIGNAL_RECORD_SCHEMA,
            "strategy_id": strategy_id,
            "signal_date": signal_date.isoformat(),
            "execute_on": execute_on.isoformat(),
            "signal_generated_at": generated_at.isoformat(),
            "recorded_at": moment.isoformat(),
            "target_codes": target_codes,
            "target_weights": target_weights,
            "effective_positions": round(effective_positions, 8),
            "decision_evidence": dict(signal.get("decision_evidence") or {}),
            "signal_request_sha256": request_sha,
            "strategy_config_sha256": str(spec["strategy_config_sha256"]).lower(),
            "code_snapshot_sha256": str(spec["code_snapshot_sha256"]).lower(),
            "execution_config_sha256": str(spec["execution_config_sha256"]).lower(),
            "spec_sha256": spec["spec_sha256"],
            "data_refs": ref_evidence,
            **({"source_bundle": source_bundle} if source_bundle is not None else {}),
            **(
                {"formal_materialization": formal_evidence}
                if formal_evidence is not None
                else {}
            ),
            "real_orders": False,
        }
        record = {**identity, "signal_sha256": sha256_digest(identity)}
        root = self._strategy_root(strategy_id) / "signals"
        execution_pointer = root / "by-execution" / f"{execute_on}.json"
        if execution_pointer.is_file():
            existing_pointer = _read_json(execution_pointer)
            if existing_pointer.get("signal_sha256") != record["signal_sha256"]:
                raise ForwardConflictError("two formal signals target the same execution session")
        _immutable_json(root / "records" / f"{record['signal_sha256']}.json", record)
        pointer = {
            "signal_date": signal_date.isoformat(),
            "execute_on": execute_on.isoformat(),
            "signal_sha256": record["signal_sha256"],
            "signal_request_sha256": request_sha,
        }
        _atomic_json(signal_day_path, pointer)
        _atomic_json(execution_pointer, pointer)
        return {**record, "idempotent": False}

    @staticmethod
    def _validate_market_payload(payload: Any, trade_date: date) -> tuple[dict[str, Any], dict[str, float]]:
        if not isinstance(payload, dict) or payload.get("schema") != MARKET_SESSION_SCHEMA:
            raise ForwardDataError("unsupported market session schema")
        if _day(payload.get("trade_date")) != trade_date:
            raise ForwardDataError("market session trade_date mismatch")
        if _day(payload.get("max_event_date")) > trade_date:
            raise ForwardDataError("market session contains future events")
        as_of = _timestamp(str(payload.get("as_of_time") or ""))
        if as_of.astimezone(SHANGHAI).date() != trade_date or as_of.astimezone(SHANGHAI).time() < time(15, 0):
            raise ForwardDataError("market session must be a post-close final snapshot")
        bars = dict(payload.get("bars") or {})
        marks_raw = dict(payload.get("valuation_marks") or {})
        if not bars:
            raise ForwardDataError("market session contains no bars")
        marks: dict[str, float] = {}
        for code, value in marks_raw.items():
            number = float(value)
            if not math.isfinite(number) or number <= 0:
                raise ForwardDataError(f"invalid valuation mark for {code}")
            marks[str(code)] = number
        validated_bars: dict[str, dict[str, Any]] = {}
        for code, bar_value in bars.items():
            bar = dict(bar_value or {})
            required = {
                "open",
                "high",
                "low",
                "close",
                "preclose",
                "volume",
                "suspended",
                "is_st",
                "trading_days_since_listing",
                "unsupported_corporate_action",
                "liquidity_history",
            }
            missing = sorted(required - set(bar))
            if missing:
                raise ForwardDataError(
                    f"execution bar for {code} is missing fields: {', '.join(missing)}"
                )
            unexpected = sorted(
                set(bar)
                - required
                - {"limit_up_locked", "limit_down_locked"}
            )
            if unexpected:
                raise ForwardDataError(
                    f"execution bar for {code} contains unexpected fields: "
                    + ", ".join(unexpected)
                )
            prices = {
                field: float(bar[field])
                for field in ("open", "high", "low", "close", "preclose")
            }
            open_price = prices["open"]
            volume = float(bar.get("volume") or 0)
            if (
                any(not math.isfinite(value) or value <= 0 for value in prices.values())
                or not math.isfinite(volume)
                or volume < 0
            ):
                raise ForwardDataError(f"invalid execution bar for {code}")
            if prices["low"] > min(prices["open"], prices["close"]):
                raise ForwardDataError(f"incoherent execution bar low for {code}")
            if prices["high"] < max(prices["open"], prices["close"]):
                raise ForwardDataError(f"incoherent execution bar high for {code}")
            if prices["low"] > prices["high"]:
                raise ForwardDataError(f"incoherent execution bar range for {code}")
            if not isinstance(bar["suspended"], bool) or not isinstance(bar["is_st"], bool):
                raise ForwardDataError(f"execution status flags are invalid for {code}")
            if not isinstance(bar["unsupported_corporate_action"], bool):
                raise ForwardDataError(f"corporate-action flag is invalid for {code}")
            listing_days = bar["trading_days_since_listing"]
            if not isinstance(listing_days, int) or isinstance(listing_days, bool) or listing_days < 0:
                raise ForwardDataError(f"listing age is invalid for {code}")
            try:
                bar["liquidity_evidence"] = derive_liquidity_evidence(
                    bar["liquidity_history"],
                    trade_date=trade_date,
                    current_volume=volume,
                )
            except ValueError as exc:
                raise ForwardDataError(
                    f"invalid liquidity history for {code}: {exc}"
                ) from exc
            validated_bars[str(code)] = bar
        bars = validated_bars
        missing_mark_bars = sorted(set(marks) - set(bars))
        if missing_mark_bars:
            raise ForwardDataError(
                "valuation marks lack matching market bars: "
                + ", ".join(missing_mark_bars)
            )
        inconsistent_marks = sorted(
            code
            for code, mark in marks.items()
            if abs(float(mark) - float(dict(bars[code])["close"])) > 1e-8
        )
        if inconsistent_marks:
            raise ForwardDataError(
                "valuation marks differ from final close bars: "
                + ", ".join(inconsistent_marks)
            )
        return bars, marks

    def _receipt_path(self, strategy_id: str, trade_date: date) -> Path:
        return self._strategy_root(strategy_id) / "runs" / "by-date" / f"{trade_date}.json"

    def _observation_path(self, strategy_id: str, trade_date: date) -> Path:
        return (
            self._strategy_root(strategy_id)
            / "observations"
            / "by-date"
            / f"{trade_date}.json"
        )

    def _due_signal_record(
        self, strategy_id: str, trade_date: date
    ) -> dict[str, Any]:
        pointer_path = (
            self._strategy_root(strategy_id)
            / "signals"
            / "by-execution"
            / f"{trade_date}.json"
        )
        if not pointer_path.is_file():
            raise ForwardDataError(f"no frozen signal is due on {trade_date}")
        pointer = _read_json(pointer_path)
        digest = _hash(pointer.get("signal_sha256"), "due signal")
        signal = _hashed_record(
            self._strategy_root(strategy_id)
            / "signals"
            / "records"
            / f"{digest}.json",
            "signal_sha256",
        )
        if signal.get("strategy_id") != strategy_id or signal.get(
            "execute_on"
        ) != trade_date.isoformat():
            raise ForwardConflictError("due signal identity does not match its pointer")
        return signal

    def platform_portfolio_preflight(
        self,
        entries: list[dict[str, Any]],
        *,
        trade_date: date,
        recorded_at: datetime,
        batch_request_sha256: str,
    ) -> dict[str, Any]:
        """Freeze one complete, read-only parent-account assessment for a batch."""
        request_sha = _hash(batch_request_sha256, "daily batch request")
        root = self.runtime_root / "_platform_portfolio" / "preflights"
        request_path = root / "by-request" / f"{request_sha}.json"
        if request_path.is_file():
            pointer = _read_json(request_path)
            digest = _hash(pointer.get("preflight_sha256"), "platform preflight")
            existing = _hashed_record(
                root / "records" / f"{digest}.json", "preflight_sha256"
            )
            if (
                existing.get("schema") != PLATFORM_PORTFOLIO_PREFLIGHT_SCHEMA
                or existing.get("batch_request_sha256") != request_sha
            ):
                raise ForwardConflictError("platform preflight request identity mismatch")
            return {**existing, "idempotent": True}

        registry = self._registry()
        expected_ids = sorted(
            str(item.get("strategy_id") or "")
            for item in list(registry.get("experiments") or [])
        )
        supplied_ids = [str(item.get("strategy_id") or "") for item in entries]
        if sorted(supplied_ids) != expected_ids:
            raise ForwardDataError(
                "daily batch must cover every formally registered strategy exactly once"
            )

        rows: list[dict[str, Any]] = []
        execution_bindings: list[dict[str, Any]] = []
        for entry in sorted(entries, key=lambda item: str(item["strategy_id"])):
            strategy_id = str(entry["strategy_id"])
            spec = self._experiment(strategy_id)
            execution_reference = entry.get("execution")
            observation_reference = entry.get("observation")
            if execution_reference is None and observation_reference is None:
                raise ForwardDataError(
                    f"daily batch entry lacks a finalized market observation: {strategy_id}"
                )
            if (
                execution_reference is not None
                and observation_reference is not None
                and dict(execution_reference) != dict(observation_reference)
            ):
                raise ForwardDataError(
                    f"{strategy_id} execution and observation evidence diverged"
                )
            reference = dict(execution_reference or observation_reference or {})
            formal_market = self._formal_market_snapshot(
                spec=spec,
                strategy_id=strategy_id,
                trade_date=trade_date,
                cutoff_at=recorded_at,
                market_reference=reference,
                required_codes=self._formal_market_required_codes(
                    strategy_id=strategy_id,
                    trade_date=trade_date,
                    include_due_signal=execution_reference is not None,
                )
                if strategy_id in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
                and strategy_id != P1_STRATEGY_ID
                else [],
            )
            if formal_market is not None:
                valuation = formal_market
                market_source_bundle = dict(formal_market["source_bundle"])
                execution = formal_market if execution_reference is not None else None
            else:
                market_source_bundle = None
                valuation = self._approved_dataset(spec, reference, "valuation")
                execution = None
                if execution_reference is not None:
                    execution = self._approved_dataset(spec, reference, "execution")
                    if execution["manifest_sha256"] != valuation["manifest_sha256"]:
                        raise ForwardDataError(
                            "execution and valuation snapshots diverged"
                        )
            if valuation["available_at"] > recorded_at:
                raise ForwardDataError(
                    f"{strategy_id} market snapshot was unavailable at preflight"
                )
            bars, marks = self._validate_market_payload(
                valuation["payload"], trade_date
            )
            if _timestamp(str(valuation["payload"]["as_of_time"])) > recorded_at:
                raise ForwardDataError(
                    f"{strategy_id} market snapshot as_of_time is after recorded_at"
                )

            store = self._ledger_store(strategy_id)
            if store.inspect()["status"] != "READY":
                raise ForwardHaltedError(
                    f"{strategy_id} ledger is not READY for platform preflight"
                )
            ledger, recovery = store.recover()
            if recovery.get("read_only"):
                raise ForwardHaltedError(
                    f"{strategy_id} ledger recovery is read-only"
                )
            missing_marks = sorted(set(ledger.position_quantities) - set(marks))
            if missing_marks:
                raise ForwardDataError(
                    f"{strategy_id} valuation marks are missing for: "
                    + ", ".join(missing_marks)
                )
            equity = ledger.equity(marks)
            current = {
                code: float(quantity) * float(marks[code])
                for code, quantity in ledger.position_quantities.items()
                if int(quantity) > 0
            }
            report = ledger.report()
            risk = dict(report.get("portfolio_risk") or {})
            risk_mode = str(risk.get("mode") or "")
            maximum_loss_pct = float(
                dict(spec.get("loss_budget") or {}).get("maximum_loss_pct") or 0
            )
            loss_pct = max(
                0.0,
                (float(spec["initial_cash"]) - float(equity))
                / float(spec["initial_cash"])
                * 100,
            )
            loss_budget_intact = loss_pct <= maximum_loss_pct + 1e-10
            proposed = dict(current)
            due_signal_sha256: str | None = None
            signal: dict[str, Any] | None = None
            if execution_reference is not None:
                signal = self._due_signal_record(strategy_id, trade_date)
                due_signal_sha256 = str(signal["signal_sha256"])
                missing_targets = sorted(set(signal["target_codes"]) - set(marks))
                if missing_targets:
                    raise ForwardDataError(
                        f"{strategy_id} valuation marks are missing for targets: "
                        + ", ".join(missing_targets)
                    )
                if risk_mode == "NORMAL" and loss_budget_intact:
                    proposed = {
                        code: float(equity) * float(weight)
                        for code, weight in dict(signal["target_weights"]).items()
                    }
                else:
                    proposed = {}
            risk_policy = PortfolioRiskPolicy.from_config(
                dict(ledger.config["portfolio_risk_policy"])
            )
            stress_codes = set(current) | set(proposed)
            asset_metadata = dict(risk_policy.asset_metadata)
            if signal is not None:
                asset_metadata.update(
                    _signal_risk_metadata(
                        spec, signal, required_codes=stress_codes
                    )
                )
            missing_stress_bars = sorted(stress_codes - set(bars))
            if missing_stress_bars:
                raise ForwardDataError(
                    f"{strategy_id} market bars are missing for stress testing: "
                    + ", ".join(missing_stress_bars)
                )
            rows.append(
                {
                    "strategy_id": strategy_id,
                    "equity": str(equity),
                    "cash": str(ledger.cash),
                    "current_positions_notional": current,
                    "proposed_positions_notional": proposed,
                    "asset_metadata": asset_metadata,
                    "liquidity": {
                        code: {
                            "price": float(dict(bars[code])["close"]),
                            **dict(dict(bars[code])["liquidity_evidence"]),
                        }
                        for code in sorted(stress_codes)
                    },
                    "risk_mode": risk_mode,
                    "loss_budget_intact": loss_budget_intact,
                }
            )
            execution_bindings.append(
                {
                    "strategy_id": strategy_id,
                    "execution": execution_reference is not None,
                    "market_manifest_sha256": str(
                        valuation["manifest_sha256"]
                    ),
                    "market_source_bundle_sha256": (
                        market_source_bundle["source_bundle_sha256"]
                        if market_source_bundle is not None
                        else None
                    ),
                    "signal_sha256": due_signal_sha256,
                }
            )

        try:
            assessment = PlatformPortfolioSupervisor(
                self._platform_policy()
            ).assess(rows, expected_strategy_ids=expected_ids)
            stress_assessment = PortfolioStressSupervisor(
                self._portfolio_stress_policy()
            ).assess(rows)
        except ValueError as exc:
            raise ForwardDataError(f"platform portfolio preflight failed: {exc}") from exc

        safety_before = self._platform_safety_state()
        decisions = {
            str(assessment["decision"]),
            str(stress_assessment["decision"]),
        }
        if "BLOCKED" in decisions:
            effective_decision = "BLOCKED"
        elif "REDUCE_ONLY" in decisions:
            effective_decision = "REDUCE_ONLY"
        elif "MONITOR_ONLY" in decisions:
            effective_decision = "MONITOR_ONLY"
        else:
            effective_decision = "PASS"
        blockers = sorted(
            set(
                list(assessment["proposed"]["breaches"])
                + list(stress_assessment["proposed"]["breaches"])
            )
        )
        halt_event: dict[str, Any] | None = None
        if effective_decision != "PASS":
            halt_event = self._halt_platform_portfolio(
                "platform portfolio is not eligible for new risk",
                {
                    "trade_date": trade_date.isoformat(),
                    "batch_request_sha256": request_sha,
                    "assessment_sha256": assessment["assessment_sha256"],
                    "stress_assessment_sha256": stress_assessment[
                        "assessment_sha256"
                    ],
                    "decision": effective_decision,
                    "breaches": blockers,
                },
            )
        elif safety_before.get("status") == "OPEN":
            effective_decision = "BLOCKED"
            blockers = ["PLATFORM_HALT_ACKNOWLEDGEMENT_REQUIRED"]

        identity = {
            "schema": PLATFORM_PORTFOLIO_PREFLIGHT_SCHEMA,
            "trade_date": trade_date.isoformat(),
            "recorded_at": recorded_at.isoformat(),
            "batch_request_sha256": request_sha,
            "assessment": assessment,
            "stress_assessment": stress_assessment,
            "portfolio_rows": rows,
            "execution_bindings": execution_bindings,
            "effective_decision": effective_decision,
            "blockers": blockers,
            "safety_before": safety_before,
            "halt_event_sha256": (
                halt_event["event_sha256"] if halt_event is not None else None
            ),
            "real_orders": False,
        }
        preflight = {**identity, "preflight_sha256": sha256_digest(identity)}
        _immutable_json(
            root / "records" / f"{preflight['preflight_sha256']}.json",
            preflight,
        )
        pointer = {
            "batch_request_sha256": request_sha,
            "preflight_sha256": preflight["preflight_sha256"],
        }
        _atomic_json(request_path, pointer)
        _atomic_json(root / "latest.json", pointer)
        return {**preflight, "idempotent": False}

    def _assert_platform_execution_authorized(
        self,
        *,
        strategy_id: str,
        trade_date: date,
        preflight_sha256: str | None,
        market_manifest_sha256: str | None,
        market_source_bundle_sha256: str | None,
    ) -> dict[str, Any]:
        if preflight_sha256 is None:
            raise ForwardHaltedError(
                "formal execution requires a complete daily-batch platform preflight"
            )
        digest = _hash(preflight_sha256, "platform preflight")
        preflight = _hashed_record(
            self.runtime_root
            / "_platform_portfolio"
            / "preflights"
            / "records"
            / f"{digest}.json",
            "preflight_sha256",
        )
        if preflight.get("schema") != PLATFORM_PORTFOLIO_PREFLIGHT_SCHEMA:
            raise ForwardHaltedError(
                "legacy platform preflight cannot authorize execution"
            )
        concentration = dict(preflight.get("assessment") or {})
        stress = dict(preflight.get("stress_assessment") or {})
        if (
            concentration.get("schema")
            != PLATFORM_PORTFOLIO_ASSESSMENT_SCHEMA
            or stress.get("schema")
            != PORTFOLIO_STRESS_ASSESSMENT_SCHEMA
            or dict(concentration.get("policy") or {}).get("policy_sha256")
            != self._platform_policy().evidence()["policy_sha256"]
            or dict(stress.get("policy") or {}).get("policy_sha256")
            != self._portfolio_stress_policy().evidence()["policy_sha256"]
            or stress.get("decision") not in {"PASS", "REDUCE_ONLY"}
        ):
            raise ForwardHaltedError(
                "platform preflight policies or stress evidence do not authorize execution"
            )
        decision = str(preflight.get("effective_decision") or "")
        if decision not in {"PASS", "REDUCE_ONLY"}:
            raise ForwardHaltedError(
                f"platform preflight does not authorize execution: {decision}"
            )
        if preflight.get("trade_date") != trade_date.isoformat():
            raise ForwardConflictError("platform preflight trade date mismatch")
        assessed_ids = {
            str(item.get("strategy_id") or "")
            for item in list(
                concentration.get("strategies") or []
            )
        }
        if strategy_id not in assessed_ids:
            raise ForwardConflictError(
                "strategy is absent from the complete platform preflight"
            )
        bindings = [
            dict(item)
            for item in list(preflight.get("execution_bindings") or [])
            if item.get("strategy_id") == strategy_id
        ]
        if len(bindings) != 1 or bindings[0].get("execution") is not True:
            raise ForwardConflictError(
                "platform preflight did not authorize this strategy execution"
            )
        expected_market = _hash(
            bindings[0].get("market_manifest_sha256"),
            "platform preflight market manifest",
        )
        supplied_market = _hash(
            market_manifest_sha256, "execution market manifest"
        )
        if supplied_market != expected_market:
            raise ForwardConflictError(
                "execution market manifest differs from platform preflight"
            )
        expected_source_bundle = bindings[0].get("market_source_bundle_sha256")
        if expected_source_bundle is None:
            if market_source_bundle_sha256 is not None:
                raise ForwardConflictError(
                    "unexpected market source bundle differs from platform preflight"
                )
        elif _hash(
            expected_source_bundle, "platform preflight market source bundle"
        ) != _hash(market_source_bundle_sha256, "execution market source bundle"):
            raise ForwardConflictError(
                "execution market source bundle differs from platform preflight"
            )
        due_signal = self._due_signal_record(strategy_id, trade_date)
        if bindings[0].get("signal_sha256") != due_signal.get("signal_sha256"):
            raise ForwardConflictError(
                "due signal differs from the platform preflight"
            )
        if (
            decision == "PASS"
            and self._platform_safety_state().get("status") == "OPEN"
        ):
            raise ForwardHaltedError(
                "platform portfolio halt requires acknowledgement before new risk"
            )
        return preflight

    @staticmethod
    def _execution_targets(
        *,
        spec: dict[str, Any],
        ledger: SimulationLedger,
        signal: dict[str, Any],
        marks: dict[str, float],
    ) -> tuple[list[str], dict[str, float]]:
        risk = ledger.report().get("portfolio_risk") or {}
        pretrade_equity = ledger.equity(marks)
        maximum_loss_pct = float(
            dict(spec.get("loss_budget") or {}).get("maximum_loss_pct") or 0
        )
        loss_pct = max(
            0.0,
            (float(spec["initial_cash"]) - float(pretrade_equity))
            / float(spec["initial_cash"])
            * 100,
        )
        loss_budget_intact = loss_pct <= maximum_loss_pct + 1e-10
        target_codes = (
            []
            if (
                str(risk.get("mode") or "NORMAL") != "NORMAL"
                or not loss_budget_intact
            )
            else list(signal["target_codes"])
        )
        target_weights = {} if not target_codes else dict(signal["target_weights"])
        return target_codes, target_weights

    def prepare_due_execution(
        self,
        strategy_id: str,
        *,
        trade_date: str,
        market_reference: dict[str, Any],
        recorded_at: str | datetime,
        platform_preflight_sha256: str,
    ) -> dict[str, Any]:
        """Replay one due execution in memory without changing a ledger or pointer."""
        spec = self._experiment(strategy_id)
        day = _day(trade_date)
        moment = _timestamp(recorded_at)
        if moment.astimezone(SHANGHAI).date() != day:
            raise ForwardDataError("formal execution preparation cannot be backfilled")
        if moment.astimezone(SHANGHAI).time() < time(15, 0):
            raise ForwardDataError(
                "paper execution preparation requires a post-close final snapshot"
            )
        if self._safety_state(strategy_id).get("status") == "OPEN":
            raise ForwardHaltedError("strategy is halted until operator acknowledgement")
        signal = self._due_signal_record(strategy_id, day)
        formal_market = self._formal_market_snapshot(
            spec=spec,
            strategy_id=strategy_id,
            trade_date=day,
            cutoff_at=moment,
            market_reference=market_reference,
            required_codes=self._formal_market_required_codes(
                strategy_id=strategy_id,
                trade_date=day,
                include_due_signal=True,
            )
            if strategy_id in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
            and strategy_id != P1_STRATEGY_ID
            else [],
        )
        if formal_market is not None:
            market = formal_market
            valuation = formal_market
            market_source_bundle = dict(formal_market["source_bundle"])
        else:
            market_source_bundle = None
            market = self._approved_dataset(spec, market_reference, "execution")
            valuation = self._approved_dataset(spec, market_reference, "valuation")
            if market["manifest_sha256"] != valuation["manifest_sha256"]:
                raise ForwardDataError("execution and valuation snapshots diverged")
        self._assert_platform_execution_authorized(
            strategy_id=strategy_id,
            trade_date=day,
            preflight_sha256=platform_preflight_sha256,
            market_manifest_sha256=market.get("manifest_sha256"),
            market_source_bundle_sha256=(
                market_source_bundle["source_bundle_sha256"]
                if market_source_bundle is not None
                else None
            ),
        )
        if market["available_at"] > moment:
            raise ForwardDataError(
                "market snapshot was unavailable at execution preparation"
            )
        bars, marks = self._validate_market_payload(market["payload"], day)
        if _timestamp(str(market["payload"]["as_of_time"])) > moment:
            raise ForwardDataError("market snapshot as_of_time is after recorded_at")
        store = self._ledger_store(strategy_id)
        if store.inspect()["status"] != "READY":
            raise ForwardHaltedError(
                f"{strategy_id} ledger is not READY for execution preparation"
            )
        try:
            ledger, recovery = store.recover()
        except LedgerPersistenceError as exc:
            raise ForwardHaltedError(str(exc)) from exc
        if recovery.get("read_only"):
            raise ForwardHaltedError(
                f"{strategy_id} ledger recovery is read-only"
            )
        _bind_signal_risk_metadata(spec, ledger, signal)
        required_bars = set(signal["target_codes"]) | set(
            ledger.position_quantities
        )
        missing_marks = sorted(required_bars - set(marks))
        if missing_marks:
            raise ForwardDataError(
                "valuation marks missing for target/held positions: "
                + ", ".join(missing_marks)
            )
        missing_bars = sorted(required_bars - set(bars))
        if missing_bars:
            raise ForwardDataError(
                "execution bars missing for target/held positions: "
                + ", ".join(missing_bars)
            )
        source_snapshot = ledger.snapshot()
        preview = SimulationLedger.from_snapshot(source_snapshot)
        target_codes, target_weights = self._execution_targets(
            spec=spec, ledger=preview, signal=signal, marks=marks
        )
        initial_fill_count = len(preview.fills)
        rebalance = preview.rebalance(
            signal_date=str(signal["signal_date"]),
            trade_date=day.isoformat(),
            target_codes=target_codes,
            bars=bars,
            valuation_marks=marks,
            target_weights=target_weights,
        )
        reconciliation = preview.reconcile(
            day.isoformat(), marks=marks, data_integrity_ok=True
        )
        if reconciliation.get("ok") is not True:
            raise ForwardHaltedError("prepared daily ledger reconciliation failed")
        planned_snapshot = preview.snapshot()
        try:
            return build_pretrade_child_receipt(
                strategy_id=strategy_id,
                trade_date=day.isoformat(),
                recorded_at=moment.isoformat(),
                signal_sha256=str(signal["signal_sha256"]),
                market_manifest_sha256=str(market["manifest_sha256"]),
                platform_preflight_sha256=platform_preflight_sha256,
                source_checkpoint_sha256=str(
                    recovery["selected_checkpoint_sha256"]
                ),
                source_snapshot_sha256=str(source_snapshot["snapshot_sha256"]),
                planned_rebalance=rebalance,
                planned_fills=preview.fills[initial_fill_count:],
                planned_reconciliation=reconciliation,
                planned_equity=str(preview.equity(marks)),
                planned_cash=str(preview.cash),
                planned_positions_notional={
                    code: str(float(quantity) * float(marks[code]))
                    for code, quantity in preview.position_quantities.items()
                },
                planned_snapshot_sha256=str(
                    planned_snapshot["snapshot_sha256"]
                ),
            )
        except ExecutionOrchestrationError as exc:
            raise ForwardDataError(
                f"child execution preparation failed: {exc}"
            ) from exc

    def assess_prepared_executions(
        self,
        *,
        platform_preflight: dict[str, Any],
        child_receipts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Recheck exact preview states against parent capital and stress limits."""
        if platform_preflight.get("schema") != PLATFORM_PORTFOLIO_PREFLIGHT_SCHEMA:
            raise ForwardHaltedError(
                "prepared execution assessment requires the current preflight schema"
            )
        rows = [dict(item) for item in list(platform_preflight.get("portfolio_rows") or [])]
        if not rows:
            raise ForwardDataError("platform preflight lacks frozen portfolio rows")
        children = [validate_pretrade_child_receipt(item) for item in child_receipts]
        child_by_strategy = {str(item["strategy_id"]): item for item in children}
        if len(child_by_strategy) != len(children):
            raise ForwardDataError("prepared child strategies are duplicate")
        expected_execution_ids = {
            str(item["strategy_id"])
            for item in list(platform_preflight.get("execution_bindings") or [])
            if item.get("execution") is True
        }
        if set(child_by_strategy) != expected_execution_ids:
            raise ForwardDataError(
                "prepared child receipts do not cover every authorized execution"
            )

        absolute_rows: list[dict[str, Any]] = []
        stress_rows: list[dict[str, Any]] = []
        for row in rows:
            strategy_id = str(row.get("strategy_id") or "")
            child = child_by_strategy.get(strategy_id)
            if child is None:
                planned_equity = str(row["equity"])
                planned_cash = str(row["cash"])
                planned_positions = dict(row["current_positions_notional"])
            else:
                planned_equity = str(child["planned_equity"])
                planned_cash = str(child["planned_cash"])
                planned_positions = dict(child["planned_positions_notional"])
            absolute_rows.append(
                {
                    **row,
                    "equity": planned_equity,
                    "cash": planned_cash,
                    "current_positions_notional": planned_positions,
                    "proposed_positions_notional": planned_positions,
                }
            )
            stress_rows.append(
                {
                    **row,
                    "equity": str(
                        min(float(row["equity"]), float(planned_equity))
                    ),
                    "current_positions_notional": dict(
                        row["current_positions_notional"]
                    ),
                    "proposed_positions_notional": planned_positions,
                }
            )
        expected_ids = sorted(str(item["strategy_id"]) for item in rows)
        try:
            concentration = PlatformPortfolioSupervisor(
                self._platform_policy()
            ).assess(absolute_rows, expected_strategy_ids=expected_ids)
            stress = PortfolioStressSupervisor(
                self._portfolio_stress_policy()
            ).assess(stress_rows)
        except (TypeError, ValueError, KeyError) as exc:
            raise ForwardDataError(
                f"prepared execution risk assessment failed: {exc}"
            ) from exc

        monitor_observation = (
            not children
            and platform_preflight.get("effective_decision") == "MONITOR_ONLY"
        )
        exact_metrics = dict(concentration["proposed"])
        exact_breaches = list(exact_metrics.get("breaches") or [])
        concentration_decision = "MONITOR_ONLY" if monitor_observation else "PASS"
        risk_reducing = False
        if exact_breaches and not monitor_observation:
            original_current = dict(
                dict(platform_preflight["assessment"])["current"]
            )
            original_breaches = set(original_current.get("breaches") or [])
            platform_codes = [
                code for code in exact_breaches if str(code).startswith("PLATFORM_")
            ]
            restriction_codes = sorted(set(exact_breaches) - set(platform_codes))
            comparable = all(code in original_breaches for code in platform_codes)
            nonworsening = comparable and all(
                PlatformPortfolioSupervisor._breach_measure(code, exact_metrics)
                <= PlatformPortfolioSupervisor._breach_measure(
                    code, original_current
                )
                for code in platform_codes
            )
            strict_improvement = comparable and any(
                PlatformPortfolioSupervisor._breach_measure(code, exact_metrics)
                < PlatformPortfolioSupervisor._breach_measure(
                    code, original_current
                )
                for code in platform_codes
            )
            gross_reduced = float(exact_metrics["gross_exposure_pct"]) < float(
                original_current["gross_exposure_pct"]
            )
            restrictions_reduced = (
                all(str(code).startswith("STRATEGY_") for code in restriction_codes)
                and gross_reduced
            )
            risk_reducing = (
                platform_preflight.get("effective_decision") == "REDUCE_ONLY"
                and nonworsening
                and (strict_improvement or gross_reduced)
                and (not restriction_codes or restrictions_reduced)
            )
            concentration_decision = "REDUCE_ONLY" if risk_reducing else "BLOCKED"
        allowed_stress_decisions = {"PASS", "REDUCE_ONLY"}
        if monitor_observation:
            allowed_stress_decisions.add("MONITOR_ONLY")
        if (
            concentration_decision == "BLOCKED"
            or stress.get("decision") not in allowed_stress_decisions
        ):
            blockers = sorted(
                set(exact_breaches + list(stress["proposed"]["breaches"]))
            )
            raise ForwardHaltedError(
                "exact prepared executions violate parent risk: "
                + ", ".join(blockers or ["UNEXPLAINED_PREPARED_RISK"])
            )
        if concentration["decision"] != concentration_decision:
            identity = {
                key: value
                for key, value in concentration.items()
                if key != "assessment_sha256"
            }
            identity["decision"] = concentration_decision
            identity["risk_reducing"] = risk_reducing
            concentration = {
                **identity,
                "assessment_sha256": sha256_digest(identity),
            }
        return {
            "prepared_portfolio_assessment": concentration,
            "prepared_stress_assessment": stress,
        }

    def _assert_pretrade_execution_authorized(
        self,
        *,
        strategy_id: str,
        trade_date: date,
        pretrade_batch_sha256: str | None,
        platform_preflight_sha256: str | None,
        signal_sha256: str,
        market_manifest_sha256: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if pretrade_batch_sha256 is None:
            raise ForwardHaltedError(
                "formal execution requires a frozen pretrade execution batch"
            )
        digest = _hash(pretrade_batch_sha256, "pretrade execution batch")
        try:
            batch = validate_pretrade_execution_batch(
                _hashed_record(
                    self.runtime_root
                    / "_pretrade_execution_batches"
                    / "records"
                    / f"{digest}.json",
                    "pretrade_batch_sha256",
                )
            )
        except (ExecutionOrchestrationError, ForwardPaperError) as exc:
            raise ForwardHaltedError(
                f"pretrade execution batch is invalid: {exc}"
            ) from exc
        if (
            batch["trade_date"] != trade_date.isoformat()
            or batch["platform_preflight_sha256"]
            != _hash(platform_preflight_sha256, "platform preflight")
        ):
            raise ForwardConflictError("pretrade execution batch identity mismatch")
        if (
            dict(batch["prepared_portfolio_assessment"].get("policy") or {}).get(
                "policy_sha256"
            )
            != self._platform_policy().evidence()["policy_sha256"]
            or dict(batch["prepared_stress_assessment"].get("policy") or {}).get(
                "policy_sha256"
            )
            != self._portfolio_stress_policy().evidence()["policy_sha256"]
        ):
            raise ForwardHaltedError(
                "prepared execution risk policies differ from current policies"
            )
        children = [
            dict(item)
            for item in list(batch["child_receipts"])
            if item.get("strategy_id") == strategy_id
        ]
        if len(children) != 1:
            raise ForwardConflictError(
                "strategy is absent or duplicated in pretrade execution batch"
            )
        child = children[0]
        if (
            child["signal_sha256"] != _hash(signal_sha256, "due signal")
            or child["market_manifest_sha256"]
            != _hash(market_manifest_sha256, "market manifest")
        ):
            raise ForwardConflictError(
                "pretrade child receipt differs from due execution evidence"
            )
        plan = dict(batch["parent_order_allocation_plan"])
        stored_plan = _hashed_record(
            self.runtime_root
            / "_parent_order_allocation"
            / "plans"
            / "records"
            / f"{plan['allocation_plan_sha256']}.json",
            "allocation_plan_sha256",
        )
        if stored_plan != plan:
            raise ForwardConflictError(
                "pretrade batch and independent parent allocation record diverged"
            )
        return batch, child

    @staticmethod
    def _assert_execution_matches_pretrade(
        *,
        child: dict[str, Any],
        ledger: SimulationLedger,
        committed: dict[str, Any],
        rebalance: dict[str, Any],
        reconciliation: dict[str, Any],
        equity: float,
    ) -> None:
        actual_fills = [
            dict(item)
            for item in ledger.fills
            if str(item.get("date")) == str(child["trade_date"])
        ]
        mismatches: list[str] = []
        if actual_fills != list(child["planned_fills"]):
            mismatches.append("fills")
        if rebalance != dict(child["planned_rebalance"]):
            mismatches.append("rebalance")
        if reconciliation != dict(child["planned_reconciliation"]):
            mismatches.append("reconciliation")
        if str(committed.get("snapshot_sha256") or "") != str(
            child["planned_snapshot_sha256"]
        ):
            mismatches.append("snapshot_sha256")
        if abs(float(child["planned_equity"]) - float(equity)) > 0.000001:
            mismatches.append("equity")
        if mismatches:
            raise ForwardConflictError(
                "committed paper execution differs from its pretrade preparation: "
                + ", ".join(mismatches)
            )

    def _build_receipt(
        self,
        *,
        spec: dict[str, Any],
        signal: dict[str, Any],
        market: dict[str, Any],
        recorded_at: datetime,
        committed: dict[str, Any],
        ledger: SimulationLedger,
        rebalance: dict[str, Any],
        reconciliation: dict[str, Any],
        equity: float,
        recovered: bool,
        market_source_bundle_sha256: str | None,
        pretrade_batch: dict[str, Any],
        pretrade_child: dict[str, Any],
    ) -> dict[str, Any]:
        report = ledger.report()
        identity = {
            "schema": FORWARD_RUN_RECEIPT_SCHEMA,
            "strategy_id": spec["strategy_id"],
            "trade_date": signal["execute_on"],
            "recorded_at": recorded_at.isoformat(),
            "signal_sha256": signal["signal_sha256"],
            "market_dataset_id": market["dataset_id"],
            "market_manifest_sha256": market["manifest_sha256"],
            "market_payload_sha256": market["payload_sha256"],
            "market_source_bundle_sha256": market_source_bundle_sha256,
            "market_source_bundle": (
                dict(market["source_bundle"])
                if market.get("source_bundle") is not None
                else None
            ),
            "market_materialization": (
                dict(market["materialization"])
                if market.get("materialization") is not None
                else None
            ),
            "checkpoint_sha256": committed["checkpoint_sha256"],
            "snapshot_sha256": committed["snapshot_sha256"],
            "operation_key": committed["operation_key"],
            "pretrade_batch_sha256": pretrade_batch["pretrade_batch_sha256"],
            "pretrade_child_receipt_sha256": pretrade_child["receipt_sha256"],
            "allocation_plan_sha256": pretrade_batch[
                "parent_order_allocation_plan"
            ]["allocation_plan_sha256"],
            "spec_sha256": spec["spec_sha256"],
            "execution_config_sha256": str(spec["execution_config_sha256"]).lower(),
            "target_codes": signal["target_codes"],
            "target_weights": signal["target_weights"],
            "rebalance": rebalance,
            "fills": [
                dict(item)
                for item in ledger.fills
                if str(item.get("date")) == str(signal["execute_on"])
            ],
            "reconciliation": reconciliation,
            "equity": round(float(equity), 6),
            "ledger_summary": report["summary"],
            "portfolio_risk": report.get("portfolio_risk"),
            "recovered_after_receipt_interruption": recovered,
            "real_orders": False,
        }
        return {**identity, "receipt_sha256": sha256_digest(identity)}

    def _build_observation_receipt(
        self,
        *,
        spec: dict[str, Any],
        trade_date: date,
        market: dict[str, Any],
        recorded_at: datetime,
        committed: dict[str, Any],
        ledger: SimulationLedger,
        reconciliation: dict[str, Any],
        equity: float,
        recovered: bool,
        market_source_bundle_sha256: str | None,
    ) -> dict[str, Any]:
        report = ledger.report()
        identity = {
            "schema": FORWARD_OBSERVATION_RECEIPT_SCHEMA,
            "strategy_id": spec["strategy_id"],
            "trade_date": trade_date.isoformat(),
            "recorded_at": recorded_at.isoformat(),
            "market_dataset_id": market["dataset_id"],
            "market_manifest_sha256": market["manifest_sha256"],
            "market_payload_sha256": market["payload_sha256"],
            "market_source_bundle_sha256": market_source_bundle_sha256,
            "market_source_bundle": (
                dict(market["source_bundle"])
                if market.get("source_bundle") is not None
                else None
            ),
            "market_materialization": (
                dict(market["materialization"])
                if market.get("materialization") is not None
                else None
            ),
            "checkpoint_sha256": committed["checkpoint_sha256"],
            "snapshot_sha256": committed["snapshot_sha256"],
            "operation_key": committed["operation_key"],
            "spec_sha256": spec["spec_sha256"],
            "execution_config_sha256": str(spec["execution_config_sha256"]).lower(),
            "reconciliation": reconciliation,
            "equity": round(float(equity), 6),
            "ledger_summary": report["summary"],
            "portfolio_risk": report.get("portfolio_risk"),
            "recovered_after_receipt_interruption": recovered,
            "real_orders": False,
        }
        return {**identity, "receipt_sha256": sha256_digest(identity)}

    @_locked_mutation
    def observe_session(
        self,
        strategy_id: str,
        *,
        trade_date: str,
        market_reference: dict[str, Any],
        recorded_at: str | datetime,
    ) -> dict[str, Any]:
        """Persist a no-trade daily close, equity and risk observation."""
        spec = self._experiment(strategy_id)
        day = _day(trade_date)
        moment = _timestamp(recorded_at)
        if moment.astimezone(SHANGHAI).date() != day:
            raise ForwardDataError("formal observations cannot be backfilled")
        if moment.astimezone(SHANGHAI).time() < time(15, 0):
            raise ForwardDataError("paper observations require a post-close session snapshot")
        if self._safety_state(strategy_id).get("status") == "OPEN":
            raise ForwardHaltedError("strategy is halted until operator acknowledgement")
        if self._receipt_path(strategy_id, day).is_file():
            raise ForwardConflictError("session is already finalized by a due execution")

        formal_market = self._formal_market_snapshot(
            spec=spec,
            strategy_id=strategy_id,
            trade_date=day,
            cutoff_at=moment,
            market_reference=market_reference,
            required_codes=self._formal_market_required_codes(
                strategy_id=strategy_id,
                trade_date=day,
                include_due_signal=False,
            )
            if strategy_id in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
            and strategy_id != P1_STRATEGY_ID
            else [],
        )
        if formal_market is not None:
            market = formal_market
            market_source_bundle = dict(formal_market["source_bundle"])
        else:
            market = self._approved_dataset(spec, market_reference, "valuation")
            market_source_bundle = None
        market_source_bundle_sha = (
            market_source_bundle["source_bundle_sha256"]
            if market_source_bundle is not None
            else None
        )

        if market["available_at"] > moment:
            raise ForwardDataError("market snapshot was unavailable at observation finalization")
        _, marks = self._validate_market_payload(market["payload"], day)
        if _timestamp(str(market["payload"]["as_of_time"])) > moment:
            raise ForwardDataError("market snapshot as_of_time is after recorded_at")

        pointer_path = self._observation_path(strategy_id, day)
        market_sha = str(market["manifest_sha256"])
        if pointer_path.is_file():
            pointer = _read_json(pointer_path)
            if (
                pointer.get("market_manifest_sha256") != market_sha
                or pointer.get("market_source_bundle_sha256")
                != market_source_bundle_sha
            ):
                raise ForwardConflictError(
                    "observation date already finalized with different evidence"
                )
            receipt = _hashed_record(
                self._strategy_root(strategy_id)
                / "observations"
                / "receipts"
                / f"{pointer['receipt_sha256']}.json",
                "receipt_sha256",
            )
            return {**receipt, "idempotent": True}

        store = self._ledger_store(strategy_id)
        inspection = store.inspect()
        if inspection["status"] != "READY":
            self._halt(
                strategy_id,
                "persistent ledger is not initialized or is degraded",
                {"trade_date": day.isoformat(), "inspection": inspection},
            )
            raise ForwardHaltedError("persistent ledger is not initialized or is degraded")
        operation_key = (
            f"observe:{strategy_id}:{day.isoformat()}:{market_sha}:"
            f"{market_source_bundle_sha or 'legacy'}"
        )
        committed_operation = store.committed_operation(operation_key)
        try:
            if committed_operation is not None:
                ledger, operation = store.recover_operation(operation_key)
                committed = {**operation, "operation_key": operation_key}
                recovered = True
                reconciliation = dict(ledger.report().get("latest_reconciliation") or {})
            else:
                ledger, recovery = store.recover()
                if recovery["read_only"]:
                    raise LedgerReadOnlyError(
                        "degraded recovery requires operator acknowledgement"
                    )
                missing_marks = sorted(set(ledger.position_quantities) - set(marks))
                if missing_marks:
                    raise ForwardDataError(
                        "valuation marks missing for held positions: "
                        + ", ".join(missing_marks)
                    )
                reconciliation = ledger.reconcile(
                    day.isoformat(), marks=marks, data_integrity_ok=True
                )
                if reconciliation.get("ok") is not True:
                    raise ForwardHaltedError("daily ledger reconciliation failed")
                committed = store.commit(ledger, operation_key)
                recovered = False
            missing_marks = sorted(set(ledger.position_quantities) - set(marks))
            if missing_marks:
                raise ForwardDataError(
                    "valuation marks missing for held positions: "
                    + ", ".join(missing_marks)
                )
            equity = ledger.equity(marks)
            receipt = self._build_observation_receipt(
                spec=spec,
                trade_date=day,
                market=market,
                recorded_at=moment,
                committed=committed,
                ledger=ledger,
                reconciliation=reconciliation,
                equity=float(equity),
                recovered=recovered,
                market_source_bundle_sha256=market_source_bundle_sha,
            )
        except (ForwardPaperError, LedgerPersistenceError, ValueError, KeyError) as exc:
            self._halt(
                strategy_id,
                f"{type(exc).__name__}: {exc}",
                {
                    "trade_date": day.isoformat(),
                    "market_manifest_sha256": market_sha,
                    "operation": "observe_session",
                },
            )
            raise

        root = self._strategy_root(strategy_id) / "observations"
        _immutable_json(root / "receipts" / f"{receipt['receipt_sha256']}.json", receipt)
        _atomic_json(
            pointer_path,
            {
                "trade_date": day.isoformat(),
                "receipt_sha256": receipt["receipt_sha256"],
                "market_manifest_sha256": market_sha,
                "market_source_bundle_sha256": market_source_bundle_sha,
            },
        )
        return {**receipt, "idempotent": recovered}

    @_locked_mutation
    def execute_due(
        self,
        strategy_id: str,
        *,
        trade_date: str,
        market_reference: dict[str, Any],
        recorded_at: str | datetime,
        platform_preflight_sha256: str | None = None,
        pretrade_batch_sha256: str | None = None,
    ) -> dict[str, Any]:
        spec = self._experiment(strategy_id)
        day = _day(trade_date)
        moment = _timestamp(recorded_at)
        if moment.astimezone(SHANGHAI).date() != day:
            raise ForwardDataError("formal executions cannot be backfilled")
        if moment.astimezone(SHANGHAI).time() < time(15, 0):
            raise ForwardDataError("paper fills are finalized only from a post-close session snapshot")
        if self._safety_state(strategy_id).get("status") == "OPEN":
            raise ForwardHaltedError("strategy is halted until operator acknowledgement")
        signal = self._due_signal_record(strategy_id, day)
        formal_market = self._formal_market_snapshot(
            spec=spec,
            strategy_id=strategy_id,
            trade_date=day,
            cutoff_at=moment,
            market_reference=market_reference,
            required_codes=self._formal_market_required_codes(
                strategy_id=strategy_id,
                trade_date=day,
                include_due_signal=True,
            )
            if strategy_id in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
            and strategy_id != P1_STRATEGY_ID
            else [],
        )
        if formal_market is not None:
            market = formal_market
            valuation = formal_market
            market_source_bundle = dict(formal_market["source_bundle"])
        else:
            market_source_bundle = None
            market = self._approved_dataset(spec, market_reference, "execution")
            valuation = self._approved_dataset(spec, market_reference, "valuation")
            if market["manifest_sha256"] != valuation["manifest_sha256"]:
                raise ForwardDataError("execution and valuation snapshots diverged")
        market_source_bundle_sha = (
            market_source_bundle["source_bundle_sha256"]
            if market_source_bundle is not None
            else None
        )
        self._assert_platform_execution_authorized(
            strategy_id=strategy_id,
            trade_date=day,
            preflight_sha256=platform_preflight_sha256,
            market_manifest_sha256=market.get("manifest_sha256"),
            market_source_bundle_sha256=market_source_bundle_sha,
        )

        if market["available_at"] > moment:
            raise ForwardDataError("market snapshot was unavailable at execution finalization")
        bars, marks = self._validate_market_payload(market["payload"], day)
        if _timestamp(str(market["payload"]["as_of_time"])) > moment:
            raise ForwardDataError("market snapshot as_of_time is after recorded_at")
        pretrade_batch, pretrade_child = self._assert_pretrade_execution_authorized(
            strategy_id=strategy_id,
            trade_date=day,
            pretrade_batch_sha256=pretrade_batch_sha256,
            platform_preflight_sha256=platform_preflight_sha256,
            signal_sha256=str(signal["signal_sha256"]),
            market_manifest_sha256=str(market["manifest_sha256"]),
        )

        receipt_pointer = self._receipt_path(strategy_id, day)
        if self._observation_path(strategy_id, day).is_file():
            raise ForwardConflictError("session is already finalized as a no-trade observation")
        market_sha = str(market["manifest_sha256"])
        if receipt_pointer.is_file():
            pointer = _read_json(receipt_pointer)
            if (
                pointer.get("signal_sha256") != signal["signal_sha256"]
                or pointer.get("market_manifest_sha256") != market_sha
                or pointer.get("market_source_bundle_sha256")
                != market_source_bundle_sha
            ):
                raise ForwardConflictError("execution date already finalized with different evidence")
            try:
                receipt = _hashed_record(
                    self._strategy_root(strategy_id)
                    / "runs"
                    / "receipts"
                    / f"{pointer['receipt_sha256']}.json",
                    "receipt_sha256",
                )
                if receipt.get("schema") != FORWARD_RUN_RECEIPT_SCHEMA or not isinstance(
                    receipt.get("fills"), list
                ):
                    raise ForwardDataError(
                        "legacy execution receipt lacks pretrade binding"
                    )
                if (
                    receipt.get("pretrade_batch_sha256")
                    != pretrade_batch["pretrade_batch_sha256"]
                    or receipt.get("pretrade_child_receipt_sha256")
                    != pretrade_child["receipt_sha256"]
                    or receipt.get("allocation_plan_sha256")
                    != pretrade_batch["parent_order_allocation_plan"][
                        "allocation_plan_sha256"
                    ]
                    or receipt.get("market_source_bundle_sha256")
                    != market_source_bundle_sha
                ):
                    raise ForwardConflictError(
                        "execution receipt differs from frozen pretrade evidence"
                    )
            except ForwardPaperError as exc:
                self._halt(
                    strategy_id,
                    f"execution receipt integrity failure: {exc}",
                    {"trade_date": day.isoformat(), "receipt_pointer": pointer},
                )
                raise
            return {**receipt, "idempotent": True}

        store = self._ledger_store(strategy_id)
        inspection = store.inspect()
        if inspection["status"] != "READY":
            self._halt(
                strategy_id,
                "persistent ledger is not initialized or is degraded",
                {"trade_date": day.isoformat(), "inspection": inspection},
            )
            raise ForwardHaltedError("persistent ledger is not initialized or is degraded")
        operation_key = (
            f"execute:{strategy_id}:{signal['signal_sha256']}:{market['manifest_sha256']}:"
            f"{pretrade_batch['pretrade_batch_sha256']}:"
            f"{market_source_bundle_sha or 'legacy'}"
        )
        committed_operation = store.committed_operation(operation_key)
        if committed_operation is not None:
            try:
                ledger, operation = store.recover_operation(operation_key)
                missing_marks = sorted(set(ledger.position_quantities) - set(marks))
                if missing_marks:
                    raise ForwardDataError(
                        f"valuation marks missing for recovered positions: {', '.join(missing_marks)}"
                    )
                reconciliation = dict(ledger.report().get("latest_reconciliation") or {})
                equity = ledger.equity(marks)
                committed = {**operation, "operation_key": operation_key}
                rebalance = dict(pretrade_child["planned_rebalance"])
                self._assert_execution_matches_pretrade(
                    child=pretrade_child,
                    ledger=ledger,
                    committed=committed,
                    rebalance=rebalance,
                    reconciliation=reconciliation,
                    equity=float(equity),
                )
                receipt = self._build_receipt(
                    spec=spec,
                    signal=signal,
                    market=market,
                    recorded_at=moment,
                    committed=committed,
                    ledger=ledger,
                    rebalance=rebalance,
                    reconciliation=reconciliation,
                    equity=float(equity),
                    recovered=True,
                    market_source_bundle_sha256=market_source_bundle_sha,
                    pretrade_batch=pretrade_batch,
                    pretrade_child=pretrade_child,
                )
            except (ForwardPaperError, LedgerPersistenceError, ValueError, KeyError) as exc:
                self._halt(
                    strategy_id,
                    f"{type(exc).__name__}: {exc}",
                    {
                        "trade_date": day.isoformat(),
                        "signal_sha256": signal["signal_sha256"],
                        "market_manifest_sha256": market_sha,
                    },
                )
                raise
        else:
            try:
                ledger, recovery = store.recover()
                if recovery["read_only"]:
                    raise LedgerReadOnlyError("degraded recovery requires operator acknowledgement")
                _bind_signal_risk_metadata(spec, ledger, signal)
                source_snapshot = ledger.snapshot()
                if (
                    str(recovery.get("selected_checkpoint_sha256") or "")
                    != pretrade_child["source_checkpoint_sha256"]
                    or source_snapshot["snapshot_sha256"]
                    != pretrade_child["source_snapshot_sha256"]
                ):
                    raise ForwardConflictError(
                        "child ledger changed after pretrade preparation"
                    )
                required_bars = set(signal["target_codes"]) | set(ledger.position_quantities)
                missing_marks = sorted(required_bars - set(marks))
                if missing_marks:
                    raise ForwardDataError(
                        f"valuation marks missing for target/held positions: {', '.join(missing_marks)}"
                    )
                missing_bars = sorted(required_bars - set(bars))
                if missing_bars:
                    raise ForwardDataError(
                        f"execution bars missing for target/held positions: {', '.join(missing_bars)}"
                    )
                target_codes, target_weights = self._execution_targets(
                    spec=spec,
                    ledger=ledger,
                    signal=signal,
                    marks=marks,
                )
                rebalance = ledger.rebalance(
                    signal_date=str(signal["signal_date"]),
                    trade_date=day.isoformat(),
                    target_codes=target_codes,
                    bars=bars,
                    valuation_marks=marks,
                    target_weights=target_weights,
                )
                reconciliation = ledger.reconcile(
                    day.isoformat(), marks=marks, data_integrity_ok=True
                )
                if reconciliation.get("ok") is not True:
                    raise ForwardHaltedError("daily ledger reconciliation failed")
                equity = ledger.equity(marks)
                candidate_snapshot = ledger.snapshot()
                self._assert_execution_matches_pretrade(
                    child=pretrade_child,
                    ledger=ledger,
                    committed={
                        "snapshot_sha256": candidate_snapshot[
                            "snapshot_sha256"
                        ]
                    },
                    rebalance=rebalance,
                    reconciliation=reconciliation,
                    equity=float(equity),
                )
                committed = store.commit(ledger, operation_key)
                if (
                    committed["snapshot_sha256"]
                    != candidate_snapshot["snapshot_sha256"]
                ):
                    raise ForwardConflictError(
                        "committed snapshot differs from validated candidate"
                    )
                receipt = self._build_receipt(
                    spec=spec,
                    signal=signal,
                    market=market,
                    recorded_at=moment,
                    committed=committed,
                    ledger=ledger,
                    rebalance=rebalance,
                    reconciliation=reconciliation,
                    equity=float(equity),
                    recovered=False,
                    market_source_bundle_sha256=market_source_bundle_sha,
                    pretrade_batch=pretrade_batch,
                    pretrade_child=pretrade_child,
                )
            except (ForwardPaperError, LedgerPersistenceError, ValueError, KeyError) as exc:
                self._halt(
                    strategy_id,
                    f"{type(exc).__name__}: {exc}",
                    {
                        "trade_date": day.isoformat(),
                        "signal_sha256": signal["signal_sha256"],
                        "market_manifest_sha256": market_sha,
                    },
                )
                raise

        root = self._strategy_root(strategy_id) / "runs"
        _immutable_json(root / "receipts" / f"{receipt['receipt_sha256']}.json", receipt)
        _atomic_json(
            receipt_pointer,
            {
                "trade_date": day.isoformat(),
                "receipt_sha256": receipt["receipt_sha256"],
                "signal_sha256": signal["signal_sha256"],
                "market_manifest_sha256": market_sha,
                "market_source_bundle_sha256": market_source_bundle_sha,
            },
        )
        return {
            **receipt,
            "idempotent": bool(receipt.get("recovered_after_receipt_interruption")),
        }

    def strategy_status(self, strategy_id: str) -> dict[str, Any]:
        spec = self._experiment(strategy_id)
        root = self._strategy_root(strategy_id)
        inspection = self._ledger_store(strategy_id).inspect()
        signal_pointers = sorted((root / "signals" / "by-date").glob("*.json"))
        run_pointers = sorted((root / "runs" / "by-date").glob("*.json"))
        observation_pointers = sorted(
            (root / "observations" / "by-date").glob("*.json")
        )
        receipts: list[dict[str, Any]] = []
        observations: list[dict[str, Any]] = []
        receipt_errors: list[str] = []
        observation_errors: list[str] = []
        signal_errors: list[str] = []
        for path in signal_pointers:
            try:
                pointer = _read_json(path)
                signal_record = _hashed_record(
                    root / "signals" / "records" / f"{pointer['signal_sha256']}.json",
                    "signal_sha256",
                )
                for reference in list(signal_record.get("data_refs") or []):
                    verification = self.catalog.verify(
                        str(reference["dataset_id"]), str(reference["manifest_sha256"])
                    )
                    if verification["verified"] is not True:
                        raise ForwardDataError(
                            f"signal catalog evidence failed verification: {verification['errors']}"
                        )
            except ForwardPaperError as exc:
                signal_errors.append(str(exc))
        for path in run_pointers:
            try:
                pointer = _read_json(path)
                receipt = _hashed_record(
                    root / "runs" / "receipts" / f"{pointer['receipt_sha256']}.json",
                    "receipt_sha256",
                )
                if receipt.get("schema") != FORWARD_RUN_RECEIPT_SCHEMA or not isinstance(
                    receipt.get("fills"), list
                ):
                    raise ForwardDataError(
                        "legacy execution receipt lacks pretrade binding"
                    )
                try:
                    prepared = validate_pretrade_execution_batch(
                        _hashed_record(
                            self.runtime_root
                            / "_pretrade_execution_batches"
                            / "records"
                            / f"{receipt['pretrade_batch_sha256']}.json",
                            "pretrade_batch_sha256",
                        )
                    )
                except (ExecutionOrchestrationError, KeyError) as exc:
                    raise ForwardDataError(
                        f"execution pretrade evidence is invalid: {exc}"
                    ) from exc
                children = [
                    dict(item)
                    for item in list(prepared["child_receipts"])
                    if item.get("receipt_sha256")
                    == receipt.get("pretrade_child_receipt_sha256")
                    and item.get("strategy_id") == strategy_id
                ]
                if (
                    len(children) != 1
                    or list(children[0]["planned_fills"])
                    != list(receipt["fills"])
                    or prepared["parent_order_allocation_plan"][
                        "allocation_plan_sha256"
                    ]
                    != receipt.get("allocation_plan_sha256")
                ):
                    raise ForwardDataError(
                        "execution receipt differs from pretrade preparation"
                    )
                verification = self.catalog.verify(
                    str(receipt["market_dataset_id"]),
                    str(receipt["market_manifest_sha256"]),
                )
                if verification["verified"] is not True:
                    raise ForwardDataError(
                        f"execution catalog evidence failed verification: {verification['errors']}"
                    )
                receipts.append(receipt)
            except ForwardPaperError as exc:
                receipt_errors.append(str(exc))
        for path in observation_pointers:
            try:
                pointer = _read_json(path)
                receipt = _hashed_record(
                    root
                    / "observations"
                    / "receipts"
                    / f"{pointer['receipt_sha256']}.json",
                    "receipt_sha256",
                )
                verification = self.catalog.verify(
                    str(receipt["market_dataset_id"]),
                    str(receipt["market_manifest_sha256"]),
                )
                if verification["verified"] is not True:
                    raise ForwardDataError(
                        "observation catalog evidence failed verification: "
                        f"{verification['errors']}"
                    )
                observations.append(receipt)
            except ForwardPaperError as exc:
                observation_errors.append(str(exc))
        session_records = sorted(
            [*receipts, *observations], key=lambda item: str(item["trade_date"])
        )
        session_dates = [str(item["trade_date"]) for item in session_records]
        if len(session_dates) != len(set(session_dates)):
            observation_errors.append(
                "a trading date is finalized by both execution and observation"
            )
        safety = self._safety_state(strategy_id)
        zero_reconciliation_failures = bool(session_records) and all(
            item.get("reconciliation", {}).get("ok") is True
            for item in session_records
        )
        zero_risk_breaches = bool(session_records) and all(
            not list(
                (
                    (item.get("portfolio_risk") or {}).get("latest_assessment") or {}
                ).get("breaches")
                or []
            )
            for item in session_records
        )
        current_equity = (
            float(session_records[-1]["equity"])
            if session_records
            else float(spec["initial_cash"])
        )
        maximum_loss_pct = float(dict(spec.get("loss_budget") or {}).get("maximum_loss_pct") or 0)
        loss_pct = max(
            [0.0]
            + [
                (float(spec["initial_cash"]) - float(item["equity"]))
                / float(spec["initial_cash"])
                * 100
                for item in session_records
            ]
        )
        loss_budget_intact = maximum_loss_pct > 0 and loss_pct <= maximum_loss_pct
        halt_event_count = len(list((root / "safety" / "events").glob("*.json")))
        prospective_gate = dict(
            dict(spec["strategy_config"].get("activation") or {}).get(
                "prospective_gate"
            )
            or {}
        )
        performance = (
            calculate_forward_performance(
                session_records,
                initial_cash=float(spec["initial_cash"]),
                prospective_gate=prospective_gate,
            )
            if prospective_gate
            else {
                "schema": "quant-platform/forward-performance-evidence/v1",
                "source": "NOT_CONFIGURED",
                "thresholds": {},
                "metrics": {},
                "checks": [],
                "passed": False,
                "evidence_sha256": None,
            }
        )
        performance_evidence = {
            "prospective_only": performance.get("source")
            == "FORMAL_FORWARD_SESSIONS_ONLY",
            **dict(performance.get("thresholds") or {}),
            **dict(performance.get("metrics") or {}),
        }
        platform_preflight_errors: list[str] = []
        platform_preflights: list[dict[str, Any]] = []
        platform_preflight_root = (
            self.runtime_root / "_platform_portfolio" / "preflights" / "records"
        )
        for path in sorted(platform_preflight_root.glob("*.json")):
            try:
                platform_preflights.append(
                    _hashed_record(path, "preflight_sha256")
                )
            except ForwardPaperError as exc:
                platform_preflight_errors.append(str(exc))
        try:
            platform_policy_bound = bool(
                self._platform_policy().evidence()["policy_sha256"]
            )
        except ForwardPaperError as exc:
            platform_policy_bound = False
            platform_preflight_errors.append(str(exc))
        try:
            stress_policy_bound = bool(
                self._portfolio_stress_policy().evidence()["policy_sha256"]
            )
        except ForwardPaperError as exc:
            stress_policy_bound = False
            platform_preflight_errors.append(str(exc))
        zero_platform_breaches = (
            bool(platform_preflights)
            and not platform_preflight_errors
            and self._platform_safety_state().get("status") == "CLEAR"
            and all(
                item.get("effective_decision") == "PASS"
                and not list(item.get("blockers") or [])
                for item in platform_preflights
            )
        )
        zero_stress_breaches = (
            bool(platform_preflights)
            and stress_policy_bound
            and not platform_preflight_errors
            and self._platform_safety_state().get("status") == "CLEAR"
            and all(
                dict(item.get("stress_assessment") or {}).get("decision")
                == "PASS"
                and not list(
                    dict(
                        dict(item.get("stress_assessment") or {}).get(
                            "proposed"
                        )
                        or {}
                    ).get("breaches")
                    or []
                )
                for item in platform_preflights
            )
        )
        allocation_errors: list[str] = []
        allocation_records: list[dict[str, Any]] = []
        allocation_root = (
            self.runtime_root / "_parent_order_allocation" / "plans" / "records"
        )
        for path in sorted(allocation_root.glob("*.json")):
            try:
                allocation_records.append(
                    validate_parent_order_plan(
                        _hashed_record(path, "allocation_plan_sha256")
                    )
                )
            except (ForwardPaperError, OrderAllocationError, KeyError) as exc:
                allocation_errors.append(str(exc))
        pretrade_errors: list[str] = []
        pretrade_records: list[dict[str, Any]] = []
        pretrade_root = (
            self.runtime_root / "_pretrade_execution_batches" / "records"
        )
        for path in sorted(pretrade_root.glob("*.json")):
            try:
                prepared = validate_pretrade_execution_batch(
                    _hashed_record(path, "pretrade_batch_sha256")
                )
                plan = dict(prepared["parent_order_allocation_plan"])
                if plan not in allocation_records:
                    raise ForwardDataError(
                        "pretrade batch has no matching allocation record"
                    )
                if (
                    dict(
                        prepared["prepared_portfolio_assessment"].get("policy")
                        or {}
                    ).get("policy_sha256")
                    != self._platform_policy().evidence()["policy_sha256"]
                    or dict(
                        prepared["prepared_stress_assessment"].get("policy")
                        or {}
                    ).get("policy_sha256")
                    != self._portfolio_stress_policy().evidence()[
                        "policy_sha256"
                    ]
                ):
                    raise ForwardDataError(
                        "pretrade batch risk policy binding is stale"
                    )
                pretrade_records.append(prepared)
            except (
                ForwardPaperError,
                ExecutionOrchestrationError,
                KeyError,
            ) as exc:
                pretrade_errors.append(str(exc))
        expected_allocation_intents = {
            (
                f"{strategy_id}:{fill['id']}",
                str(receipt.get("pretrade_child_receipt_sha256") or ""),
            )
            for receipt in receipts
            for fill in list(receipt.get("fills") or [])
        }
        actual_allocation_intents = {
            (
                str(intent.get("intent_id") or ""),
                str(intent.get("source_receipt_sha256") or ""),
            )
            for plan in allocation_records
            for intent in list(plan.get("child_intents") or [])
            if str(intent.get("strategy_id") or "") == strategy_id
        }
        strategy_snapshot_paths = {
            str(item.get("path") or "")
            for item in list(dict(spec.get("code_snapshot") or {}).get("files") or [])
        }
        parent_order_allocation_bound = (
            PARENT_ORDER_ALLOCATION_SNAPSHOT_PATHS <= strategy_snapshot_paths
        )
        pretrade_execution_bound = (
            PRETRADE_ORCHESTRATION_SNAPSHOT_PATHS <= strategy_snapshot_paths
        )
        parent_order_allocation_complete = (
            bool(allocation_records)
            and not allocation_errors
            and expected_allocation_intents == actual_allocation_intents
        )
        prepared_pairs = {
            (
                str(child["receipt_sha256"]),
                str(prepared["pretrade_batch_sha256"]),
            )
            for prepared in pretrade_records
            for child in list(prepared["child_receipts"])
            if str(child.get("strategy_id") or "") == strategy_id
        }
        committed_pairs = {
            (
                str(receipt.get("pretrade_child_receipt_sha256") or ""),
                str(receipt.get("pretrade_batch_sha256") or ""),
            )
            for receipt in receipts
        }
        child_by_pair = {
            (
                str(child["receipt_sha256"]),
                str(prepared["pretrade_batch_sha256"]),
            ): dict(child)
            for prepared in pretrade_records
            for child in list(prepared["child_receipts"])
            if str(child.get("strategy_id") or "") == strategy_id
        }
        receipt_by_pair = {
            (
                str(receipt.get("pretrade_child_receipt_sha256") or ""),
                str(receipt.get("pretrade_batch_sha256") or ""),
            ): receipt
            for receipt in receipts
        }
        pretrade_execution_complete = (
            bool(pretrade_records)
            and not pretrade_errors
            and prepared_pairs == committed_pairs
            and all(
                list(child_by_pair[pair]["planned_fills"])
                == list(receipt_by_pair[pair].get("fills") or [])
                and str(receipt_by_pair[pair].get("allocation_plan_sha256") or "")
                == str(
                    next(
                        prepared["parent_order_allocation_plan"][
                            "allocation_plan_sha256"
                        ]
                        for prepared in pretrade_records
                        if prepared["pretrade_batch_sha256"] == pair[1]
                    )
                )
                for pair in prepared_pairs
            )
        )
        promotion = evaluate_promotion(
            strategy_id,
            {
                "research": {
                    "strategy_artifact_frozen": True,
                    "clean_code_commit": True,
                    "data_catalog_verified": bool(signal_pointers) and not signal_errors,
                    "temporal_bias_passed": True,
                    "experiment_ledger_verified": bool(
                        spec.get("research_evidence_verified")
                    ),
                    "parameter_lockbox_verified": bool(
                        spec.get("research_evidence_verified")
                    ),
                    "purged_walk_forward_passed": bool(
                        spec.get("research_evidence_verified")
                    ),
                    "statistical_gate_passed": bool(
                        spec.get("research_evidence_verified")
                    ),
                    "robustness_gate_passed": bool(
                        spec.get("research_evidence_verified")
                    ),
                    "adversarial_audit_passed": bool(
                        spec.get("research_evidence_verified")
                    ),
                    "point_in_time_ready": False,
                    "execution_conformant": spec["execution_conformance"].get(
                        "canonical_eligible"
                    )
                    is True,
                    "portfolio_risk_compliant": True,
                    "forward_only": spec.get("historical_research_gate")
                    == "STRICT_FORWARD_ONLY_SUBSTITUTION",
                },
                "paper": {
                    "formally_registered": True,
                    "paper_only": True,
                    "real_orders": False,
                    "approval_precedes_start": True,
                    "approved_forward_data": bool(signal_pointers),
                    "recovery_drill_passed": True,
                    "platform_portfolio_policy_bound": platform_policy_bound,
                    "portfolio_stress_policy_bound": stress_policy_bound,
                    "parent_order_allocation_bound": parent_order_allocation_bound,
                    "pretrade_execution_bound": pretrade_execution_bound,
                    "active": safety.get("status") != "OPEN" and inspection["status"] == "READY",
                    "observed_trading_days": len(set(session_dates)),
                    "minimum_trading_days": int(spec["minimum_trading_days"]),
                    "observation_count": len(signal_pointers),
                    "minimum_observation_count": int(spec["minimum_observation_count"]),
                    "loss_budget_intact": loss_budget_intact,
                    "zero_reconciliation_failures": zero_reconciliation_failures,
                    "zero_data_integrity_failures": (
                        not receipt_errors
                        and not observation_errors
                        and not signal_errors
                        and halt_event_count == 0
                        and safety.get("status") != "OPEN"
                    ),
                    "zero_portfolio_risk_breaches": zero_risk_breaches,
                    "zero_platform_portfolio_breaches": zero_platform_breaches,
                    "zero_portfolio_stress_breaches": zero_stress_breaches,
                    "parent_order_allocation_complete": parent_order_allocation_complete,
                    "pretrade_execution_complete": pretrade_execution_complete,
                    "no_rule_drift": True,
                    "adversarial_audit_passed": False,
                    "performance": performance_evidence,
                },
                "broker": {},
            },
        )
        return {
            "strategy_id": strategy_id,
            "spec_sha256": spec["spec_sha256"],
            "approval_status": spec["approval_status"],
            "first_allowed_signal_date": spec["first_allowed_signal_date"],
            "ledger": inspection,
            "safety": safety,
            "signal_count": len(signal_pointers),
            "observation_count": len(signal_pointers),
            "observed_trading_days": len(set(session_dates)),
            "minimum_trading_days": int(spec["minimum_trading_days"]),
            "minimum_observation_count": int(spec["minimum_observation_count"]),
            "current_equity": round(current_equity, 6),
            "loss_pct": round(loss_pct, 6),
            "loss_budget_intact": loss_budget_intact,
            "forward_performance": performance,
            "execution_conformance": {
                "report_sha256": spec["execution_conformance"][
                    "report_sha256"
                ],
                "canonical_eligible": spec["execution_conformance"][
                    "canonical_eligible"
                ],
                "promotion_eligible": spec["execution_conformance"][
                    "promotion_eligible"
                ],
                "summaries": spec["execution_conformance"]["summaries"],
                "fresh_replay_verified": True,
            },
            "receipt_errors": receipt_errors,
            "observation_errors": observation_errors,
            "signal_errors": signal_errors,
            "halt_event_count": halt_event_count,
            "platform_portfolio_evidence": {
                "policy_bound": platform_policy_bound,
                "stress_policy_bound": stress_policy_bound,
                "preflight_count": len(platform_preflights),
                "zero_breaches": zero_platform_breaches,
                "zero_stress_breaches": zero_stress_breaches,
                "allocation_bound": parent_order_allocation_bound,
                "allocation_complete": parent_order_allocation_complete,
                "allocation_plan_count": len(allocation_records),
                "pretrade_execution_bound": pretrade_execution_bound,
                "pretrade_execution_complete": pretrade_execution_complete,
                "pretrade_batch_count": len(pretrade_records),
                "errors": (
                    platform_preflight_errors
                    + allocation_errors
                    + pretrade_errors
                ),
            },
            "promotion": promotion,
            "real_orders": False,
        }

    def status(self) -> dict[str, Any]:
        registry = self._registry()
        strategies: list[dict[str, Any]] = []
        invalid: list[dict[str, str]] = []
        for item in list(registry.get("experiments") or []):
            strategy_id = str(item.get("strategy_id") or "")
            try:
                strategies.append(self.strategy_status(strategy_id))
            except ForwardPaperError as exc:
                invalid.append({"strategy_id": strategy_id, "error": str(exc)})
        try:
            platform_portfolio = self.platform_portfolio_status()
        except (ForwardPaperError, ValueError, KeyError) as exc:
            platform_portfolio = {
                "configured": False,
                "status": "DEGRADED",
                "error": f"{type(exc).__name__}: {exc}",
                "real_orders": False,
            }
        return {
            "schema": FORWARD_STATUS_SCHEMA,
            "registry_id": registry.get("registry_id"),
            "registry_sha256": sha256_digest(registry),
            "mode": "PAPER",
            "real_orders": False,
            "canonical_execution_adapter": "quant_core",
            "registered_count": len(list(registry.get("experiments") or [])),
            "valid_count": len(strategies),
            "invalid_count": len(invalid),
            "strategies": strategies,
            "invalid_registrations": invalid,
            "platform_portfolio": platform_portfolio,
        }


def default_forward_runner(platform_root: str | Path) -> ForwardPaperRunner:
    root = Path(platform_root).expanduser().resolve()
    runtime = Path(
        os.environ.get("VR_FORWARD_PAPER_ROOT", str(root / "data" / "quant-lab" / "forward-paper"))
    )
    catalog = Path(
        os.environ.get("VR_FORWARD_DATA_CATALOG", str(root / "data" / "quant-lab" / "forward-datahub"))
    )
    return ForwardPaperRunner(platform_root=root, runtime_root=runtime, catalog_root=catalog)
