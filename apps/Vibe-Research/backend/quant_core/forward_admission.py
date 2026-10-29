"""Content-addressed operator admission for formal PAPER-forward candidates.

The freeze-pack builder deliberately stops at a draft.  This module turns an
explicit operator decision into an immutable receipt and binds the active
registry entry back to the exact draft.  It never enables real orders.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from copy import deepcopy
from datetime import date, datetime
from pathlib import Path
from typing import Any, Mapping
from zoneinfo import ZoneInfo

from .provenance import sha256_digest
from .provider_readiness import (
    assess_formal_data_readiness,
    resolve_formal_data_readiness_policy,
)


FORWARD_ADMISSION_SCHEMA = "quant-platform/formal-forward-admission/v3"
P1_STRATEGY_ID = "diversified_etf_trend_p1"
P2_STRATEGY_ID = "diversified_etf_trend_p2"
I7_STRATEGY_ID = "independent_multifactor_i7_forward_only"
GENERIC_FREEZE_MANIFEST_STATUS = "DRAFT_REQUIRES_OPERATOR_APPROVAL"
I7_FREEZE_MANIFEST_STATUS = (
    "DRAFT_REQUIRES_FORMAL_STOCK_DATA_AND_OPERATOR_APPROVAL"
)
SUPPORTED_FORMAL_ADMISSION_STRATEGIES = frozenset(
    {P1_STRATEGY_ID, P2_STRATEGY_ID, I7_STRATEGY_ID}
)
LEGACY_P1_FREEZE_PACK_SCHEMA = "quant-platform/p1-freeze-pack/v1"
FORWARD_FREEZE_PACK_SCHEMA = "quant-platform/forward-freeze-pack/v2"
ADMISSION_FIELDS = {"admission_record_path", "admission_record_sha256"}
SHANGHAI = ZoneInfo("Asia/Shanghai")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ForwardAdmissionError(RuntimeError):
    """Raised when a formal-forward admission cannot be trusted."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ForwardAdmissionError(f"admission evidence is unreadable: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ForwardAdmissionError(f"admission evidence must be an object: {path}")
    return payload


def _file_sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _inside(root: Path, relative: str, label: str) -> Path:
    value = str(relative or "").strip().replace("\\", "/")
    if not value or Path(value).is_absolute():
        raise ForwardAdmissionError(f"{label} must be a relative platform path")
    path = (root / value).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ForwardAdmissionError(f"{label} escapes the platform root") from exc
    return path


def _atomic_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _immutable_json(path: Path, payload: Mapping[str, Any]) -> None:
    if path.is_file():
        if _read_json(path) != dict(payload):
            raise ForwardAdmissionError(f"immutable admission conflict: {path}")
        return
    _atomic_json(path, payload)


def _semantic_record(payload: Mapping[str, Any], digest_field: str) -> dict[str, Any]:
    record = dict(payload)
    digest = str(record.pop(digest_field, "")).lower()
    if len(digest) != 64 or sha256_digest(record) != digest:
        raise ForwardAdmissionError(f"{digest_field} mismatch")
    return {**record, digest_field: digest}


def _base_experiment(spec: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: deepcopy(value)
        for key, value in spec.items()
        if key not in ADMISSION_FIELDS and key != "registry_sha256"
    }


def _strategy_readiness(
    readiness: Mapping[str, Any], strategy_id: str
) -> dict[str, Any]:
    row = dict(
        dict(readiness.get("strategy_readiness") or {}).get(strategy_id) or {}
    )
    if strategy_id == P1_STRATEGY_ID:
        if readiness.get("formal_forward_ready") is not True:
            raise ForwardAdmissionError("legacy P1 provider data foundation is not ready")
        return row
    if (
        row.get("ready") is not True
        or row.get("real_orders") is not False
        or row.get("strategy_promotion_eligible") is not False
    ):
        blockers = ", ".join(str(item) for item in row.get("blockers") or [])
        raise ForwardAdmissionError(
            f"formal provider data foundation is not ready for {strategy_id}"
            + (f": {blockers}" if blockers else "")
        )
    return row


def _approved_datasets_from_readiness(
    readiness: Mapping[str, Any], strategy_id: str
) -> list[dict[str, Any]]:
    """Derive runner allow-list rows from the exact bound publication evidence."""

    strategy = _strategy_readiness(readiness, strategy_id)
    if strategy_id == P1_STRATEGY_ID:
        return []
    track_id = str(strategy.get("track") or "")
    products = dict(dict(readiness.get("tracks") or {}).get(track_id, {}).get("products") or {})
    merged: dict[str, dict[str, Any]] = {}
    for product_id in list(strategy.get("required_products") or []):
        product = dict(products.get(str(product_id)) or {})
        evidence_rows = [
            dict(item)
            for item in list(product.get("approved_publication_evidence") or [])
        ]
        minimum = int(product.get("minimum_independent_authorities") or 0)
        authorities = {
            str(item.get("authority") or "") for item in evidence_rows
            if str(item.get("authority") or "")
        }
        if product.get("ready") is not True or minimum < 2 or len(authorities) < minimum:
            raise ForwardAdmissionError(
                f"approved publication evidence is incomplete: {product_id}"
            )
        usages = sorted(str(item) for item in product.get("runner_usages") or [])
        semantics = str(product.get("semantics_version") or "")
        if not usages or not semantics:
            raise ForwardAdmissionError(
                f"runner data semantics are incomplete: {product_id}"
            )
        for evidence in evidence_rows:
            dataset_id = str(evidence.get("dataset_id") or "")
            source_id = str(evidence.get("source_id") or "")
            authority = str(evidence.get("authority") or "")
            if (
                not dataset_id
                or not source_id
                or not authority
                or not SHA256_RE.fullmatch(
                    str(evidence.get("manifest_sha256") or "").lower()
                )
                or not SHA256_RE.fullmatch(
                    str(evidence.get("receipt_sha256") or "").lower()
                )
                or not SHA256_RE.fullmatch(
                    str(evidence.get("delivery_sha256") or "").lower()
                )
                or not SHA256_RE.fullmatch(
                    str(evidence.get("revision_lineage_sha256") or "").lower()
                )
            ):
                raise ForwardAdmissionError(
                    f"approved publication identity is incomplete: {product_id}"
                )
            existing = merged.get(dataset_id)
            if existing is None:
                merged[dataset_id] = {
                    "dataset_id": dataset_id,
                    "product_id": str(product_id),
                    "authority": authority,
                    "providers": [source_id],
                    "usages": usages,
                    "semantics_version": semantics,
                }
                continue
            if (
                existing["semantics_version"] != semantics
                or existing["product_id"] != str(product_id)
                or existing["authority"] != authority
                or existing["providers"] != [source_id]
            ):
                raise ForwardAdmissionError(
                    f"one dataset crosses product, authority or source contracts: {dataset_id}"
                )
            existing["usages"] = sorted(set(existing["usages"]) | set(usages))
    result = [merged[key] for key in sorted(merged)]
    if not result:
        raise ForwardAdmissionError("formal admission derived no approved datasets")
    return result


def _load_freeze_chain(
    root: Path,
    *,
    manifest_path: Path,
    expected_pack_sha256: str | None = None,
    expected_draft_path: str | None = None,
    expected_draft_sha256: str | None = None,
    expected_strategy_id: str | None = None,
) -> tuple[dict[str, Any], Path, dict[str, Any]]:
    manifest = _semantic_record(_read_json(manifest_path), "pack_sha256")
    strategy_id = str(manifest.get("strategy_id") or "")
    schema = str(manifest.get("schema") or "")
    expected_manifest_status = (
        I7_FREEZE_MANIFEST_STATUS
        if strategy_id == I7_STRATEGY_ID
        else GENERIC_FREEZE_MANIFEST_STATUS
    )
    repository_boundary_valid = (
        manifest.get("repository_clean") is True
        if schema == LEGACY_P1_FREEZE_PACK_SCHEMA
        else (
            manifest.get("frozen_scope_clean") is True
            and manifest.get("repository_clean") is False
            and manifest.get("untracked_research_candidates_affect_pack_identity")
            is False
        )
    )
    if (
        schema not in {LEGACY_P1_FREEZE_PACK_SCHEMA, FORWARD_FREEZE_PACK_SCHEMA}
        or (schema == LEGACY_P1_FREEZE_PACK_SCHEMA and strategy_id != P1_STRATEGY_ID)
        or strategy_id not in SUPPORTED_FORMAL_ADMISSION_STRATEGIES
        or manifest.get("status") != expected_manifest_status
        or not repository_boundary_valid
        or manifest.get("formal_registry_modified") is not False
        or manifest.get("real_orders") is not False
    ):
        raise ForwardAdmissionError("freeze-pack manifest is not an approvable PAPER draft")
    if expected_strategy_id and strategy_id != expected_strategy_id:
        raise ForwardAdmissionError("freeze-pack strategy identity mismatch")
    if expected_pack_sha256 and manifest["pack_sha256"] != expected_pack_sha256:
        raise ForwardAdmissionError("freeze-pack decision binding mismatch")

    draft_rows = [
        dict(item)
        for item in list(manifest.get("artifacts") or [])
        if str(item.get("path") or "").endswith("/registration-draft.json")
    ]
    if len(draft_rows) != 1:
        raise ForwardAdmissionError("freeze pack must bind exactly one registration draft")
    draft_relative = str(draft_rows[0].get("path") or "")
    if expected_draft_path and draft_relative != expected_draft_path:
        raise ForwardAdmissionError("registration-draft path mismatch")
    draft_path = _inside(root, draft_relative, "registration_draft_path")
    if not draft_path.is_file() or _file_sha256(draft_path) != str(
        draft_rows[0].get("sha256") or ""
    ).lower():
        raise ForwardAdmissionError("registration draft file hash mismatch")
    draft = _semantic_record(_read_json(draft_path), "draft_sha256")
    if expected_draft_sha256 and draft["draft_sha256"] != expected_draft_sha256:
        raise ForwardAdmissionError("registration-draft decision binding mismatch")
    if (
        draft.get("schema") != "quant-platform/formal-forward-registration-draft/v1"
        or draft.get("status") != "REQUIRES_OPERATOR_APPROVAL"
        or draft.get("not_a_registry_entry") is not True
        or set(draft.get("missing_operator_fields") or [])
        != {"approval_status", "approved_at", "first_allowed_signal_date"}
        or draft.get("real_orders") is not False
    ):
        raise ForwardAdmissionError("registration draft is not an approvable operator draft")
    proposed = dict(draft.get("proposed_experiment") or {})
    if (
        proposed.get("strategy_id") != strategy_id
        or proposed.get("real_orders") is not False
        or proposed.get("approval_status") is not None
        or proposed.get("approved_at") is not None
        or proposed.get("first_allowed_signal_date") is not None
    ):
        raise ForwardAdmissionError(
            "registration draft strategy or inactive boundary is invalid"
        )
    return manifest, draft_path, draft


def verify_forward_admission(
    platform_root: str | Path,
    spec: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute an allow-listed PAPER admission chain from immutable evidence."""

    root = Path(platform_root).expanduser().resolve()
    strategy_id = str(spec.get("strategy_id") or "")
    if strategy_id not in SUPPORTED_FORMAL_ADMISSION_STRATEGIES:
        raise ForwardAdmissionError("strategy is not allow-listed for formal admission")
    record_sha = str(spec.get("admission_record_sha256") or "").lower()
    record_path = _inside(
        root, str(spec.get("admission_record_path") or ""), "admission_record_path"
    )
    required_parent = (root / "data/quant-lab/forward-admissions/records").resolve()
    try:
        record_path.relative_to(required_parent)
    except ValueError as exc:
        raise ForwardAdmissionError("admission record is outside the immutable record store") from exc
    if record_path.name != f"{record_sha}.json" or not record_path.is_file():
        raise ForwardAdmissionError("admission record path does not match its digest")
    record = _semantic_record(_read_json(record_path), "admission_sha256")
    if record["admission_sha256"] != record_sha:
        raise ForwardAdmissionError("registry admission digest mismatch")

    expected_fields = {
        "schema",
        "decision",
        "strategy_id",
        "freeze_pack_manifest_path",
        "freeze_pack_sha256",
        "registration_draft_path",
        "registration_draft_sha256",
        "approval_status",
        "approved_at",
        "first_allowed_signal_date",
        "authorization_reference",
        "data_readiness_record_path",
        "data_readiness_assessment_sha256",
        "data_readiness_policy_sha256",
        "approved_datasets_sha256",
        "approved_experiment_sha256",
        "real_orders",
        "admission_sha256",
    }
    if set(record) != expected_fields:
        raise ForwardAdmissionError("admission record fields do not match the contract")
    if (
        record.get("schema") != FORWARD_ADMISSION_SCHEMA
        or record.get("decision") != "APPROVE_PAPER_FORWARD"
        or record.get("strategy_id") != strategy_id
        or record.get("approval_status") != "ACTIVE"
        or record.get("real_orders") is not False
        or not str(record.get("authorization_reference") or "").strip()
    ):
        raise ForwardAdmissionError("admission decision identity is invalid")

    readiness_sha = str(record.get("data_readiness_assessment_sha256") or "").lower()
    readiness_path = _inside(
        root,
        str(record.get("data_readiness_record_path") or ""),
        "data_readiness_record_path",
    )
    readiness_parent = (
        root / "data/quant-lab/forward-admissions/data-readiness"
    ).resolve()
    try:
        readiness_path.relative_to(readiness_parent)
    except ValueError as exc:
        raise ForwardAdmissionError(
            "data readiness record is outside the immutable record store"
        ) from exc
    if readiness_path.name != f"{readiness_sha}.json" or not readiness_path.is_file():
        raise ForwardAdmissionError("data readiness record path does not match its digest")
    readiness = _semantic_record(_read_json(readiness_path), "assessment_sha256")
    if (
        readiness["assessment_sha256"] != readiness_sha
        or readiness.get("schema") != "quant-platform/formal-data-readiness/v2"
        or readiness.get("strategy_promotion_eligible") is not False
        or readiness.get("real_orders") is not False
        or readiness.get("policy_sha256")
        != record.get("data_readiness_policy_sha256")
    ):
        raise ForwardAdmissionError("bound data readiness assessment is not approvable")
    current_readiness_policy = resolve_formal_data_readiness_policy(root)
    if (
        current_readiness_policy.get("policy_sha256")
        != record.get("data_readiness_policy_sha256")
    ):
        raise ForwardAdmissionError("data readiness policy drifted after approval")
    strategy_readiness = _strategy_readiness(readiness, strategy_id)

    manifest_path = _inside(
        root,
        str(record.get("freeze_pack_manifest_path") or ""),
        "freeze_pack_manifest_path",
    )
    manifest, _, draft = _load_freeze_chain(
        root,
        manifest_path=manifest_path,
        expected_pack_sha256=str(record.get("freeze_pack_sha256") or ""),
        expected_draft_path=str(record.get("registration_draft_path") or ""),
        expected_draft_sha256=str(record.get("registration_draft_sha256") or ""),
        expected_strategy_id=strategy_id,
    )
    base = _base_experiment(spec)
    if strategy_id != P1_STRATEGY_ID:
        approved_datasets = _approved_datasets_from_readiness(readiness, strategy_id)
        if (
            base.get("approved_datasets") != approved_datasets
            or sha256_digest(approved_datasets)
            != str(record.get("approved_datasets_sha256") or "")
            or base.get("formal_data_ready") is not True
            or strategy_readiness.get("ready") is not True
        ):
            raise ForwardAdmissionError(
                "approved datasets drifted from bound provider publications"
            )
    elif sha256_digest(list(base.get("approved_datasets") or [])) != str(
        record.get("approved_datasets_sha256") or ""
    ):
        raise ForwardAdmissionError("legacy approved dataset digest mismatch")
    if sha256_digest(base) != str(record.get("approved_experiment_sha256") or ""):
        raise ForwardAdmissionError("approved experiment digest mismatch")
    if (
        base.get("approval_status") != record.get("approval_status")
        or base.get("approved_at") != record.get("approved_at")
        or base.get("first_allowed_signal_date") != record.get("first_allowed_signal_date")
        or base.get("real_orders") is not False
        or base.get("code_commit") != manifest.get("code_commit")
    ):
        raise ForwardAdmissionError("active registry fields drifted from the admission decision")
    proposed = deepcopy(base)
    proposed.update(
        approval_status=None,
        approved_at=None,
        first_allowed_signal_date=None,
    )
    if strategy_id != P1_STRATEGY_ID:
        proposed.update(approved_datasets=[], formal_data_ready=False)
    if proposed != dict(draft.get("proposed_experiment") or {}):
        raise ForwardAdmissionError("active registry entry does not reproduce from the frozen draft")
    return record


def approve_forward_candidate(
    platform_root: str | Path,
    manifest_path: str | Path,
    *,
    approved_at: str,
    first_allowed_signal_date: str,
    authorization_reference: str,
    registration_note: str,
    expected_strategy_id: str | None = None,
) -> dict[str, Any]:
    """Approve one exact allow-listed freeze draft for PAPER only."""

    root = Path(platform_root).expanduser().resolve()
    manifest_file = Path(manifest_path).expanduser().resolve()
    try:
        manifest_relative = manifest_file.relative_to(root).as_posix()
    except ValueError as exc:
        raise ForwardAdmissionError("freeze-pack manifest must stay inside platform root") from exc
    reference = str(authorization_reference or "").strip()
    note = str(registration_note or "").strip()
    if not reference or len(reference) > 256:
        raise ForwardAdmissionError("authorization_reference is required and limited to 256 characters")
    if not note:
        raise ForwardAdmissionError("registration_note is required")
    try:
        approved_dt = datetime.fromisoformat(str(approved_at).replace("Z", "+00:00"))
        first_day = date.fromisoformat(str(first_allowed_signal_date))
    except ValueError as exc:
        raise ForwardAdmissionError("approval timestamp or first signal date is invalid") from exc
    if approved_dt.tzinfo is None:
        raise ForwardAdmissionError("approved_at must include a timezone")
    approved_value = approved_dt.isoformat()
    if first_day <= approved_dt.astimezone(SHANGHAI).date():
        raise ForwardAdmissionError(
            "first_allowed_signal_date must be strictly after approval"
        )

    manifest, draft_path, draft = _load_freeze_chain(
        root,
        manifest_path=manifest_file,
        expected_strategy_id=expected_strategy_id,
    )
    strategy_id = str(manifest["strategy_id"])
    readiness = assess_formal_data_readiness(root)
    _strategy_readiness(readiness, strategy_id)
    readiness_sha = str(readiness.get("assessment_sha256") or "").lower()
    if len(readiness_sha) != 64:
        raise ForwardAdmissionError("formal data readiness assessment is not content-addressed")
    readiness_relative = (
        f"data/quant-lab/forward-admissions/data-readiness/{readiness_sha}.json"
    )
    _immutable_json(root / readiness_relative, readiness)
    experiment = deepcopy(dict(draft.get("proposed_experiment") or {}))
    approved_datasets = list(experiment.get("approved_datasets") or [])
    if strategy_id != P1_STRATEGY_ID:
        if approved_datasets or experiment.get("formal_data_ready") is not False:
            raise ForwardAdmissionError(
                "freeze draft contains unfrozen runtime data approval"
            )
        approved_datasets = _approved_datasets_from_readiness(
            readiness, strategy_id
        )
        experiment.update(
            approved_datasets=approved_datasets,
            formal_data_ready=True,
        )
    experiment.update(
        approval_status="ACTIVE",
        approved_at=approved_value,
        first_allowed_signal_date=first_day.isoformat(),
    )
    if experiment.get("real_orders") is not False:
        raise ForwardAdmissionError("formal admission can never enable real orders")

    decision_identity = {
        "schema": FORWARD_ADMISSION_SCHEMA,
        "decision": "APPROVE_PAPER_FORWARD",
        "strategy_id": strategy_id,
        "freeze_pack_manifest_path": manifest_relative,
        "freeze_pack_sha256": manifest["pack_sha256"],
        "registration_draft_path": draft_path.relative_to(root).as_posix(),
        "registration_draft_sha256": draft["draft_sha256"],
        "approval_status": "ACTIVE",
        "approved_at": approved_value,
        "first_allowed_signal_date": first_day.isoformat(),
        "authorization_reference": reference,
        "data_readiness_record_path": readiness_relative,
        "data_readiness_assessment_sha256": readiness_sha,
        "data_readiness_policy_sha256": readiness["policy_sha256"],
        "approved_datasets_sha256": sha256_digest(approved_datasets),
        "approved_experiment_sha256": sha256_digest(experiment),
        "real_orders": False,
    }
    decision = {
        **decision_identity,
        "admission_sha256": sha256_digest(decision_identity),
    }
    record_relative = (
        f"data/quant-lab/forward-admissions/records/{decision['admission_sha256']}.json"
    )
    record_path = root / record_relative
    _immutable_json(record_path, decision)
    experiment.update(
        admission_record_path=record_relative,
        admission_record_sha256=decision["admission_sha256"],
    )

    registry_path = root / "config/strategy-lab/canonical-forward-runner-registry.json"
    if registry_path.is_file():
        registry = _read_json(registry_path)
    else:
        registry = {
            "schema_version": 1,
            "registry_id": "canonical-forward-runner-registry-v1",
            "runner": "quant_core.forward_paper/v1",
            "mode": "PAPER",
            "real_orders": False,
            "registration_status": "WAITING_FOR_CLEAN_FROZEN_EVIDENCE",
            "registration_note": "No candidate has completed formal admission.",
            "experiments": [],
        }
    expected_registry_fields = {
        "schema_version",
        "registry_id",
        "runner",
        "mode",
        "real_orders",
        "registration_status",
        "registration_note",
        "experiments",
    }
    if (
        set(registry) != expected_registry_fields
        or registry.get("schema_version") != 1
        or registry.get("registry_id") != "canonical-forward-runner-registry-v1"
        or registry.get("runner") != "quant_core.forward_paper/v1"
        or registry.get("mode") != "PAPER"
        or registry.get("real_orders") is not False
    ):
        raise ForwardAdmissionError("canonical forward registry is invalid")
    experiments = [dict(item) for item in list(registry.get("experiments") or [])]
    matching = [item for item in experiments if item.get("strategy_id") == strategy_id]
    if matching:
        if len(matching) == 1 and matching[0] == experiment:
            return {
                "status": "ALREADY_REGISTERED",
                "strategy_id": strategy_id,
                "admission_record_path": record_relative,
                "admission_record_sha256": decision["admission_sha256"],
                "registry_path": str(registry_path),
                "real_orders": False,
            }
        raise ForwardAdmissionError(
            f"{strategy_id} already has a different formal registration"
        )

    candidate_registry = {
        **registry,
        "registration_status": "HAS_ACTIVE_EXPERIMENTS",
        "registration_note": note,
        "experiments": [*experiments, experiment],
    }
    # Validate the exact candidate before making the central registry visible.
    from .forward_paper import ForwardPaperRunner

    validator = ForwardPaperRunner(
        platform_root=root,
        runtime_root=root / "data/quant-lab/forward-paper",
        catalog_root=root / "data/quant-lab/catalog",
        registry_path=registry_path,
    )
    validator._validate_spec(
        {**experiment, "registry_sha256": sha256_digest(candidate_registry)}
    )
    _atomic_json(registry_path, candidate_registry)
    return {
        "status": "REGISTERED_PAPER_ONLY",
        "strategy_id": strategy_id,
        "admission_record_path": record_relative,
        "admission_record_sha256": decision["admission_sha256"],
        "registry_path": str(registry_path),
        "real_orders": False,
    }


def approve_p1_forward_candidate(
    platform_root: str | Path,
    manifest_path: str | Path,
    *,
    approved_at: str,
    first_allowed_signal_date: str,
    authorization_reference: str,
    registration_note: str,
) -> dict[str, Any]:
    """Backward-compatible P1-only wrapper around generic PAPER admission."""

    return approve_forward_candidate(
        platform_root,
        manifest_path,
        approved_at=approved_at,
        first_allowed_signal_date=first_allowed_signal_date,
        authorization_reference=authorization_reference,
        registration_note=registration_note,
        expected_strategy_id=P1_STRATEGY_ID,
    )
