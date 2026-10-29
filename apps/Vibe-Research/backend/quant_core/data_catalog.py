"""Append-only, content-addressed catalog for research dataset snapshots."""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

from .provenance import canonical_json, sha256_digest


DATA_CATALOG_SCHEMA = "quant-core/data-catalog-entry/v1"
DATA_CATALOG_POINTER_SCHEMA = "quant-core/data-catalog-latest/v1"
DATA_CATALOG_HISTORY_SCHEMA = "quant-core/data-catalog-history/v1"
DATA_CATALOG_AS_OF_SCHEMA = "quant-core/data-catalog-as-of-selection/v1"
_DATASET_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MANIFEST_FIELDS = {
    "schema",
    "dataset_id",
    "revision",
    "payload_sha256",
    "declared_dataset_sha256",
    "previous_manifest_sha256",
    "provider",
    "available_at",
    "metadata",
    "manifest_sha256",
}


class DataCatalogError(RuntimeError):
    """Raised when an append-only catalog cannot be safely read or written."""


def _locked_publish(method):
    @wraps(method)
    def wrapped(self, dataset_id: str, *args, **kwargs):
        normalized = self._validate_dataset_id(dataset_id)
        with self._write_lock(normalized):
            return method(self, normalized, *args, **kwargs)

    return wrapped


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False),
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
            raise DataCatalogError(f"immutable catalog collision: {path}")
        return
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temporary.write_text(encoded, encoding="utf-8")
    try:
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


class DataCatalog:
    """Persist immutable JSON payloads and an auditable provider-revision chain."""

    def __init__(self, root: Path | str):
        self.root = Path(root).expanduser().resolve()

    @staticmethod
    def _load_json(path: Path) -> Any:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {constant}")
            ),
        )

    @staticmethod
    def _validate_dataset_id(dataset_id: str) -> str:
        normalized = str(dataset_id).strip().lower()
        if not _DATASET_ID_RE.fullmatch(normalized):
            raise DataCatalogError("dataset_id must use lowercase letters, digits, dot, dash or underscore")
        return normalized

    def _dataset_root(self, dataset_id: str) -> Path:
        return self.root / "datasets" / self._validate_dataset_id(dataset_id)

    @staticmethod
    def _timestamp(value: str | datetime, label: str) -> datetime:
        try:
            moment = value if isinstance(value, datetime) else datetime.fromisoformat(
                str(value).strip().replace("Z", "+00:00")
            )
        except (TypeError, ValueError) as exc:
            raise DataCatalogError(f"{label} must be an ISO-8601 timestamp") from exc
        if moment.tzinfo is None or moment.utcoffset() is None:
            raise DataCatalogError(f"{label} must include a timezone")
        return moment.astimezone(timezone.utc)

    @classmethod
    def _validated_timestamp(cls, value: str | datetime, label: str) -> str:
        cls._timestamp(value, label)
        return value.isoformat() if isinstance(value, datetime) else str(value).strip()

    @contextmanager
    def _write_lock(self, dataset_id: str, timeout_seconds: float = 10.0):
        """Serialize revision allocation for one dataset across collector processes."""
        lock_path = self.root / "_locks" / f"{dataset_id}.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+b")
        acquired = False
        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
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
                    if time.monotonic() >= deadline:
                        raise DataCatalogError(
                            f"another publisher is active for dataset {dataset_id}"
                        ) from exc
                    time.sleep(0.05)
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

    def _read_latest_pointer(self, dataset_id: str) -> dict | None:
        path = self._dataset_root(dataset_id) / "latest.json"
        if not path.exists():
            return None
        try:
            pointer = self._load_json(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise DataCatalogError(f"invalid latest pointer for {dataset_id}: {exc}") from exc
        if pointer.get("schema") != DATA_CATALOG_POINTER_SCHEMA:
            raise DataCatalogError(f"unsupported latest pointer schema for {dataset_id}")
        if pointer.get("dataset_id") != dataset_id:
            raise DataCatalogError(f"latest pointer dataset id mismatch for {dataset_id}")
        revision = pointer.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise DataCatalogError(f"latest pointer revision is invalid for {dataset_id}")
        for key in ("payload_sha256", "manifest_sha256"):
            if not _SHA256_RE.fullmatch(str(pointer.get(key) or "")):
                raise DataCatalogError(f"latest pointer {key} is invalid for {dataset_id}")
        return pointer

    def _verify_manifest_record(
        self, dataset_id: str, manifest_sha256: str
    ) -> tuple[dict[str, Any] | None, list[str]]:
        errors: list[str] = []
        if not _SHA256_RE.fullmatch(str(manifest_sha256)):
            return None, ["manifest_sha256 must be 64 lowercase hexadecimal characters"]
        manifest_path = (
            self._dataset_root(dataset_id) / "manifests" / f"{manifest_sha256}.json"
        )
        try:
            manifest = self._load_json(manifest_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            return None, [f"manifest unreadable: {exc}"]
        if not isinstance(manifest, dict):
            return None, ["manifest must be a JSON object"]
        fields = set(manifest)
        if fields != _MANIFEST_FIELDS:
            missing = sorted(_MANIFEST_FIELDS - fields)
            unexpected = sorted(fields - _MANIFEST_FIELDS)
            if missing:
                errors.append(f"manifest fields missing: {missing}")
            if unexpected:
                errors.append(f"manifest fields unexpected: {unexpected}")
        identity = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
        if manifest.get("schema") != DATA_CATALOG_SCHEMA:
            errors.append("unsupported manifest schema")
        if manifest.get("dataset_id") != dataset_id:
            errors.append("dataset id mismatch")
        revision = manifest.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            errors.append("revision must be a positive integer")
        if sha256_digest(identity) != manifest_sha256 or manifest.get("manifest_sha256") != manifest_sha256:
            errors.append("manifest hash mismatch")
        payload_sha256 = str(manifest.get("payload_sha256") or "")
        if not _SHA256_RE.fullmatch(payload_sha256):
            errors.append("payload_sha256 is invalid")
        previous = manifest.get("previous_manifest_sha256")
        if previous is not None and not _SHA256_RE.fullmatch(str(previous)):
            errors.append("previous_manifest_sha256 is invalid")
        if not isinstance(manifest.get("provider"), dict):
            errors.append("provider must be an object")
        if not isinstance(manifest.get("metadata"), dict):
            errors.append("metadata must be an object")
        try:
            self._timestamp(str(manifest.get("available_at") or ""), "available_at")
        except DataCatalogError as exc:
            errors.append(str(exc))
        if _SHA256_RE.fullmatch(payload_sha256):
            try:
                payload_path = (
                    self._dataset_root(dataset_id)
                    / "snapshots"
                    / f"{payload_sha256}.json"
                )
                payload = self._load_json(payload_path)
                if sha256_digest(payload) != payload_sha256:
                    errors.append("payload hash mismatch")
            except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
                errors.append(f"snapshot unreadable: {exc}")
        return manifest, errors

    @_locked_publish
    def publish(
        self,
        dataset_id: str,
        payload: Any,
        *,
        provider: Mapping[str, Any] | str,
        available_at: str | datetime,
        metadata: Mapping[str, Any] | None = None,
        declared_dataset_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Publish a snapshot idempotently; changed content creates a new revision."""
        dataset_id = self._validate_dataset_id(dataset_id)
        dataset_root = self._dataset_root(dataset_id)
        payload_sha256 = sha256_digest(payload)
        provider_record = dict(provider) if isinstance(provider, Mapping) else {"name": str(provider)}
        metadata_record = dict(metadata or {})
        declared_sha = str(declared_dataset_sha256 or "")
        available_at_text = self._validated_timestamp(available_at, "available_at")
        latest = self._read_latest_pointer(dataset_id)
        previous_manifest: dict[str, Any] | None = None
        if latest:
            verification = self.verify(dataset_id, str(latest["manifest_sha256"]))
            if not verification["verified"]:
                raise DataCatalogError(f"latest catalog entry failed verification: {verification['errors']}")
            previous_manifest = dict(verification["manifest"] or {})
            # Preserve the first known availability timestamp for a genuinely
            # identical publication, but never let equal payload bytes hide a
            # changed source, declaration or quality/provenance record.
            if (
                latest.get("payload_sha256") == payload_sha256
                and previous_manifest.get("provider") == provider_record
                and previous_manifest.get("metadata") == metadata_record
                and str(previous_manifest.get("declared_dataset_sha256") or "")
                == declared_sha
            ):
                return previous_manifest
            previous_available_at = self._timestamp(
                str(previous_manifest.get("available_at") or ""),
                "previous available_at",
            )
            if self._timestamp(available_at_text, "available_at") <= previous_available_at:
                raise DataCatalogError(
                    "available_at must be strictly later than the current catalog head"
                )

        previous_manifest_sha256 = str(latest["manifest_sha256"]) if latest else None
        revision = int(latest.get("revision", 0)) + 1 if latest else 1
        identity = {
            "schema": DATA_CATALOG_SCHEMA,
            "dataset_id": dataset_id,
            "revision": revision,
            "payload_sha256": payload_sha256,
            "declared_dataset_sha256": declared_sha,
            "previous_manifest_sha256": previous_manifest_sha256,
            "provider": provider_record,
            "available_at": available_at_text,
            "metadata": metadata_record,
        }
        manifest_sha256 = sha256_digest(identity)
        manifest = {**identity, "manifest_sha256": manifest_sha256}

        _immutable_json(dataset_root / "snapshots" / f"{payload_sha256}.json", payload)
        _immutable_json(dataset_root / "manifests" / f"{manifest_sha256}.json", manifest)
        history = self.history(dataset_id, manifest_sha256)
        if not history["verified"]:
            raise DataCatalogError(f"new catalog history failed verification: {history['errors']}")
        _atomic_json(
            dataset_root / "latest.json",
            {
                "schema": DATA_CATALOG_POINTER_SCHEMA,
                "dataset_id": dataset_id,
                "revision": revision,
                "payload_sha256": payload_sha256,
                "manifest_sha256": manifest_sha256,
            },
        )
        verification = self.verify(dataset_id)
        if not verification["verified"]:
            raise DataCatalogError(f"new catalog entry failed verification: {verification['errors']}")
        return manifest

    def history(
        self, dataset_id: str, head_manifest_sha256: str | None = None
    ) -> dict[str, Any]:
        """Audit every revision reachable from a selected immutable catalog head."""
        dataset_id = self._validate_dataset_id(dataset_id)
        errors: list[str] = []
        try:
            pointer = self._read_latest_pointer(dataset_id) if head_manifest_sha256 is None else None
            selected = head_manifest_sha256 or (str(pointer["manifest_sha256"]) if pointer else "")
            if not selected:
                raise DataCatalogError("dataset has no catalog entry")
        except (KeyError, DataCatalogError) as exc:
            return {
                "schema": DATA_CATALOG_HISTORY_SCHEMA,
                "verified": False,
                "dataset_id": dataset_id,
                "errors": [str(exc)],
                "head_manifest_sha256": None,
                "history_sha256": None,
                "manifests": [],
            }

        newest_to_oldest: list[dict[str, Any]] = []
        seen: set[str] = set()
        current: str | None = str(selected)
        expected_revision: int | None = None
        while current:
            if current in seen:
                errors.append(f"revision chain cycle detected at {current}")
                break
            seen.add(current)
            manifest, record_errors = self._verify_manifest_record(dataset_id, current)
            errors.extend(f"{current}: {message}" for message in record_errors)
            if manifest is None:
                break
            newest_to_oldest.append(manifest)
            revision = manifest.get("revision")
            if isinstance(revision, int) and not isinstance(revision, bool):
                if expected_revision is not None and revision != expected_revision:
                    errors.append(
                        f"revision continuity mismatch: expected {expected_revision}, found {revision}"
                    )
                expected_revision = revision - 1
            current = manifest.get("previous_manifest_sha256")

        manifests = list(reversed(newest_to_oldest))
        previous_available: datetime | None = None
        for index, manifest in enumerate(manifests, start=1):
            if manifest.get("revision") != index:
                errors.append(
                    f"revision sequence must start at 1 and be contiguous; found {manifest.get('revision')} at position {index}"
                )
            expected_previous = manifests[index - 2]["manifest_sha256"] if index > 1 else None
            if manifest.get("previous_manifest_sha256") != expected_previous:
                errors.append(f"revision {index} previous manifest link mismatch")
            try:
                available = self._timestamp(manifest.get("available_at"), "available_at")
                if previous_available is not None and available <= previous_available:
                    errors.append("available_at must be strictly increasing across revisions")
                previous_available = available
            except DataCatalogError as exc:
                errors.append(str(exc))

        head = manifests[-1] if manifests else None
        if pointer is not None and head is not None:
            if pointer.get("manifest_sha256") != head.get("manifest_sha256"):
                errors.append("latest pointer manifest does not match audited head")
            if pointer.get("revision") != head.get("revision"):
                errors.append("latest pointer revision does not match audited head")
            if pointer.get("payload_sha256") != head.get("payload_sha256"):
                errors.append("latest pointer payload does not match audited head")

        history_identity = {
            "schema": DATA_CATALOG_HISTORY_SCHEMA,
            "dataset_id": dataset_id,
            "head_manifest_sha256": str(head.get("manifest_sha256")) if head else str(selected),
            "revisions": [
                {
                    "revision": manifest.get("revision"),
                    "manifest_sha256": manifest.get("manifest_sha256"),
                    "payload_sha256": manifest.get("payload_sha256"),
                    "available_at": manifest.get("available_at"),
                }
                for manifest in manifests
            ],
        }
        return {
            **history_identity,
            "history_sha256": sha256_digest(history_identity) if manifests else None,
            "verified": not errors,
            "errors": errors,
            "revision_count": len(manifests),
            "head_revision": head.get("revision") if head else None,
            "manifests": manifests,
        }

    def verify(self, dataset_id: str, manifest_sha256: str | None = None) -> dict[str, Any]:
        history = self.history(dataset_id, manifest_sha256)
        manifest = history["manifests"][-1] if history["manifests"] else None
        return {
            "verified": history["verified"],
            "dataset_id": history["dataset_id"],
            "revision": manifest.get("revision") if manifest else None,
            "revision_count": history.get("revision_count", 0),
            "manifest_sha256": manifest.get("manifest_sha256") if manifest else None,
            "payload_sha256": manifest.get("payload_sha256") if manifest else None,
            "history_sha256": history.get("history_sha256"),
            "first_available_at": (
                history["manifests"][0].get("available_at")
                if history["manifests"]
                else None
            ),
            "latest_available_at": manifest.get("available_at") if manifest else None,
            "errors": history["errors"],
            "manifest": manifest,
        }

    def resolve_as_of(
        self,
        dataset_id: str,
        knowledge_cutoff: str | datetime,
        *,
        catalog_head_manifest_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Select the latest revision known by a cutoff under an immutable catalog head."""
        dataset_id = self._validate_dataset_id(dataset_id)
        cutoff = self._timestamp(knowledge_cutoff, "knowledge_cutoff")
        cutoff_text = cutoff.isoformat().replace("+00:00", "Z")
        history = self.history(dataset_id, catalog_head_manifest_sha256)
        if not history["verified"]:
            raise DataCatalogError(
                f"catalog history failed verification for {dataset_id}: {history['errors']}"
            )
        selected: dict[str, Any] | None = None
        selected_index = -1
        for index, manifest in enumerate(history["manifests"]):
            if self._timestamp(manifest["available_at"], "available_at") <= cutoff:
                selected = manifest
                selected_index = index
            else:
                break
        if selected is None:
            raise DataCatalogError(
                f"dataset {dataset_id} has no revision available by {cutoff_text}"
            )
        prefix_identity = {
            "schema": DATA_CATALOG_HISTORY_SCHEMA,
            "dataset_id": dataset_id,
            "head_manifest_sha256": selected["manifest_sha256"],
            "revisions": history["revisions"][: selected_index + 1],
        }
        identity = {
            "schema": DATA_CATALOG_AS_OF_SCHEMA,
            "dataset_id": dataset_id,
            "knowledge_cutoff": cutoff_text,
            "catalog_head_manifest_sha256": history["head_manifest_sha256"],
            "catalog_head_revision": history["head_revision"],
            "catalog_history_sha256": history["history_sha256"],
            "selected_manifest_sha256": selected["manifest_sha256"],
            "selected_revision": selected["revision"],
            "selected_payload_sha256": selected["payload_sha256"],
            "selected_available_at": selected["available_at"],
            "selected_history_prefix_sha256": sha256_digest(prefix_identity),
            "excluded_later_revision_count": history["revision_count"] - selected_index - 1,
        }
        return {**identity, "as_of_sha256": sha256_digest(identity)}

    def verify_as_of(self, selection: Mapping[str, Any]) -> dict[str, Any]:
        """Rebuild a frozen as-of selection and reject stale, forged or extended evidence."""
        candidate = dict(selection)
        errors: list[str] = []
        if candidate.get("schema") != DATA_CATALOG_AS_OF_SCHEMA:
            errors.append("unsupported as-of selection schema")
        try:
            rebuilt = self.resolve_as_of(
                str(candidate.get("dataset_id") or ""),
                str(candidate.get("knowledge_cutoff") or ""),
                catalog_head_manifest_sha256=str(
                    candidate.get("catalog_head_manifest_sha256") or ""
                ),
            )
            if rebuilt != candidate:
                errors.append("as-of selection does not match the verified catalog history")
        except DataCatalogError as exc:
            errors.append(str(exc))
            rebuilt = None
        return {
            "verified": not errors,
            "dataset_id": candidate.get("dataset_id"),
            "as_of_sha256": candidate.get("as_of_sha256"),
            "errors": errors,
            "selection": rebuilt,
        }

    def load(self, dataset_id: str, manifest_sha256: str | None = None) -> dict[str, Any]:
        """Load a snapshot only after its manifest and payload hashes verify."""
        verification = self.verify(dataset_id, manifest_sha256)
        if not verification["verified"]:
            raise DataCatalogError(
                f"catalog entry failed verification for {dataset_id}: "
                f"{verification['errors']}"
            )
        payload_sha256 = str(verification["payload_sha256"])
        payload_path = self._dataset_root(dataset_id) / "snapshots" / f"{payload_sha256}.json"
        try:
            payload = self._load_json(payload_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise DataCatalogError(f"verified snapshot became unreadable: {exc}") from exc
        return {
            "dataset_id": self._validate_dataset_id(dataset_id),
            "manifest": verification["manifest"],
            "manifest_sha256": verification["manifest_sha256"],
            "payload_sha256": payload_sha256,
            "payload": payload,
        }

    def status(self) -> dict[str, Any]:
        datasets: list[dict[str, Any]] = []
        datasets_root = self.root / "datasets"
        if datasets_root.is_dir():
            for path in sorted(datasets_root.iterdir(), key=lambda item: item.name):
                if path.is_dir() and _DATASET_ID_RE.fullmatch(path.name):
                    datasets.append(self.verify(path.name))
        verified = sum(1 for item in datasets if item["verified"])
        return {
            "schema": "quant-core/data-catalog-status/v2",
            "root": str(self.root),
            "dataset_count": len(datasets),
            "verified_count": verified,
            "revision_count": sum(int(item.get("revision_count") or 0) for item in datasets),
            "full_history_audit_required": True,
            "timezone_aware_availability_required": True,
            "backdated_revisions_rejected": True,
            "frozen_head_as_of_resolution_supported": True,
            "status": "READY" if datasets and verified == len(datasets) else ("EMPTY" if not datasets else "DEGRADED"),
            "datasets": datasets,
        }
