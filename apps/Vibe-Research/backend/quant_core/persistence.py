"""Content-addressed persistent checkpoints for the central paper ledger."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Callable, TypeVar

from .execution import SimulationLedger
from .provenance import sha256_digest


LEDGER_CHECKPOINT_SCHEMA = "quant-core/persistent-ledger-checkpoint/v1"
LEDGER_POINTER_SCHEMA = "quant-core/persistent-ledger-latest/v1"
LEDGER_OPERATION_SCHEMA = "quant-core/persistent-ledger-operation/v1"

_WINDOWS_WRITE_RETRY_ATTEMPTS = 8
_WINDOWS_WRITE_RETRY_INITIAL_SECONDS = 0.01

_T = TypeVar("_T")


class LedgerPersistenceError(RuntimeError):
    pass


class LedgerReadOnlyError(LedgerPersistenceError):
    pass


class LedgerOperationConflict(LedgerPersistenceError):
    pass


def _retry_permission_error(operation: Callable[[], _T]) -> _T:
    """Retry only transient sharing violations, then preserve fail-closed behavior."""
    delay = _WINDOWS_WRITE_RETRY_INITIAL_SECONDS
    for attempt in range(_WINDOWS_WRITE_RETRY_ATTEMPTS):
        try:
            return operation()
        except PermissionError:
            if attempt + 1 >= _WINDOWS_WRITE_RETRY_ATTEMPTS:
                raise
            time.sleep(delay)
            delay *= 2
    raise AssertionError("unreachable")


def _durable_temporary(path: Path, encoded: str) -> Path:
    """Write and fsync a uniquely named sibling before it becomes visible."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw_path)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _atomic_json(path: Path, payload: Any) -> None:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    )
    temporary = _durable_temporary(path, encoded)
    try:
        _retry_permission_error(lambda: os.replace(temporary, path))
    finally:
        temporary.unlink(missing_ok=True)


def _immutable_json(path: Path, payload: Any) -> None:
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False
    )
    temporary = _durable_temporary(path, encoded)
    try:
        try:
            # A hard-link publish is atomic and cannot overwrite a competing
            # immutable record.  os.replace() would silently violate that rule.
            _retry_permission_error(lambda: os.link(temporary, path))
        except FileExistsError:
            existing = _retry_permission_error(
                lambda: path.read_text(encoding="utf-8")
            )
            if existing != encoded:
                raise LedgerPersistenceError(
                    f"immutable ledger record conflict: {path}"
                )
    finally:
        temporary.unlink(missing_ok=True)


class PersistentLedgerStore:
    """Append-only checkpoint store with idempotent operations and fail-closed recovery."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()
        self.read_only = False
        self.current_checkpoint_sha256: str | None = None
        self.last_recovery_report: dict[str, Any] | None = None

    @staticmethod
    def _load_json(path: Path) -> Any:
        return json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {constant}")
            ),
        )

    @property
    def latest_path(self) -> Path:
        return self.root / "latest.json"

    def _checkpoint_path(self, sequence: int, checkpoint_sha256: str) -> Path:
        return self.root / "checkpoints" / f"{sequence:012d}-{checkpoint_sha256}.json"

    def _operation_path(self, operation_key: str) -> Path:
        return self.root / "operations" / f"{sha256_digest(operation_key)}.json"

    def committed_operation(self, operation_key: str) -> dict[str, Any] | None:
        """Return a verified operation receipt without changing the latest pointer."""
        key = str(operation_key).strip()
        if not key:
            raise ValueError("operation_key is required")
        path = self._operation_path(key)
        if not path.exists():
            return None
        try:
            operation = self._load_json(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise LedgerPersistenceError(f"operation record is unreadable: {exc}") from exc
        if operation.get("schema") != LEDGER_OPERATION_SCHEMA:
            raise LedgerPersistenceError("unsupported ledger operation schema")
        expected_fields = {
            "schema",
            "operation_key",
            "operation_key_sha256",
            "sequence",
            "checkpoint_sha256",
            "snapshot_sha256",
        }
        if set(operation) != expected_fields:
            raise LedgerPersistenceError("ledger operation fields do not match schema")
        if operation.get("operation_key") != key:
            raise LedgerPersistenceError("operation key hash collision or record mismatch")
        if operation.get("operation_key_sha256") != sha256_digest(key):
            raise LedgerPersistenceError("operation key hash mismatch")
        checkpoint_sha256 = str(operation.get("checkpoint_sha256") or "")
        envelope, _ = self._read_checkpoint(checkpoint_sha256)
        if (
            int(operation.get("sequence") or 0) != int(envelope["sequence"])
            or operation.get("snapshot_sha256") != envelope.get("snapshot_sha256")
            or operation.get("operation_key") != envelope.get("operation_key")
        ):
            raise LedgerPersistenceError("operation record does not match its checkpoint")
        return operation

    def recover_operation(self, operation_key: str) -> tuple[SimulationLedger, dict[str, Any]]:
        """Restore the exact state committed by an idempotent operation key."""
        operation = self.committed_operation(operation_key)
        if operation is None:
            raise LedgerPersistenceError(f"operation is not committed: {operation_key}")
        _, ledger = self._read_checkpoint(str(operation["checkpoint_sha256"]))
        return ledger, operation

    def _read_pointer(self) -> dict[str, Any] | None:
        if not self.latest_path.exists():
            return None
        try:
            pointer = self._load_json(self.latest_path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise LedgerPersistenceError(f"latest pointer is unreadable: {exc}") from exc
        if pointer.get("schema") != LEDGER_POINTER_SCHEMA:
            raise LedgerPersistenceError("unsupported ledger pointer schema")
        if set(pointer) != {
            "schema",
            "sequence",
            "checkpoint_sha256",
            "snapshot_sha256",
        }:
            raise LedgerPersistenceError("latest pointer fields do not match schema")
        if int(pointer.get("sequence") or 0) < 1:
            raise LedgerPersistenceError("latest pointer sequence is invalid")
        return pointer

    def _read_checkpoint_path(self, path: Path) -> tuple[dict[str, Any], SimulationLedger]:
        try:
            envelope = self._load_json(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise LedgerPersistenceError(f"checkpoint unreadable: {path.name}: {exc}") from exc
        if envelope.get("schema") != LEDGER_CHECKPOINT_SCHEMA:
            raise LedgerPersistenceError(f"unsupported checkpoint schema: {path.name}")
        expected = str(envelope.get("checkpoint_sha256") or "")
        identity = {key: value for key, value in envelope.items() if key != "checkpoint_sha256"}
        if not expected or sha256_digest(identity) != expected:
            raise LedgerPersistenceError(f"checkpoint hash mismatch: {path.name}")
        expected_name = self._checkpoint_path(int(envelope.get("sequence") or 0), expected).name
        if path.name != expected_name:
            raise LedgerPersistenceError(f"checkpoint filename mismatch: {path.name}")
        snapshot = dict(envelope.get("snapshot") or {})
        if snapshot.get("snapshot_sha256") != envelope.get("snapshot_sha256"):
            raise LedgerPersistenceError(f"snapshot identity mismatch: {path.name}")
        try:
            ledger = SimulationLedger.from_snapshot(snapshot)
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            raise LedgerPersistenceError(f"snapshot restore failed: {path.name}: {exc}") from exc
        return envelope, ledger

    def _find_checkpoint(self, checkpoint_sha256: str) -> Path:
        matches = list((self.root / "checkpoints").glob(f"*-{checkpoint_sha256}.json"))
        if len(matches) != 1:
            raise LedgerPersistenceError(f"checkpoint not found or ambiguous: {checkpoint_sha256}")
        return matches[0]

    def _read_checkpoint(self, checkpoint_sha256: str) -> tuple[dict[str, Any], SimulationLedger]:
        return self._read_checkpoint_path(self._find_checkpoint(checkpoint_sha256))

    @contextmanager
    def _commit_lock(self):
        """Protect the chain-head check and publication across store instances."""
        self.root.mkdir(parents=True, exist_ok=True)
        handle = (self.root / ".commit.lock").open("a+b")
        acquired = False
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:  # pragma: no cover - the deployed platform is Windows
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise LedgerOperationConflict("another ledger commit is active") from exc
            acquired = True
            yield
        finally:
            try:
                if acquired:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:  # pragma: no cover
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            finally:
                handle.close()

    def commit(self, ledger: SimulationLedger, operation_key: str) -> dict[str, Any]:
        with self._commit_lock():
            return self._commit_locked(ledger, operation_key)

    def _commit_locked(self, ledger: SimulationLedger, operation_key: str) -> dict[str, Any]:
        key = str(operation_key).strip()
        if not key:
            raise ValueError("operation_key is required")
        if self.read_only:
            raise LedgerReadOnlyError("ledger store is read-only until recovery is explicitly acknowledged")
        snapshot = ledger.snapshot()
        snapshot_sha256 = str(snapshot["snapshot_sha256"])
        operation_path = self._operation_path(key)
        if operation_path.exists():
            operation = self.committed_operation(key)
            assert operation is not None
            if operation.get("operation_key") != key or operation.get("snapshot_sha256") != snapshot_sha256:
                raise LedgerOperationConflict(f"operation key already committed with different state: {key}")
            checkpoint_sha256 = str(operation["checkpoint_sha256"])
            envelope, _ = self._read_checkpoint(checkpoint_sha256)
            operation_pointer = {
                "schema": LEDGER_POINTER_SCHEMA,
                "sequence": envelope["sequence"],
                "checkpoint_sha256": checkpoint_sha256,
                "snapshot_sha256": snapshot_sha256,
            }
            candidates = self._valid_chain_tips()
            if not candidates:
                raise LedgerPersistenceError("committed operation has no valid ledger chain")
            tip_envelope, _ = candidates[0]
            committed_hashes = {
                str(item[0]["checkpoint_sha256"]) for item in candidates
            }
            if checkpoint_sha256 not in committed_hashes:
                raise LedgerPersistenceError(
                    "committed operation is outside the valid ledger chain"
                )
            latest = {
                "schema": LEDGER_POINTER_SCHEMA,
                "sequence": int(tip_envelope["sequence"]),
                "checkpoint_sha256": str(tip_envelope["checkpoint_sha256"]),
                "snapshot_sha256": str(tip_envelope["snapshot_sha256"]),
            }
            _atomic_json(self.latest_path, latest)
            self.current_checkpoint_sha256 = str(tip_envelope["checkpoint_sha256"])
            return {
                **operation_pointer,
                "operation_key": key,
                "idempotent": True,
                "latest_checkpoint_sha256": self.current_checkpoint_sha256,
            }

        pointer = self._read_pointer()
        candidates = self._valid_chain_tips()
        previous_sha256 = None
        sequence = 1
        if pointer is not None:
            previous_sha256 = str(pointer["checkpoint_sha256"])
            previous, _ = self._read_checkpoint(previous_sha256)
            if (
                int(previous["sequence"]) != int(pointer["sequence"])
                or previous.get("snapshot_sha256")
                != pointer.get("snapshot_sha256")
            ):
                raise LedgerPersistenceError("latest pointer does not match checkpoint")
            if (
                not candidates
                or str(candidates[0][0]["checkpoint_sha256"])
                != previous_sha256
            ):
                raise LedgerPersistenceError(
                    "latest pointer is stale or references an uncommitted checkpoint"
                )
            if self.current_checkpoint_sha256 != previous_sha256:
                raise LedgerOperationConflict(
                    "ledger state is stale or has not been recovered; recover before committing"
                )
            sequence = int(pointer["sequence"]) + 1
        elif self.current_checkpoint_sha256:
            previous, _ = self._read_checkpoint(self.current_checkpoint_sha256)
            previous_sha256 = self.current_checkpoint_sha256
            if (
                not candidates
                or str(candidates[0][0]["checkpoint_sha256"])
                != previous_sha256
            ):
                raise LedgerPersistenceError(
                    "in-memory checkpoint is not the latest committed chain tip"
                )
            sequence = int(previous["sequence"]) + 1
        elif candidates:
            raise LedgerPersistenceError(
                "latest pointer is missing; recover before committing a new operation"
            )

        if previous_sha256 is not None:
            # The same invariant applies when an already-open store continues
            # from its known chain head after the mutable pointer was lost.
            previous_events = previous["snapshot"]["events"]
            if snapshot["events"][:len(previous_events)] != previous_events:
                raise LedgerOperationConflict(
                    "ledger state is stale: committed audit events cannot be replaced"
                )

        identity = {
            "schema": LEDGER_CHECKPOINT_SCHEMA,
            "sequence": sequence,
            "operation_key": key,
            "previous_checkpoint_sha256": previous_sha256,
            "snapshot_sha256": snapshot_sha256,
            "snapshot": snapshot,
        }
        checkpoint_sha256 = sha256_digest(identity)
        envelope = {**identity, "checkpoint_sha256": checkpoint_sha256}
        checkpoint_path = self._checkpoint_path(sequence, checkpoint_sha256)
        _immutable_json(checkpoint_path, envelope)
        operation = {
            "schema": LEDGER_OPERATION_SCHEMA,
            "operation_key": key,
            "operation_key_sha256": sha256_digest(key),
            "sequence": sequence,
            "checkpoint_sha256": checkpoint_sha256,
            "snapshot_sha256": snapshot_sha256,
        }
        _immutable_json(operation_path, operation)
        latest = {
            "schema": LEDGER_POINTER_SCHEMA,
            "sequence": sequence,
            "checkpoint_sha256": checkpoint_sha256,
            "snapshot_sha256": snapshot_sha256,
        }
        _atomic_json(self.latest_path, latest)
        self.current_checkpoint_sha256 = checkpoint_sha256
        return {**latest, "operation_key": key, "idempotent": False}

    def _valid_chain_tips(self) -> list[tuple[dict[str, Any], SimulationLedger]]:
        valid: dict[str, tuple[dict[str, Any], SimulationLedger]] = {}
        for path in sorted((self.root / "checkpoints").glob("*.json")):
            try:
                envelope, ledger = self._read_checkpoint_path(path)
                operation_key = str(envelope.get("operation_key") or "")
                operation = self.committed_operation(operation_key)
                if (
                    operation is None
                    or operation.get("checkpoint_sha256")
                    != envelope.get("checkpoint_sha256")
                ):
                    continue
            except (LedgerPersistenceError, ValueError):
                continue
            valid[str(envelope["checkpoint_sha256"])] = (envelope, ledger)
        chain_valid: dict[str, tuple[dict[str, Any], SimulationLedger]] = {}
        branches: dict[tuple[int, str | None], str] = {}
        for checkpoint_sha256, item in sorted(valid.items(), key=lambda pair: int(pair[1][0]["sequence"])):
            envelope = item[0]
            previous = envelope.get("previous_checkpoint_sha256")
            sequence = int(envelope["sequence"])
            if previous is None:
                if sequence != 1:
                    continue
            else:
                prior = chain_valid.get(str(previous))
                if prior is None or sequence != int(prior[0]["sequence"]) + 1:
                    continue
            branch_key = (sequence, str(previous) if previous is not None else None)
            competing = branches.get(branch_key)
            if competing is not None and competing != checkpoint_sha256:
                raise LedgerPersistenceError(
                    "ambiguous committed ledger fork requires manual investigation"
                )
            branches[branch_key] = checkpoint_sha256
            chain_valid[checkpoint_sha256] = item
        return sorted(chain_valid.values(), key=lambda item: int(item[0]["sequence"]), reverse=True)

    def recover(self) -> tuple[SimulationLedger, dict[str, Any]]:
        pointer_error: str | None = None
        pointer: dict[str, Any] | None = None
        selected: tuple[dict[str, Any], SimulationLedger] | None = None
        candidates = self._valid_chain_tips()
        try:
            pointer = self._read_pointer()
            if pointer is not None:
                selected = self._read_checkpoint(str(pointer["checkpoint_sha256"]))
                envelope = selected[0]
                if (
                    int(pointer["sequence"]) != int(envelope["sequence"])
                    or pointer.get("snapshot_sha256")
                    != envelope.get("snapshot_sha256")
                ):
                    raise LedgerPersistenceError(
                        "latest pointer does not match its checkpoint"
                    )
                if (
                    not candidates
                    or str(envelope["checkpoint_sha256"])
                    != str(candidates[0][0]["checkpoint_sha256"])
                ):
                    raise LedgerPersistenceError(
                        "latest pointer is not the unique committed chain tip"
                    )
        except (KeyError, LedgerPersistenceError) as exc:
            pointer_error = str(exc)
            selected = None
        degraded = pointer is None or selected is None
        if selected is None:
            if not candidates:
                raise LedgerPersistenceError("no valid ledger checkpoint is recoverable")
            selected = candidates[0]
        envelope, ledger = selected
        selected_sha256 = str(envelope["checkpoint_sha256"])
        if pointer is not None and str(pointer.get("checkpoint_sha256")) != selected_sha256:
            degraded = True
        self.current_checkpoint_sha256 = selected_sha256
        self.read_only = degraded
        report_identity = {
            "schema": "quant-core/ledger-recovery-report/v1",
            "selected_sequence": int(envelope["sequence"]),
            "selected_checkpoint_sha256": selected_sha256,
            "selected_snapshot_sha256": str(envelope["snapshot_sha256"]),
            "pointer_checkpoint_sha256": str((pointer or {}).get("checkpoint_sha256") or ""),
            "degraded": degraded,
            "read_only": self.read_only,
            "pointer_error": pointer_error,
        }
        report = {**report_identity, "report_sha256": sha256_digest(report_identity)}
        _immutable_json(self.root / "recovery" / "reports" / f"{report['report_sha256']}.json", report)
        _atomic_json(
            self.root / "recovery" / "latest.json",
            {"report_sha256": report["report_sha256"], "read_only": self.read_only},
        )
        self.last_recovery_report = report
        return ledger, report

    def inspect(self) -> dict[str, Any]:
        """Verify the latest checkpoint without repairing or writing recovery files."""
        if not self.latest_path.exists():
            return {
                "schema": "quant-core/persistent-ledger-inspection/v1",
                "status": "EMPTY",
                "read_only_recommended": True,
                "error": None,
                "checkpoint": None,
                "ledger": None,
            }
        try:
            pointer = self._read_pointer()
            assert pointer is not None
            envelope, ledger = self._read_checkpoint(str(pointer["checkpoint_sha256"]))
            if int(pointer["sequence"]) != int(envelope["sequence"]):
                raise LedgerPersistenceError("latest pointer sequence mismatch")
            if pointer.get("snapshot_sha256") != envelope.get("snapshot_sha256"):
                raise LedgerPersistenceError("latest pointer snapshot mismatch")
            candidates = self._valid_chain_tips()
            if (
                not candidates
                or str(candidates[0][0]["checkpoint_sha256"])
                != str(envelope["checkpoint_sha256"])
            ):
                raise LedgerPersistenceError(
                    "latest pointer is not the unique committed chain tip"
                )
            return {
                "schema": "quant-core/persistent-ledger-inspection/v1",
                "status": "READY",
                "read_only_recommended": False,
                "error": None,
                "checkpoint": {
                    "sequence": int(envelope["sequence"]),
                    "checkpoint_sha256": str(envelope["checkpoint_sha256"]),
                    "snapshot_sha256": str(envelope["snapshot_sha256"]),
                },
                "ledger": ledger.report(),
            }
        except (KeyError, LedgerPersistenceError) as exc:
            return {
                "schema": "quant-core/persistent-ledger-inspection/v1",
                "status": "DEGRADED",
                "read_only_recommended": True,
                "error": str(exc),
                "checkpoint": None,
                "ledger": None,
            }

    def acknowledge_recovery(self, checkpoint_sha256: str, authorization_reference: str) -> dict[str, Any]:
        with self._commit_lock():
            return self._acknowledge_recovery_locked(checkpoint_sha256, authorization_reference)

    def _acknowledge_recovery_locked(self, checkpoint_sha256: str, authorization_reference: str) -> dict[str, Any]:
        reference = str(authorization_reference).strip()
        if not self.read_only:
            raise LedgerPersistenceError("store is not awaiting recovery acknowledgement")
        if not reference:
            raise ValueError("authorization_reference is required")
        if checkpoint_sha256 != self.current_checkpoint_sha256:
            raise LedgerPersistenceError("recovery acknowledgement checkpoint mismatch")
        candidates = self._valid_chain_tips()
        if (
            not candidates
            or str(candidates[0][0]["checkpoint_sha256"]) != checkpoint_sha256
        ):
            raise LedgerOperationConflict(
                "recovery checkpoint is stale; recover again before acknowledgement"
            )
        self._read_checkpoint(checkpoint_sha256)
        identity = {
            "schema": "quant-core/ledger-recovery-acknowledgement/v1",
            "checkpoint_sha256": checkpoint_sha256,
            "recovery_report_sha256": str((self.last_recovery_report or {}).get("report_sha256") or ""),
            "authorization_reference": reference,
        }
        acknowledgement = {**identity, "acknowledgement_sha256": sha256_digest(identity)}
        _immutable_json(
            self.root / "recovery" / "acknowledgements" / f"{acknowledgement['acknowledgement_sha256']}.json",
            acknowledgement,
        )
        envelope, _ = self._read_checkpoint(checkpoint_sha256)
        _atomic_json(
            self.latest_path,
            {
                "schema": LEDGER_POINTER_SCHEMA,
                "sequence": int(envelope["sequence"]),
                "checkpoint_sha256": checkpoint_sha256,
                "snapshot_sha256": str(envelope["snapshot_sha256"]),
            },
        )
        self.read_only = False
        return acknowledgement

    def health(self) -> dict[str, Any]:
        return {
            "schema": "quant-core/persistent-ledger-health/v1",
            "root": str(self.root),
            "checkpoint_count": len(list((self.root / "checkpoints").glob("*.json"))),
            "operation_count": len(list((self.root / "operations").glob("*.json"))),
            "current_checkpoint_sha256": self.current_checkpoint_sha256,
            "read_only": self.read_only,
            "last_recovery_report": self.last_recovery_report,
        }
