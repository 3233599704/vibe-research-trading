"""Hermetic, non-authoritative offline PAPER demonstration.

This module builds a disposable platform tree and exercises the real quant_core
forward stack.  It never treats the demonstration as formal forward evidence.
"""

from __future__ import annotations

import base64
import builtins
from contextlib import ExitStack, contextmanager
from datetime import date, datetime, timedelta
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterator, Mapping
import zlib

from research.strategy_lab.strict_json import StrictJSONError, strict_json_object


RESULT_SCHEMA = "vibe-research/offline-paper-demo-result/v1"
FIXTURE_SCHEMA = "vibe-research/offline-paper-demo-fixture/v1"
QMT_FIXTURE_SCHEMA = "vibe-research/qmt-compat-sandbox-fixture/v1"
CLASSIFICATION = "DEMO_ONLY_NOT_FORMAL_EVIDENCE"
STRATEGY_ID = "demo-only-etf-trend-v1"
ENGINE_ID = "quant-platform/diversified-etf-trend/v1"
PROVIDER_NAME = "offline-demo-fixture"
ALLOWED_EXECUTION_PAYLOAD_SHA256 = (
    "c4b4d07865835b5d5282f8cc4489239ef92e415d076a5fa3373ff52543d8ead1"
)
ALLOWED_EXECUTION_COMPRESSED_SHA256 = (
    "c8d38a88a268a33206425f8f8a182cdcd0a2b2e1952802fb4f2c67fc96ec6051"
)
ALLOWED_SOURCE_REPOSITORY_HEAD = "46c63eccf4c3d918fd96b517b33c83358260bbe3"
MAX_FIXTURE_BYTES = 64 * 1024
MAX_COMPRESSED_SNAPSHOT_BYTES = 16 * 1024
MAX_EXECUTION_PAYLOAD_BYTES = 64 * 1024
_WORKSPACE_PREFIX = "vibe-offline-paper-demo-"
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURE = (
    ROOT
    / "research"
    / "strategy_lab"
    / "fixtures"
    / "offline_paper_demo"
    / "demo-only-etf-trend-v1.json"
)
FIXTURE_SCHEMA_PATH = (
    ROOT / "config" / "strategy-lab" / "offline-paper-demo-fixture-v1.schema.json"
)
QMT_FIXTURE = (
    ROOT
    / "research"
    / "strategy_lab"
    / "fixtures"
    / "offline_paper_demo"
    / "qmt-compat-sandbox-v1.json"
)
QMT_FIXTURE_SCHEMA_PATH = (
    ROOT / "config" / "strategy-lab" / "qmt-compat-sandbox-fixture-v1.schema.json"
)
QMT_FIXTURE_RAW_SHA256 = (
    "debbf1b3b89010d530f52f4ca55cae979f8324cd9e39f8ffb6d328b44e3ed1f8"
)

_PARENT_SNAPSHOT_PATHS = {
    "apps/Vibe-Research/backend/quant_core/order_allocation.py",
    "apps/Vibe-Research/backend/quant_core/execution_orchestrator.py",
    "config/broker/parent-order-allocation-plan.schema.json",
    "config/broker/parent-fill-allocation.schema.json",
    "config/strategy-lab/pretrade-child-execution-receipt.schema.json",
    "config/strategy-lab/pretrade-execution-batch.schema.json",
}

_POLICY_SNAPSHOT_PATHS = {
    "config/risk/platform-portfolio-policy-v1.json",
    "config/risk/portfolio-stress-policy-v1.json",
}
_PROTECTED_SOURCE_PATHS = (
    "config/strategy-lab/canonical-forward-runner-registry.json",
    "config/strategy-lab/forward-test-registry.json",
    "data/quant-lab",
)

_AUTHORITY_FIELDS = frozenset(
    {
        "authoritative_for_execution",
        "demo_authority",
        "formal_admission_eligible",
        "formal_forward_evidence",
        "promotion_eligible",
        "real_orders",
        "real_orders_enabled",
    }
)


class OfflinePaperDemoError(RuntimeError):
    """Stable machine error raised by the demo boundary."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class NetworkPoisonError(OfflinePaperDemoError):
    def __init__(self) -> None:
        super().__init__("NETWORK_FORBIDDEN", "offline demo attempted network access")


class SubprocessPoisonError(OfflinePaperDemoError):
    def __init__(self) -> None:
        super().__init__(
            "SUBPROCESS_FORBIDDEN", "offline demo attempted subprocess execution"
        )


def _canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def canonical_json_line(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_bytes(value))


def _file_sha256(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _schema_error() -> OfflinePaperDemoError:
    return OfflinePaperDemoError(
        "FIXTURE_SCHEMA_INVALID", "frozen fixture violates its schema"
    )


_SUPPORTED_SCHEMA_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "const",
        "enum",
        "exclusiveMinimum",
        "format",
        "items",
        "maximum",
        "maxItems",
        "minItems",
        "minimum",
        "minLength",
        "minProperties",
        "pattern",
        "properties",
        "required",
        "type",
        "uniqueItems",
    }
)
_SUPPORTED_SCHEMA_TYPES = frozenset(
    {"array", "boolean", "integer", "number", "object", "string"}
)


def _schema_unsupported(message: str) -> OfflinePaperDemoError:
    return OfflinePaperDemoError("SCHEMA_UNSUPPORTED", message)


def _audit_schema_node(schema: Mapping[str, Any]) -> None:
    unknown = set(schema) - _SUPPORTED_SCHEMA_KEYWORDS
    if unknown:
        raise _schema_unsupported("fixture schema contains an unknown keyword")
    if "$ref" in schema and set(schema) != {"$ref"}:
        raise _schema_unsupported("fixture schema combines $ref with sibling keywords")
    expected_type = schema.get("type")
    if expected_type is not None and expected_type not in _SUPPORTED_SCHEMA_TYPES:
        raise _schema_unsupported("fixture schema contains an unsupported type")
    if "additionalProperties" in schema and schema["additionalProperties"] is not False:
        raise _schema_unsupported(
            "fixture schema only permits fail-closed additionalProperties"
        )
    for name in ("$defs", "properties"):
        children = schema.get(name)
        if children is None:
            continue
        if not isinstance(children, Mapping):
            raise _schema_unsupported("fixture schema child map is invalid")
        for child in children.values():
            if not isinstance(child, Mapping):
                raise _schema_unsupported("fixture schema child is not an object")
            _audit_schema_node(child)
    items = schema.get("items")
    if items is not None:
        if not isinstance(items, Mapping):
            raise _schema_unsupported("fixture schema items must be an object")
        _audit_schema_node(items)
    required = schema.get("required")
    if required is not None and (
        not isinstance(required, list)
        or any(not isinstance(item, str) for item in required)
        or len(required) != len(set(required))
    ):
        raise _schema_unsupported("fixture schema required list is invalid")
    value_format = schema.get("format")
    if value_format is not None and value_format not in {"date", "date-time"}:
        raise _schema_unsupported("fixture schema format is unsupported")
    pattern = schema.get("pattern")
    if pattern is not None:
        if not isinstance(pattern, str):
            raise _schema_unsupported("fixture schema pattern is invalid")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise _schema_unsupported("fixture schema pattern cannot compile") from exc
    for name in (
        "exclusiveMinimum",
        "maximum",
        "maxItems",
        "minimum",
        "minItems",
        "minLength",
        "minProperties",
    ):
        if name in schema and type(schema[name]) not in {int, float}:
            raise _schema_unsupported("fixture schema numeric bound is invalid")
    if "uniqueItems" in schema and schema["uniqueItems"] is not True:
        raise _schema_unsupported("fixture schema uniqueItems is invalid")


def _validate_schema_node(
    value: Any,
    schema: Mapping[str, Any],
    root_schema: Mapping[str, Any],
) -> None:
    """Validate the deliberately small schema vocabulary used by this fixture."""

    reference = schema.get("$ref")
    if reference is not None:
        if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
            raise OfflinePaperDemoError(
                "SCHEMA_UNSUPPORTED", "fixture schema uses a non-local reference"
            )
        target: Any = root_schema
        for part in reference[2:].split("/"):
            if not isinstance(target, Mapping) or part not in target:
                raise OfflinePaperDemoError(
                    "SCHEMA_UNSUPPORTED", "fixture schema reference is unresolved"
                )
            target = target[part]
        if not isinstance(target, Mapping):
            raise OfflinePaperDemoError(
                "SCHEMA_UNSUPPORTED", "fixture schema reference is not an object"
            )
        _validate_schema_node(value, target, root_schema)
        return

    expected_type = schema.get("type")
    type_matches = {
        "object": isinstance(value, Mapping),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "boolean": type(value) is bool,
        "integer": type(value) is int,
        "number": type(value) in {int, float} and math.isfinite(float(value)),
    }
    if expected_type is not None and not type_matches.get(str(expected_type), False):
        raise _schema_error()
    if "const" in schema and value != schema["const"]:
        raise _schema_error()
    if "enum" in schema and value not in schema["enum"]:
        raise _schema_error()

    if isinstance(value, Mapping):
        required = set(schema.get("required") or [])
        if not required.issubset(value):
            raise _schema_error()
        properties = dict(schema.get("properties") or {})
        if schema.get("additionalProperties") is False and not set(value).issubset(
            properties
        ):
            raise _schema_error()
        minimum_properties = schema.get("minProperties")
        if minimum_properties is not None and len(value) < int(minimum_properties):
            raise _schema_error()
        for key, child in value.items():
            child_schema = properties.get(key)
            if child_schema is not None:
                _validate_schema_node(child, child_schema, root_schema)

    if isinstance(value, list):
        minimum_items = schema.get("minItems")
        maximum_items = schema.get("maxItems")
        if minimum_items is not None and len(value) < int(minimum_items):
            raise _schema_error()
        if maximum_items is not None and len(value) > int(maximum_items):
            raise _schema_error()
        if schema.get("uniqueItems") is True:
            identities = [canonical_json_line(item) for item in value]
            if len(identities) != len(set(identities)):
                raise _schema_error()
        item_schema = schema.get("items")
        if isinstance(item_schema, Mapping):
            for item in value:
                _validate_schema_node(item, item_schema, root_schema)

    if isinstance(value, str):
        if len(value) < int(schema.get("minLength", 0)):
            raise _schema_error()
        pattern = schema.get("pattern")
        if pattern is not None and re.search(str(pattern), value) is None:
            raise _schema_error()
        value_format = schema.get("format")
        try:
            if value_format == "date":
                date.fromisoformat(value)
            elif value_format == "date-time":
                datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise _schema_error() from exc

    if type(value) in {int, float}:
        if "minimum" in schema and value < schema["minimum"]:
            raise _schema_error()
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            raise _schema_error()
        if "maximum" in schema and value > schema["maximum"]:
            raise _schema_error()


def _external_draft_validator() -> Any | None:
    try:
        from jsonschema import (  # type: ignore[import-not-found]  # noqa: PLC0415
            Draft202012Validator,
        )
    except ImportError:
        return None
    return Draft202012Validator


def _validate_document_schema(
    fixture: Mapping[str, Any], schema_path: Path
) -> None:
    try:
        raw_schema = schema_path.read_bytes()
        schema = strict_json_object(raw_schema)
    except (OSError, StrictJSONError) as exc:
        raise OfflinePaperDemoError(
            "SCHEMA_UNREADABLE", "fixture schema is unreadable"
        ) from exc
    if raw_schema != _canonical_bytes(schema):
        raise _schema_unsupported("fixture schema is not canonical JSON")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise _schema_unsupported("fixture schema is not Draft 2020-12")
    _audit_schema_node(schema)
    _validate_schema_node(fixture, schema, schema)
    Draft202012Validator = _external_draft_validator()
    if Draft202012Validator is None:
        return
    try:
        Draft202012Validator.check_schema(schema)
        errors = sorted(
            Draft202012Validator(schema).iter_errors(fixture),
            key=lambda item: list(item.absolute_path),
        )
    except Exception as exc:
        raise OfflinePaperDemoError(
            "SCHEMA_UNSUPPORTED", "fixture schema cannot be validated"
        ) from exc
    if errors:
        raise _schema_error()


def _validate_fixture_schema(fixture: Mapping[str, Any]) -> None:
    _validate_document_schema(fixture, FIXTURE_SCHEMA_PATH)


def _decode_execution_snapshot(snapshot: Mapping[str, Any]) -> bytes:
    if snapshot.get("source_repository_head") != ALLOWED_SOURCE_REPOSITORY_HEAD:
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded execution snapshot source identity is not allowed",
        )
    if snapshot.get("execution_model_sha256") != ALLOWED_EXECUTION_PAYLOAD_SHA256:
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded execution payload identity is not allowed",
        )
    if (
        snapshot.get("execution_model_gzip_sha256")
        != ALLOWED_EXECUTION_COMPRESSED_SHA256
    ):
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded compressed snapshot identity is not allowed",
        )
    encoded = snapshot.get("execution_model_gzip_base64")
    if not isinstance(encoded, str):
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded execution snapshot encoding is invalid",
        )
    try:
        compressed = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded execution snapshot is not strict base64",
        ) from exc
    if len(compressed) > MAX_COMPRESSED_SNAPSHOT_BYTES:
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded compressed snapshot exceeds its size limit",
        )
    if _sha256_bytes(compressed) != ALLOWED_EXECUTION_COMPRESSED_SHA256:
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded compressed snapshot hash mismatch",
        )
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        payload = decompressor.decompress(
            compressed, MAX_EXECUTION_PAYLOAD_BYTES + 1
        )
        if len(payload) <= MAX_EXECUTION_PAYLOAD_BYTES:
            payload += decompressor.flush(
                MAX_EXECUTION_PAYLOAD_BYTES + 1 - len(payload)
            )
    except zlib.error as exc:
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded execution snapshot gzip stream is invalid",
        ) from exc
    if len(payload) > MAX_EXECUTION_PAYLOAD_BYTES or decompressor.unconsumed_tail:
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded execution payload exceeds its size limit",
        )
    if not decompressor.eof or decompressor.unused_data:
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded execution snapshot is truncated or has trailing members",
        )
    if _sha256_bytes(payload) != ALLOWED_EXECUTION_PAYLOAD_SHA256:
        raise OfflinePaperDemoError(
            "COMPATIBILITY_SNAPSHOT_INVALID",
            "embedded execution payload hash mismatch",
        )
    return payload


def _load_fixture(path: Path = DEFAULT_FIXTURE) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_FIXTURE_BYTES + 1)
        if len(raw) > MAX_FIXTURE_BYTES:
            raise OfflinePaperDemoError(
                "FIXTURE_TOO_LARGE", "frozen fixture exceeds its size limit"
            )
        parsed = strict_json_object(raw)
    except OfflinePaperDemoError:
        raise
    except (OSError, StrictJSONError) as exc:
        code = getattr(exc, "code", "FIXTURE_UNREADABLE")
        raise OfflinePaperDemoError(str(code), "frozen fixture is unreadable") from exc
    fixture = dict(parsed)
    if raw != _canonical_bytes(fixture):
        raise OfflinePaperDemoError(
            "FIXTURE_NOT_CANONICAL", "frozen fixture bytes are not canonical JSON"
        )
    claimed = str(fixture.get("fixture_sha256") or "")
    identity = {key: value for key, value in fixture.items() if key != "fixture_sha256"}
    actual = _sha256_bytes(_canonical_bytes(identity))
    if claimed != actual:
        raise OfflinePaperDemoError(
            "FIXTURE_HASH_MISMATCH", "frozen fixture self-hash does not match"
        )
    if fixture.get("schema") != FIXTURE_SCHEMA:
        raise OfflinePaperDemoError("FIXTURE_SCHEMA_INVALID", "unsupported fixture schema")
    if any(
        fixture.get(field) is not False
        for field in (
            "authoritative_for_execution",
            "demo_authority",
            "formal_admission_eligible",
            "formal_forward_evidence",
            "promotion_eligible",
            "real_orders",
        )
    ):
        raise OfflinePaperDemoError(
            "DEMO_BOUNDARY_VIOLATION", "fixture weakens the demo-only boundary"
        )
    if not FIXTURE_SCHEMA_PATH.is_file():
        raise OfflinePaperDemoError("SCHEMA_UNREADABLE", "fixture schema is missing")
    _validate_fixture_schema(fixture)
    _decode_execution_snapshot(dict(fixture["compatibility_snapshot"]))
    return fixture


def _load_qmt_fixture(path: Path = QMT_FIXTURE) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        parsed = strict_json_object(raw)
    except (OSError, StrictJSONError) as exc:
        code = getattr(exc, "code", "FIXTURE_UNREADABLE")
        raise OfflinePaperDemoError(str(code), "QMT fixture is unreadable") from exc
    fixture = dict(parsed)
    if len(raw) > MAX_FIXTURE_BYTES:
        raise OfflinePaperDemoError("FIXTURE_TOO_LARGE", "QMT fixture is oversized")
    if raw != _canonical_bytes(fixture):
        raise OfflinePaperDemoError(
            "FIXTURE_NOT_CANONICAL", "QMT fixture is not canonical JSON"
        )
    if _sha256_bytes(raw) != QMT_FIXTURE_RAW_SHA256:
        raise OfflinePaperDemoError(
            "FIXTURE_RAW_HASH_MISMATCH", "QMT fixture raw identity changed"
        )
    claimed = str(fixture.get("fixture_sha256") or "")
    identity = {key: value for key, value in fixture.items() if key != "fixture_sha256"}
    if claimed != _sha256_bytes(_canonical_bytes(identity)):
        raise OfflinePaperDemoError(
            "FIXTURE_HASH_MISMATCH", "QMT fixture logical self-hash changed"
        )
    if fixture.get("schema") != QMT_FIXTURE_SCHEMA:
        raise OfflinePaperDemoError(
            "FIXTURE_SCHEMA_INVALID", "unsupported QMT fixture schema"
        )
    _validate_document_schema(fixture, QMT_FIXTURE_SCHEMA_PATH)
    for field in (
        "authoritative_for_execution",
        "demo_authority",
        "formal_admission_eligible",
        "formal_forward_evidence",
        "promotion_eligible",
        "qmt_runtime_accessed",
        "qmt_vendor_certified",
        "real_broker_accessed",
        "real_orders",
        "xtquant_imported",
    ):
        if fixture.get(field) is not False:
            raise OfflinePaperDemoError(
                "DEMO_BOUNDARY_VIOLATION", "QMT fixture weakens the PAPER boundary"
            )
    callbacks = list(fixture.get("callbacks") or [])
    if sorted(item.get("sequence") for item in callbacks) != list(range(1, 13)):
        raise OfflinePaperDemoError(
            "FIXTURE_SCHEMA_INVALID", "QMT callback sequence set is not frozen"
        )
    for item in callbacks:
        callback_type = item.get("type")
        if callback_type in {"order", "trade", "order_error"} and not item.get(
            "alias"
        ):
            raise OfflinePaperDemoError(
                "FIXTURE_SCHEMA_INVALID", "QMT order callback alias is missing"
            )
    return fixture


@contextmanager
def qmt_runtime_poison_guard() -> Iterator[None]:
    """Reject any attempt to import the real QMT vendor runtime."""

    if any(
        name == "xtquant" or name.startswith("xtquant.")
        for name in tuple(sys.modules)
    ):
        error = OfflinePaperDemoError(
            "QMT_RUNTIME_PRELOADED",
            "QMT vendor runtime was already loaded before the compatibility guard",
        )
        error.xtquant_imported = True
        raise error
    original_import = builtins.__import__

    def blocked_import(
        name: str,
        globals: Any = None,
        locals: Any = None,
        fromlist: Any = (),
        level: int = 0,
    ) -> Any:
        if name == "xtquant" or name.startswith("xtquant."):
            raise OfflinePaperDemoError(
                "QMT_RUNTIME_FORBIDDEN",
                "QMT compatibility demo attempted to import the vendor runtime",
            )
        return original_import(name, globals, locals, fromlist, level)

    builtins.__import__ = blocked_import
    try:
        yield
    finally:
        builtins.__import__ = original_import


@contextmanager
def network_poison_guard() -> Iterator[None]:
    """Poison new network handles, DNS, and subprocess escape in a fresh CLI."""

    original_socket = socket.socket
    original_socket_type = socket.SocketType
    original_popen = subprocess.Popen
    original_system = os.system
    socket_function_names = (
        "create_connection",
        "create_server",
        "fromfd",
        "fromshare",
        "getaddrinfo",
        "gethostbyaddr",
        "gethostbyname",
        "gethostbyname_ex",
        "getnameinfo",
        "socketpair",
    )
    original_socket_functions = {
        name: getattr(socket, name)
        for name in socket_function_names
        if hasattr(socket, name)
    }

    def blocked_network(*_args: Any, **_kwargs: Any) -> Any:
        raise NetworkPoisonError()

    def blocked_subprocess(*_args: Any, **_kwargs: Any) -> Any:
        raise SubprocessPoisonError()

    class PoisonedSocket(original_socket):
        accept = blocked_network
        bind = blocked_network
        connect = blocked_network
        connect_ex = blocked_network
        listen = blocked_network
        recvfrom = blocked_network
        recvfrom_into = blocked_network
        recvmsg = blocked_network
        recvmsg_into = blocked_network
        send = blocked_network
        sendall = blocked_network
        sendmsg = blocked_network
        sendto = blocked_network

    socket.socket = PoisonedSocket
    socket.SocketType = PoisonedSocket
    for name in original_socket_functions:
        setattr(socket, name, blocked_network)
    subprocess.Popen = blocked_subprocess
    os.system = blocked_subprocess
    try:
        yield
    finally:
        socket.socket = original_socket
        socket.SocketType = original_socket_type
        for name, original in original_socket_functions.items():
            setattr(socket, name, original)
        subprocess.Popen = original_popen
        os.system = original_system


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return bool(attributes & 0x400)


def _snapshot_source_path(
    root: Path,
    path: Path,
    relative: str,
    records: list[dict[str, Any]],
) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        records.append({"path": relative, "state": "MISSING"})
        return
    identity = {
        "device": int(metadata.st_dev),
        "inode": int(metadata.st_ino),
        "links": int(metadata.st_nlink),
    }
    if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
        try:
            target = os.readlink(path)
        except OSError:
            target = "UNREADABLE"
        records.append(
            {
                "path": relative,
                "state": "LINK_OR_REPARSE",
                "target": target,
                **identity,
            }
        )
        return
    if stat.S_ISDIR(metadata.st_mode):
        records.append({"path": relative, "state": "DIRECTORY", **identity})
        with os.scandir(path) as entries:
            children = sorted(entries, key=lambda item: item.name)
        for child in children:
            child_relative = f"{relative}/{child.name}"
            _snapshot_source_path(root, Path(child.path), child_relative, records)
        return
    if stat.S_ISREG(metadata.st_mode):
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            payload = stream.read()
            after = os.fstat(stream.fileno())
        before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if before_identity != after_identity:
            raise OfflinePaperDemoError(
                "CANONICAL_SOURCE_UNSTABLE",
                "protected source changed while it was being inspected",
            )
        records.append(
            {
                "path": relative,
                "state": "FILE",
                "size": len(payload),
                "sha256": _sha256_bytes(payload),
                **identity,
            }
        )
        return
    records.append({"path": relative, "state": "OTHER", **identity})


def _source_state(root: Path) -> str:
    records: list[dict[str, Any]] = []
    for relative in _PROTECTED_SOURCE_PATHS:
        _snapshot_source_path(root, root / relative, relative, records)
    return _sha256_bytes(_canonical_bytes(records))


def _assert_plain_directory_tree(path: Path) -> None:
    current = path
    while True:
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise OfflinePaperDemoError(
                "TEMP_ROOT_UNSAFE", "system temp path contains a link or reparse point"
            )
        if current.parent == current:
            return
        current = current.parent


def _workspace_candidate() -> tuple[Path, Path]:
    raw_temp_root = tempfile.gettempdir()
    temp_root = Path(raw_temp_root)
    if not temp_root.is_absolute() or str(temp_root).startswith(("\\\\", "//")):
        raise OfflinePaperDemoError(
            "TEMP_ROOT_UNSAFE", "system temp directory is not a local absolute path"
        )
    if any(part.lower() == ".git" for part in temp_root.parts):
        raise OfflinePaperDemoError(
            "TEMP_ROOT_UNSAFE", "system temp directory crosses git metadata"
        )
    try:
        _assert_plain_directory_tree(temp_root)
        source = ROOT.resolve(strict=True)
        resolved_temp_root = temp_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise OfflinePaperDemoError(
            "TEMP_ROOT_UNSAFE", "system temp directory cannot be verified"
        ) from exc
    if (
        resolved_temp_root == source
        or source in resolved_temp_root.parents
        or resolved_temp_root in source.parents
    ):
        raise OfflinePaperDemoError(
            "CANONICAL_PATH_FORBIDDEN", "system temp directory overlaps the checkout"
        )
    name = f"{_WORKSPACE_PREFIX}{secrets.token_hex(16)}"
    workspace = temp_root / name
    if workspace.parent != temp_root or re.fullmatch(
        rf"{re.escape(_WORKSPACE_PREFIX)}[0-9a-f]{{32}}", workspace.name
    ) is None:
        raise OfflinePaperDemoError(
            "TEMP_PATH_INVALID", "generated demo workspace name is invalid"
        )
    return temp_root, workspace


def _validate_workspace_identity(
    temp_root: Path,
    workspace: Path,
    *,
    must_exist: bool,
) -> None:
    if workspace.parent != temp_root or re.fullmatch(
        rf"{re.escape(_WORKSPACE_PREFIX)}[0-9a-f]{{32}}", workspace.name
    ) is None:
        raise OfflinePaperDemoError(
            "TEMP_PATH_INVALID", "demo workspace identity is invalid"
        )
    if not temp_root.samefile(workspace.parent):
        raise OfflinePaperDemoError(
            "TEMP_PATH_INVALID", "demo workspace parent identity changed"
        )
    if not must_exist:
        if os.path.lexists(workspace):
            raise OfflinePaperDemoError(
                "TEMP_PATH_CONFLICT", "generated demo workspace already exists"
            )
        return
    metadata = workspace.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse_point(metadata)
        or int(metadata.st_nlink) != 1
    ):
        raise OfflinePaperDemoError(
            "TEMP_PATH_INVALID", "demo workspace is not a private plain directory"
        )


def _cleanup_workspace(temp_root: Path, workspace: Path) -> None:
    if not os.path.lexists(workspace):
        return
    _validate_workspace_identity(temp_root, workspace, must_exist=True)
    shutil.rmtree(workspace, ignore_errors=False)
    if os.path.lexists(workspace):
        raise OfflinePaperDemoError(
            "CLEANUP_FAILED", "demo workspace still exists after cleanup"
        )


def _trading_dates(signal_date: str, observations: int = 121) -> list[str]:
    current = date.fromisoformat(signal_date)
    values: list[date] = []
    while len(values) < observations:
        if current.weekday() < 5:
            values.append(current)
        current -= timedelta(days=1)
    values.reverse()
    return [item.isoformat() for item in values]


def _liquidity_history(trade_date: str, volume: float) -> list[dict[str, Any]]:
    current = date.fromisoformat(trade_date)
    values: list[date] = []
    while len(values) < 60:
        if current.weekday() < 5:
            values.append(current)
        current -= timedelta(days=1)
    values.reverse()
    return [{"date": item.isoformat(), "volume": volume} for item in values]


def _market_payload(
    *, trade_date: str, codes: list[str], open_price: float, close_price: float, volume: float
) -> dict[str, Any]:
    high = max(open_price, close_price)
    low = min(open_price, close_price)
    return {
        "schema": "quant-platform/market-session/v2",
        "trade_date": trade_date,
        "as_of_time": f"{trade_date}T15:05:00+08:00",
        "max_event_date": trade_date,
        "bars": {
            code: {
                "open": open_price,
                "high": high,
                "low": low,
                "close": close_price,
                "preclose": open_price,
                "volume": volume,
                "liquidity_history": _liquidity_history(trade_date, volume),
                "suspended": False,
                "is_st": False,
                "trading_days_since_listing": 1000,
                "unsupported_corporate_action": False,
            }
            for code in codes
        },
        "valuation_marks": {code: close_price for code in codes},
    }


def _exchange_rules() -> dict[str, Any]:
    boards = ("main", "chinext", "star", "beijing")
    return {
        "version": "offline-demo-exchange-rules-v1",
        "price_limits": {
            board: {
                "normal": [{"effective_date": "1900-01-01", "rate": 0.1}],
                "st": [{"effective_date": "1900-01-01", "rate": 0.1}],
            }
            for board in boards
        },
        "no_initial_limit": {
            board: {"effective_date": "2999-01-01", "trading_days": 0}
            for board in boards
        },
        "lot_rules": {
            "main": {"minimum": 100, "increment": 100},
            "chinext": {"minimum": 100, "increment": 100},
            "star": {"minimum": 200, "increment": 1},
            "beijing": {"minimum": 100, "increment": 1},
        },
    }


def _risk_policy(universe: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "policy_id": "offline-demo/portfolio-risk/v1",
        "max_gross_exposure_pct": 70,
        "max_asset_pct": 35,
        "max_sector_pct": 50,
        "max_correlation_cluster_pct": 60,
        "minimum_cash_pct": 30,
        "minimum_effective_positions": 2,
        "soft_drawdown_pct": 8,
        "hard_drawdown_pct": 12,
        "asset_metadata": {
            item["code"]: {
                "sector": item["sector"],
                "correlation_cluster": item["correlation_cluster"],
            }
            for item in universe
        },
    }


def _platform_policy() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "policy_id": "offline-demo/platform-portfolio/v1",
        "mode": "PAPER",
        "real_orders": False,
        "max_gross_exposure_pct": 70,
        "max_asset_pct": 35,
        "max_sector_pct": 50,
        "max_correlation_cluster_pct": 60,
        "minimum_cash_pct": 30,
        "minimum_effective_assets": 2,
        "max_active_strategies": 1,
        "unknown_asset_action": "REJECT",
        "require_consistent_asset_metadata": True,
        "require_complete_registry_batch": True,
        "allow_reduce_only_recovery": True,
    }


def _stress_policy() -> dict[str, Any]:
    scenarios = (
        ("CN_EQUITY_GAP_DOWN", -5, {"CN_RISK": -20, "REAL_ASSET": -8}, 50),
        ("CORRELATION_CONVERGENCE", -12, {"CN_RISK": -20, "REAL_ASSET": -15}, 70),
        ("LIQUIDITY_FREEZE", -5, {"CN_RISK": -10, "REAL_ASSET": -8}, 95),
        ("COMBINED_CRISIS", -12, {"CN_RISK": -30, "REAL_ASSET": -12}, 90),
    )
    return {
        "schema_version": 1,
        "policy_id": "offline-demo/portfolio-stress/v1",
        "mode": "PAPER",
        "real_orders": False,
        "max_platform_stress_loss_pct": 15,
        "max_strategy_stress_loss_pct": 20,
        "max_liquidation_days": 10,
        "max_daily_liquidation_participation_pct": 5,
        "allow_reduce_only_recovery": True,
        "required_scenario_ids": [item[0] for item in scenarios],
        "scenarios": [
            {
                "scenario_id": scenario_id,
                "default_shock_pct": default_shock,
                "cluster_shocks_pct": cluster_shocks,
                "asset_shocks_pct": {},
                "liquidity_haircut_pct": haircut,
            }
            for scenario_id, default_shock, cluster_shocks, haircut in scenarios
        ],
    }


def _copy_snapshot(
    source_root: Path,
    platform: Path,
    relative: str,
    fixture: Mapping[str, Any],
) -> None:
    target = platform / relative
    if relative == "research/platform-native-strategy/tools/execution_model.py":
        payload = _decode_execution_snapshot(
            dict(fixture["compatibility_snapshot"])
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    if relative == "research/platform-native-strategy/configs/trading/cost-model-v1.json":
        canonical = json.loads(
            (source_root / "config/execution/cn-a-share-cost-v1.json").read_text(
                encoding="utf-8"
            )
        )
        _write_json(
            target,
            {
                "version": "a-share-cost-v1",
                "commission_rate": canonical["commission_bps"] / 10_000,
                "minimum_commission": canonical["min_commission"],
                "slippage_rate": canonical["slippage_bps"] / 10_000,
                "stamp_tax_schedule": canonical["stamp_tax_schedule"],
                "transfer_fee_schedule": canonical["transfer_fee_schedule"],
            },
        )
        return
    if relative == "research/platform-native-strategy/configs/trading/exchange-rules-v1.json":
        canonical = json.loads(
            (
                source_root
                / "config/execution/cn-a-share-exchange-rules-v1.json"
            ).read_text(encoding="utf-8")
        )
        _write_json(
            target,
            {
                "version": "a-share-exchange-rules-v1",
                "price_limits": canonical["price_limits"],
                "no_initial_limit": canonical["no_initial_limit"],
                "lot_rules": canonical["lot_rules"],
                "sources": [item["url"] for item in canonical["sources"]],
            },
        )
        return
    source = (source_root / relative).resolve()
    try:
        source.relative_to(source_root.resolve())
    except ValueError as exc:
        raise OfflinePaperDemoError(
            "SOURCE_PATH_INVALID", "snapshot source escapes checkout"
        ) from exc
    if not source.is_file():
        raise OfflinePaperDemoError(
            "SOURCE_SNAPSHOT_MISSING", "required product snapshot is missing"
        )
    target.write_bytes(source.read_bytes())


def _materialize_platform(workspace: Path, fixture: dict[str, Any], api: Any) -> dict[str, Any]:
    platform = workspace / "platform"
    runtime = workspace / "runtime"
    catalog_root = workspace / "catalog"
    registry_path = workspace / "registry" / "demo-registry.json"
    universe = [dict(item) for item in fixture["strategy"]["universe"]]
    risk = _risk_policy(universe)
    global_risk = {key: value for key, value in risk.items() if key != "asset_metadata"}
    platform_policy = _platform_policy()
    stress_policy = _stress_policy()
    _write_json(platform / "config/risk/portfolio-risk-policy-v1.json", global_risk)
    _write_json(
        platform / "config/risk/platform-portfolio-policy-v1.json",
        platform_policy,
    )
    _write_json(
        platform / "config/risk/portfolio-stress-policy-v1.json", stress_policy
    )
    governance_relative = "config/research/research-governance-policy-v1.json"
    governance_target = platform / governance_relative
    governance_target.parent.mkdir(parents=True, exist_ok=True)
    governance_target.write_bytes((ROOT / governance_relative).read_bytes())

    snapshot_paths = set(api.EXECUTION_CONFORMANCE_SNAPSHOT_PATHS) | _PARENT_SNAPSHOT_PATHS
    for relative in sorted(snapshot_paths):
        _copy_snapshot(ROOT, platform, relative, fixture)

    strategy_config = {
        "schema_version": 1,
        "strategy_id": STRATEGY_ID,
        "classification": CLASSIFICATION,
        "authoritative_for_execution": False,
        "demo_authority": False,
        "formal_admission_eligible": False,
        "formal_forward_evidence": False,
        "promotion_eligible": False,
        "source_candidate_status": fixture["strategy"]["source_candidate_status"],
        "engine_reuse_only": True,
        "historical_backtest_enabled": False,
        "historical_results_may_support_promotion": False,
        "forward_only": True,
        "real_orders": False,
        "universe": universe,
        "signal_engine": {
            "id": ENGINE_ID,
            "input_schema": "quant-platform/point-in-time-etf-qfq-close-proxy/v1",
            "price_field": "qfq_close_proxy",
            "return_horizons_trading_days": [60, 120],
            "moving_average_trading_days": 120,
            "volatility_trading_days": 20,
            "volatility_floor": 0.001,
        },
        "selection": {
            "signal_frequency": "monthly",
            "top_k": 2,
            "unique_risk_group": True,
            "minimum_eligible_risk_groups": 2,
            "insufficient_eligible_action": "ALL_CASH",
            "tie_breaker": "score_desc_then_code_asc",
        },
        "position_rules": {
            "target_weight_per_asset": 0.35,
            "maximum_positions": 2,
            "maximum_single_asset_weight": 0.35,
            "maximum_gross_exposure": 0.7,
            "minimum_cash_weight": 0.3,
            "minimum_effective_positions_when_invested": 2,
            "allow_cash": True,
            "leverage": False,
            "shorting": False,
        },
    }
    strategy_relative = "demo/strategy.json"
    strategy_path = platform / strategy_relative
    _write_json(strategy_path, strategy_config)

    execution = {
        # This is a synthetic demonstration calendar, not an exchange calendar.
        # Bind its exact sessions rather than weakening the core T+1 gate.
        "market": "SSE_SZSE",
        "t_plus_one_calendar_required": True,
        "trading_calendar": api.build_versioned_trading_calendar_binding(
            calendar_id="offline-demo-synthetic-calendar",
            calendar_version="v1",
            market="SSE_SZSE",
            coverage_start=fixture["timeline"]["signal_date"],
            coverage_end=fixture["timeline"]["valuation_date"],
            sessions=[
                fixture["timeline"]["signal_date"],
                fixture["timeline"]["execute_date"],
                fixture["timeline"]["valuation_date"],
            ],
        ),
        "version": "offline-demo-zero-cost-v1",
        "asset_class": "exchange_traded_fund",
        "commission_bps": 0,
        "min_commission": 0,
        "slippage_bps": 0,
        "stamp_tax_schedule": [{"effective_date": "1900-01-01", "rate": 0}],
        "transfer_fee_schedule": [{"effective_date": "1900-01-01", "rate": 0}],
        "exchange_rules": _exchange_rules(),
        "portfolio_risk_policy": risk,
        "max_volume_participation_pct": 10,
        "max_position_pct": 35,
        "cash_reserve_pct": 30,
        "max_positions": 2,
        "lot_size": 100,
        "t_plus_one": True,
        "enforce_next_session": True,
        "retry_blocked_orders": True,
        "retry_partial_orders": True,
        "authoritative_for_execution": False,
        "demo_authority": False,
        "formal_admission_eligible": False,
        "formal_forward_evidence": False,
        "promotion_eligible": False,
        "real_orders": False,
    }
    bound_snapshot_paths = snapshot_paths | _POLICY_SNAPSHOT_PATHS
    code_snapshot_files = [
        {"path": strategy_relative, "sha256": _file_sha256(strategy_path)},
        *[
            {"path": relative, "sha256": _file_sha256(platform / relative)}
            for relative in sorted(bound_snapshot_paths)
        ],
    ]
    code_snapshot = {"commit": "d" * 40, "files": code_snapshot_files}
    code_snapshot_sha = api.sha256_digest(code_snapshot)
    strategy_sha = _file_sha256(strategy_path)
    execution_sha = api.sha256_digest(execution)
    binding = {
        "strategy_id": STRATEGY_ID,
        "strategy_config_sha256": strategy_sha,
        "code_snapshot_sha256": code_snapshot_sha,
        "passed": True,
        "classification": CLASSIFICATION,
        "authoritative_for_execution": False,
        "demo_authority": False,
        "formal_admission_eligible": False,
        "formal_forward_evidence": False,
        "promotion_eligible": False,
        "real_orders": False,
    }
    recovery_identity = {
        "schema": "quant-platform/recovery-drill/v1",
        **binding,
        "execution_config_sha256": execution_sha,
        "drill_engine": "quant-platform/persistent-ledger-recovery-drill/v2",
        "checks": [
            {"code": code, "passed": True}
            for code in sorted(api.REQUIRED_RECOVERY_DRILL_CHECKS)
        ],
    }
    recovery = {
        **recovery_identity,
        "drill_sha256": api.sha256_digest(recovery_identity),
    }
    recovery_relative = "demo/evidence/recovery.json"
    _write_json(platform / recovery_relative, recovery)
    temporal_identity = {
        "schema": "quant-platform/temporal-bias-audit/v1",
        **binding,
        "audit_engine": "offline-demo/temporal-contract-check/v1",
        "checks": [
            {"code": code, "passed": True}
            for code in sorted(api.REQUIRED_TEMPORAL_AUDIT_CHECKS)
        ],
    }
    temporal = {
        **temporal_identity,
        "audit_sha256": api.sha256_digest(temporal_identity),
    }
    temporal_relative = "demo/evidence/temporal.json"
    _write_json(platform / temporal_relative, temporal)
    conformance = api.build_execution_conformance_report(platform)
    conformance_relative = "demo/evidence/execution-conformance.json"
    _write_json(platform / conformance_relative, conformance)
    conformance_file_sha256 = _file_sha256(platform / conformance_relative)
    research_policy = api.resolve_research_governance_policy(platform)
    configured_risk_sha = api.PortfolioRiskPolicy.from_config(risk).evidence()["policy_sha256"]
    timeline = fixture["timeline"]
    experiment = {
        "strategy_id": STRATEGY_ID,
        "classification": CLASSIFICATION,
        "authoritative_for_execution": False,
        "demo_authority": False,
        "formal_admission_eligible": False,
        "formal_forward_evidence": False,
        "promotion_eligible": False,
        "approval_status": "ACTIVE",
        "approved_at": timeline["approved_at"],
        "first_allowed_signal_date": timeline["signal_date"],
        "frozen": True,
        "code_state": "CLEAN_COMMIT",
        "code_commit": "d" * 40,
        "real_orders": False,
        "execution_adapter_id": "quant_core",
        "initial_cash": fixture["strategy"]["initial_cash"],
        "minimum_trading_days": 252,
        "minimum_observation_count": 12,
        "signal_frequency": "monthly",
        "loss_budget": {"maximum_loss_pct": 10},
        "strategy_config_path": strategy_relative,
        "strategy_config_sha256": strategy_sha,
        "code_snapshot": code_snapshot,
        "code_snapshot_sha256": code_snapshot_sha,
        "execution_config": execution,
        "execution_config_sha256": execution_sha,
        "execution_conformance_path": conformance_relative,
        "execution_conformance_sha256": conformance_file_sha256,
        "portfolio_risk_policy_sha256": configured_risk_sha,
        "recovery_drill_path": recovery_relative,
        "recovery_drill_sha256": _file_sha256(platform / recovery_relative),
        "temporal_bias_audit_path": temporal_relative,
        "temporal_bias_audit_sha256": _file_sha256(platform / temporal_relative),
        "research_governance_policy_path": research_policy["policy_path"],
        "research_governance_policy_sha256": research_policy["policy_sha256"],
        "historical_research_gate": "STRICT_FORWARD_ONLY_NO_INHERITED_ALPHA",
        "independent_adversarial_audit_required_before_paper_completion": True,
        "allowed_symbols": [
            {"code": item["code"], "name": item["name"]} for item in universe
        ],
        "approved_datasets": [
            {
                "dataset_id": "demo-calendar",
                "providers": [PROVIDER_NAME],
                "usages": ["calendar"],
                "semantics_version": "trading-calendar/v1",
            },
            {
                "dataset_id": "demo-signal-input",
                "providers": [PROVIDER_NAME],
                "usages": ["signal"],
                "semantics_version": "point-in-time-etf-qfq-close-proxy/v1",
            },
            {
                "dataset_id": "demo-market-session",
                "providers": [PROVIDER_NAME],
                "usages": ["execution", "valuation"],
                "semantics_version": "market-session/v2",
            },
        ],
    }
    registry = {
        "schema_version": 1,
        "registry_id": "canonical-forward-runner-registry-v1",
        "runner": "quant_core.forward_paper/v1",
        "mode": "PAPER",
        "real_orders": False,
        "registration_status": "HAS_ACTIVE_EXPERIMENTS",
        "registration_note": CLASSIFICATION,
        "experiments": [experiment],
    }
    _write_json(registry_path, registry)
    return {
        "platform": platform,
        "runtime": runtime,
        "catalog_root": catalog_root,
        "registry_path": registry_path,
        "boundary_documents": {
            "registry": registry,
            "global_risk_policy": global_risk,
            "platform_policy": platform_policy,
            "stress_policy": stress_policy,
            "strategy": strategy_config,
            "execution": execution,
            "binding": binding,
            "recovery_evidence": recovery,
            "temporal_evidence": temporal,
            "research_governance_evidence": research_policy,
        },
        "execution_conformance": conformance,
        "execution_conformance_file_sha256": conformance_file_sha256,
    }


class _Api:
    pass


def _product_api() -> _Api:
    backend = ROOT / "apps" / "Vibe-Research" / "backend"
    if str(backend) not in sys.path:
        sys.path.insert(0, str(backend))
    from quant_core import (  # noqa: PLC0415
        BrokerCapability,
        BrokerPermissionError,
        BrokerSafetyEnvelope,
        BrokerSafetyPolicy,
        DataCatalog,
        EXECUTION_CONFORMANCE_SNAPSHOT_PATHS,
        ForwardDailyBatch,
        PersistentLedgerStore,
        PortfolioRiskPolicy,
        QmtCompatPaperAdapter,
        build_execution_conformance_report,
        resolve_research_governance_policy,
        sha256_digest,
    )
    from quant_core.forward_paper import (  # noqa: PLC0415
        REQUIRED_RECOVERY_DRILL_CHECKS,
        REQUIRED_TEMPORAL_AUDIT_CHECKS,
        ForwardConflictError,
        ForwardPaperRunner,
    )
    from quant_core.versioned_trading_calendar import (
        build_versioned_trading_calendar_binding,
    )

    api = _Api()
    api.DataCatalog = DataCatalog
    api.build_versioned_trading_calendar_binding = build_versioned_trading_calendar_binding
    api.BrokerCapability = BrokerCapability
    api.BrokerPermissionError = BrokerPermissionError
    api.BrokerSafetyEnvelope = BrokerSafetyEnvelope
    api.BrokerSafetyPolicy = BrokerSafetyPolicy
    api.EXECUTION_CONFORMANCE_SNAPSHOT_PATHS = EXECUTION_CONFORMANCE_SNAPSHOT_PATHS
    api.ForwardConflictError = ForwardConflictError
    api.ForwardDailyBatch = ForwardDailyBatch
    api.ForwardPaperRunner = ForwardPaperRunner
    api.PersistentLedgerStore = PersistentLedgerStore
    api.PortfolioRiskPolicy = PortfolioRiskPolicy
    api.QmtCompatPaperAdapter = QmtCompatPaperAdapter
    api.REQUIRED_RECOVERY_DRILL_CHECKS = REQUIRED_RECOVERY_DRILL_CHECKS
    api.REQUIRED_TEMPORAL_AUDIT_CHECKS = REQUIRED_TEMPORAL_AUDIT_CHECKS
    api.build_execution_conformance_report = build_execution_conformance_report
    api.resolve_research_governance_policy = resolve_research_governance_policy
    api.sha256_digest = sha256_digest
    return api


def _publish_inputs(fixture: dict[str, Any], catalog: Any) -> dict[str, Any]:
    timeline = fixture["timeline"]
    strategy = fixture["strategy"]
    history = _trading_dates(timeline["signal_date"], 121)
    calendar_dates = [*history, timeline["execute_date"], timeline["valuation_date"]]
    calendar = catalog.publish(
        "demo-calendar",
        {"trading_dates": calendar_dates},
        provider={"name": PROVIDER_NAME},
        available_at="2026-07-30T15:00:00+08:00",
        metadata={"semantics_version": "trading-calendar/v1"},
    )
    signal_input = {
        "schema": "quant-platform/point-in-time-etf-qfq-close-proxy/v1",
        "as_of_date": timeline["signal_date"],
        "max_event_date": timeline["signal_date"],
        "series": {
            code: [
                {
                    "date": day,
                    "qfq_close_proxy": round(100 * (1 + daily_return) ** index, 10),
                }
                for index, day in enumerate(history)
            ]
            for code, daily_return in strategy["daily_returns"].items()
        },
    }
    signal = catalog.publish(
        "demo-signal-input",
        signal_input,
        provider={"name": PROVIDER_NAME},
        available_at="2026-07-31T15:05:00+08:00",
        metadata={
            "semantics_version": "point-in-time-etf-qfq-close-proxy/v1"
        },
    )
    all_codes = [item["code"] for item in strategy["universe"]]

    def market(day: str, codes: list[str], open_price: float, close_price: float) -> dict[str, str]:
        manifest = catalog.publish(
            "demo-market-session",
            _market_payload(
                trade_date=day,
                codes=codes,
                open_price=open_price,
                close_price=close_price,
                volume=float(fixture["market"]["volume"]),
            ),
            provider={"name": PROVIDER_NAME},
            available_at=f"{day}T15:06:00+08:00",
            metadata={"semantics_version": "market-session/v2"},
        )
        return {
            "dataset_id": "demo-market-session",
            "manifest_sha256": manifest["manifest_sha256"],
        }

    return {
        "calendar": {
            "dataset_id": "demo-calendar",
            "manifest_sha256": calendar["manifest_sha256"],
        },
        "signal": {
            "dataset_id": "demo-signal-input",
            "manifest_sha256": signal["manifest_sha256"],
        },
        "signal_market": market(
            timeline["signal_date"],
            all_codes,
            float(fixture["market"]["signal_close"]),
            float(fixture["market"]["signal_close"]),
        ),
        "execution_market": market(
            timeline["execute_date"],
            ["510300", "518880"],
            float(fixture["market"]["execution_open"]),
            float(fixture["market"]["execution_close"]),
        ),
        "valuation_market": market(
            timeline["valuation_date"],
            ["510300", "518880"],
            float(fixture["market"]["execution_close"]),
            float(fixture["market"]["valuation_close"]),
        ),
    }


def _require(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise OfflinePaperDemoError(code, message)


def _demo_boundary_preflight(documents: Mapping[str, Any]) -> None:
    def inspect(value: Any, location: str) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key in _AUTHORITY_FIELDS and child is not False:
                    raise OfflinePaperDemoError(
                        "DEMO_BOUNDARY_VIOLATION",
                        f"demo material enables forbidden field: {location}.{key}",
                    )
                inspect(child, f"{location}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                inspect(child, f"{location}[{index}]")

    for label, document in documents.items():
        inspect(document, label)


def _technical_conformance_preflight(conformance: Mapping[str, Any]) -> None:
    if (
        conformance.get("real_orders") is not False
        or conformance.get("canonical_eligible") is not True
        or conformance.get("promotion_eligible") is not True
    ):
        raise OfflinePaperDemoError(
            "DEMO_BOUNDARY_VIOLATION",
            "execution conformance evidence violates the PAPER boundary",
        )
    scoped = {
        key: value for key, value in conformance.items() if key != "promotion_eligible"
    }
    _demo_boundary_preflight({"execution_conformance": scoped})


def _daily_requests(
    fixture: Mapping[str, Any], refs: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    timeline = fixture["timeline"]
    signal_request = {
        "schema": "quant-platform/forward-daily-batch/v1",
        "trade_date": timeline["signal_date"],
        "recorded_at": timeline["signal_recorded_at"],
        "strategies": [
            {
                "strategy_id": STRATEGY_ID,
                "observation": refs["signal_market"],
                "signal": {
                    "generated_at": timeline["signal_generated_at"],
                    "data_refs": {
                        "calendar": refs["calendar"],
                        "signal": refs["signal"],
                    },
                },
            }
        ],
        "real_orders": False,
    }
    execution_request = {
        "schema": "quant-platform/forward-daily-batch/v1",
        "trade_date": timeline["execute_date"],
        "recorded_at": timeline["execute_recorded_at"],
        "strategies": [
            {"strategy_id": STRATEGY_ID, "execution": refs["execution_market"]}
        ],
        "real_orders": False,
    }
    valuation_request = {
        "schema": "quant-platform/forward-daily-batch/v1",
        "trade_date": timeline["valuation_date"],
        "recorded_at": timeline["valuation_recorded_at"],
        "strategies": [
            {"strategy_id": STRATEGY_ID, "observation": refs["valuation_market"]}
        ],
        "real_orders": False,
    }
    return signal_request, execution_request, valuation_request


def _qmt_compat_shadow(
    api: _Api,
    workspace: Path,
    qmt_fixture: Mapping[str, Any],
    allocation: Mapping[str, Any],
    ledger: Any,
) -> dict[str, Any]:
    with ExitStack() as adapters:
        return _qmt_compat_shadow_managed(
            api, workspace, qmt_fixture, allocation, ledger, adapters
        )


def _qmt_compat_shadow_managed(
    api: _Api,
    workspace: Path,
    qmt_fixture: Mapping[str, Any],
    allocation: Mapping[str, Any],
    ledger: Any,
    adapters: ExitStack,
) -> dict[str, Any]:
    adapter_root = workspace / "qmt-compat-adapter"
    adapter = adapters.enter_context(
        api.QmtCompatPaperAdapter(
            adapter_root,
            initial_cash="100000",
            clock=lambda: str(qmt_fixture["recorded_at"]),
        )
    )
    policy = api.BrokerSafetyPolicy.from_config(
        {
            "schema": "quant-core/broker-safety-policy/v1",
            "policy_id": "offline-qmt-compat-paper-only",
            "real_orders_enabled": False,
            "allowed_read_only_adapters": ["qmt-compat-sandbox"],
            "allowed_live_adapters": [],
            "allowed_live_accounts": [],
            "max_order_notional": 100000,
            "max_daily_notional": 500000,
            "max_daily_order_count": 10,
            "max_live_capital": 500000,
            "authorization_ttl_minutes": 1,
            "require_read_only_shadow": True,
            "require_sandbox_certification": True,
            "require_recovery_drill": True,
            "require_kill_switch_test": True,
            "require_durable_order_journal": True,
            "require_trusted_report_consumer": True,
            "require_account_reservation_book": True,
            "require_trusted_account_snapshot_collector": True,
            "require_prior_session_reconciliation": True,
            "require_trusted_adapter_certification_registry": True,
            "separation_of_duties": {
                "strategy_can_enable_live": False,
                "application_can_discover_credentials": False,
                "manual_approval_required": True,
                "sticky_halt_requires_operator_acknowledgement": True,
            },
        }
    )
    boundary = api.BrokerSafetyEnvelope(adapter, policy)
    boundary.connect_read_only()
    boundary.enable_paper()
    parents = sorted(
        (dict(item) for item in allocation["parent_orders"]),
        key=lambda item: str(item["code"]),
    )
    _require(
        [item["code"] for item in parents] == ["510300", "518880"],
        "QMT_PARENT_SET_MISMATCH",
        "QMT shadow did not receive the frozen parent order set",
    )
    aliases: dict[str, str] = {}
    main_results: list[dict[str, Any]] = []
    submit_at = datetime.fromisoformat(str(qmt_fixture["recorded_at"]))
    for parent in parents:
        result = boundary.submit_order(
            parent,
            operation_key=f"qmt-shadow-parent-{parent['code']}",
            now=submit_at,
        )
        aliases[f"parent_{parent['code']}"] = result["broker_order_id"]
        main_results.append(result)

    cancel_result = boundary.submit_order(
        {
            "code": "510500",
            "side": "buy",
            "quantity": 100,
            "order_type": "market",
            "limit_price": None,
            "reference_price": "10",
        },
        operation_key="qmt-shadow-cancel-scenario",
        now=submit_at,
    )
    reject_result = boundary.submit_order(
        {
            "code": "511010",
            "side": "buy",
            "quantity": 100,
            "order_type": "market",
            "limit_price": None,
            "reference_price": "10",
        },
        operation_key="qmt-shadow-reject-scenario",
        now=submit_at,
    )
    aliases["cancel_scenario"] = cancel_result["broker_order_id"]
    aliases["reject_scenario"] = reject_result["broker_order_id"]
    boundary.cancel_order(cancel_result["broker_order_id"], now=submit_at)

    live_cut_before = adapter.get_atomic_account_snapshot()["cut"]
    try:
        adapter.submit_live_order({"forbidden": True})
    except api.BrokerPermissionError:
        live_submit_rejected = True
    else:
        live_submit_rejected = False
    live_cut_after = adapter.get_atomic_account_snapshot()["cut"]
    _require(
        live_submit_rejected and live_cut_before == live_cut_after,
        "QMT_LIVE_BOUNDARY_WEAKENED",
        "QMT compatibility adapter exposed a writable live path",
    )

    buffered_count = 0
    callback_results: list[dict[str, Any]] = []
    first_callback: tuple[str, dict[str, Any]] | None = None
    for frozen in qmt_fixture["callbacks"]:
        item = dict(frozen)
        callback_type = str(item.pop("type"))
        alias = item.pop("alias", None)
        if alias is not None:
            item["order_id"] = aliases[str(alias)]
        if callback_type == "order":
            method = adapter.on_stock_order
        elif callback_type == "trade":
            method = adapter.on_stock_trade
        elif callback_type == "order_error":
            method = adapter.on_order_error
        elif callback_type == "disconnect":
            method = adapter.on_disconnected
        elif callback_type == "reconnect":
            method = adapter.on_reconnected
        else:
            raise OfflinePaperDemoError(
                "FIXTURE_SCHEMA_INVALID", "QMT callback type is unsupported"
            )
        if first_callback is None:
            first_callback = (callback_type, dict(item))
        outcome = method(item)
        callback_results.append(outcome)
        buffered_count += int(outcome.get("buffered") is True)

    _require(first_callback is not None, "QMT_CALLBACKS_EMPTY", "QMT callback fixture is empty")
    first_type, first_payload = first_callback
    duplicate_method = {
        "order": adapter.on_stock_order,
        "trade": adapter.on_stock_trade,
        "order_error": adapter.on_order_error,
    }[first_type]
    duplicate = duplicate_method(first_payload)
    _require(
        duplicate.get("idempotent") is True,
        "QMT_CALLBACK_REPLAY_FAILED",
        "duplicate QMT callback was not idempotent",
    )

    before_restart = adapter.get_atomic_account_snapshot()
    event_count_before = before_restart["cut"]["sequence"]
    adapter.close()
    restarted = adapters.enter_context(
        api.QmtCompatPaperAdapter(
            adapter_root,
            initial_cash="100000",
            clock=lambda: str(qmt_fixture["recorded_at"]),
        )
    )
    after_restart = restarted.get_atomic_account_snapshot()
    _require(
        before_restart == after_restart
        and after_restart["cut"]["sequence"] == event_count_before,
        "QMT_RESTART_RECOVERY_FAILED",
        "QMT compatibility state changed during restart recovery",
    )
    _require(
        restarted.status()["mode"] == "READY"
        and after_restart["degraded"] is False,
        "QMT_ADAPTER_DEGRADED",
        "QMT compatibility adapter remained degraded after callbacks",
    )

    orders = {
        item["broker_order_id"]: item for item in restarted.list_orders()
    }
    main_orders = [orders[result["broker_order_id"]] for result in main_results]
    shadow_positions = {
        item["code"]: int(item["quantity"])
        for item in restarted.get_positions()
        if item["code"] in {"510300", "518880"}
    }
    ledger_positions = {
        code: int(quantity)
        for code, quantity in ledger.position_quantities.items()
        if code in {"510300", "518880"}
    }
    _require(
        all(item["status"] == "FILLED" for item in main_orders)
        and shadow_positions == ledger_positions == {"510300": 3500, "518880": 3500},
        "QMT_SHADOW_RECONCILIATION_FAILED",
        "QMT shadow fills do not reconcile with the primary PAPER ledger",
    )
    _require(
        orders[cancel_result["broker_order_id"]]["status"] == "CANCELLED"
        and orders[reject_result["broker_order_id"]]["status"] == "REJECTED",
        "QMT_NEGATIVE_SCENARIOS_FAILED",
        "QMT cancel or definite reject scenario did not reach its terminal state",
    )
    capabilities = adapter.capabilities()
    _require(
        api.BrokerCapability.LIVE_ORDER.value not in capabilities
        and api.BrokerCapability.MARKET_DATA_READ.value not in capabilities,
        "QMT_CAPABILITY_LEAK",
        "QMT compatibility adapter exposed a forbidden capability",
    )
    usage = restarted.get_daily_order_usage("2026-08-03")
    result = {
        "adapter_id": adapter.adapter_id,
        "sandbox_adapter_exercised": True,
        "execution_binding": "SHADOW_RECONCILED_NOT_PRIMARY_EXECUTION",
        "main_parent_count": len(main_results),
        "main_filled_order_count": sum(item["status"] == "FILLED" for item in main_orders),
        "main_fill_quantity_by_code": shadow_positions,
        "ledger_reconciled": True,
        "cancel_scenario": "CANCELLED",
        "reject_scenario": "REJECTED",
        "callback_count": len(callback_results),
        "out_of_order_buffer_count": buffered_count,
        "duplicate_callback_idempotent": True,
        "disconnect_reconnect_exercised": True,
        "restart_recovered_without_resubmit": True,
        "daily_usage": usage,
        "atomic_snapshot": {
            "callback_cut": after_restart["callback_cut"],
            "connection_epoch": after_restart["connection_epoch"],
            "connected": after_restart["connected"],
            "degraded": after_restart["degraded"],
            "event_cut": after_restart["cut"],
        },
        "live_submit_rejected_without_write": True,
        "real_orders": False,
    }
    restarted.close()
    return result


def _execute(
    workspace: Path,
    fixture: dict[str, Any],
    *,
    broker_mode: str = "NONE",
    qmt_fixture: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    api = _product_api()
    paths = _materialize_platform(workspace, fixture, api)
    catalog = api.DataCatalog(paths["catalog_root"])
    refs = _publish_inputs(fixture, catalog)
    signal_request, execution_request, valuation_request = _daily_requests(
        fixture, refs
    )
    _technical_conformance_preflight(paths["execution_conformance"])
    _demo_boundary_preflight(
        {
            "fixture": fixture,
            **paths["boundary_documents"],
            "signal_request": signal_request,
            "execution_request": execution_request,
            "valuation_request": valuation_request,
        }
    )
    runner = api.ForwardPaperRunner(
        platform_root=paths["platform"],
        runtime_root=paths["runtime"],
        catalog_root=paths["catalog_root"],
        registry_path=paths["registry_path"],
    )
    timeline = fixture["timeline"]
    activation = runner.initialize(STRATEGY_ID, recorded_at=timeline["initialized_at"])
    activation_replay = runner.initialize(
        STRATEGY_ID, recorded_at=timeline["initialized_at"]
    )
    batch = api.ForwardDailyBatch(runner)
    signal_batch = batch.run(signal_request)
    signal_replay = batch.run(signal_request)
    execution_batch = batch.run(execution_request)
    execution_replay = batch.run(execution_request)
    valuation_batch = batch.run(valuation_request)
    valuation_replay = batch.run(valuation_request)
    conflicting_valuation_request = {
        **valuation_request,
        "recorded_at": (
            datetime.fromisoformat(timeline["valuation_recorded_at"])
            + timedelta(seconds=1)
        ).isoformat(),
    }
    try:
        batch.run(conflicting_valuation_request)
    except api.ForwardConflictError:
        replay_conflict_rejected = True
    else:
        replay_conflict_rejected = False

    signal_sha = signal_batch["results"][0]["signal"]["signal_sha256"]
    signal_record_path = (
        paths["runtime"]
        / STRATEGY_ID
        / "signals"
        / "records"
        / f"{signal_sha}.json"
    )
    signal_record = json.loads(signal_record_path.read_text(encoding="utf-8"))
    store = api.PersistentLedgerStore(paths["runtime"] / STRATEGY_ID / "ledger")
    ledger, recovery = store.recover()
    report = ledger.report()
    report_summary = dict(report.get("summary") or {})
    marks = {
        code: float(fixture["market"]["valuation_close"])
        for code in ledger.position_quantities
    }
    equity = float(ledger.equity(marks))
    pnl = equity - float(fixture["strategy"]["initial_cash"])
    allocation = execution_batch["parent_order_allocation_plan"]
    pretrade = execution_batch["pretrade_execution_batch"]
    risk = dict(report.get("portfolio_risk") or {})
    latest_risk = dict(risk.get("latest_assessment") or {})
    latest_reconciliation = dict(report.get("latest_reconciliation") or {})
    health = store.health()

    _require(
        signal_record["decision_evidence"]["engine_id"] == ENGINE_ID,
        "SIGNAL_ENGINE_MISMATCH",
        "real signal factory engine was not used",
    )
    _require(
        signal_record["target_codes"] == ["510300", "518880"],
        "SIGNAL_TARGET_MISMATCH",
        "real engine did not select the frozen two-risk-group basket",
    )
    _require(
        signal_record["target_weights"] == {"510300": 0.35, "518880": 0.35},
        "SIGNAL_WEIGHT_MISMATCH",
        "real engine target weights changed",
    )
    _require(
        all(
            item["idempotent"] is False
            for item in (signal_batch, execution_batch, valuation_batch)
        ),
        "FIRST_RUN_NOT_NEW",
        "first daily requests were not new",
    )
    _require(
        all(
            item["idempotent"] is True
            for item in (signal_replay, execution_replay, valuation_replay)
        ),
        "REPLAY_NOT_IDEMPOTENT",
        "same-request replay was not idempotent",
    )
    _require(
        replay_conflict_rejected,
        "REPLAY_CONFLICT_ACCEPTED",
        "changed same-date replay was not rejected",
    )
    _require(
        activation["idempotent"] is False
        and activation_replay["idempotent"] is True,
        "ACTIVATION_NOT_IDEMPOTENT",
        "activation replay was not idempotent",
    )
    _require(
        len(allocation["child_intents"]) == 2
        and len(allocation["parent_orders"]) == 2,
        "ORDER_ALLOCATION_MISMATCH",
        "parent-child allocation did not produce two orders",
    )
    _require(
        len(pretrade["child_receipts"]) == 1
        and pretrade["status"] == "PREPARED",
        "PRETRADE_MISMATCH",
        "pretrade batch was not prepared",
    )
    _require(
        int(report_summary["fill_count"]) == 2,
        "FILL_COUNT_MISMATCH",
        "simulation ledger did not record two fills",
    )
    _require(
        int(health["checkpoint_count"]) == 4,
        "CHECKPOINT_COUNT_MISMATCH",
        "persistent ledger checkpoint count changed",
    )
    _require(
        latest_reconciliation.get("ok") is True,
        "RECONCILIATION_FAILED",
        "ledger reconciliation failed",
    )
    _require(
        latest_risk.get("compliant") is True and risk.get("mode") == "NORMAL",
        "RISK_NOT_PASS",
        "portfolio risk did not remain compliant",
    )
    _require(
        pnl != 0,
        "PNL_NOT_NONZERO",
        "D+2 marks did not create non-zero mark-to-market PnL",
    )
    _require(
        recovery.get("read_only") is False and recovery.get("degraded") is False,
        "LEDGER_RECOVERY_FAILED",
        "public ledger recovery was not clean",
    )

    qmt_shadow: dict[str, Any] | None = None
    if broker_mode == "QMT_COMPAT_SANDBOX":
        _require(
            qmt_fixture is not None,
            "QMT_FIXTURE_MISSING",
            "QMT compatibility fixture was not loaded",
        )
        qmt_shadow = _qmt_compat_shadow(
            api, workspace, qmt_fixture, allocation, ledger
        )
    elif broker_mode != "NONE":
        raise OfflinePaperDemoError(
            "ARGUMENT_ERROR", "offline demo broker option is unsupported"
        )

    result = {
        "schema": RESULT_SCHEMA,
        "ok": True,
        "classification": CLASSIFICATION,
        "authoritative_for_execution": False,
        "demo_authority": False,
        "formal_admission_eligible": False,
        "formal_forward_evidence": False,
        "promotion_eligible": False,
        "real_orders": False,
        "broker": broker_mode,
        "broker_accessed": False,
        "network": "POISONED",
        "network_accessed": False,
        "network_isolation_scope": "FRESH_CLI_NEW_CONNECTIONS_AND_SUBPROCESSES",
        "preexisting_socket_handles_covered": False,
        "execution_conformance": {
            "adapter_reproduction_all_passed": paths["execution_conformance"][
                "promotion_eligible"
            ]
            is True,
            "authority_mapping": False,
        },
        "strategy": {
            "strategy_id": STRATEGY_ID,
            "engine_id": ENGINE_ID,
            "engine_reuse_only": True,
            "source_candidate_status": "FALSIFIED_REDESIGN_REQUIRED",
        },
        "timeline": {
            "signal_date": timeline["signal_date"],
            "execute_date": timeline["execute_date"],
            "valuation_date": timeline["valuation_date"],
        },
        "signal": {
            "signal_sha256": signal_sha,
            "target_codes": signal_record["target_codes"],
            "target_weights": signal_record["target_weights"],
            "eligible_risk_group_count": signal_record["decision_evidence"][
                "eligible_risk_group_count"
            ],
        },
        "execution": {
            "platform_preflight": execution_batch["platform_portfolio_preflight"][
                "effective_decision"
            ],
            "pretrade_status": pretrade["status"],
            "child_receipt_count": len(pretrade["child_receipts"]),
            "child_intent_count": len(allocation["child_intents"]),
            "parent_order_count": len(allocation["parent_orders"]),
            "fill_count": int(report_summary["fill_count"]),
        },
        "ledger": {
            "checkpoint_count": int(health["checkpoint_count"]),
            "positions": {
                code: int(quantity)
                for code, quantity in sorted(ledger.position_quantities.items())
            },
            "cash": float(ledger.cash),
            "equity": equity,
            "mark_to_market_pnl": pnl,
            "reconciliation_ok": True,
            "recovery_read_only": False,
        },
        "risk": {"decision": "PASS", "mode": "NORMAL", "compliant": True},
        "idempotency": {
            "activation": True,
            "signal_batch": True,
            "execution_batch": True,
            "valuation_batch": True,
            "conflict_rejected": True,
        },
        "evidence": {
            "execution_conformance_file_sha256": paths[
                "execution_conformance_file_sha256"
            ],
            "execution_conformance_report_sha256": paths["execution_conformance"][
                "report_sha256"
            ],
            "fixture_sha256": fixture["fixture_sha256"],
            "signal_batch_receipt_sha256": signal_batch["receipt_sha256"],
            "execution_batch_receipt_sha256": execution_batch["receipt_sha256"],
            "valuation_batch_receipt_sha256": valuation_batch["receipt_sha256"],
            "ledger_checkpoint_sha256": recovery["selected_checkpoint_sha256"],
        },
    }
    if qmt_shadow is not None:
        assert qmt_fixture is not None
        result.update(
            {
                "sandbox_adapter_exercised": True,
                "execution_binding": "SHADOW_RECONCILED_NOT_PRIMARY_EXECUTION",
                "real_broker_accessed": False,
                "qmt_runtime_accessed": False,
                "xtquant_imported": False,
                "live_order_capability_exposed": False,
                "qmt_vendor_certified": False,
                "certification_status": "NOT_RUN_REAL_QMT",
                "platform_durability_certified": False,
                "durability_certification_status": "NOT_POWER_LOSS_CERTIFIED",
                "qmt_compat": qmt_shadow,
            }
        )
        result["evidence"].update(
            {
                "qmt_fixture_sha256": qmt_fixture["fixture_sha256"],
                "qmt_fixture_raw_sha256": QMT_FIXTURE_RAW_SHA256,
                "qmt_event_head_sha256": qmt_shadow["atomic_snapshot"][
                    "event_cut"
                ]["event_sha256"],
            }
        )
    return result


def _run_demo() -> dict[str, Any]:
    """Run the private implementation used only by the fresh-process CLI."""

    return _run_demo_mode("NONE")


def _run_qmt_compat_demo() -> dict[str, Any]:
    """Run the explicit offline QMT compatibility PAPER path."""

    return _run_demo_mode("QMT_COMPAT_SANDBOX")


def _run_demo_mode(broker_mode: str) -> dict[str, Any]:
    if broker_mode not in {"NONE", "QMT_COMPAT_SANDBOX"}:
        raise OfflinePaperDemoError(
            "ARGUMENT_ERROR", "offline demo broker option is unsupported"
        )

    fixture = _load_fixture()
    qmt_fixture = (
        _load_qmt_fixture() if broker_mode == "QMT_COMPAT_SANDBOX" else None
    )
    source_before = _source_state(ROOT)
    temp_root, workspace = _workspace_candidate()
    result: dict[str, Any] | None = None
    primary_error: BaseException | None = None
    cleanup_error: BaseException | None = None
    source_error: BaseException | None = None
    source_after: str | None = None
    try:
        _validate_workspace_identity(temp_root, workspace, must_exist=False)
        workspace.mkdir(mode=0o700, parents=False, exist_ok=False)
        _assert_plain_directory_tree(temp_root)
        _validate_workspace_identity(temp_root, workspace, must_exist=True)
        with network_poison_guard():
            if broker_mode == "QMT_COMPAT_SANDBOX":
                with qmt_runtime_poison_guard():
                    result = _execute(
                        workspace,
                        fixture,
                        broker_mode=broker_mode,
                        qmt_fixture=qmt_fixture,
                    )
            else:
                result = _execute(workspace, fixture)
    except BaseException as exc:
        primary_error = exc
    finally:
        try:
            _cleanup_workspace(temp_root, workspace)
            if os.path.lexists(workspace):
                raise OfflinePaperDemoError(
                    "CLEANUP_FAILED", "demo workspace remains after cleanup"
                )
        except BaseException as exc:
            cleanup_error = exc
        try:
            source_after = _source_state(ROOT)
        except BaseException as exc:
            source_error = exc

    if source_error is not None or source_after != source_before:
        mutation = OfflinePaperDemoError(
            "CANONICAL_SOURCE_MUTATED",
            "canonical registry or protected quant-lab state changed",
        )
        if cleanup_error is not None:
            mutation.add_note("workspace cleanup also failed")
        mutation.cleanup_failed = cleanup_error is not None
        mutation.workspace_cleaned = cleanup_error is None
        raise mutation from (primary_error or source_error or cleanup_error)
    if primary_error is not None:
        if cleanup_error is not None:
            primary_error.add_note("workspace cleanup also failed")
        primary_error.cleanup_failed = cleanup_error is not None
        primary_error.workspace_cleaned = cleanup_error is None
        raise primary_error
    if cleanup_error is not None:
        if isinstance(cleanup_error, OfflinePaperDemoError):
            cleanup_error.cleanup_failed = True
            cleanup_error.workspace_cleaned = False
            raise cleanup_error
        cleanup_failure = OfflinePaperDemoError(
            "CLEANUP_FAILED", "demo workspace cleanup failed"
        )
        cleanup_failure.cleanup_failed = True
        cleanup_failure.workspace_cleaned = False
        raise cleanup_failure from cleanup_error
    if result is None or os.path.lexists(workspace):
        lifecycle_failure = OfflinePaperDemoError(
            "CLEANUP_FAILED", "demo workspace lifecycle did not finish cleanly"
        )
        lifecycle_failure.cleanup_failed = True
        lifecycle_failure.workspace_cleaned = False
        raise lifecycle_failure
    result["cleanup_failed"] = False
    result["workspace_cleaned"] = True
    result["evidence"]["canonical_source_unchanged"] = True
    result["evidence"]["workspace_cleaned"] = True
    return result


def failure_document(
    exc: BaseException, *, broker: str | None = None
) -> dict[str, Any]:
    if isinstance(exc, OfflinePaperDemoError):
        code = exc.code
        message = str(exc)
    else:
        code = "UNEXPECTED_FAILURE"
        message = type(exc).__name__
    cleanup_failed = getattr(exc, "cleanup_failed", False) is True
    workspace_cleaned = getattr(exc, "workspace_cleaned", True) is True
    result = {
        "schema": RESULT_SCHEMA,
        "ok": False,
        "classification": CLASSIFICATION,
        "authoritative_for_execution": False,
        "demo_authority": False,
        "formal_admission_eligible": False,
        "formal_forward_evidence": False,
        "promotion_eligible": False,
        "real_orders": False,
        "broker_accessed": False,
        "cleanup_failed": cleanup_failed,
        "network_accessed": False,
        "network_isolation_scope": "FRESH_CLI_NEW_CONNECTIONS_AND_SUBPROCESSES",
        "preexisting_socket_handles_covered": False,
        "workspace_cleaned": workspace_cleaned,
        "error": {"code": code, "message": message},
    }
    if broker == "QMT_COMPAT_SANDBOX":
        xtquant_imported = getattr(exc, "xtquant_imported", False) is True or any(
            name == "xtquant" or name.startswith("xtquant.")
            for name in tuple(sys.modules)
        )
        result.update(
            {
                "broker": "QMT_COMPAT_SANDBOX",
                "sandbox_adapter_exercised": False,
                "execution_binding": "SHADOW_RECONCILED_NOT_PRIMARY_EXECUTION",
                "real_broker_accessed": False,
                "qmt_runtime_accessed": xtquant_imported,
                "xtquant_imported": xtquant_imported,
                "live_order_capability_exposed": False,
                "qmt_vendor_certified": False,
                "certification_status": "NOT_RUN_REAL_QMT",
                "platform_durability_certified": False,
                "durability_certification_status": "NOT_POWER_LOSS_CERTIFIED",
            }
        )
    return result
