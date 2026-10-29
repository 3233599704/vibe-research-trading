"""Strict raw-JSON boundary for machine-admitted platform contracts.

This is intentionally implemented inside Vibe instead of importing the root
Strategy Lab runtime.  Provider and research contracts share the same frozen
profile: UTF-8, NFC strings, unique keys (including after NFC normalization),
finite numbers, at most 128 structural levels and at most 1024 integer digits.
"""

from __future__ import annotations

import json
from json import JSONDecodeError
import math
from pathlib import Path
from typing import Any
import unicodedata


MAX_JSON_DEPTH = 128
MAX_JSON_INTEGER_DIGITS = 1024


class StrictContractJSONError(ValueError):
    """Raw representation rejection with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class StrictJSONObject(dict[str, Any]):
    """Marker proving that an object came from the strict decoder."""


def _object_pairs(pairs: list[tuple[str, Any]]) -> StrictJSONObject:
    value: StrictJSONObject = StrictJSONObject()
    normalized_keys: dict[str, str] = {}
    for key, item in pairs:
        if key in value:
            raise StrictContractJSONError(
                "DUPLICATE_JSON_KEY", f"duplicate key in JSON object: {key!r}"
            )
        normalized = unicodedata.normalize("NFC", key)
        prior = normalized_keys.get(normalized)
        if prior is not None:
            raise StrictContractJSONError(
                "NFC_KEY_COLLISION",
                f"JSON keys collide after NFC normalization: {prior!r}, {key!r}",
            )
        normalized_keys[normalized] = key
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise StrictContractJSONError(
        "NONFINITE_NUMBER", f"non-finite number is forbidden in JSON: {value}"
    )


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise StrictContractJSONError(
            "NONFINITE_NUMBER", f"JSON number overflows finite range: {value}"
        )
    return parsed


def _bounded_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise StrictContractJSONError(
            "INTEGER_TOO_LONG",
            f"JSON integer exceeds {MAX_JSON_INTEGER_DIGITS} decimal digits",
        )
    try:
        return int(value)
    except (OverflowError, ValueError) as exc:
        raise StrictContractJSONError(
            "INVALID_INTEGER", "JSON integer is not deterministic"
        ) from exc


def _enforce_unicode_scalars(value: Any) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise StrictContractJSONError(
                "INVALID_UNICODE_SCALAR",
                "JSON strings cannot contain unpaired UTF-16 surrogates",
            ) from exc
        if unicodedata.normalize("NFC", value) != value:
            raise StrictContractJSONError(
                "NON_NFC_STRING", "all JSON keys and string values must be NFC"
            )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _enforce_unicode_scalars(key)
            _enforce_unicode_scalars(item)
        return
    if isinstance(value, list):
        for item in value:
            _enforce_unicode_scalars(item)


def _enforce_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise StrictContractJSONError(
                    "JSON_TOO_DEEP",
                    f"JSON structural depth exceeds {MAX_JSON_DEPTH}",
                )
        elif character in "]}":
            depth -= 1


def strict_json_loads(raw: str | bytes | bytearray) -> Any:
    if isinstance(raw, (bytes, bytearray)):
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StrictContractJSONError("INVALID_UTF8", str(exc)) from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise TypeError("strict JSON input must be str or UTF-8 bytes")
    _enforce_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            parse_int=_bounded_int,
        )
    except JSONDecodeError as exc:
        raise StrictContractJSONError("INVALID_JSON", str(exc)) from exc
    except RecursionError as exc:
        raise StrictContractJSONError("JSON_TOO_DEEP", str(exc)) from exc
    _enforce_unicode_scalars(value)
    return value


def strict_json_object(raw: str | bytes | bytearray) -> StrictJSONObject:
    value = strict_json_loads(raw)
    if not isinstance(value, StrictJSONObject):
        raise StrictContractJSONError(
            "JSON_OBJECT_REQUIRED", "top-level JSON object required"
        )
    return value


def strict_json_file(path: str | Path) -> Any:
    """Read one file through the shared strict raw-JSON boundary."""

    return strict_json_loads(Path(path).read_bytes())


def strict_json_file_object(path: str | Path) -> StrictJSONObject:
    """Read a top-level object through the shared strict raw-JSON boundary."""

    return strict_json_object(Path(path).read_bytes())
