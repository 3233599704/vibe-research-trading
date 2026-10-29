"""Strict raw JSON boundary for Strategy Lab v3 admission.

The ordinary :mod:`json` mapping API has already discarded duplicate object
keys.  V3 admission therefore starts from UTF-8 bytes or text and marks every
object produced by this decoder so an arbitrary ``dict`` cannot masquerade as
raw evidence.
"""

from __future__ import annotations

import json
from json import JSONDecodeError
import math
from typing import Any
import unicodedata


MAX_JSON_DEPTH = 128
MAX_JSON_INTEGER_DIGITS = 1024


class StrictJSONError(ValueError):
    """Deterministic raw-JSON rejection with a machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class StrictJSONObject(dict[str, Any]):
    """Marker proving an object came from :func:`strict_json_loads`."""


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> StrictJSONObject:
    value: StrictJSONObject = StrictJSONObject()
    normalized_keys: dict[str, str] = {}
    for key, item in pairs:
        if key in value:
            raise StrictJSONError(
                "DUPLICATE_JSON_KEY",
                f"duplicate JSON object key: {key!r}",
            )
        normalized = unicodedata.normalize("NFC", key)
        prior = normalized_keys.get(normalized)
        if prior is not None:
            raise StrictJSONError(
                "NFC_KEY_COLLISION",
                "JSON keys collide after NFC normalization: "
                f"{prior!r}, {key!r}",
            )
        normalized_keys[normalized] = key
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise StrictJSONError(
        "NONFINITE_NUMBER",
        f"non-finite JSON number is forbidden: {value}",
    )


def _finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise StrictJSONError(
            "NONFINITE_NUMBER",
            f"JSON number overflows finite range: {value}",
        )
    return parsed


def _bounded_int(value: str) -> int:
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise StrictJSONError(
            "INTEGER_TOO_LONG",
            "JSON integer exceeds the fixed decimal digit limit "
            f"{MAX_JSON_INTEGER_DIGITS}",
        )
    try:
        return int(value)
    except (OverflowError, ValueError) as exc:
        raise StrictJSONError(
            "INVALID_INTEGER",
            "JSON integer could not be represented deterministically",
        ) from exc


def _enforce_unicode_scalars(value: Any) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise StrictJSONError(
                "INVALID_UNICODE_SCALAR",
                "JSON strings cannot contain unpaired UTF-16 surrogates",
            ) from exc
        if unicodedata.normalize("NFC", value) != value:
            raise StrictJSONError(
                "NON_NFC_STRING",
                "all JSON keys and string values must already be NFC",
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


def _enforce_json_depth(text: str) -> None:
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
                raise StrictJSONError(
                    "JSON_TOO_DEEP",
                    "JSON structural depth exceeds fixed limit "
                    f"{MAX_JSON_DEPTH}",
                )
        elif character in "]}":
            depth -= 1


def strict_json_loads(raw: str | bytes | bytearray) -> Any:
    """Parse finite JSON while rejecting ambiguous raw representations."""

    if isinstance(raw, (bytes, bytearray)):
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise StrictJSONError("INVALID_UTF8", str(exc)) from exc
    elif isinstance(raw, str):
        text = raw
    else:
        raise TypeError("strict JSON input must be str or UTF-8 bytes")
    _enforce_json_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_strict_object_pairs,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
            parse_int=_bounded_int,
        )
    except JSONDecodeError as exc:
        raise StrictJSONError("INVALID_JSON", str(exc)) from exc
    except RecursionError as exc:
        raise StrictJSONError(
            "JSON_TOO_DEEP",
            "JSON decoder recursion exceeded fixed limit "
            f"{MAX_JSON_DEPTH}",
        ) from exc
    _enforce_unicode_scalars(value)
    return value


def strict_json_object(raw: str | bytes | bytearray) -> StrictJSONObject:
    """Return a strictly decoded top-level JSON object."""

    value = strict_json_loads(raw)
    if not isinstance(value, StrictJSONObject):
        raise StrictJSONError(
            "JSON_OBJECT_REQUIRED",
            "top-level JSON object required",
        )
    return value
