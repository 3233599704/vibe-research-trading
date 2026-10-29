"""Immutable, credential-free HTTP evidence used by provider normalizers.

The capture is a canonical JSON container.  Each exchange embeds the exact HTTP
entity body as base64 plus its byte length and SHA-256.  Capture clients must ask
for identity encoding so the archived bytes are not an implicitly decompressed
representation of a different wire body.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit


PROVIDER_WIRE_CAPTURE_SCHEMA = "quant-platform/provider-wire-capture/v1"
PROVIDER_WIRE_CAPTURE_MEDIA_TYPE = (
    "application/vnd.quant-platform.provider-wire-capture+json"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
HEADER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
MAX_EXCHANGES = 64
MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BODY_BYTES = 64 * 1024 * 1024

_CAPTURE_FIELDS = {"schema", "capture_id", "completed_at", "exchanges"}
_EXCHANGE_FIELDS = {"exchange_id", "request", "response", "received_at"}
_REQUEST_FIELDS = {"method", "url", "query", "headers"}
_QUERY_FIELDS = {"name", "value"}
_RESPONSE_FIELDS = {
    "status_code",
    "headers",
    "body_byte_size",
    "body_sha256",
    "body_base64",
}
_ALLOWED_REQUEST_HEADERS = {
    "accept",
    "accept-encoding",
    "referer",
    "user-agent",
}
_ALLOWED_RESPONSE_HEADERS = {
    "cache-control",
    "content-encoding",
    "content-type",
    "date",
    "etag",
    "expires",
    "last-modified",
}
_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}
_SENSITIVE_QUERY_NAMES = {
    "access_token",
    "api-key",
    "api_key",
    "apikey",
    "authorization",
    "key",
    "password",
    "secret",
    "token",
}


class ProviderWireCaptureError(RuntimeError):
    """A wire capture is incomplete, mutable, unsafe, or internally inconsistent."""


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ProviderWireCaptureError(
                f"provider wire capture contains a duplicate object key: {key}"
            )
        output[key] = value
    return output


def _validate_json_value(value: Any, path: str = "$") -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ProviderWireCaptureError(
            f"provider wire capture contains a non-finite number at {path}"
        )
    if isinstance(value, str) and any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ProviderWireCaptureError(
            f"provider wire capture contains an unpaired Unicode surrogate at {path}"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_json_value(key, f"{path}.<key>")
            _validate_json_value(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise ProviderWireCaptureError(
            f"{label} fields are invalid; missing={missing}, extra={extra}"
        )


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProviderWireCaptureError(f"{label} must be a non-empty string")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    raw = _text(value, label)
    try:
        moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProviderWireCaptureError(f"{label} is not an ISO-8601 timestamp") from exc
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ProviderWireCaptureError(f"{label} must include a timezone")
    return moment


def _headers(value: Any, *, response: bool) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ProviderWireCaptureError("wire capture headers must be an object")
    allowed = _ALLOWED_RESPONSE_HEADERS if response else _ALLOWED_REQUEST_HEADERS
    output: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = _text(raw_name, "header name")
        if name != name.lower() or not HEADER_RE.fullmatch(name):
            raise ProviderWireCaptureError("wire capture header names must be lowercase")
        if name in _SENSITIVE_HEADERS:
            raise ProviderWireCaptureError(f"sensitive HTTP header cannot be archived: {name}")
        if name not in allowed:
            raise ProviderWireCaptureError(f"HTTP header is outside the capture allowlist: {name}")
        header_value = _text(raw_value, f"header {name}")
        if "\r" in header_value or "\n" in header_value:
            raise ProviderWireCaptureError("HTTP header values cannot contain newlines")
        output[name] = header_value
    if not response and output.get("accept-encoding") != "identity":
        raise ProviderWireCaptureError(
            "wire capture requests must set accept-encoding to identity"
        )
    content_encoding = output.get("content-encoding") if response else None
    if content_encoding is not None and content_encoding.lower() != "identity":
        raise ProviderWireCaptureError(
            "compressed response bodies are not accepted as raw identity bytes"
        )
    return output


def _query(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        raise ProviderWireCaptureError("wire capture query must be an array")
    output: list[dict[str, str]] = []
    names: set[str] = set()
    for raw_item in value:
        if not isinstance(raw_item, dict):
            raise ProviderWireCaptureError("wire capture query entries must be objects")
        _exact_fields(raw_item, _QUERY_FIELDS, "wire capture query entry")
        name = _text(raw_item.get("name"), "query name")
        query_value = _text(raw_item.get("value"), f"query parameter {name}")
        if name in names:
            raise ProviderWireCaptureError(f"duplicate query parameter: {name}")
        if name.lower() in _SENSITIVE_QUERY_NAMES:
            raise ProviderWireCaptureError(
                f"sensitive query parameter cannot be archived: {name}"
            )
        names.add(name)
        output.append({"name": name, "value": query_value})
    return output


def load_provider_wire_capture(raw_bytes: bytes) -> dict[str, Any]:
    """Parse and validate an immutable capture, returning decoded entity bodies."""

    if len(raw_bytes) > MAX_TOTAL_BODY_BYTES * 2:
        raise ProviderWireCaptureError("provider wire capture container is too large")
    try:
        capture = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_strict_object_pairs,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ProviderWireCaptureError(
                    f"provider wire capture contains a non-finite number: {constant}"
                )
            ),
        )
    except UnicodeDecodeError as exc:
        raise ProviderWireCaptureError("provider wire capture is not strict UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ProviderWireCaptureError(f"provider wire capture is invalid JSON: {exc}") from exc
    if not isinstance(capture, dict):
        raise ProviderWireCaptureError("provider wire capture must decode to an object")
    _validate_json_value(capture)
    _exact_fields(capture, _CAPTURE_FIELDS, "provider wire capture")
    if capture.get("schema") != PROVIDER_WIRE_CAPTURE_SCHEMA:
        raise ProviderWireCaptureError("unsupported provider wire capture schema")
    capture_id = _text(capture.get("capture_id"), "capture_id")
    if not ID_RE.fullmatch(capture_id):
        raise ProviderWireCaptureError("capture_id is invalid")
    completed_at_raw = _text(capture.get("completed_at"), "completed_at")
    completed_at = _timestamp(completed_at_raw, "completed_at")
    raw_exchanges = capture.get("exchanges")
    if not isinstance(raw_exchanges, list) or not 1 <= len(raw_exchanges) <= MAX_EXCHANGES:
        raise ProviderWireCaptureError("wire capture must contain 1 to 64 exchanges")

    exchanges: list[dict[str, Any]] = []
    exchange_ids: set[str] = set()
    total_bytes = 0
    for raw_exchange in raw_exchanges:
        if not isinstance(raw_exchange, dict):
            raise ProviderWireCaptureError("wire capture exchanges must be objects")
        _exact_fields(raw_exchange, _EXCHANGE_FIELDS, "wire capture exchange")
        exchange_id = _text(raw_exchange.get("exchange_id"), "exchange_id")
        if not ID_RE.fullmatch(exchange_id) or exchange_id in exchange_ids:
            raise ProviderWireCaptureError("wire capture exchange_id is invalid or duplicated")
        exchange_ids.add(exchange_id)

        raw_request = raw_exchange.get("request")
        if not isinstance(raw_request, dict):
            raise ProviderWireCaptureError("wire capture request must be an object")
        _exact_fields(raw_request, _REQUEST_FIELDS, "wire capture request")
        if raw_request.get("method") != "GET":
            raise ProviderWireCaptureError("only GET provider wire captures are supported")
        url = _text(raw_request.get("url"), "request URL")
        parsed_url = urlsplit(url)
        try:
            parsed_port = parsed_url.port
        except ValueError as exc:
            raise ProviderWireCaptureError("request URL port is invalid") from exc
        if (
            parsed_url.scheme != "https"
            or not parsed_url.hostname
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_port not in (None, 443)
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ProviderWireCaptureError(
                "request URL must be credential-free HTTPS without query or fragment"
            )
        query = _query(raw_request.get("query"))
        request_headers = _headers(raw_request.get("headers"), response=False)

        raw_response = raw_exchange.get("response")
        if not isinstance(raw_response, dict):
            raise ProviderWireCaptureError("wire capture response must be an object")
        _exact_fields(raw_response, _RESPONSE_FIELDS, "wire capture response")
        status_code = raw_response.get("status_code")
        if isinstance(status_code, bool) or status_code != 200:
            raise ProviderWireCaptureError("provider wire capture response must be HTTP 200")
        response_headers = _headers(raw_response.get("headers"), response=True)
        byte_size = raw_response.get("body_byte_size")
        if (
            isinstance(byte_size, bool)
            or not isinstance(byte_size, int)
            or not 0 <= byte_size <= MAX_BODY_BYTES
        ):
            raise ProviderWireCaptureError("response body_byte_size is invalid")
        expected_sha = _text(raw_response.get("body_sha256"), "response body_sha256")
        if not SHA256_RE.fullmatch(expected_sha):
            raise ProviderWireCaptureError("response body_sha256 is invalid")
        encoded = _text(raw_response.get("body_base64"), "response body_base64")
        try:
            body = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ProviderWireCaptureError("response body_base64 is invalid") from exc
        if len(body) != byte_size:
            raise ProviderWireCaptureError("response body length does not match capture")
        if hashlib.sha256(body).hexdigest() != expected_sha:
            raise ProviderWireCaptureError("response body digest does not match capture")
        total_bytes += len(body)
        if total_bytes > MAX_TOTAL_BODY_BYTES:
            raise ProviderWireCaptureError("wire capture response bodies exceed total size limit")

        received_at_raw = _text(raw_exchange.get("received_at"), "received_at")
        received_at = _timestamp(received_at_raw, "received_at")
        if received_at > completed_at:
            raise ProviderWireCaptureError("exchange received_at is after completed_at")
        exchanges.append(
            {
                "exchange_id": exchange_id,
                "request": {
                    "method": "GET",
                    "url": url,
                    "query": query,
                    "headers": request_headers,
                },
                "response": {
                    "status_code": 200,
                    "headers": response_headers,
                    "body_byte_size": byte_size,
                    "body_sha256": expected_sha,
                    "body_bytes": body,
                },
                "received_at": received_at_raw,
            }
        )
    return {
        "schema": PROVIDER_WIRE_CAPTURE_SCHEMA,
        "capture_id": capture_id,
        "completed_at": completed_at_raw,
        "exchanges": exchanges,
    }


def build_provider_wire_capture(
    *,
    capture_id: str,
    completed_at: str,
    exchanges: Sequence[Mapping[str, Any]],
) -> bytes:
    """Build validated capture bytes from in-memory HTTP exchange evidence.

    This helper performs no network access.  ``response.body_bytes`` must contain
    the already captured identity-encoded entity body.
    """

    serializable: list[dict[str, Any]] = []
    for item in exchanges:
        response = dict(item.get("response") or {})
        body = response.pop("body_bytes", None)
        if not isinstance(body, bytes):
            raise ProviderWireCaptureError("response.body_bytes must be bytes")
        response.update(
            {
                "body_byte_size": len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_base64": base64.b64encode(body).decode("ascii"),
            }
        )
        serializable.append(
            {
                "exchange_id": item.get("exchange_id"),
                "request": dict(item.get("request") or {}),
                "response": response,
                "received_at": item.get("received_at"),
            }
        )
    raw = json.dumps(
        {
            "schema": PROVIDER_WIRE_CAPTURE_SCHEMA,
            "capture_id": capture_id,
            "completed_at": completed_at,
            "exchanges": serializable,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    load_provider_wire_capture(raw)
    return raw


def provider_wire_capture_completed_at(raw_bytes: bytes) -> str:
    """Return the verified bundle completion timestamp."""

    return str(load_provider_wire_capture(raw_bytes)["completed_at"])
