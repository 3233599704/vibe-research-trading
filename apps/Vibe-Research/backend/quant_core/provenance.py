"""Deterministic provenance records for research runs.

The functions in this module deliberately avoid market or strategy semantics.  They
only answer three audit questions:

* Which exact observations were used?
* Which configuration and implementation produced the result?
* Can the same scientific output be identified independently of wall-clock time?
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any


CANONICAL_JSON_SCHEMA = "quant-core/canonical-json/v1"
DATASET_SNAPSHOT_SCHEMA = "quant-core/dataset-snapshot/v1"
CODE_SNAPSHOT_SCHEMA = "quant-core/code-snapshot/v1"
RUN_MANIFEST_SCHEMA = "quant-core/run-manifest/v2"


def _canonical_value(value: Any) -> Any:
    """Convert supported values into an unambiguous JSON-compatible value."""

    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON does not permit NaN or infinity")
        return 0.0 if value == 0 else value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("canonical JSON does not permit non-finite decimals")
        normalized = value.normalize()
        return {"$decimal": format(normalized, "f")}
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("canonical datetimes must include a timezone")
        return {"$datetime": value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}
    if isinstance(value, date):
        return {"$date": value.isoformat()}
    if isinstance(value, Path):
        return {"$path": value.as_posix()}
    if isinstance(value, Mapping):
        converted: dict[str, Any] = {}
        for key, item in value.items():
            text_key = str(key)
            if text_key in converted:
                raise ValueError(f"duplicate canonical mapping key: {text_key}")
            converted[text_key] = _canonical_value(item)
        return converted
    if isinstance(value, set | frozenset):
        converted = [_canonical_value(item) for item in value]
        return sorted(converted, key=_canonical_json_from_value)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_canonical_value(item) for item in value]
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def _canonical_json_from_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_json(value: Any) -> str:
    """Return stable JSON whose hash is independent of dict insertion order."""

    return _canonical_json_from_value(_canonical_value(value))


def sha256_digest(value: Any) -> str:
    """Hash a supported object using the canonical JSON representation."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def build_dataset_snapshot(
    bars_by_code: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    source: Mapping[str, Any] | str,
    adjustment: str,
    requested_start: str,
    requested_end: str,
) -> dict[str, Any]:
    """Describe and fingerprint a collection of market bars.

    Rows and instruments are sorted before hashing.  Provider response order can
    therefore change without manufacturing a new dataset identity, while any
    actual field/value change creates a new content hash.
    """

    assets: list[dict[str, Any]] = []
    for raw_code in sorted(bars_by_code, key=str):
        code = str(raw_code)
        rows = [dict(row) for row in bars_by_code[raw_code]]
        rows.sort(key=lambda row: (str(row.get("date", "")), canonical_json(row)))
        dates = [str(row.get("date")) for row in rows if row.get("date") is not None]
        fields = sorted({str(field) for row in rows for field in row})
        assets.append(
            {
                "code": code,
                "row_count": len(rows),
                "first_date": min(dates) if dates else None,
                "last_date": max(dates) if dates else None,
                "fields": fields,
                "content_sha256": sha256_digest(rows),
            }
        )

    identity = {
        "schema": DATASET_SNAPSHOT_SCHEMA,
        "canonicalization": CANONICAL_JSON_SCHEMA,
        "source": source,
        "adjustment": str(adjustment),
        "requested_period": {"start": str(requested_start), "end": str(requested_end)},
        "assets": assets,
    }
    return {**identity, "content_sha256": sha256_digest(identity)}


def build_code_snapshot(paths: Sequence[Path], *, base_dir: Path | None = None) -> dict[str, Any]:
    """Fingerprint the implementation files that define a research engine."""

    resolved_base = base_dir.resolve() if base_dir is not None else None
    files: list[dict[str, Any]] = []
    for path in sorted((Path(item).resolve() for item in paths), key=lambda item: item.as_posix()):
        try:
            relative = path.relative_to(resolved_base).as_posix() if resolved_base else path.name
        except ValueError:
            relative = path.name
        if path.is_file():
            content = path.read_bytes()
            files.append(
                {
                    "path": relative,
                    "size_bytes": len(content),
                    "content_sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        else:
            files.append({"path": relative, "missing": True})

    identity = {"schema": CODE_SNAPSHOT_SCHEMA, "files": files}
    return {**identity, "content_sha256": sha256_digest(identity)}


def build_run_manifest(
    *,
    config: Mapping[str, Any],
    dataset_snapshot: Mapping[str, Any],
    code_snapshot: Mapping[str, Any],
    engine: Mapping[str, Any],
    execution_semantics: Mapping[str, Any],
    output: Mapping[str, Any],
    limitations: Sequence[str] = (),
    catalog_as_of_selection: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a deterministic run identity plus independently verifiable output hash."""

    catalog_as_of = dict(catalog_as_of_selection) if catalog_as_of_selection is not None else None
    catalog_as_of_sha256 = (
        str(catalog_as_of.get("as_of_sha256") or "") if catalog_as_of is not None else None
    )
    if catalog_as_of is not None and len(catalog_as_of_sha256) != 64:
        raise ValueError("catalog as-of selection must include a 64-character as_of_sha256")
    identity = {
        "schema": RUN_MANIFEST_SCHEMA,
        "engine": dict(engine),
        "config_sha256": sha256_digest(config),
        "dataset_sha256": str(dataset_snapshot["content_sha256"]),
        "code_sha256": str(code_snapshot["content_sha256"]),
        "execution_semantics": dict(execution_semantics),
        "catalog_as_of_sha256": catalog_as_of_sha256,
    }
    return {
        **identity,
        "run_fingerprint": sha256_digest(identity),
        "output_sha256": sha256_digest(output),
        "output_hash_scope": "scientific payload excluding id, created_at, manifest and integrity hashes",
        "dataset": dict(dataset_snapshot),
        "catalog_as_of": catalog_as_of,
        "code": dict(code_snapshot),
        "limitations": [str(item) for item in limitations],
    }
