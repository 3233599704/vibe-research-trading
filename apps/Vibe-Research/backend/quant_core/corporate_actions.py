"""Canonical economic contract for corporate-action records.

Corporate-action identity alone is insufficient for replay: a dividend amount
or split multiplier changes both cash and holdings.  This module freezes the
small, explicit event vocabulary and its units so historical materialization
and formal-forward admission cannot interpret the same record differently.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any


CASH_PER_SHARE_SEMANTICS = "gross_cash_per_pre_event_share_cny"
SPLIT_RATIO_SEMANTICS = "post_event_shares_per_pre_event_share"
CASH_EVENT_TYPES = frozenset({"cash_distribution", "delisting_cash_recovery"})
SPLIT_EVENT_TYPES = frozenset({"split"})
CANONICAL_CORPORATE_ACTION_EVENT_TYPES = CASH_EVENT_TYPES | SPLIT_EVENT_TYPES
CANONICAL_CORPORATE_ACTION_ECONOMIC_FIELDS = (
    "cash_per_share",
    "split_ratio",
    "economic_semantics",
)


class CorporateActionEconomicsError(ValueError):
    """A corporate-action record has ambiguous or invalid economics."""


def _positive_finite(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CorporateActionEconomicsError(f"{field} must be a finite positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise CorporateActionEconomicsError(f"{field} must be a finite positive number")
    return result


def validate_corporate_action_economics(
    record: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and return the canonical event-dependent economic fields.

    All three economic keys must be present on every row.  The inactive numeric
    field must be explicit ``None``; this keeps empty/inactive values distinct
    from a missing field and makes dual-source comparison deterministic.
    """

    missing = [
        field
        for field in ("event_type", *CANONICAL_CORPORATE_ACTION_ECONOMIC_FIELDS)
        if field not in record
    ]
    if missing:
        raise CorporateActionEconomicsError(
            "corporate action omits required economic fields: " + ", ".join(missing)
        )
    event_type = str(record.get("event_type") or "").strip().lower()
    if event_type not in CANONICAL_CORPORATE_ACTION_EVENT_TYPES:
        raise CorporateActionEconomicsError(
            f"unsupported canonical corporate action: {event_type or '<blank>'}"
        )
    semantics = str(record.get("economic_semantics") or "").strip()
    cash_value = record.get("cash_per_share")
    split_value = record.get("split_ratio")
    if event_type in CASH_EVENT_TYPES:
        cash = _positive_finite(cash_value, "cash_per_share")
        if split_value is not None:
            raise CorporateActionEconomicsError(
                "cash corporate action must set split_ratio to null"
            )
        if semantics != CASH_PER_SHARE_SEMANTICS:
            raise CorporateActionEconomicsError(
                "cash corporate action has unsupported economic semantics"
            )
        return {
            "event_type": event_type,
            "cash_per_share": cash,
            "split_ratio": None,
            "economic_semantics": semantics,
        }

    ratio = _positive_finite(split_value, "split_ratio")
    if math.isclose(ratio, 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise CorporateActionEconomicsError("split_ratio cannot be a no-op value of 1")
    if cash_value is not None:
        raise CorporateActionEconomicsError(
            "split corporate action must set cash_per_share to null"
        )
    if semantics != SPLIT_RATIO_SEMANTICS:
        raise CorporateActionEconomicsError(
            "split corporate action has unsupported economic semantics"
        )
    return {
        "event_type": event_type,
        "cash_per_share": None,
        "split_ratio": ratio,
        "economic_semantics": semantics,
    }
