"""Deterministic, auditable liquidity-window derivation for formal paper trading."""

from __future__ import annotations

import math
import statistics
from datetime import date
from typing import Any, Mapping, Sequence

from .provenance import sha256_digest


LIQUIDITY_EVIDENCE_SCHEMA = "quant-platform/liquidity-window-evidence/v1"
LIQUIDITY_WINDOW_SESSIONS = 60


def _volume(value: Any, label: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be numeric") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return number


def derive_liquidity_evidence(
    history: Sequence[Mapping[str, Any]],
    *,
    trade_date: date,
    current_volume: Any,
) -> dict[str, Any]:
    """Validate raw session volumes and derive a conservative frozen capacity.

    The last 60 observations are content-addressed. The usable volume is the
    minimum of the current session, 20/60-session averages and the 20-session
    median, preventing one unusually active day from inflating exit capacity.
    """

    if isinstance(history, (str, bytes)) or not isinstance(history, Sequence):
        raise ValueError("liquidity history must be an array")
    if len(history) < LIQUIDITY_WINDOW_SESSIONS:
        raise ValueError(
            f"liquidity history requires at least {LIQUIDITY_WINDOW_SESSIONS} sessions"
        )

    normalized: list[dict[str, Any]] = []
    previous: date | None = None
    for index, raw in enumerate(history):
        if not isinstance(raw, Mapping) or set(raw) != {"date", "volume"}:
            raise ValueError(
                f"liquidity history row {index} must contain exactly date and volume"
            )
        try:
            session = date.fromisoformat(str(raw["date"]))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"liquidity history row {index} has invalid date") from exc
        if session > trade_date:
            raise ValueError("liquidity history contains a future session")
        if session.weekday() >= 5:
            raise ValueError("liquidity history contains a weekend session")
        if previous is not None and session <= previous:
            raise ValueError("liquidity history dates must be strictly increasing")
        normalized.append(
            {
                "date": session.isoformat(),
                "volume": _volume(raw["volume"], f"liquidity history row {index} volume"),
            }
        )
        previous = session

    if previous != trade_date:
        raise ValueError("liquidity history must end on the market trade_date")
    observed_current = _volume(current_volume, "current market volume")
    if abs(normalized[-1]["volume"] - observed_current) > 1e-8:
        raise ValueError("current market volume differs from liquidity history")

    window = normalized[-LIQUIDITY_WINDOW_SESSIONS:]
    if (trade_date - date.fromisoformat(window[0]["date"])).days > 120:
        raise ValueError("liquidity history 60-session window is implausibly sparse")
    volumes_20 = [float(item["volume"]) for item in window[-20:]]
    volumes_60 = [float(item["volume"]) for item in window]
    adv20 = sum(volumes_20) / 20
    adv60 = sum(volumes_60) / LIQUIDITY_WINDOW_SESSIONS
    median20 = float(statistics.median(volumes_20))
    conservative = min(observed_current, adv20, adv60, median20)
    identity = {
        "schema": LIQUIDITY_EVIDENCE_SCHEMA,
        "trade_date": trade_date.isoformat(),
        "window_start": window[0]["date"],
        "window_end": window[-1]["date"],
        "window_sessions": LIQUIDITY_WINDOW_SESSIONS,
        "source_observation_count": len(normalized),
        "current_volume": observed_current,
        "adv20_volume": adv20,
        "adv60_volume": adv60,
        "median20_volume": median20,
        "conservative_volume": conservative,
        "zero_volume_sessions": sum(1 for item in window if item["volume"] == 0),
        "history_sha256": sha256_digest(
            {
                "schema": "quant-platform/liquidity-history-window/v1",
                "trade_date": trade_date.isoformat(),
                "sessions": window,
            }
        ),
    }
    return {**identity, "evidence_sha256": sha256_digest(identity)}
