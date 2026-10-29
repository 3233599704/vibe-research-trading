"""Content-addressed trading-session calendars for fail-closed T+1 eligibility.

The resolver is intentionally clock-free.  It never derives a session from a
weekday guess or ``calendar day + 1``; eligibility advances only through the
ordered sessions frozen in one exact calendar version.
"""

from __future__ import annotations

from bisect import bisect_right
from copy import deepcopy
from dataclasses import dataclass
from datetime import date
import re
from typing import Any, Iterable

from .provenance import sha256_digest


TRADING_CALENDAR_SCHEMA = "quant-core/versioned-trading-calendar/v1"
SUPPORTED_T1_MARKETS = frozenset({"SSE_SZSE"})
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class TradingCalendarError(RuntimeError):
    """Stable fail-closed calendar error suitable for machine assertions."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _fail(code: str, message: str) -> TradingCalendarError:
    return TradingCalendarError(code, message)


def _canonical_date(value: Any, *, code: str) -> date:
    if not isinstance(value, str):
        raise _fail(code, "trading calendar date is invalid")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise _fail(code, "trading calendar date is invalid") from None
    if parsed.isoformat() != value:
        raise _fail(code, "trading calendar date is invalid")
    return parsed


def build_versioned_trading_calendar_binding(
    *,
    calendar_id: str,
    calendar_version: str,
    market: str,
    coverage_start: str,
    coverage_end: str,
    sessions: Iterable[str],
) -> dict[str, Any]:
    """Build one immutable, content-addressed calendar descriptor."""

    identity = {
        "schema": TRADING_CALENDAR_SCHEMA,
        "calendar_id": str(calendar_id),
        "calendar_version": str(calendar_version),
        "market": str(market),
        "timezone": "Asia/Shanghai",
        "coverage_start": str(coverage_start),
        "coverage_end": str(coverage_end),
        "sessions": [str(item) for item in sessions],
        "next_session_rule": "ORDERED_VERSIONED_SESSION_INDEX",
    }
    binding = {**identity, "calendar_sha256": sha256_digest(identity)}
    VersionedTradingCalendar.from_binding(binding)
    return binding


@dataclass(frozen=True, slots=True)
class VersionedTradingCalendar:
    calendar_id: str
    calendar_version: str
    market: str
    timezone: str
    coverage_start: date
    coverage_end: date
    sessions: tuple[date, ...]
    calendar_sha256: str

    @classmethod
    def from_binding(cls, raw: dict[str, Any]) -> "VersionedTradingCalendar":
        binding = deepcopy(dict(raw or {}))
        required = {
            "schema",
            "calendar_id",
            "calendar_version",
            "market",
            "timezone",
            "coverage_start",
            "coverage_end",
            "sessions",
            "next_session_rule",
            "calendar_sha256",
        }
        if set(binding) != required:
            raise _fail(
                "CALENDAR_BINDING_INVALID",
                "trading calendar binding fields are invalid",
            )
        if binding["schema"] != TRADING_CALENDAR_SCHEMA:
            raise _fail(
                "CALENDAR_BINDING_INVALID", "trading calendar schema is unsupported"
            )
        calendar_id = str(binding["calendar_id"])
        calendar_version = str(binding["calendar_version"])
        if not _IDENTIFIER_RE.fullmatch(calendar_id) or not _IDENTIFIER_RE.fullmatch(
            calendar_version
        ):
            raise _fail(
                "CALENDAR_BINDING_INVALID", "trading calendar identity is invalid"
            )
        market = str(binding["market"])
        if market not in SUPPORTED_T1_MARKETS:
            raise _fail("CALENDAR_MARKET_UNSUPPORTED", "trading market is unsupported")
        if binding["timezone"] != "Asia/Shanghai":
            raise _fail(
                "CALENDAR_BINDING_INVALID", "trading calendar timezone is invalid"
            )
        if binding["next_session_rule"] != "ORDERED_VERSIONED_SESSION_INDEX":
            raise _fail(
                "CALENDAR_BINDING_INVALID", "trading calendar next-session rule is invalid"
            )
        coverage_start = _canonical_date(
            binding["coverage_start"], code="CALENDAR_BINDING_INVALID"
        )
        coverage_end = _canonical_date(
            binding["coverage_end"], code="CALENDAR_BINDING_INVALID"
        )
        if coverage_start > coverage_end:
            raise _fail(
                "CALENDAR_BINDING_INVALID", "trading calendar coverage is inverted"
            )
        raw_sessions = binding["sessions"]
        if not isinstance(raw_sessions, list) or not raw_sessions:
            raise _fail(
                "CALENDAR_BINDING_INVALID", "trading calendar sessions are empty"
            )
        sessions = tuple(
            _canonical_date(item, code="CALENDAR_BINDING_INVALID")
            for item in raw_sessions
        )
        if sessions != tuple(sorted(set(sessions))):
            raise _fail(
                "CALENDAR_BINDING_INVALID",
                "trading calendar sessions must be unique and sorted",
            )
        if sessions[0] < coverage_start or sessions[-1] > coverage_end:
            raise _fail(
                "CALENDAR_BINDING_INVALID", "trading sessions exceed calendar coverage"
            )
        claimed_sha = str(binding["calendar_sha256"]).lower()
        identity = {key: value for key, value in binding.items() if key != "calendar_sha256"}
        if claimed_sha != sha256_digest(identity):
            raise _fail(
                "CALENDAR_BINDING_HASH_MISMATCH",
                "trading calendar binding hash does not match",
            )
        return cls(
            calendar_id=calendar_id,
            calendar_version=calendar_version,
            market=market,
            timezone="Asia/Shanghai",
            coverage_start=coverage_start,
            coverage_end=coverage_end,
            sessions=sessions,
            calendar_sha256=claimed_sha,
        )

    def evidence(self) -> dict[str, Any]:
        return {
            "schema": TRADING_CALENDAR_SCHEMA,
            "calendar_id": self.calendar_id,
            "calendar_version": self.calendar_version,
            "market": self.market,
            "timezone": self.timezone,
            "coverage_start": self.coverage_start.isoformat(),
            "coverage_end": self.coverage_end.isoformat(),
            "session_count": len(self.sessions),
            "next_session_rule": "ORDERED_VERSIONED_SESSION_INDEX",
            "calendar_sha256": self.calendar_sha256,
        }

    def require_session(self, value: str | date) -> date:
        text = value.isoformat() if isinstance(value, date) else value
        candidate = _canonical_date(text, code="CALENDAR_DATE_INVALID")
        if candidate < self.coverage_start or candidate > self.coverage_end:
            raise _fail(
                "CALENDAR_DATE_UNAVAILABLE",
                "date is outside the frozen trading calendar coverage",
            )
        index = bisect_right(self.sessions, candidate)
        if index == 0 or self.sessions[index - 1] != candidate:
            raise _fail("NON_TRADING_SESSION", "date is not a trading session")
        return candidate

    def next_session(self, acquired_on: str | date) -> date:
        acquired = self.require_session(acquired_on)
        index = bisect_right(self.sessions, acquired)
        if index >= len(self.sessions):
            raise _fail(
                "CALENDAR_NEXT_SESSION_UNAVAILABLE",
                "next trading session is outside the frozen calendar",
            )
        return self.sessions[index]

    def is_t1_eligible(
        self, *, acquired_on: str | date, candidate_session: str | date
    ) -> bool:
        acquired = self.require_session(acquired_on)
        candidate = self.require_session(candidate_session)
        eligible_on = self.next_session(acquired)
        return candidate >= eligible_on

    def assert_same_binding(self, raw: dict[str, Any]) -> None:
        candidate = VersionedTradingCalendar.from_binding(raw)
        if (
            candidate.calendar_id,
            candidate.calendar_version,
            candidate.market,
            candidate.calendar_sha256,
        ) != (
            self.calendar_id,
            self.calendar_version,
            self.market,
            self.calendar_sha256,
        ):
            raise _fail(
                "CALENDAR_REVISION_REQUIRES_NEW_LEDGER",
                "calendar revision cannot mutate an existing ledger",
            )


__all__ = [
    "SUPPORTED_T1_MARKETS",
    "TRADING_CALENDAR_SCHEMA",
    "TradingCalendarError",
    "VersionedTradingCalendar",
    "build_versioned_trading_calendar_binding",
]
