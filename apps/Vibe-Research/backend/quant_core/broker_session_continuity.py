"""Fail-closed admission gate between consecutive broker trading sessions."""

from __future__ import annotations

from datetime import date, datetime, timezone
import re
from typing import Any, Mapping, Sequence

from .broker_account_snapshot_collector import (
    BrokerAccountSnapshotCollector,
    BrokerAccountSnapshotCollectorError,
)
from .broker_daily_reconciliation import (
    BrokerDailyReconciliationError,
    BrokerDailyReconciliationStore,
)
from .provenance import sha256_digest


BROKER_SESSION_CALENDAR_SCHEMA = "quant-core/broker-session-calendar/v1"
BROKER_RECONCILIATION_BOOTSTRAP_SCHEMA = (
    "quant-core/broker-reconciliation-bootstrap/v1"
)
BROKER_SESSION_CONTINUITY_ASSESSMENT_SCHEMA = (
    "quant-core/broker-session-continuity-assessment/v1"
)
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$")
TIMEZONE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._+\-/]{0,79}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BrokerSessionContinuityError(RuntimeError):
    """Raised when session or reconciliation admission evidence is invalid."""


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not ID_RE.fullmatch(text):
        raise BrokerSessionContinuityError(f"{label} is invalid")
    return text


def _hash(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not SHA256_RE.fullmatch(text):
        raise BrokerSessionContinuityError(f"{label} must be a sha256 digest")
    return text


def _timezone_name(value: Any) -> str:
    text = str(value or "").strip()
    if not TIMEZONE_RE.fullmatch(text):
        raise BrokerSessionContinuityError("timezone is invalid")
    return text


def _trade_date(value: Any, label: str = "trade_date") -> str:
    try:
        return date.fromisoformat(str(value)).isoformat()
    except (TypeError, ValueError) as exc:
        raise BrokerSessionContinuityError(f"{label} is invalid") from exc


def _timestamp(value: Any, label: str) -> str:
    try:
        parsed = (
            value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
        )
    except (TypeError, ValueError) as exc:
        raise BrokerSessionContinuityError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise BrokerSessionContinuityError(f"{label} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat()


def build_broker_session_calendar(
    *,
    calendar_id: str,
    market: str,
    timezone_name: str,
    sessions: Sequence[str],
    source_reference: str,
    published_at: datetime,
) -> dict[str, Any]:
    """Freeze an ordered exchange-session list as content-addressed evidence."""

    normalized_sessions = [_trade_date(value, "session") for value in sessions]
    if not normalized_sessions:
        raise BrokerSessionContinuityError("session calendar cannot be empty")
    if normalized_sessions != sorted(set(normalized_sessions)):
        raise BrokerSessionContinuityError(
            "session calendar must be strictly increasing and unique"
        )
    identity = {
        "schema": BROKER_SESSION_CALENDAR_SCHEMA,
        "calendar_id": _identifier(calendar_id, "calendar_id"),
        "market": _identifier(market, "market"),
        "timezone": _timezone_name(timezone_name),
        "sessions": normalized_sessions,
        "source_reference": _identifier(source_reference, "source_reference"),
        "published_at": _timestamp(published_at, "published_at"),
    }
    return {**identity, "calendar_sha256": sha256_digest(identity)}


def validate_broker_session_calendar(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BrokerSessionContinuityError("session calendar must be an object")
    calendar = dict(value)
    required = {
        "schema",
        "calendar_id",
        "market",
        "timezone",
        "sessions",
        "source_reference",
        "published_at",
        "calendar_sha256",
    }
    if set(calendar) != required or calendar.get("schema") != BROKER_SESSION_CALENDAR_SCHEMA:
        raise BrokerSessionContinuityError("session calendar fields are invalid")
    if not isinstance(calendar.get("sessions"), list):
        raise BrokerSessionContinuityError("session calendar sessions must be an array")
    rebuilt = build_broker_session_calendar(
        calendar_id=calendar["calendar_id"],
        market=calendar["market"],
        timezone_name=calendar["timezone"],
        sessions=calendar["sessions"],
        source_reference=calendar["source_reference"],
        published_at=calendar["published_at"],
    )
    if rebuilt != calendar or _hash(calendar["calendar_sha256"], "calendar_sha256") != rebuilt["calendar_sha256"]:
        raise BrokerSessionContinuityError(
            "session calendar hash or canonical form mismatch"
        )
    return rebuilt


def build_broker_reconciliation_bootstrap(
    *,
    bootstrap_id: str,
    adapter_id: str,
    account_fingerprint: str,
    first_live_trade_date: str,
    calendar_sha256: str,
    manual_approval_reference: str,
    authorized_at: datetime,
) -> dict[str, Any]:
    """Create explicit operator evidence for the first admitted live session."""

    fingerprint = str(account_fingerprint or "").strip()
    if not fingerprint or len(fingerprint) > 160:
        raise BrokerSessionContinuityError("account_fingerprint is invalid")
    identity = {
        "schema": BROKER_RECONCILIATION_BOOTSTRAP_SCHEMA,
        "bootstrap_id": _identifier(bootstrap_id, "bootstrap_id"),
        "adapter_id": _identifier(adapter_id, "adapter_id"),
        "account_fingerprint": fingerprint,
        "first_live_trade_date": _trade_date(first_live_trade_date, "first_live_trade_date"),
        "calendar_sha256": _hash(calendar_sha256, "calendar_sha256"),
        "manual_approval_reference": _identifier(
            manual_approval_reference, "manual_approval_reference"
        ),
        "authorized_at": _timestamp(authorized_at, "authorized_at"),
    }
    return {**identity, "bootstrap_sha256": sha256_digest(identity)}


def validate_broker_reconciliation_bootstrap(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise BrokerSessionContinuityError("reconciliation bootstrap must be an object")
    bootstrap = dict(value)
    required = {
        "schema",
        "bootstrap_id",
        "adapter_id",
        "account_fingerprint",
        "first_live_trade_date",
        "calendar_sha256",
        "manual_approval_reference",
        "authorized_at",
        "bootstrap_sha256",
    }
    if set(bootstrap) != required or bootstrap.get("schema") != BROKER_RECONCILIATION_BOOTSTRAP_SCHEMA:
        raise BrokerSessionContinuityError("reconciliation bootstrap fields are invalid")
    rebuilt = build_broker_reconciliation_bootstrap(
        bootstrap_id=bootstrap["bootstrap_id"],
        adapter_id=bootstrap["adapter_id"],
        account_fingerprint=bootstrap["account_fingerprint"],
        first_live_trade_date=bootstrap["first_live_trade_date"],
        calendar_sha256=bootstrap["calendar_sha256"],
        manual_approval_reference=bootstrap["manual_approval_reference"],
        authorized_at=bootstrap["authorized_at"],
    )
    if rebuilt != bootstrap or _hash(bootstrap["bootstrap_sha256"], "bootstrap_sha256") != rebuilt["bootstrap_sha256"]:
        raise BrokerSessionContinuityError(
            "reconciliation bootstrap hash or canonical form mismatch"
        )
    return rebuilt


class BrokerSessionContinuityGate:
    """Require a durable PASS for the calendar-derived prior session."""

    def __init__(
        self,
        *,
        calendar: Mapping[str, Any],
        reconciliation_store: BrokerDailyReconciliationStore,
        account_snapshot_collector: BrokerAccountSnapshotCollector,
        bootstrap: Mapping[str, Any] | None = None,
    ) -> None:
        self.calendar = validate_broker_session_calendar(calendar)
        self.reconciliation_store = reconciliation_store
        self.account_snapshot_collector = account_snapshot_collector
        self.bootstrap = (
            validate_broker_reconciliation_bootstrap(bootstrap)
            if bootstrap is not None
            else None
        )
        if (
            account_snapshot_collector.adapter_id
            != reconciliation_store.adapter_id
            or account_snapshot_collector.account_fingerprint
            != reconciliation_store.account_fingerprint
        ):
            raise BrokerSessionContinuityError(
                "account snapshot collector is misbound to reconciliation store"
            )
        if self.bootstrap is not None and (
            self.bootstrap["adapter_id"] != reconciliation_store.adapter_id
            or self.bootstrap["account_fingerprint"]
            != reconciliation_store.account_fingerprint
            or self.bootstrap["calendar_sha256"]
            != self.calendar["calendar_sha256"]
            or self.bootstrap["first_live_trade_date"]
            != self.calendar["sessions"][0]
        ):
            raise BrokerSessionContinuityError(
                "reconciliation bootstrap is misbound to the store or calendar"
            )

    @property
    def adapter_id(self) -> str:
        return self.reconciliation_store.adapter_id

    @property
    def account_fingerprint(self) -> str:
        return self.reconciliation_store.account_fingerprint

    def assess(self, trade_date: str) -> dict[str, Any]:
        current = _trade_date(trade_date)
        sessions = list(self.calendar["sessions"])
        try:
            index = sessions.index(current)
        except ValueError:
            index = -1
        inspection = self.reconciliation_store.inspect()
        prior_session = sessions[index - 1] if index > 0 else None
        prior_record = next(
            (
                item
                for item in inspection.get("trade_dates", [])
                if item.get("trade_date") == prior_session
            ),
            None,
        )
        trusted_prior_snapshots = False
        if prior_record is not None and prior_record.get("status") == "PASS":
            try:
                receipt = self.reconciliation_store.latest_for_trade_date(
                    prior_session
                )
                collector_inspection = self.account_snapshot_collector.inspect()
                opening = (
                    self.account_snapshot_collector.snapshot_by_sha256(
                        receipt["opening_snapshot_sha256"]
                    )
                    if receipt is not None
                    and collector_inspection.get("status") == "READY"
                    else None
                )
                closing = (
                    self.account_snapshot_collector.snapshot_by_sha256(
                        receipt["closing_snapshot_sha256"]
                    )
                    if receipt is not None
                    and collector_inspection.get("status") == "READY"
                    else None
                )
                trusted_prior_snapshots = (
                    receipt is not None
                    and opening is not None
                    and closing is not None
                    and opening.get("trade_date") == prior_session
                    and closing.get("trade_date") == prior_session
                )
            except (
                BrokerAccountSnapshotCollectorError,
                BrokerDailyReconciliationError,
                KeyError,
                TypeError,
            ):
                trusted_prior_snapshots = False
        bootstrap_allowed = (
            index == 0
            and self.bootstrap is not None
            and self.bootstrap["first_live_trade_date"] == current
            and inspection.get("record_count") == 0
        )
        if index < 0:
            status = "BLOCKED_UNAPPROVED_SESSION"
            reason = "trade date is absent from the approved session calendar"
        elif inspection.get("status") == "DEGRADED":
            status = "DEGRADED"
            reason = "daily reconciliation evidence is degraded"
        elif bootstrap_allowed:
            status = "BOOTSTRAP_ALLOWED"
            reason = "first live session has explicit operator bootstrap evidence"
        elif index == 0:
            status = "BLOCKED_BOOTSTRAP_REQUIRED"
            reason = "first approved session requires explicit bootstrap evidence"
        elif prior_record is None:
            status = "BLOCKED_MISSING_RECONCILIATION"
            reason = "calendar-derived prior session has no reconciliation record"
        elif prior_record.get("status") != "PASS":
            status = "BLOCKED_PRIOR_RECONCILIATION"
            reason = "calendar-derived prior session reconciliation did not pass"
        elif not trusted_prior_snapshots:
            status = "BLOCKED_UNTRUSTED_ACCOUNT_SNAPSHOTS"
            reason = (
                "prior reconciliation account snapshots are absent from the "
                "trusted atomic collection chain"
            )
        else:
            status = "PASS"
            reason = "calendar-derived prior session reconciliation passed"
        identity = {
            "schema": BROKER_SESSION_CONTINUITY_ASSESSMENT_SCHEMA,
            "status": status,
            "admitted": status in {"PASS", "BOOTSTRAP_ALLOWED"},
            "reason": reason,
            "trade_date": current,
            "prior_session": prior_session,
            "adapter_id": self.adapter_id,
            "account_fingerprint": self.account_fingerprint,
            "calendar_sha256": self.calendar["calendar_sha256"],
            "bootstrap_sha256": (
                self.bootstrap["bootstrap_sha256"] if bootstrap_allowed else None
            ),
            "prior_reconciliation_sha256": (
                prior_record.get("reconciliation_sha256")
                if prior_record is not None
                else None
            ),
            "reconciliation_store_status": inspection.get("status"),
            "reconciliation_store_head_sha256": inspection.get(
                "latest_record_sha256"
            ),
        }
        return {**identity, "assessment_sha256": sha256_digest(identity)}
