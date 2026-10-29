"""Fail-closed broker boundary for read-only, paper and controlled-live adapters.

The module intentionally contains no vendor SDK and cannot discover credentials.
Strategies only submit normalized intents to :class:`BrokerSafetyEnvelope`; they
never receive a broker client and cannot enable live trading themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
import re
from typing import Any, Protocol, runtime_checkable

from .provenance import sha256_digest
from .order_allocation import OrderAllocationError, validate_parent_order_plan
from .broker_order_lifecycle import (
    AMBIGUOUS_STATUSES,
    TERMINAL_STATUSES,
    BrokerOrderJournal,
    BrokerOrderJournalConflict,
    BrokerOrderJournalError,
)
from .broker_report_consumer import (
    BrokerReportConflict,
    BrokerReportConsumer,
    BrokerReportConsumerError,
)
from .broker_account_control import (
    BrokerAccountControlError,
    BrokerAccountReservationBook,
)
from .broker_account_snapshot_collector import (
    BrokerAccountSnapshotCollector,
    BrokerAccountSnapshotCollectorError,
)
from .broker_session_continuity import (
    BrokerSessionContinuityError,
    BrokerSessionContinuityGate,
)
from .broker_adapter_certification import (
    REQUIRED_BROKER_ADAPTER_CAPABILITIES,
    BrokerAdapterCertificationError,
    BrokerAdapterCertificationRegistry,
)


BROKER_SAFETY_SCHEMA = "quant-core/broker-safety/v1"
LIVE_AUTHORIZATION_SCHEMA = "quant-core/live-authorization/v1"
PARENT_LIVE_AUTHORIZATION_SCHEMA = "quant-core/parent-live-authorization/v2"
BROKER_SYMBOL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
BROKER_STRATEGY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class BrokerSafetyError(RuntimeError):
    """Base class for rejected broker boundary operations."""


class BrokerPermissionError(BrokerSafetyError):
    """Raised when the current safety mode does not permit an operation."""


class BrokerOperationConflict(BrokerSafetyError):
    """Raised when an idempotency key is reused for a different intent."""


class BrokerMode(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    READ_ONLY = "READ_ONLY"
    PAPER = "PAPER"
    LIVE_LOCKED = "LIVE_LOCKED"
    LIVE_ENABLED = "LIVE_ENABLED"
    HALTED = "HALTED"


class BrokerCapability(str, Enum):
    ACCOUNT_READ = "ACCOUNT_READ"
    POSITIONS_READ = "POSITIONS_READ"
    ORDERS_READ = "ORDERS_READ"
    MARKET_DATA_READ = "MARKET_DATA_READ"
    PAPER_ORDER = "PAPER_ORDER"
    LIVE_ORDER = "LIVE_ORDER"
    CANCEL_ORDER = "CANCEL_ORDER"
    CLIENT_ORDER_IDEMPOTENCY = "CLIENT_ORDER_IDEMPOTENCY"
    DAILY_USAGE_READ = "DAILY_USAGE_READ"
    ATOMIC_ACCOUNT_SNAPSHOT_READ = "ATOMIC_ACCOUNT_SNAPSHOT_READ"


READ_ONLY_CAPABILITIES = frozenset(
    {
        BrokerCapability.ACCOUNT_READ.value,
        BrokerCapability.POSITIONS_READ.value,
        BrokerCapability.ORDERS_READ.value,
    }
)


def _utc(value: datetime | None = None) -> datetime:
    parsed = value or datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _positive_decimal(value: Any, field: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field} must be a finite decimal") from exc
    if not parsed.is_finite() or parsed <= 0:
        raise ValueError(f"{field} must be positive")
    return parsed


def _nonnegative_decimal(value: Any, field: str) -> Decimal:
    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise BrokerSafetyError(f"{field} must be a finite decimal") from exc
    if not parsed.is_finite() or parsed < 0:
        raise BrokerSafetyError(f"{field} must be a nonnegative finite decimal")
    return parsed


@runtime_checkable
class BrokerAdapter(Protocol):
    """Minimal vendor-neutral adapter contract.

    Implementations must keep authentication inside the adapter.  The safety
    envelope deliberately has no credential or secret arguments.
    """

    adapter_id: str
    adapter_version: str
    implementation_fingerprint: str
    environment: str
    account_fingerprint: str

    def capabilities(self) -> set[str]: ...

    def get_account(self) -> dict[str, Any]: ...

    def get_positions(self) -> list[dict[str, Any]]: ...

    def list_orders(self) -> list[dict[str, Any]]: ...

    def submit_paper_order(self, intent: dict[str, Any]) -> dict[str, Any]: ...

    def submit_live_order(self, intent: dict[str, Any]) -> dict[str, Any]: ...

    def cancel_order(self, broker_order_id: str) -> dict[str, Any]: ...

    def find_order_by_client_id(self, client_order_id: str) -> dict[str, Any] | None: ...

    def get_daily_order_usage(self, trade_date: str) -> dict[str, Any]: ...

    def get_atomic_account_snapshot(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class BrokerSafetyPolicy:
    policy_id: str
    real_orders_enabled: bool
    allowed_read_only_adapters: tuple[str, ...]
    allowed_live_adapters: tuple[str, ...]
    allowed_live_accounts: tuple[str, ...]
    max_order_notional: Decimal
    max_daily_notional: Decimal
    max_daily_order_count: int
    max_live_capital: Decimal
    authorization_ttl_minutes: int
    require_read_only_shadow: bool = True
    require_sandbox_certification: bool = True
    require_recovery_drill: bool = True
    require_kill_switch_test: bool = True
    require_durable_order_journal: bool = True
    require_trusted_report_consumer: bool = True
    require_account_reservation_book: bool = True
    require_trusted_account_snapshot_collector: bool = True
    require_prior_session_reconciliation: bool = True
    require_trusted_adapter_certification_registry: bool = True

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "BrokerSafetyPolicy":
        required_fields = {
            "schema",
            "policy_id",
            "real_orders_enabled",
            "allowed_read_only_adapters",
            "allowed_live_adapters",
            "allowed_live_accounts",
            "max_order_notional",
            "max_daily_notional",
            "max_daily_order_count",
            "max_live_capital",
            "authorization_ttl_minutes",
            "require_read_only_shadow",
            "require_sandbox_certification",
            "require_recovery_drill",
            "require_kill_switch_test",
            "require_durable_order_journal",
            "require_trusted_report_consumer",
            "require_account_reservation_book",
            "require_trusted_account_snapshot_collector",
            "require_prior_session_reconciliation",
            "require_trusted_adapter_certification_registry",
            "separation_of_duties",
        }
        missing = sorted(required_fields - set(config))
        if missing:
            raise ValueError(
                "broker safety policy is missing required fields: "
                + ", ".join(missing)
            )
        if config.get("schema") != "quant-core/broker-safety-policy/v1":
            raise ValueError("unsupported broker safety policy schema")
        duties = dict(config.get("separation_of_duties") or {})
        if duties != {
            "strategy_can_enable_live": False,
            "application_can_discover_credentials": False,
            "manual_approval_required": True,
            "sticky_halt_requires_operator_acknowledgement": True,
        }:
            raise ValueError("broker separation-of-duties policy was weakened")
        for field in (
            "require_read_only_shadow",
            "require_sandbox_certification",
            "require_recovery_drill",
            "require_kill_switch_test",
            "require_durable_order_journal",
            "require_trusted_report_consumer",
            "require_account_reservation_book",
            "require_trusted_account_snapshot_collector",
            "require_prior_session_reconciliation",
            "require_trusted_adapter_certification_registry",
        ):
            if config.get(field) is not True:
                raise ValueError(f"broker safety gate cannot be disabled: {field}")
        policy = cls(
            policy_id=str(config.get("policy_id") or "broker-safety-v1"),
            real_orders_enabled=config.get("real_orders_enabled") is True,
            allowed_read_only_adapters=tuple(
                str(item) for item in config.get("allowed_read_only_adapters", ())
            ),
            allowed_live_adapters=tuple(
                str(item) for item in config.get("allowed_live_adapters", ())
            ),
            allowed_live_accounts=tuple(
                str(item) for item in config.get("allowed_live_accounts", ())
            ),
            max_order_notional=_positive_decimal(
                config.get("max_order_notional", 1), "max_order_notional"
            ),
            max_daily_notional=_positive_decimal(
                config.get("max_daily_notional", 1), "max_daily_notional"
            ),
            max_daily_order_count=int(config.get("max_daily_order_count", 1)),
            max_live_capital=_positive_decimal(
                config.get("max_live_capital", 1), "max_live_capital"
            ),
            authorization_ttl_minutes=int(config.get("authorization_ttl_minutes", 60)),
            require_read_only_shadow=config.get("require_read_only_shadow", True) is True,
            require_sandbox_certification=(
                config.get("require_sandbox_certification", True) is True
            ),
            require_recovery_drill=config.get("require_recovery_drill", True) is True,
            require_kill_switch_test=config.get("require_kill_switch_test", True) is True,
            require_durable_order_journal=(
                config.get("require_durable_order_journal", True) is True
            ),
            require_trusted_report_consumer=(
                config.get("require_trusted_report_consumer", True) is True
            ),
            require_account_reservation_book=(
                config.get("require_account_reservation_book", True) is True
            ),
            require_trusted_account_snapshot_collector=(
                config.get("require_trusted_account_snapshot_collector", True)
                is True
            ),
            require_prior_session_reconciliation=(
                config.get("require_prior_session_reconciliation", True) is True
            ),
            require_trusted_adapter_certification_registry=(
                config.get(
                    "require_trusted_adapter_certification_registry", True
                )
                is True
            ),
        )
        if policy.max_daily_order_count <= 0:
            raise ValueError("max_daily_order_count must be positive")
        if policy.authorization_ttl_minutes <= 0:
            raise ValueError("authorization_ttl_minutes must be positive")
        if policy.max_order_notional > policy.max_daily_notional:
            raise ValueError("max_order_notional cannot exceed max_daily_notional")
        if policy.max_daily_notional > policy.max_live_capital:
            raise ValueError("max_daily_notional cannot exceed max_live_capital")
        for label, values in (
            ("allowed_read_only_adapters", policy.allowed_read_only_adapters),
            ("allowed_live_adapters", policy.allowed_live_adapters),
            ("allowed_live_accounts", policy.allowed_live_accounts),
        ):
            if any(not value.strip() for value in values) or len(set(values)) != len(values):
                raise ValueError(f"{label} must contain unique non-empty values")
        if policy.real_orders_enabled and (
            not policy.allowed_live_adapters or not policy.allowed_live_accounts
        ):
            raise ValueError(
                "real orders require explicit live adapter and account allowlists"
            )
        return policy

    def evidence(self) -> dict[str, Any]:
        values = {
            "schema": BROKER_SAFETY_SCHEMA,
            "policy_id": self.policy_id,
            "real_orders_enabled": self.real_orders_enabled,
            "allowed_read_only_adapters": list(self.allowed_read_only_adapters),
            "allowed_live_adapters": list(self.allowed_live_adapters),
            "allowed_live_accounts": list(self.allowed_live_accounts),
            "max_order_notional": str(self.max_order_notional),
            "max_daily_notional": str(self.max_daily_notional),
            "max_daily_order_count": self.max_daily_order_count,
            "max_live_capital": str(self.max_live_capital),
            "authorization_ttl_minutes": self.authorization_ttl_minutes,
            "require_read_only_shadow": self.require_read_only_shadow,
            "require_sandbox_certification": self.require_sandbox_certification,
            "require_recovery_drill": self.require_recovery_drill,
            "require_kill_switch_test": self.require_kill_switch_test,
            "require_durable_order_journal": self.require_durable_order_journal,
            "require_trusted_report_consumer": self.require_trusted_report_consumer,
            "require_account_reservation_book": self.require_account_reservation_book,
            "require_trusted_account_snapshot_collector": (
                self.require_trusted_account_snapshot_collector
            ),
            "require_prior_session_reconciliation": (
                self.require_prior_session_reconciliation
            ),
            "require_trusted_adapter_certification_registry": (
                self.require_trusted_adapter_certification_registry
            ),
            "separation_of_duties": {
                "strategy_can_enable_live": False,
                "application_can_discover_credentials": False,
                "manual_approval_required": True,
                "sticky_halt_requires_operator_acknowledgement": True,
            },
        }
        return {**values, "policy_sha256": sha256_digest(values)}


@dataclass(frozen=True)
class LiveAuthorization:
    authorization_id: str
    strategy_id: str
    policy_sha256: str
    account_fingerprint: str
    allowed_symbols: tuple[str, ...]
    allowed_order_types: tuple[str, ...]
    paper_gate_assessment_sha256: str
    adapter_conformance_sha256: str
    recovery_drill_sha256: str
    manual_approval_reference: str
    not_after: datetime
    capital_cap: Decimal
    allocated_notional_at_authorization: Decimal
    paper_gate_passed: bool
    read_only_shadow_passed: bool
    sandbox_certification_passed: bool
    kill_switch_test_passed: bool
    authorization_sha256: str = ""

    def evidence(self) -> dict[str, Any]:
        identity = {
            "schema": LIVE_AUTHORIZATION_SCHEMA,
            "authorization_id": self.authorization_id,
            "strategy_id": self.strategy_id,
            "policy_sha256": self.policy_sha256,
            "account_fingerprint": self.account_fingerprint,
            "allowed_symbols": list(self.allowed_symbols),
            "allowed_order_types": list(self.allowed_order_types),
            "paper_gate_assessment_sha256": self.paper_gate_assessment_sha256,
            "adapter_conformance_sha256": self.adapter_conformance_sha256,
            "recovery_drill_sha256": self.recovery_drill_sha256,
            "manual_approval_reference": self.manual_approval_reference,
            "not_after": _utc(self.not_after).isoformat(),
            "capital_cap": str(self.capital_cap),
            "allocated_notional_at_authorization": str(
                self.allocated_notional_at_authorization
            ),
            "paper_gate_passed": self.paper_gate_passed,
            "read_only_shadow_passed": self.read_only_shadow_passed,
            "sandbox_certification_passed": self.sandbox_certification_passed,
            "kill_switch_test_passed": self.kill_switch_test_passed,
        }
        return {**identity, "authorization_sha256": sha256_digest(identity)}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "LiveAuthorization":
        expected_fields = {
            "schema",
            "authorization_id",
            "strategy_id",
            "policy_sha256",
            "account_fingerprint",
            "allowed_symbols",
            "allowed_order_types",
            "paper_gate_assessment_sha256",
            "adapter_conformance_sha256",
            "recovery_drill_sha256",
            "manual_approval_reference",
            "not_after",
            "capital_cap",
            "allocated_notional_at_authorization",
            "paper_gate_passed",
            "read_only_shadow_passed",
            "sandbox_certification_passed",
            "kill_switch_test_passed",
            "authorization_sha256",
        }
        if set(value) != expected_fields:
            raise ValueError("live authorization fields do not match schema")
        if value.get("schema") != LIVE_AUTHORIZATION_SCHEMA:
            raise ValueError("unsupported live authorization schema")
        not_after = value["not_after"]
        parsed_not_after = (
            datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
            if not isinstance(not_after, datetime)
            else not_after
        )
        authorization = cls(
            authorization_id=str(value["authorization_id"]),
            strategy_id=str(value["strategy_id"]),
            policy_sha256=str(value["policy_sha256"]),
            account_fingerprint=str(value["account_fingerprint"]),
            allowed_symbols=tuple(str(item) for item in value["allowed_symbols"]),
            allowed_order_types=tuple(
                str(item).lower() for item in value["allowed_order_types"]
            ),
            paper_gate_assessment_sha256=str(value["paper_gate_assessment_sha256"]),
            adapter_conformance_sha256=str(value["adapter_conformance_sha256"]),
            recovery_drill_sha256=str(value["recovery_drill_sha256"]),
            manual_approval_reference=str(value["manual_approval_reference"]),
            not_after=_utc(parsed_not_after),
            capital_cap=_positive_decimal(value["capital_cap"], "capital_cap"),
            allocated_notional_at_authorization=Decimal(
                str(value.get("allocated_notional_at_authorization", 0))
            ),
            paper_gate_passed=value["paper_gate_passed"] is True,
            read_only_shadow_passed=value["read_only_shadow_passed"] is True,
            sandbox_certification_passed=value["sandbox_certification_passed"] is True,
            kill_switch_test_passed=value["kill_switch_test_passed"] is True,
            authorization_sha256=str(value.get("authorization_sha256") or ""),
        )
        if authorization.authorization_sha256 != authorization.evidence()[
            "authorization_sha256"
        ]:
            raise ValueError("live authorization hash mismatch")
        return authorization


@dataclass(frozen=True)
class LiveStrategyAllocation:
    """One child strategy's immutable scope inside a parent authorization."""

    strategy_id: str
    allowed_symbols: tuple[str, ...]
    capital_cap: Decimal
    allocated_notional_at_authorization: Decimal

    def evidence(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "allowed_symbols": list(self.allowed_symbols),
            "capital_cap": str(self.capital_cap),
            "allocated_notional_at_authorization": str(
                self.allocated_notional_at_authorization
            ),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "LiveStrategyAllocation":
        required = {
            "strategy_id",
            "allowed_symbols",
            "capital_cap",
            "allocated_notional_at_authorization",
        }
        if set(value) != required:
            raise ValueError("live strategy allocation fields do not match schema")
        allocated = _nonnegative_decimal(
            value["allocated_notional_at_authorization"],
            "allocated_notional_at_authorization",
        )
        return cls(
            strategy_id=str(value["strategy_id"]),
            allowed_symbols=tuple(str(item) for item in value["allowed_symbols"]),
            capital_cap=_positive_decimal(value["capital_cap"], "capital_cap"),
            allocated_notional_at_authorization=allocated,
        )


@dataclass(frozen=True)
class ParentLiveAuthorization:
    """Batch-scoped authorization for a deterministic multi-strategy parent plan.

    The authorization binds the normalized child-intent manifest rather than a
    parent-plan hash.  This avoids a circular dependency because the eventual
    LIVE_AUTHORIZED plan itself must bind this authorization's content hash.
    """

    authorization_id: str
    policy_sha256: str
    account_fingerprint: str
    authorized_batch_request_sha256: str
    authorized_trade_date: str
    authorized_child_intents_sha256: str
    platform_preflight_sha256: str
    pretrade_execution_batch_sha256: str
    strategy_allocations: tuple[LiveStrategyAllocation, ...]
    allowed_order_types: tuple[str, ...]
    paper_gate_assessment_sha256: str
    adapter_conformance_sha256: str
    recovery_drill_sha256: str
    manual_approval_reference: str
    not_after: datetime
    capital_cap: Decimal
    paper_gate_passed: bool
    read_only_shadow_passed: bool
    sandbox_certification_passed: bool
    kill_switch_test_passed: bool
    authorization_sha256: str = ""

    @property
    def authorized_strategy_ids(self) -> tuple[str, ...]:
        return tuple(item.strategy_id for item in self.strategy_allocations)

    @property
    def allowed_symbols(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    symbol
                    for allocation in self.strategy_allocations
                    for symbol in allocation.allowed_symbols
                }
            )
        )

    @property
    def allocated_notional_at_authorization(self) -> Decimal:
        return sum(
            (
                item.allocated_notional_at_authorization
                for item in self.strategy_allocations
            ),
            Decimal("0"),
        )

    def evidence(self) -> dict[str, Any]:
        identity = {
            "schema": PARENT_LIVE_AUTHORIZATION_SCHEMA,
            "authorization_id": self.authorization_id,
            "policy_sha256": self.policy_sha256,
            "account_fingerprint": self.account_fingerprint,
            "authorized_batch_request_sha256": (
                self.authorized_batch_request_sha256
            ),
            "authorized_trade_date": self.authorized_trade_date,
            "authorized_child_intents_sha256": (
                self.authorized_child_intents_sha256
            ),
            "platform_preflight_sha256": self.platform_preflight_sha256,
            "pretrade_execution_batch_sha256": (
                self.pretrade_execution_batch_sha256
            ),
            "strategy_allocations": [
                item.evidence()
                for item in sorted(
                    self.strategy_allocations, key=lambda item: item.strategy_id
                )
            ],
            "allowed_order_types": list(self.allowed_order_types),
            "paper_gate_assessment_sha256": self.paper_gate_assessment_sha256,
            "adapter_conformance_sha256": self.adapter_conformance_sha256,
            "recovery_drill_sha256": self.recovery_drill_sha256,
            "manual_approval_reference": self.manual_approval_reference,
            "not_after": _utc(self.not_after).isoformat(),
            "capital_cap": str(self.capital_cap),
            "paper_gate_passed": self.paper_gate_passed,
            "read_only_shadow_passed": self.read_only_shadow_passed,
            "sandbox_certification_passed": self.sandbox_certification_passed,
            "kill_switch_test_passed": self.kill_switch_test_passed,
        }
        return {**identity, "authorization_sha256": sha256_digest(identity)}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ParentLiveAuthorization":
        expected_fields = {
            "schema",
            "authorization_id",
            "policy_sha256",
            "account_fingerprint",
            "authorized_batch_request_sha256",
            "authorized_trade_date",
            "authorized_child_intents_sha256",
            "platform_preflight_sha256",
            "pretrade_execution_batch_sha256",
            "strategy_allocations",
            "allowed_order_types",
            "paper_gate_assessment_sha256",
            "adapter_conformance_sha256",
            "recovery_drill_sha256",
            "manual_approval_reference",
            "not_after",
            "capital_cap",
            "paper_gate_passed",
            "read_only_shadow_passed",
            "sandbox_certification_passed",
            "kill_switch_test_passed",
            "authorization_sha256",
        }
        if set(value) != expected_fields:
            raise ValueError("parent live authorization fields do not match schema")
        if value.get("schema") != PARENT_LIVE_AUTHORIZATION_SCHEMA:
            raise ValueError("unsupported parent live authorization schema")
        try:
            parsed_not_after = datetime.fromisoformat(
                str(value["not_after"]).replace("Z", "+00:00")
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("parent live authorization not_after is invalid") from exc
        allocations = tuple(
            LiveStrategyAllocation.from_dict(dict(item))
            for item in list(value["strategy_allocations"])
        )
        authorization = cls(
            authorization_id=str(value["authorization_id"]),
            policy_sha256=str(value["policy_sha256"]),
            account_fingerprint=str(value["account_fingerprint"]),
            authorized_batch_request_sha256=str(
                value["authorized_batch_request_sha256"]
            ),
            authorized_trade_date=str(value["authorized_trade_date"]),
            authorized_child_intents_sha256=str(
                value["authorized_child_intents_sha256"]
            ),
            platform_preflight_sha256=str(value["platform_preflight_sha256"]),
            pretrade_execution_batch_sha256=str(
                value["pretrade_execution_batch_sha256"]
            ),
            strategy_allocations=allocations,
            allowed_order_types=tuple(
                str(item).lower() for item in value["allowed_order_types"]
            ),
            paper_gate_assessment_sha256=str(
                value["paper_gate_assessment_sha256"]
            ),
            adapter_conformance_sha256=str(value["adapter_conformance_sha256"]),
            recovery_drill_sha256=str(value["recovery_drill_sha256"]),
            manual_approval_reference=str(value["manual_approval_reference"]),
            not_after=_utc(parsed_not_after),
            capital_cap=_positive_decimal(value["capital_cap"], "capital_cap"),
            paper_gate_passed=value["paper_gate_passed"] is True,
            read_only_shadow_passed=value["read_only_shadow_passed"] is True,
            sandbox_certification_passed=(
                value["sandbox_certification_passed"] is True
            ),
            kill_switch_test_passed=value["kill_switch_test_passed"] is True,
            authorization_sha256=str(value["authorization_sha256"]),
        )
        if authorization.authorization_sha256 != authorization.evidence()[
            "authorization_sha256"
        ]:
            raise ValueError("parent live authorization hash mismatch")
        return authorization


BrokerLiveAuthorization = LiveAuthorization | ParentLiveAuthorization


class ReadOnlySnapshotAdapter:
    """Offline adapter for importing a broker statement without order methods."""

    environment = "snapshot"

    def __init__(
        self,
        *,
        adapter_id: str,
        account_fingerprint: str,
        account: dict[str, Any],
        positions: list[dict[str, Any]],
        orders: list[dict[str, Any]],
        atomic_snapshot: dict[str, Any] | None = None,
    ) -> None:
        self.adapter_id = adapter_id
        self.adapter_version = "1.0.0"
        self.implementation_fingerprint = sha256_digest(
            {
                "adapter_id": adapter_id,
                "implementation": "ReadOnlySnapshotAdapter/v1",
            }
        )
        self.account_fingerprint = account_fingerprint
        self._account = dict(account)
        self._positions = [dict(item) for item in positions]
        self._orders = [dict(item) for item in orders]
        self._atomic_snapshot = (
            dict(atomic_snapshot) if atomic_snapshot is not None else None
        )

    def capabilities(self) -> set[str]:
        capabilities = set(READ_ONLY_CAPABILITIES)
        if self._atomic_snapshot is not None:
            capabilities.add(BrokerCapability.ATOMIC_ACCOUNT_SNAPSHOT_READ.value)
        return capabilities

    def get_account(self) -> dict[str, Any]:
        return dict(self._account)

    def get_positions(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._positions]

    def list_orders(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._orders]

    def submit_paper_order(self, intent: dict[str, Any]) -> dict[str, Any]:
        raise BrokerPermissionError("snapshot adapter has no order capability")

    def submit_live_order(self, intent: dict[str, Any]) -> dict[str, Any]:
        raise BrokerPermissionError("snapshot adapter has no order capability")

    def cancel_order(self, broker_order_id: str) -> dict[str, Any]:
        raise BrokerPermissionError("snapshot adapter has no cancel capability")

    def find_order_by_client_id(self, client_order_id: str) -> dict[str, Any] | None:
        return None

    def get_daily_order_usage(self, trade_date: str) -> dict[str, Any]:
        return {"order_count": 0, "notional": "0"}

    def get_atomic_account_snapshot(self) -> dict[str, Any]:
        if self._atomic_snapshot is None:
            raise BrokerPermissionError(
                "snapshot adapter has no atomic account snapshot evidence"
            )
        return dict(self._atomic_snapshot)


class BrokerSafetyEnvelope:
    """Stateful safety interlock around a broker adapter.

    Live mode requires an explicit policy switch *and* independent evidence.
    A halt is sticky: only an operator acknowledgement can return to read-only.
    """

    def __init__(
        self,
        adapter: BrokerAdapter,
        policy: BrokerSafetyPolicy,
        *,
        order_journal: BrokerOrderJournal | None = None,
        report_consumer: BrokerReportConsumer | None = None,
        account_reservation_book: BrokerAccountReservationBook | None = None,
        account_snapshot_collector: BrokerAccountSnapshotCollector | None = None,
        session_continuity_gate: BrokerSessionContinuityGate | None = None,
        adapter_certification_registry: (
            BrokerAdapterCertificationRegistry | None
        ) = None,
    ) -> None:
        self.adapter = adapter
        self.policy = policy
        self.order_journal = order_journal
        self.report_consumer = report_consumer
        self.account_reservation_book = account_reservation_book
        self.account_snapshot_collector = account_snapshot_collector
        self.session_continuity_gate = session_continuity_gate
        self.adapter_certification_registry = adapter_certification_registry
        self.mode = BrokerMode.DISCONNECTED
        self.authorization: BrokerLiveAuthorization | None = None
        self.halt_reason: str | None = None
        self.events: list[dict[str, Any]] = []
        self._sequence = 0
        self._operations: dict[str, dict[str, Any]] = {}
        self._daily_usage: dict[str, dict[str, Decimal | int]] = {}
        self._authorized_buy_notional = Decimal("0")
        self._event("BOUNDARY_CREATED", {"policy_id": policy.policy_id})

    @property
    def capabilities(self) -> set[str]:
        return {
            item.value if isinstance(item, BrokerCapability) else str(item)
            for item in self.adapter.capabilities()
        }

    @classmethod
    def _sanitize_event_value(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): cls._sanitize_event_value(item)
                for key, item in value.items()
                if not any(
                    marker in str(key).lower()
                    for marker in ("secret", "credential", "token", "password")
                )
            }
        if isinstance(value, (list, tuple)):
            return [cls._sanitize_event_value(item) for item in value]
        return value

    def _event(self, kind: str, detail: dict[str, Any]) -> None:
        self._sequence += 1
        safe_detail = self._sanitize_event_value(detail)
        self.events.append(
            {
                "sequence": self._sequence,
                "kind": kind,
                "mode": self.mode.value,
                "detail": safe_detail,
            }
        )

    def _require_live_journal(
        self, *, allow_ambiguous_operation_key: str | None = None
    ) -> BrokerOrderJournal:
        journal = self.order_journal
        if journal is None:
            self.halt("durable broker order journal is unavailable")
            raise BrokerSafetyError(
                "durable broker order journal is unavailable; boundary halted"
            )
        if journal.account_fingerprint != self.adapter.account_fingerprint:
            self.halt("durable broker order journal account mismatch")
            raise BrokerSafetyError(
                "durable broker order journal account mismatch; boundary halted"
            )
        inspection = journal.inspect()
        settlement_inspection = journal.inspect_fill_settlements()
        unexpected_ambiguous = [
            key
            for key in inspection["ambiguous_operation_keys"]
            if key != allow_ambiguous_operation_key
        ]
        if (
            inspection["status"] not in {"EMPTY", "READY"}
            or unexpected_ambiguous
            or settlement_inspection["status"] not in {"EMPTY", "READY"}
        ):
            self.halt("durable broker order journal is degraded")
            raise BrokerSafetyError(
                "durable broker order journal is degraded; boundary halted"
            )
        return journal

    def _require_live_report_consumer(self) -> BrokerReportConsumer:
        consumer = self.report_consumer
        if consumer is None:
            self.halt("trusted broker report consumer is unavailable")
            raise BrokerSafetyError(
                "trusted broker report consumer is unavailable; boundary halted"
            )
        inspection = consumer.inspect()
        if (
            consumer.adapter_id != self.adapter.adapter_id
            or consumer.account_fingerprint != self.adapter.account_fingerprint
            or consumer.journal is not self.order_journal
            or consumer.account_reservation_book is not self.account_reservation_book
            or inspection["status"] not in {"EMPTY", "READY"}
        ):
            self.halt("trusted broker report consumer is degraded or misbound")
            raise BrokerSafetyError(
                "trusted broker report consumer is degraded or misbound; boundary halted"
            )
        return consumer

    def _require_account_reservation_book(
        self,
        *,
        now: datetime,
        allow_pending_operation_key: str | None = None,
    ) -> BrokerAccountReservationBook:
        book = self.account_reservation_book
        collector = self.account_snapshot_collector
        if book is None:
            self.halt("account reservation book is unavailable")
            raise BrokerSafetyError(
                "account reservation book is unavailable; boundary halted"
            )
        collector_inspection = (
            collector.inspect() if collector is not None else None
        )
        try:
            collected_snapshot = (
                collector.snapshot_by_sha256(book.snapshot_sha256)
                if collector is not None
                and collector_inspection is not None
                and collector_inspection["status"] == "READY"
                else None
            )
        except BrokerAccountSnapshotCollectorError as exc:
            self.halt("trusted account snapshot collector is degraded")
            raise BrokerSafetyError(
                "trusted account snapshot collector is degraded; boundary halted"
            ) from exc
        if (
            collector is None
            or collector.adapter is not self.adapter
            or collector.adapter_id != self.adapter.adapter_id
            or collector.account_fingerprint != self.adapter.account_fingerprint
            or collector_inspection is None
            or collector_inspection["status"] != "READY"
            or collected_snapshot != book.account_snapshot
        ):
            self.halt("trusted account snapshot collector is degraded or misbound")
            raise BrokerSafetyError(
                "trusted account snapshot collector is degraded or misbound; boundary halted"
            )
        inspection = book.inspect()
        recoverable = set(inspection["unresolved_operation_keys"])
        recoverable.update(inspection["pending_lifecycle_operation_keys"])
        recoverable.update(inspection["pending_reconciliation_operation_keys"])
        unexpected = sorted(
            key for key in recoverable if key != allow_pending_operation_key
        )
        try:
            received_at = datetime.fromisoformat(
                str(book.account_snapshot["received_at"])
            ).astimezone(timezone.utc)
            snapshot_age = (now - received_at).total_seconds()
        except (KeyError, TypeError, ValueError) as exc:
            self.halt("account reservation snapshot timestamp is invalid")
            raise BrokerSafetyError(
                "account reservation snapshot timestamp is invalid; boundary halted"
            ) from exc
        valid_status = inspection["status"] == "READY" or (
            inspection["status"]
            in {"PENDING_LIFECYCLE", "PENDING_RECONCILIATION", "UNRESOLVED"}
            and not unexpected
            and allow_pending_operation_key is not None
        )
        if (
            book.adapter_id != self.adapter.adapter_id
            or book.account_fingerprint != self.adapter.account_fingerprint
            or book.journal is not self.order_journal
            or book.trade_date != now.date().isoformat()
            or snapshot_age < 0
            or snapshot_age > int(book.policy["max_snapshot_age_seconds"])
            or not valid_status
        ):
            self.halt("account reservation book is stale, degraded or misbound")
            raise BrokerSafetyError(
                "account reservation book is stale, degraded or misbound; boundary halted"
            )
        return book

    def _require_prior_session_reconciliation(
        self, *, now: datetime
    ) -> dict[str, Any]:
        gate = self.session_continuity_gate
        try:
            assessment = (
                gate.assess(now.date().isoformat()) if gate is not None else None
            )
        except BrokerSessionContinuityError as exc:
            self.halt("prior-session reconciliation gate is degraded")
            raise BrokerSafetyError(
                "prior-session reconciliation gate is degraded; boundary halted"
            ) from exc
        if (
            gate is None
            or gate.adapter_id != self.adapter.adapter_id
            or gate.account_fingerprint != self.adapter.account_fingerprint
            or gate.account_snapshot_collector is not self.account_snapshot_collector
            or assessment is None
            or assessment.get("admitted") is not True
        ):
            self.halt("prior-session reconciliation is missing, failed or misbound")
            raise BrokerSafetyError(
                "prior-session reconciliation is missing, failed or misbound; "
                "new live orders are blocked and the boundary is halted"
            )
        return assessment

    def _adapter_certification_state(
        self,
        authorization: BrokerLiveAuthorization | None,
        *,
        now: datetime,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None, bool]:
        registry = self.adapter_certification_registry
        inspection = registry.inspect() if registry is not None else None
        try:
            report = (
                registry.resolve(authorization.adapter_conformance_sha256)
                if registry is not None
                and authorization is not None
                and inspection is not None
                and inspection.get("status") == "READY"
                else None
            )
            completed_at = (
                datetime.fromisoformat(str(report["completed_at"])).astimezone(
                    timezone.utc
                )
                if report is not None
                else None
            )
            valid_until = (
                datetime.fromisoformat(str(report["valid_until"])).astimezone(
                    timezone.utc
                )
                if report is not None
                else None
            )
        except (
            BrokerAdapterCertificationError,
            KeyError,
            TypeError,
            ValueError,
        ):
            report = None
            completed_at = None
            valid_until = None
        implementation_fingerprint = str(
            getattr(self.adapter, "implementation_fingerprint", "") or ""
        ).lower()
        adapter_version = str(
            getattr(self.adapter, "adapter_version", "") or ""
        )
        ready = (
            registry is not None
            and registry.adapter_id == self.adapter.adapter_id
            and inspection is not None
            and inspection.get("status") == "READY"
            and report is not None
            and report.get("status") == "PASS"
            and report.get("environment") == "sandbox"
            and report.get("adapter_id") == self.adapter.adapter_id
            and report.get("adapter_version") == adapter_version
            and report.get("adapter_implementation_sha256")
            == implementation_fingerprint
            and SHA256_RE.fullmatch(implementation_fingerprint) is not None
            and completed_at is not None
            and valid_until is not None
            and completed_at <= now < valid_until
            and set(REQUIRED_BROKER_ADAPTER_CAPABILITIES) <= self.capabilities
        )
        return inspection, report, ready

    def _require_adapter_certification(
        self, *, now: datetime
    ) -> dict[str, Any]:
        inspection, report, ready = self._adapter_certification_state(
            self.authorization, now=now
        )
        if not ready or report is None:
            self.halt(
                "adapter sandbox certification is missing, revoked, expired or misbound"
            )
            raise BrokerSafetyError(
                "adapter sandbox certification is missing, revoked, expired or "
                "misbound; new live orders are blocked and the boundary is halted"
            )
        return {
            "inspection": inspection,
            "report": report,
        }

    def _reconcile_account_reservation(
        self, operation_key: str, lifecycle_event: dict[str, Any]
    ) -> dict[str, Any]:
        book = self.account_reservation_book
        try:
            if (
                book is None
                or book.adapter_id != self.adapter.adapter_id
                or book.account_fingerprint != self.adapter.account_fingerprint
                or book.journal is not self.order_journal
            ):
                raise BrokerAccountControlError(
                    "account reservation book is unavailable or misbound"
                )
            inspection = book.inspect()
            pending = set(inspection["unresolved_operation_keys"])
            pending.update(inspection["pending_lifecycle_operation_keys"])
            pending.update(inspection["pending_reconciliation_operation_keys"])
            if inspection["status"] == "DEGRADED" or pending - {operation_key}:
                raise BrokerAccountControlError(
                    "another account reservation operation is unresolved"
                )
            return book.reconcile_lifecycle(lifecycle_event)
        except (BrokerAccountControlError, KeyError, TypeError, ValueError) as exc:
            self.halt("account reservation could not follow order lifecycle")
            raise BrokerSafetyError(
                "account reservation could not follow order lifecycle; boundary halted"
            ) from exc

    def _settle_live_parent_fill(
        self,
        operation_key: str,
        *,
        allocation_plan: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        journal = self._require_live_journal(
            allow_ambiguous_operation_key=operation_key
        )
        try:
            if allocation_plan is None:
                return journal.settle_latest_parent_fill_for_operation(
                    operation_key
                )
            return journal.settle_latest_parent_fill(
                allocation_plan, operation_key
            )
        except BrokerOrderJournalError as exc:
            self.halt("parent fill settlement could not be durably reconciled")
            raise BrokerSafetyError(
                "parent fill settlement could not be durably reconciled; boundary halted"
            ) from exc

    @staticmethod
    def _exact_nonnegative_integer(value: Any, label: str) -> int:
        if isinstance(value, bool) or not (
            isinstance(value, int)
            or (isinstance(value, str) and value.strip().isdigit())
        ):
            raise BrokerSafetyError(f"{label} must be an exact integer")
        parsed = int(value)
        if parsed < 0:
            raise BrokerSafetyError(f"{label} must be nonnegative")
        return parsed

    @classmethod
    def _normalize_broker_snapshot(
        cls,
        snapshot: dict[str, Any],
        *,
        order_quantity: int,
        previous: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(snapshot, dict):
            raise BrokerSafetyError("broker order snapshot must be an object")
        raw_status = str(snapshot.get("status") or "").strip().lower().replace("-", "_")
        status_map = {
            "accepted": "ACCEPTED",
            "new": "ACCEPTED",
            "open": "ACCEPTED",
            "pending": "ACCEPTED",
            "partially_filled": "PARTIALLY_FILLED",
            "partial_fill": "PARTIALLY_FILLED",
            "filled": "FILLED",
            "cancel_requested": "CANCEL_PENDING",
            "pending_cancel": "CANCEL_PENDING",
            "cancel_pending": "CANCEL_PENDING",
            "cancelled": "CANCELLED",
            "canceled": "CANCELLED",
            "rejected": "REJECTED",
            "failed": "REJECTED",
            "unknown": "UNKNOWN",
        }
        if raw_status not in status_map:
            raise BrokerSafetyError("broker order status is unsupported")
        prior = previous or {}
        raw_filled = snapshot.get(
            "cumulative_filled_quantity",
            snapshot.get(
                "filled_quantity", prior.get("cumulative_filled_quantity", 0)
            ),
        )
        filled = cls._exact_nonnegative_integer(
            raw_filled, "cumulative_filled_quantity"
        )
        fee_fen = cls._exact_nonnegative_integer(
            snapshot.get("cumulative_fee_fen", prior.get("cumulative_fee_fen", 0)),
            "cumulative_fee_fen",
        )
        status = status_map[raw_status]
        if status == "ACCEPTED" and filled > 0:
            status = "FILLED" if filled == order_quantity else "PARTIALLY_FILLED"
        elif status == "CANCEL_PENDING" and filled == order_quantity:
            status = "FILLED"
        average_price = snapshot.get("average_price", prior.get("average_price"))
        broker_order_id = str(
            snapshot.get("broker_order_id")
            or prior.get("broker_order_id")
            or ""
        ).strip() or None
        if status not in {"REJECTED", "UNKNOWN"} and broker_order_id is None:
            raise BrokerSafetyError("broker order snapshot has no broker_order_id")
        return {
            "status": status,
            "broker_order_id": broker_order_id,
            "cumulative_filled_quantity": filled,
            "average_price": average_price,
            "cumulative_fee_fen": fee_fen,
        }

    def _mark_lifecycle_unknown(
        self,
        operation_key: str,
        *,
        recorded_at: datetime,
        event_type: str,
    ) -> None:
        try:
            unknown = self._require_live_journal(
                allow_ambiguous_operation_key=operation_key
            ).mark_unknown(
                operation_key,
                recorded_at=recorded_at,
                event_type=event_type,
            )
            self._reconcile_account_reservation(operation_key, unknown)
        except BrokerOrderJournalError:
            self.halt("broker order outcome is unknown and journal update failed")

    def _reconcile_lifecycle_snapshot(
        self,
        operation_key: str,
        snapshot: dict[str, Any],
        *,
        order_quantity: int,
        recorded_at: datetime,
    ) -> dict[str, Any]:
        journal = self._require_live_journal(
            allow_ambiguous_operation_key=operation_key
        )
        try:
            previous = journal.latest(operation_key)
            if previous is None:
                raise BrokerOrderJournalConflict(
                    "broker snapshot lacks prepared operation"
                )
            normalized = self._normalize_broker_snapshot(
                snapshot,
                order_quantity=order_quantity,
                previous=previous,
            )
            if (
                previous["status"] == "SUBMITTING"
                and normalized["status"] in {"ACCEPTED", "REJECTED"}
                and normalized["cumulative_filled_quantity"] == 0
                and normalized["cumulative_fee_fen"] == 0
            ):
                lifecycle = journal.acknowledge_submission(
                    operation_key,
                    recorded_at=recorded_at,
                    broker_order_id=normalized["broker_order_id"],
                    accepted=normalized["status"] == "ACCEPTED",
                )
            else:
                lifecycle = journal.reconcile(
                    operation_key,
                    recorded_at=recorded_at,
                    **normalized,
                )
            self._reconcile_account_reservation(operation_key, lifecycle)
            return lifecycle
        except (
            BrokerOrderJournalError,
            BrokerAccountControlError,
            BrokerSafetyError,
        ) as exc:
            self.halt("broker snapshot conflicts with durable order lifecycle")
            raise BrokerSafetyError(
                "broker snapshot conflicts with durable order lifecycle; boundary halted"
            ) from exc

    def _require_capabilities(self, required: set[str]) -> None:
        missing = sorted(required - self.capabilities)
        if missing:
            raise BrokerPermissionError(f"adapter is missing capabilities: {', '.join(missing)}")

    def connect_read_only(self) -> dict[str, Any]:
        if self.mode == BrokerMode.HALTED:
            raise BrokerPermissionError("halt must be acknowledged before reconnecting")
        if self.adapter.adapter_id not in self.policy.allowed_read_only_adapters:
            raise BrokerPermissionError("adapter is not approved for read-only access")
        self._require_capabilities(set(READ_ONLY_CAPABILITIES))
        self.authorization = None
        self.mode = BrokerMode.READ_ONLY
        self._event("READ_ONLY_CONNECTED", {"adapter_id": self.adapter.adapter_id})
        return self.status()

    def enable_paper(self) -> dict[str, Any]:
        if self.mode != BrokerMode.READ_ONLY:
            raise BrokerPermissionError("paper mode can only be entered from read-only")
        self._require_capabilities({BrokerCapability.PAPER_ORDER.value})
        self.mode = BrokerMode.PAPER
        self._event("PAPER_ENABLED", {"adapter_id": self.adapter.adapter_id})
        return self.status()

    def lock_live(self) -> dict[str, Any]:
        """Expose the intended transition while retaining a fail-closed lock."""
        if self.mode not in {BrokerMode.READ_ONLY, BrokerMode.PAPER}:
            raise BrokerPermissionError("live lock can only be prepared from read-only or paper")
        self.authorization = None
        self.mode = BrokerMode.LIVE_LOCKED
        self._event("LIVE_LOCK_PREPARED", {"adapter_id": self.adapter.adapter_id})
        return self.status()

    def activate_live(
        self,
        authorization: BrokerLiveAuthorization,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _utc(now)
        if self.mode != BrokerMode.LIVE_LOCKED:
            raise BrokerPermissionError("live activation requires LIVE_LOCKED mode")
        if not self.policy.real_orders_enabled:
            raise BrokerPermissionError("policy master switch disables real orders")
        if self.adapter.environment.lower() != "live":
            raise BrokerPermissionError("adapter is not connected to a live environment")
        if self.adapter.adapter_id not in self.policy.allowed_live_adapters:
            raise BrokerPermissionError("adapter is not approved for live access")
        if self.adapter.account_fingerprint not in self.policy.allowed_live_accounts:
            raise BrokerPermissionError("account fingerprint is not approved for live access")
        self._require_capabilities(
            set(READ_ONLY_CAPABILITIES)
            | {
                BrokerCapability.LIVE_ORDER.value,
                BrokerCapability.CANCEL_ORDER.value,
                BrokerCapability.CLIENT_ORDER_IDEMPOTENCY.value,
                BrokerCapability.DAILY_USAGE_READ.value,
            }
        )
        policy_sha = str(self.policy.evidence()["policy_sha256"])
        if isinstance(authorization, ParentLiveAuthorization):
            strategy_ids = list(authorization.authorized_strategy_ids)
            allocations = list(authorization.strategy_allocations)
            parent_batch_bindings = all(
                SHA256_RE.fullmatch(value.strip())
                for value in (
                    authorization.authorized_batch_request_sha256,
                    authorization.authorized_child_intents_sha256,
                    authorization.platform_preflight_sha256,
                    authorization.pretrade_execution_batch_sha256,
                )
            )
            try:
                canonical_trade_date = date.fromisoformat(
                    authorization.authorized_trade_date
                ).isoformat()
            except ValueError:
                canonical_trade_date = ""
            strategy_allocations_valid = (
                bool(allocations)
                and len(strategy_ids) == len(set(strategy_ids))
                and all(
                    BROKER_STRATEGY_RE.fullmatch(item.strategy_id.strip())
                    and item.capital_cap.is_finite()
                    and Decimal("0") < item.capital_cap <= authorization.capital_cap
                    and item.allocated_notional_at_authorization.is_finite()
                    and Decimal("0")
                    <= item.allocated_notional_at_authorization
                    <= item.capital_cap
                    and bool(item.allowed_symbols)
                    and len(item.allowed_symbols) == len(set(item.allowed_symbols))
                    and all(
                        BROKER_SYMBOL_RE.fullmatch(symbol)
                        for symbol in item.allowed_symbols
                    )
                    for item in allocations
                )
                and authorization.allocated_notional_at_authorization
                <= authorization.capital_cap
            )
        else:
            strategy_ids = [authorization.strategy_id]
            parent_batch_bindings = True
            canonical_trade_date = "legacy-single-strategy"
            strategy_allocations_valid = True
        journal_inspection = (
            self.order_journal.inspect() if self.order_journal is not None else None
        )
        settlement_inspection = (
            self.order_journal.inspect_fill_settlements()
            if self.order_journal is not None
            else None
        )
        report_inspection = (
            self.report_consumer.inspect()
            if self.report_consumer is not None
            else None
        )
        account_reservation_inspection = (
            self.account_reservation_book.inspect()
            if self.account_reservation_book is not None
            else None
        )
        account_collection_inspection = (
            self.account_snapshot_collector.inspect()
            if self.account_snapshot_collector is not None
            else None
        )
        durable_journal_valid = (
            self.order_journal is not None
            and self.order_journal.account_fingerprint
            == self.adapter.account_fingerprint
            and journal_inspection is not None
            and journal_inspection["status"] in {"EMPTY", "READY"}
            and settlement_inspection is not None
            and settlement_inspection["status"] in {"EMPTY", "READY"}
        )
        trusted_report_consumer_valid = (
            self.report_consumer is not None
            and self.report_consumer.adapter_id == self.adapter.adapter_id
            and self.report_consumer.account_fingerprint
            == self.adapter.account_fingerprint
            and self.report_consumer.journal is self.order_journal
            and self.report_consumer.account_reservation_book
            is self.account_reservation_book
            and report_inspection is not None
            and report_inspection["status"] in {"EMPTY", "READY"}
        )
        try:
            account_snapshot_received_at = (
                datetime.fromisoformat(
                    str(self.account_reservation_book.account_snapshot["received_at"])
                ).astimezone(timezone.utc)
                if self.account_reservation_book is not None
                else None
            )
            account_snapshot_age = (
                (moment - account_snapshot_received_at).total_seconds()
                if account_snapshot_received_at is not None
                else None
            )
        except (KeyError, TypeError, ValueError):
            account_snapshot_age = None
        account_reservation_valid = (
            self.account_reservation_book is not None
            and self.account_reservation_book.adapter_id == self.adapter.adapter_id
            and self.account_reservation_book.account_fingerprint
            == self.adapter.account_fingerprint
            and self.account_reservation_book.journal is self.order_journal
            and self.account_reservation_book.trade_date
            == moment.date().isoformat()
            and account_reservation_inspection is not None
            and account_reservation_inspection["status"]
            in {
                "READY",
                "PENDING_LIFECYCLE",
                "PENDING_RECONCILIATION",
                "UNRESOLVED",
            }
            and account_snapshot_age is not None
            and 0 <= account_snapshot_age
            <= int(
                self.account_reservation_book.policy[
                    "max_snapshot_age_seconds"
                ]
            )
        )
        try:
            collected_account_snapshot = (
                self.account_snapshot_collector.snapshot_by_sha256(
                    self.account_reservation_book.snapshot_sha256
                )
                if self.account_snapshot_collector is not None
                and self.account_reservation_book is not None
                and account_collection_inspection is not None
                and account_collection_inspection["status"] == "READY"
                else None
            )
        except BrokerAccountSnapshotCollectorError:
            collected_account_snapshot = None
        trusted_account_snapshot_collector_valid = (
            self.account_snapshot_collector is not None
            and self.account_snapshot_collector.adapter is self.adapter
            and self.account_snapshot_collector.adapter_id
            == self.adapter.adapter_id
            and self.account_snapshot_collector.account_fingerprint
            == self.adapter.account_fingerprint
            and account_collection_inspection is not None
            and account_collection_inspection["status"] == "READY"
            and self.account_reservation_book is not None
            and collected_account_snapshot
            == self.account_reservation_book.account_snapshot
        )
        admission_trade_date = (
            canonical_trade_date
            if isinstance(authorization, ParentLiveAuthorization)
            else moment.date().isoformat()
        )
        try:
            session_continuity_assessment = (
                self.session_continuity_gate.assess(admission_trade_date)
                if self.session_continuity_gate is not None
                else None
            )
        except BrokerSessionContinuityError:
            session_continuity_assessment = None
        prior_session_reconciliation_valid = (
            self.session_continuity_gate is not None
            and self.session_continuity_gate.adapter_id
            == self.adapter.adapter_id
            and self.session_continuity_gate.account_fingerprint
            == self.adapter.account_fingerprint
            and self.session_continuity_gate.account_snapshot_collector
            is self.account_snapshot_collector
            and session_continuity_assessment is not None
            and session_continuity_assessment.get("admitted") is True
        )
        (
            adapter_certification_inspection,
            adapter_certification_report,
            trusted_adapter_certification_valid,
        ) = self._adapter_certification_state(authorization, now=moment)
        checks = {
            "authorization_id": bool(authorization.authorization_id.strip()),
            "authorization_sha256": authorization.authorization_sha256
            == authorization.evidence()["authorization_sha256"],
            "strategy_ids": bool(strategy_ids)
            and len(strategy_ids) == len(set(strategy_ids))
            and all(BROKER_STRATEGY_RE.fullmatch(item) for item in strategy_ids),
            "strategy_allocations": strategy_allocations_valid,
            "parent_batch_bindings": parent_batch_bindings
            and canonical_trade_date == authorization.authorized_trade_date
            if isinstance(authorization, ParentLiveAuthorization)
            else True,
            "policy_sha256": authorization.policy_sha256 == policy_sha,
            "account_fingerprint": (
                authorization.account_fingerprint == self.adapter.account_fingerprint
            ),
            "paper_gate_assessment": (
                authorization.paper_gate_passed
                and bool(
                    SHA256_RE.fullmatch(
                        authorization.paper_gate_assessment_sha256.strip()
                    )
                )
            ),
            "adapter_conformance": (
                trusted_adapter_certification_valid
                if self.policy.require_trusted_adapter_certification_registry
                else bool(
                    SHA256_RE.fullmatch(
                        authorization.adapter_conformance_sha256.strip()
                    )
                )
            ),
            "manual_approval": bool(authorization.manual_approval_reference.strip()),
            "not_expired": moment < authorization.not_after,
            "ttl_bounded": (
                (authorization.not_after - moment).total_seconds()
                <= self.policy.authorization_ttl_minutes * 60
            ),
            "capital_cap": authorization.capital_cap.is_finite()
            and authorization.capital_cap <= self.policy.max_live_capital,
            "allocated_notional": (
                authorization.allocated_notional_at_authorization.is_finite()
                and
                Decimal("0") <= authorization.allocated_notional_at_authorization
                <= authorization.capital_cap
            ),
            "allowed_symbols": bool(authorization.allowed_symbols)
            and len(set(authorization.allowed_symbols))
            == len(authorization.allowed_symbols)
            and all(BROKER_SYMBOL_RE.fullmatch(item) for item in authorization.allowed_symbols),
            "allowed_order_types": bool(authorization.allowed_order_types)
            and len(set(authorization.allowed_order_types))
            == len(authorization.allowed_order_types)
            and set(authorization.allowed_order_types) <= {"limit", "market"},
            "read_only_shadow": (
                authorization.read_only_shadow_passed
                if self.policy.require_read_only_shadow
                else True
            ),
            "sandbox_certification": (
                authorization.sandbox_certification_passed
                if self.policy.require_sandbox_certification
                else True
            ),
            "recovery_drill": (
                bool(SHA256_RE.fullmatch(authorization.recovery_drill_sha256.strip()))
                if self.policy.require_recovery_drill
                else True
            ),
            "kill_switch_test": (
                authorization.kill_switch_test_passed
                if self.policy.require_kill_switch_test
                else True
            ),
            "durable_order_journal": (
                durable_journal_valid
                if self.policy.require_durable_order_journal
                else True
            ),
            "trusted_report_consumer": (
                trusted_report_consumer_valid
                if self.policy.require_trusted_report_consumer
                else True
            ),
            "account_reservation_book": (
                account_reservation_valid
                if self.policy.require_account_reservation_book
                else True
            ),
            "trusted_account_snapshot_collector": (
                trusted_account_snapshot_collector_valid
                if self.policy.require_trusted_account_snapshot_collector
                else True
            ),
            "prior_session_reconciliation": (
                prior_session_reconciliation_valid
                if self.policy.require_prior_session_reconciliation
                else True
            ),
        }
        failures = sorted(key for key, passed in checks.items() if not passed)
        if failures:
            raise BrokerPermissionError(f"live authorization rejected: {', '.join(failures)}")
        self.authorization = authorization
        self._authorized_buy_notional = Decimal("0")
        self.mode = BrokerMode.LIVE_ENABLED
        self._event(
            "LIVE_ENABLED",
            {
                "authorization_id": authorization.authorization_id,
                "authorization_schema": authorization.evidence()["schema"],
                "strategy_ids": strategy_ids,
                "account_fingerprint": authorization.account_fingerprint,
                "allowed_symbols": list(authorization.allowed_symbols),
                "allowed_order_types": list(authorization.allowed_order_types),
                "not_after": authorization.not_after.isoformat(),
                "capital_cap": str(authorization.capital_cap),
                "allocated_notional_at_authorization": str(
                    authorization.allocated_notional_at_authorization
                ),
                "durable_order_journal_status": (
                    journal_inspection["status"] if journal_inspection else None
                ),
                "recovery_only_ambiguous_operation_keys": (
                    journal_inspection["ambiguous_operation_keys"]
                    if journal_inspection
                    else []
                ),
                "durable_fill_settlement_status": (
                    settlement_inspection["status"]
                    if settlement_inspection
                    else None
                ),
                "trusted_report_consumer_status": (
                    report_inspection["status"] if report_inspection else None
                ),
                "account_reservation_status": (
                    account_reservation_inspection["status"]
                    if account_reservation_inspection
                    else None
                ),
                "account_snapshot_sha256": (
                    self.account_reservation_book.snapshot_sha256
                    if self.account_reservation_book is not None
                    else None
                ),
                "trusted_account_snapshot_collector_status": (
                    account_collection_inspection["status"]
                    if account_collection_inspection
                    else None
                ),
                "session_continuity_status": (
                    session_continuity_assessment["status"]
                    if session_continuity_assessment
                    else None
                ),
                "session_continuity_assessment_sha256": (
                    session_continuity_assessment["assessment_sha256"]
                    if session_continuity_assessment
                    else None
                ),
                "adapter_certification_report_sha256": (
                    adapter_certification_report["report_sha256"]
                    if adapter_certification_report
                    else None
                ),
                "adapter_certification_registry_status": (
                    adapter_certification_inspection["status"]
                    if adapter_certification_inspection
                    else None
                ),
            },
        )
        return self.status(now=moment)

    def consume_broker_report(
        self,
        report: dict[str, Any],
        *,
        allocation_plan: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Durably consume an asynchronous broker execution report.

        Gap and unknown outcomes are recorded first, then force a sticky halt.
        Reports remain consumable while halted so an operator can close a gap;
        returning to read-only still requires explicit acknowledgement.
        """

        consumer = self.report_consumer
        if consumer is None:
            self.halt("trusted broker report consumer is unavailable")
            raise BrokerSafetyError(
                "trusted broker report consumer is unavailable; boundary halted"
            )
        if (
            consumer.adapter_id != self.adapter.adapter_id
            or consumer.account_fingerprint != self.adapter.account_fingerprint
            or consumer.journal is not self.order_journal
        ):
            self.halt("trusted broker report consumer identity mismatch")
            raise BrokerSafetyError(
                "trusted broker report consumer identity mismatch; boundary halted"
            )
        try:
            result = consumer.consume(
                report,
                allocation_plan=allocation_plan,
            )
        except (BrokerReportConflict, BrokerReportConsumerError, OSError) as exc:
            self.halt("broker execution report failed trusted consumption")
            raise BrokerSafetyError(
                "broker execution report failed trusted consumption; boundary halted"
            ) from exc
        self._event(
            "BROKER_REPORT_CONSUMED",
            {
                "operation_key": result["operation_key"],
                "report_sha256": result["report_sha256"],
                "status": result["status"],
                "applied_count": len(result["applied"]),
                "next_expected_report_sequence": result[
                    "next_expected_report_sequence"
                ],
            },
        )
        if result["status"] not in {"READY"}:
            self.halt(
                "broker execution report sequence is incomplete or unresolved"
            )
        return result

    @staticmethod
    def _normalize_intent(intent: dict[str, Any]) -> tuple[dict[str, Any], Decimal]:
        code = str(intent.get("code") or "").strip()
        side = str(intent.get("side") or "").lower().strip()
        raw_quantity = intent.get("quantity")
        if isinstance(raw_quantity, bool) or not (
            isinstance(raw_quantity, int)
            or (
                isinstance(raw_quantity, str)
                and raw_quantity.strip().isdigit()
            )
        ):
            raise BrokerSafetyError("order quantity must be an exact integer")
        quantity = int(raw_quantity)
        order_type = str(intent.get("order_type") or "limit").lower().strip()
        price_value = intent.get("limit_price")
        if price_value is None:
            price_value = intent.get("reference_price")
        if not BROKER_SYMBOL_RE.fullmatch(code):
            raise BrokerSafetyError("order code is invalid")
        if side not in {"buy", "sell"}:
            raise BrokerSafetyError("order side must be buy or sell")
        if quantity <= 0:
            raise BrokerSafetyError("order quantity must be positive")
        if order_type not in {"limit", "market"}:
            raise BrokerSafetyError("unsupported order type")
        try:
            price = _positive_decimal(price_value, "limit_price/reference_price")
        except ValueError as exc:
            raise BrokerSafetyError(str(exc)) from exc
        normalized = {
            "code": code,
            "side": side,
            "quantity": quantity,
            "order_type": order_type,
            "limit_price": str(price) if order_type == "limit" else None,
            "reference_price": str(price),
        }
        return normalized, price * quantity

    def _live_authorization_valid(self, now: datetime) -> None:
        if self.authorization is None or now >= self.authorization.not_after:
            self.halt("live authorization expired")
            raise BrokerPermissionError("live authorization expired; boundary halted")

    def _recover_live_order(
        self,
        *,
        operation_key: str,
        intent_sha: str,
        client_order_id: str,
        normalized_intent: dict[str, Any],
        allocation_plan_sha256: str,
        allocation_plan: dict[str, Any],
        authorization_sha256: str,
        parent_order_id: str,
        recorded_at: datetime,
    ) -> dict[str, Any] | None:
        journal = self._require_live_journal(
            allow_ambiguous_operation_key=operation_key
        )
        try:
            latest = journal.latest(operation_key)
            inspection = journal.inspect()
        except BrokerOrderJournalError as exc:
            self.halt("durable broker order journal became unreadable")
            raise BrokerSafetyError(
                "durable broker order journal became unreadable; boundary halted"
            ) from exc
        if inspection["status"] not in {"EMPTY", "READY"}:
            self.halt("durable broker order journal became degraded")
            raise BrokerSafetyError(
                "durable broker order journal became degraded; boundary halted"
            )
        other_ambiguous = sorted(
            set(inspection["ambiguous_operation_keys"]) - {operation_key}
        )
        if other_ambiguous:
            self.halt("another live order has an unresolved broker outcome")
            raise BrokerSafetyError(
                "another live order has an unresolved broker outcome; boundary halted"
            )
        if latest is not None:
            expected_identity = {
                "client_order_id": client_order_id,
                "authorization_sha256": authorization_sha256,
                "intent_sha256": intent_sha,
                "allocation_plan_sha256": allocation_plan_sha256,
                "parent_order_id": parent_order_id,
                "order_quantity": normalized_intent["quantity"],
            }
            lifecycle_mismatches = sorted(
                field
                for field, expected in expected_identity.items()
                if latest.get(field) != expected
            )
            if lifecycle_mismatches:
                self.halt("operation conflicts with durable order identity")
                raise BrokerOperationConflict(
                    "operation conflicts with durable order identity: "
                    + ", ".join(lifecycle_mismatches)
                )
            if latest["status"] in TERMINAL_STATUSES:
                account_reservation = self._reconcile_account_reservation(
                    operation_key, latest
                )
                settlement = (
                    None
                    if latest["status"] == "REJECTED"
                    else self._settle_live_parent_fill(
                        operation_key, allocation_plan=allocation_plan
                    )
                )
                recovered_terminal = {
                    "operation_key": operation_key,
                    "intent_sha256": intent_sha,
                    "execution_mode": "live",
                    "broker_order_id": str(latest.get("broker_order_id") or ""),
                    "status": str(latest["status"]).lower(),
                    "idempotent": True,
                    "recovered_from_journal": True,
                    "client_order_id": client_order_id,
                    "allocation_plan_sha256": allocation_plan_sha256,
                    "cumulative_filled_quantity": latest[
                        "cumulative_filled_quantity"
                    ],
                    "average_price": latest["average_price"],
                    "cumulative_fee_fen": latest["cumulative_fee_fen"],
                    "lifecycle_event_sha256": latest["event_sha256"],
                    "fill_settlement_sha256": (
                        settlement["settlement_sha256"]
                        if settlement is not None
                        else None
                    ),
                    "account_reservation_event_sha256": account_reservation[
                        "event_sha256"
                    ],
                }
                self._operations[operation_key] = {
                    "intent_sha256": intent_sha,
                    "result": dict(recovered_terminal),
                }
                self._event(
                    "TERMINAL_ORDER_RECOVERED_FROM_JOURNAL",
                    {
                        "operation_key": operation_key,
                        "intent_sha256": intent_sha,
                        "status": latest["status"],
                        "lifecycle_event_sha256": latest["event_sha256"],
                    },
                )
                return recovered_terminal
        try:
            existing = self.adapter.find_order_by_client_id(client_order_id)
        except Exception as exc:
            self.halt("broker idempotency lookup is unavailable")
            raise BrokerSafetyError(
                "cannot determine whether the live order already exists; boundary halted"
            ) from exc
        if existing is None and latest is not None:
            self.halt("persisted live order is absent from broker lookup")
            raise BrokerSafetyError(
                "persisted live order outcome cannot be resolved; boundary halted"
            )
        if existing is None:
            return None
        if latest is None:
            self.halt("broker returned an unjournaled live order")
            raise BrokerSafetyError(
                "broker returned an unjournaled live order; boundary halted"
            )
        if not isinstance(existing, dict):
            self.halt("broker idempotency lookup returned an invalid record")
            raise BrokerSafetyError(
                "broker idempotency lookup is invalid; boundary halted"
            )
        comparable_fields = (
            "code",
            "side",
            "quantity",
            "order_type",
            "limit_price",
            "reference_price",
        )
        mismatches: list[str] = []
        for field in comparable_fields:
            actual = existing.get(field)
            expected = normalized_intent.get(field)
            if field == "quantity":
                try:
                    matches = (
                        not isinstance(actual, bool)
                        and int(actual) == int(expected)
                    )
                except (TypeError, ValueError):
                    matches = False
            elif field in {"limit_price", "reference_price"}:
                try:
                    matches = (
                        (actual is None and expected is None)
                        or Decimal(str(actual)) == Decimal(str(expected))
                    )
                except (InvalidOperation, ValueError):
                    matches = False
            else:
                matches = str(actual or "").lower() == str(expected or "").lower()
            if not matches:
                mismatches.append(field)
        if str(existing.get("allocation_plan_sha256") or "") != str(
            allocation_plan_sha256 or ""
        ):
            mismatches.append("allocation_plan_sha256")
        if mismatches:
            self.halt("broker idempotency lookup conflicts with frozen order intent")
            raise BrokerOperationConflict(
                "broker order conflicts with operation intent: "
                + ", ".join(mismatches)
            )
        lifecycle = self._reconcile_lifecycle_snapshot(
            operation_key,
            existing,
            order_quantity=normalized_intent["quantity"],
            recorded_at=recorded_at,
        )
        if lifecycle["status"] == "UNKNOWN":
            self.halt("broker lookup did not resolve the persisted order outcome")
            raise BrokerSafetyError(
                "persisted live order outcome remains unknown; boundary halted"
            )
        settlement = self._settle_live_parent_fill(
            operation_key, allocation_plan=allocation_plan
        )
        account_reservation = self.account_reservation_book.latest(operation_key)
        if account_reservation is None:
            self.halt("recovered broker order lacks account reservation")
            raise BrokerSafetyError(
                "recovered broker order lacks account reservation; boundary halted"
            )
        broker_order_id = str(lifecycle.get("broker_order_id") or "")
        recovered = {
            "operation_key": operation_key,
            "intent_sha256": intent_sha,
            "execution_mode": "live",
            "broker_order_id": broker_order_id,
            "status": str(lifecycle["status"]).lower(),
            "idempotent": True,
            "recovered_from_broker": True,
            "client_order_id": client_order_id,
            "allocation_plan_sha256": allocation_plan_sha256,
            "cumulative_filled_quantity": lifecycle[
                "cumulative_filled_quantity"
            ],
            "average_price": lifecycle["average_price"],
            "cumulative_fee_fen": lifecycle["cumulative_fee_fen"],
            "lifecycle_event_sha256": lifecycle["event_sha256"],
            "fill_settlement_sha256": settlement["settlement_sha256"],
            "account_reservation_event_sha256": account_reservation[
                "event_sha256"
            ],
        }
        self._operations[operation_key] = {
            "intent_sha256": intent_sha,
            "result": dict(recovered),
        }
        self._event(
            "ORDER_RECOVERED_FROM_BROKER",
            {
                "operation_key": operation_key,
                "intent_sha256": intent_sha,
                "broker_order_id": broker_order_id,
                "client_order_id": client_order_id,
                "allocation_plan_sha256": allocation_plan_sha256,
            },
        )
        return recovered

    @staticmethod
    def _validate_live_plan_scope(
        plan: dict[str, Any], authorization: BrokerLiveAuthorization
    ) -> None:
        children = [dict(item) for item in list(plan.get("child_intents") or [])]
        child_strategy_ids = {
            str(item.get("strategy_id") or "") for item in children
        }
        if isinstance(authorization, LiveAuthorization):
            if child_strategy_ids != {authorization.strategy_id}:
                raise BrokerPermissionError(
                    "live authorization does not cover every child allocation strategy"
                )
            return

        if (
            plan.get("batch_request_sha256")
            != authorization.authorized_batch_request_sha256
            or plan.get("trade_date") != authorization.authorized_trade_date
            or sha256_digest(children)
            != authorization.authorized_child_intents_sha256
        ):
            raise BrokerPermissionError(
                "parent allocation plan differs from the authorized live batch"
            )
        by_strategy = {
            item.strategy_id: item for item in authorization.strategy_allocations
        }
        if not child_strategy_ids or not child_strategy_ids <= set(by_strategy):
            raise BrokerPermissionError(
                "parent authorization does not cover every child allocation strategy"
            )

        planned_buy_notional: dict[str, Decimal] = {
            strategy_id: Decimal("0") for strategy_id in by_strategy
        }
        allowed_order_types = set(authorization.allowed_order_types)
        for child in children:
            strategy_id = str(child["strategy_id"])
            allocation = by_strategy[strategy_id]
            if str(child["code"]) not in set(allocation.allowed_symbols):
                raise BrokerPermissionError(
                    f"child symbol is outside the live authorization: {strategy_id}"
                )
            if str(child["order_type"]) not in allowed_order_types:
                raise BrokerPermissionError(
                    f"child order type is outside the live authorization: {strategy_id}"
                )
            if str(child["side"]) == "buy":
                planned_buy_notional[strategy_id] += (
                    Decimal(str(child["reference_price"]))
                    * int(child["quantity"])
                )
        for strategy_id, allocation in by_strategy.items():
            if (
                allocation.allocated_notional_at_authorization
                + planned_buy_notional[strategy_id]
                > allocation.capital_cap
            ):
                raise BrokerPermissionError(
                    f"child strategy exceeds authorized capital cap: {strategy_id}"
                )
        if (
            authorization.allocated_notional_at_authorization
            + sum(planned_buy_notional.values(), Decimal("0"))
            > authorization.capital_cap
        ):
            raise BrokerPermissionError(
                "parent live batch exceeds authorized aggregate capital cap"
            )

    def submit_order(
        self,
        intent: dict[str, Any],
        *,
        operation_key: str,
        now: datetime | None = None,
        allocation_plan: dict[str, Any] | None = None,
        parent_order_id: str | None = None,
    ) -> dict[str, Any]:
        moment = _utc(now)
        if self.mode not in {BrokerMode.PAPER, BrokerMode.LIVE_ENABLED}:
            raise BrokerPermissionError(f"orders are disabled in {self.mode.value} mode")
        operation_key = str(operation_key).strip()
        if not operation_key:
            raise BrokerSafetyError("operation_key is required")
        normalized, notional = self._normalize_intent(intent)
        allocation_plan_sha: str | None = None
        if self.mode == BrokerMode.LIVE_ENABLED:
            self._live_authorization_valid(moment)
            self._require_adapter_certification(now=moment)
            self._require_prior_session_reconciliation(now=moment)
            if allocation_plan is None or not str(parent_order_id or "").strip():
                raise BrokerPermissionError(
                    "live orders require a validated parent allocation plan"
                )
            assert self.authorization is not None
            try:
                frozen_plan = validate_parent_order_plan(allocation_plan)
            except OrderAllocationError as exc:
                raise BrokerPermissionError(
                    f"parent allocation plan rejected: {exc}"
                ) from exc
            if (
                frozen_plan.get("mode") != "LIVE_AUTHORIZED"
                or frozen_plan.get("real_orders") is not True
                or frozen_plan.get("account_fingerprint")
                != self.adapter.account_fingerprint
                or frozen_plan.get("authorization_sha256")
                != self.authorization.authorization_sha256
            ):
                raise BrokerPermissionError(
                    "parent allocation plan is outside the active live authorization"
                )
            self._validate_live_plan_scope(frozen_plan, self.authorization)
            parent_matches = [
                item
                for item in list(frozen_plan.get("parent_orders") or [])
                if item.get("parent_order_id") == str(parent_order_id)
            ]
            if len(parent_matches) != 1:
                raise BrokerPermissionError(
                    "parent_order_id is absent or ambiguous in allocation plan"
                )
            parent_order = dict(parent_matches[0])
            parent_normalized = {
                "code": str(parent_order.get("code") or ""),
                "side": str(parent_order.get("side") or ""),
                "quantity": int(parent_order.get("quantity") or 0),
                "order_type": str(parent_order.get("order_type") or ""),
                "limit_price": parent_order.get("limit_price"),
                "reference_price": parent_order.get("reference_price"),
            }
            if parent_normalized != normalized:
                raise BrokerPermissionError(
                    "broker intent differs from frozen parent allocation order"
                )
            allocation_plan_sha = str(frozen_plan["allocation_plan_sha256"])
        intent_sha = sha256_digest(
            {
                "normalized_intent": normalized,
                "allocation_plan_sha256": allocation_plan_sha,
            }
        )
        if self.mode == BrokerMode.LIVE_ENABLED and self.authorization is not None:
            authorization_scope = (
                self.authorization.strategy_id
                if isinstance(self.authorization, LiveAuthorization)
                else f"parent:{self.authorization.authorization_sha256}"
            )
        else:
            authorization_scope = "paper"
        client_order_id = (
            "vr-"
            + sha256_digest(
                {
                    "authorization_scope": authorization_scope,
                    "operation_key": operation_key,
                }
            )[:24].lower()
        )
        previous = self._operations.get(operation_key)
        if previous:
            if previous["intent_sha256"] != intent_sha:
                raise BrokerOperationConflict("operation_key was already used for another intent")
            return {**dict(previous["result"]), "idempotent": True}

        if self.mode == BrokerMode.LIVE_ENABLED:
            assert allocation_plan_sha is not None
            assert self.authorization is not None
            assert parent_order_id is not None
            self._require_live_report_consumer()
            account_book = self._require_account_reservation_book(
                now=moment,
                allow_pending_operation_key=operation_key,
            )
            if account_book.latest(operation_key) is not None:
                try:
                    account_book.reserve_order(
                        frozen_plan,
                        parent_order_id=str(parent_order_id),
                        operation_key=operation_key,
                        client_order_id=client_order_id,
                        authorization_sha256=self.authorization.authorization_sha256,
                        recorded_at=moment,
                    )
                except BrokerAccountControlError as exc:
                    self.halt("operation conflicts with existing account reservation")
                    raise BrokerOperationConflict(
                        f"operation conflicts with existing account reservation: {exc}"
                    ) from exc
            recovered = self._recover_live_order(
                operation_key=operation_key,
                intent_sha=intent_sha,
                client_order_id=client_order_id,
                normalized_intent=normalized,
                allocation_plan_sha256=allocation_plan_sha,
                allocation_plan=frozen_plan,
                authorization_sha256=self.authorization.authorization_sha256,
                parent_order_id=str(parent_order_id),
                recorded_at=moment,
            )
            if recovered is not None:
                return recovered

        day = moment.date().isoformat()
        usage = self._daily_usage.setdefault(
            day, {"order_count": 0, "notional": Decimal("0")}
        )
        broker_usage = {"order_count": 0, "notional": Decimal("0")}
        if self.mode == BrokerMode.LIVE_ENABLED:
            try:
                raw_usage = self.adapter.get_daily_order_usage(day)
                raw_count = raw_usage.get("order_count")
                if isinstance(raw_count, bool) or not (
                    isinstance(raw_count, int)
                    or (
                        isinstance(raw_count, str)
                        and raw_count.strip().isdigit()
                    )
                    or raw_count is None
                ):
                    raise ValueError("daily order count must be an exact integer")
                broker_usage = {
                    "order_count": int(raw_count or 0),
                    "notional": _nonnegative_decimal(
                        raw_usage.get("notional") or 0, "broker daily notional"
                    ),
                }
            except Exception:
                self.halt("adapter returned invalid daily usage")
                raise BrokerSafetyError("adapter returned invalid daily usage; boundary halted")
            if int(broker_usage["order_count"]) < 0:
                self.halt("adapter returned invalid daily usage")
                raise BrokerSafetyError("adapter returned invalid daily usage; boundary halted")
        effective_count = max(int(usage["order_count"]), int(broker_usage["order_count"]))
        effective_notional = max(
            Decimal(usage["notional"]), Decimal(broker_usage["notional"])
        )
        if notional > self.policy.max_order_notional:
            raise BrokerPermissionError("order exceeds max_order_notional")
        if effective_count + 1 > self.policy.max_daily_order_count:
            raise BrokerPermissionError("daily order count cap exceeded")
        if effective_notional + notional > self.policy.max_daily_notional:
            raise BrokerPermissionError("daily notional cap exceeded")

        if self.mode == BrokerMode.LIVE_ENABLED:
            self._live_authorization_valid(moment)
            assert self.authorization is not None
            if normalized["code"] not in set(self.authorization.allowed_symbols):
                raise BrokerPermissionError("symbol is outside the live authorization")
            if normalized["order_type"] not in set(
                self.authorization.allowed_order_types
            ):
                raise BrokerPermissionError(
                    "order type is outside the live authorization"
                )
            if normalized["side"] == "buy":
                allocated = self.authorization.allocated_notional_at_authorization
                already_used = max(self._authorized_buy_notional, effective_notional)
                if allocated + already_used + notional > self.authorization.capital_cap:
                    raise BrokerPermissionError("order exceeds remaining authorized capital cap")
            account_book = self._require_account_reservation_book(
                now=moment,
                allow_pending_operation_key=operation_key,
            )
            try:
                account_book.reserve_order(
                    frozen_plan,
                    parent_order_id=str(parent_order_id),
                    operation_key=operation_key,
                    client_order_id=client_order_id,
                    authorization_sha256=self.authorization.authorization_sha256,
                    recorded_at=moment,
                )
            except BrokerAccountControlError as exc:
                raise BrokerPermissionError(
                    f"account cash or sellable position reservation rejected: {exc}"
                ) from exc
            journal = self._require_live_journal()
            try:
                prepared = journal.prepare_submission(
                    recorded_at=moment,
                    operation_key=operation_key,
                    client_order_id=client_order_id,
                    authorization_sha256=self.authorization.authorization_sha256,
                    intent_sha256=intent_sha,
                    allocation_plan_sha256=str(allocation_plan_sha),
                    parent_order_id=str(parent_order_id),
                    order_quantity=normalized["quantity"],
                )
                self._reconcile_account_reservation(operation_key, prepared)
            except (BrokerOrderJournalError, BrokerAccountControlError) as exc:
                self.halt("live order could not be durably prepared")
                raise BrokerSafetyError(
                    "live order could not be durably prepared; boundary halted"
                ) from exc
            try:
                raw_result = self.adapter.submit_live_order(
                    {
                        **dict(normalized),
                        "client_order_id": client_order_id,
                        "allocation_plan_sha256": allocation_plan_sha,
                    }
                )
            except Exception as exc:
                self._mark_lifecycle_unknown(
                    operation_key,
                    recorded_at=moment,
                    event_type="SUBMISSION_UNKNOWN",
                )
                self.halt("live order outcome is unknown after adapter failure")
                raise BrokerSafetyError(
                    "live adapter failed with unknown order outcome; boundary halted"
                ) from exc
            if not isinstance(raw_result, dict):
                self._mark_lifecycle_unknown(
                    operation_key,
                    recorded_at=moment,
                    event_type="SUBMISSION_UNKNOWN",
                )
                self.halt("live adapter returned an invalid order response")
                raise BrokerSafetyError(
                    "live adapter response is invalid; boundary halted"
                )
            lifecycle_event = self._reconcile_lifecycle_snapshot(
                operation_key,
                raw_result,
                order_quantity=normalized["quantity"],
                recorded_at=moment,
            )
            if lifecycle_event["status"] == "UNKNOWN":
                self.halt("live adapter returned an unresolved order outcome")
                raise BrokerSafetyError(
                    "live adapter returned an unresolved order outcome; boundary halted"
                )
            settlement_event = (
                None
                if lifecycle_event["status"] == "REJECTED"
                else self._settle_live_parent_fill(
                    operation_key, allocation_plan=frozen_plan
                )
            )
            execution_mode = "live"
        else:
            self._require_capabilities({BrokerCapability.PAPER_ORDER.value})
            raw_result = self.adapter.submit_paper_order(
                {**dict(normalized), "client_order_id": client_order_id}
            )
            execution_mode = "paper"
            lifecycle_event = None
            settlement_event = None

        result = {
            "operation_key": operation_key,
            "intent_sha256": intent_sha,
            "execution_mode": execution_mode,
            "broker_order_id": str(
                (
                    lifecycle_event.get("broker_order_id")
                    if lifecycle_event is not None
                    else raw_result.get("broker_order_id")
                )
                or ""
            ),
            "status": (
                str(lifecycle_event["status"]).lower()
                if lifecycle_event is not None
                else str(raw_result.get("status") or "accepted")
            ),
            "idempotent": False,
            "client_order_id": client_order_id,
            "allocation_plan_sha256": allocation_plan_sha,
            "cumulative_filled_quantity": (
                lifecycle_event["cumulative_filled_quantity"]
                if lifecycle_event is not None
                else 0
            ),
            "average_price": (
                lifecycle_event["average_price"]
                if lifecycle_event is not None
                else None
            ),
            "cumulative_fee_fen": (
                lifecycle_event["cumulative_fee_fen"]
                if lifecycle_event is not None
                else 0
            ),
            "lifecycle_event_sha256": (
                lifecycle_event["event_sha256"]
                if lifecycle_event is not None
                else None
            ),
            "fill_settlement_sha256": (
                settlement_event["settlement_sha256"]
                if settlement_event is not None
                else None
            ),
            "account_reservation_event_sha256": (
                self.account_reservation_book.latest(operation_key)["event_sha256"]
                if lifecycle_event is not None
                and self.account_reservation_book is not None
                and self.account_reservation_book.latest(operation_key) is not None
                else None
            ),
        }
        if not result["broker_order_id"] and result["status"] != "rejected":
            self.halt("adapter returned no broker_order_id")
            raise BrokerSafetyError("adapter response is missing broker_order_id; boundary halted")
        usage["order_count"] = int(usage["order_count"]) + 1
        usage["notional"] = Decimal(usage["notional"]) + notional
        if execution_mode == "live" and normalized["side"] == "buy":
            self._authorized_buy_notional += notional
        self._operations[operation_key] = {
            "intent_sha256": intent_sha,
            "result": dict(result),
        }
        self._event(
            "ORDER_SUBMITTED",
            {
                "operation_key": operation_key,
                "intent_sha256": intent_sha,
                "execution_mode": execution_mode,
                "broker_order_id": result["broker_order_id"],
                "allocation_plan_sha256": allocation_plan_sha,
            },
        )
        return result

    def cancel_order(
        self, broker_order_id: str, *, now: datetime | None = None
    ) -> dict[str, Any]:
        if self.mode not in {
            BrokerMode.PAPER,
            BrokerMode.LIVE_ENABLED,
            BrokerMode.HALTED,
        }:
            raise BrokerPermissionError("cancel is unavailable in the current mode")
        self._require_capabilities({BrokerCapability.CANCEL_ORDER.value})
        moment = _utc(now)
        broker_order_id = str(broker_order_id).strip()
        lifecycle_record: dict[str, Any] | None = None
        if self.order_journal is not None:
            try:
                lifecycle_record = self.order_journal.latest_for_broker_order_id(
                    broker_order_id
                )
            except BrokerOrderJournalError as exc:
                self.halt("durable broker order journal is unreadable during cancel")
                raise BrokerSafetyError(
                    "durable broker order journal is unreadable; boundary halted"
                ) from exc
        live_cancel = self.mode == BrokerMode.LIVE_ENABLED or lifecycle_record is not None
        if live_cancel:
            journal = self._require_live_journal()
            if lifecycle_record is None:
                self.halt("live cancel target is absent from durable order journal")
                raise BrokerSafetyError(
                    "live cancel target is absent from durable order journal; boundary halted"
                )
            if lifecycle_record["status"] == "CANCEL_PENDING":
                account_reservation = self._reconcile_account_reservation(
                    lifecycle_record["operation_key"], lifecycle_record
                )
                settlement_event = self._settle_live_parent_fill(
                    lifecycle_record["operation_key"]
                )
                return {
                    "broker_order_id": broker_order_id,
                    "status": "cancel_pending",
                    "idempotent": True,
                    "lifecycle_event_sha256": lifecycle_record["event_sha256"],
                    "fill_settlement_sha256": settlement_event[
                        "settlement_sha256"
                    ],
                    "account_reservation_event_sha256": account_reservation[
                        "event_sha256"
                    ],
                }
            if lifecycle_record["status"] in AMBIGUOUS_STATUSES:
                self.halt("live cancel target has an unresolved broker outcome")
                raise BrokerSafetyError(
                    "live cancel target has an unresolved broker outcome; boundary halted"
                )
            try:
                cancel_requested = journal.request_cancel(
                    broker_order_id, recorded_at=moment
                )
                self._reconcile_account_reservation(
                    lifecycle_record["operation_key"], cancel_requested
                )
            except BrokerOrderJournalError as exc:
                raise BrokerPermissionError(
                    "live cancel is inconsistent with durable order lifecycle"
                ) from exc
        try:
            result = self.adapter.cancel_order(broker_order_id)
        except Exception as exc:
            if live_cancel and lifecycle_record is not None:
                self._mark_lifecycle_unknown(
                    lifecycle_record["operation_key"],
                    recorded_at=moment,
                    event_type="CANCEL_UNKNOWN",
                )
                self.halt("live cancel outcome is unknown after adapter failure")
            raise BrokerSafetyError("broker cancel adapter failed") from exc
        if not isinstance(result, dict):
            if live_cancel and lifecycle_record is not None:
                self._mark_lifecycle_unknown(
                    lifecycle_record["operation_key"],
                    recorded_at=moment,
                    event_type="CANCEL_UNKNOWN",
                )
                self.halt("live cancel adapter returned an invalid response")
            raise BrokerSafetyError("broker cancel adapter response is invalid")
        if live_cancel and lifecycle_record is not None:
            lifecycle_event = self._reconcile_lifecycle_snapshot(
                lifecycle_record["operation_key"],
                result,
                order_quantity=lifecycle_record["order_quantity"],
                recorded_at=moment,
            )
            settlement_event = self._settle_live_parent_fill(
                lifecycle_record["operation_key"]
            )
            result = {
                **dict(result),
                "status": str(lifecycle_event["status"]).lower(),
                "idempotent": False,
                "lifecycle_event_sha256": lifecycle_event["event_sha256"],
                "fill_settlement_sha256": settlement_event[
                    "settlement_sha256"
                ],
                "account_reservation_event_sha256": self.account_reservation_book.latest(
                    lifecycle_record["operation_key"]
                )["event_sha256"],
            }
        self._event("ORDER_CANCEL_REQUESTED", {"broker_order_id": str(broker_order_id)})
        return dict(result)

    def get_account(self) -> dict[str, Any]:
        if self.mode == BrokerMode.DISCONNECTED:
            raise BrokerPermissionError("broker boundary is disconnected")
        self._require_capabilities({BrokerCapability.ACCOUNT_READ.value})
        return dict(self.adapter.get_account())

    def get_positions(self) -> list[dict[str, Any]]:
        if self.mode == BrokerMode.DISCONNECTED:
            raise BrokerPermissionError("broker boundary is disconnected")
        self._require_capabilities({BrokerCapability.POSITIONS_READ.value})
        return [dict(item) for item in self.adapter.get_positions()]

    def list_orders(self) -> list[dict[str, Any]]:
        if self.mode == BrokerMode.DISCONNECTED:
            raise BrokerPermissionError("broker boundary is disconnected")
        self._require_capabilities({BrokerCapability.ORDERS_READ.value})
        return [dict(item) for item in self.adapter.list_orders()]

    def halt(self, reason: str) -> dict[str, Any]:
        self.authorization = None
        self._authorized_buy_notional = Decimal("0")
        self.halt_reason = str(reason).strip() or "unspecified safety halt"
        self.mode = BrokerMode.HALTED
        self._event("BOUNDARY_HALTED", {"reason": self.halt_reason})
        return self.status()

    def acknowledge_halt(self, *, authorization_reference: str) -> dict[str, Any]:
        if self.mode != BrokerMode.HALTED:
            raise BrokerPermissionError("boundary is not halted")
        if not authorization_reference.strip():
            raise BrokerPermissionError("operator authorization reference is required")
        if self.adapter.adapter_id not in self.policy.allowed_read_only_adapters:
            raise BrokerPermissionError("adapter is no longer approved for read-only access")
        self._require_capabilities(set(READ_ONLY_CAPABILITIES))
        previous_reason = self.halt_reason
        self.halt_reason = None
        self.mode = BrokerMode.READ_ONLY
        self._event(
            "HALT_ACKNOWLEDGED",
            {
                "authorization_reference": authorization_reference,
                "previous_reason": previous_reason,
            },
        )
        return self.status()

    def status(self, *, now: datetime | None = None) -> dict[str, Any]:
        moment = _utc(now)
        authorization = self.authorization
        journal_inspection = (
            self.order_journal.inspect() if self.order_journal is not None else None
        )
        settlement_inspection = (
            self.order_journal.inspect_fill_settlements()
            if self.order_journal is not None
            else None
        )
        report_inspection = (
            self.report_consumer.inspect()
            if self.report_consumer is not None
            else None
        )
        account_reservation_inspection = (
            self.account_reservation_book.inspect()
            if self.account_reservation_book is not None
            else None
        )
        account_collection_inspection = (
            self.account_snapshot_collector.inspect()
            if self.account_snapshot_collector is not None
            else None
        )
        journal_ready = (
            journal_inspection is not None
            and journal_inspection["status"] in {"EMPTY", "READY"}
            and self.order_journal is not None
            and self.order_journal.account_fingerprint
            == self.adapter.account_fingerprint
            and not journal_inspection["ambiguous_operation_keys"]
            and settlement_inspection is not None
            and settlement_inspection["status"] in {"EMPTY", "READY"}
        )
        report_consumer_ready = (
            report_inspection is not None
            and report_inspection["status"] in {"EMPTY", "READY"}
            and self.report_consumer is not None
            and self.report_consumer.adapter_id == self.adapter.adapter_id
            and self.report_consumer.account_fingerprint
            == self.adapter.account_fingerprint
            and self.report_consumer.journal is self.order_journal
            and self.report_consumer.account_reservation_book
            is self.account_reservation_book
        )
        try:
            account_received_at = (
                datetime.fromisoformat(
                    str(self.account_reservation_book.account_snapshot["received_at"])
                ).astimezone(timezone.utc)
                if self.account_reservation_book is not None
                else None
            )
            account_snapshot_age = (
                (moment - account_received_at).total_seconds()
                if account_received_at is not None
                else None
            )
        except (KeyError, TypeError, ValueError):
            account_snapshot_age = None
        account_reservation_ready = (
            account_reservation_inspection is not None
            and account_reservation_inspection["status"] == "READY"
            and self.account_reservation_book is not None
            and self.account_reservation_book.adapter_id == self.adapter.adapter_id
            and self.account_reservation_book.account_fingerprint
            == self.adapter.account_fingerprint
            and self.account_reservation_book.journal is self.order_journal
            and self.account_reservation_book.trade_date
            == moment.date().isoformat()
            and account_snapshot_age is not None
            and 0 <= account_snapshot_age
            <= int(
                self.account_reservation_book.policy[
                    "max_snapshot_age_seconds"
                ]
            )
        )
        try:
            collected_account_snapshot = (
                self.account_snapshot_collector.snapshot_by_sha256(
                    self.account_reservation_book.snapshot_sha256
                )
                if self.account_snapshot_collector is not None
                and self.account_reservation_book is not None
                and account_collection_inspection is not None
                and account_collection_inspection["status"] == "READY"
                else None
            )
        except BrokerAccountSnapshotCollectorError:
            collected_account_snapshot = None
        account_snapshot_collector_ready = (
            self.account_snapshot_collector is not None
            and self.account_snapshot_collector.adapter is self.adapter
            and self.account_snapshot_collector.adapter_id
            == self.adapter.adapter_id
            and self.account_snapshot_collector.account_fingerprint
            == self.adapter.account_fingerprint
            and account_collection_inspection is not None
            and account_collection_inspection["status"] == "READY"
            and self.account_reservation_book is not None
            and collected_account_snapshot
            == self.account_reservation_book.account_snapshot
        )
        try:
            session_continuity_assessment = (
                self.session_continuity_gate.assess(moment.date().isoformat())
                if self.session_continuity_gate is not None
                else None
            )
        except BrokerSessionContinuityError:
            session_continuity_assessment = None
        session_continuity_ready = (
            self.session_continuity_gate is not None
            and self.session_continuity_gate.adapter_id
            == self.adapter.adapter_id
            and self.session_continuity_gate.account_fingerprint
            == self.adapter.account_fingerprint
            and self.session_continuity_gate.account_snapshot_collector
            is self.account_snapshot_collector
            and session_continuity_assessment is not None
            and session_continuity_assessment.get("admitted") is True
        )
        (
            adapter_certification_inspection,
            adapter_certification_report,
            adapter_certification_ready,
        ) = self._adapter_certification_state(authorization, now=moment)
        return {
            "schema": BROKER_SAFETY_SCHEMA,
            "mode": self.mode.value,
            "adapter_id": self.adapter.adapter_id,
            "environment": self.adapter.environment,
            "account_fingerprint": self.adapter.account_fingerprint,
            "capabilities": sorted(self.capabilities),
            "real_orders_policy_enabled": self.policy.real_orders_enabled,
            "real_orders_allowed": (
                self.mode == BrokerMode.LIVE_ENABLED
                and authorization is not None
                and moment < authorization.not_after
                and (
                    journal_ready
                    if self.policy.require_durable_order_journal
                    else True
                )
                and (
                    report_consumer_ready
                    if self.policy.require_trusted_report_consumer
                    else True
                )
                and (
                    account_reservation_ready
                    if self.policy.require_account_reservation_book
                    else True
                )
                and (
                    account_snapshot_collector_ready
                    if self.policy.require_trusted_account_snapshot_collector
                    else True
                )
                and (
                    session_continuity_ready
                    if self.policy.require_prior_session_reconciliation
                    else True
                )
                and (
                    adapter_certification_ready
                    if self.policy.require_trusted_adapter_certification_registry
                    else True
                )
            ),
            "authorization_id": authorization.authorization_id if authorization else None,
            "authorization_schema": (
                authorization.evidence()["schema"] if authorization else None
            ),
            "authorized_strategy_id": (
                authorization.strategy_id
                if isinstance(authorization, LiveAuthorization)
                else None
            ),
            "authorized_strategy_ids": (
                [authorization.strategy_id]
                if isinstance(authorization, LiveAuthorization)
                else (
                    list(authorization.authorized_strategy_ids)
                    if isinstance(authorization, ParentLiveAuthorization)
                    else []
                )
            ),
            "authorized_symbols": list(authorization.allowed_symbols) if authorization else [],
            "authorized_order_types": (
                list(authorization.allowed_order_types) if authorization else []
            ),
            "authorization_not_after": (
                authorization.not_after.isoformat() if authorization else None
            ),
            "halt_reason": self.halt_reason,
            "event_count": len(self.events),
            "operation_count": len(self._operations),
            "durable_order_journal": journal_inspection,
            "durable_fill_settlements": settlement_inspection,
            "trusted_report_consumer": report_inspection,
            "account_reservation_book": account_reservation_inspection,
            "trusted_account_snapshot_collector": account_collection_inspection,
            "prior_session_reconciliation": session_continuity_assessment,
            "trusted_adapter_certification_registry": (
                adapter_certification_inspection
            ),
            "adapter_certification_report": adapter_certification_report,
            "policy": self.policy.evidence(),
        }
