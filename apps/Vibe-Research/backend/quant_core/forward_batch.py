"""Idempotent post-close orchestration for formal forward-paper strategies."""

from __future__ import annotations

from datetime import date, datetime, time
from pathlib import Path
from typing import Any, Mapping

from .forward_paper import (
    SHANGHAI,
    ForwardConflictError,
    ForwardDataError,
    ForwardHaltedError,
    ForwardPaperRunner,
    _atomic_json,
    _day,
    _hashed_record,
    _immutable_json,
    _read_json,
    _timestamp,
)
from .forward_signals import ForwardSignalFactory
from .order_allocation import (
    OrderAllocationError,
    build_parent_order_plan,
    validate_parent_order_plan,
)
from .execution_orchestrator import (
    ExecutionOrchestrationError,
    build_pretrade_execution_batch,
    child_order_intents,
    validate_pretrade_execution_batch,
)
from .provenance import sha256_digest


FORWARD_DAILY_BATCH_SCHEMA = "quant-platform/forward-daily-batch/v1"
FORWARD_DAILY_RECEIPT_SCHEMA = "quant-platform/forward-daily-batch-receipt/v4"


class ForwardDailyBatch:
    """Execute due orders first, then freeze today's signal when scheduled."""

    def __init__(
        self,
        runner: ForwardPaperRunner,
        *,
        signal_factory: ForwardSignalFactory | None = None,
    ) -> None:
        self.runner = runner
        self.signal_factory = signal_factory or ForwardSignalFactory(runner)

    @property
    def root(self) -> Path:
        return self.runner.runtime_root / "_daily_batches"

    @property
    def allocation_root(self) -> Path:
        return self.runner.runtime_root / "_parent_order_allocation"

    @property
    def pretrade_root(self) -> Path:
        return self.runner.runtime_root / "_pretrade_execution_batches"

    @staticmethod
    def _signal_due(frequency: str, day: date, calendar_dates: list[date]) -> bool:
        following = [value for value in calendar_dates if value > day]
        if not following:
            raise ForwardDataError("approved calendar has no next trading session")
        next_day = following[0]
        if frequency == "daily":
            return True
        if frequency == "weekly":
            return day.isocalendar()[:2] != next_day.isocalendar()[:2]
        if frequency == "monthly":
            return (day.year, day.month) != (next_day.year, next_day.month)
        raise ForwardDataError(f"unsupported formal signal frequency: {frequency}")

    def _existing(self, day: date, request_sha256: str) -> dict[str, Any] | None:
        pointer_path = self.root / "by-date" / f"{day}.json"
        if not pointer_path.is_file():
            return None
        pointer = _read_json(pointer_path)
        if pointer.get("request_sha256") != request_sha256:
            raise ForwardConflictError(
                "a different formal daily batch is already finalized for this date"
            )
        receipt = _hashed_record(
            self.root / "receipts" / f"{pointer['receipt_sha256']}.json",
            "receipt_sha256",
        )
        if receipt.get("schema") != FORWARD_DAILY_RECEIPT_SCHEMA:
            raise ForwardConflictError(
                "legacy daily receipt cannot satisfy the parent allocation contract"
            )
        if sha256_digest(dict(receipt.get("request") or {})) != request_sha256:
            raise ForwardConflictError(
                "daily receipt does not retain its exact content-addressed request"
            )
        try:
            plan = validate_parent_order_plan(
                dict(receipt.get("parent_order_allocation_plan") or {})
            )
        except OrderAllocationError as exc:
            raise ForwardConflictError(
                f"daily receipt parent allocation evidence is invalid: {exc}"
            ) from exc
        stored_plan = _hashed_record(
            self.allocation_root
            / "plans"
            / "records"
            / f"{plan['allocation_plan_sha256']}.json",
            "allocation_plan_sha256",
        )
        if stored_plan != plan:
            raise ForwardConflictError(
                "daily receipt and parent allocation record diverged"
            )
        try:
            pretrade = validate_pretrade_execution_batch(
                dict(receipt.get("pretrade_execution_batch") or {})
            )
        except ExecutionOrchestrationError as exc:
            raise ForwardConflictError(
                f"daily receipt pretrade evidence is invalid: {exc}"
            ) from exc
        if (
            pretrade["batch_request_sha256"] != request_sha256
            or pretrade["parent_order_allocation_plan"] != plan
        ):
            raise ForwardConflictError(
                "daily receipt and pretrade execution batch diverged"
            )
        stored_pretrade = _hashed_record(
            self.pretrade_root
            / "records"
            / f"{pretrade['pretrade_batch_sha256']}.json",
            "pretrade_batch_sha256",
        )
        if stored_pretrade != pretrade:
            raise ForwardConflictError(
                "daily receipt and pretrade batch record diverged"
            )
        return {**receipt, "idempotent": True}

    def _prepared(self, request_sha256: str) -> dict[str, Any] | None:
        pointer_path = self.pretrade_root / "by-request" / f"{request_sha256}.json"
        if not pointer_path.is_file():
            return None
        pointer = _read_json(pointer_path)
        if pointer.get("batch_request_sha256") != request_sha256:
            raise ForwardConflictError("pretrade request pointer identity mismatch")
        try:
            prepared = validate_pretrade_execution_batch(
                _hashed_record(
                    self.pretrade_root
                    / "records"
                    / f"{pointer['pretrade_batch_sha256']}.json",
                    "pretrade_batch_sha256",
                )
            )
        except (ExecutionOrchestrationError, KeyError) as exc:
            raise ForwardConflictError(
                f"stored pretrade execution batch is invalid: {exc}"
            ) from exc
        if prepared["batch_request_sha256"] != request_sha256:
            raise ForwardConflictError("stored pretrade batch request mismatch")
        plan = dict(prepared["parent_order_allocation_plan"])
        stored_plan = _hashed_record(
            self.allocation_root
            / "plans"
            / "records"
            / f"{plan['allocation_plan_sha256']}.json",
            "allocation_plan_sha256",
        )
        if stored_plan != plan:
            raise ForwardConflictError(
                "stored pretrade batch and parent allocation record diverged"
            )
        return prepared

    def run(self, request: Mapping[str, Any]) -> dict[str, Any]:
        payload = dict(request)
        if payload.get("schema") != FORWARD_DAILY_BATCH_SCHEMA:
            raise ForwardDataError("unsupported forward daily batch schema")
        if payload.get("real_orders") is not False:
            raise ForwardDataError("forward daily batch must explicitly disable real orders")
        trade_date = _day(payload.get("trade_date"))
        recorded_at = _timestamp(str(payload.get("recorded_at") or ""))
        local = recorded_at.astimezone(SHANGHAI)
        if local.date() != trade_date or local.time() < time(15, 0):
            raise ForwardDataError("daily batch must run post-close on its own local trade date")
        entries = [dict(item) for item in list(payload.get("strategies") or [])]
        ids = [str(item.get("strategy_id") or "") for item in entries]
        if not entries or any(not item for item in ids) or len(ids) != len(set(ids)):
            raise ForwardDataError("daily batch requires unique non-empty strategy entries")
        request_sha256 = sha256_digest(payload)

        with self.runner._mutation_lock("platform-forward-batch"):
            existing = self._existing(trade_date, request_sha256)
            if existing is not None:
                return existing
            platform_preflight: dict[str, Any] | None = None
            preflight_method = getattr(
                self.runner, "platform_portfolio_preflight", None
            )
            if callable(preflight_method):
                try:
                    platform_preflight = preflight_method(
                        entries,
                        trade_date=trade_date,
                        recorded_at=recorded_at,
                        batch_request_sha256=request_sha256,
                    )
                except Exception as exc:
                    halt_method = getattr(
                        self.runner, "_halt_platform_portfolio", None
                    )
                    if callable(halt_method):
                        try:
                            halt_method(
                                "platform portfolio preflight input failed closed",
                                {
                                    "trade_date": trade_date.isoformat(),
                                    "batch_request_sha256": request_sha256,
                                    "error": f"{type(exc).__name__}: {exc}",
                                },
                            )
                        except Exception:
                            # Preserve the primary failure.  A secondary safety
                            # persistence failure must never turn the batch into
                            # a success path.
                            pass
                    raise
                platform_preflight = {
                    key: value
                    for key, value in platform_preflight.items()
                    if key != "idempotent"
                }
                if platform_preflight.get("effective_decision") == "BLOCKED":
                    raise ForwardHaltedError(
                        "platform portfolio preflight blocked the complete daily batch: "
                        + ", ".join(platform_preflight.get("blockers") or [])
                    )
            platform_decision = (
                str(platform_preflight.get("effective_decision"))
                if platform_preflight is not None
                else "PASS"
            )
            if platform_decision == "MONITOR_ONLY" and any(
                item.get("execution") is not None for item in entries
            ):
                raise ForwardHaltedError(
                    "MONITOR_ONLY permits valuation observations, not due executions"
                )
            if platform_preflight is None:
                raise ForwardHaltedError(
                    "formal daily batch requires a complete platform preflight"
                )

            pretrade_batch = self._prepared(request_sha256)
            if pretrade_batch is not None:
                if (
                    pretrade_batch["trade_date"] != trade_date.isoformat()
                    or pretrade_batch["recorded_at"] != recorded_at.isoformat()
                    or pretrade_batch["platform_preflight_sha256"]
                    != platform_preflight["preflight_sha256"]
                ):
                    raise ForwardConflictError(
                        "stored pretrade batch differs from current batch preflight"
                    )
                allocation_plan = dict(
                    pretrade_batch["parent_order_allocation_plan"]
                )
            else:
                prepare_method = getattr(
                    self.runner, "prepare_due_execution", None
                )
                if not callable(prepare_method):
                    raise ForwardHaltedError(
                        "runner lacks the mandatory pretrade preparation phase"
                    )
                child_receipts: list[dict[str, Any]] = []
                try:
                    for entry in sorted(
                        entries, key=lambda item: str(item["strategy_id"])
                    ):
                        if entry.get("execution") is None:
                            continue
                        child_receipts.append(
                            prepare_method(
                                str(entry["strategy_id"]),
                                trade_date=trade_date.isoformat(),
                                market_reference=dict(entry["execution"]),
                                recorded_at=recorded_at,
                                platform_preflight_sha256=platform_preflight[
                                    "preflight_sha256"
                                ],
                            )
                        )
                    prepared_assessment_method = getattr(
                        self.runner, "assess_prepared_executions", None
                    )
                    if not callable(prepared_assessment_method):
                        raise ForwardHaltedError(
                            "runner lacks exact prepared portfolio assessment"
                        )
                    prepared_assessments = prepared_assessment_method(
                        platform_preflight=platform_preflight,
                        child_receipts=child_receipts,
                    )
                    allocation_intents = [
                        intent
                        for child in child_receipts
                        for intent in child_order_intents(child)
                    ]
                    allocation_plan = build_parent_order_plan(
                        allocation_intents,
                        batch_request_sha256=request_sha256,
                        trade_date=trade_date,
                        account_fingerprint="paper-parent-account",
                        mode="PAPER",
                    )
                    pretrade_batch = build_pretrade_execution_batch(
                        child_receipts,
                        parent_order_allocation_plan=allocation_plan,
                        batch_request_sha256=request_sha256,
                        platform_preflight_sha256=platform_preflight[
                            "preflight_sha256"
                        ],
                        trade_date=trade_date,
                        recorded_at=recorded_at,
                        prepared_portfolio_assessment=dict(
                            prepared_assessments[
                                "prepared_portfolio_assessment"
                            ]
                        ),
                        prepared_stress_assessment=dict(
                            prepared_assessments[
                                "prepared_stress_assessment"
                            ]
                        ),
                    )
                except Exception as exc:
                    halt_method = getattr(
                        self.runner, "_halt_platform_portfolio", None
                    )
                    if callable(halt_method):
                        try:
                            halt_method(
                                "pretrade execution preparation failed closed",
                                {
                                    "trade_date": trade_date.isoformat(),
                                    "batch_request_sha256": request_sha256,
                                    "error": f"{type(exc).__name__}: {exc}",
                                },
                            )
                        except Exception:
                            pass
                    if isinstance(
                        exc, (OrderAllocationError, ExecutionOrchestrationError)
                    ):
                        raise ForwardHaltedError(
                            f"pretrade execution preparation failed: {exc}"
                        ) from exc
                    raise
                for child in child_receipts:
                    _immutable_json(
                        self.pretrade_root
                        / "child-receipts"
                        / f"{child['receipt_sha256']}.json",
                        child,
                    )
                _immutable_json(
                    self.allocation_root
                    / "plans"
                    / "records"
                    / f"{allocation_plan['allocation_plan_sha256']}.json",
                    allocation_plan,
                )
                allocation_pointer = {
                    "trade_date": trade_date.isoformat(),
                    "batch_request_sha256": request_sha256,
                    "allocation_plan_sha256": allocation_plan[
                        "allocation_plan_sha256"
                    ],
                }
                _atomic_json(
                    self.allocation_root
                    / "plans"
                    / "by-date"
                    / f"{trade_date}.json",
                    allocation_pointer,
                )
                _atomic_json(
                    self.allocation_root / "plans" / "latest.json",
                    allocation_pointer,
                )
                _immutable_json(
                    self.pretrade_root
                    / "records"
                    / f"{pretrade_batch['pretrade_batch_sha256']}.json",
                    pretrade_batch,
                )
                pretrade_pointer = {
                    "trade_date": trade_date.isoformat(),
                    "batch_request_sha256": request_sha256,
                    "pretrade_batch_sha256": pretrade_batch[
                        "pretrade_batch_sha256"
                    ],
                }
                _atomic_json(
                    self.pretrade_root
                    / "by-request"
                    / f"{request_sha256}.json",
                    pretrade_pointer,
                )
                _atomic_json(
                    self.pretrade_root / "by-date" / f"{trade_date}.json",
                    pretrade_pointer,
                )
                _atomic_json(
                    self.pretrade_root / "latest.json", pretrade_pointer
                )
            results: list[dict[str, Any]] = []
            for entry in sorted(entries, key=lambda item: str(item["strategy_id"])):
                strategy_id = str(entry["strategy_id"])
                spec = self.runner._experiment(strategy_id)
                execution_result: dict[str, Any] | None = None
                observation_result: dict[str, Any] | None = None
                signal_result: dict[str, Any] | None = None
                execution = entry.get("execution")
                observation = entry.get("observation")
                if execution is None and observation is None:
                    raise ForwardDataError(
                        f"daily batch entry lacks a finalized market observation: {strategy_id}"
                    )
                if execution is not None:
                    try:
                        execution_result = self.runner.execute_due(
                            strategy_id,
                            trade_date=trade_date.isoformat(),
                            market_reference=dict(execution),
                            recorded_at=recorded_at,
                            platform_preflight_sha256=(
                                platform_preflight["preflight_sha256"]
                                if platform_preflight is not None
                                else None
                            ),
                            pretrade_batch_sha256=pretrade_batch[
                                "pretrade_batch_sha256"
                            ],
                        )
                    except Exception as exc:
                        halt_method = getattr(
                            self.runner, "_halt_platform_portfolio", None
                        )
                        if callable(halt_method):
                            try:
                                halt_method(
                                    "child execution failed during complete platform batch",
                                    {
                                        "strategy_id": strategy_id,
                                        "trade_date": trade_date.isoformat(),
                                        "batch_request_sha256": request_sha256,
                                        "platform_preflight_sha256": (
                                            platform_preflight.get("preflight_sha256")
                                            if platform_preflight is not None
                                            else None
                                        ),
                                        "error": f"{type(exc).__name__}: {exc}",
                                    },
                                )
                            except Exception:
                                pass
                        raise
                    if observation is not None and dict(observation) != dict(execution):
                        raise ForwardDataError(
                            f"{strategy_id} execution and observation evidence diverged"
                        )
                    observation_result = {
                        "status": "COVERED_BY_EXECUTION",
                        "receipt_sha256": execution_result["receipt_sha256"],
                        "checkpoint_sha256": execution_result["checkpoint_sha256"],
                    }
                elif observation is not None:
                    observed = self.runner.observe_session(
                        strategy_id,
                        trade_date=trade_date.isoformat(),
                        market_reference=dict(observation),
                        recorded_at=recorded_at,
                    )
                    observation_result = {
                        "status": "FINALIZED_NO_TRADE",
                        "receipt_sha256": observed["receipt_sha256"],
                        "checkpoint_sha256": observed["checkpoint_sha256"],
                    }

                signal = entry.get("signal")
                if signal is not None:
                    refs = dict(dict(signal).get("data_refs") or {})
                    generated_at = _timestamp(
                        str(
                            dict(signal).get("generated_at")
                            or payload["recorded_at"]
                        )
                    )
                    formal_materialized = (
                        self.runner._formal_signal_materialization(
                            spec=spec,
                            strategy_id=strategy_id,
                            signal_date=trade_date,
                            cutoff_at=generated_at,
                            data_refs=refs,
                        )
                        if callable(
                            getattr(
                                self.runner,
                                "_formal_signal_materialization",
                                None,
                            )
                        )
                        else None
                    )
                    if formal_materialized is not None:
                        calendar_payload = dict(
                            formal_materialized["payloads"]["calendar"]
                        )
                    else:
                        calendar = self.runner._approved_dataset(
                            spec, dict(refs.get("calendar") or {}), "calendar"
                        )
                        calendar_payload = dict(calendar["payload"])
                    calendar_dates = sorted(
                        {
                            _day(value)
                            for value in list(
                                calendar_payload.get("trading_dates") or []
                            )
                        }
                    )
                    if trade_date not in calendar_dates:
                        raise ForwardDataError(
                            f"batch date is absent from {strategy_id} approved calendar"
                        )
                    if platform_decision != "PASS":
                        signal_result = {
                            "status": f"SKIPPED_PLATFORM_{platform_decision}",
                            "signal_sha256": None,
                            "execute_on": None,
                        }
                    elif self._signal_due(
                        str(spec["signal_frequency"]), trade_date, calendar_dates
                    ):
                        frozen = self.signal_factory.generate_and_register(
                            strategy_id,
                            signal_date=trade_date.isoformat(),
                            generated_at=generated_at,
                            recorded_at=recorded_at,
                            data_refs=refs,
                        )
                        signal_result = {
                            "status": "REGISTERED",
                            "signal_sha256": frozen["signal_sha256"],
                            "execute_on": frozen["execute_on"],
                        }
                    else:
                        signal_result = {
                            "status": "SKIPPED_NOT_SIGNAL_DAY",
                            "signal_sha256": None,
                            "execute_on": None,
                        }
                assert observation_result is not None
                results.append(
                    {
                        "strategy_id": strategy_id,
                        "execution": (
                            None
                            if execution_result is None
                            else {
                                "status": "FINALIZED",
                                "receipt_sha256": execution_result["receipt_sha256"],
                                "checkpoint_sha256": execution_result[
                                    "checkpoint_sha256"
                                ],
                            }
                        ),
                        "observation": observation_result,
                        "signal": signal_result,
                    }
                )

            identity = {
                "schema": FORWARD_DAILY_RECEIPT_SCHEMA,
                "trade_date": trade_date.isoformat(),
                "recorded_at": recorded_at.isoformat(),
                "request_sha256": request_sha256,
                "request": payload,
                "platform_portfolio_preflight": platform_preflight,
                "pretrade_execution_batch": pretrade_batch,
                "parent_order_allocation_plan": allocation_plan,
                "results": results,
                "real_orders": False,
            }
            receipt = {**identity, "receipt_sha256": sha256_digest(identity)}
            _immutable_json(
                self.root / "receipts" / f"{receipt['receipt_sha256']}.json",
                receipt,
            )
            _atomic_json(
                self.root / "by-date" / f"{trade_date}.json",
                {
                    "trade_date": trade_date.isoformat(),
                    "request_sha256": request_sha256,
                    "receipt_sha256": receipt["receipt_sha256"],
                },
            )
            return {**receipt, "idempotent": False}
