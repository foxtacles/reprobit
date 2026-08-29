"""Typed, machine-readable progress events for long-running workflows."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from types import TracebackType
from typing import Self


class ProgressKind(StrEnum):
    """Stable event kinds emitted by ReproBit workflows."""

    PHASE_STARTED = "phase_started"
    PHASE_FINISHED = "phase_finished"
    PHASE_FAILED = "phase_failed"
    HEARTBEAT = "heartbeat"
    UNIT_FINISHED = "unit_finished"
    CACHE_HIT = "cache_hit"
    CACHE_MISS = "cache_miss"


_PHASE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """One ordered progress observation suitable for terminal or NDJSON UIs."""

    sequence: int
    kind: ProgressKind
    phase: str
    message: str
    elapsed_seconds: float
    completed: int | None = None
    total: int | None = None
    node_id: str | None = None
    reason: str | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        if self.schema_version != 1:
            raise ValueError("unsupported progress-event schema")
        if self.sequence < 1:
            raise ValueError("progress sequence must be positive")
        if not _PHASE.fullmatch(self.phase):
            raise ValueError(f"invalid progress phase: {self.phase!r}")
        if not self.message or "\0" in self.message:
            raise ValueError("progress message must be non-empty and NUL-free")
        if self.elapsed_seconds < 0:
            raise ValueError("progress elapsed time cannot be negative")
        if (self.completed is None) != (self.total is None):
            raise ValueError("progress completed and total must be supplied together")
        if (
            self.completed is not None
            and self.total is not None
            and (self.total < 0 or not 0 <= self.completed <= self.total)
        ):
            raise ValueError("progress counts are outside their declared total")
        if self.node_id is not None and (not self.node_id or "\0" in self.node_id):
            raise ValueError("progress node id must be non-empty and NUL-free")
        if self.reason is not None and (not self.reason or "\0" in self.reason):
            raise ValueError("progress reason must be non-empty and NUL-free")

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-ready document without absent optional fields."""

        result: dict[str, object] = {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "kind": self.kind.value,
            "phase": self.phase,
            "message": self.message,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
        }
        if self.completed is not None:
            result["completed"] = self.completed
            result["total"] = self.total
        if self.node_id is not None:
            result["node_id"] = self.node_id
        if self.reason is not None:
            result["reason"] = self.reason
        return result


ProgressObserver = Callable[[ProgressEvent], None]


class ProgressEmitter:
    """Serialize events and provide heartbeat-backed phase scopes."""

    def __init__(
        self,
        observer: ProgressObserver | None,
        *,
        heartbeat_seconds: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if heartbeat_seconds <= 0:
            raise ValueError("progress heartbeat interval must be positive")
        self._observer = observer
        self._heartbeat_seconds = heartbeat_seconds
        self._clock = clock
        self._started = clock()
        self._sequence = 0
        self._lock = threading.Lock()

    def emit(
        self,
        kind: ProgressKind,
        phase: str,
        message: str,
        *,
        completed: int | None = None,
        total: int | None = None,
        node_id: str | None = None,
        reason: str | None = None,
        elapsed_seconds: float | None = None,
    ) -> ProgressEvent:
        """Emit one event in total order and return it for local rendering."""

        with self._lock:
            self._sequence += 1
            event = ProgressEvent(
                sequence=self._sequence,
                kind=kind,
                phase=phase,
                message=message,
                elapsed_seconds=(
                    max(0.0, self._clock() - self._started)
                    if elapsed_seconds is None
                    else elapsed_seconds
                ),
                completed=completed,
                total=total,
                node_id=node_id,
                reason=reason,
            )
            if self._observer is not None:
                self._observer(event)
            return event

    def phase(self, phase: str, message: str) -> ProgressPhase:
        """Create a scope that emits start, heartbeats, and one terminal event."""

        return ProgressPhase(self, phase, message, self._heartbeat_seconds)


class ProgressPhase:
    """Context manager for a phase with bounded-silence heartbeats."""

    def __init__(
        self,
        emitter: ProgressEmitter,
        phase: str,
        message: str,
        heartbeat_seconds: float,
    ) -> None:
        self._emitter = emitter
        self.phase = phase
        self.message = message
        self._heartbeat_seconds = heartbeat_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._entered = False
        self._started: float | None = None
        self._snapshot_lock = threading.Lock()
        self._latest_count: tuple[int, int] | None = None
        self._latest_context: tuple[str, str] | None = None
        self._latest_reason: str | None = None

    def _remember(
        self,
        *,
        phase: str,
        node_id: str,
        completed: int | None = None,
        total: int | None = None,
        reason: str | None = None,
    ) -> None:
        with self._snapshot_lock:
            if completed is not None and total is not None:
                self._latest_count = (completed, total)
            self._latest_context = (phase, node_id)
            self._latest_reason = reason

    def _snapshot(
        self,
    ) -> tuple[int | None, int | None, str, str | None, str | None]:
        with self._snapshot_lock:
            completed, total = self._latest_count or (None, None)
            if self._latest_context is None:
                return completed, total, self.phase, None, self._latest_reason
            phase, node_id = self._latest_context
            return completed, total, phase, node_id, self._latest_reason

    def _elapsed(self) -> float:
        if self._started is None:
            raise RuntimeError("progress phase has not started")
        return max(0.0, self._emitter._clock() - self._started)

    def __enter__(self) -> Self:
        if self._entered:
            raise RuntimeError("progress phase is single-use")
        self._entered = True
        self._started = self._emitter._clock()
        self._emitter.emit(
            ProgressKind.PHASE_STARTED,
            self.phase,
            self.message,
            elapsed_seconds=0.0,
        )

        def heartbeat() -> None:
            while not self._stop.wait(self._heartbeat_seconds):
                completed, total, phase, node_id, reason = self._snapshot()
                self._emitter.emit(
                    ProgressKind.HEARTBEAT,
                    phase,
                    self.message,
                    completed=completed,
                    total=total,
                    node_id=node_id,
                    reason=reason,
                    elapsed_seconds=self._elapsed(),
                )

        self._thread = threading.Thread(
            target=heartbeat,
            name=f"reprobit-progress-{self.phase}",
            daemon=True,
        )
        self._thread.start()
        return self

    def advance(
        self,
        *,
        completed: int,
        total: int,
        phase: str,
        node_id: str,
    ) -> ProgressEvent:
        """Record completion of one known work unit."""

        event = self._emitter.emit(
            ProgressKind.UNIT_FINISHED,
            phase,
            f"completed {node_id}",
            completed=completed,
            total=total,
            node_id=node_id,
            elapsed_seconds=self._elapsed(),
        )
        self._remember(
            completed=completed,
            total=total,
            phase=phase,
            node_id=node_id,
        )
        return event

    def cache(
        self,
        *,
        hit: bool,
        phase: str,
        node_id: str,
        completed: int,
        total: int,
        reason: str | None = None,
    ) -> ProgressEvent:
        """Record an explicit developer-cache decision."""

        event = self._emitter.emit(
            ProgressKind.CACHE_HIT if hit else ProgressKind.CACHE_MISS,
            phase,
            f"cache {'hit' if hit else 'miss'} for {node_id}",
            completed=completed,
            total=total,
            node_id=node_id,
            reason=reason,
            elapsed_seconds=self._elapsed(),
        )
        self._remember(
            completed=completed,
            total=total,
            phase=phase,
            node_id=node_id,
            reason=reason,
        )
        return event

    def activity(
        self,
        *,
        kind: ProgressKind,
        phase: str,
        message: str,
        reason: str | None = None,
    ) -> ProgressEvent:
        """Record one named sub-phase without changing completed-unit counts."""

        if kind not in {
            ProgressKind.PHASE_STARTED,
            ProgressKind.PHASE_FINISHED,
            ProgressKind.PHASE_FAILED,
            ProgressKind.HEARTBEAT,
        }:
            raise ValueError(f"progress activity cannot emit {kind.value!r}")
        event = self._emitter.emit(
            kind,
            phase,
            message,
            reason=reason,
            elapsed_seconds=self._elapsed(),
        )
        self._remember(
            phase=phase,
            node_id=message,
            reason=reason if kind is ProgressKind.PHASE_FAILED else None,
        )
        return event

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del traceback
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=min(self._heartbeat_seconds, 1.0))
        completed, total, phase, node_id, _reason = self._snapshot()
        if exc_type is None:
            self._emitter.emit(
                ProgressKind.PHASE_FINISHED,
                self.phase,
                self.message,
                completed=completed,
                total=total,
                node_id=node_id,
                elapsed_seconds=self._elapsed(),
            )
        else:
            detail = str(exc) if exc is not None else exc_type.__name__
            if not detail:
                detail = exc_type.__name__
            detail = detail.replace("\x00", r"\0")
            self._emitter.emit(
                ProgressKind.PHASE_FAILED,
                phase,
                self.message,
                completed=completed,
                total=total,
                node_id=node_id,
                reason=detail,
                elapsed_seconds=self._elapsed(),
            )


__all__ = [
    "ProgressEmitter",
    "ProgressEvent",
    "ProgressKind",
    "ProgressObserver",
    "ProgressPhase",
]
