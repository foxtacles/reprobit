"""Stable human and machine output rendering for ReproBit commands."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path, PurePath
from threading import Lock
from typing import TYPE_CHECKING, Any, TextIO

from pydantic import BaseModel
from rich.console import Console
from rich.progress import (
    MofNCompleteColumn,
    Progress,
    ProgressColumn,
    SpinnerColumn,
    Task,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.text import Text

from reprobit.progress import ProgressEmitter, ProgressEvent, ProgressKind

if TYPE_CHECKING:
    from reprobit.incremental import IncrementalBuildSummary


ACTIVITY_PHASE_KINDS = frozenset(
    {
        ProgressKind.PHASE_STARTED,
        ProgressKind.PHASE_FINISHED,
        ProgressKind.PHASE_FAILED,
        ProgressKind.HEARTBEAT,
    }
)

_MAX_FAILURE_DETAIL = 160
_ASCII_BAR_WIDTH = 24

# Every ndjson event carries this version, matching the progress events'
# ProgressEvent.schema_version, so consumers can detect a future shape change.
EVENT_SCHEMA_VERSION = 1


def human_command(argv: Sequence[str | Path]) -> str:
    """Render copyable human text while machine events retain the argv array."""

    arguments = tuple(os.fspath(value) for value in argv)
    return subprocess.list2cmdline(arguments) if os.name == "nt" else shlex.join(arguments)


def count_phrase(count: int, singular: str, plural: str | None = None) -> str:
    """Render a grammatical count for user-facing CLI text."""

    noun = singular if count == 1 else (plural or f"{singular}s")
    return f"{count} {noun}"


class _ASCIIBarColumn(ProgressColumn):
    """Compact terminal-safe bar using only portable ASCII characters."""

    def render(self, task: Task) -> Text:
        total = task.total
        if total is None or total <= 0:
            cycle = max(1, (_ASCII_BAR_WIDTH - 1) * 2)
            step = int(task.get_time() * 8) % cycle
            position = min(step, cycle - step)
            cells = ["-"] * _ASCII_BAR_WIDTH
            cells[position] = "#"
        else:
            ratio = min(1.0, max(0.0, task.completed / total))
            filled = min(_ASCII_BAR_WIDTH, int(ratio * _ASCII_BAR_WIDTH))
            cells = ["#"] * filled + ["-"] * (_ASCII_BAR_WIDTH - filled)
        return Text("[" + "".join(cells) + "]", style="progress.bar.complete")


_FRIENDLY_PHASES = {
    "analysis-link": "Creating comparison files",
    "analysis-pair": "Publishing comparison files",
    "analyze": "Analyzing candidates",
    "compile": "Compiling source",
    "compose": "Applying reviewed interventions",
    "discovery-analyze": "Analyzing candidates",
    "discovery-compile": "Trying declaration states",
    "discovery-enumerate": "Planning the search",
    "discovery-finalize": "Writing discovery results",
    "grind-donors": "Trying donor candidates",
    "grind-finalize": "Finishing the search",
    "grind-publish": "Saving proven project files",
    "grind-qualify": "Checking candidate compatibility",
    "grind-seed": "Compiling the current translation unit",
    "grind-skip": "Skipping incompatible candidates",
    "grind-verify": "Verifying the best candidate from scratch",
    "donor-compile": "Building donor candidates",
    "evidence": "Checking trust evidence",
    "input-namespace": "Preparing compiler inputs",
    "link": "Linking targets",
    "link-controls": "Checking linker inputs",
    "object-transform": "Stabilizing object layout",
    "repair-probe": "Trying nearby donor settings",
    "repair-probe-prepare": "Preparing a safe donor search",
    "resource": "Compiling resources",
    "source-epoch": "Preparing source inputs",
    "terminal": "Saving verified targets",
    "validate": "Checking project files",
    "validation": "Validating final output",
}


def _friendly_phase(phase: str) -> str:
    return _FRIENDLY_PHASES.get(phase, phase.replace("-", " ").capitalize())


def _friendly_incremental_phase(phase: str, node_id: str) -> str:
    """Give analysis nodes their user-facing work name without changing the DAG."""

    if node_id.startswith("analysis-link."):
        return _friendly_phase("analysis-link")
    return _friendly_phase(phase)


_FRIENDLY_INVALIDATIONS = {
    # classic_cache.probe_compiler_cache: the cache holds no earlier record
    # for this step, so nothing could be reused.
    "no prior dependency hint": "not cached on this machine yet (first build of this step)",
}


def _friendly_invalidation(reason: str) -> str:
    return _FRIENDLY_INVALIDATIONS.get(reason, reason)


def _compact_failure_detail(error: BaseException | str) -> str:
    detail = " ".join(str(error).replace("\0", r"\0").split())
    if not detail:
        detail = type(error).__name__ if isinstance(error, BaseException) else "unknown error"
    if len(detail) <= _MAX_FAILURE_DETAIL:
        return detail
    return detail[: _MAX_FAILURE_DETAIL - 3] + "..."


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_jsonable(item) for item in value]
    return value


@dataclass(slots=True)
class CLIOutput:
    output_format: str
    stdout: TextIO
    stderr: TextIO
    heartbeat_seconds: float = 5.0
    _progress: ProgressEmitter = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._progress = ProgressEmitter(
            self._observe_progress,
            heartbeat_seconds=self.heartbeat_seconds,
        )

    @property
    def _interactive(self) -> bool:
        return bool(getattr(self.stderr, "isatty", lambda: False)())

    def _observe_progress(self, progress_event: ProgressEvent) -> None:
        if self.output_format == "ndjson":
            event_name = (
                "producer_progress"
                if progress_event.kind
                in {
                    ProgressKind.UNIT_FINISHED,
                    ProgressKind.CACHE_HIT,
                    ProgressKind.CACHE_MISS,
                }
                else "workflow_progress"
            )
            document = {"event": event_name, **progress_event.as_dict()}
            self.stdout.write(
                json.dumps(
                    document,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            self.stdout.flush()
            return
        if self._interactive or progress_event.kind in {
            ProgressKind.UNIT_FINISHED,
            ProgressKind.CACHE_HIT,
            ProgressKind.CACHE_MISS,
        }:
            return
        context: list[str] = []
        if progress_event.completed is not None and progress_event.total is not None:
            context.append(f"{progress_event.completed}/{progress_event.total}")
        if progress_event.node_id is not None:
            context.append(f"{progress_event.phase}: {progress_event.node_id}")
        if progress_event.kind is ProgressKind.PHASE_STARTED:
            rendered = f"{progress_event.message}..."
        elif progress_event.kind is ProgressKind.HEARTBEAT:
            context.append(f"{progress_event.elapsed_seconds:.1f}s elapsed")
            rendered = f"{progress_event.message}... ({'; '.join(context)})"
        elif progress_event.kind is ProgressKind.PHASE_FINISHED:
            context.append(f"{progress_event.elapsed_seconds:.1f}s elapsed")
            rendered = f"{progress_event.message}: complete ({'; '.join(context)})"
        elif progress_event.kind is ProgressKind.PHASE_FAILED:
            if progress_event.reason is not None:
                context.append(f"error: {_compact_failure_detail(progress_event.reason)}")
            detail = f" ({'; '.join(context)})" if context else ""
            rendered = f"{progress_event.message}: failed{detail}"
        else:
            rendered = progress_event.message
        self.stderr.write(rendered + "\n")
        self.stderr.flush()

    def emit(
        self,
        event: str,
        message: str,
        *,
        diagnostic: bool = False,
        **fields: Any,
    ) -> None:
        if self.output_format == "ndjson":
            document = {
                "event": event,
                "message": message,
                "schema_version": EVENT_SCHEMA_VERSION,
                **fields,
            }
            self.stdout.write(
                json.dumps(
                    _jsonable(document),
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
        else:
            stream = self.stderr if diagnostic else self.stdout
            stream.write(message + "\n")
            stream.flush()
            return
        self.stdout.flush()

    def incremental_summary(self, summary: IncrementalBuildSummary) -> None:
        """Emit one compact warm-build cache/runtime outcome."""

        start_unit = "time" if summary.runtime_init_count == 1 else "times"
        message = (
            f"Incremental build: {summary.hits} reused, {summary.misses} rebuilt "
            f"({summary.hit_rate:.1%} reused); compiler environment started "
            f"{summary.runtime_init_count} {start_unit}; "
            f"{summary.elapsed_seconds:.2f}s"
        )
        if summary.published_targets or summary.unchanged_targets:
            message += (
                f"; target outputs: {summary.unchanged_targets} unchanged, "
                f"{summary.published_targets} updated"
            )
        if summary.published_comparison_pairs or summary.unchanged_comparison_pairs:
            message += (
                f"; comparison pairs: {summary.unchanged_comparison_pairs} unchanged, "
                f"{summary.published_comparison_pairs} updated"
            )
        if self.output_format == "text" and summary.invalidations:
            visible = summary.invalidations[:8]
            lines = [message, "Why steps were rebuilt:"]
            lines.extend(
                f"  {node_id}: {_friendly_invalidation(reason)}" for node_id, reason in visible
            )
            remaining = len(summary.invalidations) - len(visible)
            if remaining:
                lines.append(f"  ... and {remaining} more")
            message = "\n".join(lines)
        self.emit(
            "incremental_build_summary",
            message,
            producer_hits=summary.producer_hits,
            producer_misses=summary.producer_misses,
            transform_hits=summary.transform_hits,
            transform_misses=summary.transform_misses,
            hits=summary.hits,
            misses=summary.misses,
            hit_rate=summary.hit_rate,
            elapsed_seconds=summary.elapsed_seconds,
            runtime_init_count=summary.runtime_init_count,
            published_targets=summary.published_targets,
            unchanged_targets=summary.unchanged_targets,
            published_comparison_pairs=summary.published_comparison_pairs,
            unchanged_comparison_pairs=summary.unchanged_comparison_pairs,
            invalidations=[
                {"node_id": node_id, "reason": reason} for node_id, reason in summary.invalidations
            ],
        )

    @contextmanager
    def activity(
        self,
        description: str,
        *,
        phase: str = "work",
    ) -> Iterator[Callable[[str], None]]:
        with self._progress.phase(phase, description) as phase_scope:
            if self.output_format != "text" or not self._interactive:

                def update(message: str) -> None:
                    phase_scope.activity(
                        kind=ProgressKind.PHASE_STARTED,
                        phase=phase,
                        message=message,
                    )

                yield update
                return
            console = Console(file=self.stderr)
            started = time.monotonic()
            failure: BaseException | None = None
            try:
                with Progress(
                    SpinnerColumn("line"),
                    TextColumn("{task.description}"),
                    TimeElapsedColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task(description, total=None)

                    def update(message: str) -> None:
                        phase_scope.activity(
                            kind=ProgressKind.PHASE_STARTED,
                            phase=phase,
                            message=message,
                        )
                        progress.update(task, description=message)

                    yield update
            except BaseException as error:
                failure = error
                raise
            finally:
                elapsed = max(0.0, time.monotonic() - started)
                if failure is not None:
                    summary = (
                        f"{description}: failed ({elapsed:.1f}s elapsed; "
                        f"error: {_compact_failure_detail(failure)})"
                    )
                    self.stderr.write(summary + "\n")
                    self.stderr.flush()

    @contextmanager
    def producer_activity(self, description: str) -> Iterator[Callable[..., None]]:
        """Render serialized producer progress without corrupting machine output."""

        lock = Lock()
        with self._progress.phase("execute", description) as phase_scope:
            if self.output_format == "ndjson":

                def emit_ndjson(
                    completed: int,
                    total: int,
                    phase: str,
                    node_id: str,
                    kind: ProgressKind = ProgressKind.UNIT_FINISHED,
                    reason: str | None = None,
                ) -> None:
                    if kind in ACTIVITY_PHASE_KINDS:
                        phase_scope.activity(
                            kind=kind,
                            phase=phase,
                            message=node_id,
                            reason=reason,
                        )
                        return
                    if kind in {ProgressKind.CACHE_HIT, ProgressKind.CACHE_MISS}:
                        phase_scope.cache(
                            hit=kind is ProgressKind.CACHE_HIT,
                            completed=completed,
                            total=total,
                            phase=phase,
                            node_id=node_id,
                            reason=reason,
                        )
                    else:
                        phase_scope.advance(
                            completed=completed,
                            total=total,
                            phase=phase,
                            node_id=node_id,
                        )

                yield emit_ndjson
                return
            if self._interactive:
                console = Console(file=self.stderr)
                started = time.monotonic()
                cache_hits = 0
                cache_misses = 0
                latest_count: tuple[int, int] | None = None
                latest_context: tuple[str, str, str] | None = None
                latest_failure: tuple[str, str, str | None] | None = None
                failure: BaseException | None = None
                try:
                    with Progress(
                        SpinnerColumn("line"),
                        TextColumn("{task.description}"),
                        _ASCIIBarColumn(),
                        MofNCompleteColumn(),
                        TimeElapsedColumn(),
                        TimeRemainingColumn(),
                        console=console,
                        transient=True,
                    ) as progress:
                        task = progress.add_task(description, total=None)

                        def update_tty(
                            completed: int,
                            total: int,
                            phase: str,
                            node_id: str,
                            kind: ProgressKind = ProgressKind.UNIT_FINISHED,
                            reason: str | None = None,
                        ) -> None:
                            nonlocal cache_hits, cache_misses
                            nonlocal latest_context, latest_count, latest_failure
                            if kind in ACTIVITY_PHASE_KINDS:
                                phase_scope.activity(
                                    kind=kind,
                                    phase=phase,
                                    message=node_id,
                                    reason=reason,
                                )
                                disposition = {
                                    ProgressKind.PHASE_FINISHED: "complete",
                                    ProgressKind.PHASE_FAILED: "failed",
                                }.get(kind, "active")
                            elif kind in {ProgressKind.CACHE_HIT, ProgressKind.CACHE_MISS}:
                                hit = kind is ProgressKind.CACHE_HIT
                                phase_scope.cache(
                                    hit=hit,
                                    completed=completed,
                                    total=total,
                                    phase=phase,
                                    node_id=node_id,
                                    reason=reason,
                                )
                                disposition = "hit" if hit else "miss"
                            else:
                                phase_scope.advance(
                                    completed=completed,
                                    total=total,
                                    phase=phase,
                                    node_id=node_id,
                                )
                                disposition = "complete"
                            with lock:
                                if kind in {ProgressKind.CACHE_HIT, ProgressKind.CACHE_MISS}:
                                    cache_hits += int(kind is ProgressKind.CACHE_HIT)
                                    cache_misses += int(kind is ProgressKind.CACHE_MISS)
                                if kind not in ACTIVITY_PHASE_KINDS:
                                    latest_count = (completed, total)
                                latest_context = (phase, node_id, disposition)
                                if kind is ProgressKind.PHASE_FAILED:
                                    latest_failure = (phase, node_id, reason)
                                progress.update(
                                    task,
                                    total=total,
                                    completed=completed,
                                    description=(
                                        f"{description} - "
                                        f"{_friendly_incremental_phase(phase, node_id)}"
                                    ),
                                )

                        yield update_tty
                except BaseException as error:
                    failure = error
                    raise
                finally:
                    elapsed = max(0.0, time.monotonic() - started)
                    with lock:
                        cache = (
                            f"; cache {cache_hits} hit/{cache_misses} miss"
                            if cache_hits or cache_misses
                            else ""
                        )
                        if failure is not None:
                            count = (
                                f" after {latest_count[0]}/{latest_count[1]}"
                                if latest_count is not None
                                else ""
                            )
                            details = [f"{elapsed:.1f}s elapsed"]
                            failure_detail = _compact_failure_detail(failure)
                            reported_failure_detail: str | None = None
                            if latest_failure is not None:
                                failed_phase, failed_node, failed_reason = latest_failure
                                failed_context = f"{failed_phase}: {failed_node}"
                                if failed_reason is not None:
                                    reported_failure_detail = _compact_failure_detail(failed_reason)
                                    failed_context += f": {reported_failure_detail}"
                                details.append(f"last failure: {failed_context}")
                            elif latest_context is not None:
                                last_phase, last_node, disposition = latest_context
                                details.append(
                                    f"last progress: {last_phase}: {last_node} ({disposition})"
                                )
                            if failure_detail != reported_failure_detail:
                                details.append(f"error: {failure_detail}")
                            summary = f"{description}: failed{count} ({'; '.join(details)}{cache})"
                            self.stderr.write(summary + "\n")
                            self.stderr.flush()
                return

            last_decile = -1
            cache_hits = 0
            cache_misses = 0

            def emit_text(
                completed: int,
                total: int,
                phase: str,
                node_id: str,
                kind: ProgressKind = ProgressKind.UNIT_FINISHED,
                reason: str | None = None,
            ) -> None:
                nonlocal cache_hits, cache_misses, last_decile
                if kind in ACTIVITY_PHASE_KINDS:
                    phase_scope.activity(
                        kind=kind,
                        phase=phase,
                        message=node_id,
                        reason=reason,
                    )
                    return
                if kind in {ProgressKind.CACHE_HIT, ProgressKind.CACHE_MISS}:
                    hit = kind is ProgressKind.CACHE_HIT
                    cache_hits += int(hit)
                    cache_misses += int(not hit)
                    phase_scope.cache(
                        hit=hit,
                        completed=completed,
                        total=total,
                        phase=phase,
                        node_id=node_id,
                        reason=reason,
                    )
                else:
                    phase_scope.advance(
                        completed=completed,
                        total=total,
                        phase=phase,
                        node_id=node_id,
                    )
                decile = 10 if completed == total else (completed * 10) // max(total, 1)
                if completed != 1 and decile <= last_decile:
                    return
                with lock:
                    if completed != 1 and decile <= last_decile:
                        return
                    last_decile = decile
                    cache = (
                        f"; cache {cache_hits} hit/{cache_misses} miss"
                        if cache_hits or cache_misses
                        else ""
                    )
                    self.stderr.write(
                        f"{description}: {completed}/{total} ({phase}: {node_id}{cache})\n"
                    )
                    self.stderr.flush()

            yield emit_text
