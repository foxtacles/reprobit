"""Bounded run-workspace lifecycle and inspectable local state.

The state directory is deliberately outside the authenticity boundary: cold
verification never consumes cached artifacts from it.  This module only owns
ephemeral run arenas and their leases so successful runs do not accumulate
multi-gigabyte compiler and Wine workspaces indefinitely.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Self

from reprobit.atomic_io import write_json_atomic
from reprobit.state_lock import AdvisoryFileLock as _AdvisoryFileLock
from reprobit.state_lock import StateError as _StateError


class KeepWorkspace(StrEnum):
    """When a run arena remains available for diagnostics."""

    NEVER = "never"
    ON_FAILURE = "on-failure"
    ALWAYS = "always"


@dataclass(frozen=True, slots=True)
class RunState:
    """One inspectable run beneath ``state/runs``."""

    path: Path
    kind: str
    active: bool
    outcome: str
    bytes: int
    files: int
    modified_ns: int


@dataclass(frozen=True, slots=True)
class StateStatus:
    """A bounded snapshot of state usage."""

    root: Path
    runs: tuple[RunState, ...]
    cache_bytes: int
    cache_files: int
    report_bytes: int
    report_files: int
    cache_records: int = 0
    cache_blobs: int = 0
    cache_active_leases: int = 0
    cache_stale_leases: int = 0
    cache_current_records: int = 0
    cache_obsolete_records: int = 0

    @property
    def run_bytes(self) -> int:
        return sum(item.bytes for item in self.runs)

    @property
    def run_files(self) -> int:
        return sum(item.files for item in self.runs)

    @property
    def total_bytes(self) -> int:
        return self.run_bytes + self.cache_bytes + self.report_bytes

    @property
    def total_files(self) -> int:
        return self.run_files + self.cache_files + self.report_files


@dataclass(frozen=True, slots=True)
class GCResult:
    """The exact result of one state garbage-collection pass."""

    removed: tuple[Path, ...]
    reclaimed_bytes: int
    skipped_active: tuple[Path, ...]
    skipped_recent: tuple[Path, ...]
    reports_removed: tuple[Path, ...] = ()
    report_files: int = 0
    report_bytes: int = 0
    cache_removed_records: int = 0
    cache_removed_blobs: int = 0
    cache_active_leases: int = 0
    cache_skipped_recent_records: int = 0
    dry_run: bool = False


_RUN_KIND = re.compile(r"^[a-z][a-z0-9]{0,31}$")
_OUTCOME_FILE = ".outcome.json"
_LEASE_FILE = ".lease"
_MAINTENANCE_FILE = ".maintenance.lock"
_CANONICAL_REPORTS = ("report.html", "report.json")
_GRIND_REPORT_DIRECTORY = "grind"


def _require_real_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise _StateError(f"{label} must be absolute: {path}")
    if os.path.lexists(path):
        if path.is_symlink() or not path.is_dir():
            raise _StateError(f"{label} is not a real directory: {path}")
    else:
        path.mkdir(parents=True)
    return path.resolve(strict=True)


@contextmanager
def _maintenance_gate(state_root: Path, *, create: bool = True) -> Iterator[None]:
    """Serialize short arena lifecycle transitions and state GC."""

    if state_root.is_symlink() or not state_root.is_dir():
        raise _StateError(f"state root is not a real directory: {state_root}")
    lock_path = state_root / _MAINTENANCE_FILE
    if not create and not os.path.lexists(lock_path):
        yield
        return
    lock = _AdvisoryFileLock(lock_path, create=create)
    try:
        if not lock.acquire(nonblocking=False):  # pragma: no cover - blocking lock
            raise AssertionError("blocking maintenance lock unexpectedly failed")
        lock.read_locked(maximum=1)
        yield
    finally:
        lock.close()


@contextmanager
def report_publication_lease(state_root: Path) -> Iterator[None]:
    """Keep managed report publication exclusive with state cleanup."""

    root = _require_real_directory(state_root, "state root")
    with _maintenance_gate(root):
        yield


def _require_runs_root(runs_root: Path) -> None:
    if os.path.lexists(runs_root):
        if runs_root.is_symlink() or not runs_root.is_dir():
            raise _StateError(f"runs root is not a real directory: {runs_root}")
    else:
        runs_root.mkdir()


def _tree_usage(root: Path) -> tuple[int, int, int]:
    """Return bytes, regular-file count, and newest mtime without following links."""

    total_bytes = 0
    files = 0
    root_stat = root.stat(follow_symlinks=False)
    if not stat.S_ISDIR(root_stat.st_mode):
        raise _StateError(f"state run is not a real directory: {root}")
    newest = root_stat.st_mtime_ns
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = os.scandir(directory)
        except OSError as exc:
            raise _StateError(f"cannot inspect state directory {directory}: {exc}") from exc
        with entries:
            for entry in entries:
                try:
                    stat_result = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise _StateError(f"cannot inspect state entry {entry.path}: {exc}") from exc
                newest = max(newest, stat_result.st_mtime_ns)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    files += 1
                    total_bytes += stat_result.st_size
    return total_bytes, files, newest


def _outcome(path: Path) -> str:
    outcome_path = path / _OUTCOME_FILE
    if outcome_path.is_symlink() or not outcome_path.is_file():
        return "incomplete"
    try:
        value = json.loads(outcome_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return "invalid"
    outcome = value.get("outcome") if isinstance(value, dict) else None
    return outcome if outcome in {"succeeded", "failed", "interrupted"} else "invalid"


class RunArena:
    """A leased per-invocation workspace with deterministic retention."""

    def __init__(
        self,
        state_root: Path,
        *,
        kind: str,
        keep: KeepWorkspace = KeepWorkspace.ON_FAILURE,
        run_id: str | None = None,
    ) -> None:
        if not _RUN_KIND.fullmatch(kind):
            raise _StateError(f"invalid run kind: {kind!r}")
        self.state_root = _require_real_directory(state_root, "state root")
        self.runs_root = self.state_root / "runs"
        if os.path.lexists(self.runs_root) and (
            self.runs_root.is_symlink() or not self.runs_root.is_dir()
        ):
            raise _StateError(f"runs root is not a real directory: {self.runs_root}")
        identifier = run_id or uuid.uuid4().hex
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", identifier):
            raise _StateError(f"invalid run id: {identifier!r}")
        self.path = self.runs_root / f"{kind}-{identifier}"
        self.keep = KeepWorkspace(keep)
        self._lease: _AdvisoryFileLock | None = None
        self._entered = False
        self._finished = False

    def __enter__(self) -> Self:
        if self._entered:
            raise _StateError("run arena is single-use")
        self._entered = True
        with _maintenance_gate(self.state_root):
            _require_runs_root(self.runs_root)
            try:
                self.path.mkdir(exist_ok=False)
            except FileExistsError as exc:
                raise _StateError(f"run arena already exists: {self.path}") from exc
            lease = _AdvisoryFileLock(self.path / _LEASE_FILE)
            try:
                if not lease.acquire(nonblocking=True):  # freshly-created path
                    raise _StateError(f"cannot lease fresh run arena: {self.path}")
                self._lease = lease
                write_json_atomic(
                    self.path / _OUTCOME_FILE,
                    {
                        "kind": self.path.name.split("-", 1)[0],
                        "outcome": "interrupted",
                        "pid": os.getpid(),
                        "started_ns": time.time_ns(),
                    },
                )
            except BaseException:
                self._lease = None
                lease.close()
                shutil.rmtree(self.path)
                raise
        return self

    def finish(self, *, succeeded: bool) -> None:
        if not self._entered or self._finished:
            raise _StateError("run arena is not active")
        self._finished = True
        outcome = "succeeded" if succeeded else "failed"
        write_json_atomic(
            self.path / _OUTCOME_FILE,
            {
                "kind": self.path.name.split("-", 1)[0],
                "outcome": outcome,
                "pid": os.getpid(),
                "finished_ns": time.time_ns(),
            },
        )
        should_keep = self.keep is KeepWorkspace.ALWAYS or (
            self.keep is KeepWorkspace.ON_FAILURE and not succeeded
        )
        lease = self._lease
        self._lease = None
        with _maintenance_gate(self.state_root):
            if lease is not None:
                lease.close()
            if not should_keep:
                self._remove()

    def _remove(self) -> None:
        if self.path.is_symlink() or not self.path.is_dir():
            raise _StateError(f"run arena changed type before cleanup: {self.path}")
        if self.path.parent.resolve(strict=True) != self.runs_root.resolve(strict=True):
            raise _StateError("run arena escaped the runs root")
        shutil.rmtree(self.path)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc, traceback
        if not self._finished:
            self.finish(succeeded=exc_type is None)


class StateStore:
    """Inspect and garbage-collect state without racing active arenas."""

    def __init__(self, root: Path, *, create: bool = True) -> None:
        if create:
            self.root = _require_real_directory(root, "state root")
        else:
            if not root.is_absolute():
                raise _StateError(f"state root must be absolute: {root}")
            if os.path.lexists(root):
                if root.is_symlink() or not root.is_dir():
                    raise _StateError(f"state root is not a real directory: {root}")
                self.root = root.resolve(strict=True)
            else:
                self.root = root.resolve(strict=False)
        self.runs_root = self.root / "runs"
        self.cache_root = self.root / "cache"
        self.reports_root = self.root / "reports"

    def _managed_report_paths(self) -> tuple[Path, ...]:
        """Return only report paths created and owned by ReproBit."""

        if not os.path.lexists(self.reports_root):
            return ()
        if self.reports_root.is_symlink() or not self.reports_root.is_dir():
            raise _StateError(f"reports root is not a real directory: {self.reports_root}")
        paths: list[Path] = []
        for name in _CANONICAL_REPORTS:
            path = self.reports_root / name
            if not os.path.lexists(path):
                continue
            if path.is_symlink() or not path.is_file():
                raise _StateError(f"managed report is not a real file: {path}")
            paths.append(path)
        grind = self.reports_root / _GRIND_REPORT_DIRECTORY
        if os.path.lexists(grind):
            if grind.is_symlink() or not grind.is_dir():
                raise _StateError(f"grind reports root is not a real directory: {grind}")
            paths.append(grind)
        return tuple(paths)

    @staticmethod
    def _report_usage(paths: tuple[Path, ...]) -> tuple[int, int]:
        total_bytes = 0
        total_files = 0
        for path in paths:
            if path.is_dir():
                size, files, _ = _tree_usage(path)
                total_bytes += size
                total_files += files
            else:
                report_stat = path.stat(follow_symlinks=False)
                if not stat.S_ISREG(report_stat.st_mode):
                    raise _StateError(f"managed report is not a real file: {path}")
                total_bytes += report_stat.st_size
                total_files += 1
        return total_bytes, total_files

    def _run_paths(self) -> tuple[Path, ...]:
        if not os.path.lexists(self.runs_root):
            return ()
        if self.runs_root.is_symlink() or not self.runs_root.is_dir():
            raise _StateError(f"runs root is not a real directory: {self.runs_root}")
        paths: list[Path] = []
        for item in self.runs_root.iterdir():
            if item.is_symlink() or not item.is_dir():
                continue
            paths.append(item)
        return tuple(sorted(paths, key=lambda item: item.name))

    @staticmethod
    def _active(path: Path) -> bool:
        lease_path = path / _LEASE_FILE
        if lease_path.is_symlink():
            return True
        if not os.path.lexists(lease_path):
            return False
        if not lease_path.is_file():
            raise _StateError(f"run lease is not a real file: {lease_path}")
        try:
            lock = _AdvisoryFileLock(lease_path, create=False)
        except FileNotFoundError:
            return False
        try:
            if not lock.acquire(nonblocking=True):
                return True
            lock.read_locked(maximum=1)
            return False
        finally:
            lock.close()

    def status(
        self,
        *,
        cache_implementation: str = "state-maintenance-v1",
        cache_implementation_family: str | None = None,
    ) -> StateStatus:
        runs: list[RunState] = []
        if os.path.lexists(self.root):
            with _maintenance_gate(self.root, create=False):
                run_activity = tuple((path, self._active(path)) for path in self._run_paths())
        else:
            run_activity = ()
        for path, active in run_activity:
            try:
                size, files, modified_ns = _tree_usage(path)
                outcome = _outcome(path)
            except (FileNotFoundError, _StateError):
                if not os.path.lexists(path):
                    continue
                raise
            if not os.path.lexists(path):
                continue
            runs.append(
                RunState(
                    path=path,
                    kind=path.name.split("-", 1)[0],
                    active=active,
                    outcome=outcome,
                    bytes=size,
                    files=files,
                    modified_ns=modified_ns,
                )
            )
        if os.path.lexists(self.cache_root):
            if self.cache_root.is_symlink() or not self.cache_root.is_dir():
                raise _StateError(f"cache root is not a real directory: {self.cache_root}")
            from reprobit.cache import IncrementalCache

            cache_status = IncrementalCache(
                self.root,
                implementation=cache_implementation,
                create=False,
            ).status(implementation_family=cache_implementation_family)
            cache_bytes = cache_status.bytes
            cache_files = cache_status.files
        else:
            cache_bytes, cache_files = 0, 0
            cache_status = None
        try:
            report_paths = self._managed_report_paths()
            report_bytes, report_files = self._report_usage(report_paths)
        except FileNotFoundError:
            # A completed report may be replaced or removed while status is
            # scanning it. A later status invocation will observe the new set.
            report_paths = self._managed_report_paths()
            report_bytes, report_files = self._report_usage(report_paths)
        return StateStatus(
            self.root,
            tuple(runs),
            cache_bytes,
            cache_files,
            report_bytes,
            report_files,
            cache_records=cache_status.records if cache_status is not None else 0,
            cache_blobs=cache_status.blobs if cache_status is not None else 0,
            cache_active_leases=(cache_status.active_leases if cache_status is not None else 0),
            cache_stale_leases=(cache_status.stale_leases if cache_status is not None else 0),
            cache_current_records=(cache_status.current_records if cache_status is not None else 0),
            cache_obsolete_records=(
                cache_status.obsolete_records if cache_status is not None else 0
            ),
        )

    def gc(
        self,
        *,
        older_than_seconds: float = 0.0,
        dry_run: bool = False,
        include_cache: bool = False,
        include_reports: bool = False,
        obsolete_cache_implementation: str | None = None,
        obsolete_cache_implementation_family: str | None = None,
    ) -> GCResult:
        """Remove inactive runs and explicitly selected cache or report data."""

        if older_than_seconds < 0:
            raise _StateError("GC age cannot be negative")
        obsolete_cache_requested = obsolete_cache_implementation is not None
        if obsolete_cache_requested != (obsolete_cache_implementation_family is not None):
            raise _StateError(
                "obsolete cache cleanup requires both an implementation and its family"
            )
        if include_cache and obsolete_cache_requested:
            raise _StateError("full and obsolete-only cache cleanup are mutually exclusive")
        cutoff_ns = time.time_ns() - int(older_than_seconds * 1_000_000_000)
        removed: list[Path] = []
        skipped_active: list[Path] = []
        skipped_recent: list[Path] = []
        reclaimed = 0
        cache_removed_records = 0
        cache_removed_blobs = 0
        cache_active_leases = 0
        cache_skipped_recent_records = 0
        reports_removed: tuple[Path, ...] = ()
        report_files = 0
        report_bytes = 0
        if os.path.lexists(self.root):
            with _maintenance_gate(self.root):
                for path in self._run_paths():
                    lease_path = path / _LEASE_FILE
                    if lease_path.is_symlink():
                        skipped_active.append(path)
                        continue
                    lease: _AdvisoryFileLock | None = None
                    if os.path.lexists(lease_path):
                        if not lease_path.is_file():
                            raise _StateError(f"run lease is not a real file: {lease_path}")
                        try:
                            lease = _AdvisoryFileLock(lease_path, create=False)
                        except FileNotFoundError:
                            lease = None
                        if lease is not None:
                            try:
                                acquired = lease.acquire(nonblocking=True)
                                if acquired:
                                    lease.read_locked(maximum=1)
                            except BaseException:
                                lease.close()
                                raise
                            if not acquired:
                                lease.close()
                                skipped_active.append(path)
                                continue
                    try:
                        # Scan only after an existing lease is owned. A missing
                        # lease denotes an abandoned pre-lease arena; the state
                        # maintenance gate prevents a creator from entering it.
                        size, _, modified_ns = _tree_usage(path)
                        if modified_ns > cutoff_ns:
                            skipped_recent.append(path)
                            continue
                        if path.is_symlink() or path.parent.resolve(strict=True) != self.runs_root:
                            raise _StateError(f"run escaped state root during GC: {path}")
                        # Windows cannot remove a held lease file. The state-wide
                        # gate keeps the close-to-remove window exclusive.
                        if lease is not None:
                            lease.close()
                            lease = None
                        if not dry_run:
                            shutil.rmtree(path)
                        removed.append(path)
                        reclaimed += size
                    except (FileNotFoundError, _StateError):
                        if not os.path.lexists(path):
                            continue
                        raise
                    finally:
                        if lease is not None:
                            lease.close()

        if (include_cache or obsolete_cache_requested) and os.path.lexists(self.cache_root):
            if self.cache_root.is_symlink() or not self.cache_root.is_dir():
                raise _StateError(f"cache root is not a real directory: {self.cache_root}")
            from reprobit.cache import IncrementalCache

            cache_result = IncrementalCache(
                self.root,
                implementation=(
                    obsolete_cache_implementation
                    if obsolete_cache_implementation is not None
                    else "state-maintenance-v1"
                ),
                create=False,
            ).gc(
                older_than_seconds=older_than_seconds,
                dry_run=dry_run,
                obsolete_implementation_family=obsolete_cache_implementation_family,
            )
            cache_removed_records = cache_result.removed_records
            cache_removed_blobs = cache_result.removed_blobs
            cache_active_leases = cache_result.active_leases
            cache_skipped_recent_records = cache_result.skipped_recent_records
            reclaimed += cache_result.reclaimed_bytes
        if include_cache:
            from reprobit.classic_repair_probe_cache import (
                probe_store_directory,
                probe_store_usage,
            )

            probe_store = probe_store_directory(self.root)
            if os.path.lexists(probe_store):
                if probe_store.is_symlink() or not probe_store.is_dir():
                    raise _StateError(f"probe store is not a real directory: {probe_store}")
                _files, probe_bytes = probe_store_usage(self.root)
                if not dry_run:
                    shutil.rmtree(probe_store)
                removed.append(probe_store)
                reclaimed += probe_bytes
        if include_reports and os.path.lexists(self.root):
            with _maintenance_gate(self.root):
                reports_removed = self._managed_report_paths()
                report_bytes, report_files = self._report_usage(reports_removed)
                if not dry_run:
                    for path in reports_removed:
                        if path.is_dir():
                            shutil.rmtree(path)
                        else:
                            path.unlink()
                reclaimed += report_bytes
        return GCResult(
            removed=tuple(removed),
            reclaimed_bytes=reclaimed,
            skipped_active=tuple(skipped_active),
            skipped_recent=tuple(skipped_recent),
            reports_removed=reports_removed,
            report_files=report_files,
            report_bytes=report_bytes,
            cache_removed_records=cache_removed_records,
            cache_removed_blobs=cache_removed_blobs,
            cache_active_leases=cache_active_leases,
            cache_skipped_recent_records=cache_skipped_recent_records,
            dry_run=dry_run,
        )


def human_bytes(value: int) -> str:
    """Render a stable compact byte count for CLI status output."""

    if value < 0:
        raise ValueError("byte count cannot be negative")
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    amount = float(value)
    for unit in units:
        if amount < 1024 or unit == units[-1]:
            return f"{int(amount)} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    raise AssertionError("byte unit loop did not terminate")


__all__ = [
    "GCResult",
    "KeepWorkspace",
    "RunArena",
    "RunState",
    "StateStatus",
    "StateStore",
    "human_bytes",
    "report_publication_lease",
]
