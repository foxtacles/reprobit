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
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Any, Self


class StateError(RuntimeError):
    """Local state is unsafe, busy, or cannot be managed."""


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
    cache_records: int = 0
    cache_blobs: int = 0
    cache_active_leases: int = 0
    cache_stale_leases: int = 0

    @property
    def run_bytes(self) -> int:
        return sum(item.bytes for item in self.runs)

    @property
    def run_files(self) -> int:
        return sum(item.files for item in self.runs)

    @property
    def total_bytes(self) -> int:
        return self.run_bytes + self.cache_bytes

    @property
    def total_files(self) -> int:
        return self.run_files + self.cache_files


@dataclass(frozen=True, slots=True)
class GCResult:
    """The exact result of one state garbage-collection pass."""

    removed: tuple[Path, ...]
    reclaimed_bytes: int
    skipped_active: tuple[Path, ...]
    skipped_recent: tuple[Path, ...]
    cache_removed_records: int = 0
    cache_removed_blobs: int = 0
    cache_active_leases: int = 0
    cache_skipped_recent_records: int = 0
    dry_run: bool = False


_RUN_KIND = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_OUTCOME_FILE = ".outcome.json"
_LEASE_FILE = ".lease"


class _FileLock:
    """Small cross-platform advisory lock around one held byte."""

    def __init__(self, path: Path, *, create: bool = True) -> None:
        if create:
            path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        flags = (
            os.O_RDWR
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        if create:
            flags |= os.O_CREAT
        descriptor = os.open(path, flags, 0o600)
        self.stream = os.fdopen(descriptor, "r+b", buffering=0)
        if self.stream.seek(0, os.SEEK_END) == 0:
            if not create:
                self.stream.close()
                raise StateError(f"existing state lock is empty: {path}")
            self.stream.write(b"\0")
        self.stream.seek(0)
        self.locked = False

    def acquire(self, *, nonblocking: bool) -> bool:
        if self.locked:
            raise StateError(f"state lock is already held: {self.path}")
        if os.name == "nt":
            import msvcrt

            native_msvcrt: Any = msvcrt
            mode = native_msvcrt.LK_NBLCK if nonblocking else native_msvcrt.LK_LOCK
            try:
                native_msvcrt.locking(self.stream.fileno(), mode, 1)
            except OSError:
                if nonblocking:
                    return False
                raise
        else:
            import fcntl

            operation = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
            try:
                fcntl.flock(self.stream.fileno(), operation)
            except BlockingIOError:
                return False
        self.locked = True
        return True

    def read_locked(self, *, maximum: int) -> bytes:
        """Read a small marker through the handle that owns the lock.

        Windows byte-range locks are mandatory, so reopening the same marker
        while it is locked fails even in the owning process.  Reading through
        this held descriptor works on every supported platform and also lets
        us confirm that the named path still identifies the locked file.
        """

        if not self.locked:
            raise StateError(f"state lock is not held: {self.path}")
        if maximum < 0:
            raise ValueError("locked read maximum cannot be negative")
        held_before = os.fstat(self.stream.fileno())
        named_before = os.stat(self.path, follow_symlinks=False)
        if not stat.S_ISREG(named_before.st_mode) or not os.path.samestat(
            held_before, named_before
        ):
            raise StateError(f"state lock path changed while held: {self.path}")
        self.stream.seek(0)
        payload = self.stream.read(maximum + 1)
        self.stream.seek(0)
        held_after = os.fstat(self.stream.fileno())
        named_after = os.stat(self.path, follow_symlinks=False)
        if (
            not stat.S_ISREG(named_after.st_mode)
            or not os.path.samestat(held_before, held_after)
            or not os.path.samestat(held_after, named_after)
        ):
            raise StateError(f"state lock path changed while held: {self.path}")
        if len(payload) > maximum:
            raise StateError(f"state lock marker is oversized: {self.path}")
        return payload

    def close(self) -> None:
        if self.locked:
            if os.name == "nt":
                import msvcrt

                native_msvcrt: Any = msvcrt
                self.stream.seek(0)
                native_msvcrt.locking(
                    self.stream.fileno(), native_msvcrt.LK_UNLCK, 1
                )
            else:
                import fcntl

                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            self.locked = False
        self.stream.close()

    def __enter__(self) -> Self:
        if not self.acquire(nonblocking=False):  # pragma: no cover - blocking lock
            raise AssertionError("blocking state lock unexpectedly failed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self.close()


# Cache and run-state maintenance share this small primitive so garbage
# collection and active operations follow one cross-platform locking contract.
AdvisoryFileLock = _FileLock


def _require_real_directory(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise StateError(f"{label} must be absolute: {path}")
    if os.path.lexists(path):
        if path.is_symlink() or not path.is_dir():
            raise StateError(f"{label} is not a real directory: {path}")
    else:
        path.mkdir(parents=True)
    return path.resolve(strict=True)


def _atomic_json(path: Path, value: object) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _tree_usage(root: Path) -> tuple[int, int, int]:
    """Return bytes, regular-file count, and newest mtime without following links."""

    total_bytes = 0
    files = 0
    newest = root.stat(follow_symlinks=False).st_mtime_ns
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = tuple(os.scandir(directory))
        except OSError as exc:
            raise StateError(f"cannot inspect state directory {directory}: {exc}") from exc
        for entry in entries:
            try:
                stat_result = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise StateError(f"cannot inspect state entry {entry.path}: {exc}") from exc
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
            raise StateError(f"invalid run kind: {kind!r}")
        self.state_root = _require_real_directory(state_root, "state root")
        self.runs_root = self.state_root / "runs"
        if os.path.lexists(self.runs_root):
            if self.runs_root.is_symlink() or not self.runs_root.is_dir():
                raise StateError(f"runs root is not a real directory: {self.runs_root}")
        else:
            self.runs_root.mkdir()
        identifier = run_id or uuid.uuid4().hex
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", identifier):
            raise StateError(f"invalid run id: {identifier!r}")
        self.path = self.runs_root / f"{kind}-{identifier}"
        self.keep = KeepWorkspace(keep)
        self._lease: _FileLock | None = None
        self._entered = False
        self._finished = False

    def __enter__(self) -> Self:
        if self._entered:
            raise StateError("run arena is single-use")
        self._entered = True
        try:
            self.path.mkdir(exist_ok=False)
        except FileExistsError as exc:
            raise StateError(f"run arena already exists: {self.path}") from exc
        lease = _FileLock(self.path / _LEASE_FILE)
        try:
            if not lease.acquire(nonblocking=True):  # freshly-created path
                raise StateError(f"cannot lease fresh run arena: {self.path}")
            self._lease = lease
            _atomic_json(
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
            raise StateError("run arena is not active")
        self._finished = True
        outcome = "succeeded" if succeeded else "failed"
        _atomic_json(
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
        if lease is not None:
            lease.close()
        if not should_keep:
            self._remove()

    def _remove(self) -> None:
        if self.path.is_symlink() or not self.path.is_dir():
            raise StateError(f"run arena changed type before cleanup: {self.path}")
        if self.path.parent.resolve(strict=True) != self.runs_root.resolve(strict=True):
            raise StateError("run arena escaped the runs root")
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
                raise StateError(f"state root must be absolute: {root}")
            if os.path.lexists(root):
                if root.is_symlink() or not root.is_dir():
                    raise StateError(f"state root is not a real directory: {root}")
                self.root = root.resolve(strict=True)
            else:
                self.root = root.resolve(strict=False)
        self.runs_root = self.root / "runs"
        self.cache_root = self.root / "cache"

    def _run_paths(self) -> tuple[Path, ...]:
        if not os.path.lexists(self.runs_root):
            return ()
        if self.runs_root.is_symlink() or not self.runs_root.is_dir():
            raise StateError(f"runs root is not a real directory: {self.runs_root}")
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
        if not lease_path.is_file():
            return False
        lock = _FileLock(lease_path)
        try:
            return not lock.acquire(nonblocking=True)
        finally:
            lock.close()

    def status(self) -> StateStatus:
        runs: list[RunState] = []
        for path in self._run_paths():
            size, files, modified_ns = _tree_usage(path)
            runs.append(
                RunState(
                    path=path,
                    kind=path.name.split("-", 1)[0],
                    active=self._active(path),
                    outcome=_outcome(path),
                    bytes=size,
                    files=files,
                    modified_ns=modified_ns,
                )
            )
        if os.path.lexists(self.cache_root):
            if self.cache_root.is_symlink() or not self.cache_root.is_dir():
                raise StateError(f"cache root is not a real directory: {self.cache_root}")
            from reprobit.cache import IncrementalCache

            cache_status = IncrementalCache(
                self.root,
                implementation="state-maintenance-v1",
                create=False,
            ).status()
            cache_bytes = cache_status.bytes
            cache_files = cache_status.files
        else:
            cache_bytes, cache_files = 0, 0
            cache_status = None
        return StateStatus(
            self.root,
            tuple(runs),
            cache_bytes,
            cache_files,
            cache_records=cache_status.records if cache_status is not None else 0,
            cache_blobs=cache_status.blobs if cache_status is not None else 0,
            cache_active_leases=(
                cache_status.active_leases if cache_status is not None else 0
            ),
            cache_stale_leases=(
                cache_status.stale_leases if cache_status is not None else 0
            ),
        )

    def gc(
        self,
        *,
        older_than_seconds: float = 0.0,
        dry_run: bool = False,
    ) -> GCResult:
        if older_than_seconds < 0:
            raise StateError("GC age cannot be negative")
        cutoff_ns = time.time_ns() - int(older_than_seconds * 1_000_000_000)
        removed: list[Path] = []
        skipped_active: list[Path] = []
        skipped_recent: list[Path] = []
        reclaimed = 0
        for path in self._run_paths():
            size, _, modified_ns = _tree_usage(path)
            lease_path = path / _LEASE_FILE
            if lease_path.is_symlink():
                skipped_active.append(path)
                continue
            lease = _FileLock(lease_path)
            if not lease.acquire(nonblocking=True):
                lease.close()
                skipped_active.append(path)
                continue
            try:
                # Recheck under the lease; a completed arena cannot become active
                # without replacing the directory, which is rejected below.
                _, _, modified_ns = _tree_usage(path)
                if modified_ns > cutoff_ns:
                    skipped_recent.append(path)
                    continue
                if path.is_symlink() or path.parent.resolve(strict=True) != self.runs_root:
                    raise StateError(f"run escaped state root during GC: {path}")
                # Windows cannot remove the held lease file. Close only after
                # ownership has been established and immediately remove it.
                lease.close()
                if not dry_run:
                    shutil.rmtree(path)
                removed.append(path)
                reclaimed += size
            finally:
                lease.close()
        cache_removed_records = 0
        cache_removed_blobs = 0
        cache_active_leases = 0
        cache_skipped_recent_records = 0
        if os.path.lexists(self.cache_root):
            if self.cache_root.is_symlink() or not self.cache_root.is_dir():
                raise StateError(f"cache root is not a real directory: {self.cache_root}")
            from reprobit.cache import IncrementalCache

            cache_result = IncrementalCache(
                self.root,
                implementation="state-maintenance-v1",
                create=False,
            ).gc(
                older_than_seconds=older_than_seconds,
                dry_run=dry_run,
            )
            cache_removed_records = cache_result.removed_records
            cache_removed_blobs = cache_result.removed_blobs
            cache_active_leases = cache_result.active_leases
            cache_skipped_recent_records = cache_result.skipped_recent_records
            reclaimed += cache_result.reclaimed_bytes
        return GCResult(
            tuple(removed),
            reclaimed,
            tuple(skipped_active),
            tuple(skipped_recent),
            cache_removed_records,
            cache_removed_blobs,
            cache_active_leases,
            cache_skipped_recent_records,
            dry_run,
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
    "AdvisoryFileLock",
    "GCResult",
    "KeepWorkspace",
    "RunArena",
    "RunState",
    "StateError",
    "StateStatus",
    "StateStore",
    "human_bytes",
]
