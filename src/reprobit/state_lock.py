"""Cross-platform advisory lock shared by local state and cache storage."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import TracebackType
from typing import Any, Self


class StateError(RuntimeError):
    """Local state is unsafe, busy, or cannot be managed."""


class AdvisoryFileLock:
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
        try:
            held = os.fstat(descriptor)
            named = os.stat(path, follow_symlinks=False)
            if not stat.S_ISREG(named.st_mode) or not os.path.samestat(held, named):
                raise StateError(f"state lock path is not a real file: {path}")
            self.stream = os.fdopen(descriptor, "r+b", buffering=0)
        except BaseException:
            os.close(descriptor)
            raise
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
