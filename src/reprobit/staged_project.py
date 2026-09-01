"""Run-private copies of sealed project inputs shared by repair and discovery."""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType

from reprobit.model import Digest
from reprobit.state import KeepWorkspace, RunArena


@dataclass(frozen=True, slots=True)
class ProjectFileSnapshot:
    """One immutable project input captured before a private run begins."""

    relative_path: str
    digest: Digest
    payload: bytes


class StagedProject:
    """A run-private project copy containing only sealed certification inputs.

    Every staged byte is flushed and fsynced before its digest is rechecked so
    that a retained workspace never carries an unsynced, partially written input.
    """

    def __init__(
        self,
        state_root: Path,
        files: tuple[ProjectFileSnapshot, ...],
        *,
        kind: str,
        keep: KeepWorkspace,
        error: Callable[[str], Exception],
    ) -> None:
        self.files = files
        self.arena = RunArena(state_root, kind=kind, keep=keep)
        self.root: Path | None = None
        self._error = error

    @property
    def retained_path(self) -> Path:
        return self.arena.path

    def __enter__(self) -> Path:
        arena = self.arena.__enter__()
        root = arena.path / "project"
        self.root = root
        try:
            root.mkdir()
            for snapshot in self.files:
                destination = root.joinpath(*PurePosixPath(snapshot.relative_path).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as stream:
                    stream.write(snapshot.payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                if Digest.from_path(destination) != snapshot.digest:
                    raise self._error(snapshot.relative_path)
        except BaseException:
            arena.finish(succeeded=False)
            raise
        return root

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.arena.__exit__(exc_type, exc, traceback)


__all__ = ["ProjectFileSnapshot", "StagedProject"]
