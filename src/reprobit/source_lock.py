"""Portable, race-checked project source manifests."""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath

from reprobit.model import Digest
from reprobit.schema import ProjectSpec, SourceManifestDocument, SourceManifestEntry


class SourceLockError(ValueError):
    """A project read-set cannot be represented as portable regular files."""


def _relative(value: str | Path) -> str:
    rendered = value.as_posix() if isinstance(value, Path) else value.replace("\\", "/")
    path = PurePosixPath(rendered)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise SourceLockError(f"source path is not canonical and relative: {value!r}")
    canonical = path.as_posix()
    if canonical != rendered:
        raise SourceLockError(f"source path is not canonical POSIX text: {value!r}")
    return canonical


def _receipt(path: Path, *, capture: bool = False) -> tuple[int, Digest, bytes | None]:
    if path.is_symlink() or not path.is_file():
        raise SourceLockError(f"source input is absent, non-regular, or redirected: {path}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    digest = sha256()
    captured: list[bytes] | None = [] if capture else None
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise SourceLockError(f"source input is not regular: {path}")
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
                if captured is not None:
                    captured.append(chunk)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise SourceLockError(f"cannot receipt source input {path}: {exc}") from exc
    before_identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if before_identity != after_identity:
        raise SourceLockError(f"source input changed while being receipted: {path}")
    data = b"".join(captured) if captured is not None else None
    return after.st_size, Digest(value=digest.hexdigest()), data


@dataclass(frozen=True, slots=True)
class ResolvedSourceRoot:
    """A project root resolved once so a batch of receipts can share it.

    Build one with :func:`resolve_source_root` before receipting many inputs
    below the same root.  Only the root resolution is shared; each receipt
    still walks its own components and resolves the input before and after
    reading it.
    """

    path: Path

    def __post_init__(self) -> None:
        if not self.path.is_absolute():
            raise SourceLockError(f"resolved source root must be absolute: {self.path}")


def resolve_source_root(root: Path) -> ResolvedSourceRoot:
    """Strictly resolve ``root`` once for a batch of :func:`receipt_source_input` calls."""

    return ResolvedSourceRoot(root.resolve(strict=True))


def receipt_source_input(
    root: Path | ResolvedSourceRoot,
    relative: str | Path,
    *,
    capture: bool = False,
) -> tuple[int, Digest, bytes | None]:
    """Receipt one canonical input while rejecting redirected path components.

    ``root`` may be a :class:`ResolvedSourceRoot` when the caller receipts
    many inputs; a plain path is resolved here for that one receipt.
    """

    root = root.path if isinstance(root, ResolvedSourceRoot) else root.resolve(strict=True)
    canonical = _relative(relative)
    path = root
    for component in PurePosixPath(canonical).parts:
        path = path / component
        if path.is_symlink():
            raise SourceLockError(f"source input is redirected: {canonical!r}")
    try:
        before = path.resolve(strict=True)
        before.relative_to(root)
    except (OSError, ValueError) as exc:
        raise SourceLockError(f"source input escapes or is absent: {canonical!r}") from exc
    size, digest, data = _receipt(path, capture=capture)
    try:
        after = path.resolve(strict=True)
        after.relative_to(root)
    except (OSError, ValueError) as exc:
        raise SourceLockError(f"source input escapes or is absent: {canonical!r}") from exc
    if before != after:
        raise SourceLockError(f"source input changed identity while being receipted: {canonical!r}")
    return size, digest, data


def git_tracked_paths(root: Path) -> tuple[str, ...]:
    """Return the repository's finite tracked file set as canonical paths."""

    root = root.resolve(strict=True)
    try:
        completed = subprocess.run(
            ("git", "-C", os.fspath(root), "ls-files", "-z", "--cached", "--recurse-submodules"),
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SourceLockError(f"cannot enumerate tracked project inputs: {exc}") from exc
    try:
        cached = tuple(
            _relative(item.decode("utf-8")) for item in completed.stdout.split(b"\0") if item
        )
    except UnicodeDecodeError as exc:
        raise SourceLockError("tracked source paths must be valid UTF-8") from exc
    values: list[str] = []
    for relative in cached:
        candidate = root
        redirected_or_unsupported = False
        parts = PurePosixPath(relative).parts
        for index, component in enumerate(parts):
            candidate = candidate / component
            if candidate.is_symlink():
                redirected_or_unsupported = True
                break
            if index < len(parts) - 1 and os.path.lexists(candidate) and not candidate.is_dir():
                redirected_or_unsupported = True
                break
        if redirected_or_unsupported or os.path.lexists(candidate):
            values.append(relative)
    if not values:
        raise SourceLockError("the project has no tracked source inputs")
    return tuple(values)


def is_git_worktree(root: Path) -> bool:
    """Return whether the default source selector can inspect ``root`` with Git."""

    root = root.resolve(strict=True)
    try:
        completed = subprocess.run(
            ("git", "-C", os.fspath(root), "rev-parse", "--is-inside-work-tree"),
            check=False,
            capture_output=True,
        )
    except OSError:
        return False
    return completed.returncode == 0 and completed.stdout.strip() == b"true"


def _forbidden(spec: ProjectSpec) -> tuple[set[str], tuple[str, ...]]:
    exact = {
        "reprobit.toml",
        spec.toolchain.lock_file.replace("\\", "/").casefold(),
        spec.layout.source_manifest.replace("\\", "/").casefold(),
        spec.layout.build_plan.replace("\\", "/").casefold(),
        spec.layout.producer_graph.replace("\\", "/").casefold(),
        *(
            value.replace("\\", "/").casefold()
            for target in spec.targets
            for value in (target.artifact, target.oracle)
        ),
    }
    roots = tuple(
        value.replace("\\", "/").rstrip("/").casefold() + "/"
        for value in (
            spec.state_dir,
            spec.layout.interventions,
            spec.layout.proofs,
            spec.layout.oracles,
            # Host CI configuration is never a build input; admitting it only
            # forces a relock for every workflow edit.
            ".github",
        )
    )
    return exact, roots


def _selected_source_paths(
    paths: Iterable[str | Path],
    *,
    spec: ProjectSpec | None,
) -> tuple[str, ...]:
    exact, roots = _forbidden(spec) if spec is not None else (set(), ())
    canonical: dict[str, str] = {}
    for raw in paths:
        relative = _relative(raw)
        folded = relative.casefold()
        if folded in exact or folded.startswith(roots):
            continue
        previous = canonical.get(folded)
        if previous is not None and previous != relative:
            raise SourceLockError(
                f"source paths collide under DOS case folding: {previous!r}, {relative!r}"
            )
        canonical[folded] = relative
    return tuple(sorted(canonical.values(), key=lambda item: (item.casefold(), item)))


def tracked_source_paths(root: Path, spec: ProjectSpec) -> tuple[str, ...]:
    """Select the default source membership without hashing file contents."""

    return _selected_source_paths(git_tracked_paths(root), spec=spec)


def build_source_manifest(
    root: Path,
    paths: Iterable[str | Path],
    *,
    spec: ProjectSpec | None = None,
    complete: bool = True,
) -> SourceManifestDocument:
    """Hash an explicit source read set, rejecting redirects and DOS collisions."""

    resolved = resolve_source_root(root)
    entries = []
    for relative in _selected_source_paths(paths, spec=spec):
        size, digest, _ = receipt_source_input(resolved, relative)
        entries.append(SourceManifestEntry(path=relative, size=size, digest=digest))
    if not entries:
        raise SourceLockError("source manifest would contain no admitted files")
    return SourceManifestDocument(
        schema_version=3,
        complete=complete,
        entries=tuple(entries),
    )


def lock_tracked_sources(root: Path, spec: ProjectSpec) -> SourceManifestDocument:
    """Build the default complete authority from version-controlled inputs."""

    return build_source_manifest(root, git_tracked_paths(root), spec=spec, complete=True)


__all__ = [
    "ResolvedSourceRoot",
    "SourceLockError",
    "build_source_manifest",
    "git_tracked_paths",
    "is_git_worktree",
    "lock_tracked_sources",
    "receipt_source_input",
    "resolve_source_root",
    "tracked_source_paths",
]
