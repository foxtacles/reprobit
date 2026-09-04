"""Journaled compare-and-swap transactions for project-file updates."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Self

from reprobit.atomic_io import fsync_directory
from reprobit.exact_tree import (
    ExactTreeError,
    create_directory_in_exact_parent,
    move_directory_in_exact_parent,
    remove_exact_directory_tree,
)
from reprobit.model import Digest
from reprobit.secure_path_contracts import (
    SecureFileSnapshot,
    SecurePathError,
    is_redirected,
    no_follow_directory_flags,
)
from reprobit.secure_paths import (
    atomic_publish_new_relative_from_stream as _publish_new_from_stream,
)
from reprobit.secure_paths import (
    atomic_publish_relative_if_current,
    digest_relative_file,
    promote_relative_new,
    read_relative_file,
    remove_published_relative,
)
from reprobit.strict_json import canonical_json


class TransactionError(RuntimeError):
    """A transaction could not be safely staged, applied, or recovered."""


class TransactionConflict(TransactionError):
    """A target changed since its expected preimage was recorded."""


class TransactionBusy(TransactionError):
    """Another process owns the project transaction lock."""


_AUTOMATIC: Final = object()
_TRANSACTION_ID = re.compile(r"[0-9a-f]{32}").fullmatch
_DirectoryIdentity = tuple[int, int]


def sha256_bytes(data: bytes) -> str:
    return Digest.from_bytes(data).value


def sha256_file(path: Path) -> str:
    return Digest.from_path(path).value


def _validate_digest(value: str | None) -> str | None:
    if value is None:
        return None
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("expected SHA-256 must be 64 lower-case hexadecimal characters")
    return value


def _relative_path(value: Path | str) -> Path:
    path = Path(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"transaction path must be canonical and relative: {value}")
    rendered = str(value)
    if "\0" in rendered or ("\\" in rendered and (isinstance(value, str) or os.sep != "\\")):
        raise ValueError(f"transaction path contains an unsafe character: {value}")
    return path


def _canonical_transaction_id(value: object) -> str:
    if not isinstance(value, str) or _TRANSACTION_ID(value) is None:
        raise ValueError("transaction id must be 32 lower-case hexadecimal characters")
    return value


def _directory_identity(path: Path) -> _DirectoryIdentity:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise TransactionError(f"cannot inspect transaction directory: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode) or is_redirected(path):
        raise TransactionError(f"transaction seat is not a real directory: {path}")
    return metadata.st_dev, metadata.st_ino


def _require_directory_identity(path: Path, expected: _DirectoryIdentity) -> None:
    if _directory_identity(path) != expected:
        raise TransactionError(f"transaction seat changed: {path}")


def _state_root_identity(path: Path) -> _DirectoryIdentity:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise TransactionError(f"cannot inspect project transaction state: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode) or is_redirected(path):
        raise TransactionError(f"project transaction state is not a real directory: {path}")
    return metadata.st_dev, metadata.st_ino


def _require_state_root_identity(path: Path, expected: _DirectoryIdentity) -> None:
    if _state_root_identity(path) != expected:
        raise TransactionError(f"project transaction state changed: {path}")


def _sync_transaction_directory(path: Path, expected: _DirectoryIdentity) -> None:
    """Durably record private children through the captured transaction seat."""

    _require_directory_identity(path, expected)
    if os.name == "nt":
        fsync_directory(path)
    else:
        descriptor = os.open(path, no_follow_directory_flags())
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or (
                    metadata.st_dev,
                    metadata.st_ino,
                )
                != expected
            ):
                raise TransactionError(f"transaction seat changed: {path}")
            try:
                os.fsync(descriptor)
            except OSError as error:
                if error.errno not in {
                    errno.EINVAL,
                    getattr(errno, "ENOTSUP", errno.EINVAL),
                }:
                    raise
        finally:
            os.close(descriptor)
    _require_directory_identity(path, expected)


def _seat_expectations(
    root: Path,
    directory: Path,
    identity: _DirectoryIdentity,
    state_root_identity: _DirectoryIdentity,
) -> dict[str, _DirectoryIdentity]:
    try:
        relative = directory.relative_to(root)
    except ValueError as error:
        raise TransactionError(f"transaction seat escapes its project: {directory}") from error
    parent = relative.parent
    if parent == Path("."):
        raise TransactionError(f"transaction seat has no private state parent: {directory}")
    return {
        parent.as_posix(): state_root_identity,
        relative.as_posix(): identity,
    }


def _identity_record(identity: _DirectoryIdentity) -> list[int]:
    return [identity[0], identity[1]]


def _identity_from_record(value: object) -> _DirectoryIdentity:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(type(part) is not int or part < 0 for part in value)
    ):
        raise ValueError("directory identity must contain two non-negative integers")
    return value[0], value[1]


def _directory_ancestors(relative: Path, *, include_self: bool = False) -> tuple[Path, ...]:
    limit = len(relative.parts) if include_self else len(relative.parts) - 1
    return tuple(Path(*relative.parts[:depth]) for depth in range(1, limit + 1))


def _expectations_for(
    expected: dict[str, _DirectoryIdentity],
    *relatives: Path,
) -> dict[str, _DirectoryIdentity]:
    """Select identities accepted by one secure multi-path operation."""

    allowed = {"."}
    for relative in relatives:
        allowed.update(path.as_posix() for path in _directory_ancestors(relative))
    return {path: identity for path, identity in expected.items() if path in allowed}


def _capture_existing_directories(
    root: Path,
    *,
    file_paths: tuple[Path, ...],
    directory_paths: tuple[Path, ...] = (),
) -> dict[str, _DirectoryIdentity]:
    """Capture the real project directories that define transaction targets."""

    wanted = {Path(".")}
    for relative in file_paths:
        wanted.update(_directory_ancestors(relative))
    for relative in directory_paths:
        wanted.update(_directory_ancestors(relative, include_self=True))

    captured: dict[str, _DirectoryIdentity] = {}
    for relative in sorted(wanted, key=lambda path: (len(path.parts), path.as_posix())):
        path = root if relative == Path(".") else root.joinpath(*relative.parts)
        if relative != Path(".") and not os.path.lexists(path):
            continue
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError as error:
            raise TransactionConflict(f"transaction directory changed: {path}") from error
        if not stat.S_ISDIR(metadata.st_mode) or is_redirected(path):
            raise TransactionConflict(f"transaction directory is redirected: {path}")
        key = "." if relative == Path(".") else relative.as_posix()
        captured[key] = (metadata.st_dev, metadata.st_ino)

    _require_expected_directories(root, captured)
    return captured


def _require_expected_directories(
    root: Path,
    expected: dict[str, _DirectoryIdentity],
) -> None:
    for relative, identity in expected.items():
        path = root if relative == "." else root.joinpath(*Path(relative).parts)
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError as error:
            raise TransactionConflict(f"transaction directory changed: {path}") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or is_redirected(path)
            or (metadata.st_dev, metadata.st_ino) != identity
        ):
            raise TransactionConflict(f"transaction directory changed: {path}")


def _directory_records(
    record: dict[str, Any],
) -> dict[str, _DirectoryIdentity | None]:
    value = record.get("directories", {})
    if not isinstance(value, dict):
        raise ValueError("transaction directories must be an object")
    captured: dict[str, _DirectoryIdentity | None] = {}
    for relative, identity in value.items():
        if not isinstance(relative, str):
            raise ValueError("transaction directory path must be a string")
        if relative == ".":
            canonical = relative
        else:
            canonical = _relative_path(relative).as_posix()
            if canonical != relative:
                raise ValueError("transaction directory path must be canonical")
            if canonical.startswith(".reprobit-transactions/") or canonical == (
                ".reprobit-transactions"
            ):
                raise ValueError("transaction directory cannot name private state")
        captured[canonical] = None if identity is None else _identity_from_record(identity)
    return captured


def _recorded_directories(record: dict[str, Any]) -> dict[str, _DirectoryIdentity]:
    return {
        path: identity
        for path, identity in _directory_records(record).items()
        if identity is not None
    }


def _prepare_state_root(root: Path, state_root: Path) -> _DirectoryIdentity:
    root_identity = _directory_identity(root)
    if os.path.lexists(state_root):
        state_identity = _state_root_identity(state_root)
    else:
        try:
            state_identity = create_directory_in_exact_parent(
                state_root,
                root_identity,
            )
        except ExactTreeError as error:
            raise TransactionError(
                f"cannot securely create project transaction state: {state_root}"
            ) from error
        fsync_directory(root)
    _require_state_root_identity(state_root, state_identity)
    try:
        state_root.resolve(strict=True).relative_to(root)
    except ValueError as error:
        raise TransactionError("project transaction state escapes its root") from error
    _require_state_root_identity(state_root, state_identity)
    return state_identity


def _safe_target(root: Path, relative_path: Path) -> Path:
    target = root.joinpath(*relative_path.parts)
    current = root
    for component in relative_path.parts[:-1]:
        current = current / component
        if is_redirected(current):
            raise TransactionError(f"transaction parent is redirected: {current}")
        if current.exists() and not current.is_dir():
            raise TransactionError(f"transaction parent is not a directory: {current}")
    if is_redirected(target):
        raise TransactionError(f"transaction target is redirected: {target}")
    return target


def _move_to_backup(
    root: Path,
    source: Path,
    backup: Path,
    *,
    expected: SecureFileSnapshot,
    expected_directories: dict[str, _DirectoryIdentity],
) -> SecureFileSnapshot:
    """Move an exact preimage without following a raced project path."""

    return promote_relative_new(
        root,
        source.as_posix(),
        backup.as_posix(),
        expected=expected,
        expected_directories=expected_directories,
    )


def _promote_staged(
    root: Path,
    source: Path,
    target: Path,
    *,
    expected: SecureFileSnapshot,
    expected_directories: dict[str, _DirectoryIdentity],
) -> SecureFileSnapshot:
    """Publish one exact staged output with commit-time no-clobber."""

    return promote_relative_new(
        root,
        source.as_posix(),
        target.as_posix(),
        expected=expected,
        expected_directories=expected_directories,
    )


def _publication_record(snapshot: SecureFileSnapshot) -> dict[str, object]:
    """Serialize identity fields that survive a held promotion."""

    return {
        "digest": snapshot.digest.value,
        "size": snapshot.size,
        "device": snapshot.device,
        "inode": snapshot.inode,
        "mtime_ns": snapshot.mtime_ns,
        "mode": snapshot.mode,
        "windows_file_id": snapshot.windows_file_id.hex(),
        "windows_attributes": snapshot.windows_attributes,
    }


def _snapshot_matches_record(
    snapshot: SecureFileSnapshot,
    record: object,
    expected_sha256: str | None = None,
) -> bool:
    if not isinstance(record, dict):
        return False
    if expected_sha256 is not None and snapshot.digest.value != expected_sha256:
        return False
    return _publication_record(snapshot) == record


def _optional_snapshot(
    root: Path,
    relative: Path,
    *,
    expected_directories: dict[str, _DirectoryIdentity] | None = None,
) -> SecureFileSnapshot | None:
    """Securely inspect a file, distinguishing a stable absence from redirects."""

    try:
        return digest_relative_file(
            root,
            relative.as_posix(),
            expected_directories=expected_directories,
        )
    except (FileNotFoundError, SecurePathError):
        for directory, identity in (expected_directories or {}).items():
            seat = root if directory == "." else root.joinpath(*Path(directory).parts)
            _require_directory_identity(seat, identity)
        if not os.path.lexists(root.joinpath(*relative.parts)):
            return None
        raise


def _write_journal(
    root: Path,
    relative: Path,
    record: dict[str, Any],
    *,
    expected: SecureFileSnapshot | None,
    expected_directories: dict[str, _DirectoryIdentity],
) -> SecureFileSnapshot:
    """Publish one journal revision only inside the captured seat."""

    try:
        return atomic_publish_relative_if_current(
            root,
            relative.as_posix(),
            canonical_json(record),
            expected=expected,
            mode=None if os.name == "nt" else 0o600,
            expected_directories=expected_directories,
        )
    except SecurePathError as error:
        raise TransactionError(f"transaction journal changed: {relative}") from error


def _read_journal(
    root: Path,
    directory: Path,
    identity: _DirectoryIdentity,
    state_root_identity: _DirectoryIdentity,
) -> tuple[dict[str, Any], SecureFileSnapshot] | None:
    """Read a journal through the captured seat, or report stable absence."""

    transaction_relative = directory.relative_to(root)
    journal_relative = transaction_relative / "journal.json"
    expected_directories = _seat_expectations(
        root,
        directory,
        identity,
        state_root_identity,
    )
    try:
        payload, snapshot = read_relative_file(
            root,
            journal_relative.as_posix(),
            expected_directories=expected_directories,
        )
    except (FileNotFoundError, SecurePathError) as error:
        _require_directory_identity(directory, identity)
        if not os.path.lexists(directory / "journal.json"):
            return None
        raise TransactionError(f"cannot securely read transaction journal: {directory}") from error
    try:
        value = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise TransactionError(f"cannot read transaction journal: {directory}") from error
    if not isinstance(value, dict):
        raise TransactionError(f"malformed transaction journal: {directory}")
    return value, snapshot


def _move_to_quarantine(
    source: Path,
    identity: _DirectoryIdentity,
    quarantine: Path,
    parent_identity: _DirectoryIdentity,
) -> None:
    """Keep the destructive rename patchable for deterministic race tests."""

    move_directory_in_exact_parent(
        source,
        identity,
        quarantine,
        parent_identity,
    )


def _remove_transaction_directory(
    root: Path,
    directory: Path,
    identity: _DirectoryIdentity,
    state_root_identity: _DirectoryIdentity,
    *,
    journal: SecureFileSnapshot | None,
) -> None:
    """Remove only an exact private seat, preserving every raced replacement."""

    expected_directories = _seat_expectations(
        root,
        directory,
        identity,
        state_root_identity,
    )
    if journal is not None:
        journal_relative = directory.relative_to(root) / "journal.json"
        try:
            removed = remove_published_relative(
                root,
                journal_relative.as_posix(),
                expected=journal,
                expected_directories=expected_directories,
            )
        except SecurePathError as error:
            raise TransactionError(f"transaction journal changed: {directory}") from error
        if not removed:
            raise TransactionError(f"transaction journal changed: {directory}")
    _require_state_root_identity(directory.parent, state_root_identity)
    _require_directory_identity(directory, identity)
    quarantine = directory.with_name(uuid.uuid4().hex)
    try:
        _move_to_quarantine(
            directory,
            identity,
            quarantine,
            state_root_identity,
        )
    except (ExactTreeError, OSError) as error:
        raise TransactionError(f"cannot quarantine transaction seat: {directory}") from error
    try:
        if _directory_identity(quarantine) != identity:
            raise TransactionError(
                f"transaction seat changed during cleanup; replacement preserved at {quarantine}"
            )
        remove_exact_directory_tree(quarantine, identity)
        _require_state_root_identity(directory.parent, state_root_identity)
        fsync_directory(directory.parent)
    except (ExactTreeError, OSError) as error:
        raise TransactionError(
            f"cannot remove quarantined transaction seat; preserved at {quarantine}"
        ) from error


def _validate_journal_record(directory: Path, record: dict[str, Any]) -> None:
    """Bind a recovery journal and all private paths to its exact seat."""

    try:
        transaction_id = _canonical_transaction_id(record.get("transaction_id"))
        recorded_directory = _canonical_transaction_id(record.get("transaction_directory"))
    except ValueError as error:
        raise TransactionError(f"malformed transaction journal: {directory}") from error
    if transaction_id != directory.name or recorded_directory != directory.name:
        raise TransactionError(f"transaction journal does not match its seat: {directory}")
    if record.get("schema") != CASTransaction.JOURNAL_SCHEMA:
        raise TransactionError(f"unsupported transaction journal: {directory / 'journal.json'}")
    if record.get("state") not in {"prepared", "applying", "committed"}:
        raise TransactionError(f"malformed transaction journal state: {directory}")
    operations = record.get("operations")
    if not isinstance(operations, list):
        raise TransactionError(f"malformed transaction journal: {directory}")
    allowed_directories = {"."}
    for index, entry in enumerate(operations):
        if not isinstance(entry, dict):
            raise TransactionError(f"malformed transaction operation: {directory}")
        try:
            operation_index = entry["index"]
            kind = entry["kind"]
            relative = _relative_path(entry["path"])
            _validate_digest(entry["expected_sha256"])
            result = _validate_digest(entry["result_sha256"])
            backup = _relative_path(entry["backup"])
            staged_path = _relative_path(entry["staged_path"])
        except (KeyError, TypeError, ValueError) as error:
            raise TransactionError(f"malformed transaction operation: {directory}") from error
        if (
            type(operation_index) is not int
            or operation_index != index
            or not isinstance(kind, str)
            or kind not in {"write", "delete", "check"}
            or relative.parts[0] == ".reprobit-transactions"
            or backup.as_posix() != f"backups/{index}"
            or staged_path.as_posix() != f"staged/{index}"
            or (kind == "write" and result is None)
            or (kind != "write" and result is not None)
        ):
            raise TransactionError(f"malformed transaction operation: {directory}")
        allowed_directories.update(parent.as_posix() for parent in _directory_ancestors(relative))
    try:
        directory_records = _directory_records(record)
    except (TypeError, ValueError) as error:
        raise TransactionError(f"malformed transaction directories: {directory}") from error
    if not set(directory_records).issubset(allowed_directories):
        raise TransactionError(f"malformed transaction directories: {directory}")
    if record.get("state") != "prepared" and set(directory_records) != allowed_directories:
        raise TransactionError(f"malformed transaction directories: {directory}")
    if record.get("state") != "prepared" and directory_records.get(".") is None:
        raise TransactionError(f"malformed transaction directories: {directory}")


def _open_project_lock(path: Path, parent_identity: _DirectoryIdentity) -> Any:
    """Open the lock through the exact transaction-state directory."""

    try:
        if os.name == "nt":
            import msvcrt

            from reprobit.secure_paths_windows import _HeldWindowsRoot

            native_msvcrt: Any = msvcrt
            with _HeldWindowsRoot(path.parent, expected_identity=parent_identity) as held:
                handle = held.api.open_relative(
                    held.handle,
                    path.name,
                    directory=False,
                    write=True,
                    allow_missing=True,
                )
                if handle is None:
                    try:
                        handle = held.api.open_relative(
                            held.handle,
                            path.name,
                            directory=False,
                            create=True,
                            write=True,
                            exclusive=True,
                        )
                    except SecurePathError:
                        handle = held.api.open_relative(
                            held.handle,
                            path.name,
                            directory=False,
                            write=True,
                        )
                assert handle is not None
                held.verify_root()
                try:
                    descriptor = native_msvcrt.open_osfhandle(
                        handle,
                        os.O_RDWR | getattr(os, "O_BINARY", 0),
                    )
                except BaseException:
                    held.api.close(handle)
                    raise
            return os.fdopen(descriptor, "r+b", buffering=0)

        from reprobit.secure_paths_posix import _HeldPosixRoot

        with _HeldPosixRoot(path.parent, expected_identity=parent_identity) as held:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path.name, flags, 0o600, dir_fd=held.fd)
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise TransactionError(f"project transaction lock is not a file: {path}")
                held.recheck([])
            except BaseException:
                os.close(descriptor)
                raise
        return os.fdopen(descriptor, "r+b", buffering=0)
    except (OSError, SecurePathError) as error:
        raise TransactionError(f"cannot securely open project transaction lock: {path}") from error


class _ProjectLock:
    def __init__(self, path: Path, parent_identity: _DirectoryIdentity) -> None:
        self._path = path
        self._parent_identity = parent_identity
        self._stream = _open_project_lock(path, parent_identity)
        self._stream.seek(0, os.SEEK_END)
        if self._stream.tell() == 0:
            self._stream.write(b"\0")
            self._stream.flush()
        self._locked = False

    def acquire(self, *, nonblocking: bool) -> None:
        _require_state_root_identity(self._path.parent, self._parent_identity)
        if os.name == "nt":
            import msvcrt

            native_msvcrt: Any = msvcrt
            self._stream.seek(0)
            mode = native_msvcrt.LK_NBLCK if nonblocking else native_msvcrt.LK_LOCK
            try:
                native_msvcrt.locking(self._stream.fileno(), mode, 1)
            except OSError as error:
                raise TransactionBusy("project transaction lock is busy") from error
        else:
            import fcntl

            operation = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
            try:
                fcntl.flock(self._stream.fileno(), operation)
            except BlockingIOError as error:
                raise TransactionBusy("project transaction lock is busy") from error
        self._locked = True
        _require_state_root_identity(self._path.parent, self._parent_identity)

    def close(self) -> None:
        if self._locked:
            if os.name == "nt":
                import msvcrt

                native_msvcrt: Any = msvcrt
                self._stream.seek(0)
                native_msvcrt.locking(self._stream.fileno(), native_msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._stream.fileno(), fcntl.LOCK_UN)
            self._locked = False
        self._stream.close()

    def __enter__(self) -> _ProjectLock:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class _Operation:
    kind: str
    relative_path: Path
    expected_sha256: str | None
    data: bytes | None
    result_sha256: str | None


@dataclass(frozen=True, slots=True)
class _JsonDirectoryAssertion:
    relative_path: Path
    expected_members: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TransactionResult:
    transaction_id: str
    changed_paths: tuple[Path, ...]
    cleanup_warning: str | None = None


class CASTransaction:
    """A finite, journaled multi-file compare-and-swap update.

    Supplying ``expected_sha256=None`` means the path must be absent.  Omitting
    it snapshots the current digest immediately and still rechecks that digest
    beneath the project lock during commit.  That lock coordinates ReproBit
    writers; commit-time no-clobber publication and moved-preimage checks
    preserve changes made by external writers that do not honor it.
    """

    JOURNAL_SCHEMA = "reprobit.cas-transaction.v2"

    def __init__(self, root: Path | str, *, nonblocking: bool = False) -> None:
        candidate = Path(root)
        if not candidate.is_absolute():
            raise ValueError("transaction root must be absolute")
        if is_redirected(candidate) or not candidate.is_dir():
            raise ValueError("transaction root must be an existing real directory")
        self.root = candidate.resolve(strict=True)
        self.state_root = self.root / ".reprobit-transactions"
        self.nonblocking = nonblocking
        self.transaction_id = uuid.uuid4().hex
        self._operations: list[_Operation] = []
        self._paths: set[Path] = set()
        self._json_directories: list[_JsonDirectoryAssertion] = []
        self._directory_paths: set[Path] = set()
        self._committed = False
        self._closed = False

    def _target(self, relative_path: Path) -> Path:
        return _safe_target(self.root, relative_path)

    def _snapshot(
        self,
        relative_path: Path,
        *,
        expected_directories: dict[str, _DirectoryIdentity] | None = None,
    ) -> str | None:
        target = self._target(relative_path)
        try:
            snapshot = _optional_snapshot(
                self.root,
                relative_path,
                expected_directories=(
                    None
                    if expected_directories is None
                    else _expectations_for(expected_directories, relative_path)
                ),
            )
        except SecurePathError as error:
            raise TransactionError(f"transaction target is not a regular file: {target}") from error
        return None if snapshot is None else snapshot.digest.value

    def _add(
        self,
        kind: str,
        relative_path: Path | str,
        data: bytes | None,
        expected_sha256: str | object | None,
    ) -> None:
        if self._committed or self._closed:
            raise TransactionError("transaction is already closed")
        relative = _relative_path(relative_path)
        if relative.parts[0] == ".reprobit-transactions":
            raise ValueError("transaction paths cannot name private transaction state")
        if relative in self._paths:
            raise TransactionError(f"transaction path is repeated: {relative}")
        expected = self._snapshot(relative) if expected_sha256 is _AUTOMATIC else expected_sha256
        expected = _validate_digest(expected)  # type: ignore[arg-type]
        result = None if data is None else sha256_bytes(data)
        if kind == "write" and result == expected:
            kind = "check"
            data = None
            result = None
        self._operations.append(_Operation(kind, relative, expected, data, result))
        self._paths.add(relative)

    def write(
        self,
        relative_path: Path | str,
        data: bytes,
        *,
        expected_sha256: str | object | None = _AUTOMATIC,
    ) -> None:
        if not isinstance(data, bytes):
            raise TypeError("transaction output must be bytes")
        self._add("write", relative_path, data, expected_sha256)

    def delete(
        self,
        relative_path: Path | str,
        *,
        expected_sha256: str | object | None = _AUTOMATIC,
    ) -> None:
        self._add("delete", relative_path, None, expected_sha256)

    def assert_unchanged(
        self,
        relative_path: Path | str,
        *,
        expected_sha256: str | object | None = _AUTOMATIC,
    ) -> None:
        """Add a compare-only precondition without rewriting the admitted file."""

        self._add("check", relative_path, None, expected_sha256)

    def assert_json_members(
        self,
        relative_path: Path | str,
        *,
        expected_members: tuple[str, ...],
    ) -> None:
        """Require an authority directory's recursive JSON membership to stay exact."""

        if self._committed or self._closed:
            raise TransactionError("transaction is already closed")
        relative = _relative_path(relative_path)
        if relative.parts[0] == ".reprobit-transactions":
            raise ValueError("transaction paths cannot name private transaction state")
        if relative in self._directory_paths:
            raise TransactionError(f"transaction directory is repeated: {relative}")
        checked: list[str] = []
        for value in expected_members:
            member = _relative_path(value)
            rendered = member.as_posix()
            if member.suffix.casefold() != ".json":
                raise ValueError("directory assertion members must be JSON paths")
            checked.append(rendered)
        canonical = tuple(sorted(checked, key=lambda item: (item.casefold(), item)))
        unique = len({item.casefold() for item in checked}) == len(checked)
        if tuple(checked) != canonical or not unique:
            raise ValueError("directory assertion members must be canonical and unique")
        self._json_directories.append(_JsonDirectoryAssertion(relative, canonical))
        self._directory_paths.add(relative)

    def _json_members(
        self,
        relative_path: Path,
        *,
        expected_directories: dict[str, _DirectoryIdentity] | None = None,
    ) -> tuple[str, ...]:
        directory = self._target(relative_path)
        relevant = {
            key: identity
            for key, identity in (expected_directories or {}).items()
            if key == "." or Path(key) == relative_path or Path(key) in relative_path.parents
        }
        _require_expected_directories(self.root, relevant)
        if not directory.exists():
            _require_expected_directories(self.root, relevant)
            return ()
        if not directory.is_dir() or is_redirected(directory):
            raise TransactionConflict(
                f"transaction authority directory changed: {relative_path.as_posix()}"
            )
        entries = tuple(directory.rglob("*"))
        if any(is_redirected(path) for path in entries):
            raise TransactionConflict(
                f"transaction authority directory is redirected: {relative_path.as_posix()}"
            )
        members = tuple(
            sorted(
                (
                    path.relative_to(directory).as_posix()
                    for path in entries
                    if path.suffix.casefold() == ".json" and path.is_file()
                ),
                key=lambda item: (item.casefold(), item),
            )
        )
        _require_expected_directories(self.root, relevant)
        return members

    def _journal_record(self, transaction_directory: Path, state: str) -> dict[str, Any]:
        return {
            "schema": self.JOURNAL_SCHEMA,
            "transaction_id": self.transaction_id,
            "state": state,
            "operations": [
                {
                    "index": index,
                    "kind": operation.kind,
                    "path": operation.relative_path.as_posix(),
                    "expected_sha256": operation.expected_sha256,
                    "result_sha256": operation.result_sha256,
                    "preimage": None,
                    "staged": None,
                    "backup": f"backups/{index}",
                    "staged_path": f"staged/{index}",
                }
                for index, operation in enumerate(self._operations)
            ],
            "directories": {},
            "transaction_directory": transaction_directory.name,
        }

    def _capture_preimages(
        self,
        expected_directories: dict[str, _DirectoryIdentity],
    ) -> dict[int, SecureFileSnapshot]:
        conflicts: list[str] = []
        captured: dict[int, SecureFileSnapshot] = {}
        for index, operation in enumerate(self._operations):
            target = self._target(operation.relative_path)
            try:
                snapshot = _optional_snapshot(
                    self.root,
                    operation.relative_path,
                    expected_directories=_expectations_for(
                        expected_directories,
                        operation.relative_path,
                    ),
                )
            except SecurePathError as error:
                raise TransactionConflict(
                    f"transaction target is redirected or not a regular file: {target}"
                ) from error
            actual = None if snapshot is None else snapshot.digest.value
            if actual != operation.expected_sha256:
                conflicts.append(
                    f"{operation.relative_path}: expected "
                    f"{operation.expected_sha256}, found {actual}"
                )
            elif snapshot is not None:
                captured[index] = snapshot
        if conflicts:
            raise TransactionConflict("transaction preimage conflict: " + "; ".join(conflicts))

        self._verify_json_members(
            postimages=False,
            expected_directories=expected_directories,
        )
        return captured

    def _verify_preimages(self) -> None:
        expected_directories = _capture_existing_directories(
            self.root,
            file_paths=tuple(operation.relative_path for operation in self._operations),
            directory_paths=tuple(assertion.relative_path for assertion in self._json_directories),
        )
        self._capture_preimages(expected_directories)

    def _verify_postimages(
        self,
        expected_directories: dict[str, _DirectoryIdentity],
    ) -> None:
        conflicts: list[str] = []
        for operation in self._operations:
            expected = (
                operation.expected_sha256 if operation.kind == "check" else operation.result_sha256
            )
            actual = self._snapshot(
                operation.relative_path,
                expected_directories=expected_directories,
            )
            if actual != expected:
                conflicts.append(f"{operation.relative_path}: expected {expected}, found {actual}")
        if conflicts:
            raise TransactionConflict("transaction postimage conflict: " + "; ".join(conflicts))

        self._verify_json_members(
            postimages=True,
            expected_directories=expected_directories,
        )

    def _verify_json_members(
        self,
        *,
        postimages: bool,
        expected_directories: dict[str, _DirectoryIdentity],
    ) -> None:
        membership_conflicts: list[str] = []
        for assertion in self._json_directories:
            expected = set(assertion.expected_members)
            if postimages:
                for operation in self._operations:
                    try:
                        member = operation.relative_path.relative_to(assertion.relative_path)
                    except ValueError:
                        continue
                    if member.suffix.casefold() != ".json":
                        continue
                    rendered = member.as_posix()
                    if operation.kind == "write":
                        expected.add(rendered)
                    elif operation.kind == "delete":
                        expected.discard(rendered)
            expected_members = tuple(sorted(expected, key=lambda item: (item.casefold(), item)))
            actual_members = self._json_members(
                assertion.relative_path,
                expected_directories=expected_directories,
            )
            if actual_members != expected_members:
                membership_conflicts.append(
                    f"{assertion.relative_path}: expected {expected_members}, "
                    f"found {actual_members}"
                )
        if membership_conflicts:
            raise TransactionConflict(
                "transaction authority membership conflict: " + "; ".join(membership_conflicts)
            )

    @classmethod
    def _rollback_record(
        cls,
        root: Path,
        directory: Path,
        identity: _DirectoryIdentity,
        state_root_identity: _DirectoryIdentity,
        record: dict[str, Any],
    ) -> None:
        _validate_journal_record(directory, record)
        # A prepared journal contains only private staged files.
        if record.get("state") == "prepared":
            return
        operations = record.get("operations")
        if not isinstance(operations, list):
            raise TransactionError(f"malformed transaction journal: {directory}")
        transaction_relative = directory.relative_to(root)
        seat_expectations = _seat_expectations(
            root,
            directory,
            identity,
            state_root_identity,
        )
        try:
            project_expectations = _recorded_directories(record)
        except ValueError as error:
            raise TransactionError(f"malformed transaction directories: {directory}") from error
        for entry in reversed(operations):
            try:
                if entry.get("kind") == "check":
                    continue
                relative = _relative_path(entry["path"])
                target = _safe_target(root, relative)
                backup_relative = transaction_relative / _relative_path(entry["backup"])
                backup = root.joinpath(*backup_relative.parts)
                expected = _validate_digest(entry["expected_sha256"])
                result = _validate_digest(entry["result_sha256"])
                preimage_record = entry.get("preimage")
                staged_record = entry.get("staged")
            except (KeyError, TypeError, ValueError) as error:
                raise TransactionError(f"malformed transaction operation: {directory}") from error
            target_expectations = _expectations_for(project_expectations, relative)
            private_expectations = {
                **_expectations_for(project_expectations, backup_relative),
                **seat_expectations,
            }
            promotion_expectations = {
                **_expectations_for(
                    project_expectations,
                    backup_relative,
                    relative,
                ),
                **seat_expectations,
            }
            try:
                current = _optional_snapshot(
                    root,
                    relative,
                    expected_directories=target_expectations,
                )
                backup_snapshot = _optional_snapshot(
                    root,
                    backup_relative,
                    expected_directories=private_expectations,
                )
            except SecurePathError as error:
                raise TransactionError(f"transaction recovery path changed: {target}") from error
            if backup_snapshot is not None:
                if not _snapshot_matches_record(backup_snapshot, preimage_record, expected):
                    raise TransactionError(f"transaction backup changed: {backup}")
                if current is not None:
                    if entry.get("kind") != "write" or not _snapshot_matches_record(
                        current,
                        staged_record,
                        result,
                    ):
                        raise TransactionError(f"recovery target has unknown contents: {target}")
                    if not remove_published_relative(
                        root,
                        relative.as_posix(),
                        expected=current,
                        expected_directories=target_expectations,
                    ):
                        raise TransactionError(f"recovery target changed: {target}")
                try:
                    promote_relative_new(
                        root,
                        backup_relative.as_posix(),
                        relative.as_posix(),
                        expected=backup_snapshot,
                        expected_directories=promotion_expectations,
                    )
                except SecurePathError as error:
                    raise TransactionError(f"recovery target changed: {target}") from error
                fsync_directory(target.parent)
                continue
            if expected is not None:
                if current is None or not _snapshot_matches_record(
                    current,
                    preimage_record,
                    expected,
                ):
                    raise TransactionError(f"recovery target has unknown contents: {target}")
                continue
            if current is None:
                continue
            if entry.get("kind") != "write" or not _snapshot_matches_record(
                current,
                staged_record,
                result,
            ):
                raise TransactionError(f"recovery target has unknown contents: {target}")
            if not remove_published_relative(
                root,
                relative.as_posix(),
                expected=current,
                expected_directories=target_expectations,
            ):
                raise TransactionError(f"recovery target changed: {target}")
            fsync_directory(target.parent)

    @classmethod
    def _recover_locked(
        cls,
        root: Path,
        state_root: Path,
        state_root_identity: _DirectoryIdentity,
    ) -> tuple[str, ...]:
        recovered: list[str] = []
        _require_state_root_identity(state_root, state_root_identity)
        try:
            entries = sorted(os.scandir(state_root), key=lambda entry: entry.name)
        except OSError as error:
            raise TransactionError(f"cannot inspect transaction state: {state_root}") from error
        _require_state_root_identity(state_root, state_root_identity)
        for entry in entries:
            try:
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError as error:
                raise TransactionError(
                    f"cannot inspect transaction state entry: {entry.path}"
                ) from error
            if not is_directory:
                continue
            directory = Path(entry.path)
            try:
                transaction_id = _canonical_transaction_id(entry.name)
            except ValueError as error:
                raise TransactionError(f"invalid transaction seat: {directory}") from error
            identity = _directory_identity(directory)
            loaded = _read_journal(
                root,
                directory,
                identity,
                state_root_identity,
            )
            if loaded is None:
                _remove_transaction_directory(
                    root,
                    directory,
                    identity,
                    state_root_identity,
                    journal=None,
                )
                recovered.append(transaction_id)
                continue
            record, journal_snapshot = loaded
            _validate_journal_record(directory, record)
            if record.get("state") != "committed":
                cls._rollback_record(
                    root,
                    directory,
                    identity,
                    state_root_identity,
                    record,
                )
            _remove_transaction_directory(
                root,
                directory,
                identity,
                state_root_identity,
                journal=journal_snapshot,
            )
            recovered.append(transaction_id)
        return tuple(recovered)

    @classmethod
    def recover(cls, root: Path | str, *, nonblocking: bool = False) -> tuple[str, ...]:
        candidate = Path(root)
        if not candidate.is_absolute() or is_redirected(candidate) or not candidate.is_dir():
            raise ValueError("recovery root must be an existing absolute real directory")
        project_root = candidate.resolve(strict=True)
        state_root = project_root / ".reprobit-transactions"
        state_root_identity = _prepare_state_root(project_root, state_root)
        with _ProjectLock(
            state_root / "project.lock",
            state_root_identity,
        ) as lock:
            lock.acquire(nonblocking=nonblocking)
            _require_state_root_identity(state_root, state_root_identity)
            return cls._recover_locked(
                project_root,
                state_root,
                state_root_identity,
            )

    def commit(self) -> TransactionResult:
        if self._committed or self._closed:
            raise TransactionError("transaction is already closed")
        if not self._operations and not self._json_directories:
            self._committed = True
            self._closed = True
            return TransactionResult(self.transaction_id, ())
        state_root_identity = _prepare_state_root(self.root, self.state_root)
        transaction_directory = self.state_root / self.transaction_id
        cleanup_warning: str | None = None
        with _ProjectLock(
            self.state_root / "project.lock",
            state_root_identity,
        ) as lock:
            lock.acquire(nonblocking=self.nonblocking)
            _require_state_root_identity(self.state_root, state_root_identity)
            self._recover_locked(
                self.root,
                self.state_root,
                state_root_identity,
            )
            if not any(operation.kind != "check" for operation in self._operations):
                self._verify_preimages()
                self._committed = True
                self._closed = True
                return TransactionResult(self.transaction_id, ())
            try:
                transaction_identity = create_directory_in_exact_parent(
                    transaction_directory,
                    state_root_identity,
                )
            except ExactTreeError as error:
                raise TransactionError(
                    f"cannot securely create transaction seat: {transaction_directory}"
                ) from error
            _require_state_root_identity(self.state_root, state_root_identity)
            fsync_directory(self.state_root)
            transaction_relative = transaction_directory.relative_to(self.root)
            seat_expectations = _seat_expectations(
                self.root,
                transaction_directory,
                transaction_identity,
                state_root_identity,
            )
            journal_relative = transaction_relative / "journal.json"
            record = self._journal_record(
                transaction_directory,
                "prepared",
            )
            journal_snapshot: SecureFileSnapshot | None = None
            try:
                # Make the private seat recoverable before creating its payloads.
                journal_snapshot = _write_journal(
                    self.root,
                    journal_relative,
                    record,
                    expected=None,
                    expected_directories=seat_expectations,
                )
                staged_snapshots: dict[int, SecureFileSnapshot] = {}
                for index, operation in enumerate(self._operations):
                    if operation.data is None or operation.result_sha256 is None:
                        continue
                    staged_relative = transaction_relative / "staged" / str(index)
                    staged_snapshots[index] = _publish_new_from_stream(
                        self.root,
                        staged_relative.as_posix(),
                        BytesIO(operation.data),
                        expected_digest=Digest(value=operation.result_sha256),
                        expected_size=len(operation.data),
                        expected_directories=seat_expectations,
                    )
                if any(
                    operation.kind != "check" and operation.expected_sha256 is not None
                    for operation in self._operations
                ):
                    backup_marker = transaction_relative / "backups" / ".ready"
                    _publish_new_from_stream(
                        self.root,
                        backup_marker.as_posix(),
                        BytesIO(b""),
                        expected_digest=Digest.from_bytes(b""),
                        expected_size=0,
                        expected_directories=seat_expectations,
                    )
                _sync_transaction_directory(
                    transaction_directory,
                    transaction_identity,
                )
                for index, snapshot in staged_snapshots.items():
                    record["operations"][index]["staged"] = _publication_record(snapshot)
                journal_snapshot = _write_journal(
                    self.root,
                    journal_relative,
                    record,
                    expected=journal_snapshot,
                    expected_directories=seat_expectations,
                )

                project_expectations = _capture_existing_directories(
                    self.root,
                    file_paths=tuple(operation.relative_path for operation in self._operations),
                    directory_paths=tuple(
                        assertion.relative_path for assertion in self._json_directories
                    ),
                )
                journal_paths = {"."}
                for operation in self._operations:
                    journal_paths.update(
                        parent.as_posix()
                        for parent in _directory_ancestors(operation.relative_path)
                    )
                record["directories"] = {
                    path: (
                        None
                        if path not in project_expectations
                        else _identity_record(project_expectations[path])
                    )
                    for path in sorted(journal_paths)
                }
                preimages = self._capture_preimages(project_expectations)
                for index, snapshot in preimages.items():
                    record["operations"][index]["preimage"] = _publication_record(snapshot)
                journal_snapshot = _write_journal(
                    self.root,
                    journal_relative,
                    record,
                    expected=journal_snapshot,
                    expected_directories=seat_expectations,
                )
                record["state"] = "applying"
                journal_snapshot = _write_journal(
                    self.root,
                    journal_relative,
                    record,
                    expected=journal_snapshot,
                    expected_directories=seat_expectations,
                )
                for index, operation in enumerate(self._operations):
                    if operation.kind == "check":
                        continue
                    target = self._target(operation.relative_path)
                    backup_relative = transaction_relative / "backups" / str(index)
                    target_expectations = _expectations_for(
                        project_expectations,
                        operation.relative_path,
                    )
                    operation_expectations = {
                        **_expectations_for(
                            project_expectations,
                            operation.relative_path,
                            backup_relative,
                        ),
                        **seat_expectations,
                    }
                    if operation.expected_sha256 is not None:
                        preimage = preimages.get(index)
                        if preimage is None:
                            raise TransactionError("transaction preimage identity is missing")
                        try:
                            _move_to_backup(
                                self.root,
                                operation.relative_path,
                                backup_relative,
                                expected=preimage,
                                expected_directories=operation_expectations,
                            )
                        except SecurePathError as error:
                            raise TransactionConflict(
                                "transaction target changed while applying: "
                                f"{operation.relative_path.as_posix()}"
                            ) from error
                        fsync_directory(target.parent)
                    if operation.data is not None:
                        if operation.result_sha256 is None:
                            raise TransactionError("transaction output digest is missing")
                        staged_snapshot = staged_snapshots.get(index)
                        if staged_snapshot is None:
                            raise TransactionError("transaction staged identity is missing")
                        staged_relative = transaction_relative / "staged" / str(index)
                        try:
                            published = _promote_staged(
                                self.root,
                                staged_relative,
                                operation.relative_path,
                                expected=staged_snapshot,
                                expected_directories=operation_expectations,
                            )
                        except SecurePathError as error:
                            if operation.expected_sha256 is None:
                                # The no-clobber promotion installed nothing,
                                # so this operation needs no rollback.
                                record["operations"][index]["kind"] = "check"
                                record["operations"][index]["result_sha256"] = None
                                record["operations"][index]["staged"] = None
                                journal_snapshot = _write_journal(
                                    self.root,
                                    journal_relative,
                                    record,
                                    expected=journal_snapshot,
                                    expected_directories=seat_expectations,
                                )
                            raise TransactionConflict(
                                "transaction target changed while applying: "
                                f"{operation.relative_path.as_posix()}"
                            ) from error
                        if published.digest.value != operation.result_sha256:
                            raise TransactionError(f"installed output digest differs: {target}")
                    elif operation.expected_sha256 is None:
                        actual = self._snapshot(
                            operation.relative_path,
                            expected_directories=target_expectations,
                        )
                        if actual is not None:
                            raise TransactionConflict(
                                "transaction target appeared while applying: "
                                f"{operation.relative_path.as_posix()}"
                            )
                    if operation.expected_sha256 is not None or operation.data is not None:
                        fsync_directory(target.parent)
                # Writers that do not honor our project lock may race any
                # authority or output path while publication is in progress.
                self._verify_postimages(project_expectations)
                record["state"] = "committed"
                journal_snapshot = _write_journal(
                    self.root,
                    journal_relative,
                    record,
                    expected=journal_snapshot,
                    expected_directories=seat_expectations,
                )
            except BaseException as error:
                try:
                    self._rollback_record(
                        self.root,
                        transaction_directory,
                        transaction_identity,
                        state_root_identity,
                        record,
                    )
                    _remove_transaction_directory(
                        self.root,
                        transaction_directory,
                        transaction_identity,
                        state_root_identity,
                        journal=journal_snapshot,
                    )
                except BaseException as rollback_error:
                    error.add_note(
                        "transaction rollback also failed; its recovery journal remains at "
                        f"{transaction_directory}: {rollback_error}"
                    )
                    raise error from rollback_error
                raise
            try:
                _remove_transaction_directory(
                    self.root,
                    transaction_directory,
                    transaction_identity,
                    state_root_identity,
                    journal=journal_snapshot,
                )
            except TransactionError as error:
                cleanup_warning = (
                    "private transaction cleanup was refused; recovery state remains at "
                    f"{transaction_directory}: {error}"
                )
        self._committed = True
        self._closed = True
        return TransactionResult(
            self.transaction_id,
            tuple(
                operation.relative_path
                for operation in self._operations
                if operation.kind != "check"
            ),
            cleanup_warning,
        )

    def abort(self) -> None:
        if self._committed:
            raise TransactionError("cannot abort a committed transaction")
        self._closed = True
        self._operations.clear()
        self._paths.clear()
        self._json_directories.clear()
        self._directory_paths.clear()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is None:
            if not self._committed and not self._closed:
                self.commit()
        elif not self._committed:
            self.abort()


__all__ = [
    "CASTransaction",
    "TransactionBusy",
    "TransactionConflict",
    "TransactionError",
    "TransactionResult",
    "sha256_bytes",
    "sha256_file",
]
