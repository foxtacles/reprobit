"""Journaled compare-and-swap transactions for project-file updates."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Self


class TransactionError(RuntimeError):
    """A transaction could not be safely staged, applied, or recovered."""


class TransactionConflict(TransactionError):
    """A target changed since its expected preimage was recorded."""


class TransactionBusy(TransactionError):
    """Another process owns the project transaction lock."""


_AUTOMATIC: Final = object()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_json_atomic(path: Path, value: object) -> None:
    data = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _prepare_state_root(root: Path, state_root: Path) -> None:
    if os.path.lexists(state_root):
        if state_root.is_symlink() or not state_root.is_dir():
            raise TransactionError(
                f"project transaction state is not a real directory: {state_root}"
            )
    else:
        state_root.mkdir()
    try:
        state_root.resolve(strict=True).relative_to(root)
    except ValueError as error:
        raise TransactionError("project transaction state escapes its root") from error


def _safe_target(root: Path, relative_path: Path) -> Path:
    target = root.joinpath(*relative_path.parts)
    current = root
    for component in relative_path.parts[:-1]:
        current = current / component
        if current.is_symlink():
            raise TransactionError(f"transaction parent is a symlink: {current}")
        if current.exists() and not current.is_dir():
            raise TransactionError(f"transaction parent is not a directory: {current}")
    if target.is_symlink():
        raise TransactionError(f"transaction target is a symlink: {target}")
    return target


class _ProjectLock:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("a+b", buffering=0)
        if self._stream.tell() == 0:
            self._stream.write(b"\0")
            self._stream.flush()
        self._locked = False

    def acquire(self, *, nonblocking: bool) -> None:
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

    @property
    def result_sha256(self) -> str | None:
        return None if self.data is None else sha256_bytes(self.data)


@dataclass(frozen=True, slots=True)
class _JsonDirectoryAssertion:
    relative_path: Path
    expected_members: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TransactionResult:
    transaction_id: str
    changed_paths: tuple[Path, ...]


class CASTransaction:
    """A finite, journaled multi-file compare-and-swap update.

    Supplying ``expected_sha256=None`` means the path must be absent.  Omitting
    it snapshots the current digest immediately and still rechecks that digest
    beneath the project lock during commit.
    """

    JOURNAL_SCHEMA = "reprobit.cas-transaction.v1"

    def __init__(self, root: Path | str, *, nonblocking: bool = False) -> None:
        candidate = Path(root)
        if not candidate.is_absolute():
            raise ValueError("transaction root must be absolute")
        if not candidate.is_dir() or candidate.is_symlink():
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

    def _snapshot(self, relative_path: Path) -> str | None:
        target = self._target(relative_path)
        if not target.exists():
            return None
        if not target.is_file():
            raise TransactionError(f"transaction target is not a regular file: {target}")
        return sha256_file(target)

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
        if relative in self._paths:
            raise TransactionError(f"transaction path is repeated: {relative}")
        expected = self._snapshot(relative) if expected_sha256 is _AUTOMATIC else expected_sha256
        expected = _validate_digest(expected)  # type: ignore[arg-type]
        self._operations.append(_Operation(kind, relative, expected, data))
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

    def _json_members(self, relative_path: Path) -> tuple[str, ...]:
        directory = self._target(relative_path)
        if not directory.exists():
            return ()
        if not directory.is_dir() or directory.is_symlink():
            raise TransactionConflict(
                f"transaction authority directory changed: {relative_path.as_posix()}"
            )
        entries = tuple(directory.rglob("*"))
        if any(path.is_symlink() for path in entries):
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
                    "payload": f"payloads/{index}" if operation.data is not None else None,
                    "backup": f"backups/{index}",
                }
                for index, operation in enumerate(self._operations)
            ],
            "transaction_directory": transaction_directory.name,
        }

    def _verify_preimages(self) -> None:
        conflicts: list[str] = []
        for operation in self._operations:
            actual = self._snapshot(operation.relative_path)
            if actual != operation.expected_sha256:
                conflicts.append(
                    f"{operation.relative_path}: expected "
                    f"{operation.expected_sha256}, found {actual}"
                )
        if conflicts:
            raise TransactionConflict("transaction preimage conflict: " + "; ".join(conflicts))
        membership_conflicts: list[str] = []
        for assertion in self._json_directories:
            actual_members = self._json_members(assertion.relative_path)
            if actual_members != assertion.expected_members:
                membership_conflicts.append(
                    f"{assertion.relative_path}: expected {assertion.expected_members}, "
                    f"found {actual_members}"
                )
        if membership_conflicts:
            raise TransactionConflict(
                "transaction authority membership conflict: " + "; ".join(membership_conflicts)
            )

    @classmethod
    def _rollback_record(cls, root: Path, directory: Path, record: dict[str, Any]) -> None:
        # A prepared journal has staged payloads but has not touched project
        # paths.  In particular, a failed preimage check may be reporting a
        # legitimate concurrent file; recovery must never mistake that file
        # for a partially installed transaction output.
        if record.get("state") == "prepared":
            return
        operations = record.get("operations")
        if not isinstance(operations, list):
            raise TransactionError(f"malformed transaction journal: {directory}")
        for entry in reversed(operations):
            try:
                if entry.get("kind") == "check":
                    continue
                relative = _relative_path(entry["path"])
                target = _safe_target(root, relative)
                backup = directory / entry["backup"]
                expected = _validate_digest(entry["expected_sha256"])
                result = _validate_digest(entry["result_sha256"])
            except (KeyError, TypeError, ValueError) as error:
                raise TransactionError(f"malformed transaction operation: {directory}") from error
            if backup.is_file():
                if backup.is_symlink():
                    raise TransactionError(f"transaction backup is a symlink: {backup}")
                if target.exists():
                    if not target.is_file():
                        raise TransactionError(f"recovery target is not a file: {target}")
                    if result is None or sha256_file(target) != result:
                        raise TransactionError(f"recovery target has unknown contents: {target}")
                    target.unlink()
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(backup, target)
                if sha256_file(target) != expected:
                    raise TransactionError(f"restored preimage digest differs: {target}")
                _fsync_directory(target.parent)
            elif expected is None and target.is_file():
                if result is not None and sha256_file(target) == result:
                    target.unlink()
                    _fsync_directory(target.parent)
                elif result is not None:
                    raise TransactionError(f"recovery target has unknown contents: {target}")

    @classmethod
    def _recover_locked(cls, root: Path, state_root: Path) -> tuple[str, ...]:
        recovered: list[str] = []
        if not state_root.is_dir():
            return ()
        for directory in sorted(state_root.iterdir()):
            if not directory.is_dir():
                continue
            journal = directory / "journal.json"
            if not journal.is_file():
                raise TransactionError(f"transaction directory lacks a journal: {directory}")
            try:
                record = json.loads(journal.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise TransactionError(f"cannot read transaction journal: {journal}") from error
            if record.get("schema") != cls.JOURNAL_SCHEMA:
                raise TransactionError(f"unsupported transaction journal: {journal}")
            if record.get("state") != "committed":
                cls._rollback_record(root, directory, record)
            recovered.append(str(record.get("transaction_id", directory.name)))
            shutil.rmtree(directory)
            _fsync_directory(state_root)
        return tuple(recovered)

    @classmethod
    def recover(cls, root: Path | str, *, nonblocking: bool = False) -> tuple[str, ...]:
        candidate = Path(root)
        if not candidate.is_absolute() or not candidate.is_dir() or candidate.is_symlink():
            raise ValueError("recovery root must be an existing absolute real directory")
        project_root = candidate.resolve(strict=True)
        state_root = project_root / ".reprobit-transactions"
        _prepare_state_root(project_root, state_root)
        with _ProjectLock(state_root / "project.lock") as lock:
            lock.acquire(nonblocking=nonblocking)
            return cls._recover_locked(project_root, state_root)

    def commit(self) -> TransactionResult:
        if self._committed or self._closed:
            raise TransactionError("transaction is already closed")
        if not self._operations and not self._json_directories:
            self._committed = True
            self._closed = True
            return TransactionResult(self.transaction_id, ())
        _prepare_state_root(self.root, self.state_root)
        transaction_directory = self.state_root / self.transaction_id
        with _ProjectLock(self.state_root / "project.lock") as lock:
            lock.acquire(nonblocking=self.nonblocking)
            self._recover_locked(self.root, self.state_root)
            if not self._operations:
                self._verify_preimages()
                self._committed = True
                self._closed = True
                return TransactionResult(self.transaction_id, ())
            transaction_directory.mkdir(exist_ok=False)
            payloads = transaction_directory / "payloads"
            backups = transaction_directory / "backups"
            payloads.mkdir()
            backups.mkdir()
            for index, operation in enumerate(self._operations):
                if operation.data is None:
                    continue
                payload = payloads / str(index)
                with payload.open("xb") as stream:
                    stream.write(operation.data)
                    stream.flush()
                    os.fsync(stream.fileno())
            record = self._journal_record(transaction_directory, "prepared")
            _write_json_atomic(transaction_directory / "journal.json", record)
            try:
                self._verify_preimages()
                record["state"] = "applying"
                _write_json_atomic(transaction_directory / "journal.json", record)
                for index, operation in enumerate(self._operations):
                    if operation.kind == "check":
                        continue
                    target = self._target(operation.relative_path)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    backup = backups / str(index)
                    if target.exists():
                        os.replace(target, backup)
                        _fsync_directory(target.parent)
                    if operation.data is not None:
                        payload = payloads / str(index)
                        os.replace(payload, target)
                        if sha256_file(target) != operation.result_sha256:
                            raise TransactionError(f"installed output digest differs: {target}")
                    _fsync_directory(target.parent)
                record["state"] = "committed"
                _write_json_atomic(transaction_directory / "journal.json", record)
            except BaseException:
                self._rollback_record(self.root, transaction_directory, record)
                shutil.rmtree(transaction_directory)
                _fsync_directory(self.state_root)
                raise
            shutil.rmtree(transaction_directory)
            _fsync_directory(self.state_root)
        self._committed = True
        self._closed = True
        return TransactionResult(
            self.transaction_id,
            tuple(
                operation.relative_path
                for operation in self._operations
                if operation.kind != "check"
            ),
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
