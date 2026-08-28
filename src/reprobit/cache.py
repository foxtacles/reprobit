"""Immutable, non-certifying local cache for incremental producer builds.

The cache is deliberately outside ReproBit's authenticity boundary.  Cold
verification does not construct this type.  Warm developer builds may use it
to avoid repeating producer work, but every record and blob is independently
validated before use and restored by copying into the fresh run workspace.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
import time
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Self

from reprobit.model import Digest
from reprobit.secure_paths import (
    SecureFileSnapshot,
    SecurePathError,
    atomic_copy_new_relative,
    atomic_publish_new_relative,
    atomic_publish_relative,
    canonical_system_path,
    digest_relative_file,
    promote_relative_new,
    read_relative_file,
    remove_regular_relative,
    stat_relative_file,
)
from reprobit.state import AdvisoryFileLock
from reprobit.strict_json import JsonValue, canonical_json, strict_loads


class CacheError(RuntimeError):
    """The incremental cache cannot safely complete an operation."""


class CachePoisonError(CacheError):
    """A named immutable cache object exists with invalid or conflicting bytes."""


class CacheBusyError(CacheError):
    """Cache maintenance cannot run while a build lease is active."""


@dataclass(frozen=True, slots=True)
class CacheOutput:
    """One named output stored by content digest."""

    name: str
    digest: str
    size: int
    executable: bool


@dataclass(frozen=True, slots=True)
class CacheRecord:
    """One immutable cache record in an implementation/domain namespace."""

    implementation: str
    domain: str
    key: str
    created_ns: int
    outputs: tuple[CacheOutput, ...]
    metadata: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class CacheStatus:
    """Inspectable cache usage without following redirected entries."""

    records: int
    blobs: int
    bytes: int
    files: int
    active_leases: int
    stale_leases: int


@dataclass(frozen=True, slots=True)
class CacheGCResult:
    """Result of one cache record/blob garbage-collection pass."""

    removed_records: int
    removed_blobs: int
    reclaimed_bytes: int
    active_leases: int
    skipped_recent_records: int
    dry_run: bool
    removed_indexes: int = 0


_FORMAT = 1
_FORMAT_DIRECTORY = "v1"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_IMPLEMENTATION = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_INDEX = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_LEASE = re.compile(r"^[0-9a-f]{32}\.lease$")
_LEASE_PUBLICATION_TEMP = re.compile(
    r"^\.(?:layout|[0-9a-f]{32}\.lease)\.reprobit-[0-9a-f]{32}$"
)
_RECORD_PUBLICATION_TEMP = re.compile(
    r"^\.[0-9a-f]{64}\.json\.reprobit-[0-9a-f]{32}$"
)
_MAX_RECORD_BYTES = 16 * 1024 * 1024
_MAX_INDEX_CANDIDATES = 16
_LAYOUT_MARKER = b"reprobit-cache-layout-v1\n"
_INDEX_LOCK_MARKER = b"\0"


def _require_hex(value: str, *, label: str) -> str:
    if not _HEX.fullmatch(value):
        raise CacheError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_domain(value: str) -> str:
    if not _DOMAIN.fullmatch(value):
        raise CacheError(f"invalid cache domain: {value!r}")
    return value


def _require_implementation(value: str) -> str:
    if not _IMPLEMENTATION.fullmatch(value):
        raise CacheError(f"invalid cache implementation id: {value!r}")
    return value


def _require_output_name(value: str) -> str:
    if not value or "\\" in value or "\x00" in value:
        raise CacheError(f"invalid cache output name: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(item in {"", ".", ".."} for item in path.parts)
    ):
        raise CacheError(f"invalid cache output name: {value!r}")
    return value


def cache_key(
    domain: str,
    material: Mapping[str, JsonValue],
    *,
    implementation: str,
) -> str:
    """Hash a typed, versioned cache-key preimage.

    Callers must put every semantic dependency in ``material``.  The format,
    implementation, and domain are injected here so records from different
    algorithms can never alias even when their caller material is identical.
    """

    _require_domain(domain)
    _require_implementation(implementation)
    payload = canonical_json(
        {
            "schema": _FORMAT,
            "implementation": implementation,
            "domain": domain,
            "material": material,
        }
    )
    return hashlib.sha256(payload).hexdigest()


def _require_directory(path: Path, *, create: bool, label: str) -> Path:
    if not path.is_absolute():
        raise CacheError(f"{label} must be absolute: {path}")
    if os.path.lexists(path):
        if path.is_symlink() or not path.is_dir():
            raise CacheError(f"{label} is not a real directory: {path}")
    elif create:
        path.mkdir(parents=True)
    return path.resolve(strict=create)


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _secure_location(path: Path) -> tuple[Path, str]:
    """Anchor one absolute path at its filesystem root for held traversal."""

    absolute = canonical_system_path(path)
    if not absolute.anchor or len(absolute.parts) < 2:
        raise CacheError(f"cache path has no secure relative location: {path}")
    return Path(absolute.anchor), PurePosixPath(*absolute.parts[1:]).as_posix()


def _secure_read(path: Path, *, maximum: int | None = None) -> bytes:
    root, relative = _secure_location(path)
    try:
        payload, _snapshot = read_relative_file(root, relative)
    except SecurePathError as exc:
        raise CachePoisonError(f"cache object is absent, redirected, or unstable: {path}") from exc
    if maximum is not None and len(payload) > maximum:
        raise CachePoisonError(f"cache object is oversized: {path}")
    return payload


def _read_settled_immutable(path: Path, *, maximum: int | None = None) -> bytes:
    """Read after a concurrent POSIX hard-link publication has settled."""

    for attempt in range(2):
        try:
            return _secure_read(path, maximum=maximum)
        except CachePoisonError:
            if attempt == 0:
                # A winning POSIX publisher removes its temporary hard link
                # after committing the shared name.  That one-time unlink can
                # advance ctime during a strict read by another process.
                continue
            raise
    raise AssertionError("immutable read retry loop did not return")


def _publish_immutable(path: Path, payload: bytes) -> None:
    """Converge concurrent publishers without ever replacing a named inode."""

    root, relative = _secure_location(path)
    try:
        atomic_publish_new_relative(root, relative, payload)
        return
    except SecurePathError as publication_error:
        try:
            current = _read_settled_immutable(path)
        except CachePoisonError:
            raise CachePoisonError(
                f"immutable cache publication failed: {path}"
            ) from publication_error
        if current != payload:
            raise CachePoisonError(
                f"immutable cache object conflicts with existing bytes: {path}"
            ) from publication_error


def _replace_mutable_index(path: Path, payload: bytes) -> None:
    """Publish a best-effort bounded hint; concurrent last-writer wins safely."""

    root, relative = _secure_location(path)
    try:
        atomic_publish_relative(root, relative, payload)
    except SecurePathError as exc:
        raise CachePoisonError(f"cache index publication failed: {path}") from exc


def _file_output_receipt(name: str, path: Path) -> CacheOutput:
    root, relative = _secure_location(path)
    try:
        snapshot = digest_relative_file(root, relative)
    except SecurePathError as exc:
        raise CacheError(f"cache source is absent, redirected, or unstable: {path}") from exc
    return CacheOutput(
        name,
        snapshot.digest.value,
        snapshot.size,
        bool(snapshot.mode & stat.S_IXUSR),
    )


def _atomic_bytes(path: Path, payload: bytes) -> None:
    _publish_immutable(path, payload)


def _replace_bytes(path: Path, payload: bytes) -> None:
    """Atomically replace a non-authoritative bounded lookup index."""

    _replace_mutable_index(path, payload)


def _secure_remove(path: Path) -> bool:
    root, relative = _secure_location(path)
    try:
        return remove_regular_relative(root, relative)
    except SecurePathError as exc:
        raise CachePoisonError(f"cache removal target is unsafe: {path}") from exc


class IncrementalCache:
    """An immutable CAS with explicit whole-build leases."""

    def __init__(
        self,
        state_root: Path,
        *,
        implementation: str,
        create: bool = True,
    ) -> None:
        self.state_root = _require_directory(state_root, create=create, label="state root")
        self.implementation = _require_implementation(implementation)
        cache_root = self.state_root / "cache"
        if not create and not os.path.lexists(cache_root):
            self.cache_root = cache_root
            self.format_root = self.cache_root / _FORMAT_DIRECTORY
            return
        self.cache_root = cache_root
        self.format_root = self.cache_root / _FORMAT_DIRECTORY
        if create:
            publications = {
                self.format_root / "format.json": canonical_json({"schema": _FORMAT}),
                self.format_root / "gate.lock": b"\0",
                self.format_root / "leases" / ".layout": _LAYOUT_MARKER,
                self.format_root / "blobs" / ".layout": _LAYOUT_MARKER,
                self.format_root / "records" / ".layout": _LAYOUT_MARKER,
                self.format_root / "indexes" / ".layout": _LAYOUT_MARKER,
            }
            for path, payload in publications.items():
                _publish_immutable(path, payload)
        self._ensure_layout()

    def _ensure_layout(self) -> None:
        if not os.path.lexists(self.format_root):
            raise CacheError("incremental cache does not exist")
        if not hasattr(self, "_gate_path"):
            self._gate_path = self.format_root / "gate.lock"
            self._leases_root = self.format_root / "leases"
            self._blobs_root = self.format_root / "blobs"
            self._records_root = self.format_root / "records"
            self._indexes_root = self.format_root / "indexes"
        marker = self.format_root / "format.json"
        if _read_settled_immutable(marker, maximum=1024) != canonical_json(
            {"schema": _FORMAT}
        ):
            raise CachePoisonError("cache format marker is invalid")
        if _read_settled_immutable(self._gate_path, maximum=1) != b"\0":
            raise CachePoisonError("cache gate marker is invalid")
        for root in (
            self._leases_root,
            self._blobs_root,
            self._records_root,
            self._indexes_root,
        ):
            if _read_settled_immutable(root / ".layout", maximum=64) != _LAYOUT_MARKER:
                raise CachePoisonError(f"cache layout marker is invalid: {root}")

    @contextmanager
    def lease(self) -> Iterator[CacheLease]:
        """Hold a GC-visible lease for one complete warm build."""

        self._ensure_layout()
        gate = AdvisoryFileLock(self._gate_path, create=False)
        gate.acquire(nonblocking=False)
        identifier = uuid.uuid4().hex
        lease_path = self._leases_root / f"{identifier}.lease"
        lease_lock: AdvisoryFileLock | None = None
        try:
            self._ensure_layout()
            _publish_immutable(lease_path, b"\0")
            lease_lock = AdvisoryFileLock(lease_path, create=False)
            if not lease_lock.acquire(nonblocking=True):
                raise CacheError("fresh cache lease could not be acquired")
            if _read_settled_immutable(lease_path, maximum=1) != b"\0":
                raise CachePoisonError("fresh cache lease marker is invalid")
        except BaseException:
            if lease_lock is not None:
                lease_lock.close()
            _secure_remove(lease_path)
            raise
        finally:
            gate.close()
        lease = CacheLease(self, identifier, lease_path, lease_lock)
        try:
            yield lease
        finally:
            lease.close()

    def _blob_path(self, digest: str, *, create: bool) -> Path:
        del create
        _require_hex(digest, label="blob digest")
        return self._blobs_root / "sha256" / digest[:2] / digest

    def _record_path(self, domain: str, key: str, *, create: bool) -> Path:
        return self._record_path_for(self.implementation, domain, key, create=create)

    def _record_path_for(
        self,
        implementation: str,
        domain: str,
        key: str,
        *,
        create: bool,
    ) -> Path:
        del create
        _require_implementation(implementation)
        _require_domain(domain)
        _require_hex(key, label="cache key")
        return self._records_root / implementation / domain / key[:2] / f"{key}.json"

    def _index_path(
        self,
        domain: str,
        index: str,
        value: str,
        *,
        create: bool,
    ) -> Path:
        del create
        _require_domain(domain)
        if not _INDEX.fullmatch(index):
            raise CacheError(f"invalid cache index: {index!r}")
        _require_hex(value, label="cache index value")
        return (
            self._indexes_root / self.implementation / domain / index / value[:2] / f"{value}.json"
        )

    def _active_lease_count(self, *, remove_stale: bool) -> tuple[int, int]:
        active = 0
        stale = 0
        for path in sorted(self._leases_root.iterdir(), key=lambda item: item.name):
            if path.name == ".layout":
                continue
            if _LEASE_PUBLICATION_TEMP.fullmatch(path.name):
                try:
                    temporary = path.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(temporary.st_mode):
                    raise CachePoisonError(
                        f"cache lease directory contains an unsafe entry: {path}"
                    )
                continue
            if (
                not _LEASE.fullmatch(path.name)
                or path.is_symlink()
                or not path.is_file()
            ):
                raise CachePoisonError(f"cache lease directory contains an unsafe entry: {path}")
            try:
                lock = AdvisoryFileLock(path, create=False)
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise CachePoisonError(f"cache lease is unsafe: {path}") from exc
            try:
                if lock.acquire(nonblocking=True):
                    stale += 1
                    lock.close()
                    if remove_stale:
                        _secure_remove(path)
                else:
                    active += 1
            finally:
                lock.close()
        return active, stale

    def status(self) -> CacheStatus:
        if not os.path.lexists(self.format_root):
            return CacheStatus(0, 0, 0, 0, 0, 0)
        self._ensure_layout()
        active, stale = self._active_lease_count(remove_stale=False)
        records = 0
        blobs = 0
        files = 0
        size = 0
        pending = [self.format_root]
        while pending:
            directory = pending.pop()
            if directory.is_symlink() or not directory.is_dir():
                raise CachePoisonError(f"cache tree contains a redirected directory: {directory}")
            for entry in os.scandir(directory):
                if entry.is_symlink():
                    raise CachePoisonError(f"cache tree contains a symlink: {entry.path}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise CachePoisonError(f"cache tree contains a special file: {entry.path}")
                stat_result = entry.stat(follow_symlinks=False)
                files += 1
                size += stat_result.st_size
                path = Path(entry.path)
                if (
                    path.suffix == ".json"
                    and path.name != "format.json"
                    and ("records" in path.parts)
                ):
                    records += 1
                if "blobs" in path.parts and _HEX.fullmatch(path.name):
                    blobs += 1
        return CacheStatus(records, blobs, size, files, active, stale)

    def gc(
        self,
        *,
        older_than_seconds: float = 0.0,
        dry_run: bool = False,
    ) -> CacheGCResult:
        """Remove old records then unreferenced blobs under the global GC gate."""

        if older_than_seconds < 0:
            raise CacheError("cache GC age cannot be negative")
        if not os.path.lexists(self.format_root):
            return CacheGCResult(0, 0, 0, 0, 0, dry_run)
        self._ensure_layout()
        cutoff = time.time_ns() - int(older_than_seconds * 1_000_000_000)
        gate = AdvisoryFileLock(self._gate_path, create=False)
        gate.acquire(nonblocking=False)
        try:
            self._ensure_layout()
            active, _ = self._active_lease_count(remove_stale=not dry_run)
            if active:
                return CacheGCResult(0, 0, 0, active, 0, dry_run)
            record_paths: list[Path] = []
            for path in self._records_root.rglob("*.json"):
                if path.is_symlink() or not path.is_file():
                    raise CachePoisonError(f"cache record is redirected: {path}")
                record_paths.append(path)
            removed_records = 0
            skipped_recent = 0
            reclaimed = 0
            retained_records: list[CacheRecord] = []
            for path in sorted(record_paths):
                record = self._parse_record(path, require_current=False)
                if path.stat(follow_symlinks=False).st_mtime_ns > cutoff:
                    skipped_recent += 1
                    retained_records.append(record)
                    continue
                removed_records += 1
                reclaimed += path.stat(follow_symlinks=False).st_size
                if not dry_run and not _secure_remove(path):
                    raise CachePoisonError(f"cache record disappeared during GC: {path}")
            referenced = {output.digest for record in retained_records for output in record.outputs}
            blob_paths: list[Path] = []
            algorithm_root = self._blobs_root / "sha256"
            if os.path.lexists(algorithm_root):
                if algorithm_root.is_symlink() or not algorithm_root.is_dir():
                    raise CachePoisonError("cache blob algorithm root is redirected")
                for path in algorithm_root.rglob("*"):
                    if path.is_file() and not path.is_symlink():
                        if not _HEX.fullmatch(path.name):
                            raise CachePoisonError(f"cache blob name is invalid: {path}")
                        blob_paths.append(path)
                    elif path.is_symlink() or (not path.is_dir()):
                        raise CachePoisonError(f"cache blob tree has an unsafe entry: {path}")
            removed_blobs = 0
            for path in sorted(blob_paths):
                if path.name in referenced:
                    continue
                removed_blobs += 1
                reclaimed += path.stat(follow_symlinks=False).st_size
                if not dry_run and not _secure_remove(path):
                    raise CachePoisonError(f"cache blob disappeared during GC: {path}")
            removed_indexes = 0
            removed_index_locks: set[Path] = set()
            for path in sorted(self._indexes_root.rglob("*.json")):
                if path.is_symlink() or not path.is_file():
                    raise CachePoisonError(f"cache index is redirected: {path}")
                if path.stat(follow_symlinks=False).st_mtime_ns > cutoff:
                    continue
                removed_indexes += 1
                reclaimed += path.stat(follow_symlinks=False).st_size
                if not dry_run and not _secure_remove(path):
                    raise CachePoisonError(f"cache index disappeared during GC: {path}")
                lock_path = path.with_suffix(".lock")
                if os.path.lexists(lock_path):
                    if lock_path.is_symlink() or not lock_path.is_file():
                        raise CachePoisonError(f"cache index lock is redirected: {lock_path}")
                    reclaimed += lock_path.stat(follow_symlinks=False).st_size
                    removed_index_locks.add(lock_path)
                    if not dry_run and not _secure_remove(lock_path):
                        raise CachePoisonError(
                            f"cache index lock disappeared during GC: {lock_path}"
                        )
            for lock_path in sorted(self._indexes_root.rglob("*.lock")):
                if lock_path in removed_index_locks:
                    continue
                if lock_path.is_symlink() or not lock_path.is_file():
                    raise CachePoisonError(f"cache index lock is redirected: {lock_path}")
                if lock_path.with_suffix(".json").exists() or (
                    lock_path.stat(follow_symlinks=False).st_mtime_ns > cutoff
                ):
                    continue
                reclaimed += lock_path.stat(follow_symlinks=False).st_size
                if not dry_run and not _secure_remove(lock_path):
                    raise CachePoisonError(f"cache index lock disappeared during GC: {lock_path}")
            if not dry_run:
                _fsync_directory(self.format_root)
            return CacheGCResult(
                removed_records,
                removed_blobs,
                reclaimed,
                0,
                skipped_recent,
                dry_run,
                removed_indexes,
            )
        finally:
            gate.close()

    def _parse_record(self, path: Path, *, require_current: bool = True) -> CacheRecord:
        try:
            value = strict_loads(
                _read_settled_immutable(path, maximum=_MAX_RECORD_BYTES)
            )
        except (TypeError, ValueError) as exc:
            raise CachePoisonError(f"cache record is malformed: {path}") from exc
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "implementation",
            "domain",
            "key",
            "created_ns",
            "outputs",
            "metadata",
        }:
            raise CachePoisonError(f"cache record has an invalid field set: {path}")
        implementation = value["implementation"]
        domain = value["domain"]
        key = value["key"]
        created_ns = value["created_ns"]
        raw_outputs = value["outputs"]
        metadata = value["metadata"]
        if (
            value["schema"] != _FORMAT
            or not isinstance(implementation, str)
            or not _IMPLEMENTATION.fullmatch(implementation)
            or (require_current and implementation != self.implementation)
            or not isinstance(domain, str)
            or not _DOMAIN.fullmatch(domain)
            or not isinstance(key, str)
            or not _HEX.fullmatch(key)
            or not isinstance(created_ns, int)
            or isinstance(created_ns, bool)
            or created_ns < 0
            or not isinstance(raw_outputs, list)
            or not isinstance(metadata, dict)
        ):
            raise CachePoisonError(f"cache record identity is invalid: {path}")
        expected = self._record_path_for(implementation, domain, key, create=False)
        if Path(os.path.abspath(path)) != Path(os.path.abspath(expected)):
            raise CachePoisonError(f"cache record is stored at the wrong path: {path}")
        outputs: list[CacheOutput] = []
        for raw in raw_outputs:
            if not isinstance(raw, dict) or set(raw) != {
                "name",
                "digest",
                "size",
                "executable",
            }:
                raise CachePoisonError(f"cache output receipt is malformed: {path}")
            name = raw["name"]
            digest = raw["digest"]
            size = raw["size"]
            executable = raw["executable"]
            if (
                not isinstance(name, str)
                or not isinstance(digest, str)
                or not _HEX.fullmatch(digest)
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size < 0
                or not isinstance(executable, bool)
            ):
                raise CachePoisonError(f"cache output receipt is invalid: {path}")
            try:
                _require_output_name(name)
            except CacheError as exc:
                raise CachePoisonError(str(exc)) from exc
            outputs.append(CacheOutput(name, digest, size, executable))
        if tuple(sorted(outputs, key=lambda item: item.name)) != tuple(outputs) or len(
            {item.name for item in outputs}
        ) != len(outputs):
            raise CachePoisonError(f"cache outputs are not canonical: {path}")
        return CacheRecord(
            implementation,
            domain,
            key,
            created_ns,
            tuple(outputs),
            MappingProxyType(metadata),
        )


class CacheLease:
    """The only interface that can read, publish, or restore cache objects."""

    def __init__(
        self,
        cache: IncrementalCache,
        identifier: str,
        path: Path,
        lock: AdvisoryFileLock,
    ) -> None:
        self.cache = cache
        self.identifier = identifier
        self.path = path
        self._lock: AdvisoryFileLock | None = lock

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _require_open(self) -> None:
        if self._lock is None:
            raise CacheError("cache lease is closed")

    def close(self) -> None:
        lock = self._lock
        if lock is None:
            return
        lock.close()
        self._lock = None
        # GC may have observed the just-released lock and removed the stale
        # marker first.  Either remover is safe because deletion is held and
        # no-follow; absence here is therefore a benign convergence case.
        _secure_remove(self.path)

    def lookup(self, domain: str, key: str) -> CacheRecord | None:
        self._require_open()
        path = self.cache._record_path(domain, key, create=False)
        if not os.path.lexists(path):
            return None
        record = self.cache._parse_record(path)
        for output in record.outputs:
            self._probe_blob(output)
        return record

    def records(self, domain: str) -> tuple[CacheRecord, ...]:
        """Return one validated implementation/domain record snapshot.

        This supports append-only dependency hints: callers scan candidates
        once per warm build and select a record only after re-resolving its
        current recursive-read authority.
        """

        self._require_open()
        _require_domain(domain)
        root = self.cache._records_root / self.cache.implementation / domain
        if not os.path.lexists(root):
            return ()
        if root.is_symlink() or not root.is_dir():
            raise CachePoisonError(f"cache record domain is redirected: {root}")
        paths: list[Path] = []
        for prefix in sorted(root.iterdir(), key=lambda item: item.name):
            if (
                prefix.is_symlink()
                or not prefix.is_dir()
                or not re.fullmatch(r"[0-9a-f]{2}", prefix.name)
            ):
                raise CachePoisonError(f"cache record domain contains an unsafe prefix: {prefix}")
            for path in sorted(prefix.iterdir(), key=lambda item: item.name):
                if _RECORD_PUBLICATION_TEMP.fullmatch(path.name):
                    try:
                        temporary = path.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if not stat.S_ISREG(temporary.st_mode):
                        raise CachePoisonError(
                            f"cache record prefix contains an unsafe entry: {path}"
                        )
                    continue
                if (
                    not re.fullmatch(r"[0-9a-f]{64}\.json", path.name)
                    or path.is_symlink()
                    or not path.is_file()
                ):
                    raise CachePoisonError(f"cache record prefix contains an unsafe entry: {path}")
                paths.append(path)
        records = tuple(self.cache._parse_record(path) for path in paths)
        for record in records:
            for output in record.outputs:
                self._probe_blob(output)
        return records

    def index_record(
        self,
        domain: str,
        index: str,
        value: str,
        record: CacheRecord,
    ) -> None:
        """Add a record to a bounded, non-authoritative lookup hint.

        Records and blobs remain immutable.  This small replaceable index only
        remembers the most recent candidate keys; losing or corrupting it can
        cause a rebuild but can never admit an artifact.
        """

        self._require_open()
        if record.implementation != self.cache.implementation or record.domain != domain:
            raise CacheError("cache index record differs from its namespace")
        if self.lookup(domain, record.key) != record:
            raise CacheError("cache index cannot name an absent record")
        path = self.cache._index_path(domain, index, value, create=True)
        lock_path = path.with_suffix(".lock")
        _publish_immutable(lock_path, _INDEX_LOCK_MARKER)
        try:
            lock = AdvisoryFileLock(lock_path, create=False)
        except OSError as exc:
            raise CachePoisonError(f"cache index lock is unsafe: {lock_path}") from exc
        try:
            lock.acquire(nonblocking=False)
            if _read_settled_immutable(lock_path, maximum=1) != _INDEX_LOCK_MARKER:
                raise CachePoisonError(f"cache index lock is invalid: {lock_path}")
            existing = self._read_index(path, domain, index, value)
            keys = [record.key]
            keys.extend(key for key in existing if key != record.key)
            keys = keys[:_MAX_INDEX_CANDIDATES]
            _replace_bytes(
                path,
                canonical_json(
                    {
                        "schema": _FORMAT,
                        "implementation": self.cache.implementation,
                        "domain": domain,
                        "index": index,
                        "value": value,
                        "records": keys,
                    }
                ),
            )
        finally:
            lock.close()

    def indexed_records(
        self,
        domain: str,
        index: str,
        value: str,
    ) -> tuple[CacheRecord, ...]:
        """Resolve at most sixteen recent candidates from one exact index key."""

        keys = self.indexed_record_keys(domain, index, value)
        records: list[CacheRecord] = []
        for key in keys:
            record = self.lookup(domain, key)
            if record is not None:
                records.append(record)
        return tuple(records)

    def indexed_record_keys(
        self,
        domain: str,
        index: str,
        value: str,
    ) -> tuple[str, ...]:
        """Return bounded candidate keys without eagerly loading records.

        The mutable index is only a non-authoritative hint.  Callers that can
        stop at the first exact candidate resolve these keys lazily, avoiding
        record parsing and blob probes for the rest of a mature history.
        """

        self._require_open()
        path = self.cache._index_path(domain, index, value, create=False)
        return self._read_index(path, domain, index, value)

    def _read_index(
        self,
        path: Path,
        domain: str,
        index: str,
        value: str,
    ) -> tuple[str, ...]:
        if not os.path.lexists(path):
            return ()
        try:
            raw = strict_loads(_secure_read(path, maximum=_MAX_RECORD_BYTES))
        except (CachePoisonError, TypeError, ValueError):
            return ()
        if not isinstance(raw, dict) or set(raw) != {
            "schema",
            "implementation",
            "domain",
            "index",
            "value",
            "records",
        }:
            return ()
        keys = raw["records"]
        if (
            raw["schema"] != _FORMAT
            or raw["implementation"] != self.cache.implementation
            or raw["domain"] != domain
            or raw["index"] != index
            or raw["value"] != value
            or not isinstance(keys, list)
            or len(keys) > _MAX_INDEX_CANDIDATES
            or any(not isinstance(key, str) or not _HEX.fullmatch(key) for key in keys)
            or len(set(keys)) != len(keys)
        ):
            return ()
        return tuple(key for key in keys if isinstance(key, str))

    def _probe_blob_once(self, output: CacheOutput) -> Path:
        """Perform the cheap pre-restore blob shape check.

        Full content validation is fused with the eventual restore copy so a
        cache hit reads each selected blob only once.
        """

        path = self.cache._blob_path(output.digest, create=False)
        root, relative = _secure_location(path)
        try:
            metadata = stat_relative_file(root, relative)
        except SecurePathError as exc:
            raise CachePoisonError(
                f"cache blob is absent, redirected, or non-regular: {path}"
            ) from exc
        if metadata.size != output.size:
            raise CachePoisonError(f"cache blob failed integrity validation (wrong size): {path}")
        return path

    def _probe_blob(self, output: CacheOutput) -> Path:
        for attempt in range(2):
            try:
                return self._probe_blob_once(output)
            except CachePoisonError:
                if attempt == 0:
                    # A concurrent POSIX publisher may unlink its staging
                    # name during any immutable blob shape observation.
                    continue
                raise
        raise AssertionError("immutable blob probe retry loop did not return")

    def _validate_existing_blob(self, output: CacheOutput) -> Path:
        for attempt in range(2):
            try:
                path = self._probe_blob_once(output)
                root, relative = _secure_location(path)
                snapshot = digest_relative_file(root, relative)
                break
            except CachePoisonError:
                if attempt == 0:
                    # The winning publisher's staging unlink can advance ctime
                    # during either the cheap shape probe or the full digest.
                    continue
                raise
            except SecurePathError as exc:
                if attempt == 0:
                    continue
                raise CachePoisonError(f"cache blob is redirected or unstable: {path}") from exc
        if snapshot.digest.value != output.digest or snapshot.size != output.size:
            raise CachePoisonError(f"cache blob failed integrity validation: {path}")
        return path

    def stage_record(
        self,
        domain: str,
        key: str,
        outputs: Mapping[str, Path],
        *,
        metadata: Mapping[str, JsonValue] | None = None,
    ) -> CacheRecord:
        """Publish immutable blobs and build an unpublished record value."""

        self._require_open()
        _require_domain(domain)
        _require_hex(key, label="cache key")
        if not outputs:
            raise CacheError("cache record must contain at least one output")
        names = tuple(sorted(outputs))
        if len(names) != len(set(names)):
            raise CacheError("cache output names overlap")
        for name in names:
            _require_output_name(name)
        normalized_metadata = dict(metadata or {})
        canonical_json(normalized_metadata)
        path = self.cache._record_path(domain, key, create=True)
        existing = self.lookup(domain, key) if os.path.lexists(path) else None
        if existing is not None:
            requested = tuple(_file_output_receipt(name, outputs[name]) for name in names)
            if requested != existing.outputs or dict(existing.metadata) != (normalized_metadata):
                raise CachePoisonError(
                    "cache key already names different immutable output or metadata: "
                    f"{domain}/{key}"
                )
            return existing

        receipts: list[CacheOutput] = []
        for name in names:
            source = outputs[name]
            source_root, source_relative = _secure_location(source)
            try:
                source_identity = stat_relative_file(source_root, source_relative)
            except SecurePathError as exc:
                raise CacheError(
                    f"cache source is absent, redirected, or unstable: {source}"
                ) from exc
            staging = self.cache.format_root / "incoming" / uuid.uuid4().hex
            staging_root, staging_relative = _secure_location(staging)
            try:
                staged = atomic_copy_new_relative(
                    source_root,
                    source_relative,
                    staging_root,
                    staging_relative,
                    executable=False,
                    expected_size=source_identity.size,
                    expected_source=source_identity,
                )
            except SecurePathError as exc:
                raise CacheError(
                    f"cache source changed or staging publication failed: {source}"
                ) from exc
            receipt = CacheOutput(
                name,
                staged.digest.value,
                staged.size,
                bool(source_identity.mode & stat.S_IXUSR),
            )
            blob = self.cache._blob_path(receipt.digest, create=True)
            blob_root, blob_relative = _secure_location(blob)
            if staging_root != blob_root:
                raise CacheError("cache staging and CAS roots differ")
            try:
                promote_relative_new(
                    blob_root,
                    staging_relative,
                    blob_relative,
                    expected=staged,
                )
            except SecurePathError as publication_error:
                try:
                    self._validate_existing_blob(receipt)
                except CachePoisonError:
                    if not os.path.lexists(blob):
                        raise CacheError(
                            f"cache source changed or blob publication failed: {source}"
                        ) from publication_error
                    raise
            finally:
                with suppress(CacheError):
                    _secure_remove(staging)
            receipts.append(receipt)

        return CacheRecord(
            self.cache.implementation,
            domain,
            key,
            time.time_ns(),
            tuple(receipts),
            MappingProxyType(normalized_metadata),
        )

    def publish_record(self, record: CacheRecord) -> CacheRecord:
        """Atomically publish one previously staged record after run validation."""

        self._require_open()
        _require_domain(record.domain)
        _require_hex(record.key, label="cache key")
        if record.implementation != self.cache.implementation:
            raise CacheError("staged cache record differs from its implementation namespace")
        if not record.outputs:
            raise CacheError("staged cache record has no outputs")
        names = tuple(item.name for item in record.outputs)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise CacheError("staged cache record outputs are not canonical")
        for output in record.outputs:
            _require_output_name(output.name)
            _require_hex(output.digest, label="cache blob digest")
            if output.size < 0:
                raise CacheError("staged cache output size is negative")
            # ``stage_record`` already copied and hashed this immutable blob in
            # one held-descriptor pass (or validated an existing convergent
            # blob).  Publication only needs to prove that the named regular
            # blob with the same size still exists.  The selected restore
            # fuses the next full digest validation with its copy, avoiding a
            # second complete read of every large output here.
            self._probe_blob(output)
        normalized_metadata = dict(record.metadata)
        canonical_json(normalized_metadata)
        path = self.cache._record_path(record.domain, record.key, create=True)
        existing = self.lookup(record.domain, record.key) if os.path.lexists(path) else None
        if existing is not None:
            if existing.outputs != record.outputs or dict(existing.metadata) != normalized_metadata:
                raise CachePoisonError(
                    "cache key already names different immutable output or metadata: "
                    f"{record.domain}/{record.key}"
                )
            return existing
        record_value = {
            "schema": _FORMAT,
            "implementation": self.cache.implementation,
            "domain": record.domain,
            "key": record.key,
            "created_ns": record.created_ns,
            "outputs": [
                {
                    "name": item.name,
                    "digest": item.digest,
                    "size": item.size,
                    "executable": item.executable,
                }
                for item in record.outputs
            ],
            "metadata": normalized_metadata,
        }
        payload = canonical_json(record_value)
        record_root, record_relative = _secure_location(path)
        try:
            atomic_publish_new_relative(record_root, record_relative, payload)
        except SecurePathError as publication_error:
            existing = self.lookup(record.domain, record.key)
            if existing is None:
                raise CachePoisonError(
                    "immutable cache record publication failed: "
                    f"{record.domain}/{record.key}"
                ) from publication_error
            if record.outputs != existing.outputs or dict(existing.metadata) != normalized_metadata:
                raise CachePoisonError(
                    "cache key concurrently named different immutable output or metadata: "
                    f"{record.domain}/{record.key}"
                ) from publication_error
            return existing
        return self.cache._parse_record(path)

    def store(
        self,
        domain: str,
        key: str,
        outputs: Mapping[str, Path],
        *,
        metadata: Mapping[str, JsonValue] | None = None,
    ) -> CacheRecord:
        """Stage blobs and immediately publish a record for simple callers."""

        return self.publish_record(
            self.stage_record(domain, key, outputs, metadata=metadata)
        )

    def restore(
        self,
        record: CacheRecord,
        destinations: Mapping[str, Path],
        *,
        allowed_root: Path,
    ) -> None:
        """Restore validated blobs by copy into a fresh, bounded workspace."""

        self._require_open()
        if record.implementation != self.cache.implementation or set(destinations) != {
            item.name for item in record.outputs
        }:
            raise CacheError("cache restore request differs from its record")
        self.restore_selected(record, destinations, allowed_root=allowed_root)

    def restore_selected(
        self,
        record: CacheRecord,
        destinations: Mapping[str, Path],
        *,
        allowed_root: Path,
    ) -> Mapping[str, SecureFileSnapshot]:
        """Restore an exact named subset of one immutable record by copy."""

        self._require_open()
        outputs = {item.name: item for item in record.outputs}
        if (
            record.implementation != self.cache.implementation
            or not destinations
            or not set(destinations).issubset(outputs)
        ):
            raise CacheError("cache selected restore request differs from its record")
        root = _require_directory(allowed_root, create=False, label="restore root")
        restored: dict[str, SecureFileSnapshot] = {}
        for name, destination in sorted(destinations.items()):
            output = outputs[name]
            if not destination.is_absolute():
                raise CacheError(f"cache restore destination is not absolute: {destination}")
            canonical_destination = canonical_system_path(destination)
            try:
                relative = canonical_destination.relative_to(root)
            except ValueError as exc:
                raise CacheError(
                    f"cache restore destination escapes its root: {destination}"
                ) from exc
            if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
                raise CacheError(f"cache restore destination is not canonical: {destination}")
            if os.path.lexists(canonical_destination):
                raise CacheError(f"cache restore destination already exists: {destination}")
            blob = self._probe_blob(output)
            blob_root, blob_relative = _secure_location(blob)
            destination_root, destination_relative = _secure_location(canonical_destination)
            try:
                restored[name] = atomic_copy_new_relative(
                    blob_root,
                    blob_relative,
                    destination_root,
                    destination_relative,
                    executable=output.executable,
                    expected_digest=Digest(value=output.digest),
                    expected_size=output.size,
                )
            except SecurePathError as exc:
                message = str(exc)
                if "redirected" in message or "changed while held" in message:
                    raise CachePoisonError(
                        f"cache restore source or destination is redirected: {destination}"
                    ) from exc
                if (
                    "digest differs" in message
                    or "size differs" in message
                    or "copy source" in message
                ):
                    raise CachePoisonError(
                        f"cache blob failed integrity validation during restore: {blob}"
                    ) from exc
                raise CacheError(
                    f"cache restore could not safely publish {destination}: {exc}"
                ) from exc
        return MappingProxyType(restored)


__all__ = [
    "CacheBusyError",
    "CacheError",
    "CacheGCResult",
    "CacheLease",
    "CacheOutput",
    "CachePoisonError",
    "CacheRecord",
    "CacheStatus",
    "IncrementalCache",
    "cache_key",
]
