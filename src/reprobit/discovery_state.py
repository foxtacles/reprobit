"""Ownership and guarded cleanup for advanced discovery campaign state."""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import cast

from reprobit.model import Digest
from reprobit.state_lock import AdvisoryFileLock, StateError
from reprobit.strict_json import canonical_json, strict_loads
from reprobit.transactions import CASTransaction

MARKER_NAME = ".reprobit-discovery-state.json"
_LOCK_DIRECTORY = ".reprobit-discovery-locks"
_MARKER_KIND = "reprobit-discovery-state"


class DiscoveryStateError(RuntimeError):
    """Discovery state is unowned, redirected, busy, or malformed."""


@dataclass(frozen=True, slots=True)
class DiscoveryStateUsage:
    path: Path
    files: int
    bytes: int
    state_directory: str
    requests: tuple[str, ...]
    marker_digest: Digest
    identity: tuple[int, int] | None


def _portable(value: Path) -> str:
    rendered = PurePosixPath(*value.parts).as_posix()
    if (
        value.is_absolute()
        or not rendered
        or rendered == "."
        or any(part in {"", ".", ".."} for part in value.parts)
    ):
        raise DiscoveryStateError("discovery state must be a non-empty relative directory")
    return rendered


def state_lock(root: Path, state: Path) -> AdvisoryFileLock:
    """Return an external lock that remains held while the state tree is removed."""

    relative = _portable(state)
    lock_root = root / _LOCK_DIRECTORY
    try:
        lock_root.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise DiscoveryStateError(f"cannot create the discovery lock root: {exc}") from exc
    if lock_root.is_symlink() or not lock_root.is_dir():
        raise DiscoveryStateError(f"discovery lock root is not a real directory: {lock_root}")
    identity = sha256(relative.encode("utf-8")).hexdigest()
    try:
        return AdvisoryFileLock(lock_root / f"{identity}.lock")
    except (OSError, StateError) as exc:
        raise DiscoveryStateError(f"cannot open the discovery state lock: {exc}") from exc


def _marker_document(payload: bytes, *, state: str) -> tuple[str, ...]:
    try:
        value = strict_loads(payload)
    except ValueError as exc:
        raise DiscoveryStateError(f"discovery state marker is invalid: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {
        "kind",
        "requests",
        "schema_version",
        "state_directory",
    }:
        raise DiscoveryStateError("discovery state marker has an unknown shape")
    if (
        value["schema_version"] != 1
        or value["kind"] != _MARKER_KIND
        or value["state_directory"] != state
    ):
        raise DiscoveryStateError("discovery state marker does not own this directory")
    raw_requests = value["requests"]
    if (
        not isinstance(raw_requests, list)
        or not raw_requests
        or any(not isinstance(item, str) or not item or "\0" in item for item in raw_requests)
    ):
        raise DiscoveryStateError("discovery state marker has invalid request ownership")
    requests = cast(list[str], raw_requests)
    if requests != sorted(set(requests), key=lambda item: (item.casefold(), item)):
        raise DiscoveryStateError("discovery state marker has invalid request ownership")
    return tuple(requests)


def register_state(root: Path, state: Path, request_name: str) -> None:
    """Bind a real campaign state directory to a request under an external lock."""

    state_value = _portable(state)
    state_root = root / state
    if state_root.is_symlink() or not state_root.is_dir():
        raise DiscoveryStateError(f"discovery state is not a real directory: {state_root}")
    marker = state_root / MARKER_NAME
    prior: Digest | None = None
    requests: tuple[str, ...] = ()
    if os.path.lexists(marker):
        if marker.is_symlink() or not marker.is_file():
            raise DiscoveryStateError(f"discovery state marker is not a real file: {marker}")
        payload = marker.read_bytes()
        requests = _marker_document(payload, state=state_value)
        prior = Digest.from_bytes(payload)
    updated = tuple(sorted({*requests, request_name}, key=lambda item: (item.casefold(), item)))
    document = {
        "schema_version": 1,
        "kind": _MARKER_KIND,
        "state_directory": state_value,
        "requests": list(updated),
    }
    if updated == requests:
        return
    transaction = CASTransaction(root)
    transaction.write(
        state / MARKER_NAME,
        canonical_json(document),
        expected_sha256=prior.value if prior is not None else None,
    )
    transaction.commit()


def _require_request_ownership(
    requests: tuple[str, ...],
    request_name: str,
    *,
    allow_shared: bool,
    state_root: Path,
) -> None:
    if request_name not in requests:
        raise DiscoveryStateError(
            f"discovery state is not owned by request {request_name!r}: {state_root}"
        )
    if len(requests) > 1 and not allow_shared:
        owners = ", ".join(repr(item) for item in requests)
        raise DiscoveryStateError(
            f"discovery state is shared by {owners}; rerun with --all-requests to remove "
            "their shared state together"
        )


def inspect_owned_state(
    root: Path,
    state: Path,
    request_name: str,
    *,
    allow_shared: bool = False,
) -> DiscoveryStateUsage | None:
    """Validate marker ownership and return a no-follow disk-usage receipt."""

    state_value = _portable(state)
    state_root = root / state
    if not os.path.lexists(state_root):
        return None
    if state_root.is_symlink() or not state_root.is_dir():
        raise DiscoveryStateError(f"discovery state is not a real directory: {state_root}")
    marker = state_root / MARKER_NAME
    if marker.is_symlink() or not marker.is_file():
        raise DiscoveryStateError(
            f"refusing to clean unmarked discovery state: {state_root}; rerun the campaign first"
        )
    marker_payload = marker.read_bytes()
    requests = _marker_document(marker_payload, state=state_value)
    _require_request_ownership(
        requests,
        request_name,
        allow_shared=allow_shared,
        state_root=state_root,
    )
    root_metadata = state_root.stat(follow_symlinks=False)
    inode = getattr(root_metadata, "st_ino", 0)
    identity = (root_metadata.st_dev, inode) if inode else None

    files = 0
    total = 0
    pending = [state_root]
    is_junction = getattr(os.path, "isjunction", lambda _path: False)
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                if entry.is_symlink() or is_junction(path):
                    raise DiscoveryStateError(
                        f"refusing to clean redirected discovery state entry: {path}"
                    )
                metadata = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(metadata.st_mode):
                    pending.append(path)
                elif stat.S_ISREG(metadata.st_mode):
                    files += 1
                    total += metadata.st_size
                else:
                    raise DiscoveryStateError(
                        f"refusing to clean special discovery state entry: {path}"
                    )
    return DiscoveryStateUsage(
        state_root,
        files,
        total,
        state_value,
        requests,
        Digest.from_bytes(marker_payload),
        identity,
    )


def remove_owned_state(
    usage: DiscoveryStateUsage,
    request_name: str,
    *,
    allow_shared: bool = False,
) -> None:
    """Revalidate the ownership boundary immediately before removing the tree."""

    if usage.path.is_symlink() or not usage.path.is_dir():
        raise DiscoveryStateError(f"discovery state changed before cleanup: {usage.path}")
    current_metadata = usage.path.stat(follow_symlinks=False)
    current_inode = getattr(current_metadata, "st_ino", 0)
    current_identity = (current_metadata.st_dev, current_inode) if current_inode else None
    if usage.identity is not None and current_identity != usage.identity:
        raise DiscoveryStateError(f"discovery state changed before cleanup: {usage.path}")
    marker = usage.path / MARKER_NAME
    if marker.is_symlink() or not marker.is_file():
        raise DiscoveryStateError(f"discovery state marker changed before cleanup: {marker}")
    marker_payload = marker.read_bytes()
    if Digest.from_bytes(marker_payload) != usage.marker_digest:
        raise DiscoveryStateError(f"discovery state ownership changed before cleanup: {marker}")
    requests = _marker_document(marker_payload, state=usage.state_directory)
    if requests != usage.requests:
        raise DiscoveryStateError(f"discovery state ownership changed before cleanup: {marker}")
    _require_request_ownership(
        requests,
        request_name,
        allow_shared=allow_shared,
        state_root=usage.path,
    )
    shutil.rmtree(usage.path)


__all__ = [
    "DiscoveryStateError",
    "DiscoveryStateUsage",
    "inspect_owned_state",
    "register_state",
    "remove_owned_state",
    "state_lock",
]
