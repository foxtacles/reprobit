"""Canonical linker identity for LINK 4.20-specific classic proofs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from reprobit.model import Digest
from reprobit.schema import MsvcRelease, ToolchainLock
from reprobit.strict_json import canonical_json

MSVC420_LINKER_TARGET: Final = "msvc-4.20-link-win32-i386"

_LOCK_ADAPTER: Final = "classic-msvc"
_LOCK_PROFILE: Final = "msvc_4_2"
_SOURCE_REPOSITORY: Final = "https://github.com/archaic-msvc/msvc420.git"
_SOURCE_REVISION: Final = "b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50"
_RECEIPT_SCHEMA: Final = "reprobit.classic-linker-identity.v1"
_ISSUANCE_KEY: Final = object()


@dataclass(frozen=True, slots=True)
class CanonicalLinkerTool:
    """The reviewed LINK executable used by the ordering theorem."""

    path: str
    size: int
    digest: Digest
    roles: tuple[str, ...]

    def receipt(self) -> dict[str, object]:
        return {
            "path": self.path,
            "size": self.size,
            "digest": self.digest.model_dump(mode="json"),
            "roles": list(self.roles),
        }


_CANONICAL_LINKER: Final = CanonicalLinkerTool(
    path="bin/LINK.EXE",
    size=514_048,
    digest=Digest(value="6ca5a19155e4170e8df08247769b4586fa951743f09f1d8fcec838fc4eb9750e"),
    roles=("linker",),
)


@dataclass(frozen=True, slots=True, init=False)
class Msvc420LinkerIdentity:
    """Evidence that a schema-v3 lock names the reviewed LINK 4.20 bytes."""

    toolchain_lock_digest: Digest

    def __init__(
        self, toolchain_lock_digest: Digest, *, _issuance_key: object | None = None
    ) -> None:
        if _issuance_key is not _ISSUANCE_KEY:
            raise TypeError("MSVC 4.20 linker identities must be issued from a validated lock")
        object.__setattr__(self, "toolchain_lock_digest", toolchain_lock_digest)

    @property
    def target(self) -> str:
        return MSVC420_LINKER_TARGET

    @property
    def tool(self) -> CanonicalLinkerTool:
        return _CANONICAL_LINKER

    def receipt_material(self) -> dict[str, object]:
        return {
            "schema": _RECEIPT_SCHEMA,
            "target": self.target,
            "adapter": _LOCK_ADAPTER,
            "profile": _LOCK_PROFILE,
            "release": MsvcRelease.V4_2.value,
            "architecture": "x86",
            "coff_machine": "i386",
            "source": {
                "repository": _SOURCE_REPOSITORY,
                "revision": _SOURCE_REVISION,
                "paths": [self.tool.path],
            },
            "tool": self.tool.receipt(),
            "toolchain_lock_digest": self.toolchain_lock_digest.model_dump(mode="json"),
        }

    def canonical_receipt(self) -> bytes:
        return canonical_json(self.receipt_material())

    def receipt_digest(self) -> Digest:
        return Digest.from_bytes(self.canonical_receipt())

    def proof_receipt(self) -> dict[str, object]:
        return {
            **self.receipt_material(),
            "receipt_digest": self.receipt_digest().model_dump(mode="json"),
        }


def _source_is_canonical(lock: ToolchainLock) -> bool:
    matching_sources = [
        source
        for source in lock.profile_sources
        if source.repository == _SOURCE_REPOSITORY and source.revision == _SOURCE_REVISION
    ]
    if len(matching_sources) != 1:
        return False
    source = matching_sources[0]
    assignments = [
        (candidate, path)
        for candidate in lock.profile_sources
        for path in candidate.paths
        if path.casefold() == _CANONICAL_LINKER.path.casefold()
    ]
    return assignments == [(source, _CANONICAL_LINKER.path)]


def _tool_is_canonical(lock: ToolchainLock) -> bool:
    matches = [
        tool
        for tool in lock.tools
        if tool.path.casefold() == _CANONICAL_LINKER.path.casefold()
    ]
    if len(matches) != 1:
        return False
    received = matches[0]
    if (
        received.path != _CANONICAL_LINKER.path
        or received.size != _CANONICAL_LINKER.size
        or received.digest != _CANONICAL_LINKER.digest
        or received.roles != _CANONICAL_LINKER.roles
    ):
        return False
    linker_tools = [
        tool for tool in (*lock.tools, *lock.runtime_files) if "linker" in tool.roles
    ]
    return len(linker_tools) == 1 and linker_tools[0] == received


def issue_msvc420_linker_identity(lock: ToolchainLock) -> Msvc420LinkerIdentity | None:
    """Issue exact LINK 4.20 evidence, or fail closed."""

    if not isinstance(lock, ToolchainLock):
        return None
    if (
        type(lock.schema_version) is not int
        or lock.schema_version != 3
        or type(lock.adapter) is not str
        or lock.adapter != _LOCK_ADAPTER
        or type(lock.profile) is not str
        or lock.profile != _LOCK_PROFILE
        or lock.release is not MsvcRelease.V4_2
        or not _source_is_canonical(lock)
        or not _tool_is_canonical(lock)
    ):
        return None
    return Msvc420LinkerIdentity(
        toolchain_lock_digest=Digest.from_bytes(canonical_json(lock)),
        _issuance_key=_ISSUANCE_KEY,
    )


__all__ = [
    "MSVC420_LINKER_TARGET",
    "CanonicalLinkerTool",
    "Msvc420LinkerIdentity",
    "issue_msvc420_linker_identity",
]
