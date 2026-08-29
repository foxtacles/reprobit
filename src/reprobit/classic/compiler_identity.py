"""Canonical compiler identities used by compiler-specific classic proofs.

An ordinary toolchain lock proves that the files used by a run match the
project's declarations.  A compiler-specific theorem needs the narrower fact
that those declarations identify the reviewed compiler bytes.  This module is
the sole owner of that conversion for the Visual C++ 4.20 Win32 compiler.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from reprobit.model import Digest
from reprobit.schema import MsvcRelease, ToolchainLock
from reprobit.strict_json import canonical_json

MSVC420_WIN32_I386_TARGET: Final = "msvc-4.20-win32-i386"

_LOCK_ADAPTER: Final = "classic-msvc"
_LOCK_PROFILE: Final = "msvc_4_2"
_SOURCE_REPOSITORY: Final = "https://github.com/archaic-msvc/msvc420.git"
_SOURCE_REVISION: Final = "b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50"
_RECEIPT_SCHEMA: Final = "reprobit.classic-compiler-identity.v1"
_ISSUANCE_KEY: Final = object()


@dataclass(frozen=True, slots=True)
class CanonicalCompilerTool:
    """One reviewed compiler executable."""

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


_CANONICAL_TOOLS: Final = (
    CanonicalCompilerTool(
        path="bin/CL.EXE",
        size=37_888,
        digest=Digest(value="c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f"),
        roles=("compiler",),
    ),
    CanonicalCompilerTool(
        path="bin/C1XX.EXE",
        size=793_088,
        digest=Digest(value="9e0782ec157b30a387ca855374bc4c1b8a605dfb12364425497ba431541a5bf9"),
        roles=("runtime",),
    ),
    CanonicalCompilerTool(
        path="bin/C2.EXE",
        size=549_888,
        digest=Digest(value="2aa1fcace0779531b3ec80b730663acd98f181aed3cdff51366440c602b724b5"),
        roles=("runtime",),
    ),
)


@dataclass(frozen=True, slots=True, init=False)
class Msvc420CompilerIdentity:
    """Immutable evidence that a schema-v3 lock names reviewed MSVC 4.20 bytes."""

    toolchain_lock_digest: Digest

    def __init__(
        self, toolchain_lock_digest: Digest, *, _issuance_key: object | None = None
    ) -> None:
        if _issuance_key is not _ISSUANCE_KEY:
            raise TypeError("MSVC 4.20 compiler identities must be issued from a validated lock")
        object.__setattr__(self, "toolchain_lock_digest", toolchain_lock_digest)

    @property
    def target(self) -> str:
        return MSVC420_WIN32_I386_TARGET

    @property
    def tools(self) -> tuple[CanonicalCompilerTool, ...]:
        return _CANONICAL_TOOLS

    def receipt_material(self) -> dict[str, object]:
        """Return the canonical, self-digest-free proof statement."""

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
                "paths": [tool.path for tool in self.tools],
            },
            "tools": [tool.receipt() for tool in self.tools],
            "toolchain_lock_digest": self.toolchain_lock_digest.model_dump(mode="json"),
        }

    def canonical_receipt(self) -> bytes:
        """Serialize the identity statement for storage or comparison."""

        return canonical_json(self.receipt_material())

    def receipt_digest(self) -> Digest:
        """Digest the canonical identity statement."""

        return Digest.from_bytes(self.canonical_receipt())

    def proof_receipt(self) -> dict[str, object]:
        """Return the statement plus its independently reproducible digest."""

        return {
            **self.receipt_material(),
            "receipt_digest": self.receipt_digest().model_dump(mode="json"),
        }


def _source_is_canonical(lock: ToolchainLock) -> bool:
    canonical_paths = {tool.path for tool in _CANONICAL_TOOLS}
    matching_sources = [
        source
        for source in lock.profile_sources
        if source.repository == _SOURCE_REPOSITORY and source.revision == _SOURCE_REVISION
    ]
    if len(matching_sources) != 1:
        return False
    source = matching_sources[0]
    if not canonical_paths.issubset(source.paths):
        return False

    # A model copied without validation could assign a case variant or a second
    # source to the same DOS path.  Count every assignment and require the one
    # exact canonical spelling to belong to the reviewed source pin.
    for expected in canonical_paths:
        assignments = [
            (candidate, path)
            for candidate in lock.profile_sources
            for path in candidate.paths
            if path.casefold() == expected.casefold()
        ]
        if assignments != [(source, expected)]:
            return False
    return True


def _tools_are_canonical(lock: ToolchainLock) -> bool:
    for expected in _CANONICAL_TOOLS:
        matches = [tool for tool in lock.tools if tool.path.casefold() == expected.path.casefold()]
        if len(matches) != 1:
            return False
        received = matches[0]
        if (
            received.path != expected.path
            or received.size != expected.size
            or received.digest != expected.digest
            or received.roles != expected.roles
        ):
            return False
    compiler_tools = [
        tool for tool in (*lock.tools, *lock.runtime_files) if "compiler" in tool.roles
    ]
    return len(compiler_tools) == 1 and compiler_tools[0].path == _CANONICAL_TOOLS[0].path


def issue_msvc420_compiler_identity(lock: ToolchainLock) -> Msvc420CompilerIdentity | None:
    """Issue exact MSVC 4.20 Win32 i386 evidence, or fail closed.

    Physical-file validation remains the runtime toolchain doctor's job.  This
    function deliberately accepts only its schema-v3 authority and proves that
    the authority names the canonical compiler source and executable receipts.
    """

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
        or not _tools_are_canonical(lock)
    ):
        return None
    return Msvc420CompilerIdentity(
        toolchain_lock_digest=Digest.from_bytes(canonical_json(lock)),
        _issuance_key=_ISSUANCE_KEY,
    )


__all__ = [
    "MSVC420_WIN32_I386_TARGET",
    "CanonicalCompilerTool",
    "Msvc420CompilerIdentity",
    "issue_msvc420_compiler_identity",
]
