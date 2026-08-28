"""Capability profiles and receipts for classic Microsoft C/C++ toolchains."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal

from reprobit.context import CompileContext
from reprobit.paths import normalize_logical_path

if TYPE_CHECKING:
    from reprobit.schema import ToolchainLock as SchemaToolchainLock


class ToolchainError(RuntimeError):
    """A toolchain profile, installation, or lock failed validation."""


MSVC_42 = "msvc_4_2"
MSVC_50_RTM = "msvc_5_0_rtm"
MSVC_50_SP1 = "msvc_5_0_sp1"
MSVC_50_SP2 = "msvc_5_0_sp2"
MSVC_50_SP3 = "msvc_5_0_sp3"
TREE_RECEIPT_ALGORITHM: Literal["portable-tree-v1"] = "portable-tree-v1"

_TREE_MAX_ENTRIES = 200_000
_TREE_MAX_DEPTH = 64


def _relative(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"toolchain path must be canonical and relative: {value!r}")
    return path.as_posix()


@dataclass(frozen=True, slots=True)
class ToolchainCapabilities:
    architecture: str = "x86"
    coff_machine: str = "i386"
    program_database: bool = True
    separate_object_pdb: bool = True
    incremental_linking: bool = True
    response_files: bool = True
    compiler_frontend_form: str = "executable"
    pdb_generation: str = "4.1"


@dataclass(frozen=True, slots=True)
class ToolchainSourcePin:
    """One reviewed repository input for installed profile paths."""

    repository: str
    revision: str
    paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not self.repository
            or self.repository != self.repository.strip()
            or any(ord(character) < 0x20 for character in self.repository)
        ):
            raise ValueError(
                "toolchain profile-source repository must be a non-empty canonical URL"
            )
        if len(self.revision) != 40 or any(
            character not in "0123456789abcdef" for character in self.revision
        ):
            raise ValueError(
                "toolchain profile-source revision must be a full lower-case Git hash"
            )
        paths = tuple(sorted((_relative(path) for path in self.paths), key=str.casefold))
        if not paths:
            raise ValueError(
                "toolchain profile source must supply at least one installed path"
            )
        if len({path.casefold() for path in paths}) != len(paths):
            raise ValueError(
                "toolchain profile-source paths must be unique under DOS case folding"
            )
        object.__setattr__(self, "paths", paths)


@dataclass(frozen=True, slots=True)
class ToolchainProfile:
    identifier: str
    display_name: str
    family: str
    release: str
    sources: tuple[ToolchainSourcePin, ...]
    compiler: str
    linker: str
    librarian: str
    resource_compiler: str
    required_producers: tuple[str, ...]
    include_roots: tuple[str, ...]
    library_roots: tuple[str, ...]
    default_compile_options: tuple[str, ...]
    capabilities: ToolchainCapabilities
    required_runtime_files: tuple[str, ...] = ()
    wine_dll_overrides: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.identifier or not self.display_name or not self.family or not self.release:
            raise ValueError("toolchain profile identity fields must not be empty")
        for field in ("compiler", "linker", "librarian", "resource_compiler"):
            object.__setattr__(self, field, _relative(getattr(self, field)))
        object.__setattr__(
            self, "required_producers", tuple(_relative(path) for path in self.required_producers)
        )
        object.__setattr__(
            self, "include_roots", tuple(_relative(path) for path in self.include_roots)
        )
        object.__setattr__(
            self, "library_roots", tuple(_relative(path) for path in self.library_roots)
        )
        object.__setattr__(
            self,
            "required_runtime_files",
            tuple(_relative(path) for path in self.required_runtime_files),
        )
        if len(set(self.required_producers)) != len(self.required_producers):
            raise ValueError("toolchain producer paths must be unique")
        all_files = tuple(path.casefold() for path in self.required_producers) + tuple(
            path.casefold() for path in self.required_runtime_files
        )
        if len(all_files) != len(set(all_files)):
            raise ValueError("toolchain producer and runtime paths must be disjoint")
        override_names = [name.casefold() for name, _ in self.wine_dll_overrides]
        if len(set(override_names)) != len(override_names):
            raise ValueError("toolchain Wine DLL overrides must be unique")

        source_keys = [(source.repository, source.revision) for source in self.sources]
        if len(source_keys) != len(set(source_keys)):
            raise ValueError("toolchain repository revisions must be unique")
        supplied_paths = [path for source in self.sources for path in source.paths]
        if len({path.casefold() for path in supplied_paths}) != len(supplied_paths):
            raise ValueError(
                "toolchain profile sources assign an installed path more than once"
            )
        declared_paths = {
            path.casefold()
            for path in (
                *self.required_producers,
                *self.required_runtime_files,
                *self.include_roots,
                *self.library_roots,
            )
        }
        received_paths = {path.casefold() for path in supplied_paths}
        if received_paths != declared_paths:
            raise ValueError(
                "toolchain source paths differ from the profile authority; "
                f"missing={sorted(declared_paths - received_paths)}, "
                f"extra={sorted(received_paths - declared_paths)}"
            )

    def source_for_path(self, path: str) -> ToolchainSourcePin:
        """Return the immutable repository input for one declared installed path."""

        folded = _relative(path).casefold()
        for source in self.sources:
            if folded in {candidate.casefold() for candidate in source.paths}:
                return source
        raise ToolchainError(f"profile does not assign a repository input for {path!r}")


_COMMON_OPTIONS = ("/nologo", "/c")

_MSVC42_PRODUCERS = (
    "bin/CL.EXE",
    "bin/C1.EXE",
    "bin/C1XX.EXE",
    "bin/C2.EXE",
    "bin/MSPDB41.DLL",
    "bin/LINK.EXE",
    "bin/LIB.EXE",
    "bin/RC.EXE",
    "bin/CVTRES.EXE",
)
_MSVC42_INPUT_ROOTS = ("include", "mfc/include", "lib", "mfc/lib")
_MSVC42_RUNTIME = ("bin/MSVCRT40.dll", "bin/msvcrt20.dll", "bin/RCDLL.DLL")
_MSVC50_PRODUCERS = (
    "bin/cl.exe",
    "bin/c1.dll",
    "bin/c1xx.dll",
    "bin/c2.exe",
    "bin/mspdb50.dll",
    "bin/link.exe",
    "bin/lib.exe",
    "bin/rc.exe",
    "bin/cvtres.exe",
)
_MSVC50_INPUT_ROOTS = ("include", "mfc/include", "atl/include", "lib", "mfc/lib")
_MSVC50_RUNTIME = ("bin/msdis100.dll",)

_PROFILES = {
    MSVC_42: ToolchainProfile(
        identifier=MSVC_42,
        display_name="Microsoft Visual C++ 4.2",
        family="msvc",
        release="4.2",
        sources=(
            ToolchainSourcePin(
                repository="https://github.com/archaic-msvc/msvc420.git",
                revision="b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50",
                paths=(*_MSVC42_PRODUCERS, *_MSVC42_INPUT_ROOTS, "bin/RCDLL.DLL"),
            ),
            ToolchainSourcePin(
                repository="https://github.com/archaic-msvc/msvc500.git",
                revision="8abf95ce980161ad87b0b02402269cce76988953",
                paths=("bin/MSVCRT40.dll", "bin/msvcrt20.dll"),
            ),
        ),
        compiler="bin/CL.EXE",
        linker="bin/LINK.EXE",
        librarian="bin/LIB.EXE",
        resource_compiler="bin/RC.EXE",
        required_producers=_MSVC42_PRODUCERS,
        include_roots=("include", "mfc/include"),
        library_roots=("lib", "mfc/lib"),
        default_compile_options=_COMMON_OPTIONS,
        capabilities=ToolchainCapabilities(),
        required_runtime_files=_MSVC42_RUNTIME,
        wine_dll_overrides=(("msvcrt40", "n"), ("msvcrt20", "n")),
    ),
    MSVC_50_RTM: ToolchainProfile(
        identifier=MSVC_50_RTM,
        display_name="Microsoft Visual C++ 5.0 RTM",
        family="msvc",
        release="5.0-rtm",
        sources=(
            ToolchainSourcePin(
                repository="https://github.com/archaic-msvc/msvc500.git",
                revision="8abf95ce980161ad87b0b02402269cce76988953",
                paths=(*_MSVC50_PRODUCERS, *_MSVC50_INPUT_ROOTS, *_MSVC50_RUNTIME),
            ),
        ),
        compiler="bin/cl.exe",
        linker="bin/link.exe",
        librarian="bin/lib.exe",
        resource_compiler="bin/rc.exe",
        required_producers=_MSVC50_PRODUCERS,
        include_roots=("include", "mfc/include", "atl/include"),
        library_roots=("lib", "mfc/lib"),
        default_compile_options=_COMMON_OPTIONS,
        capabilities=ToolchainCapabilities(
            compiler_frontend_form="dynamic_library", pdb_generation="5.0"
        ),
        required_runtime_files=_MSVC50_RUNTIME,
    ),
    MSVC_50_SP1: ToolchainProfile(
        identifier=MSVC_50_SP1,
        display_name="Microsoft Visual C++ 5.0 SP1",
        family="msvc",
        release="5.0-sp1",
        sources=(
            ToolchainSourcePin(
                repository="https://github.com/archaic-msvc/msvc500sp1.git",
                revision="401174749393c9991a6b91425a795e04e8bdeedb",
                paths=(*_MSVC50_PRODUCERS, *_MSVC50_INPUT_ROOTS, *_MSVC50_RUNTIME),
            ),
        ),
        compiler="bin/cl.exe",
        linker="bin/link.exe",
        librarian="bin/lib.exe",
        resource_compiler="bin/rc.exe",
        required_producers=_MSVC50_PRODUCERS,
        include_roots=("include", "mfc/include", "atl/include"),
        library_roots=("lib", "mfc/lib"),
        default_compile_options=_COMMON_OPTIONS,
        capabilities=ToolchainCapabilities(
            compiler_frontend_form="dynamic_library", pdb_generation="5.0"
        ),
        required_runtime_files=_MSVC50_RUNTIME,
    ),
    MSVC_50_SP2: ToolchainProfile(
        identifier=MSVC_50_SP2,
        display_name="Microsoft Visual C++ 5.0 SP2",
        family="msvc",
        release="5.0-sp2",
        sources=(
            ToolchainSourcePin(
                repository="https://github.com/archaic-msvc/msvc500sp2.git",
                revision="4ebf02022705b4c9e9108d3ed3f286ed80ba2ed9",
                paths=(*_MSVC50_PRODUCERS, *_MSVC50_INPUT_ROOTS, *_MSVC50_RUNTIME),
            ),
        ),
        compiler="bin/cl.exe",
        linker="bin/link.exe",
        librarian="bin/lib.exe",
        resource_compiler="bin/rc.exe",
        required_producers=_MSVC50_PRODUCERS,
        include_roots=("include", "mfc/include", "atl/include"),
        library_roots=("lib", "mfc/lib"),
        default_compile_options=_COMMON_OPTIONS,
        capabilities=ToolchainCapabilities(
            compiler_frontend_form="dynamic_library", pdb_generation="5.0"
        ),
        required_runtime_files=_MSVC50_RUNTIME,
    ),
    MSVC_50_SP3: ToolchainProfile(
        identifier=MSVC_50_SP3,
        display_name="Microsoft Visual C++ 5.0 SP3",
        family="msvc",
        release="5.0-sp3",
        sources=(
            ToolchainSourcePin(
                repository="https://github.com/archaic-msvc/msvc500sp3.git",
                revision="259a03f0bc863de5baf657ec064cb60cb20a2cdc",
                paths=(*_MSVC50_PRODUCERS, *_MSVC50_INPUT_ROOTS, *_MSVC50_RUNTIME),
            ),
        ),
        compiler="bin/cl.exe",
        linker="bin/link.exe",
        librarian="bin/lib.exe",
        resource_compiler="bin/rc.exe",
        required_producers=_MSVC50_PRODUCERS,
        include_roots=("include", "mfc/include", "atl/include"),
        library_roots=("lib", "mfc/lib"),
        default_compile_options=_COMMON_OPTIONS,
        capabilities=ToolchainCapabilities(
            compiler_frontend_form="dynamic_library", pdb_generation="5.0"
        ),
        required_runtime_files=_MSVC50_RUNTIME,
    ),
}

TOOLCHAIN_PROFILES: Mapping[str, ToolchainProfile] = MappingProxyType(_PROFILES)


def profile(identifier: str) -> ToolchainProfile:
    try:
        return TOOLCHAIN_PROFILES[identifier]
    except KeyError as error:
        raise ToolchainError(f"unsupported classic MSVC profile: {identifier}") from error


@dataclass(frozen=True, slots=True)
class ToolchainFileReceipt:
    path: str
    size: int | None
    sha256: str
    roles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _relative(self.path))
        if self.size is not None and self.size <= 0:
            raise ValueError("toolchain file receipt size must be positive")
        _validate_sha256(self.sha256, "toolchain file")
        if not isinstance(self.roles, (list, tuple)) or any(
            not isinstance(role, str)
            or not re.fullmatch(r"[a-z][a-z0-9._-]{0,127}", role)
            for role in self.roles
        ):
            raise ValueError("toolchain file roles must be canonical identifiers")
        roles = tuple(self.roles)
        if len(roles) != len(set(roles)):
            raise ValueError("toolchain file roles must be unique")
        object.__setattr__(self, "roles", roles)


@dataclass(frozen=True, slots=True)
class ToolchainTreeReceipt:
    path: str
    entry_count: int
    max_depth: int
    membership_sha256: str
    content_sha256: str
    algorithm: Literal["portable-tree-v1"] = TREE_RECEIPT_ALGORITHM

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _relative(self.path))
        if self.entry_count < 0 or self.max_depth < 0:
            raise ValueError("toolchain tree receipt counts must be non-negative")
        if self.algorithm != TREE_RECEIPT_ALGORITHM:
            raise ValueError(f"unsupported toolchain tree algorithm: {self.algorithm}")
        _validate_sha256(self.membership_sha256, "toolchain tree membership")
        _validate_sha256(self.content_sha256, "toolchain tree content")

    def __iter__(self) -> Iterator[str]:
        """Retain ``dict(lock.tree_digests)`` compatibility for v1 callers."""

        yield self.path
        yield self.content_sha256


def _validate_sha256(value: str, label: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{label} digest must be lower-case SHA-256")


def profile_source_pins_for_paths(
    selected: ToolchainProfile, paths: Iterable[str]
) -> tuple[ToolchainSourcePin, ...]:
    """Project a profile's repository pins onto a finite locked path set."""

    admitted = {_relative(path).casefold() for path in paths}
    projected: list[ToolchainSourcePin] = []
    for source in selected.sources:
        source_paths = tuple(path for path in source.paths if path.casefold() in admitted)
        if source_paths:
            projected.append(
                ToolchainSourcePin(source.repository, source.revision, source_paths)
            )
    return tuple(projected)


def _source_assignments(
    sources: Iterable[ToolchainSourcePin],
) -> dict[str, tuple[str, str]]:
    assignments: dict[str, tuple[str, str]] = {}
    source_keys: set[tuple[str, str]] = set()
    for source in sources:
        key = (source.repository, source.revision)
        if key in source_keys:
            raise ValueError("toolchain repository revision is repeated")
        source_keys.add(key)
        for path in source.paths:
            folded = path.casefold()
            if folded in assignments:
                raise ValueError("toolchain profile-source path is assigned more than once")
            assignments[folded] = key
    return assignments


@dataclass(frozen=True, slots=True)
class ToolchainLock:
    schema: str
    profile: str
    profile_sources: tuple[ToolchainSourcePin, ...]
    files: tuple[ToolchainFileReceipt, ...]
    tree_digests: tuple[ToolchainTreeReceipt, ...] = ()
    runtime_files: tuple[ToolchainFileReceipt, ...] = ()

    SCHEMA = "reprobit.toolchain-lock.v2"

    def __post_init__(self) -> None:
        if self.schema != self.SCHEMA:
            raise ValueError(f"unsupported runtime toolchain lock schema: {self.schema}")
        selected = profile(self.profile)
        file_paths = [item.path.casefold() for item in self.files]
        runtime_paths = [item.path.casefold() for item in self.runtime_files]
        tree_paths = [item.path.casefold() for item in self.tree_digests]
        if len(file_paths) != len(set(file_paths)):
            raise ValueError("runtime toolchain lock repeats a producer path")
        if len(tree_paths) != len(set(tree_paths)):
            raise ValueError("runtime toolchain lock repeats an input tree path")
        if len(runtime_paths) != len(set(runtime_paths)):
            raise ValueError("runtime toolchain lock repeats a runtime-file path")
        if set(file_paths) & set(runtime_paths):
            raise ValueError("runtime toolchain producer and runtime paths overlap")
        locked_paths = {*file_paths, *runtime_paths, *tree_paths}
        assignments = _source_assignments(self.profile_sources)
        unknown_paths = set(assignments) - locked_paths
        if unknown_paths:
            raise ValueError(
                "toolchain profile-source mapping names unlocked paths: "
                f"{sorted(unknown_paths)}"
            )
        expected = _source_assignments(
            profile_source_pins_for_paths(selected, locked_paths)
        )
        if set(assignments) != set(expected):
            raise ValueError(
                "runtime toolchain profile-source assignment set differs; "
                f"missing={sorted(set(expected) - set(assignments))}, "
                f"extra={sorted(set(assignments) - set(expected))}"
            )
        mismatched = {
            path
            for path, source in expected.items()
            if assignments.get(path) != source
        }
        if mismatched:
            raise ValueError(
                "runtime toolchain profile-source mapping differs for paths: "
                f"{sorted(mismatched)}"
            )

    def to_dict(self) -> dict[str, object]:
        body: dict[str, object] = {
            "schema": self.schema,
            "profile": self.profile,
            "profile_sources": [asdict(item) for item in self.profile_sources],
            "files": [asdict(item) for item in self.files],
            "tree_digests": [asdict(item) for item in self.tree_digests],
            "runtime_files": [asdict(item) for item in self.runtime_files],
        }
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        body["sha256"] = digest
        return body

    @classmethod
    def from_dict(cls, document: Mapping[str, Any]) -> ToolchainLock:
        """Load and authenticate the internal v2 receipt representation."""

        required_fields = {
            "schema",
            "profile",
            "profile_sources",
            "files",
            "tree_digests",
            "sha256",
        }
        allowed_fields = required_fields | {"runtime_files"}
        if not required_fields.issubset(document) or not set(document).issubset(allowed_fields):
            raise ToolchainError("runtime toolchain lock fields differ from v2")
        body = {key: value for key, value in document.items() if key != "sha256"}
        actual_digest = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if document["sha256"] != actual_digest:
            raise ToolchainError("runtime toolchain lock receipt digest differs")
        try:
            files_value = document["files"]
            trees_value = document["tree_digests"]
            runtime_value = document.get("runtime_files", [])
            sources_value = document["profile_sources"]
            if not all(
                isinstance(value, list)
                for value in (files_value, trees_value, runtime_value, sources_value)
            ):
                raise TypeError("lock receipt collections must be arrays")
            sources = tuple(ToolchainSourcePin(**item) for item in sources_value)
            files = tuple(ToolchainFileReceipt(**item) for item in files_value)
            trees = tuple(ToolchainTreeReceipt(**item) for item in trees_value)
            runtime_files = tuple(ToolchainFileReceipt(**item) for item in runtime_value)
            return cls(
                schema=str(document["schema"]),
                profile=str(document["profile"]),
                profile_sources=sources,
                files=files,
                tree_digests=trees,
                runtime_files=runtime_files,
            )
        except (TypeError, ValueError) as error:
            raise ToolchainError(f"invalid runtime toolchain lock: {error}") from error

    def to_schema_v3(self) -> SchemaToolchainLock:
        """Convert the internal receipt to the sole committed lock format."""

        from reprobit.model import Digest
        from reprobit.schema import (
            InputTreeReceipt,
            LockedTool,
            MsvcRelease,
            ToolchainProfileSource,
        )
        from reprobit.schema import ToolchainLock as SchemaToolchainLock

        selected = profile(self.profile)
        release = MsvcRelease(selected.release)
        tools = tuple(
            LockedTool(
                id=_receipt_identifier("tool", item.path),
                path=item.path,
                digest=Digest(value=item.sha256),
                size=item.size,
                roles=item.roles or _producer_roles(selected, item.path),
            )
            for item in self.files
        )
        trees = tuple(
            InputTreeReceipt(
                id=_receipt_identifier("tree", item.path),
                path=item.path,
                algorithm=item.algorithm,
                entry_count=item.entry_count,
                max_depth=item.max_depth,
                membership_digest=Digest(value=item.membership_sha256),
                content_digest=Digest(value=item.content_sha256),
            )
            for item in self.tree_digests
        )
        runtime_files = tuple(
            LockedTool(
                id=_receipt_identifier("runtime", item.path),
                path=item.path,
                digest=Digest(value=item.sha256),
                size=item.size,
                roles=item.roles or ("runtime",),
            )
            for item in self.runtime_files
        )
        return SchemaToolchainLock(
            schema_version=3,
            profile=self.profile,
            release=release,
            profile_sources=tuple(
                ToolchainProfileSource(
                    repository=source.repository,
                    revision=source.revision,
                    paths=source.paths,
                )
                for source in self.profile_sources
            ),
            tools=tools,
            runtime_files=runtime_files,
            input_trees=trees,
        )

    @classmethod
    def from_schema_v3(cls, document: Any) -> ToolchainLock:
        """Explicitly project a validated schema-v3 lock into runtime receipts."""

        from reprobit.schema import ToolchainLock as SchemaToolchainLock

        if not isinstance(document, SchemaToolchainLock):
            document = SchemaToolchainLock.model_validate(document)
        selected = profile(document.profile)
        runtime_sources = validate_toolchain_profile_sources(document)
        required = {
            path.casefold(): path for path in selected.required_producers
        }
        known_runtime = {
            path.casefold(): path for path in selected.required_runtime_files
        }
        locked = (*document.tools, *document.runtime_files)
        producer_items = tuple(
            item for item in locked if item.path.casefold() in required
        )
        received = {item.path.casefold() for item in producer_items}
        missing = set(required) - received
        if missing:
            raise ToolchainError(
                "schema-v3 lock omits required producers: "
                f"{sorted(required[path] for path in missing)}"
            )
        runtime_items = tuple(
            item for item in locked if item.path.casefold() not in required
        )
        received_runtime = {item.path.casefold() for item in runtime_items}
        missing_runtime = set(known_runtime) - received_runtime
        if missing_runtime:
            raise ToolchainError(
                "schema-v3 lock omits required runtime files: "
                f"{sorted(known_runtime[path] for path in missing_runtime)}"
            )
        known_trees = {
            path.casefold(): path
            for path in (*selected.include_roots, *selected.library_roots)
        }
        return cls(
            schema=cls.SCHEMA,
            profile=document.profile,
            profile_sources=runtime_sources,
            files=tuple(
                ToolchainFileReceipt(
                    required[item.path.casefold()],
                    item.size,
                    item.digest.value,
                    item.roles,
                )
                for item in producer_items
            ),
            tree_digests=tuple(
                ToolchainTreeReceipt(
                    known_trees.get(item.path.casefold(), item.path),
                    item.entry_count,
                    item.max_depth,
                    item.membership_digest.value,
                    item.content_digest.value,
                    item.algorithm,
                )
                for item in document.input_trees
            ),
            runtime_files=tuple(
                ToolchainFileReceipt(
                    known_runtime.get(item.path.casefold(), item.path),
                    item.size,
                    item.digest.value,
                    item.roles,
                )
                for item in runtime_items
            ),
        )


def validate_toolchain_profile_sources(document: Any) -> tuple[ToolchainSourcePin, ...]:
    """Validate a schema lock's repository inputs against its known profile."""

    from reprobit.schema import ToolchainLock as SchemaToolchainLock

    if not isinstance(document, SchemaToolchainLock):
        document = SchemaToolchainLock.model_validate(document)
    if document.adapter != "classic-msvc":
        raise ToolchainError("schema-v3 lock is not for the classic adapter")
    selected = profile(document.profile)
    if document.release.value != selected.release:
        raise ToolchainError("schema-v3 lock release differs from its profile")
    runtime_sources = tuple(
        ToolchainSourcePin(source.repository, source.revision, source.paths)
        for source in document.profile_sources
    )
    locked_paths = (
        *(item.path for item in document.tools),
        *(item.path for item in document.runtime_files),
        *(item.path for item in document.input_trees),
    )
    try:
        assignments = _source_assignments(runtime_sources)
        expected_assignments = _source_assignments(
            profile_source_pins_for_paths(selected, locked_paths)
        )
    except ValueError as error:
        raise ToolchainError(f"invalid schema-v3 profile-source mapping: {error}") from error
    if set(assignments) != set(expected_assignments):
        raise ToolchainError(
            "schema-v3 lock profile-source assignment set differs; "
            f"missing={sorted(set(expected_assignments) - set(assignments))}, "
            f"extra={sorted(set(assignments) - set(expected_assignments))}"
        )
    mismatched = {
        path
        for path, source in expected_assignments.items()
        if assignments.get(path) != source
    }
    if mismatched:
        raise ToolchainError(
            "schema-v3 lock profile-source mapping differs for paths: "
            f"{sorted(mismatched)}"
        )
    return runtime_sources


def _receipt_identifier(kind: str, path: str) -> str:
    normalized = re.sub(r"[^a-z0-9._-]+", ".", path.casefold()).strip(".-")
    identifier = f"{kind}.{normalized}"
    if len(identifier) <= 128:
        return identifier
    digest = hashlib.sha256(path.encode()).hexdigest()[:16]
    return f"{identifier[:111].rstrip('.-')}.{digest}"


def _producer_roles(selected: ToolchainProfile, path: str) -> tuple[str, ...]:
    roles: list[str] = []
    for role, producer in (
        ("compiler", selected.compiler),
        ("linker", selected.linker),
        ("librarian", selected.librarian),
        ("resource-compiler", selected.resource_compiler),
    ):
        if path.casefold() == producer.casefold():
            roles.append(role)
    return tuple(roles or ("runtime",))


@dataclass(frozen=True, slots=True)
class ToolchainCheck:
    path: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ToolchainDoctorReport:
    profile: str
    root: Path
    checks: tuple[ToolchainCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.passed for check in self.checks)

    def require_ok(self) -> None:
        failed = [check for check in self.checks if not check.passed]
        if failed:
            raise ToolchainError("; ".join(f"{item.path}: {item.detail}" for item in failed))


def _hash_file(
    path: Path, relative: str, roles: tuple[str, ...] = ()
) -> ToolchainFileReceipt:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return ToolchainFileReceipt(relative, path.stat().st_size, digest.hexdigest(), roles)


def _stable_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_mode,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _tree_receipt(root: Path, relative_root: str) -> ToolchainTreeReceipt:
    """Hash a portable, data-only input tree without following symlinks.

    ``portable-tree-v1`` commits canonical path/type/file-size/content records.
    Directory sizes, permission bits, inodes, and timestamps are deliberately
    excluded because they differ across macOS, Linux, and Windows.  The
    executable bit is normalized to false: include/library trees are data-only;
    anything the adapter may execute belongs in ``files`` or ``runtime_files``.
    """

    if root.is_symlink() or not root.is_dir():
        raise ToolchainError(f"toolchain tree root is absent or unsafe: {root}")
    try:
        root_before = root.stat(follow_symlinks=False)
    except OSError as error:
        raise ToolchainError(f"cannot inspect toolchain tree {root}: {error}") from error
    if not stat.S_ISDIR(root_before.st_mode):
        raise ToolchainError(f"toolchain tree root is absent or unsafe: {root}")
    records: list[dict[str, object]] = [{"path": ".", "type": "directory"}]
    observed_max_depth = 0

    def append(record: dict[str, object]) -> None:
        records.append(record)
        if len(records) > _TREE_MAX_ENTRIES:
            raise ToolchainError(
                f"toolchain tree exceeds {_TREE_MAX_ENTRIES} entries: {root}"
            )

    def walk(directory: Path, relative: PurePosixPath, depth: int) -> None:
        nonlocal observed_max_depth
        if depth > _TREE_MAX_DEPTH:
            raise ToolchainError(
                f"toolchain tree exceeds depth {_TREE_MAX_DEPTH}: {root}"
            )
        observed_max_depth = max(observed_max_depth, depth)
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError as error:
            raise ToolchainError(
                f"cannot enumerate toolchain tree {directory}: {error}"
            ) from error
        entries.sort(key=lambda entry: (entry.name.casefold(), entry.name))
        folded = [entry.name.casefold() for entry in entries]
        if len(folded) != len(set(folded)):
            raise ToolchainError(f"toolchain tree contains a casefold collision: {directory}")
        for entry in entries:
            name = entry.name
            if name in {"", ".", ".."} or "/" in name or "\\" in name or "\0" in name:
                raise ToolchainError(f"toolchain tree contains an unsafe entry: {name!r}")
            child_relative = relative / name
            logical_path = child_relative.as_posix()
            try:
                logical_path.encode("utf-8")
                before = entry.stat(follow_symlinks=False)
            except (OSError, UnicodeEncodeError) as error:
                raise ToolchainError(
                    f"cannot inspect toolchain tree entry {logical_path!r}: {error}"
                ) from error
            child = Path(entry.path)
            if stat.S_ISLNK(before.st_mode):
                raise ToolchainError(f"toolchain tree contains a symlink: {child}")
            if stat.S_ISDIR(before.st_mode):
                append({"path": logical_path, "type": "directory"})
                walk(child, child_relative, depth + 1)
                try:
                    after = child.stat(follow_symlinks=False)
                except OSError as error:
                    raise ToolchainError(
                        f"toolchain directory changed while hashed: {child}"
                    ) from error
                if not stat.S_ISDIR(after.st_mode) or _stable_identity(after) != _stable_identity(
                    before
                ):
                    raise ToolchainError(f"toolchain directory changed while hashed: {child}")
                continue
            if not stat.S_ISREG(before.st_mode):
                raise ToolchainError(
                    f"toolchain tree contains an unsupported entry type: {child}"
                )
            digest = hashlib.sha256()
            try:
                with child.open("rb") as stream:
                    opened = os.fstat(stream.fileno())
                    if not stat.S_ISREG(opened.st_mode) or (
                        opened.st_dev,
                        opened.st_ino,
                    ) != (before.st_dev, before.st_ino):
                        raise ToolchainError(
                            f"toolchain file changed while opened: {child}"
                        )
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                    after_read = os.fstat(stream.fileno())
                after_path = child.stat(follow_symlinks=False)
            except OSError as error:
                raise ToolchainError(f"cannot hash toolchain file {child}: {error}") from error
            if (
                _stable_identity(after_read) != _stable_identity(opened)
                or _stable_identity(after_path) != _stable_identity(opened)
                or not stat.S_ISREG(after_path.st_mode)
            ):
                raise ToolchainError(f"toolchain file changed while hashed: {child}")
            append(
                {
                    "path": logical_path,
                    "type": "file",
                    "executable": False,
                    "size": opened.st_size,
                    "sha256": digest.hexdigest(),
                }
            )

    walk(root, PurePosixPath(), 0)
    try:
        root_after = root.stat(follow_symlinks=False)
    except OSError as error:
        raise ToolchainError(f"toolchain tree changed while hashed: {root}") from error
    if _stable_identity(root_after) != _stable_identity(root_before):
        raise ToolchainError(f"toolchain tree changed while hashed: {root}")
    membership_records = [
        {key: value for key, value in record.items() if key != "sha256"}
        for record in records
    ]
    membership = hashlib.sha256(
        json.dumps(membership_records, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    content = hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return ToolchainTreeReceipt(
        relative_root,
        len(records),
        observed_max_depth,
        membership,
        content,
        TREE_RECEIPT_ALGORITHM,
    )


def portable_tree_receipt(root: Path, relative_root: str) -> ToolchainTreeReceipt:
    """Publicly recompute one locked ``portable-tree-v1`` authority receipt."""

    return _tree_receipt(root, relative_root)


class ClassicMSVCToolchain:
    """One physical installation bound to one immutable capability profile."""

    def __init__(
        self,
        profile: ToolchainProfile | str,
        root: Path | str,
        *,
        logical_root: str = "R:\\toolchain",
    ) -> None:
        if isinstance(profile, str):
            try:
                selected_profile = TOOLCHAIN_PROFILES[profile]
            except KeyError as error:
                raise ToolchainError(
                    f"unsupported classic MSVC profile: {profile}"
                ) from error
            self.profile = selected_profile
        else:
            self.profile = profile
        candidate = Path(root)
        if not candidate.is_absolute():
            raise ToolchainError("toolchain root must be absolute")
        self.root = candidate.resolve(strict=False)
        self.logical_root = normalize_logical_path(logical_root)

    def host_path(self, relative_path: str) -> Path:
        relative = _relative(relative_path)
        return self.root.joinpath(*PurePosixPath(relative).parts)

    def logical_path(self, relative_path: str) -> str:
        relative = _relative(relative_path).replace("/", "\\")
        return normalize_logical_path(self.logical_root.rstrip("\\") + "\\" + relative)

    @property
    def compiler_path(self) -> str:
        return self.logical_path(self.profile.compiler)

    @property
    def linker_path(self) -> str:
        return self.logical_path(self.profile.linker)

    @property
    def librarian_path(self) -> str:
        return self.logical_path(self.profile.librarian)

    @property
    def resource_compiler_path(self) -> str:
        return self.logical_path(self.profile.resource_compiler)

    def doctor(self, lock: ToolchainLock | None = None) -> ToolchainDoctorReport:
        expected = (
            {item.path.casefold(): item for item in lock.files} if lock is not None else {}
        )
        expected_runtime = (
            {item.path.casefold(): item for item in lock.runtime_files}
            if lock is not None
            else {}
        )
        checks: list[ToolchainCheck] = []
        if lock is not None:
            if (
                lock.schema != ToolchainLock.SCHEMA
                or lock.profile != self.profile.identifier
            ):
                checks.append(
                    ToolchainCheck(
                        "lock", False, "lock schema or profile differs"
                    )
                )
            required = {path.casefold() for path in self.profile.required_producers}
            received = {path.casefold() for path in expected}
            if received != required:
                checks.append(
                    ToolchainCheck(
                        "lock.files",
                        False,
                        "producer set differs; "
                        f"missing={sorted(required - received)}, "
                        f"extra={sorted(received - required)}",
                    )
                )
        for relative in self.profile.required_producers:
            path = self.host_path(relative)
            if not path.is_file() or path.is_symlink():
                checks.append(
                    ToolchainCheck(relative, False, "required producer is absent or unsafe")
                )
                continue
            pinned = expected.get(relative.casefold())
            if pinned is None:
                checks.append(
                    ToolchainCheck(
                        relative,
                        lock is None,
                        "present" if lock is None else "producer is not pinned",
                    )
                )
                continue
            actual = _hash_file(path, relative)
            matches = (
                (pinned.size is None or actual.size == pinned.size)
                and actual.sha256 == pinned.sha256
            )
            checks.append(
                ToolchainCheck(relative, matches, "digest matches" if matches else "digest differs")
            )
        if lock is not None:
            required_runtime = {
                path.casefold() for path in self.profile.required_runtime_files
            }
            missing_runtime = required_runtime - set(expected_runtime)
            if missing_runtime:
                checks.append(
                    ToolchainCheck(
                        "lock.runtime_files",
                        False,
                        f"required runtime files are unpinned: {sorted(missing_runtime)}",
                    )
                )
        runtime_paths = (
            tuple(item.path for item in lock.runtime_files)
            if lock is not None
            else self.profile.required_runtime_files
        )
        for relative in runtime_paths:
            path = self.host_path(relative)
            pinned = expected_runtime.get(relative.casefold())
            if not path.is_file() or path.is_symlink():
                checks.append(
                    ToolchainCheck(
                        relative,
                        False,
                        "required runtime file is absent or unsafe"
                        if lock is None
                        else "pinned runtime file is absent or unsafe",
                    )
                )
                continue
            if pinned is None:
                checks.append(ToolchainCheck(relative, True, "present"))
                continue
            actual = _hash_file(path, relative, pinned.roles)
            matches = (
                (pinned.size is None or actual.size == pinned.size)
                and actual.sha256 == pinned.sha256
            )
            checks.append(
                ToolchainCheck(
                    relative,
                    matches,
                    "runtime digest matches" if matches else "runtime digest differs",
                )
            )
        for relative in (*self.profile.include_roots, *self.profile.library_roots):
            path = self.host_path(relative)
            checks.append(
                ToolchainCheck(
                    relative,
                    path.is_dir() and not path.is_symlink(),
                    "present"
                    if path.is_dir() and not path.is_symlink()
                    else "tree is absent or unsafe",
                )
            )
        if lock is not None:
            actual_tree = {
                relative: _tree_receipt(self.host_path(relative), relative)
                for relative in (
                    *self.profile.include_roots,
                    *self.profile.library_roots,
                )
            }
            expected_tree_paths = {item.path for item in lock.tree_digests}
            declared_tree_paths = {
                *self.profile.include_roots,
                *self.profile.library_roots,
            }
            if {path.casefold() for path in expected_tree_paths} != {
                path.casefold() for path in declared_tree_paths
            }:
                checks.append(
                    ToolchainCheck(
                        "lock.input_trees", False, "input tree set differs from the profile"
                    )
                )
            for expected_receipt in lock.tree_digests:
                actual_receipt = actual_tree.get(expected_receipt.path)
                checks.append(
                    ToolchainCheck(
                        expected_receipt.path,
                        actual_receipt == expected_receipt,
                        "tree receipt matches"
                        if actual_receipt == expected_receipt
                        else "tree receipt differs",
                    )
                )
        return ToolchainDoctorReport(self.profile.identifier, self.root, tuple(checks))

    def create_lock(
        self,
        *,
        include_trees: bool = True,
        runtime_paths: Iterable[str] = (),
    ) -> ToolchainLock:
        self.doctor().require_ok()
        files: list[ToolchainFileReceipt] = []
        for relative in self.profile.required_producers:
            files.append(
                _hash_file(
                    self.host_path(relative),
                    relative,
                    _producer_roles(self.profile, relative),
                )
            )
        declared_runtime = (
            *self.profile.required_runtime_files,
            *tuple(_relative(path) for path in runtime_paths),
        )
        folded_runtime = [path.casefold() for path in declared_runtime]
        if len(folded_runtime) != len(set(folded_runtime)):
            raise ToolchainError("declared runtime file paths are repeated")
        producers = {path.casefold() for path in self.profile.required_producers}
        overlap = producers.intersection(folded_runtime)
        if overlap:
            raise ToolchainError(
                f"declared runtime files overlap required producers: {sorted(overlap)}"
            )
        runtime_files: list[ToolchainFileReceipt] = []
        for relative in declared_runtime:
            path = self.host_path(relative)
            if not path.is_file() or path.is_symlink():
                raise ToolchainError(
                    f"declared runtime file is absent or unsafe: {relative}"
                )
            runtime_files.append(_hash_file(path, relative, ("runtime",)))
        trees: list[ToolchainTreeReceipt] = []
        if include_trees:
            for relative in (*self.profile.include_roots, *self.profile.library_roots):
                trees.append(_tree_receipt(self.host_path(relative), relative))
        locked_paths = (
            *(item.path for item in files),
            *(item.path for item in runtime_files),
            *(item.path for item in trees),
        )
        return ToolchainLock(
            ToolchainLock.SCHEMA,
            self.profile.identifier,
            profile_source_pins_for_paths(self.profile, locked_paths),
            tuple(files),
            tuple(trees),
            tuple(runtime_files),
        )

    def default_environment(self, *, temp_directory: str) -> dict[str, str]:
        temporary = normalize_logical_path(temp_directory)
        include = ";".join(self.logical_path(path) for path in self.profile.include_roots)
        libraries = ";".join(self.logical_path(path) for path in self.profile.library_roots)
        return {
            "PATH": self.logical_path("bin"),
            "INCLUDE": include,
            "LIB": libraries,
            "TMP": temporary,
            "TEMP": temporary,
        }

    def compile_context(
        self,
        *,
        source: str,
        object_file: str,
        pdb_file: str,
        cwd: str,
        temp_directory: str,
        backend_profile: str,
        include_paths: Iterable[str] = (),
        forced_includes: Iterable[str] = (),
        defines: Iterable[str] = (),
        options: Iterable[str] = (),
        environment: Mapping[str, str] | None = None,
        logical_worker_root: str | None = None,
    ) -> CompileContext:
        source = normalize_logical_path(source)
        object_file = normalize_logical_path(object_file)
        pdb_file = normalize_logical_path(pdb_file)
        cwd = normalize_logical_path(cwd)
        temp_directory = normalize_logical_path(temp_directory)
        includes = tuple(normalize_logical_path(path) for path in include_paths)
        forced = tuple(normalize_logical_path(path) for path in forced_includes)
        define_values = tuple(defines)
        option_values = tuple(options)
        for label, compiler_values in (
            ("definition", define_values),
            ("option", option_values),
        ):
            if any(
                not isinstance(value, str) or not value or "\0" in value
                for value in compiler_values
            ):
                raise ToolchainError(f"compiler {label}s must be NUL-free strings")
        argv = (
            self.compiler_path,
            *self.profile.default_compile_options,
            *option_values,
            *(f"/D{value}" for value in define_values),
            *(f"/I{path}" for path in includes),
            *(f"/FI{path}" for path in forced),
            f"/Fo{object_file}",
            f"/Fd{pdb_file}",
            source,
        )
        values = self.default_environment(temp_directory=temp_directory)
        if environment is not None:
            keys = [key.casefold() for key in environment]
            if len(keys) != len(set(keys)):
                raise ToolchainError("compiler environment repeats a case-insensitive key")
            if any(
                not isinstance(key, str)
                or not key
                or "\0" in key
                or not isinstance(value, str)
                or "\0" in value
                for key, value in environment.items()
            ):
                raise ToolchainError("compiler environment must contain NUL-free strings")
            folded = {key.casefold(): key for key in values}
            for key, value in environment.items():
                old = folded.get(key.casefold())
                if old is not None:
                    del values[old]
                values[key] = value
        context = CompileContext.create(
            argv=argv,
            cwd=cwd,
            source=source,
            object_file=object_file,
            pdb_file=pdb_file,
            temp_directory=temp_directory,
            include_paths=includes,
            forced_includes=forced,
            defines=define_values,
            environment=values,
            toolchain_profile=self.profile.identifier,
            backend_profile=backend_profile,
        )
        if logical_worker_root is not None:
            context.require_private_artifacts(logical_worker_root)
        return context

    def link_command(self, arguments: Iterable[str]) -> tuple[str, ...]:
        return (self.linker_path, "/nologo", *tuple(arguments))

    def library_command(self, arguments: Iterable[str]) -> tuple[str, ...]:
        return (self.librarian_path, "/nologo", *tuple(arguments))


__all__ = [
    "MSVC_42",
    "MSVC_50_RTM",
    "MSVC_50_SP1",
    "MSVC_50_SP2",
    "MSVC_50_SP3",
    "TOOLCHAIN_PROFILES",
    "TREE_RECEIPT_ALGORITHM",
    "ClassicMSVCToolchain",
    "ToolchainCapabilities",
    "ToolchainCheck",
    "ToolchainDoctorReport",
    "ToolchainError",
    "ToolchainFileReceipt",
    "ToolchainLock",
    "ToolchainProfile",
    "ToolchainSourcePin",
    "ToolchainTreeReceipt",
    "portable_tree_receipt",
    "profile",
    "profile_source_pins_for_paths",
    "validate_toolchain_profile_sources",
]
