"""Exact declaration renderer and direct MSVC compiler used by discovery.

This module is intentionally analysis-free so raw compiler objects can remain
cache-valid when COFF qualification evolves.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from reprobit.declaration_shapes import (
    generate_extern_run,
    generate_forward_run,
    generate_pad_shape,
    generate_shape,
)
from reprobit.discovery_contracts import (
    CompileReceipt,
    DeclarationFamily,
    DeclarationPlacement,
    DeclarationState,
    DiscoveryCompileOutput,
    DiscoveryCompilerReceipt,
    DiscoveryError,
)
from reprobit.model import Digest
from reprobit.process import CancellationToken, CommandSpec, ProcessSupervisor
from reprobit.strict_json import JsonValue, canonical_json

_SOURCE_IDENTIFIER = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")
_DECLARED_IDENTIFIER = re.compile(rb"(?:class|void|int)[ \t]+([A-Za-z_][A-Za-z0-9_]*)")
_INCLUDE_DIRECTIVE = re.compile(
    rb"^[ \t]*\#[ \t]*include\b[^\r\n]*(?:\r\n|\n|\r|$)",
    re.MULTILINE,
)
_SAFE_MSVC_ARGUMENTS = frozenset(
    {
        "/c",
        "/G3",
        "/G4",
        "/G5",
        "/G6",
        "/Gd",
        "/Gf",
        "/GF",
        "/Gr",
        "/GR",
        "/GR-",
        "/Gx",
        "/GX",
        "/GX-",
        "/Gy",
        "/Gy-",
        "/Gz",
        "/J",
        "/ML",
        "/MLd",
        "/MT",
        "/MTd",
        "/nologo",
        "/O1",
        "/O2",
        "/Ob0",
        "/Ob1",
        "/Ob2",
        "/Od",
        "/Og",
        "/Oi",
        "/Oi-",
        "/Op",
        "/Op-",
        "/Os",
        "/Ot",
        "/Ox",
        "/Oy",
        "/Oy-",
        "/W0",
        "/W1",
        "/W2",
        "/W3",
        "/W4",
        "/WX",
        "/WX-",
        "/Z7",
        "/Za",
        "/Zd",
        "/Ze",
        "/Zi",
    }
)


def _require_safe_msvc_argument(argument: str) -> None:
    """Admit only path-free MSVC 4.x code-generation switches."""

    normalized = f"/{argument[1:]}" if argument.startswith("-") else argument
    if (
        not argument
        or not argument.isascii()
        or "\0" in argument
        or normalized not in _SAFE_MSVC_ARGUMENTS
    ):
        raise DiscoveryError(
            "MSVC discovery accepts only its documented path-free code-generation "
            f"switches; rejected {argument!r}"
        )


def validate_msvc_compiler_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    """Validate and return the exact ordered path-free switch sequence."""

    received = tuple(arguments)
    for argument in received:
        _require_safe_msvc_argument(argument)
    return received


def safe_msvc_compiler_arguments() -> tuple[str, ...]:
    """Return the finite request-schema vocabulary, including dash aliases."""

    return tuple(
        sorted(
            {
                *(_SAFE_MSVC_ARGUMENTS),
                *(f"-{argument[1:]}" for argument in _SAFE_MSVC_ARGUMENTS),
            }
        )
    )


@dataclass(frozen=True, slots=True)
class RenderedMsvcState:
    """One exact source/force-include pair produced from a closed state."""

    source: bytes
    force_include: bytes | None
    generated_declarations: bytes
    identifiers: tuple[str, ...]


def _integer_parameter(state: DeclarationState, name: str) -> int:
    value = state.parameter(name)
    if type(value) is not int:
        raise DiscoveryError(f"declaration parameter {name!r} is not an integer")
    return value


def _string_parameter(state: DeclarationState, name: str) -> str:
    value = state.parameter(name)
    if not isinstance(value, str):
        raise DiscoveryError(f"declaration parameter {name!r} is not a string")
    return value


def _declaration_identifiers(payloads: Sequence[bytes]) -> tuple[str, ...]:
    values = [
        match.group(1).decode("ascii", "strict")
        for payload in payloads
        for match in _DECLARED_IDENTIFIER.finditer(payload)
    ]
    if not values or len(values) != len(set(values)):
        raise DiscoveryError("generated declaration identifiers are empty or collide")
    return tuple(sorted(values))


def _append_source(source: bytes, suffix: bytes) -> bytes:
    if not suffix:
        return source
    separator = b"" if not source or source.endswith((b"\n", b"\r")) else b"\n"
    return source + separator + suffix


def _place_declarations(
    source: bytes,
    declarations: bytes,
    placement: DeclarationPlacement,
) -> tuple[bytes, bytes | None]:
    if placement is DeclarationPlacement.FORCE_INCLUDE:
        return source, declarations
    if placement is DeclarationPlacement.PREFIX:
        return declarations + source, None
    if placement is DeclarationPlacement.SUFFIX:
        return _append_source(source, declarations), None
    includes = tuple(_INCLUDE_DIRECTIVE.finditer(source))
    if not includes:
        raise DiscoveryError("after-includes placement requires an include directive")
    offset = includes[-1].end()
    return source[:offset] + declarations + source[offset:], None


def render_msvc_declaration_state(
    source: bytes,
    state: DeclarationState,
) -> RenderedMsvcState:
    """Render exactly one of the four admitted declaration-only families."""

    if not source or b"\0" in source:
        raise DiscoveryError("MSVC discovery source must be non-empty and NUL-free")
    force_include: bytes | None
    payloads: tuple[bytes, ...]
    if state.family is DeclarationFamily.DECLARATION_SHAPE:
        declarations = generate_shape(
            _integer_parameter(state, "classes"),
            _integer_parameter(state, "functions"),
        ).encode("ascii")
        rendered_source, force_include = source, declarations
        payloads = (declarations,)
    elif state.family is DeclarationFamily.PAD_SHAPE:
        declarations = generate_pad_shape(
            _integer_parameter(state, "classes"),
            _integer_parameter(state, "functions_per_class"),
        ).encode("ascii")
        rendered_source, force_include = source, declarations
        payloads = (declarations,)
    elif state.family is DeclarationFamily.FORWARD_DECLARATION_RUN:
        declarations = generate_forward_run(
            _string_parameter(state, "prefix"),
            _integer_parameter(state, "count"),
            _integer_parameter(state, "width"),
        ).encode("ascii")
        try:
            placement = DeclarationPlacement(_string_parameter(state, "placement"))
        except ValueError as exc:
            raise DiscoveryError("forward declaration placement is unsupported") from exc
        rendered_source, force_include = _place_declarations(
            source,
            declarations,
            placement,
        )
        payloads = (declarations,)
    else:
        if state.family is not DeclarationFamily.EXTERN_RUN_PAIR:
            raise DiscoveryError(f"unsupported declaration family: {state.family}")
        width = _integer_parameter(state, "width")
        header_count = _integer_parameter(state, "header_count")
        seat_count = _integer_parameter(state, "seat_count")
        if header_count == 0 and seat_count == 0:
            raise DiscoveryError("extern-run pair cannot be empty")
        header = (
            generate_extern_run(
                _string_parameter(state, "header_prefix"),
                header_count,
                width,
            ).encode("ascii")
            if header_count
            else b""
        )
        seat = (
            generate_extern_run(
                _string_parameter(state, "seat_prefix"),
                seat_count,
                width,
            ).encode("ascii")
            if seat_count
            else b""
        )
        rendered_source = _append_source(source, seat)
        force_include = header or None
        declarations = header + seat
        payloads = tuple(payload for payload in (header, seat) if payload)

    identifiers = _declaration_identifiers(payloads)
    source_identifiers = {
        item.decode("ascii", "strict") for item in _SOURCE_IDENTIFIER.findall(source)
    }
    collisions = sorted(source_identifiers.intersection(identifiers))
    if collisions:
        raise DiscoveryError(
            "generated declarations collide with source identifiers: " + ", ".join(collisions[:8])
        )
    return RenderedMsvcState(
        rendered_source,
        force_include,
        declarations,
        identifiers,
    )


class MsvcStateCompiler(Protocol):
    """Exact compiler boundary consumed by :class:`MsvcDiscoveryAdapter`."""

    @property
    def identity(self) -> str: ...

    @property
    def maximum_parallelism(self) -> int: ...

    def pinned_authority_digest(self) -> Digest: ...

    def revalidate_authority(self, expected: Digest) -> None: ...

    def compiler_receipt(self) -> DiscoveryCompilerReceipt: ...

    def compile(
        self,
        rendered: RenderedMsvcState,
        workspace: Path,
        cancellation: CancellationToken | None = None,
    ) -> DiscoveryCompileOutput: ...


@dataclass(frozen=True, slots=True)
class DirectMsvcCompiler:
    """Exact driver admitting only a small path-free MSVC codegen switch set."""

    wrapper: Path
    arguments: tuple[str, ...]
    environment: tuple[tuple[str, str], ...]
    toolchain_authority: Digest
    support_files: tuple[Path, ...] = ()
    toolchain_authority_probe: Callable[[], Digest] | None = None
    timeout_seconds: float = 120.0
    parallelism: int = 1
    _compiler_context: Digest = field(init=False, repr=False)

    def __post_init__(self) -> None:
        wrapper = Path(os.path.abspath(self.wrapper))
        if wrapper.is_symlink() or not wrapper.is_file():
            raise DiscoveryError(f"MSVC wrapper is absent or redirected: {wrapper}")
        object.__setattr__(self, "wrapper", wrapper.resolve(strict=True))
        support_files: list[Path] = []
        for raw_support in self.support_files:
            support = Path(os.path.abspath(raw_support))
            if support.is_symlink() or not support.is_file():
                raise DiscoveryError(
                    f"MSVC compiler support file is absent or redirected: {support}"
                )
            support_files.append(support.resolve(strict=True))
        if len(support_files) != len(set(support_files)):
            raise DiscoveryError("MSVC compiler support files are repeated")
        object.__setattr__(
            self,
            "support_files",
            tuple(sorted(support_files, key=os.fspath)),
        )
        if self.timeout_seconds <= 0:
            raise DiscoveryError("MSVC compiler timeout must be positive")
        if not 1 <= self.parallelism <= 64:
            raise DiscoveryError("MSVC compiler parallelism must stay in [1, 64]")
        folded_environment: set[str] = set()
        normalized_environment: list[tuple[str, str]] = []
        for key, value in self.environment:
            if not key or "=" in key or "\0" in key or "\0" in value:
                raise DiscoveryError("MSVC compiler environment is malformed")
            folded = key.casefold()
            if folded in {"cl", "_cl_"}:
                raise DiscoveryError("MSVC compiler environment may not inject CL arguments")
            if folded in folded_environment:
                raise DiscoveryError("MSVC compiler environment has duplicate keys")
            folded_environment.add(folded)
            normalized_environment.append((key, value))
        object.__setattr__(
            self,
            "environment",
            tuple(sorted(normalized_environment, key=lambda item: item[0].casefold())),
        )
        validate_msvc_compiler_arguments(self.arguments)
        object.__setattr__(self, "_compiler_context", self._current_context_digest())

    @classmethod
    def create(
        cls,
        *,
        wrapper: Path,
        arguments: Sequence[str],
        environment: Mapping[str, str],
        toolchain_authority: Digest,
        support_files: Sequence[Path] = (),
        toolchain_authority_probe: Callable[[], Digest] | None = None,
        timeout_seconds: float = 120.0,
        parallelism: int = 1,
    ) -> DirectMsvcCompiler:
        return cls(
            wrapper,
            tuple(arguments),
            tuple(environment.items()),
            toolchain_authority,
            tuple(support_files),
            toolchain_authority_probe,
            timeout_seconds,
            parallelism,
        )

    @property
    def identity(self) -> str:
        return "direct-msvc-coff-v1"

    @property
    def maximum_parallelism(self) -> int:
        return self.parallelism

    @property
    def compiler_context(self) -> Digest:
        """Pinned compiler receipt shared by every cell in this campaign."""

        return self._compiler_context

    def pinned_authority_digest(self) -> Digest:
        """Return the construction-time identity without rescanning the toolchain."""

        return self._compiler_context

    def _current_context_digest(self) -> Digest:
        return Digest.from_bytes(
            canonical_json(
                {
                    "schema_version": 1,
                    "driver": {
                        "path": os.fspath(self.wrapper),
                        "digest": Digest.from_path(self.wrapper),
                    },
                    "arguments": self.arguments,
                    "environment": self.environment,
                    "support_files": tuple(
                        {
                            "path": os.fspath(path),
                            "digest": Digest.from_path(path),
                        }
                        for path in self.support_files
                    ),
                    "toolchain": self.toolchain_authority,
                }
            )
        )

    def authority_digest(self) -> Digest:
        if self.toolchain_authority_probe is not None:
            received = self.toolchain_authority_probe()
            if received != self.toolchain_authority:
                raise DiscoveryError("MSVC toolchain authority changed during discovery")
        if self._current_context_digest() != self._compiler_context:
            raise DiscoveryError("MSVC compiler context changed during discovery")
        return self._compiler_context

    def revalidate_authority(self, expected: Digest) -> None:
        if self.authority_digest() != expected:
            raise DiscoveryError("MSVC compiler authority changed during discovery")

    def compiler_receipt(self) -> DiscoveryCompilerReceipt:
        return DiscoveryCompilerReceipt(
            identity=self.identity,
            executable=os.fspath(self.wrapper),
            arguments=self.arguments,
            toolchain_authority=self.toolchain_authority,
        )

    def compile(
        self,
        rendered: RenderedMsvcState,
        workspace: Path,
        cancellation: CancellationToken | None = None,
    ) -> DiscoveryCompileOutput:
        source = workspace / "unit.cpp"
        force_include = workspace / "declarations.h"
        output = workspace / "candidate.obj"
        pdb = workspace / "candidate.pdb"
        log = workspace / "compiler.log"
        source.write_bytes(rendered.source)
        if rendered.force_include is not None:
            force_include.write_bytes(rendered.force_include)
        arguments = list(self.arguments)
        if not any(item.casefold() in {"/c", "-c"} for item in arguments):
            arguments.append("/c")
        arguments.extend(("/Focandidate.obj", "/Fdcandidate.pdb"))
        if rendered.force_include is not None:
            arguments.append("/FIdeclarations.h")
        arguments.append("unit.cpp")
        command = CommandSpec.create(
            (os.fspath(self.wrapper), *arguments),
            cwd=workspace.resolve(strict=True),
            environment=self.environment,
            timeout_seconds=self.timeout_seconds,
            log_path=log.resolve(strict=False),
            output_limit=4 * 1024 * 1024,
        )
        with ProcessSupervisor() as supervisor:
            result = supervisor.run(command, cancellation=cancellation)
        if output.is_symlink() or not output.is_file():
            raise DiscoveryError("MSVC compiler did not produce candidate.obj")
        working_directory = os.fspath(workspace.resolve(strict=True))
        pdb_digest = Digest.from_path(pdb) if pdb.is_file() and not pdb.is_symlink() else None
        receipt = CompileReceipt(
            compiler_context=self.compiler_context,
            command=Digest.from_bytes(
                canonical_json(
                    {
                        "driver": os.fspath(self.wrapper),
                        "arguments": tuple(arguments),
                        "environment": self.environment,
                        "working_directory": working_directory,
                    }
                )
            ),
            working_directory=working_directory,
            pdb=pdb_digest,
            pdb_size=pdb.stat().st_size if pdb_digest is not None else None,
        )
        return DiscoveryCompileOutput(
            object_path=output,
            receipt=receipt,
            metadata=MappingProxyType(
                {
                    "compiler_output": cast(
                        JsonValue,
                        Digest.from_bytes(result.output).model_dump(mode="json"),
                    ),
                    "generated_declarations": cast(
                        JsonValue,
                        Digest.from_bytes(rendered.generated_declarations).model_dump(mode="json"),
                    ),
                }
            ),
        )


__all__ = [
    "DirectMsvcCompiler",
    "MsvcStateCompiler",
    "RenderedMsvcState",
    "render_msvc_declaration_state",
    "safe_msvc_compiler_arguments",
    "validate_msvc_compiler_arguments",
]


@contextmanager
def hold_wine_prefix(
    environment: Mapping[str, str],
    *,
    wineserver: str | os.PathLike[str] | None = None,
    wine: str | os.PathLike[str] | None = None,
    timeout_seconds: float = 60.0,
) -> Iterator[None]:
    """Hold one foreground wineserver for the prefix in ``environment``.

    A Wine-transported compile on a cold prefix otherwise spawns the server,
    its services, and the implicit prefix bootstrap inside the compiler's own
    process group, and the drain invariant correctly refuses the compile.
    When a ``wine`` executable can be resolved, the prefix is additionally
    initialized with ``wineboot --init`` up front, so no later command has to
    perform the bootstrap implicitly. No-op on native Windows."""

    if os.name == "nt":
        yield
        return
    executable = os.fspath(wineserver) if wineserver is not None else shutil.which("wineserver")
    if executable is None:
        raise DiscoveryError("wineserver is required to hold a Wine prefix")
    held = subprocess.Popen(
        (executable, "-f", "-p"),
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        held.wait(timeout=0.2)
    except subprocess.TimeoutExpired:
        pass
    else:
        raise DiscoveryError(f"wineserver exited during startup: {held.returncode}")
    try:
        wine_executable = (
            os.fspath(wine)
            if wine is not None
            else environment.get("WINE") or environment.get("WINELOADER") or shutil.which("wine")
        )
        if wine_executable is not None:
            boot_environment = dict(environment)
            overrides = boot_environment.get("WINEDLLOVERRIDES", "")
            if "winemenubuilder" not in overrides.casefold():
                boot_environment["WINEDLLOVERRIDES"] = ";".join(
                    item for item in (overrides, "winemenubuilder.exe=d") if item
                )
            # No pipes: the held server and its services inherit them and
            # never close their ends, which would stall the wait until the
            # timeout even after wineboot itself has finished.
            boot = subprocess.run(
                (wine_executable, "wineboot", "--init"),
                env=boot_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=timeout_seconds,
                start_new_session=True,
                check=False,
            )
            if boot.returncode != 0:
                raise DiscoveryError(f"wineboot --init failed with exit code {boot.returncode}")
        yield
    finally:
        stop = subprocess.run(
            (executable, "-k"),
            env=dict(environment),
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        del stop
        try:
            held.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            held.kill()
            held.wait()
