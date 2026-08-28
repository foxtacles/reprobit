"""Committed, closed producer graphs for high-assurance classic builds.

The graph is deliberately lower level than a build-system project.  CMake (or
another project build system) may be used to *extract* this document during a
migration, but a certifying run never executes that project-controlled build
system.  It resolves the symbolic paths below and invokes only locked producer
roles itself.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal, cast

from pydantic import Field, field_validator, model_validator

from reprobit.model import BuildTarget, Digest, Identifier, StrictModel
from reprobit.strict_json import canonical_json, strict_load

_MARKERS = ("${SOURCE}", "${BUILD}", "${TOOLCHAIN}")
_REFERENCE_KINDS = frozenset(
    {"source", "build", "toolchain", "system-library", "quarantine-archive"}
)
_WINDOWS_ABSOLUTE = re.compile(r"(?i)[a-z]:[\\/]")
_SEPARATE_PATH_OPTIONS = frozenset({"/i", "-i", "/fi", "-fi", "/fo", "-fo", "/fd", "-fd"})
_ATTACHED_PATH_OPTIONS = (
    "/libpath:",
    "-libpath:",
    "/implib:",
    "-implib:",
    "/out:",
    "-out:",
    "/pdb:",
    "-pdb:",
    "/map:",
    "-map:",
    "/def:",
    "-def:",
    "/fi",
    "-fi",
    "/fo",
    "-fo",
    "/fd",
    "-fd",
    "/i",
    "-i",
)
_PATHLIKE_SUFFIX = re.compile(
    r"(?i)\.(?:c|cc|cpp|cxx|h|hh|hpp|rc|def|obj|res|lib|exe|dll|pdb|map)$"
)
_ROLE_DIRECTORY_OPTIONS = frozenset({"/i", "-i"})
_ROLE_DIRECTORY_PREFIXES = ("/libpath:", "-libpath:")
_ROLE_INPUT_PREFIXES = ("/def:", "-def:")
_ROLE_OUTPUT_PREFIXES = (
    "/implib:",
    "-implib:",
    "/out:",
    "-out:",
    "/pdb:",
    "-pdb:",
    "/map:",
    "-map:",
    "/fo",
    "-fo",
)
_RESOURCE_LITERAL_OPTIONS = frozenset({"/nologo", "-nologo", "/r", "-r", "/v", "-v", "/x", "-x"})
_LIBRARIAN_LITERAL_OPTIONS = frozenset({"/nologo", "-nologo", "/verbose", "-verbose"})
_LINKER_LITERAL_OPTIONS = frozenset(
    {
        "/debug",
        "-debug",
        "/dll",
        "-dll",
        "/fixed",
        "-fixed",
        "/fixed:no",
        "-fixed:no",
        "/force",
        "-force",
        "/nodefaultlib",
        "-nodefaultlib",
        "/noentry",
        "-noentry",
        "/nologo",
        "-nologo",
        "/release",
        "-release",
        "/verbose",
        "-verbose",
        "/verbose:lib",
        "-verbose:lib",
    }
)
_LINKER_SCALAR_OPTIONS = (
    re.compile(r"(?i)[/-]base:(?:0x)?[0-9a-f]+"),
    re.compile(r"(?i)[/-](?:file)?align:(?:0x)?[0-9a-f]+"),
    re.compile(r"(?i)[/-](?:heap|stack):[0-9]+(?:,[0-9]+)?"),
    re.compile(r"(?i)[/-]ignore:[0-9]+(?:,[0-9]+)*"),
    re.compile(r"(?i)[/-]incremental:(?:yes|no)"),
    re.compile(r"(?i)[/-]machine:i386"),
    re.compile(r"(?i)[/-]nodefaultlib:[a-z0-9_.+@-]+(?:\.lib)?"),
    re.compile(r"(?i)[/-]opt:(?:no)?(?:ref|icf)(?:,(?:no)?(?:ref|icf))*"),
    re.compile(r"(?i)[/-]osversion:[0-9]+(?:\.[0-9]+)?"),
    re.compile(r"(?i)[/-]pdbtype:(?:con|sep)"),
    re.compile(r"(?i)[/-]subsystem:(?:windows|console|native)(?:,[0-9]+(?:\.[0-9]+)?)?"),
    re.compile(r"(?i)[/-]version:[0-9]+(?:\.[0-9]+)?"),
    re.compile(r"(?i)[/-]warn:[0-9]+"),
)
_LINKER_SYMBOL_OPTION_PREFIXES = (
    "/entry:",
    "-entry:",
    "/export:",
    "-export:",
    "/include:",
    "-include:",
)


class ProducerGraphError(ValueError):
    """Raised when a producer graph is unsafe, incomplete, or malformed."""


class ProducerRole(StrEnum):
    COMPILER = "compiler"
    RESOURCE = "resource-compiler"
    LIBRARIAN = "librarian"
    LINKER = "linker"


def _relative(value: str, *, label: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError(f"{label} must be a non-empty portable path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} must be normalized and relative")
    return value


def _validate_bound_path(value: str) -> None:
    """Require one path token to be relative or rooted at one logical seat."""

    if not value or "\\" in value or _WINDOWS_ABSOLUTE.search(value):
        raise ValueError("producer path argument is not portable")
    marker_count = sum(value.count(marker) for marker in _MARKERS)
    if marker_count:
        if marker_count != 1:
            raise ValueError("producer path argument must use exactly one logical seat")
        marker = next(marker for marker in _MARKERS if marker in value)
        prefix, marker_text, suffix = value.partition(marker)
        del prefix, marker_text
        if suffix and not suffix.startswith("/"):
            raise ValueError("logical-seat marker must end at a path boundary")
        if suffix:
            _relative(suffix[1:], label="logical-seat argument suffix")
        return
    _relative(value, label="producer path argument")


def _validate_argument_paths(values: tuple[str, ...]) -> None:
    expect_path_after: str | None = None
    for value in values:
        if expect_path_after is not None:
            _validate_bound_path(value)
            expect_path_after = None
            continue
        folded = value.casefold()
        if folded in _SEPARATE_PATH_OPTIONS:
            expect_path_after = value
            continue
        matched = False
        for prefix in _ATTACHED_PATH_OPTIONS:
            if not folded.startswith(prefix):
                continue
            payload = value[len(prefix) :]
            if not payload:
                raise ValueError(f"producer path option {value!r} has no path")
            _validate_bound_path(payload)
            matched = True
            break
        if matched:
            continue
        if any(marker in value for marker in _MARKERS):
            _validate_bound_path(value)
            continue
        portable = value.replace("\\", "/")
        if _PATHLIKE_SUFFIX.search(portable) or portable.startswith("//"):
            _validate_bound_path(value)
        elif ".." in portable.split("/"):
            raise ValueError("producer argument contains parent-directory traversal")
    if expect_path_after is not None:
        raise ValueError(f"producer path option {expect_path_after!r} has no path")


def _reference(value: str, *, output: bool = False) -> str:
    if "\x00" in value or "/" not in value:
        raise ValueError("producer-graph reference is malformed")
    kind, relative = value.split("/", 1)
    if kind not in _REFERENCE_KINDS:
        raise ValueError(f"unknown producer-graph reference kind: {kind!r}")
    if output and kind != "build":
        raise ValueError("producer outputs must remain beneath the build seat")
    if kind == "system-library":
        if "/" in relative or not re.fullmatch(r"(?i)[a-z0-9_.+@-]+\.lib", relative):
            raise ValueError("system-library reference must name one bare .lib file")
    elif kind == "quarantine-archive":
        _relative(relative, label="quarantine archive reference")
        if PurePosixPath(relative).suffix.casefold() != ".lib":
            raise ValueError("quarantine archive reference must name one .lib file")
    else:
        _relative(relative, label="producer-graph reference")
    return value


def _argument_reference(
    value: str,
    *,
    output: bool = False,
    bare_library: bool = False,
    source_library_is_quarantine: bool = False,
) -> str:
    """Translate one already-validated argv path into its graph edge.

    Relative output-option payloads are build-seat paths.  A bare library
    input is a locked system-library identity; every other input file must
    carry an explicit logical-seat marker so a project file cannot be mistaken
    for a toolchain library.
    """

    marker = next((item for item in _MARKERS if value.startswith(item)), None)
    if marker is not None:
        suffix = value[len(marker) :]
        if not suffix.startswith("/"):
            raise ValueError("logical-seat file argument lacks a relative suffix")
        kind = {
            "${SOURCE}": "source",
            "${BUILD}": "build",
            "${TOOLCHAIN}": "toolchain",
        }[marker]
        if (
            kind == "source"
            and source_library_is_quarantine
            and PurePosixPath(suffix).suffix.casefold() == ".lib"
        ):
            kind = "quarantine-archive"
        return _reference(f"{kind}/{suffix[1:]}", output=output)
    if any(item in value for item in _MARKERS):
        raise ValueError("logical-seat marker must begin a file argument")
    if output:
        relative = _relative(value, label="producer output argument")
        return _reference(f"build/{relative}", output=True)
    if bare_library and re.fullmatch(r"(?i)[a-z0-9_.+@-]+\.lib", value):
        return _reference(f"system-library/{value}")
    raise ValueError("producer input file argument must name a logical seat")


def _role_argument_edges(
    node: ProducerNode,
) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Return role-significant file inputs and explicit output paths.

    Compiler argv has a richer, profile-specific grammar and is closed by the
    classic runtime against its parsed source/Fo/Fd records.  The other classic
    producer roles have a small grammar that can be closed here without a
    toolchain adapter: RC consumes one ``.rc`` and emits ``/fo``; LIB consumes
    object files and emits ``/out``; LINK consumes object/resource/library/DEF
    files and emits ``/out`` plus optional secondary paths.
    """

    if node.role is ProducerRole.COMPILER:
        return frozenset(), frozenset(), frozenset()

    inputs: set[str] = set()
    required_outputs: set[str] = set()
    secondary_outputs: set[str] = set()
    expect_directory = False
    expect_output = False
    for value in node.arguments:
        folded = value.casefold()
        if expect_directory:
            expect_directory = False
            continue
        if expect_output:
            required_outputs.add(_argument_reference(value, output=True).casefold())
            expect_output = False
            continue
        if folded in _ROLE_DIRECTORY_OPTIONS:
            expect_directory = True
            continue
        if folded in {"/fo", "-fo"}:
            expect_output = True
            continue
        if any(folded.startswith(prefix) for prefix in _ROLE_DIRECTORY_PREFIXES):
            continue
        if (folded.startswith("/i") or folded.startswith("-i")) and not folded.startswith(
            ("/implib:", "-implib:", "/incremental")
        ):
            continue
        input_prefix = next(
            (prefix for prefix in _ROLE_INPUT_PREFIXES if folded.startswith(prefix)),
            None,
        )
        if input_prefix is not None:
            inputs.add(_argument_reference(value[len(input_prefix) :]).casefold())
            continue
        output_prefix = next(
            (prefix for prefix in _ROLE_OUTPUT_PREFIXES if folded.startswith(prefix)),
            None,
        )
        if output_prefix is not None:
            destination = _argument_reference(value[len(output_prefix) :], output=True).casefold()
            if output_prefix in {"/out:", "-out:", "/fo", "-fo"}:
                required_outputs.add(destination)
            else:
                secondary_outputs.add(destination)
            continue
        portable = value.replace("\\", "/")
        if not (_PATHLIKE_SUFFIX.search(portable) or any(marker in value for marker in _MARKERS)):
            continue
        suffix = PurePosixPath(portable).suffix.casefold()
        admitted = {
            ProducerRole.RESOURCE: {".rc"},
            ProducerRole.LIBRARIAN: {".obj"},
            ProducerRole.LINKER: {".def", ".obj", ".res", ".lib"},
        }[node.role]
        if suffix not in admitted:
            raise ValueError(
                f"{node.role.value} has an unsupported positional file argument: {value!r}"
            )
        inputs.add(
            _argument_reference(
                value,
                bare_library=node.role is ProducerRole.LINKER and suffix == ".lib",
                source_library_is_quarantine=(
                    node.role is ProducerRole.LINKER and suffix == ".lib"
                ),
            ).casefold()
        )
    if expect_directory or expect_output:
        raise ValueError(f"{node.role.value} has an incomplete path option")
    return (
        frozenset(inputs),
        frozenset(required_outputs),
        frozenset(secondary_outputs),
    )


def _validate_noncompiler_option_grammar(node: ProducerNode) -> None:
    """Reject every role option that is not explicitly modeled as safe or seated."""

    if node.role is ProducerRole.COMPILER:
        return
    expect_value = False
    for value in node.arguments:
        folded = value.casefold()
        if expect_value:
            expect_value = False
            continue
        if node.role is ProducerRole.RESOURCE:
            if folded in {"/i", "-i", "/fo", "-fo"}:
                expect_value = True
                continue
            if folded in _RESOURCE_LITERAL_OPTIONS:
                continue
            if re.fullmatch(r"(?i)[/-]d[A-Za-z_][A-Za-z0-9_]*(?:=.*)?", value):
                continue
            if re.fullmatch(r"(?i)[/-][lc](?:0x)?[0-9a-f]+", value):
                continue
            if (folded.startswith(("/i", "-i", "/fo", "-fo"))) and len(value) > 2:
                continue
            if not value.startswith(("/", "-")) and (
                PurePosixPath(value.replace("\\", "/")).suffix.casefold() == ".rc"
            ):
                continue
        elif node.role is ProducerRole.LIBRARIAN:
            if folded in _LIBRARIAN_LITERAL_OPTIONS:
                continue
            if folded.startswith(("/out:", "-out:")):
                continue
            if re.fullmatch(r"(?i)[/-]machine:i386", value):
                continue
            if not value.startswith(("/", "-")) and (
                PurePosixPath(value.replace("\\", "/")).suffix.casefold() == ".obj"
            ):
                continue
        else:
            if folded in _LINKER_LITERAL_OPTIONS:
                continue
            if folded.startswith(
                (
                    "/def:",
                    "-def:",
                    "/implib:",
                    "-implib:",
                    "/libpath:",
                    "-libpath:",
                    "/map:",
                    "-map:",
                    "/out:",
                    "-out:",
                    "/pdb:",
                    "-pdb:",
                )
            ):
                continue
            if any(pattern.fullmatch(value) for pattern in _LINKER_SCALAR_OPTIONS):
                continue
            symbol_prefix = next(
                (prefix for prefix in _LINKER_SYMBOL_OPTION_PREFIXES if folded.startswith(prefix)),
                None,
            )
            if symbol_prefix is not None:
                symbol = value[len(symbol_prefix) :]
                if symbol and not any(
                    marker in symbol for marker in ("/", "\\", "\x00", "${")
                ):
                    continue
            if not value.startswith(("/", "-")) and (
                PurePosixPath(value.replace("\\", "/")).suffix.casefold()
                in {".def", ".lib", ".obj", ".res"}
            ):
                continue
        raise ValueError(f"{node.role.value} has an unsupported or unmodeled argument: {value!r}")
    if expect_value:
        raise ValueError(f"{node.role.value} has an incomplete path option")


def graph_reference(kind: str, relative: str) -> str:
    """Return a canonical graph reference."""

    return _reference(f"{kind}/{relative}")


def linker_library_sequence(node: ProducerNode) -> tuple[str, ...]:
    """Return the linker's ordered positional archive references, including repeats."""

    if node.role is not ProducerRole.LINKER:
        raise ProducerGraphError("library sequence is defined only for linker nodes")
    references: list[str] = []
    for value in node.arguments:
        folded = value.casefold()
        if folded.startswith(
            (
                "/libpath:",
                "-libpath:",
                "/implib:",
                "-implib:",
            )
        ):
            continue
        portable = value.replace("\\", "/")
        if PurePosixPath(portable).suffix.casefold() != ".lib":
            continue
        references.append(
            _argument_reference(
                value,
                bare_library=True,
                source_library_is_quarantine=True,
            )
        )
    return tuple(references)


class ProducerNode(StrictModel):
    """One direct invocation of a locked producer role.

    ``arguments`` excludes the executable.  The runtime chooses that executable
    from the toolchain lock, so a committed project cannot replace a producer.
    Symbolic roots are expanded without a shell immediately before execution.
    """

    id: Identifier
    role: ProducerRole
    owner: BuildTarget
    target_id: Identifier | None = None
    arguments: Annotated[tuple[str, ...], Field(min_length=1)]
    inputs: tuple[str, ...] = ()
    directive_inputs: tuple[str, ...] = ()
    outputs: Annotated[tuple[str, ...], Field(min_length=1)]
    depends_on: tuple[Identifier, ...] = ()
    timeout_seconds: Annotated[int, Field(ge=1, le=86_400)] = 900

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if (
                not value
                or "\x00" in value
                or "\n" in value
                or "\r" in value
                or "`" in value
                or "$(" in value
            ):
                raise ValueError("producer arguments must be literal argv entries")
            if value.startswith("@"):
                raise ValueError("response files must be expanded in the committed graph")
            residual = value
            for marker in _MARKERS:
                residual = residual.replace(marker, "")
            if "${" in residual or "}" in residual:
                raise ValueError("producer argument contains an unknown placeholder")
            if _WINDOWS_ABSOLUTE.search(value):
                raise ValueError("producer argument contains an unseated Windows path")
        _validate_argument_paths(values)
        return values

    @field_validator("inputs")
    @classmethod
    def validate_inputs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        canonical = tuple(_reference(value) for value in values)
        if canonical != tuple(sorted(set(canonical), key=str.casefold)):
            raise ValueError("producer inputs must be unique and canonically ordered")
        return canonical

    @field_validator("directive_inputs")
    @classmethod
    def validate_directive_inputs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        canonical = tuple(_reference(value) for value in values)
        if any(not value.startswith("system-library/") for value in canonical):
            raise ValueError(
                "directive inputs must be bare locked system-library references"
            )
        if (
            len({value.casefold() for value in canonical}) != len(canonical)
            or canonical != tuple(sorted(canonical, key=str.casefold))
        ):
            raise ValueError(
                "directive inputs must be unique and canonically ordered"
            )
        return canonical

    @field_validator("outputs")
    @classmethod
    def validate_outputs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        canonical = tuple(_reference(value, output=True) for value in values)
        if canonical != tuple(sorted(set(canonical), key=str.casefold)):
            raise ValueError("producer outputs must be unique and canonically ordered")
        return canonical

    @field_validator("depends_on")
    @classmethod
    def validate_dependencies(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(set(values), key=str.casefold)):
            raise ValueError("producer dependencies must be unique and canonically ordered")
        return values

    @model_validator(mode="after")
    def validate_role_shape(self) -> ProducerNode:
        if self.role is not ProducerRole.LINKER and self.target_id is not None:
            raise ValueError("only a terminal linker node may name a project target")
        if self.role is ProducerRole.LINKER and self.target_id is None:
            raise ValueError("terminal linker nodes must name a project target")
        if self.role is not ProducerRole.LINKER and self.directive_inputs:
            raise ValueError("only terminal linkers may declare directive inputs")
        if {value.casefold() for value in self.inputs}.intersection(
            value.casefold() for value in self.directive_inputs
        ):
            raise ValueError("directive inputs must be distinct from argv inputs")
        if self.role is not ProducerRole.COMPILER:
            _validate_noncompiler_option_grammar(self)
            argv_inputs, required_outputs, secondary_outputs = _role_argument_edges(self)
            declared_inputs = frozenset(value.casefold() for value in self.inputs)
            declared_outputs = frozenset(value.casefold() for value in self.outputs)
            if argv_inputs != declared_inputs:
                missing = sorted(argv_inputs - declared_inputs)
                extra = sorted(declared_inputs - argv_inputs)
                raise ValueError(
                    f"producer argv/input edges differ: missing={missing}, extra={extra}"
                )
            if self.role in {ProducerRole.RESOURCE, ProducerRole.LIBRARIAN}:
                if required_outputs != declared_outputs or secondary_outputs:
                    raise ValueError("producer argv/output edges differ")
            else:
                if len(required_outputs) != 1 or not required_outputs <= declared_outputs:
                    raise ValueError("linker /out edge differs from declared outputs")
                unexplained = {
                    value
                    for value in declared_outputs - required_outputs - secondary_outputs
                    if PurePosixPath(value).suffix.casefold() != ".exp"
                }
                if unexplained:
                    raise ValueError(f"linker outputs lack argv paths: {sorted(unexplained)}")
            for reference in self.inputs:
                kind, relative = reference.split("/", 1)
                suffix = PurePosixPath(relative).suffix.casefold()
                if self.role is ProducerRole.RESOURCE:
                    if kind != "source" or suffix != ".rc":
                        raise ValueError("resource inputs must be manifest source .rc files")
                elif self.role is ProducerRole.LIBRARIAN:
                    if kind != "build" or suffix != ".obj":
                        raise ValueError("librarian inputs must be current-run build objects")
                elif suffix in {".obj", ".res"}:
                    if kind != "build":
                        raise ValueError(
                            "linker object/resource inputs require current-run ancestry"
                        )
                elif suffix == ".lib":
                    if kind not in {
                        "build",
                        "system-library",
                        "quarantine-archive",
                    }:
                        raise ValueError(
                            "linker archive input lacks producer or quarantine ancestry"
                        )
                elif suffix == ".def":
                    if kind != "source":
                        raise ValueError("linker DEF inputs must be manifest source files")
                else:
                    raise ValueError(f"linker input has an unsupported file kind: {reference!r}")
        return self


class ProducerGraphDocument(StrictModel):
    """Portable authority for every byte-producing child process."""

    schema_version: Literal[1, 2]
    source_manifest_digest: Digest | None = None
    source_topology_digest: Digest | None = None
    toolchain_lock_digest: Digest
    path_profile_id: Identifier
    extractor: Literal["cmake-unix-makefiles-v1"]
    nodes: Annotated[tuple[ProducerNode, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_graph(self) -> ProducerGraphDocument:
        if self.schema_version == 1:
            if self.source_manifest_digest is None or self.source_topology_digest is not None:
                raise ValueError(
                    "producer graph v1 requires only a source-manifest digest"
                )
        elif self.source_topology_digest is None or self.source_manifest_digest is not None:
            raise ValueError(
                "producer graph v2 requires only a source-topology digest"
            )
        ids = [node.id for node in self.nodes]
        if ids != sorted(ids, key=str.casefold) or len(ids) != len(set(ids)):
            raise ValueError("producer nodes must be unique and canonically ordered")
        by_id = {node.id: node for node in self.nodes}
        output_owner: dict[str, str] = {}
        for node in self.nodes:
            unknown = set(node.depends_on) - set(by_id)
            if unknown or node.id in node.depends_on:
                raise ValueError(
                    f"producer {node.id!r} has invalid dependencies: {sorted(unknown)}"
                )
            for output in node.outputs:
                previous = output_owner.setdefault(output.casefold(), node.id)
                if previous != node.id:
                    raise ValueError(
                        f"producer output {output!r} is owned by both {previous!r} and {node.id!r}"
                    )
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> None:
            if node_id in visited:
                return
            if node_id in visiting:
                raise ValueError(f"producer dependency cycle includes {node_id!r}")
            visiting.add(node_id)
            for parent in by_id[node_id].depends_on:
                visit(parent)
            visiting.remove(node_id)
            visited.add(node_id)

        for node_id in ids:
            visit(node_id)
        for node in self.nodes:
            declared = set(node.depends_on)
            for input_ref in node.inputs:
                if not input_ref.startswith("build/"):
                    continue
                owner = output_owner.get(input_ref.casefold())
                if owner is None:
                    raise ValueError(
                        f"producer {node.id!r} consumes unproduced build input {input_ref!r}"
                    )
                if owner not in declared:
                    raise ValueError(
                        f"producer {node.id!r} consumes {input_ref!r} without a direct "
                        f"dependency on {owner!r}"
                    )
        targets = [node.target_id for node in self.nodes if node.target_id is not None]
        if len(targets) != len(set(targets)):
            raise ValueError("producer graph repeats a terminal project target")
        return self


def producer_graph_digest(graph: ProducerGraphDocument) -> Digest:
    return Digest.from_bytes(canonical_json(graph))


def source_topology_digest(paths: Iterable[str]) -> Digest:
    """Bind the canonical source path set without coupling commands to contents.

    Producer argv and dependency topology do not change merely because an
    already-admitted source or header changes bytes.  Graph v2 therefore binds
    this path-set receipt while the source manifest and build plan continue to
    bind current contents independently.
    """

    canonical = tuple(
        sorted(
            (_relative(path, label="source path") for path in paths),
            key=str.casefold,
        )
    )
    folded = [path.casefold() for path in canonical]
    if len(folded) != len(set(folded)):
        raise ProducerGraphError("source topology contains colliding paths")
    return Digest.from_bytes(
        canonical_json(
            {
                "schema_version": 1,
                "paths": canonical,
            }
        )
    )


def producer_graph_accepts_source(
    graph: ProducerGraphDocument,
    *,
    manifest_digest: Digest,
    paths: Iterable[str],
) -> bool:
    """Return whether current source authority satisfies a v1 or v2 graph."""

    if graph.schema_version == 1:
        return graph.source_manifest_digest == manifest_digest
    return graph.source_topology_digest == source_topology_digest(paths)


def toolchain_document_digest(document: StrictModel) -> Digest:
    return Digest.from_bytes(canonical_json(document.model_dump(mode="json")))


def materialize_argument(
    value: str,
    *,
    source_root: str,
    build_root: str,
    toolchain_root: str,
) -> str:
    """Expand a reviewed graph token into one literal producer argument."""

    roots = {
        "${SOURCE}": source_root.rstrip("\\/"),
        "${BUILD}": build_root.rstrip("\\/"),
        "${TOOLCHAIN}": toolchain_root.rstrip("\\/"),
    }
    result = value
    for marker, root in roots.items():
        result = result.replace(marker, root)
    if "${" in result:
        raise ProducerGraphError(f"unresolved producer argument: {value!r}")
    return result


def materialize_reference(
    value: str,
    *,
    source_root: Path,
    build_root: Path,
    toolchain_root: Path,
) -> Path | None:
    """Resolve a graph file reference; bare locked system libraries return None."""

    _reference(value)
    kind, relative = value.split("/", 1)
    if kind == "system-library":
        return None
    root = {
        "source": source_root,
        "build": build_root,
        "toolchain": toolchain_root,
        "quarantine-archive": source_root,
    }[kind]
    path = root.joinpath(*PurePosixPath(relative).parts).resolve(strict=False)
    try:
        path.relative_to(root.resolve(strict=False))
    except ValueError as exc:  # Defensive; _reference already rejects traversal.
        raise ProducerGraphError(f"graph reference escapes {kind} seat: {value!r}") from exc
    return path


def _replace_root(value: str, root: Path, marker: str) -> str:
    native = os.fspath(root.resolve(strict=True))
    candidates = (native, native.replace("\\", "/"))
    result = value
    for candidate in sorted(set(candidates), key=len, reverse=True):
        result = result.replace(candidate, marker)
    return result


def _normalize_argument(
    value: str,
    *,
    source_root: Path,
    build_root: Path,
    toolchain_root: Path,
    produced_relatives: frozenset[str],
) -> str:
    result = _replace_root(value, source_root, "${SOURCE}")
    result = _replace_root(result, build_root, "${BUILD}")
    result = _replace_root(result, toolchain_root, "${TOOLCHAIN}")
    folded = result.replace("\\", "/").casefold()
    if folded in produced_relatives:
        result = "${BUILD}/" + result.replace("\\", "/")
    for prefix in ("/fo", "/fd", "/out:", "/implib:", "/pdb:", "/map:"):
        if folded.startswith(prefix):
            raw = result[len(prefix) :]
            raw_folded = raw.replace("\\", "/").casefold()
            if raw_folded in produced_relatives:
                result = result[: len(prefix)] + "${BUILD}/" + raw.replace("\\", "/")
            break
    return result


def _path_reference(
    value: str,
    *,
    source_root: Path,
    build_root: Path,
    toolchain_root: Path,
) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = build_root / path
    resolved = path.resolve(strict=False)
    for kind, root in (
        ("source", source_root),
        ("build", build_root),
        ("toolchain", toolchain_root),
    ):
        try:
            relative = resolved.relative_to(root.resolve(strict=True)).as_posix()
        except ValueError:
            continue
        return graph_reference(kind, relative)
    raise ProducerGraphError(f"producer path is outside all logical seats: {value!r}")


def _attached_value(arguments: Sequence[str], prefixes: Sequence[str]) -> str | None:
    for index, argument in enumerate(arguments):
        folded = argument.casefold()
        for prefix in prefixes:
            if folded == prefix.casefold() and index + 1 < len(arguments):
                return arguments[index + 1]
            if folded.startswith(prefix.casefold()) and len(argument) > len(prefix):
                return argument[len(prefix) :]
    return None


def _split_command_line(value: str) -> tuple[str, ...]:
    """Split migration-time command text without eating native path separators."""

    if os.name != "nt":
        return tuple(shlex.split(value, posix=True))

    # CMake's Windows command strings use the Microsoft C runtime rules, not
    # POSIX shell escaping.  In particular, runs of backslashes are special
    # only when they immediately precede a double quote.
    arguments: list[str] = []
    offset = 0
    while offset < len(value):
        while offset < len(value) and value[offset].isspace():
            offset += 1
        if offset == len(value):
            break
        argument: list[str] = []
        quoted = False
        while offset < len(value) and (quoted or not value[offset].isspace()):
            if value[offset] == "\\":
                start = offset
                while offset < len(value) and value[offset] == "\\":
                    offset += 1
                backslashes = offset - start
                if offset < len(value) and value[offset] == '"':
                    argument.extend("\\" * (backslashes // 2))
                    if backslashes % 2:
                        argument.append('"')
                        offset += 1
                    elif quoted and offset + 1 < len(value) and value[offset + 1] == '"':
                        argument.append('"')
                        offset += 2
                    else:
                        quoted = not quoted
                        offset += 1
                else:
                    argument.extend("\\" * backslashes)
                continue
            if value[offset] == '"':
                if quoted and offset + 1 < len(value) and value[offset + 1] == '"':
                    argument.append('"')
                    offset += 2
                else:
                    quoted = not quoted
                    offset += 1
                continue
            argument.append(value[offset])
            offset += 1
        arguments.append("".join(argument))
    return tuple(arguments)


def _expand_response(arguments: Iterable[str], *, build_root: Path) -> tuple[str, ...]:
    expanded: list[str] = []
    for argument in arguments:
        if not argument.startswith("@"):
            expanded.append(argument)
            continue
        response = Path(argument[1:])
        if not response.is_absolute():
            response = build_root / response
        try:
            response.resolve(strict=True).relative_to(build_root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise ProducerGraphError(f"response file escapes configured build: {argument}") from exc
        expanded.extend(_split_command_line(response.read_text(encoding="utf-8")))
    return tuple(expanded)


def _read_flags(path: Path, prefix: str) -> tuple[str, ...]:
    values: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix + " ="):
            values.extend(_split_command_line(line.split("=", 1)[1].strip()))
    return tuple(values)


def _resource_commands(build_root: Path) -> tuple[tuple[str, tuple[str, ...]], ...]:
    result: list[tuple[str, tuple[str, ...]]] = []
    for makefile in sorted((build_root / "CMakeFiles").glob("*.dir/build.make")):
        owner = makefile.parent.name.removesuffix(".dir")
        flags = makefile.parent / "flags.make"
        variables: dict[str, tuple[str, ...]] | None = None
        for raw_line in makefile.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("@", "#")):
                continue
            program = line.split(maxsplit=1)[0]
            if Path(program).name.casefold() not in {"rc", "rc.exe"}:
                continue
            if not flags.is_file():
                raise ProducerGraphError(f"resource target {owner!r} has no flags.make")
            if variables is None:
                variables = {
                    "$(RC_DEFINES)": _read_flags(flags, "RC_DEFINES"),
                    "$(RC_INCLUDES)": _read_flags(flags, "RC_INCLUDES"),
                    "$(RC_FLAGS)": _read_flags(flags, "RC_FLAGS"),
                }
            tokens = _split_command_line(line)
            expanded: list[str] = []
            for token in tokens[1:]:
                expanded.extend(variables.get(token, (token,)))
            result.append((owner, tuple(expanded)))
    return tuple(result)


def extract_cmake_unix_makefiles_graph(
    *,
    configured_build_root: Path,
    effective_source_root: Path,
    toolchain_root: Path,
    source_topology_digest_value: Digest,
    toolchain_lock_digest: Digest,
    path_profile_id: str,
    target_outputs: Mapping[str, str],
    directive_inputs: Mapping[str, Sequence[str]] | None = None,
) -> ProducerGraphDocument:
    """Extract a reviewable graph from one migration-time CMake configuration.

    This function is intentionally not called by certification.  Its output is
    committed, reviewed, and reloaded as authority on later runs.
    """

    build_root = configured_build_root.resolve(strict=True)
    source_root = effective_source_root.resolve(strict=True)
    toolchain = toolchain_root.resolve(strict=True)
    database_path = build_root / "compile_commands.json"
    raw_database = strict_load(database_path)
    if not isinstance(raw_database, list):
        raise ProducerGraphError("compile_commands.json must be an array")
    normalized_directive_inputs: dict[str, tuple[str, ...]] = {}
    for target_id, references in (directive_inputs or {}).items():
        if target_id not in target_outputs:
            raise ProducerGraphError(
                f"directive inputs name unknown target {target_id!r}"
            )
        canonical = tuple(_reference(value) for value in references)
        if any(not value.startswith("system-library/") for value in canonical):
            raise ProducerGraphError(
                "directive inputs must be system-library references"
            )
        if (
            len({value.casefold() for value in canonical}) != len(canonical)
            or canonical != tuple(sorted(canonical, key=str.casefold))
        ):
            raise ProducerGraphError(
                f"directive inputs for {target_id!r} are not canonical and unique"
            )
        normalized_directive_inputs[target_id] = canonical

    raw_nodes: list[dict[str, object]] = []
    produced_paths: set[str] = set()
    for index, database_item in enumerate(raw_database):
        if not isinstance(database_item, dict) or not isinstance(database_item.get("command"), str):
            raise ProducerGraphError(f"compile record {index} lacks one literal command")
        directory = Path(cast(str, database_item.get("directory"))).resolve(strict=True)
        if directory != build_root:
            raise ProducerGraphError("compile record uses an unexpected working directory")
        arguments = _split_command_line(cast(str, database_item["command"]))
        if not arguments:
            raise ProducerGraphError("compile command is empty")
        try:
            Path(arguments[0]).resolve(strict=True).relative_to(toolchain)
        except (OSError, ValueError) as exc:
            raise ProducerGraphError("compile command does not use the selected toolchain") from exc
        output = _attached_value(arguments[1:], ("/Fo", "-Fo"))
        pdb = _attached_value(arguments[1:], ("/Fd", "-Fd"))
        source = cast(str, database_item.get("file"))
        if output is None or pdb is None or not source:
            raise ProducerGraphError("compile command omits source, object, or PDB")
        output_ref = _path_reference(
            output, source_root=source_root, build_root=build_root, toolchain_root=toolchain
        )
        pdb_ref = _path_reference(
            pdb, source_root=source_root, build_root=build_root, toolchain_root=toolchain
        )
        source_ref = _path_reference(
            source, source_root=source_root, build_root=build_root, toolchain_root=toolchain
        )
        owner_match = re.match(r"(?i)^build/CMakeFiles/([^/]+)\.dir/", output_ref)
        if owner_match is None:
            raise ProducerGraphError(f"compile output has no CMake target owner: {output_ref}")
        produced_paths.update(ref.removeprefix("build/") for ref in (output_ref, pdb_ref))
        raw_nodes.append(
            {
                "role": ProducerRole.COMPILER,
                "owner": owner_match.group(1),
                "arguments": arguments[1:],
                "inputs": (source_ref,),
                "outputs": (output_ref, pdb_ref),
            }
        )

    for owner, arguments in _resource_commands(build_root):
        output = _attached_value(arguments, ("/fo", "-fo"))
        if output is None or not arguments:
            raise ProducerGraphError("resource command omits its output")
        source = arguments[-1]
        output_ref = _path_reference(
            output, source_root=source_root, build_root=build_root, toolchain_root=toolchain
        )
        source_ref = _path_reference(
            source, source_root=source_root, build_root=build_root, toolchain_root=toolchain
        )
        produced_paths.add(output_ref.removeprefix("build/"))
        raw_nodes.append(
            {
                "role": ProducerRole.RESOURCE,
                "owner": owner,
                "arguments": arguments,
                "inputs": (source_ref,),
                "outputs": (output_ref,),
            }
        )

    link_records: list[dict[str, object]] = []
    for link_file in sorted((build_root / "CMakeFiles").glob("*.dir/link.txt")):
        owner = link_file.parent.name.removesuffix(".dir")
        command = link_file.read_text(encoding="utf-8").strip()
        arguments = _split_command_line(command)
        if not arguments:
            raise ProducerGraphError(f"empty link command for {owner!r}")
        try:
            Path(arguments[0]).resolve(strict=True).relative_to(toolchain)
        except (OSError, ValueError) as exc:
            raise ProducerGraphError(f"link command for {owner!r} uses another toolchain") from exc
        expanded = _expand_response(arguments[1:], build_root=build_root)
        output = _attached_value(expanded, ("/out:", "-out:"))
        if output is None:
            raise ProducerGraphError(f"link command for {owner!r} omits /out")
        executable = Path(arguments[0]).name.casefold()
        role = ProducerRole.LIBRARIAN if executable in {"lib", "lib.exe"} else ProducerRole.LINKER
        output_refs = [
            _path_reference(
                output,
                source_root=source_root,
                build_root=build_root,
                toolchain_root=toolchain,
            )
        ]
        if role is ProducerRole.LINKER:
            switches = {item.casefold() for item in expanded}
            is_dll = bool(switches & {"/dll", "-dll"})
            implementation_library = _attached_value(expanded, ("/implib:", "-implib:"))
            if is_dll:
                if implementation_library is None:
                    raise ProducerGraphError(f"DLL link command for {owner!r} omits /implib")
                output_refs.append(
                    _path_reference(
                        implementation_library,
                        source_root=source_root,
                        build_root=build_root,
                        toolchain_root=toolchain,
                    )
                )
                export_file = os.fspath(Path(implementation_library).with_suffix(".exp"))
                output_refs.append(
                    _path_reference(
                        export_file,
                        source_root=source_root,
                        build_root=build_root,
                        toolchain_root=toolchain,
                    )
                )
            has_debug = any(
                item.casefold() in {"/debug", "-debug"}
                or item.casefold().startswith(("/debug:", "-debug:"))
                for item in expanded
            )
            if has_debug:
                pdb = _attached_value(expanded, ("/pdb:", "-pdb:"))
                if pdb is None:
                    raise ProducerGraphError(f"debug link command for {owner!r} omits /pdb")
                output_refs.append(
                    _path_reference(
                        pdb,
                        source_root=source_root,
                        build_root=build_root,
                        toolchain_root=toolchain,
                    )
                )
        produced_paths.update(ref.removeprefix("build/") for ref in output_refs)
        link_records.append(
            {
                "role": role,
                "owner": owner,
                "arguments": expanded,
                "outputs": tuple(output_refs),
            }
        )

    produced_relatives = frozenset(path.casefold() for path in produced_paths)
    raw_nodes.extend(link_records)
    normalized_nodes: list[dict[str, object]] = []
    for raw_node in raw_nodes:
        arguments = tuple(
            _normalize_argument(
                value,
                source_root=source_root,
                build_root=build_root,
                toolchain_root=toolchain,
                produced_relatives=produced_relatives,
            )
            for value in cast(tuple[str, ...], raw_node["arguments"])
        )
        explicit_inputs = set(cast(tuple[str, ...], raw_node.get("inputs", ())))
        for argument in arguments:
            plain = argument
            for prefix in ("/DEF:", "-DEF:"):
                if plain.casefold().startswith(prefix.casefold()):
                    plain = plain[len(prefix) :]
                    break
            if plain.startswith("${SOURCE}/"):
                relative = plain.removeprefix("${SOURCE}/")
                path = source_root.joinpath(*PurePosixPath(relative).parts)
                if path.is_file():
                    kind = (
                        "quarantine-archive"
                        if (
                            raw_node["role"] is ProducerRole.LINKER
                            and path.suffix.casefold() == ".lib"
                        )
                        else "source"
                    )
                    explicit_inputs.add(graph_reference(kind, relative))
            elif plain.startswith("${BUILD}/"):
                explicit_inputs.add(graph_reference("build", plain.removeprefix("${BUILD}/")))
            elif re.fullmatch(r"(?i)[a-z0-9_.+@-]+\.lib", plain):
                explicit_inputs.add(graph_reference("system-library", plain))
        explicit_inputs.difference_update(cast(tuple[str, ...], raw_node["outputs"]))
        normalized_nodes.append(
            {
                **raw_node,
                "arguments": arguments,
                "inputs": tuple(sorted(explicit_inputs, key=str.casefold)),
                "outputs": tuple(
                    sorted(cast(tuple[str, ...], raw_node["outputs"]), key=str.casefold)
                ),
            }
        )

    output_owner = {
        output.casefold(): str(normalized["owner"]) + ":" + str(index)
        for index, normalized in enumerate(normalized_nodes)
        for output in cast(tuple[str, ...], normalized["outputs"])
    }
    node_ids = [
        f"{cast(ProducerRole, normalized['role']).value}."
        f"{cast(str, normalized['owner'])}.{index:04d}"
        for index, normalized in enumerate(normalized_nodes)
    ]
    temporary_to_final = {
        f"{cast(str, normalized['owner'])}:{index}": node_ids[index]
        for index, normalized in enumerate(normalized_nodes)
    }
    nodes: list[ProducerNode] = []
    final_by_output = {
        graph_reference("build", relative): target_id
        for target_id, relative in target_outputs.items()
    }
    for index, normalized in enumerate(normalized_nodes):
        role = cast(ProducerRole, normalized["role"])
        owner = cast(str, normalized["owner"])
        node_outputs = cast(tuple[str, ...], normalized["outputs"])
        target_ids = {final_by_output[item] for item in node_outputs if item in final_by_output}
        if len(target_ids) > 1 or (target_ids and role is not ProducerRole.LINKER):
            raise ProducerGraphError("terminal target output has an invalid producer role")
        node_id = node_ids[index]
        dependencies = {
            temporary_to_final[output_owner[input_ref.casefold()]]
            for input_ref in cast(tuple[str, ...], normalized["inputs"])
            if input_ref.casefold() in output_owner
        }
        nodes.append(
            ProducerNode(
                id=node_id,
                role=role,
                owner=owner,
                target_id=next(iter(target_ids), None),
                arguments=cast(tuple[str, ...], normalized["arguments"]),
                inputs=cast(tuple[str, ...], normalized["inputs"]),
                directive_inputs=(
                    normalized_directive_inputs.get(next(iter(target_ids)), ())
                    if target_ids
                    else ()
                ),
                outputs=node_outputs,
                depends_on=tuple(sorted(dependencies, key=str.casefold)),
            )
        )
    terminal_targets = {
        node.target_id for node in nodes if node.target_id is not None
    }
    unused_directive_targets = set(normalized_directive_inputs) - terminal_targets
    if unused_directive_targets:
        raise ProducerGraphError(
            "directive inputs lack a terminal linker: "
            + ", ".join(sorted(unused_directive_targets, key=str.casefold))
        )
    return ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=source_topology_digest_value,
        toolchain_lock_digest=toolchain_lock_digest,
        path_profile_id=path_profile_id,
        extractor="cmake-unix-makefiles-v1",
        nodes=tuple(sorted(nodes, key=lambda item: item.id.casefold())),
    )


def read_producer_graph(path: Path) -> ProducerGraphDocument:
    try:
        value = strict_load(path)
        return ProducerGraphDocument.model_validate_json(canonical_json(value))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ProducerGraphError(f"invalid producer graph {path}: {exc}") from exc


def write_producer_graph(path: Path, graph: ProducerGraphDocument) -> None:
    destination = path.resolve(strict=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        temporary.write_bytes(canonical_json(graph))
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


__all__ = [
    "ProducerGraphDocument",
    "ProducerGraphError",
    "ProducerNode",
    "ProducerRole",
    "extract_cmake_unix_makefiles_graph",
    "graph_reference",
    "linker_library_sequence",
    "materialize_argument",
    "materialize_reference",
    "producer_graph_accepts_source",
    "producer_graph_digest",
    "read_producer_graph",
    "source_topology_digest",
    "toolchain_document_digest",
    "write_producer_graph",
]
