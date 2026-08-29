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
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

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


def validate_graph_reference(value: str, *, output: bool = False) -> str:
    """Validate and return one canonical producer-graph file reference."""

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
        return validate_graph_reference(f"{kind}/{suffix[1:]}", output=output)
    if any(item in value for item in _MARKERS):
        raise ValueError("logical-seat marker must begin a file argument")
    if output:
        relative = _relative(value, label="producer output argument")
        return validate_graph_reference(f"build/{relative}", output=True)
    if bare_library and re.fullmatch(r"(?i)[a-z0-9_.+@-]+\.lib", value):
        return validate_graph_reference(f"system-library/{value}")
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

    return validate_graph_reference(f"{kind}/{relative}")


def linker_input_sequence(node: ProducerNode) -> tuple[str, ...]:
    """Return ordered positional object, resource, and archive references.

    The sequence is taken directly from the already-validated linker argv.  It
    deliberately preserves repeated archives because their occurrence seats
    are part of classic archive-extraction behavior.
    """

    if node.role is not ProducerRole.LINKER:
        raise ProducerGraphError("linker input sequence is defined only for linker nodes")
    references: list[str] = []
    for value in node.arguments:
        if value.startswith(("/", "-")):
            continue
        portable = value.replace("\\", "/")
        suffix = PurePosixPath(portable).suffix.casefold()
        if suffix not in {".lib", ".obj", ".res"}:
            continue
        references.append(
            _argument_reference(
                value,
                bare_library=suffix == ".lib",
                source_library_is_quarantine=suffix == ".lib",
            )
        )
    return tuple(references)


def linker_library_sequence(node: ProducerNode) -> tuple[str, ...]:
    """Return the linker's ordered positional archive references, including repeats."""

    return tuple(
        reference
        for reference in linker_input_sequence(node)
        if PurePosixPath(reference.split("/", 1)[1]).suffix.casefold() == ".lib"
    )


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
        canonical = tuple(validate_graph_reference(value) for value in values)
        if canonical != tuple(sorted(set(canonical), key=str.casefold)):
            raise ValueError("producer inputs must be unique and canonically ordered")
        return canonical

    @field_validator("directive_inputs")
    @classmethod
    def validate_directive_inputs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        canonical = tuple(validate_graph_reference(value) for value in values)
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
        canonical = tuple(validate_graph_reference(value, output=True) for value in values)
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

    schema_version: Literal[2]
    source_topology_digest: Digest
    toolchain_lock_digest: Digest
    path_profile_id: Identifier
    extractor: Literal["cmake-unix-makefiles-v1"]
    nodes: Annotated[tuple[ProducerNode, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_graph(self) -> ProducerGraphDocument:
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
    paths: Iterable[str],
) -> bool:
    """Return whether current source paths satisfy the committed graph."""

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

    validate_graph_reference(value)
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
    "graph_reference",
    "linker_input_sequence",
    "linker_library_sequence",
    "materialize_argument",
    "materialize_reference",
    "producer_graph_accepts_source",
    "producer_graph_digest",
    "read_producer_graph",
    "source_topology_digest",
    "toolchain_document_digest",
    "validate_graph_reference",
    "write_producer_graph",
]
