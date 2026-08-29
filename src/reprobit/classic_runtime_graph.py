"""Canonical producer-graph preparation models and validation."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Literal, cast

from reprobit.classic.arguments import validate_compile_arguments
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_runtime_environment import _logical_join
from reprobit.model import Digest
from reprobit.paths import normalize_logical_path
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    materialize_argument,
    materialize_reference,
)
from reprobit.schema import ProjectBundle, project_sdk_archive_authorities
from reprobit.toolchains import ClassicMSVCToolchain


@dataclass(frozen=True, slots=True)
class ClassicProducerTarget:
    target_id: str
    build_target: str
    output: Path
    pdb: Path | None
    link_node_id: str = ""


@dataclass(frozen=True, slots=True)
class ClassicCompileRecord:
    node_id: str
    directory: Path
    source: Path
    object_path: Path
    pdb_path: Path
    arguments: tuple[str, ...]
    build_target: str


def classic_compiler_product_refs(node: ProducerNode) -> tuple[str, str]:
    """Return the unique source/object semantic edge of one compiler node."""

    source_suffixes = {".c", ".cc", ".cpp", ".cxx"}
    sources = tuple(
        value
        for value in node.inputs
        if PurePosixPath(value.split("/", 1)[-1]).suffix.casefold() in source_suffixes
    )
    objects = tuple(
        value
        for value in node.outputs
        if PurePosixPath(value.split("/", 1)[-1]).suffix.casefold() in {".obj", ".o"}
    )
    if len(sources) != 1 or len(objects) != 1:
        raise ClassicProjectError(
            f"compiler node {node.id!r} lacks one source/object semantic edge"
        )
    return sources[0], objects[0]


def _tool_with_role(bundle: ProjectBundle, role: str) -> tuple[str, str]:
    matches = [item for item in bundle.toolchain_lock.tools if role in item.roles]
    if len(matches) != 1:
        raise ClassicProjectError(f"toolchain lock does not uniquely bind role {role!r}")
    return matches[0].id, matches[0].path


def _graph_role_bindings(
    bundle: ProjectBundle,
    installation: ClassicMSVCToolchain,
) -> tuple[Mapping[ProducerRole, str], Mapping[ProducerRole, str]]:
    expected = {
        ProducerRole.COMPILER: ("compiler", installation.profile.compiler),
        ProducerRole.RESOURCE: (
            "resource-compiler",
            installation.profile.resource_compiler,
        ),
        ProducerRole.LIBRARIAN: ("librarian", installation.profile.librarian),
        ProducerRole.LINKER: ("linker", installation.profile.linker),
    }
    identifiers: dict[ProducerRole, str] = {}
    relatives: dict[ProducerRole, str] = {}
    for producer_role, (lock_role, profile_relative) in expected.items():
        tool_id, relative = _tool_with_role(bundle, lock_role)
        if relative.casefold() != profile_relative.casefold():
            raise ClassicProjectError(
                f"locked {lock_role!r} role differs from the selected profile producer"
            )
        identifiers[producer_role] = tool_id
        relatives[producer_role] = relative
    return MappingProxyType(identifiers), MappingProxyType(relatives)


def _graph_compile_records(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    *,
    effective_root: Path,
    build_root: Path,
    toolchain_root: Path,
    compiler_command: Path,
    generated_translation_units: frozenset[str] = frozenset(),
) -> tuple[ClassicCompileRecord, ...]:
    generated_folded = {item.casefold() for item in generated_translation_units}
    records: list[ClassicCompileRecord] = []
    for node in graph.nodes:
        if node.role is not ProducerRole.COMPILER:
            continue
        source_refs = tuple(value for value in node.inputs if value.startswith("source/"))
        if len(source_refs) != 1:
            raise ClassicProjectError(f"compiler node {node.id!r} must name one source input")
        outputs = {
            value: materialize_reference(
                value,
                source_root=effective_root,
                build_root=build_root,
                toolchain_root=toolchain_root,
            )
            for value in node.outputs
        }
        objects = tuple(
            path
            for reference, path in outputs.items()
            if reference.casefold().endswith(".obj") and path is not None
        )
        pdbs = tuple(
            path
            for reference, path in outputs.items()
            if reference.casefold().endswith(".pdb") and path is not None
        )
        if len(objects) != 1 or len(pdbs) != 1:
            raise ClassicProjectError(f"compiler node {node.id!r} must declare one OBJ and one PDB")
        arguments = (
            str(compiler_command),
            *(
                materialize_argument(
                    value,
                    source_root=bundle.spec.paths.source,
                    build_root=bundle.spec.paths.build,
                    toolchain_root=bundle.spec.paths.toolchain,
                )
                for value in node.arguments
            ),
        )
        try:
            parsed = validate_compile_arguments(list(arguments))
        except Exception as exc:
            raise ClassicProjectError(
                f"compiler node {node.id!r} has unsafe arguments: {exc}"
            ) from exc
        source_relative = source_refs[0].removeprefix("source/")
        expected_source = _logical_join(bundle.spec.paths.source, source_relative)
        if normalize_logical_path(parsed["source_token"].replace("/", "\\")) != expected_source:
            raise ClassicProjectError(
                f"compiler node {node.id!r} source argument differs from its input"
            )
        object_relative = next(
            value.removeprefix("build/")
            for value in node.outputs
            if value.casefold().endswith(".obj")
        )
        pdb_relative = next(
            value.removeprefix("build/")
            for value in node.outputs
            if value.casefold().endswith(".pdb")
        )
        if normalize_logical_path(parsed["Fo"][1].replace("/", "\\")) != _logical_join(
            bundle.spec.paths.build, object_relative
        ) or normalize_logical_path(parsed["Fd"][1].replace("/", "\\")) != _logical_join(
            bundle.spec.paths.build, pdb_relative
        ):
            raise ClassicProjectError(
                f"compiler node {node.id!r} output arguments differ from its outputs"
            )
        source_path = cast(
            Path,
            materialize_reference(
                source_refs[0],
                source_root=effective_root,
                build_root=build_root,
                toolchain_root=toolchain_root,
            ),
        )
        if source_relative.casefold() in generated_folded:
            if os.path.lexists(source_path):
                raise ClassicProjectError(
                    f"generated compiler source is present before its epoch: {source_relative!r}"
                )
            resolved_source = source_path.resolve(strict=False)
        else:
            if source_path.is_symlink() or not source_path.is_file():
                raise ClassicProjectError(
                    f"ordinary compiler source is absent or redirected: {source_relative!r}"
                )
            resolved_source = source_path.resolve(strict=True)
        records.append(
            ClassicCompileRecord(
                node_id=node.id,
                directory=build_root,
                source=resolved_source,
                object_path=objects[0].resolve(strict=False),
                pdb_path=pdbs[0].resolve(strict=False),
                arguments=arguments,
                build_target=node.owner,
            )
        )
    identities = [
        (record.build_target.casefold(), record.source.as_posix().casefold()) for record in records
    ]
    if len(identities) != len(set(identities)):
        raise ClassicProjectError("producer graph repeats target/source compile identity")
    return tuple(records)


def _graph_targets(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    *,
    effective_root: Path,
    build_root: Path,
    toolchain_root: Path,
) -> tuple[ClassicProducerTarget, ...]:
    gates = {
        gate.target_id: gate.build_target
        for gate in bundle.build_plan.target_gates  # type: ignore[union-attr]
    }
    specs = {target.id: target for target in bundle.spec.targets}
    targets: list[ClassicProducerTarget] = []
    for node in graph.nodes:
        if node.target_id is None:
            continue
        target_id = node.target_id
        if node.role is not ProducerRole.LINKER or node.owner != gates.get(target_id):
            raise ClassicProjectError(
                f"terminal node {node.id!r} differs from target-gate authority"
            )
        suffix = Path(specs[target_id].artifact).suffix.casefold()
        primary_refs = tuple(
            reference for reference in node.outputs if Path(reference).suffix.casefold() == suffix
        )
        if primary_refs != (specs[target_id].artifact,):
            raise ClassicProjectError(
                f"terminal node {node.id!r} primary output differs from target artifact"
            )
        candidates = tuple(
            path
            for reference in primary_refs
            for path in (
                materialize_reference(
                    reference,
                    source_root=effective_root,
                    build_root=build_root,
                    toolchain_root=toolchain_root,
                ),
            )
            if path is not None
        )
        if not suffix or len(candidates) != 1:
            raise ClassicProjectError(
                f"terminal node {node.id!r} does not identify one primary image output"
            )
        pdbs = tuple(
            path
            for reference in node.outputs
            if reference.casefold().endswith(".pdb")
            for path in (
                materialize_reference(
                    reference,
                    source_root=effective_root,
                    build_root=build_root,
                    toolchain_root=toolchain_root,
                ),
            )
            if path is not None
        )
        if len(pdbs) > 1:
            raise ClassicProjectError(f"terminal node {node.id!r} repeats PDB outputs")
        targets.append(
            ClassicProducerTarget(
                target_id=target_id,
                build_target=node.owner,
                output=candidates[0].resolve(strict=False),
                pdb=pdbs[0].resolve(strict=False) if pdbs else None,
                link_node_id=node.id,
            )
        )
    if {target.target_id for target in targets} != set(specs):
        raise ClassicProjectError("producer graph does not exactly cover project targets")
    return tuple(sorted(targets, key=lambda item: item.target_id.casefold()))


def _graph_system_library_map(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    installation: ClassicMSVCToolchain,
    *,
    effective_root: Path,
    build_root: Path,
) -> Mapping[str, Path]:
    if bundle.build_plan is None or bundle.source_manifest is None:
        raise ClassicProjectError(
            "system-library resolution requires source and build-plan authority"
        )
    sdk_authorities = {
        item.path.casefold(): item for item in project_sdk_archive_authorities(bundle.build_plan)
    }
    manifest_entries = {item.path.casefold(): item for item in bundle.source_manifest.entries}
    result: dict[str, Path] = {}
    roots = {
        "${SOURCE}": effective_root,
        "${BUILD}": build_root,
        "${TOOLCHAIN}": installation.root,
    }
    for node in graph.nodes:
        names = sorted(
            value.removeprefix("system-library/").casefold()
            for value in (*node.inputs, *node.directive_inputs)
            if value.startswith("system-library/")
        )
        if not names:
            continue
        search_roots: list[tuple[Path, Literal["source", "build", "toolchain"]]] = []
        for argument in node.arguments:
            if not argument.casefold().startswith(("/libpath:", "-libpath:")):
                continue
            raw = argument.split(":", 1)[1]
            matched = False
            for marker, root in roots.items():
                if raw == marker or raw.startswith(marker + "/"):
                    search_relative = raw.removeprefix(marker).removeprefix("/")
                    origin = cast(
                        Literal["source", "build", "toolchain"],
                        {
                            "${SOURCE}": "source",
                            "${BUILD}": "build",
                            "${TOOLCHAIN}": "toolchain",
                        }[marker],
                    )
                    search_roots.append(
                        (
                            root.joinpath(*PurePosixPath(search_relative).parts).resolve(
                                strict=True
                            ),
                            origin,
                        )
                    )
                    matched = True
                    break
            if not matched:
                raise ClassicProjectError(
                    f"producer {node.id!r} has an unseated library search path"
                )
        for relative in installation.profile.library_roots:
            search_roots.append((installation.host_path(relative), "toolchain"))
        for root, _origin in search_roots:
            if root.is_symlink() or not root.is_dir():
                raise ClassicProjectError(f"toolchain library root is absent or redirected: {root}")
        for name in names:
            selected: Path | None = None
            selected_origin: Literal["source", "build", "toolchain"] | None = None
            for root, origin in search_roots:
                matches = tuple(
                    child.resolve(strict=True)
                    for child in root.iterdir()
                    if child.is_file() and not child.is_symlink() and child.name.casefold() == name
                )
                if len(matches) > 1:
                    raise ClassicProjectError(f"system library {name!r} is ambiguous within {root}")
                if matches:
                    selected = matches[0]
                    selected_origin = origin
                    break
            if selected is None:
                raise ClassicProjectError(
                    f"system library {name!r} is absent from producer search roots"
                )
            if selected_origin == "build":
                raise ClassicProjectError(
                    f"system library {name!r} resolves through the build seat; "
                    "declare the produced build archive edge explicitly"
                )
            if selected_origin == "source":
                try:
                    sdk_relative = selected.relative_to(effective_root.resolve(strict=True))
                except ValueError as exc:
                    raise ClassicProjectError(
                        f"source-resolved system library {name!r} escaped its seat"
                    ) from exc
                logical_path = PurePosixPath(*sdk_relative.parts).as_posix()
                authority = sdk_authorities.get(logical_path.casefold())
                entry = manifest_entries.get(logical_path.casefold())
                if authority is None or entry is None:
                    raise ClassicProjectError(
                        f"source-resolved system library {name!r} lacks exact "
                        f"project SDK authority for {logical_path!r}"
                    )
                payload = selected.read_bytes()
                digest = Digest.from_bytes(payload)
                if (
                    len(payload) != entry.size
                    or digest != entry.digest
                    or digest.value != authority.sha256
                ):
                    raise ClassicProjectError(
                        f"source-resolved system library {name!r} differs from "
                        f"its project SDK/source-manifest pin"
                    )
            reference = f"system-library/{name}"
            previous = result.setdefault(reference, selected)
            if previous != selected:
                raise ClassicProjectError(
                    f"system library {name!r} resolves differently across producer nodes"
                )
    return MappingProxyType(dict(sorted(result.items(), key=lambda item: item[0].casefold())))


__all__ = [
    "ClassicCompileRecord",
    "ClassicProducerTarget",
    "classic_compiler_product_refs",
]
