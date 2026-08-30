"""Bounded CMake Makefiles producer-graph extraction."""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import cast

from reprobit.cmake_graph_paths import (
    attached_value as _attached_value,
)
from reprobit.cmake_graph_paths import (
    build_working_directory as _build_working_directory,
)
from reprobit.cmake_graph_paths import (
    normalize_arguments as _normalize_arguments,
)
from reprobit.cmake_graph_paths import (
    path_reference as _path_reference,
)
from reprobit.cmake_graph_paths import (
    replace_attached_value as _replace_attached_value,
)
from reprobit.cmake_graph_paths import (
    toolchain_executable as _toolchain_executable,
)
from reprobit.cmake_makefile_metadata import (
    MetadataReader,
    read_compile_database,
)
from reprobit.cmake_makefile_metadata import (
    compile_commands as _compile_commands,
)
from reprobit.cmake_makefile_metadata import (
    expand_response as _expand_response,
)
from reprobit.cmake_makefile_metadata import (
    metadata_files as _metadata_files,
)
from reprobit.cmake_makefile_metadata import (
    resource_commands as _resource_commands,
)
from reprobit.cmake_makefile_metadata import (
    split_command_line as _split_command_line,
)
from reprobit.model import Digest
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerGraphError,
    ProducerNode,
    ProducerRole,
    graph_reference,
    validate_graph_reference,
)


def extract_cmake_makefiles_graph(
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
    raw_database = read_compile_database(build_root)
    metadata_reader = MetadataReader()
    normalized_directive_inputs: dict[str, tuple[str, ...]] = {}
    for target_id, references in (directive_inputs or {}).items():
        if target_id not in target_outputs:
            raise ProducerGraphError(f"directive inputs name unknown target {target_id!r}")
        canonical = tuple(validate_graph_reference(value) for value in references)
        if any(not value.startswith("system-library/") for value in canonical):
            raise ProducerGraphError("directive inputs must be system-library references")
        if len({value.casefold() for value in canonical}) != len(canonical) or canonical != tuple(
            sorted(canonical, key=str.casefold)
        ):
            raise ProducerGraphError(
                f"directive inputs for {target_id!r} are not canonical and unique"
            )
        normalized_directive_inputs[target_id] = canonical

    compile_commands = _compile_commands(
        raw_database,
        build_root=build_root,
        source_root=source_root,
        toolchain_root=toolchain,
    )
    pdb_directory_owners = Counter(
        command.pdb_directory_ref.casefold()
        for command in compile_commands
        if command.pdb_directory_ref is not None
    )
    raw_nodes: list[dict[str, object]] = []
    produced_paths: set[str] = set()
    for command in compile_commands:
        arguments = command.arguments
        pdb_ref = command.pdb_ref
        if command.pdb_directory_ref is not None:
            if pdb_directory_owners[command.pdb_directory_ref.casefold()] == 1:
                # Preserve authentic CMake argv for a directory's sole owner.
                # VC 4.2 materializes ``vc40.pdb`` beneath that directory.
                pdb_ref = command.pdb_directory_ref.rstrip("/") + "/vc40.pdb"
            else:
                # Shared ``vc40.pdb`` is incompatible with isolated compiler
                # lanes.  Make the per-TU policy explicit as ``<object>.pdb``.
                # This changes debug-path input and is not byte-neutral by itself.
                pdb_ref = command.output_ref + ".pdb"
                pdb_relative = PurePosixPath(pdb_ref.removeprefix("build/"))
                pdb_path = build_root.joinpath(*pdb_relative.parts)
                arguments = _replace_attached_value(
                    arguments,
                    ("/Fd", "-Fd"),
                    os.fspath(pdb_path),
                )
        assert pdb_ref is not None
        produced_paths.update(ref.removeprefix("build/") for ref in (command.output_ref, pdb_ref))
        raw_nodes.append(
            {
                "role": ProducerRole.COMPILER,
                "owner": command.owner,
                "arguments": arguments[1:],
                "inputs": (command.source_ref,),
                "outputs": (command.output_ref, pdb_ref),
                "working_directory": command.directory,
            }
        )

    for owner, directory, arguments in _resource_commands(
        build_root,
        toolchain_root=toolchain,
        reader=metadata_reader,
    ):
        output = _attached_value(arguments, ("/fo", "-fo"))
        if output is None or not arguments:
            raise ProducerGraphError("resource command omits its output")
        source = arguments[-1]
        output_ref = _path_reference(
            output,
            working_directory=directory,
            source_root=source_root,
            build_root=build_root,
            toolchain_root=toolchain,
        )
        source_ref = _path_reference(
            source,
            working_directory=directory,
            source_root=source_root,
            build_root=build_root,
            toolchain_root=toolchain,
        )
        if not output_ref.startswith("build/"):
            raise ProducerGraphError("resource output is outside the configured build")
        produced_paths.add(output_ref.removeprefix("build/"))
        raw_nodes.append(
            {
                "role": ProducerRole.RESOURCE,
                "owner": owner,
                "arguments": arguments,
                "inputs": (source_ref,),
                "outputs": (output_ref,),
                "working_directory": directory,
            }
        )

    link_records: list[dict[str, object]] = []
    for link_file in _metadata_files(build_root, "link.txt"):
        owner = link_file.parent.name.removesuffix(".dir")
        directory = _build_working_directory(
            link_file.parent.parent.parent,
            build_root=build_root,
            label=f"link target {owner!r} working directory",
        )
        link_command_text = metadata_reader.read_text(
            link_file,
            label=f"link target {owner!r} metadata",
        ).strip()
        arguments = _split_command_line(link_command_text)
        if not arguments:
            raise ProducerGraphError(f"empty link command for {owner!r}")
        executable_path = _toolchain_executable(
            arguments[0],
            working_directory=directory,
            toolchain_root=toolchain,
            label=f"link command for {owner!r}",
        )
        expanded = _expand_response(
            arguments[1:],
            build_root=build_root,
            working_directory=directory,
            reader=metadata_reader,
        )
        output = _attached_value(expanded, ("/out:", "-out:"))
        if output is None:
            raise ProducerGraphError(f"link command for {owner!r} omits /out")
        executable = executable_path.name.casefold()
        role = ProducerRole.LIBRARIAN if executable in {"lib", "lib.exe"} else ProducerRole.LINKER
        output_refs = [
            _path_reference(
                output,
                working_directory=directory,
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
                        working_directory=directory,
                        source_root=source_root,
                        build_root=build_root,
                        toolchain_root=toolchain,
                    )
                )
                export_file = os.fspath(Path(implementation_library).with_suffix(".exp"))
                output_refs.append(
                    _path_reference(
                        export_file,
                        working_directory=directory,
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
                        working_directory=directory,
                        source_root=source_root,
                        build_root=build_root,
                        toolchain_root=toolchain,
                    )
                )
        produced_paths.update(ref.removeprefix("build/") for ref in output_refs)
        if any(not ref.startswith("build/") for ref in output_refs):
            raise ProducerGraphError(f"link outputs for {owner!r} leave the build seat")
        link_records.append(
            {
                "role": role,
                "owner": owner,
                "arguments": expanded,
                "outputs": tuple(output_refs),
                "working_directory": directory,
            }
        )

    produced_relatives = frozenset(path.casefold() for path in produced_paths)
    raw_nodes.extend(link_records)
    normalized_nodes: list[dict[str, object]] = []
    for raw_node in raw_nodes:
        arguments = _normalize_arguments(
            cast(tuple[str, ...], raw_node["arguments"]),
            working_directory=cast(Path, raw_node["working_directory"]),
            source_root=source_root,
            build_root=build_root,
            toolchain_root=toolchain,
            produced_relatives=produced_relatives,
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
    terminal_targets = {node.target_id for node in nodes if node.target_id is not None}
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
        extractor="cmake-makefiles-v1",
        nodes=tuple(sorted(nodes, key=lambda item: item.id.casefold())),
    )


__all__ = ["extract_cmake_makefiles_graph"]
