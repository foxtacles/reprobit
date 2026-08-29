"""Migration-time CMake Unix Makefiles producer-graph extraction."""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import cast

from reprobit.model import Digest
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerGraphError,
    ProducerNode,
    ProducerRole,
    graph_reference,
    validate_graph_reference,
)
from reprobit.strict_json import strict_load


def _replace_root(value: str, root: Path, marker: str) -> str:
    native = os.fspath(root.resolve(strict=True))
    candidates = (native, native.replace("\\", "/"))
    result = value
    for candidate in sorted(set(candidates), key=len, reverse=True):
        result = result.replace(candidate, marker)
    if marker in result:
        prefix, separator, suffix = result.partition(marker)
        result = prefix + separator + suffix.replace("\\", "/")
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
        canonical = tuple(validate_graph_reference(value) for value in references)
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


__all__ = ["extract_cmake_unix_makefiles_graph"]
