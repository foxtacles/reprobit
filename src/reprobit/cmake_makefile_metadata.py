"""Bounded parsing of CMake Makefiles metadata used during graph import."""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from reprobit.cmake_graph_paths import (
    attached_value,
    build_working_directory,
    path_reference,
    toolchain_executable,
)
from reprobit.producer_graph import ProducerGraphError
from reprobit.strict_json import strict_loads

_MAX_COMPILE_RECORDS = 20_000
_MAX_COMPILE_DATABASE_BYTES = 128 * 1024 * 1024
_MAX_METADATA_DIRECTORIES = 20_000
_MAX_METADATA_FILES = 20_000
_MAX_METADATA_FILE_BYTES = 16 * 1024 * 1024
_MAX_METADATA_TOTAL_BYTES = 128 * 1024 * 1024
_RESOURCE_RECIPE = re.compile(r"(?i)(?:^|[/\\\"])(?:rc|rc\.exe)(?=(?:\"|\s|$))")


@dataclass(frozen=True, slots=True)
class CompileCommand:
    directory: Path
    arguments: tuple[str, ...]
    owner: str
    source_ref: str
    output_ref: str
    pdb_ref: str | None
    pdb_directory_ref: str | None


@dataclass(slots=True)
class MetadataReader:
    """Apply one aggregate byte budget to all Makefile-side metadata reads."""

    consumed_bytes: int = 0

    def read_text(self, path: Path, *, label: str) -> str:
        if path.is_symlink() or not path.is_file():
            raise ProducerGraphError(f"{label} is absent or redirected: {path}")
        if path.stat().st_size > _MAX_METADATA_FILE_BYTES:
            raise ProducerGraphError(
                f"{label} exceeds the {_MAX_METADATA_FILE_BYTES}-byte file limit: {path}"
            )
        with path.open("rb") as stream:
            payload = stream.read(_MAX_METADATA_FILE_BYTES + 1)
        if len(payload) > _MAX_METADATA_FILE_BYTES:
            raise ProducerGraphError(
                f"{label} exceeds the {_MAX_METADATA_FILE_BYTES}-byte file limit: {path}"
            )
        if self.consumed_bytes + len(payload) > _MAX_METADATA_TOTAL_BYTES:
            raise ProducerGraphError(
                "configured build metadata exceeds the aggregate extraction byte limit"
            )
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProducerGraphError(f"{label} is not UTF-8 text: {path}") from error
        self.consumed_bytes += len(payload)
        return text


def _read_bounded_text(path: Path, *, label: str, max_bytes: int) -> str:
    if path.is_symlink() or not path.is_file():
        raise ProducerGraphError(f"{label} is absent or redirected: {path}")
    if path.stat().st_size > max_bytes:
        raise ProducerGraphError(f"{label} exceeds the {max_bytes}-byte extraction limit: {path}")
    with path.open("rb") as stream:
        payload = stream.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ProducerGraphError(f"{label} exceeds the {max_bytes}-byte extraction limit: {path}")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProducerGraphError(f"{label} is not UTF-8 text: {path}") from error


def read_compile_database(build_root: Path) -> list[object]:
    database_path = build_root / "compile_commands.json"
    raw_database = strict_loads(
        _read_bounded_text(
            database_path,
            label="compile database",
            max_bytes=_MAX_COMPILE_DATABASE_BYTES,
        )
    )
    if not isinstance(raw_database, list):
        raise ProducerGraphError("compile_commands.json must be an array")
    if len(raw_database) > _MAX_COMPILE_RECORDS:
        raise ProducerGraphError("compile database exceeds the translation-unit limit")
    return cast(list[object], raw_database)


def metadata_files(build_root: Path, name: str) -> tuple[Path, ...]:
    """Find recursive ``CMakeFiles/*.dir`` metadata without following redirects."""

    matches: list[Path] = []
    visited = 0
    for raw_directory, child_names, _files in os.walk(build_root, topdown=True):
        visited += 1
        if visited > _MAX_METADATA_DIRECTORIES:
            raise ProducerGraphError("configured build exceeds the metadata directory limit")
        directory = Path(raw_directory)
        child_names.sort(key=str.casefold)
        retained: list[str] = []
        for child_name in child_names:
            child = directory / child_name
            if child.is_symlink():
                raise ProducerGraphError(f"configured build contains redirected metadata: {child}")
            if child_name.casefold() != "cmakefiles":
                retained.append(child_name)
                continue
            for target_directory in sorted(child.iterdir(), key=lambda item: item.name.casefold()):
                if not target_directory.name.casefold().endswith(".dir"):
                    continue
                if target_directory.is_symlink() or not target_directory.is_dir():
                    raise ProducerGraphError(
                        f"CMake target metadata is redirected: {target_directory}"
                    )
                candidate = target_directory / name
                if not candidate.exists():
                    continue
                if candidate.is_symlink() or not candidate.is_file():
                    raise ProducerGraphError(f"CMake metadata is redirected: {candidate}")
                matches.append(candidate)
                if len(matches) > _MAX_METADATA_FILES:
                    raise ProducerGraphError("configured build exceeds the metadata file limit")
        child_names[:] = retained
    return tuple(sorted(matches, key=lambda item: item.relative_to(build_root).as_posix()))


def split_command_line(value: str) -> tuple[str, ...]:
    """Split migration-time command text without eating native path separators."""

    if os.name != "nt":
        return tuple(shlex.split(value, posix=True))

    # CMake's Windows strings use Microsoft C runtime rules. Backslashes are
    # special only when they immediately precede a double quote.
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


def expand_response(
    arguments: Iterable[str],
    *,
    build_root: Path,
    working_directory: Path,
    reader: MetadataReader,
) -> tuple[str, ...]:
    expanded: list[str] = []
    for argument in arguments:
        if not argument.startswith("@"):
            expanded.append(argument)
            continue
        response = Path(argument[1:])
        if not response.is_absolute():
            response = working_directory / response
        try:
            response.resolve(strict=True).relative_to(build_root.resolve(strict=True))
        except (OSError, ValueError) as exc:
            raise ProducerGraphError(f"response file escapes configured build: {argument}") from exc
        expanded.extend(split_command_line(reader.read_text(response, label="link response file")))
    return tuple(expanded)


def _read_flags(path: Path, prefix: str, *, reader: MetadataReader) -> tuple[str, ...]:
    values: list[str] = []
    for line in reader.read_text(path, label="CMake flags metadata").splitlines():
        if line.startswith(prefix + " ="):
            values.extend(split_command_line(line.split("=", 1)[1].strip()))
    return tuple(values)


def _resource_recipe(
    line: str, *, declared_working_directory: Path, build_root: Path
) -> tuple[Path, tuple[str, ...]]:
    tokens = split_command_line(line.removeprefix("@"))
    if not tokens:
        return declared_working_directory, ()
    working_directory = declared_working_directory
    if Path(tokens[0]).name.casefold() == "cd":
        try:
            separator = tokens.index("&&")
        except ValueError:
            return working_directory, ()
        directory_tokens = tokens[1:separator]
        if directory_tokens and directory_tokens[0].casefold() == "/d":
            directory_tokens = directory_tokens[1:]
        if len(directory_tokens) != 1:
            raise ProducerGraphError("CMake resource recipe has an ambiguous working directory")
        working_directory = build_working_directory(
            directory_tokens[0],
            build_root=build_root,
            label="resource recipe working directory",
        )
        tokens = tokens[separator + 1 :]
    return working_directory, tokens


def resource_commands(
    build_root: Path,
    *,
    toolchain_root: Path,
    reader: MetadataReader,
) -> tuple[tuple[str, Path, tuple[str, ...]], ...]:
    result: list[tuple[str, Path, tuple[str, ...]]] = []
    for makefile in metadata_files(build_root, "build.make"):
        owner = makefile.parent.name.removesuffix(".dir")
        declared_working_directory = build_working_directory(
            makefile.parent.parent.parent,
            build_root=build_root,
            label=f"resource target {owner!r} working directory",
        )
        flags = makefile.parent / "flags.make"
        variables: dict[str, tuple[str, ...]] | None = None
        for raw_line in reader.read_text(
            makefile, label=f"resource target {owner!r} build metadata"
        ).splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if _RESOURCE_RECIPE.search(line.removeprefix("@")) is None:
                continue
            working_directory, tokens = _resource_recipe(
                line,
                declared_working_directory=declared_working_directory,
                build_root=build_root,
            )
            if not tokens or Path(tokens[0]).name.casefold() not in {"rc", "rc.exe"}:
                continue
            toolchain_executable(
                tokens[0],
                working_directory=working_directory,
                toolchain_root=toolchain_root,
                label=f"resource compiler for {owner!r}",
            )
            if not flags.is_file():
                raise ProducerGraphError(f"resource target {owner!r} has no flags.make")
            if variables is None:
                variables = {
                    "$(RC_DEFINES)": _read_flags(flags, "RC_DEFINES", reader=reader),
                    "$(RC_INCLUDES)": _read_flags(flags, "RC_INCLUDES", reader=reader),
                    "$(RC_FLAGS)": _read_flags(flags, "RC_FLAGS", reader=reader),
                }
            expanded: list[str] = []
            for token in tokens[1:]:
                expanded.extend(variables.get(token, (token,)))
            result.append((owner, working_directory, tuple(expanded)))
    return tuple(result)


def compile_commands(
    raw_database: list[object],
    *,
    build_root: Path,
    source_root: Path,
    toolchain_root: Path,
) -> tuple[CompileCommand, ...]:
    result: list[CompileCommand] = []
    for index, database_item in enumerate(raw_database):
        if not isinstance(database_item, dict) or not isinstance(database_item.get("command"), str):
            raise ProducerGraphError(f"compile record {index} lacks one literal command")
        directory_value = database_item.get("directory")
        if not isinstance(directory_value, str):
            raise ProducerGraphError(f"compile record {index} lacks a working directory")
        directory = build_working_directory(
            directory_value,
            build_root=build_root,
            label=f"compile record {index} working directory",
        )
        arguments = split_command_line(cast(str, database_item["command"]))
        if not arguments:
            raise ProducerGraphError("compile command is empty")
        toolchain_executable(
            arguments[0],
            working_directory=directory,
            toolchain_root=toolchain_root,
            label=f"compiler for record {index}",
        )
        output = attached_value(arguments[1:], ("/Fo", "-Fo"))
        pdb = attached_value(arguments[1:], ("/Fd", "-Fd"))
        source = database_item.get("file")
        if output is None or pdb is None or not isinstance(source, str) or not source:
            raise ProducerGraphError("compile command omits source, object, or PDB")
        output_ref = path_reference(
            output,
            working_directory=directory,
            source_root=source_root,
            build_root=build_root,
            toolchain_root=toolchain_root,
        )
        if not output_ref.startswith("build/"):
            raise ProducerGraphError("compile object output is outside the configured build")
        pdb_ref: str | None = None
        pdb_directory_ref: str | None = None
        if pdb.endswith(("/", "\\")):
            pdb_directory = pdb.rstrip("/\\")
            if not pdb_directory:
                raise ProducerGraphError("compile PDB directory is empty")
            pdb_directory_ref = path_reference(
                pdb_directory,
                working_directory=directory,
                source_root=source_root,
                build_root=build_root,
                toolchain_root=toolchain_root,
            )
            if not pdb_directory_ref.startswith("build/"):
                raise ProducerGraphError("compile PDB directory is outside the build seat")
        else:
            pdb_ref = path_reference(
                pdb,
                working_directory=directory,
                source_root=source_root,
                build_root=build_root,
                toolchain_root=toolchain_root,
            )
            if not pdb_ref.startswith("build/"):
                raise ProducerGraphError("compile PDB output is outside the configured build")
        source_ref = path_reference(
            source,
            working_directory=directory,
            source_root=source_root,
            build_root=build_root,
            toolchain_root=toolchain_root,
        )
        owner_match = re.match(r"(?i)^build/(?:[^/]+/)*CMakeFiles/([^/]+)\.dir/", output_ref)
        if owner_match is None:
            raise ProducerGraphError(f"compile output has no CMake target owner: {output_ref}")
        result.append(
            CompileCommand(
                directory=directory,
                arguments=arguments,
                owner=owner_match.group(1),
                source_ref=source_ref,
                output_ref=output_ref,
                pdb_ref=pdb_ref,
                pdb_directory_ref=pdb_directory_ref,
            )
        )
    return tuple(result)


__all__ = [
    "CompileCommand",
    "MetadataReader",
    "compile_commands",
    "expand_response",
    "metadata_files",
    "read_compile_database",
    "resource_commands",
    "split_command_line",
]
