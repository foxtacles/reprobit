"""Logical-seat path handling for CMake producer-graph import."""

from __future__ import annotations

import os
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from reprobit.producer_graph import ProducerGraphError, graph_reference

_ATTACHED_PATH_PREFIXES = (
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
_SEPARATE_PATH_OPTIONS = frozenset({"/i", "-i", "/fi", "-fi", "/fo", "-fo", "/fd", "-fd"})


def replace_root(value: str, root: Path, marker: str) -> str:
    native = os.fspath(root.resolve(strict=True))
    candidates = (native, native.replace("\\", "/"))
    result = value
    for candidate in sorted(set(candidates), key=len, reverse=True):
        result = result.replace(candidate, marker)
    if marker in result:
        prefix, separator, suffix = result.partition(marker)
        result = prefix + separator + suffix.replace("\\", "/")
    return result


def seated_path(
    value: str,
    *,
    working_directory: Path,
    source_root: Path,
    build_root: Path,
    toolchain_root: Path,
) -> str:
    result = replace_root(value, source_root, "${SOURCE}")
    result = replace_root(result, build_root, "${BUILD}")
    result = replace_root(result, toolchain_root, "${TOOLCHAIN}")
    if any(marker in result for marker in ("${SOURCE}", "${BUILD}", "${TOOLCHAIN}")):
        return result.replace("\\", "/")

    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = working_directory / candidate
    resolved = candidate.resolve(strict=False)
    for marker, root in (
        ("${SOURCE}", source_root),
        ("${BUILD}", build_root),
        ("${TOOLCHAIN}", toolchain_root),
    ):
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError:
            continue
        return marker if relative == "." else f"{marker}/{relative}"
    return result.replace("\\", "/")


def produced_relative(
    value: str,
    *,
    working_directory: Path,
    build_root: Path,
    produced_relatives: frozenset[str],
) -> str | None:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = working_directory / candidate
    try:
        relative = candidate.resolve(strict=False).relative_to(build_root).as_posix()
    except ValueError:
        return None
    return relative if relative.casefold() in produced_relatives else None


def attached_path_prefix(value: str) -> str | None:
    folded = value.casefold()
    if folded.startswith(
        ("/include:", "-include:", "/incremental", "-incremental", "/ignore:", "-ignore:")
    ):
        return None
    return next(
        (
            prefix
            for prefix in _ATTACHED_PATH_PREFIXES
            if folded.startswith(prefix) and len(value) > len(prefix)
        ),
        None,
    )


def normalize_argument(
    value: str,
    *,
    working_directory: Path,
    source_root: Path,
    build_root: Path,
    toolchain_root: Path,
    produced_relatives: frozenset[str],
    force_path: bool = False,
) -> str:
    prefix = attached_path_prefix(value)
    if prefix is not None:
        payload = value[len(prefix) :]
        normalized = seated_path(
            payload,
            working_directory=working_directory,
            source_root=source_root,
            build_root=build_root,
            toolchain_root=toolchain_root,
        )
        if prefix.casefold() in {"/fd", "-fd"} and payload.endswith(("/", "\\")):
            normalized = normalized.rstrip("/") + "/"
        return value[: len(prefix)] + normalized
    if force_path:
        return seated_path(
            value,
            working_directory=working_directory,
            source_root=source_root,
            build_root=build_root,
            toolchain_root=toolchain_root,
        )

    produced = produced_relative(
        value,
        working_directory=working_directory,
        build_root=build_root,
        produced_relatives=produced_relatives,
    )
    if produced is not None:
        return "${BUILD}/" + produced

    result = replace_root(value, source_root, "${SOURCE}")
    result = replace_root(result, build_root, "${BUILD}")
    result = replace_root(result, toolchain_root, "${TOOLCHAIN}")
    if result != value:
        return result.replace("\\", "/")

    portable = value.replace("\\", "/")
    suffix = PurePosixPath(portable).suffix.casefold()
    bare_system_library = suffix == ".lib" and "/" not in portable
    if Path(value).is_absolute() or (
        not value.startswith(("/", "-"))
        and not bare_system_library
        and (
            "/" in portable
            or suffix
            in {
                ".c",
                ".cc",
                ".cpp",
                ".cxx",
                ".h",
                ".hpp",
                ".rc",
                ".def",
                ".obj",
                ".res",
                ".exe",
                ".dll",
                ".pdb",
                ".map",
            }
        )
    ):
        return seated_path(
            value,
            working_directory=working_directory,
            source_root=source_root,
            build_root=build_root,
            toolchain_root=toolchain_root,
        )
    return portable


def normalize_arguments(
    values: Sequence[str],
    *,
    working_directory: Path,
    source_root: Path,
    build_root: Path,
    toolchain_root: Path,
    produced_relatives: frozenset[str],
) -> tuple[str, ...]:
    result: list[str] = []
    force_path = False
    for value in values:
        result.append(
            normalize_argument(
                value,
                working_directory=working_directory,
                source_root=source_root,
                build_root=build_root,
                toolchain_root=toolchain_root,
                produced_relatives=produced_relatives,
                force_path=force_path,
            )
        )
        force_path = value.casefold() in _SEPARATE_PATH_OPTIONS
    if force_path:
        raise ProducerGraphError("producer command ends with an incomplete path option")
    return tuple(result)


def path_reference(
    value: str,
    *,
    working_directory: Path,
    source_root: Path,
    build_root: Path,
    toolchain_root: Path,
) -> str:
    path = Path(value)
    if not path.is_absolute():
        path = working_directory / path
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


def attached_value(arguments: Sequence[str], prefixes: Sequence[str]) -> str | None:
    for index, argument in enumerate(arguments):
        folded = argument.casefold()
        for prefix in prefixes:
            if folded == prefix.casefold() and index + 1 < len(arguments):
                return arguments[index + 1]
            if folded.startswith(prefix.casefold()) and len(argument) > len(prefix):
                return argument[len(prefix) :]
    return None


def replace_attached_value(
    arguments: Sequence[str], prefixes: Sequence[str], replacement: str
) -> tuple[str, ...]:
    result = list(arguments)
    for index, argument in enumerate(result):
        folded = argument.casefold()
        for prefix in prefixes:
            prefix_folded = prefix.casefold()
            if folded == prefix_folded and index + 1 < len(result):
                result[index + 1] = replacement
                return tuple(result)
            if folded.startswith(prefix_folded) and len(argument) > len(prefix):
                result[index] = argument[: len(prefix)] + replacement
                return tuple(result)
    raise ProducerGraphError("producer command omits the path option being rewritten")


def build_working_directory(value: str | Path, *, build_root: Path, label: str) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = build_root / candidate
    if candidate.is_symlink() or not candidate.is_dir():
        raise ProducerGraphError(f"{label} is absent or redirected: {candidate}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(build_root)
    except ValueError as exc:
        raise ProducerGraphError(f"{label} escapes the configured build: {candidate}") from exc
    return resolved


def toolchain_executable(
    value: str, *, working_directory: Path, toolchain_root: Path, label: str
) -> Path:
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = working_directory / candidate
    if candidate.is_symlink() or not candidate.is_file():
        raise ProducerGraphError(f"{label} is absent or redirected: {candidate}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(toolchain_root)
    except ValueError as exc:
        raise ProducerGraphError(f"{label} does not use the selected toolchain") from exc
    return resolved


__all__ = [
    "attached_value",
    "build_working_directory",
    "normalize_arguments",
    "path_reference",
    "replace_attached_value",
    "replace_root",
    "toolchain_executable",
]
