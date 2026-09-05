"""Resolve human defaults into explicit classic execution inputs."""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from reprobit.backends import (
    POSIX_WINE_BACKEND,
    ExecutionBackend,
    NativeWindowsBackend,
    PosixWineBackend,
    backend_for_host,
)
from reprobit.cli_paths import CLIError
from reprobit.user_config import resolve_toolchain_root


@dataclass(frozen=True, slots=True)
class ClassicExecutionInputs:
    toolchain_root: Path
    backend: ExecutionBackend
    compiler_transport: Path | None
    resource_transport: Path | None


def selected_backend(args: argparse.Namespace) -> ExecutionBackend:
    """Resolve shared CLI backend options without duplicating host policy."""

    wine = args.wine if args.wine is not None else "wine"
    wineserver = args.wineserver if args.wineserver is not None else "wineserver"
    if args.backend == "auto":
        backend = backend_for_host()
        if not isinstance(backend, PosixWineBackend) or (
            wine == "wine" and wineserver == "wineserver"
        ):
            return backend
        return PosixWineBackend(wine=wine, wineserver=wineserver)
    if args.backend == POSIX_WINE_BACKEND:
        return PosixWineBackend(wine=wine, wineserver=wineserver)
    return NativeWindowsBackend()


_EXECUTION_OPTIONS = (
    "--backend",
    "--wine",
    "--wineserver",
    "--toolchain-root",
    "--compiler-transport",
    "--resource-transport",
    "--jobs",
    "--initialization-timeout",
    "--compile-timeout",
    "--link-timeout",
    "--cleanup-timeout",
)


def execution_option_argv(
    args: argparse.Namespace, supplied_argv: Sequence[str]
) -> tuple[str, ...]:
    """Keep explicit execution choices in follow-ups without printing defaults.

    Call after argparse validates the invocation and before automatic worker
    selection. Parsed values preserve last-option-wins behavior, while matching
    accepted option prefixes also supports argparse's unambiguous abbreviations.
    """

    available = tuple(
        option for option in _EXECUTION_OPTIONS if hasattr(args, option[2:].replace("-", "_"))
    )
    selected: set[str] = set()
    for value in supplied_argv:
        if value == "--":
            break
        option = value.partition("=")[0]
        if not option.startswith("--"):
            continue
        if option in available:
            selected.add(option)
            continue
        matches = tuple(candidate for candidate in available if candidate.startswith(option))
        if len(matches) == 1:
            selected.add(matches[0])
    return tuple(
        value
        for option in available
        if option in selected
        for value in (option, str(getattr(args, option[2:].replace("-", "_"))))
    )


def resolve_classic_execution_inputs(
    *,
    profile: str,
    explicit_toolchain_root: str | os.PathLike[str] | None,
    backend: ExecutionBackend,
    compiler_transport: str | os.PathLike[str] | None,
    resource_transport: str | os.PathLike[str] | None,
) -> ClassicExecutionInputs:
    """Apply local defaults without changing committed build authority."""

    root = resolve_toolchain_root(profile, explicit_toolchain_root)
    if (compiler_transport is None) != (resource_transport is None):
        raise CLIError("compiler and resource transports must be supplied together")
    compiler = Path(compiler_transport).expanduser() if compiler_transport is not None else None
    resource = Path(resource_transport).expanduser() if resource_transport is not None else None
    if isinstance(backend, PosixWineBackend) and compiler is None:
        compiler = root / "wine" / "x86" / "cl"
        resource = root / "wine" / "x86" / "rc"
    return ClassicExecutionInputs(root, backend, compiler, resource)


__all__ = [
    "ClassicExecutionInputs",
    "execution_option_argv",
    "resolve_classic_execution_inputs",
    "selected_backend",
]
