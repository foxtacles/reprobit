"""Resolve human defaults into explicit classic execution inputs."""

from __future__ import annotations

import argparse
import os
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

    if args.backend == "auto":
        return backend_for_host()
    if args.backend == POSIX_WINE_BACKEND:
        return PosixWineBackend(wine=args.wine, wineserver=args.wineserver)
    return NativeWindowsBackend()


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
    "resolve_classic_execution_inputs",
    "selected_backend",
]
