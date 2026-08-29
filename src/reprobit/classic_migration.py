"""Non-certifying CMake configuration for producer-graph extraction.

This module is intentionally outside the classic execution trust boundary.
It materializes reviewed source authority and runs CMake only to produce the
Unix-Makefiles metadata consumed by :mod:`reprobit.producer_graph` extraction.
Certifying build and verify paths import :mod:`reprobit.classic_runtime`
instead and never call this module.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path

from reprobit.classic_project import (
    ClassicProjectError,
    _effective_source_seal,
    materialize_effective_workspace,
    write_cmake_project_plan,
)
from reprobit.cmake import CMakeExportPlan, cmake_module_path
from reprobit.model import Digest
from reprobit.process import CommandSpec, ProcessError, ProcessSupervisor
from reprobit.schema import ProducerGraphBuildAdapter, ProjectBundle
from reprobit.strict_json import canonical_json


class ClassicMigrationError(ClassicProjectError):
    """A migration-time configure boundary was incomplete or unsafe."""


@dataclass(frozen=True, slots=True)
class ClassicGraphConfiguration:
    """Closed paths and command receipt needed by ``rbit graph extract``."""

    configured_build_root: Path
    effective_source_root: Path
    toolchain_root: Path
    target_plan: Path
    compile_database: Path
    project_plan: Path
    configure_log: Path
    command: tuple[str, ...]
    command_digest: Digest
    duration_seconds: float


def _regular_executable(path: Path, *, label: str) -> Path:
    candidate = path.expanduser()
    if not candidate.is_absolute():
        raise ClassicMigrationError(f"{label} must be an absolute path")
    if candidate.is_symlink() or not candidate.is_file():
        raise ClassicMigrationError(f"{label} is absent or redirected: {candidate}")
    resolved = candidate.resolve(strict=True)
    if resolved.is_symlink() or not os.access(resolved, os.X_OK):
        raise ClassicMigrationError(f"{label} is not a regular executable: {resolved}")
    return resolved


def _transport_sibling(directory: Path, name: str) -> Path:
    matches = tuple(
        item
        for item in directory.iterdir()
        if item.name.casefold() in {name.casefold(), f"{name}.exe".casefold()}
        and not item.is_symlink()
    )
    if len(matches) != 1:
        raise ClassicMigrationError(
            f"MSVC configure transport does not uniquely provide {name!r}"
        )
    return _regular_executable(matches[0], label=f"{name} transport")


def _migration_environment(transport_directory: Path) -> dict[str, str]:
    environment = dict(os.environ)
    for canonical, value in (
        (
            "PATH",
            str(transport_directory)
            + os.pathsep
            + next(
                (
                    current
                    for key, current in environment.items()
                    if key.casefold() == "path"
                ),
                os.defpath,
            ),
        ),
        ("LANG", "C"),
        ("LC_ALL", "C"),
    ):
        for key in tuple(environment):
            if key.casefold() == canonical.casefold():
                del environment[key]
        environment[canonical] = value
    return environment


def _require_regular_output(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ClassicMigrationError(f"{label} is absent or redirected: {path}")


def configure_classic_producer_graph(
    bundle: ProjectBundle,
    *,
    project_root: Path,
    workspace_root: Path,
    toolchain_root: Path,
    cmake: Path,
    compiler_transport: Path,
    resource_transport: Path,
    configuration: str = "RelWithDebInfo",
    timeout_seconds: float = 600.0,
) -> ClassicGraphConfiguration:
    """Create one fresh Unix-Makefiles tree for graph extraction.

    The workspace must be empty.  Its fixed ``source`` and ``build`` children,
    together with the returned target-plan path, can be passed directly to
    ``rbit graph extract``.  This operation configures but never builds.
    """

    if not isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
        raise ClassicMigrationError(
            "classic graph configuration requires the producer-graph adapter"
        )
    if bundle.source_manifest is None or not bundle.source_manifest.complete or (
        bundle.build_plan is None
    ):
        raise ClassicMigrationError(
            "classic graph configuration requires complete source/build authority"
        )
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ClassicMigrationError("configure timeout must be positive and finite")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", configuration) is None:
        raise ClassicMigrationError("CMake configuration name is unsafe")

    project_root = project_root.resolve(strict=True)
    if project_root.is_symlink() or not project_root.is_dir():
        raise ClassicMigrationError("project root is absent or redirected")
    workspace_root = workspace_root.expanduser().resolve(strict=False)
    if workspace_root == project_root:
        raise ClassicMigrationError("migration workspace cannot be the project root")
    if workspace_root.is_symlink() or (
        workspace_root.exists() and not workspace_root.is_dir()
    ):
        raise ClassicMigrationError("migration workspace is redirected or not a directory")
    if workspace_root.exists() and any(workspace_root.iterdir()):
        raise ClassicMigrationError(
            f"migration workspace is not empty: {workspace_root}"
        )
    workspace_root.mkdir(parents=True, exist_ok=True)

    toolchain_root = toolchain_root.expanduser().resolve(strict=True)
    if toolchain_root.is_symlink() or not toolchain_root.is_dir():
        raise ClassicMigrationError("toolchain root is absent or redirected")
    cmake = _regular_executable(cmake, label="CMake executable")
    compiler = _regular_executable(
        compiler_transport, label="compiler transport"
    )
    resource = _regular_executable(
        resource_transport, label="resource-compiler transport"
    )
    try:
        compiler.relative_to(toolchain_root)
        resource.relative_to(toolchain_root)
    except ValueError as exc:
        raise ClassicMigrationError(
            "compiler transports must remain beneath the admitted toolchain root"
        ) from exc
    if compiler.parent != resource.parent:
        raise ClassicMigrationError(
            "compiler and resource transports must share one admitted directory"
        )
    linker = _transport_sibling(compiler.parent, "link")
    librarian = _transport_sibling(compiler.parent, "lib")

    effective_root = workspace_root / "source"
    configured_root = workspace_root / "build"
    configured_root.mkdir()
    materialize_effective_workspace(
        bundle,
        project_root,
        effective_root,
    )
    project_plan = workspace_root / "reprobit-project-plan.cmake"
    target_plan = configured_root / "reprobit-target-plan.json"
    compile_database = configured_root / "compile_commands.json"
    configure_log = configured_root / "configure.log"
    write_cmake_project_plan(bundle, effective_root, project_plan)
    module = (cmake_module_path() / "ReproBit.cmake").resolve(strict=True)
    _require_regular_output(module, label="ReproBit CMake module")
    source_seal = _effective_source_seal(effective_root)

    command = (
        str(cmake),
        "-S",
        str(effective_root),
        "-B",
        str(configured_root),
        "-G",
        "Unix Makefiles",
        f"-DCMAKE_BUILD_TYPE={configuration}",
        "-DCMAKE_SYSTEM_NAME=Windows",
        f"-DCMAKE_C_COMPILER={compiler}",
        f"-DCMAKE_CXX_COMPILER={compiler}",
        f"-DCMAKE_RC_COMPILER={resource}",
        f"-DCMAKE_LINKER={linker}",
        f"-DCMAKE_AR={librarian}",
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        f"-DREPROBIT_CMAKE_MODULE={module}",
        f"-DREPROBIT_PROJECT_PLAN={project_plan}",
        f"-DREPROBIT_TARGET_PLAN={target_plan}",
        f"-DREPROBIT_EFFECTIVE_SOURCE_ROOT={effective_root}",
        "-DREPROBIT_TERMINAL=ON",
    )
    specification = CommandSpec.create(
        command,
        cwd=effective_root,
        environment=_migration_environment(compiler.parent),
        timeout_seconds=timeout_seconds,
        log_path=configure_log,
    )
    try:
        with ProcessSupervisor() as supervisor:
            result = supervisor.run(specification)
    except ProcessError as exc:
        raise ClassicMigrationError(
            f"migration CMake configure failed; inspect {configure_log}"
        ) from exc
    if _effective_source_seal(effective_root) != source_seal:
        raise ClassicMigrationError("CMake configure changed effective source authority")
    for path, label in (
        (configured_root / "Makefile", "Unix Makefiles root"),
        (compile_database, "compile database"),
        (target_plan, "ReproBit target plan"),
        (configure_log, "configure log"),
        (project_plan, "ReproBit project plan"),
    ):
        _require_regular_output(path, label=label)
    export_plan = CMakeExportPlan.read(target_plan)
    if export_plan.link_admissions:
        raise ClassicMigrationError(
            "configured target plan declares link admissions that the direct "
            "producer graph cannot encode; remove them before graph extraction"
        )
    target_ids = {target.id for target in bundle.spec.targets}
    if {target.artifact_id for target in export_plan.targets} != target_ids or (
        len(export_plan.targets) != len(target_ids)
    ):
        raise ClassicMigrationError(
            "configured target plan differs from project target authority"
        )
    command_digest = Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "argv": list(command),
                "returncode": result.returncode,
                "output": Digest.from_bytes(result.output).model_dump(mode="json"),
            }
        )
    )
    return ClassicGraphConfiguration(
        configured_root.resolve(strict=True),
        effective_root.resolve(strict=True),
        toolchain_root,
        target_plan.resolve(strict=True),
        compile_database.resolve(strict=True),
        project_plan.resolve(strict=True),
        configure_log.resolve(strict=True),
        command,
        command_digest,
        result.duration_seconds,
    )


__all__ = [
    "ClassicGraphConfiguration",
    "ClassicMigrationError",
    "configure_classic_producer_graph",
]
