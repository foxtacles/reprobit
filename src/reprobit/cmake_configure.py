"""Non-certifying CMake configuration for producer-graph extraction.

This module is intentionally outside the classic execution trust boundary.
It materializes reviewed source authority and runs CMake only to produce the
Makefile metadata consumed by :mod:`reprobit.producer_graph` extraction.
Certifying build and verify paths import :mod:`reprobit.classic_runtime`
instead and never call this module.
"""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath

from reprobit.classic_project import (
    ClassicProjectError,
    _cmake_quote,
    effective_source_seal,
    materialize_effective_workspace,
    write_cmake_project_plan,
)
from reprobit.cmake import CMakeExportPlan, cmake_module_path
from reprobit.model import Digest
from reprobit.process import CommandSpec, ProcessError, ProcessSupervisor
from reprobit.schema import ProducerGraphBuildAdapter, ProjectBundle
from reprobit.strict_json import canonical_json


class CMakeConfigureError(ClassicProjectError):
    """A CMake import boundary was incomplete or unsafe."""


def effective_source_digest(root: Path) -> Digest:
    """Digest the complete path, size, and content receipt of an effective tree."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "files": [
                    {"path": path, "size": size, "sha256": sha256}
                    for path, size, sha256 in effective_source_seal(root)
                ],
            }
        )
    )


@dataclass(frozen=True, slots=True)
class CMakeConfiguration:
    """Closed paths and command receipt needed by ``rbit graph extract``."""

    configured_build_root: Path
    effective_source_root: Path
    effective_source_digest: Digest
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
        raise CMakeConfigureError(f"{label} must be an absolute path")
    if candidate.is_symlink() or not candidate.is_file():
        raise CMakeConfigureError(f"{label} is absent or redirected: {candidate}")
    resolved = candidate.resolve(strict=True)
    if resolved.is_symlink() or not os.access(resolved, os.X_OK):
        raise CMakeConfigureError(f"{label} is not a regular executable: {resolved}")
    return resolved


def _transport_sibling(directory: Path, name: str) -> Path:
    matches = tuple(
        item
        for item in directory.iterdir()
        if item.name.casefold() in {name.casefold(), f"{name}.exe".casefold()}
        and not item.is_symlink()
    )
    if len(matches) != 1:
        raise CMakeConfigureError(f"MSVC configure transport does not uniquely provide {name!r}")
    return _regular_executable(matches[0], label=f"{name} transport")


def _configure_environment(
    transport_directory: Path,
    *,
    include_directories: tuple[Path, ...] = (),
    library_directories: tuple[Path, ...] = (),
) -> dict[str, str]:
    environment = dict(os.environ)
    additions: list[tuple[str, str]] = [
        (
            "PATH",
            str(transport_directory)
            + os.pathsep
            + next(
                (current for key, current in environment.items() if key.casefold() == "path"),
                os.defpath,
            ),
        ),
        ("LANG", "C"),
        ("LC_ALL", "C"),
    ]
    if include_directories:
        additions.append(("INCLUDE", os.pathsep.join(map(str, include_directories))))
    if library_directories:
        additions.append(("LIB", os.pathsep.join(map(str, library_directories))))
    for canonical, value in additions:
        for key in tuple(environment):
            if key.casefold() == canonical.casefold():
                del environment[key]
        environment[canonical] = value
    return environment


def _require_regular_output(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise CMakeConfigureError(f"{label} is absent or redirected: {path}")


def _cmake_path(path: PurePath) -> str:
    """Render a filesystem path without CMake string escapes."""

    return path.as_posix()


def configure_cmake_project(
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
    defer_project_plan: bool = False,
    generator: str = "Unix Makefiles",
    make_program: Path | None = None,
) -> CMakeConfiguration:
    """Create one fresh Makefile tree for graph extraction.

    The workspace must be empty.  Its fixed ``source`` and ``build`` children,
    together with the returned target-plan path, can be passed directly to
    ``rbit graph extract``.  This operation configures but never builds.
    """

    if not isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
        raise CMakeConfigureError("CMake graph configuration requires the producer-graph adapter")
    if (
        bundle.source_manifest is None
        or not bundle.source_manifest.complete
        or (bundle.build_plan is None)
    ):
        raise CMakeConfigureError(
            "CMake graph configuration requires complete source/build authority"
        )
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise CMakeConfigureError("configure timeout must be positive and finite")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", configuration) is None:
        raise CMakeConfigureError("CMake configuration name is unsafe")
    if generator not in {"Unix Makefiles", "NMake Makefiles"}:
        raise CMakeConfigureError(f"unsupported CMake import generator: {generator!r}")
    if generator == "NMake Makefiles" and make_program is None:
        raise CMakeConfigureError("NMake Makefiles requires an explicit NMAKE program")

    project_root = project_root.resolve(strict=True)
    if project_root.is_symlink() or not project_root.is_dir():
        raise CMakeConfigureError("project root is absent or redirected")
    workspace_root = workspace_root.expanduser().resolve(strict=False)
    if workspace_root == project_root:
        raise CMakeConfigureError("CMake import workspace cannot be the project root")
    if workspace_root.is_symlink() or (workspace_root.exists() and not workspace_root.is_dir()):
        raise CMakeConfigureError("CMake import workspace is redirected or not a directory")
    if workspace_root.exists() and any(workspace_root.iterdir()):
        raise CMakeConfigureError(f"CMake import workspace is not empty: {workspace_root}")
    workspace_root.mkdir(parents=True, exist_ok=True)

    toolchain_root = toolchain_root.expanduser().resolve(strict=True)
    if toolchain_root.is_symlink() or not toolchain_root.is_dir():
        raise CMakeConfigureError("toolchain root is absent or redirected")
    cmake = _regular_executable(cmake, label="CMake executable")
    compiler = _regular_executable(compiler_transport, label="compiler transport")
    resource = _regular_executable(resource_transport, label="resource-compiler transport")
    try:
        compiler.relative_to(toolchain_root)
        resource.relative_to(toolchain_root)
    except ValueError as exc:
        raise CMakeConfigureError(
            "compiler transports must remain beneath the admitted toolchain root"
        ) from exc
    if compiler.parent != resource.parent:
        raise CMakeConfigureError(
            "compiler and resource transports must share one admitted directory"
        )
    linker = _transport_sibling(compiler.parent, "link")
    librarian = _transport_sibling(compiler.parent, "lib")
    make = (
        _regular_executable(make_program, label="CMake make program")
        if make_program is not None
        else None
    )
    if make is not None:
        try:
            make.relative_to(toolchain_root)
        except ValueError as exc:
            raise CMakeConfigureError(
                "CMake make program must remain beneath the admitted toolchain root"
            ) from exc

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
    bootstrap: Path | None = None
    if defer_project_plan:
        # CMAKE_PROJECT_INCLUDE runs during the top-level project() call.  It
        # makes the ReproBit functions available immediately, then defers the
        # generated target registrations until the directory has declared its
        # targets.  A normal CMake project therefore needs no source edit.
        bootstrap = workspace_root / "reprobit-cmake-import.cmake"
        bootstrap.write_text(
            "\n".join(
                (
                    "# Generated by ReproBit; do not edit.",
                    "get_property(_reprobit_import_scheduled GLOBAL PROPERTY "
                    "REPROBIT_CMAKE_IMPORT_SCHEDULED)",
                    "if(NOT _reprobit_import_scheduled)",
                    "  set_property(GLOBAL PROPERTY REPROBIT_CMAKE_IMPORT_SCHEDULED TRUE)",
                    f"  include({_cmake_quote(module.as_posix())})",
                    "  cmake_language(DEFER DIRECTORY "
                    f"{_cmake_quote(effective_root.as_posix())} "
                    "ID reprobit_import_plan CALL include "
                    f"{_cmake_quote(project_plan.as_posix())})",
                    "endif()",
                    "",
                )
            ),
            encoding="utf-8",
        )
    source_digest = effective_source_digest(effective_root)

    # NMake 4.2 cannot execute CMake's quoted progress-message recipe when
    # CMake is installed beneath ``Program Files``.  Progress recipes carry no
    # producer authority, so suppress them in the project and its try_compile
    # probes while retaining the real ABI and working-compiler checks.
    nmake_options = (
        (
            "-DCMAKE_RULE_MESSAGES=OFF",
            "-DCMAKE_TRY_COMPILE_PLATFORM_VARIABLES=CMAKE_RULE_MESSAGES",
        )
        if generator == "NMake Makefiles"
        else ()
    )

    command = (
        str(cmake),
        "-S",
        _cmake_path(effective_root),
        "-B",
        _cmake_path(configured_root),
        "-G",
        generator,
        f"-DCMAKE_BUILD_TYPE={configuration}",
        "-DCMAKE_SYSTEM_NAME=Windows",
        f"-DCMAKE_C_COMPILER={_cmake_path(compiler)}",
        f"-DCMAKE_CXX_COMPILER={_cmake_path(compiler)}",
        f"-DCMAKE_RC_COMPILER={_cmake_path(resource)}",
        f"-DCMAKE_LINKER={_cmake_path(linker)}",
        f"-DCMAKE_AR={_cmake_path(librarian)}",
        *nmake_options,
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        f"-DREPROBIT_CMAKE_MODULE={_cmake_path(module)}",
        f"-DREPROBIT_PROJECT_PLAN={_cmake_path(project_plan)}",
        f"-DREPROBIT_TARGET_PLAN={_cmake_path(target_plan)}",
        f"-DREPROBIT_EFFECTIVE_SOURCE_ROOT={_cmake_path(effective_root)}",
        "-DREPROBIT_TERMINAL=ON",
        *((f"-DCMAKE_MAKE_PROGRAM={_cmake_path(make)}",) if make is not None else ()),
        *((f"-DCMAKE_PROJECT_INCLUDE={_cmake_path(bootstrap)}",) if bootstrap is not None else ()),
    )
    include_directories: tuple[Path, ...] = ()
    library_directories: tuple[Path, ...] = ()
    if generator == "NMake Makefiles":
        from reprobit.toolchains import TOOLCHAIN_PROFILES

        profile = TOOLCHAIN_PROFILES[bundle.spec.toolchain.profile]
        include_directories = tuple(
            toolchain_root.joinpath(*PurePosixPath(relative).parts)
            for relative in profile.include_roots
        )
        library_directories = tuple(
            toolchain_root.joinpath(*PurePosixPath(relative).parts)
            for relative in profile.library_roots
        )
    specification = CommandSpec.create(
        command,
        cwd=effective_root,
        environment=_configure_environment(
            compiler.parent,
            include_directories=include_directories,
            library_directories=library_directories,
        ),
        timeout_seconds=timeout_seconds,
        log_path=configure_log,
    )
    try:
        with ProcessSupervisor() as supervisor:
            result = supervisor.run(specification)
    except ProcessError as exc:
        raise CMakeConfigureError(f"CMake import configure failed:\n{exc}") from exc
    if effective_source_digest(effective_root) != source_digest:
        raise CMakeConfigureError("CMake configure changed effective source authority")
    for path, label in (
        (configured_root / "Makefile", f"{generator} root"),
        (compile_database, "compile database"),
        (target_plan, "ReproBit target plan"),
        (configure_log, "configure log"),
        (project_plan, "ReproBit project plan"),
    ):
        _require_regular_output(path, label=label)
    export_plan = CMakeExportPlan.read(target_plan)
    if export_plan.link_admissions:
        raise CMakeConfigureError(
            "configured target plan declares link admissions that the direct "
            "producer graph cannot encode; remove them before graph extraction"
        )
    target_ids = {target.id for target in bundle.spec.targets}
    if {target.artifact_id for target in export_plan.targets} != target_ids or (
        len(export_plan.targets) != len(target_ids)
    ):
        raise CMakeConfigureError("configured target plan differs from project target authority")
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
    return CMakeConfiguration(
        configured_build_root=configured_root.resolve(strict=True),
        effective_source_root=effective_root.resolve(strict=True),
        effective_source_digest=source_digest,
        toolchain_root=toolchain_root,
        target_plan=target_plan.resolve(strict=True),
        compile_database=compile_database.resolve(strict=True),
        project_plan=project_plan.resolve(strict=True),
        configure_log=configure_log.resolve(strict=True),
        command=command,
        command_digest=command_digest,
        duration_seconds=result.duration_seconds,
    )


__all__ = [
    "CMakeConfiguration",
    "CMakeConfigureError",
    "configure_cmake_project",
    "effective_source_digest",
]
