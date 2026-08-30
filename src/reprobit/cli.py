"""Rebuild old binaries exactly and explain why the result can be trusted."""

from __future__ import annotations

import argparse
import math
import os
import sys
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version
from typing import TextIO

from reprobit.backends import (
    POSIX_WINE_BACKEND,
    WINDOWS_NATIVE_BACKEND,
)
from reprobit.cli_build import (
    command_build,
    command_verify,
    prepare_producer_graph_run,
)
from reprobit.cli_graph import (
    command_graph_configure,
    command_graph_extract,
)
from reprobit.cli_output import CLIOutput
from reprobit.cli_project import (
    command_cost,
    command_explain,
    command_init,
    command_report,
    command_source_export,
    command_source_lock,
    command_source_preview,
    command_status,
    command_validate,
)
from reprobit.cli_state import command_clean, command_state_status
from reprobit.discovery_cli import command_discover
from reprobit.model import AuthenticityPolicy
from reprobit.state import KeepWorkspace
from reprobit.toolchains import MSVC_42, TOOLCHAIN_PROFILES

try:
    _VERSION = version("reprobit")
except PackageNotFoundError:
    _VERSION = "0.1.0.dev0"


def _lazy_cmake_import(args: argparse.Namespace, output: CLIOutput) -> int:
    """Load the CMake importer only when that command is selected."""

    from reprobit.cli_cmake_import import command_cmake_import

    return command_cmake_import(args, output)


def _lazy_setup(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.onboarding import command_setup

    return command_setup(args, output)


def _lazy_toolchain_provision(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.onboarding import command_toolchain_provision

    return command_toolchain_provision(args, output)


def _lazy_doctor(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.onboarding import command_doctor

    return command_doctor(args, output)


def _lazy_toolchain_lock(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.onboarding import command_toolchain_lock

    return command_toolchain_lock(args, output)


def _lazy_discover_grind(args: argparse.Namespace, output: CLIOutput) -> int:
    """Delegate the bounded admission workflow without growing this CLI module."""

    from reprobit.discovery_grind_cli import command_discover_grind

    return command_discover_grind(
        args,
        output,
        prepare_run=prepare_producer_graph_run,
        verify_command=command_verify,
    )


def _lazy_discover_grind_init(args: argparse.Namespace, output: CLIOutput) -> int:
    """Load the guided grind setup only when that command is selected."""

    from reprobit.discovery_grind_cli import command_discover_grind_init

    return command_discover_grind_init(args, output)


def _command_cmake_module(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.cmake import cmake_module_path

    directory = cmake_module_path()
    value = directory / "ReproBit.cmake" if args.file else directory
    output.emit("cmake_module", str(value), path=value)
    return 0


Handler = Callable[[argparse.Namespace, CLIOutput], int]


def _positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number of seconds") from error
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return seconds


def _nonnegative_hours(value: str) -> float:
    try:
        hours = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number of hours") from error
    if not math.isfinite(hours) or hours < 0:
        raise argparse.ArgumentTypeError("must be a finite number at least zero")
    return hours


def _add_execution_options(
    command: argparse.ArgumentParser,
    *,
    cold_option: bool,
    keep_workspace_option: bool = True,
) -> None:
    command.add_argument(
        "--jobs",
        type=int,
        default=4,
        metavar="COUNT",
        help="maximum parallel build workers (default: 4)",
    )
    if cold_option:
        command.add_argument(
            "--cold",
            action="store_true",
            help="build from scratch without using the incremental cache",
        )
    if keep_workspace_option:
        command.add_argument(
            "--keep-workspace",
            choices=tuple(item.value for item in KeepWorkspace),
            default=KeepWorkspace.ON_FAILURE.value,
            help=(
                "retain run-private diagnostics never, on failure, or always (default: on-failure)"
            ),
        )
    advanced = command.add_argument_group(
        "advanced execution options",
        "Defaults are suitable for people; these controls are mainly for CI and unusual hosts.",
    )
    advanced.add_argument(
        "--backend",
        choices=("auto", POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND),
        default="auto",
        help="execution backend (default: select from the host platform)",
    )
    advanced.add_argument("--wine", default="wine", help="POSIX Wine executable or PATH name")
    advanced.add_argument(
        "--wineserver",
        default="wineserver",
        help="POSIX wineserver executable or PATH name",
    )
    advanced.add_argument(
        "--toolchain-root",
        metavar="DIRECTORY",
        help="physical root of the locally provisioned locked toolchain",
    )
    advanced.add_argument(
        "--compiler-transport",
        metavar="PATH",
        help="POSIX transport selector for the locked compiler (paired with resource transport)",
    )
    advanced.add_argument(
        "--resource-transport",
        metavar="PATH",
        help="POSIX transport selector for the locked resource compiler",
    )
    advanced.add_argument(
        "--initialization-timeout",
        type=_positive_seconds,
        default=600.0,
        metavar="SECONDS",
        help="limit for each isolated execution-lane initialization (default: 600)",
    )
    advanced.add_argument(
        "--compile-timeout",
        type=_positive_seconds,
        default=600.0,
        metavar="SECONDS",
        help="limit for each compiler or resource producer (default: 600)",
    )
    advanced.add_argument(
        "--link-timeout",
        type=_positive_seconds,
        default=900.0,
        metavar="SECONDS",
        help="limit for each librarian or linker producer (default: 900)",
    )
    advanced.add_argument(
        "--cleanup-timeout",
        type=_positive_seconds,
        default=10.0,
        metavar="SECONDS",
        help="limit for draining each isolated execution lane (default: 10)",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rbit", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {_VERSION}")
    parser.add_argument(
        "--format",
        choices=("text", "ndjson"),
        default="text",
        help="human-readable text or stable machine events (default: text)",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    init = subcommands.add_parser("init", help="start a ReproBit project")
    init.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
    init.add_argument(
        "--project-id",
        help="portable project name (default: derive it from the directory)",
    )
    init.add_argument(
        "--profile",
        choices=tuple(TOOLCHAIN_PROFILES),
        default="msvc_4_2",
        help="compiler profile (default: msvc_4_2)",
    )
    init.add_argument("--target", default="program", help="first target name")
    init.add_argument(
        "--artifact",
        help="candidate output path (default: build/TARGET.exe)",
    )
    init.add_argument(
        "--oracle",
        help="original/reference binary path (default: reference/TARGET.exe)",
    )
    init_advanced = init.add_argument_group("advanced logical path options")
    init_advanced.add_argument("--logical-source", default=r"R:\source")
    init_advanced.add_argument("--logical-build", default=r"R:\build")
    init_advanced.add_argument("--logical-toolchain", default=r"R:\toolchain")
    init.set_defaults(handler=command_init)

    setup = subcommands.add_parser(
        "setup",
        help="prepare the compiler and this machine for a project",
    )
    setup.add_argument("project", nargs="?", default=".", help="project directory (default: .)")
    setup.add_argument(
        "--toolchain-root",
        metavar="DIRECTORY",
        help="use an existing compiler installation instead of the remembered/default path",
    )
    setup.add_argument(
        "--no-provision",
        action="store_true",
        help="fail instead of downloading a missing supported compiler",
    )
    setup.add_argument(
        "--no-save",
        action="store_true",
        help="do not remember this machine's compiler location",
    )
    setup.add_argument(
        "--skip-probe",
        action="store_true",
        help="skip the bounded execution probe (faster, but less complete)",
    )
    setup_advanced = setup.add_argument_group("advanced host options")
    setup_advanced.add_argument(
        "--backend",
        choices=("auto", POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND),
        default="auto",
    )
    setup_advanced.add_argument("--wine", default="wine")
    setup_advanced.add_argument("--wineserver", default="wineserver")
    setup.set_defaults(handler=_lazy_setup)

    doctor = subcommands.add_parser(
        "doctor", help="check whether the compiler can run correctly on this machine"
    )
    doctor.add_argument("project", nargs="?", default=".", help="project directory (default: .)")
    doctor.add_argument(
        "--backend",
        choices=("auto", POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND),
        default="auto",
    )
    doctor.add_argument("--wine", default="wine", help="POSIX Wine executable or PATH name")
    doctor.add_argument(
        "--wineserver", default="wineserver", help="POSIX wineserver executable or PATH name"
    )
    doctor.add_argument(
        "--execute-probe",
        action="store_true",
        help="also run the bounded compiler child-process test",
    )
    doctor.add_argument(
        "--toolchain-profile",
        choices=tuple(TOOLCHAIN_PROFILES),
        help="compiler profile when checking an installation without a project",
    )
    doctor.add_argument(
        "--toolchain-root",
        metavar="DIRECTORY",
        help="compiler installation to authenticate",
    )
    doctor.set_defaults(handler=_lazy_doctor)

    toolchain = subcommands.add_parser("toolchain", help="install and record exact compiler files")
    toolchain_commands = toolchain.add_subparsers(dest="toolchain_command", required=True)
    provision = toolchain_commands.add_parser(
        "provision",
        help="download and authenticate a supported compiler",
    )
    provision.add_argument(
        "profile",
        nargs="?",
        choices=tuple(TOOLCHAIN_PROFILES),
        default=MSVC_42,
        help="compiler profile (default: msvc_4_2)",
    )
    provision.add_argument(
        "--destination",
        metavar="DIRECTORY",
        help="installation directory (default: this platform's standard user location)",
    )
    provision.add_argument(
        "--no-save",
        action="store_true",
        help="do not remember the installed compiler location",
    )
    provision.set_defaults(handler=_lazy_toolchain_provision)
    lock = toolchain_commands.add_parser(
        "lock", help="record the exact compiler files this project expects"
    )
    lock.add_argument(
        "--project", default=".", help="project containing reprobit.toml (default: .)"
    )
    lock.add_argument(
        "--profile",
        choices=tuple(TOOLCHAIN_PROFILES),
        help="compiler profile (default: read it from reprobit.toml)",
    )
    lock.add_argument(
        "--root",
        help="compiler installation override (normally remembered by rbit setup)",
    )
    lock.add_argument(
        "--runtime-file",
        action="append",
        default=[],
        metavar="RELATIVE_PATH",
        help="pin an additional wrapper or runtime dependency (repeatable)",
    )
    lock.add_argument(
        "--output",
        metavar="PROJECT_RELATIVE_PATH",
        help="lock-file path (default: read it from reprobit.toml)",
    )
    lock.set_defaults(handler=_lazy_toolchain_lock)

    source = subcommands.add_parser(
        "source", help="review and lock the source files a build may read"
    )
    source_commands = source.add_subparsers(dest="source_command", required=True)
    source_preview = source_commands.add_parser(
        "preview", help="show source changes and records that need review without writing"
    )
    source_preview.add_argument(
        "--project", default=".", help="project containing reprobit.toml (default: .)"
    )
    source_preview.add_argument(
        "--path",
        action="append",
        default=[],
        help="project-relative file or tree to inspect (repeatable; defaults to Git tracked files)",
    )
    source_preview.set_defaults(handler=command_source_preview)
    source_export = source_commands.add_parser(
        "export",
        help="write the reviewed effective source view used by compilers and analysis tools",
    )
    source_export.add_argument(
        "destination",
        nargs="?",
        default="build/reprobit-source",
        help=(
            "project-relative directory to create or safely refresh "
            "(default: build/reprobit-source)"
        ),
    )
    source_export.add_argument(
        "--project", default=".", help="project containing reprobit.toml (default: .)"
    )
    source_export.set_defaults(handler=command_source_export)
    source_lock = source_commands.add_parser(
        "lock", help="safely record tracked or explicitly named source inputs"
    )
    source_lock.add_argument(
        "--project", default=".", help="project containing reprobit.toml (default: .)"
    )
    source_lock.add_argument(
        "--path",
        action="append",
        default=[],
        help="project-relative file or tree to admit (repeatable; defaults to Git tracked files)",
    )
    source_lock.add_argument(
        "--invalidate-producer-graph",
        action="store_true",
        help="remove a stale generated graph in the same transaction after source changes",
    )
    source_lock.set_defaults(handler=command_source_lock)

    import_command = subcommands.add_parser(
        "import", help="turn an existing project build into ReproBit build authority"
    )
    import_commands = import_command.add_subparsers(dest="import_command", required=True)
    cmake_import = import_commands.add_parser(
        "cmake",
        help="prepare and record an ordinary CMake project in one guided run",
    )
    cmake_import.add_argument(
        "project", nargs="?", default=".", help="project directory (default: .)"
    )
    cmake_import.add_argument(
        "--target",
        action="append",
        default=[],
        metavar="TARGET=CMAKE_TARGET",
        help="map a ReproBit target when its CMake target has a different name",
    )
    cmake_import.add_argument(
        "--keep-workspace",
        choices=tuple(item.value for item in KeepWorkspace),
        default=KeepWorkspace.ON_FAILURE.value,
        help="retain temporary import files: never, on-failure (default), or always",
    )
    cmake_import_advanced = cmake_import.add_argument_group("advanced host and graph options")
    cmake_import_advanced.add_argument(
        "--toolchain-root",
        metavar="DIRECTORY",
        help="compiler installation override (normally remembered by rbit setup)",
    )
    cmake_import_advanced.add_argument(
        "--compiler-transport",
        metavar="PATH",
        help="compiler frontend override used only while CMake configures",
    )
    cmake_import_advanced.add_argument(
        "--resource-transport",
        metavar="PATH",
        help="resource-compiler frontend paired with --compiler-transport",
    )
    cmake_import_advanced.add_argument(
        "--cmake",
        default="cmake",
        metavar="PATH_OR_NAME",
        help="CMake executable (default: resolve cmake from PATH)",
    )
    cmake_import_advanced.add_argument(
        "--configuration",
        default="RelWithDebInfo",
        help="single-configuration CMake build type (default: RelWithDebInfo)",
    )
    cmake_import_advanced.add_argument(
        "--timeout",
        type=_positive_seconds,
        default=600.0,
        metavar="SECONDS",
        help="bounded configure deadline (default: 600)",
    )
    cmake_import_advanced.add_argument(
        "--directive-input",
        action="append",
        default=[],
        metavar="TARGET=LIBRARY",
        help="record one prelink-discovered default library edge (repeatable)",
    )
    cmake_import.set_defaults(handler=_lazy_cmake_import)

    graph = subcommands.add_parser(
        "graph", help="record the compiler and linker steps used by direct builds"
    )
    graph_commands = graph.add_subparsers(dest="graph_command", required=True)
    graph_configure = graph_commands.add_parser(
        "configure",
        help="create a fresh CMake metadata tree without building",
    )
    graph_configure.add_argument(
        "--project", default=".", help="project containing reprobit.toml (default: .)"
    )
    graph_configure.add_argument(
        "--workspace-root",
        required=True,
        metavar="EMPTY_DIRECTORY",
        help="new or empty workspace that will receive fixed source/ and build/ trees",
    )
    graph_configure.add_argument(
        "--toolchain-root",
        required=True,
        metavar="DIRECTORY",
        help="physical root of the locally provisioned locked toolchain",
    )
    graph_configure.add_argument(
        "--compiler-transport",
        required=True,
        metavar="PATH",
        help="admitted compiler frontend used only for CMake feature detection",
    )
    graph_configure.add_argument(
        "--resource-transport",
        required=True,
        metavar="PATH",
        help="admitted resource-compiler frontend paired with the compiler transport",
    )
    graph_configure.add_argument(
        "--cmake",
        default="cmake",
        metavar="PATH_OR_NAME",
        help="CMake executable (default: resolve cmake from PATH)",
    )
    graph_configure.add_argument(
        "--configuration",
        default="RelWithDebInfo",
        help="single-configuration CMake build type (default: RelWithDebInfo)",
    )
    graph_configure.add_argument(
        "--timeout",
        type=_positive_seconds,
        default=600.0,
        metavar="SECONDS",
        help="bounded configure deadline (default: 600)",
    )
    graph_configure.set_defaults(handler=command_graph_configure)
    graph_extract = graph_commands.add_parser(
        "extract",
        help="record direct compiler and linker steps from that CMake tree",
    )
    graph_extract.add_argument(
        "--project", default=".", help="project containing reprobit.toml (default: .)"
    )
    graph_extract.add_argument(
        "--configured-build-root",
        required=True,
        metavar="DIRECTORY",
        help="CMake Unix Makefiles tree created by rbit graph configure",
    )
    graph_extract.add_argument(
        "--effective-source-root",
        required=True,
        metavar="DIRECTORY",
        help="effective source tree whose physical paths match the configured commands",
    )
    graph_extract.add_argument(
        "--effective-source-digest",
        required=True,
        metavar="SHA256",
        help="source receipt printed by the matching rbit graph configure run",
    )
    graph_extract.add_argument(
        "--toolchain-root",
        required=True,
        metavar="DIRECTORY",
        help="physical root matching the committed logical toolchain seat",
    )
    graph_extract.add_argument(
        "--target-plan",
        help="path beneath the configured build (defaults to reprobit-target-plan.json)",
    )
    graph_extract.add_argument(
        "--directive-input",
        action="append",
        default=[],
        metavar="TARGET=LIBRARY",
        help=("commit one prelink-discovered DEFAULTLIB edge; repeat for each target/library"),
    )
    graph_extract.set_defaults(handler=command_graph_extract)

    for name, help_text, handler in (
        ("validate", "check every saved project file", command_validate),
        ("cost", "show intervention cost totals", command_cost),
    ):
        command = subcommands.add_parser(name, help=help_text)
        command.add_argument(
            "project", nargs="?", default=".", help="project directory (default: .)"
        )
        command.set_defaults(handler=handler)

    status = subcommands.add_parser(
        "status",
        help="show what is ready and the next project setup step",
    )
    status.add_argument("project", nargs="?", default=".", help="project directory (default: .)")
    status.add_argument(
        "--all",
        action="store_true",
        help="include checks that already pass",
    )
    status.set_defaults(handler=command_status)

    clean = subcommands.add_parser(
        "clean",
        help="remove inactive workspaces; cache and reports are opt-in",
    )
    clean.add_argument("project", nargs="?", default=".", help="project directory (default: .)")
    clean.add_argument(
        "--preview",
        action="store_true",
        help="show how much space can be freed without removing anything",
    )
    clean.add_argument(
        "--older-than-hours",
        type=_nonnegative_hours,
        default=None,
        metavar="HOURS",
        help="keep workspace and cache entries newer than this age (default: 0)",
    )
    clean.add_argument(
        "--cache",
        action="store_true",
        help="also remove cache records and blobs old enough for the selected age",
    )
    clean.add_argument(
        "--reports",
        action="store_true",
        help="also remove the canonical verification and grind reports",
    )
    clean.set_defaults(handler=command_clean)

    explain = subcommands.add_parser("explain", help="explain saved interventions")
    explain.add_argument("project", nargs="?", default=".", help="project directory (default: .)")
    explain.add_argument(
        "--intervention",
        metavar="ID",
        help="show full details for one intervention",
    )
    explain.set_defaults(handler=command_explain)

    build = subcommands.add_parser(
        "build",
        help="incrementally rebuild changed compiler and linker steps without CMake",
    )
    build.add_argument("project", nargs="?", default=".", help="project directory (default: .)")
    _add_execution_options(build, cold_option=True)
    build.set_defaults(handler=command_build)

    verify = subcommands.add_parser(
        "verify",
        help="build every target from scratch and check exact bytes and trust evidence",
    )
    verify.add_argument("project", nargs="?", default=".", help="project directory (default: .)")
    _add_execution_options(verify, cold_option=False)
    verify.add_argument(
        "--policy",
        choices=tuple(policy.value for policy in AuthenticityPolicy),
        help="optionally narrow the project's committed authenticity policy",
    )
    verify.add_argument(
        "--report-dir",
        metavar="PROJECT_RELATIVE_DIRECTORY",
        help="write report.json and report.html beneath this project directory",
    )
    verify.add_argument(
        "--action-receipt",
        metavar="PATH",
        help="publish a nonce-bound completion receipt after both reports finalize",
    )
    verify.add_argument(
        "--action-nonce",
        metavar="LOWERCASE_SHA256",
        help="64-hex invocation nonce paired with --action-receipt",
    )
    verify.set_defaults(handler=command_verify)

    discover = subcommands.add_parser(
        "discover",
        help="find low-cost compiler adjustments and save only proven results",
    )
    discover_commands = discover.add_subparsers(
        dest="discovery_command",
        required=True,
    )
    discover_init = discover_commands.add_parser(
        "init",
        help="create a small automatic search plan without compiling",
    )
    discover_init.add_argument(
        "project", nargs="?", default=".", help="project directory (default: .)"
    )
    discover_init.add_argument(
        "--source",
        required=True,
        help="project-relative source file to explore",
    )
    discover_init.add_argument(
        "--reference",
        required=True,
        metavar="OBJECT_PATH",
        help="project-relative .obj file containing the reference function",
    )
    discover_init.add_argument("--symbol", required=True, help="decorated function symbol")
    discover_init.add_argument(
        "--translation-unit",
        help="select one build of the source only when it is compiled more than once",
    )
    discover_init.add_argument(
        "--plan",
        default="reprobit/discovery.json",
        metavar="PROJECT_RELATIVE_PATH",
        help="new plan path (default: reprobit/discovery.json)",
    )
    discover_init.set_defaults(handler=_lazy_discover_grind_init)

    discover_run = discover_commands.add_parser(
        "run",
        help="run a bounded request file (advanced)",
    )
    discover_run.add_argument("request", help="request JSON to run")
    discover_run.add_argument(
        "--toolchain-root",
        metavar="DIRECTORY",
        help="compiler installation override (normally remembered by rbit setup)",
    )
    discover_run.add_argument(
        "--report-json",
        metavar="PATH",
        help=("canonical JSON report beside the request (default: REQUEST_STEM.report.json)"),
    )
    discover_run.add_argument(
        "--report-html",
        metavar="PATH",
        help=("human review report beside the JSON report (default: REQUEST_STEM.report.html)"),
    )
    discover_run.add_argument(
        "--state-directory",
        default=".reprobit-discovery",
        metavar="DIRECTORY",
        help="incremental cache and runtime state beside the request",
    )
    discover_run.add_argument(
        "--jobs",
        type=int,
        default=4,
        metavar="COUNT",
        help="maximum compiler workers (Wine is safely capped at 4; default: 4)",
    )
    discover_run.add_argument(
        "--compile-timeout",
        type=_positive_seconds,
        default=120.0,
        metavar="SECONDS",
        help="limit for each compiler cell (default: 120)",
    )
    discover_run.add_argument(
        "--wine",
        default="wine",
        metavar="PATH_OR_NAME",
        help="POSIX Wine executable (default: wine from PATH)",
    )
    discover_run.add_argument(
        "--wineserver",
        default="wineserver",
        metavar="PATH_OR_NAME",
        help="POSIX wineserver executable (default: wineserver from PATH)",
    )
    discover_run.add_argument(
        "--cleanup-timeout",
        type=_positive_seconds,
        default=10.0,
        metavar="SECONDS",
        help="limit for stopping and reaping the private wineserver (default: 10)",
    )
    discover_run.set_defaults(handler=command_discover)

    discover_grind = discover_commands.add_parser(
        "grind",
        help="try low-cost adjustments and keep only a freshly verified exact match",
    )
    discover_grind.add_argument(
        "project",
        nargs="?",
        default=".",
        help="ReproBit project to search (default: .)",
    )
    discover_grind.add_argument(
        "--accept-exact",
        action="store_true",
        help="rerun the proof and save an exact solution if it still passes",
    )
    discover_grind.add_argument(
        "--project-wide",
        action="store_true",
        help="try a bounded set of eligible project functions instead of one plan",
    )
    discover_grind.add_argument(
        "--reference-object",
        action="append",
        default=[],
        metavar="TU=PROJECT_PATH",
        help=(
            "pair a translation unit with a reference .obj in project-wide mode; "
            "repeat for additional units"
        ),
    )
    discover_grind.add_argument(
        "--max-symbols",
        type=int,
        default=8,
        metavar="COUNT",
        help="maximum project functions to try in deterministic order (default: 8; max: 64)",
    )
    discover_grind.add_argument(
        "--plan",
        default="reprobit/discovery.json",
        metavar="PROJECT_RELATIVE_PATH",
        help="project discovery plan (default: reprobit/discovery.json)",
    )
    _add_execution_options(
        discover_grind,
        cold_option=False,
        keep_workspace_option=False,
    )
    discover_grind.set_defaults(handler=_lazy_discover_grind)

    state = subcommands.add_parser("state", help="inspect local runs, cache, and reports")
    state_commands = state.add_subparsers(dest="state_command", required=True)
    state_status = state_commands.add_parser(
        "status", help="show retained runs, cache, reports, active leases, and disk usage"
    )
    state_status.add_argument(
        "project", nargs="?", default=".", help="project directory (default: .)"
    )
    state_status.set_defaults(handler=command_state_status)
    report = subcommands.add_parser("report", help="validate JSON and render self-contained HTML")
    report.add_argument("input", help="canonical report.json to validate and render")
    report.add_argument(
        "--html",
        metavar="PATH",
        help="HTML output path (default: replace the input suffix with .html)",
    )
    report.set_defaults(handler=command_report)

    module = subcommands.add_parser("cmake-module", help="print the packaged CMake module path")
    module.add_argument(
        "--file",
        action="store_true",
        help="print the packaged ReproBit.cmake file instead of its directory",
    )
    module.set_defaults(handler=_command_cmake_module)
    return parser


def _silence_broken_pipe(stream: TextIO) -> None:
    """Redirect a closed standard stream so interpreter shutdown stays quiet."""

    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return
    null_descriptor = -1
    try:
        null_descriptor = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null_descriptor, descriptor)
    except OSError:
        return
    finally:
        if null_descriptor >= 0:
            os.close(null_descriptor)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = CLIOutput(args.format, sys.stdout, sys.stderr)
    handler: Handler = args.handler
    if getattr(args, "jobs", 1) < 1:
        output.emit(
            "error",
            "error: --jobs must be at least one",
            error_type="CLIError",
            diagnostic=True,
        )
        return 2
    try:
        return handler(args, output)
    except KeyboardInterrupt:
        output.emit(
            "interrupted",
            "interrupted; active child processes were asked to drain",
            error_type="KeyboardInterrupt",
            exit_code=130,
            diagnostic=True,
        )
        return 130
    except BrokenPipeError:
        # A downstream pager or selector (for example, ``head``) consumed all
        # the output it requested.  Do not turn that normal pipeline close
        # into a traceback, and do not attempt a second write to the same pipe.
        _silence_broken_pipe(output.stdout)
        return 0
    except Exception as error:
        output.emit(
            "error",
            f"error: {error}",
            error_type=type(error).__name__,
            diagnostic=True,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
