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
from reprobit.classic_donor_retune_candidates import (
    DEFAULT_REPAIR_RETUNE_RADIUS,
    DEFAULT_RETUNE_CANDIDATES,
    MAX_RETUNE_CANDIDATES,
    MAX_RETUNE_RADIUS,
)
from reprobit.classic_repair_discovery import (
    DEFAULT_DISCOVERY_CANDIDATES,
    MAX_DISCOVERY_CANDIDATES,
)
from reprobit.classic_repair_probe import (
    DEFAULT_RETUNE_PROBE_CANDIDATES,
    MAX_RETUNE_PROBE_CANDIDATES,
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
    command_source_regenerate,
    command_status,
    command_validate,
)
from reprobit.cli_state import command_clean, command_state_status
from reprobit.discovery_cli import command_discover, command_discover_clean
from reprobit.model import AuthenticityPolicy
from reprobit.repair_workflow import MAX_REPAIR_ADJUSTMENT_ROUNDS
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


def _lazy_repair(args: argparse.Namespace, output: CLIOutput) -> int:
    from reprobit.cli_repair import command_repair

    return command_repair(args, output)


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


JOBS_CEILING = 8
"""Largest worker count chosen automatically when ``--jobs`` is omitted."""

_JOBS_DEFAULT_HELP = f"the CPUs this process may use, at most {JOBS_CEILING}"


def usable_cpu_count() -> int:
    """Return how many CPUs this process may run on, never below one."""

    process_count = getattr(os, "process_cpu_count", None)
    if process_count is not None:
        return max(1, process_count() or 1)
    affinity = getattr(os, "sched_getaffinity", None)
    if affinity is not None:
        return max(1, len(affinity(0)))
    return max(1, os.cpu_count() or 1)


def default_jobs() -> int:
    """Return the worker count used when ``--jobs`` is omitted.

    The value is the CPU count this process may use, capped at
    :data:`JOBS_CEILING` so that a many-core host does not start more Wine
    compilers than one wineserver serves well. It is computed once per
    invocation after parsing, not baked into the parser, so the generated
    command reference stays host-independent.
    """

    return min(usable_cpu_count(), JOBS_CEILING)


def _add_execution_options(
    command: argparse.ArgumentParser,
    *,
    cold_option: bool,
    keep_workspace_option: bool = True,
) -> None:
    command.add_argument(
        "--jobs",
        type=int,
        default=None,
        metavar="COUNT",
        help=f"maximum parallel build workers (default: {_JOBS_DEFAULT_HELP})",
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
                "keep the private workspace: never, only on failure, or always "
                "(default: on-failure)"
            ),
        )
    advanced = command.add_argument_group(
        "advanced execution options",
        "Defaults are suitable for people; these controls are mainly for CI and unusual hosts.",
    )
    _add_host_options(advanced, transports=True)
    _add_timeout_options(advanced)


_TOOLCHAIN_ROOT_HELP = "compiler installation override (normally remembered by rbit setup)"


def _add_host_options(
    group: argparse._ActionsContainer,
    *,
    backend: bool = True,
    wine: bool = True,
    toolchain_root: bool = True,
    toolchain_root_help: str = _TOOLCHAIN_ROOT_HELP,
    transports: bool = False,
) -> None:
    """Add the host-selection flags with one help text and metavar per flag.

    Every command that starts the compiler shares these; the flag set is the
    caller's choice, so a command never grows a flag its handler ignores.
    """

    if backend:
        group.add_argument(
            "--backend",
            choices=("auto", POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND),
            default="auto",
            help="execution backend (default: select from the host platform)",
        )
    if wine:
        group.add_argument(
            "--wine",
            default="wine",
            metavar="PATH_OR_NAME",
            help="POSIX Wine executable (default: wine from PATH)",
        )
        group.add_argument(
            "--wineserver",
            default="wineserver",
            metavar="PATH_OR_NAME",
            help="POSIX wineserver executable (default: wineserver from PATH)",
        )
    if toolchain_root:
        group.add_argument("--toolchain-root", metavar="DIRECTORY", help=toolchain_root_help)
    if transports:
        group.add_argument(
            "--compiler-transport",
            metavar="PATH",
            help=(
                "POSIX transport selector for the locked compiler "
                "(paired with --resource-transport)"
            ),
        )
        group.add_argument(
            "--resource-transport",
            metavar="PATH",
            help="POSIX transport selector for the locked resource compiler",
        )


def _add_timeout_options(
    group: argparse._ActionsContainer,
    *,
    initialization: bool = True,
    compile_default: float = 600.0,
    link: bool = True,
    cleanup_default: float = 10.0,
) -> None:
    """Add the per-step deadlines with one help text and metavar per flag."""

    if initialization:
        group.add_argument(
            "--initialization-timeout",
            type=_positive_seconds,
            default=600.0,
            metavar="SECONDS",
            help="limit for each isolated execution-lane initialization (default: 600)",
        )
    group.add_argument(
        "--compile-timeout",
        type=_positive_seconds,
        default=compile_default,
        metavar="SECONDS",
        help=f"limit for each compiler or resource-compiler step (default: {compile_default:g})",
    )
    if link:
        group.add_argument(
            "--link-timeout",
            type=_positive_seconds,
            default=900.0,
            metavar="SECONDS",
            help="limit for each librarian or linker producer (default: 900)",
        )
    group.add_argument(
        "--cleanup-timeout",
        type=_positive_seconds,
        default=cleanup_default,
        metavar="SECONDS",
        help=(
            "limit for stopping each isolated execution lane and its wineserver "
            f"(default: {cleanup_default:g})"
        ),
    )


def _add_project_argument(
    command: argparse.ArgumentParser,
    *,
    help: str = "project directory (default: .)",
    alias: bool = False,
) -> None:
    """Add the positional project directory, optionally with a hidden --project alias.

    ``--project`` was the spelling on toolchain lock, source export, graph
    configure and graph extract; it stays accepted but undocumented. The
    positional suppresses its own default so that a bare ``--project DIR``
    is not overwritten by the positional's absent value.
    """

    if alias:
        command.add_argument("--project", default=".", help=argparse.SUPPRESS)
        command.add_argument("project", nargs="?", default=argparse.SUPPRESS, help=help)
        return
    command.add_argument("project", nargs="?", default=".", help=help)


def _subcommand(
    commands: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    *,
    help: str,
    description: str | None = None,
) -> argparse.ArgumentParser:
    """Register one sub-command whose --help screen repeats its one-line summary.

    argparse shows ``help`` only in the parent's command list; without a
    ``description`` the command's own ``--help`` opens with a bare usage line.
    """

    if description is None:
        description = help[0].upper() + help[1:] + "."
    command = commands.add_parser(name, help=help, description=description)
    # Accept ``--format`` and ``--quiet`` after the sub-command as well as
    # before it. The defaults are suppressed so a root-level value survives
    # the sub-parser's namespace merge; the root options document the choice.
    command.add_argument(
        "--format",
        choices=("text", "ndjson"),
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    command.add_argument(
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    return command


_EPILOG = """\
exit status:
  0    the command completed and its result is ready, clean, or accepted
  1    an honest negative: status found missing setup, doctor or setup found a
       failing check, verify was not accepted, or discover grind did not find
       or save the requested result
  2    any error, including usage errors and unreadable project files
  130  interrupted with Ctrl-C; child processes were asked to drain

--format and --quiet may also follow the sub-command (rbit status --format ndjson).
Terms used in this help are defined in docs/glossary.md.
"""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbit",
        description=__doc__,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_VERSION}")
    parser.add_argument(
        "--format",
        choices=("text", "ndjson"),
        default="text",
        help="human-readable text or stable machine events (default: text)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "silence text-mode progress (phase starts, heartbeats, unit counts); "
            "results, warnings and errors still print; ndjson output is unchanged"
        ),
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    init = _subcommand(subcommands, "init", help="start a ReproBit project")
    _add_project_argument(init)
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
    init.add_argument(
        "--target",
        action="append",
        metavar="NAME",
        help="target name (repeatable; default: program)",
    )
    init.add_argument(
        "--artifact",
        action="append",
        metavar="[TARGET=]PATH",
        help=(
            "rebuilt output path for one target, or TARGET=PATH when repeated "
            "(default: build/TARGET.exe)"
        ),
    )
    init.add_argument(
        "--oracle",
        action="append",
        metavar="[TARGET=]PATH",
        help=(
            "original/reference path for one target, or TARGET=PATH when repeated "
            "(default: reference/TARGET.exe)"
        ),
    )
    init_advanced = init.add_argument_group(
        "advanced logical path options",
        "Compiler-visible DOS paths recorded in reprobit.toml; every run maps its private "
        "source, output, and toolchain trees to exactly these spellings.",
    )
    init_advanced.add_argument(
        "--logical-source",
        default=r"R:\source",
        metavar="DOS_PATH",
        help=r"compiler-visible root of the source tree (default: R:\source)",
    )
    init_advanced.add_argument(
        "--logical-build",
        default=r"R:\build",
        metavar="DOS_PATH",
        help=r"compiler-visible root of the build output tree (default: R:\build)",
    )
    init_advanced.add_argument(
        "--logical-toolchain",
        default=r"R:\toolchain",
        metavar="DOS_PATH",
        help=r"compiler-visible root of the compiler installation (default: R:\toolchain)",
    )
    init.set_defaults(handler=command_init)

    setup = _subcommand(
        subcommands,
        "setup",
        help="prepare the compiler and this machine for a project",
    )
    _add_project_argument(setup)
    setup.add_argument("--toolchain-root", metavar="DIRECTORY", help=_TOOLCHAIN_ROOT_HELP)
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
    _add_host_options(setup_advanced, toolchain_root=False)
    setup.set_defaults(handler=_lazy_setup)

    doctor = _subcommand(
        subcommands, "doctor", help="check whether the compiler can run correctly on this machine"
    )
    _add_project_argument(doctor)
    _add_host_options(doctor, toolchain_root=False)
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
        help="compiler installation to authenticate (default: check only the host backend)",
    )
    doctor.set_defaults(handler=_lazy_doctor)

    toolchain = _subcommand(
        subcommands, "toolchain", help="install and record exact compiler files"
    )
    toolchain_commands = toolchain.add_subparsers(dest="toolchain_command", required=True)
    provision = _subcommand(
        toolchain_commands,
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
    lock = _subcommand(
        toolchain_commands, "lock", help="record the exact compiler files this project expects"
    )
    _add_project_argument(lock, alias=True)
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

    source = _subcommand(
        subcommands, "source", help="review and lock the source files a build may read"
    )
    source_commands = source.add_subparsers(dest="source_command", required=True)
    source_preview = _subcommand(
        source_commands,
        "preview",
        help="show source changes and records that need review without writing",
    )
    _add_project_argument(source_preview)
    source_preview.add_argument(
        "--path",
        action="append",
        default=[],
        help="project-relative file or tree to inspect (repeatable; defaults to Git tracked files)",
    )
    source_preview.set_defaults(handler=command_source_preview)
    source_export = _subcommand(
        source_commands,
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
    _add_project_argument(source_export, alias=True)
    source_export.set_defaults(handler=command_source_export)
    source_lock = _subcommand(
        source_commands, "lock", help="safely record tracked or explicitly named source inputs"
    )
    _add_project_argument(source_lock)
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
    source_regenerate = _subcommand(
        source_commands,
        "regenerate",
        help="advanced: preview or apply saved source-record updates without building",
        description=(
            "Advanced maintenance tool. After editing an existing project file, normally "
            "run rbit repair . instead. This command only previews or applies the "
            "saved source-record updates; it does not build or verify the project."
        ),
    )
    _add_project_argument(source_regenerate)
    source_regenerate.add_argument(
        "--apply",
        action="store_true",
        help="save the changes shown by the preview (default: preview without writing)",
    )
    source_regenerate.set_defaults(handler=command_source_regenerate)

    import_command = _subcommand(
        subcommands, "import", help="prepare an existing project for direct ReproBit builds"
    )
    import_commands = import_command.add_subparsers(dest="import_command", required=True)
    cmake_import = _subcommand(
        import_commands,
        "cmake",
        help="prepare and record an ordinary CMake project in one guided run",
    )
    _add_project_argument(cmake_import)
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
    _add_host_options(cmake_import_advanced, backend=False, wine=False, transports=True)
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

    graph = _subcommand(
        subcommands, "graph", help="record the compiler and linker steps used by direct builds"
    )
    graph_commands = graph.add_subparsers(dest="graph_command", required=True)
    graph_configure = _subcommand(
        graph_commands,
        "configure",
        help="create a fresh CMake metadata tree without building",
    )
    _add_project_argument(graph_configure, alias=True)
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
    graph_extract = _subcommand(
        graph_commands,
        "extract",
        help="record direct compiler and linker steps from that CMake tree",
    )
    _add_project_argument(graph_extract, alias=True)
    graph_extract.add_argument(
        "--configured-build-root",
        required=True,
        metavar="DIRECTORY",
        help="CMake metadata tree created by rbit graph configure",
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
        command = _subcommand(subcommands, name, help=help_text)
        _add_project_argument(command)
        command.set_defaults(handler=handler)

    status = _subcommand(
        subcommands,
        "status",
        help="show what is ready and the next project setup step",
    )
    _add_project_argument(status)
    status.add_argument(
        "--all",
        action="store_true",
        help="include checks that already pass",
    )
    status.set_defaults(handler=command_status)

    clean = _subcommand(
        subcommands,
        "clean",
        help="remove inactive workspaces; cache and reports are opt-in",
    )
    _add_project_argument(clean)
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
    cache_cleanup = clean.add_mutually_exclusive_group()
    cache_cleanup.add_argument(
        "--cache",
        action="store_true",
        help=(
            "also remove incremental cache data selected by age and the complete repair "
            "search cache"
        ),
    )
    cache_cleanup.add_argument(
        "--obsolete-cache",
        action="store_true",
        help="also remove cache data this ReproBit version cannot reuse; keep the current cache",
    )
    clean.add_argument(
        "--reports",
        action="store_true",
        help="also remove the canonical verification and grind reports",
    )
    clean.set_defaults(handler=command_clean)

    explain = _subcommand(subcommands, "explain", help="explain saved interventions")
    _add_project_argument(explain)
    explain.add_argument(
        "--intervention",
        metavar="ID",
        help="show full details for one intervention",
    )
    explain.set_defaults(handler=command_explain)

    repair = _subcommand(
        subcommands,
        "repair",
        help="repair edits to already-locked source files and prove exact output",
        description=(
            "Use this after editing a file in a project that already matched exactly, "
            "including a shared header used by many source files. ReproBit repairs the "
            "saved build guidance in private, rebuilds, and publishes only after every "
            "target matches exactly. For added or removed files, start with source "
            "preview; it prints a safe next command when one is available."
        ),
    )
    _add_project_argument(repair)
    _add_execution_options(repair, cold_option=False)
    repair.add_argument(
        "--policy",
        choices=tuple(policy.value for policy in AuthenticityPolicy),
        help="optionally narrow the project's committed authenticity policy",
    )
    repair.add_argument(
        "--report-dir",
        metavar="PROJECT_RELATIVE_DIRECTORY",
        help="write report.json and report.html beneath this project directory",
    )
    search = repair.add_argument_group(
        "search bounds",
        "Widen the bounded search for larger repairs; a completed repair must still "
        "reproduce every expected output in a build from scratch.",
    )
    search.add_argument(
        "--retune-radius",
        type=int,
        default=None,
        metavar="DISTANCE",
        help=(
            "largest declaration-count change tried per saved compiler choice or source layout "
            f"(default: {DEFAULT_REPAIR_RETUNE_RADIUS}; max: {MAX_RETUNE_RADIUS})"
        ),
    )
    search.add_argument(
        "--retune-candidates",
        type=int,
        default=None,
        metavar="COUNT",
        help=(
            "maximum nearby settings tried per saved compiler choice or source layout "
            f"(default: {DEFAULT_RETUNE_CANDIDATES}; max: {MAX_RETUNE_CANDIDATES})"
        ),
    )
    search.add_argument(
        "--donor-candidates",
        type=int,
        default=None,
        metavar="COUNT",
        help=(
            "maximum nearby repair choices tested by the whole command "
            f"(default: {DEFAULT_RETUNE_PROBE_CANDIDATES}; max: {MAX_RETUNE_PROBE_CANDIDATES})"
        ),
    )
    search.add_argument(
        "--discovery-candidates",
        type=int,
        default=None,
        metavar="COUNT",
        help=(
            "fresh declaration settings built per affected source file after its saved "
            "compiler choices are exhausted "
            f"(default: {DEFAULT_DISCOVERY_CANDIDATES}; max: "
            f"{MAX_DISCOVERY_CANDIDATES})"
        ),
    )
    search.add_argument(
        "--adjustment-rounds",
        type=int,
        default=None,
        metavar="COUNT",
        help=(
            "maximum saved-guidance adjustment rounds before repair stops "
            f"(default: {MAX_REPAIR_ADJUSTMENT_ROUNDS})"
        ),
    )
    repair.set_defaults(
        handler=_lazy_repair,
        action_receipt=None,
        action_nonce=None,
    )

    build = _subcommand(
        subcommands,
        "build",
        help="incrementally rebuild changed compiler and linker steps without CMake",
    )
    _add_project_argument(build)
    _add_execution_options(build, cold_option=True)
    build.set_defaults(handler=command_build)

    verify = _subcommand(
        subcommands,
        "verify",
        help="build every target from scratch and check exact bytes and trust evidence",
    )
    _add_project_argument(verify)
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

    discover = _subcommand(
        subcommands,
        "discover",
        help="find and review low-cost compiler adjustments",
    )
    discover_commands = discover.add_subparsers(
        dest="discovery_command",
        required=True,
    )
    discover_init = _subcommand(
        discover_commands,
        "init",
        help="create a small automatic search plan without compiling",
    )
    _add_project_argument(discover_init)
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

    discover_run = _subcommand(
        discover_commands,
        "run",
        help="run a bounded request file (advanced)",
    )
    discover_run.add_argument("request", help="request JSON to run")
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
        default=None,
        metavar="COUNT",
        help=(
            f"maximum compiler workers (Wine is safely capped at 4; default: {_JOBS_DEFAULT_HELP})"
        ),
    )
    _add_host_options(discover_run, backend=False)
    _add_timeout_options(discover_run, initialization=False, compile_default=120.0, link=False)
    discover_run.set_defaults(handler=command_discover)

    discover_clean = _subcommand(
        discover_commands,
        "clean",
        help="preview or remove one advanced discovery campaign's reusable state",
    )
    discover_clean.add_argument("request", help="request JSON whose state should be removed")
    discover_clean.add_argument(
        "--state-directory",
        default=".reprobit-discovery",
        metavar="DIRECTORY",
        help="campaign state beside the request (default: .reprobit-discovery)",
    )
    discover_clean.add_argument(
        "--preview",
        action="store_true",
        help="show what would be removed without changing anything",
    )
    discover_clean.add_argument(
        "--all-requests",
        action="store_true",
        help="remove state shared by every request named in its ownership marker",
    )
    discover_clean.set_defaults(handler=command_discover_clean)

    discover_grind = _subcommand(
        discover_commands,
        "grind",
        help="find low-cost project adjustments, preview them, and optionally save proven work",
        description=(
            "Use this for a project's initial mismatch. Search a bounded, project-wide set "
            "of low-cost adjustments using project-owned reference .obj files. The default "
            "is a preview. Saved local progress does not prove the complete project; only a "
            "fresh byte-exact result does. For a later regression in an already-exact "
            "project, use rbit repair instead."
        ),
    )
    discover_grind.add_argument(
        "project",
        nargs="?",
        default=".",
        help="ReproBit project to search (default: .)",
    )
    grind_acceptance = discover_grind.add_mutually_exclusive_group()
    grind_acceptance.add_argument(
        "--accept-exact",
        action="store_true",
        help="save only if a fresh run reproduces the complete project exactly",
    )
    grind_acceptance.add_argument(
        "--accept-progress",
        action="store_true",
        help=(
            "save bounded, locally proven function adjustments even while the complete "
            "project still differs"
        ),
    )
    discover_grind.add_argument(
        "--reference-object",
        action="append",
        default=[],
        metavar="TU=PROJECT_PATH",
        help=("pair a translation unit with a reference .obj; repeat for additional units"),
    )
    discover_grind.add_argument(
        "--max-symbols",
        type=int,
        default=8,
        metavar="COUNT",
        help="maximum project functions to try in deterministic order (default: 8; max: 64)",
    )
    discover_grind.add_argument(
        "--expert-plan",
        dest="plan",
        metavar="PROJECT_RELATIVE_PATH",
        help="run one deliberately authored per-symbol plan instead of project-wide discovery",
    )
    _add_execution_options(
        discover_grind,
        cold_option=False,
        keep_workspace_option=False,
    )
    discover_grind.set_defaults(handler=_lazy_discover_grind)

    state = _subcommand(subcommands, "state", help="inspect local runs, cache, and reports")
    state_commands = state.add_subparsers(dest="state_command", required=True)
    state_status = _subcommand(
        state_commands,
        "status",
        help="show retained runs, cache, reports, active leases, and disk usage",
    )
    _add_project_argument(state_status)
    state_status.set_defaults(handler=command_state_status)
    report = _subcommand(subcommands, "report", help="validate JSON and render self-contained HTML")
    report.add_argument("input", help="canonical report.json to validate and render")
    report.add_argument(
        "--html",
        metavar="PATH",
        help="HTML output path (default: replace the input suffix with .html)",
    )
    report.set_defaults(handler=command_report)

    module = _subcommand(subcommands, "cmake-module", help="print the packaged CMake module path")
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
    output = CLIOutput(args.format, sys.stdout, sys.stderr, quiet=args.quiet)
    handler: Handler = args.handler
    if hasattr(args, "jobs") and args.jobs is None:
        args.jobs = default_jobs()
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
    except OSError as error:
        # Give a raw OS failure the same shape as every other error line:
        # which path, then the operating system's own explanation.
        if error.filename:
            message = f"error: cannot read {error.filename}: {error.strerror or error}"
        else:
            message = f"error: {error}"
        output.emit("error", message, error_type=type(error).__name__, diagnostic=True)
        return 2
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


__all__ = ["JOBS_CEILING", "default_jobs", "main", "usable_cpu_count"]
