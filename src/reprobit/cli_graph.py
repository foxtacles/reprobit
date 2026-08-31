"""Advanced CLI workflows for committed direct-producer graphs."""

from __future__ import annotations

import argparse
from pathlib import Path

from reprobit.cli_output import CLIOutput, count_phrase
from reprobit.cli_paths import (
    project_root,
    real_directory,
    resolve_program,
)
from reprobit.model import Digest
from reprobit.project_loader import load_project_tree


def command_graph_configure(args: argparse.Namespace, output: CLIOutput) -> int:
    """Create a fresh, non-certifying CMake tree for graph extraction."""

    from reprobit.cmake_configure import configure_cmake_project

    root = project_root(args.project)
    # Configuration is an import step and never executes a certifying build.
    # Load every other authority while deliberately omitting the graph being
    # replaced, which may legitimately bind the previous toolchain lock.
    bundle = load_project_tree(root, include_producer_graph=False)
    workspace = Path(args.workspace_root).expanduser()
    if not workspace.is_absolute():
        workspace = Path.cwd() / workspace
    toolchain = real_directory(args.toolchain_root, label="toolchain root")
    cmake = Path(resolve_program(args.cmake, root))

    def absolute_transport(value: str) -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        return candidate.resolve(strict=True)

    with output.activity("configuring CMake metadata"):
        result = configure_cmake_project(
            bundle,
            project_root=root,
            workspace_root=workspace,
            toolchain_root=toolchain,
            cmake=cmake,
            compiler_transport=absolute_transport(args.compiler_transport),
            resource_transport=absolute_transport(args.resource_transport),
            configuration=args.configuration,
            timeout_seconds=args.timeout,
        )
    output.emit(
        "producer_graph_configured",
        "configured build metadata; review it, then run rbit graph extract "
        f"with --configured-build-root {result.configured_build_root} and "
        f"--effective-source-root {result.effective_source_root}",
        configured_build_root=result.configured_build_root,
        effective_source_root=result.effective_source_root,
        toolchain_root=result.toolchain_root,
        target_plan=result.target_plan,
        compile_database=result.compile_database,
        project_plan=result.project_plan,
        configure_log=result.configure_log,
        command_digest=result.command_digest,
        effective_source_digest=result.effective_source_digest.value,
        duration_seconds=result.duration_seconds,
        certification_runtime=False,
    )
    return 0


def command_graph_extract(args: argparse.Namespace, output: CLIOutput) -> int:
    """Advanced CLI wrapper around the graph-recording service."""

    from reprobit.cmake_graph import record_cmake_graph

    root = project_root(args.project)
    target_plan = Path(args.target_plan).expanduser() if args.target_plan else None
    with output.activity("extracting a closed direct-producer graph"):
        result = record_cmake_graph(
            project_root=root,
            configured_build_root=Path(args.configured_build_root),
            effective_source_root=Path(args.effective_source_root),
            expected_effective_source_digest=Digest(value=args.effective_source_digest),
            toolchain_root=Path(args.toolchain_root),
            target_plan=target_plan,
            directive_inputs=args.directive_input,
            derive_translation_units=getattr(args, "derive_translation_units", False),
        )
    output.emit(
        "producer_graph_extracted",
        f"committed {count_phrase(len(result.graph.nodes), 'direct producer')} to {result.output}",
        output=result.output,
        extractor=result.graph.extractor,
        nodes=len(result.graph.nodes),
        roles=result.role_counts,
        graph_digest=result.graph_digest.value,
        transaction_id=result.transaction_id,
        translation_units=result.translation_units,
        skipped_translation_units=result.skipped_translation_units,
        certification_runtime="direct-locked-producers",
    )
    return 0
