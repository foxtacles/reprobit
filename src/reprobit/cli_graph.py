"""Migration-only CLI workflows for committed direct-producer graphs."""

from __future__ import annotations

import argparse
import re
from pathlib import Path, PurePosixPath

from reprobit.cli_output import CLIOutput
from reprobit.cli_paths import (
    CLIError,
    project_root,
    relative_output,
    resolve_program,
    safe_project_path,
)
from reprobit.migration import validate_migration_files
from reprobit.model import Digest
from reprobit.producer_graph import (
    graph_reference,
    producer_graph_digest,
    source_topology_digest,
    toolchain_document_digest,
)
from reprobit.producer_graph_cmake import extract_cmake_unix_makefiles_graph
from reprobit.project_loader import load_project, load_project_tree
from reprobit.schema import (
    ProducerGraphBuildAdapter,
    ProjectSpec,
    SourceManifestDocument,
)
from reprobit.strict_json import canonical_json, strict_load
from reprobit.transactions import CASTransaction


def _real_directory(value: str, *, label: str) -> Path:
    candidate = Path(value).expanduser()
    if candidate.is_symlink() or not candidate.is_dir():
        raise CLIError(f"{label} is not an existing real directory: {candidate}")
    return candidate.resolve(strict=True)


def _producer_graph_validation_files(
    root: Path,
    spec: ProjectSpec,
    graph_data: bytes,
) -> tuple[dict[PurePosixPath, bytes], tuple[PurePosixPath, ...]]:
    """Snapshot every document needed to validate a candidate graph."""

    files: dict[PurePosixPath, bytes] = {}
    authority: list[PurePosixPath] = []

    def admit(relative_text: str, *, required: bool = True) -> None:
        relative = PurePosixPath(relative_text.replace("\\", "/"))
        path = safe_project_path(root, relative.as_posix())
        if not path.exists() and not required:
            return
        if path.is_symlink() or not path.is_file():
            raise CLIError(f"graph-validation authority is absent or redirected: {relative}")
        files[relative] = path.read_bytes()
        authority.append(relative)

    admit("reprobit.toml")
    admit(spec.toolchain.lock_file)
    admit(spec.layout.source_manifest)
    admit(spec.layout.build_plan, required=False)
    for directory_text in (
        spec.layout.interventions,
        spec.layout.proofs,
        spec.layout.oracles,
    ):
        directory = safe_project_path(root, directory_text)
        if directory.is_symlink() or not directory.is_dir():
            raise CLIError(
                f"graph-validation manifest directory is absent or redirected: {directory}"
            )
        for path in sorted(directory.rglob("*.json"), key=lambda item: item.as_posix()):
            if path.is_symlink() or not path.is_file():
                raise CLIError(f"graph-validation document is redirected: {path}")
            relative = PurePosixPath(path.relative_to(root).as_posix())
            files[relative] = path.read_bytes()
            authority.append(relative)
    graph_relative = PurePosixPath(spec.layout.producer_graph.replace("\\", "/"))
    files[graph_relative] = graph_data
    return files, tuple(sorted(set(authority), key=lambda item: item.as_posix()))


def command_graph_configure(args: argparse.Namespace, output: CLIOutput) -> int:
    """Create a fresh, non-certifying CMake tree for graph extraction."""

    from reprobit.classic_migration import configure_classic_producer_graph

    root = project_root(args.project)
    # Configuration is migration-only and never executes a certifying build.
    # Load every other authority while deliberately omitting the graph being
    # replaced, which may legitimately bind the previous toolchain lock.
    bundle = load_project_tree(root, include_producer_graph=False)
    workspace = Path(args.workspace_root).expanduser()
    if not workspace.is_absolute():
        workspace = Path.cwd() / workspace
    toolchain = _real_directory(args.toolchain_root, label="toolchain root")
    cmake = Path(resolve_program(args.cmake, root))

    def absolute_transport(value: str) -> Path:
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        return candidate.resolve(strict=True)

    with output.activity("configuring migration-only Unix Makefiles authority"):
        result = configure_classic_producer_graph(
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
        "configured migration metadata; review it, then run `rbit graph extract` "
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
        duration_seconds=result.duration_seconds,
        certification_runtime=False,
    )
    return 0


def command_graph_extract(args: argparse.Namespace, output: CLIOutput) -> int:
    """Commit a reviewed direct-producer graph from one configured CMake tree.

    This is deliberately a migration command. Certifying builds consume its
    committed result and never execute CMake or another project build system.
    """

    from reprobit.cmake import CMakeExportPlan
    from reprobit.schema import ToolchainLock as SchemaToolchainLock

    root = project_root(args.project)
    spec = load_project(root)
    if not isinstance(spec.build, ProducerGraphBuildAdapter):
        raise CLIError("producer-graph extraction requires a producer-graph project")
    configured = _real_directory(args.configured_build_root, label="configured build root")
    effective = _real_directory(args.effective_source_root, label="effective source root")
    toolchain = _real_directory(args.toolchain_root, label="toolchain root")

    source_path = safe_project_path(root, spec.layout.source_manifest)
    lock_path = safe_project_path(root, spec.toolchain.lock_file)
    for authority_path, label in (
        (source_path, "source manifest"),
        (lock_path, "toolchain lock"),
    ):
        if authority_path.is_symlink() or not authority_path.is_file():
            raise CLIError(f"{label} is absent or redirected: {authority_path}")
    source_document = SourceManifestDocument.model_validate_json(
        canonical_json(strict_load(source_path))
    )
    lock_document = SchemaToolchainLock.model_validate_json(canonical_json(strict_load(lock_path)))
    if not source_document.complete:
        raise CLIError("producer-graph extraction requires a complete source manifest")
    if lock_document.profile != spec.toolchain.profile:
        raise CLIError("toolchain lock profile differs from reprobit.toml")

    target_plan_path = (
        Path(args.target_plan).expanduser()
        if args.target_plan
        else configured / "reprobit-target-plan.json"
    )
    if not target_plan_path.is_absolute():
        target_plan_path = configured / target_plan_path
    target_plan_path = target_plan_path.resolve(strict=False)
    try:
        target_plan_path.relative_to(configured)
    except ValueError as error:
        raise CLIError("target plan must remain beneath the configured build root") from error
    if target_plan_path.is_symlink() or not target_plan_path.is_file():
        raise CLIError(f"target plan is absent or redirected: {target_plan_path}")
    target_plan = CMakeExportPlan.read(target_plan_path)
    if target_plan.link_admissions:
        raise CLIError(
            "target plan declares link admissions that the direct producer graph "
            "cannot encode; remove them before extraction"
        )
    project_targets = {target.id for target in spec.targets}
    plan_targets = {target.artifact_id for target in target_plan.targets}
    if len(plan_targets) != len(target_plan.targets) or plan_targets != project_targets:
        missing = sorted(project_targets - plan_targets)
        extra = sorted(plan_targets - project_targets)
        raise CLIError(f"target-plan artifact mismatch; missing={missing}, extra={extra}")
    target_outputs: dict[str, str] = {}
    target_specs = {target.id: target for target in spec.targets}
    for target in target_plan.targets:
        raw_output = Path(target.output)
        candidate = raw_output if raw_output.is_absolute() else configured / raw_output
        candidate = candidate.resolve(strict=False)
        try:
            relative = candidate.relative_to(configured)
        except ValueError as error:
            raise CLIError(
                f"target-plan output escapes configured build: {target.output!r}"
            ) from error
        expected_artifact = target_specs[target.artifact_id].artifact
        graph_artifact = f"build/{relative.as_posix()}"
        if graph_artifact != expected_artifact:
            raise CLIError(
                f"target-plan output for {target.artifact_id!r} is "
                f"{graph_artifact!r}; project artifact is {expected_artifact!r}"
            )
        target_outputs[target.artifact_id] = relative.as_posix()

    directive_inputs: dict[str, list[str]] = {}
    seen_directives: set[tuple[str, str]] = set()
    for declaration in args.directive_input:
        target_id, separator, library = declaration.partition("=")
        if not separator or not target_id or not library or "=" in library:
            raise CLIError("--directive-input must use the exact TARGET=LIBRARY form")
        if target_id not in project_targets:
            raise CLIError(f"--directive-input names unknown target {target_id!r}")
        if re.fullmatch(r"[A-Za-z0-9_.+@-]+", library) is None:
            raise CLIError("--directive-input library must be one bare library name")
        normalized_library = library.casefold()
        if not normalized_library.endswith(".lib"):
            normalized_library += ".lib"
        try:
            reference = graph_reference("system-library", normalized_library)
        except ValueError as exc:
            raise CLIError(f"invalid --directive-input library {library!r}: {exc}") from exc
        identity = (target_id.casefold(), reference.casefold())
        if identity in seen_directives:
            raise CLIError(f"duplicate --directive-input {target_id}={normalized_library}")
        seen_directives.add(identity)
        directive_inputs.setdefault(target_id, []).append(reference)
    committed_directive_inputs = {
        target_id: tuple(sorted(references, key=str.casefold))
        for target_id, references in sorted(
            directive_inputs.items(), key=lambda item: item[0].casefold()
        )
    }

    with output.activity("extracting a closed direct-producer graph"):
        graph = extract_cmake_unix_makefiles_graph(
            configured_build_root=configured,
            effective_source_root=effective,
            toolchain_root=toolchain,
            source_topology_digest_value=source_topology_digest(
                item.path for item in source_document.entries
            ),
            toolchain_lock_digest=toolchain_document_digest(lock_document),
            path_profile_id=spec.paths.id,
            target_outputs=target_outputs,
            directive_inputs=committed_directive_inputs,
        )
    graph_relative_output = relative_output(root, spec.layout.producer_graph)
    graph_data = canonical_json(graph)
    validation_files, validation_authority = _producer_graph_validation_files(
        root, spec, graph_data
    )
    validate_migration_files(validation_files)
    previous_graph = (
        (root / graph_relative_output).read_bytes()
        if (root / graph_relative_output).is_file()
        else None
    )
    transaction = CASTransaction(root)
    for authority_relative in validation_authority:
        transaction.assert_unchanged(Path(*authority_relative.parts))
    transaction.write(graph_relative_output, graph_data)
    result = transaction.commit()
    try:
        load_project_tree(root)
    except Exception:
        rollback = CASTransaction(root)
        if previous_graph is None:
            rollback.delete(
                graph_relative_output,
                expected_sha256=Digest.from_bytes(graph_data).value,
            )
        else:
            rollback.write(
                graph_relative_output,
                previous_graph,
                expected_sha256=Digest.from_bytes(graph_data).value,
            )
        rollback.commit()
        raise
    role_counts = {
        role: sum(node.role.value == role for node in graph.nodes)
        for role in ("compiler", "resource-compiler", "librarian", "linker")
    }
    output.emit(
        "producer_graph_extracted",
        f"committed {len(graph.nodes)} direct producer(s) to {graph_relative_output}",
        output=graph_relative_output,
        extractor=graph.extractor,
        nodes=len(graph.nodes),
        roles=role_counts,
        graph_digest=producer_graph_digest(graph).value,
        transaction_id=result.transaction_id,
        certification_runtime="direct-locked-producers",
    )
    return 0
