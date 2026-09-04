"""Extract, validate, and atomically commit a CMake producer graph."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from reprobit.authority_snapshot import resolve_project_path
from reprobit.cli_paths import CLIError, real_directory, relative_output, safe_project_path
from reprobit.cmake import CMakeExportPlan
from reprobit.cmake_configure import cmake_define_arguments, effective_source_digest
from reprobit.cmake_import import imported_translation_unit_authority
from reprobit.model import Digest
from reprobit.producer_graph import (
    CMakeImportRecipe,
    ProducerGraphDocument,
    graph_reference,
    producer_graph_digest,
    toolchain_document_digest,
)
from reprobit.producer_graph_cmake import extract_cmake_makefiles_graph
from reprobit.project_loader import load_project, load_project_tree, validate_project_files
from reprobit.schema import (
    ProducerGraphBuildAdapter,
    ProjectSpec,
    SourceManifestDocument,
    ToolchainLock,
)
from reprobit.strict_json import canonical_json, strict_load
from reprobit.transactions import CASTransaction

if TYPE_CHECKING:
    from reprobit.toolchains import ToolchainDoctorReport


class CMakeGraphError(ValueError):
    """Configured CMake metadata cannot become closed build authority."""


@dataclass(frozen=True, slots=True)
class CMakeGraphResult:
    graph: ProducerGraphDocument
    output: Path
    transaction_id: str
    translation_units: int | None
    skipped_translation_units: int | None
    source_toolchain_report: ToolchainDoctorReport | None = None

    @property
    def role_counts(self) -> dict[str, int]:
        return {
            role: sum(node.role.value == role for node in self.graph.nodes)
            for role in ("compiler", "resource-compiler", "librarian", "linker")
        }

    @property
    def graph_digest(self) -> Digest:
        return producer_graph_digest(self.graph)


@dataclass(frozen=True, slots=True)
class _ValidationSnapshot:
    files: dict[PurePosixPath, bytes]
    preimages: dict[Path, bytes | None]
    authority: tuple[Path, ...]
    json_memberships: dict[Path, tuple[str, ...]]


def _real_directory(path: Path, *, label: str) -> Path:
    try:
        return real_directory(path, label=label)
    except CLIError as error:
        raise CMakeGraphError(str(error)) from error


def _project_path(root: Path, relative: PurePosixPath, *, label: str) -> Path:
    return resolve_project_path(root, relative.as_posix(), error=CMakeGraphError, subject=label)


def _validation_snapshot(
    root: Path,
    spec: ProjectSpec,
    graph_data: bytes,
) -> _ValidationSnapshot:
    files: dict[PurePosixPath, bytes] = {}
    preimages: dict[Path, bytes | None] = {}
    authority: list[Path] = []
    json_memberships: dict[Path, tuple[str, ...]] = {}

    def admit(relative_text: str, *, required: bool = True) -> None:
        relative = PurePosixPath(relative_text.replace("\\", "/"))
        path = _project_path(root, relative, label="graph-validation authority")
        if not path.exists() and not required:
            return
        if path.is_symlink() or not path.is_file():
            raise CMakeGraphError(f"graph-validation authority is absent or redirected: {relative}")
        data = path.read_bytes()
        files[relative] = data
        transaction_relative = Path(*relative.parts)
        preimages[transaction_relative] = data
        authority.append(transaction_relative)

    admit("reprobit.toml")
    admit(spec.toolchain.lock_file)
    admit(spec.layout.source_manifest)
    admit(spec.layout.build_plan, required=False)
    for directory_text in (
        spec.layout.interventions,
        spec.layout.proofs,
        spec.layout.oracles,
    ):
        directory_relative = PurePosixPath(directory_text.replace("\\", "/"))
        directory = _project_path(
            root,
            directory_relative,
            label="graph-validation manifest directory",
        )
        if directory.is_symlink() or not directory.is_dir():
            raise CMakeGraphError(
                f"graph-validation manifest directory is absent or redirected: {directory}"
            )
        entries = tuple(directory.rglob("*"))
        if any(path.is_symlink() for path in entries):
            raise CMakeGraphError(
                f"graph-validation manifest directory contains a redirect: {directory}"
            )
        paths = tuple(
            sorted(
                (path for path in entries if path.suffix.casefold() == ".json" and path.is_file()),
                key=lambda item: (
                    item.relative_to(directory).as_posix().casefold(),
                    item.relative_to(directory).as_posix(),
                ),
            )
        )
        directory_transaction_relative = Path(*directory_relative.parts)
        json_memberships[directory_transaction_relative] = tuple(
            path.relative_to(directory).as_posix() for path in paths
        )
        for path in paths:
            if not path.is_file():
                raise CMakeGraphError(f"graph-validation document is redirected: {path}")
            relative = PurePosixPath(path.relative_to(root).as_posix())
            data = path.read_bytes()
            files[relative] = data
            transaction_relative = Path(*relative.parts)
            preimages[transaction_relative] = data
            authority.append(transaction_relative)
    graph_relative = PurePosixPath(spec.layout.producer_graph.replace("\\", "/"))
    graph_path = _project_path(root, graph_relative, label="producer graph")
    graph_transaction_relative = Path(*graph_relative.parts)
    if os.path.lexists(graph_path):
        if graph_path.is_symlink() or not graph_path.is_file():
            raise CMakeGraphError(f"producer graph is redirected: {graph_path}")
        preimages[graph_transaction_relative] = graph_path.read_bytes()
    else:
        preimages[graph_transaction_relative] = None
    files[graph_relative] = graph_data
    return _ValidationSnapshot(
        files=files,
        preimages=preimages,
        authority=tuple(sorted(set(authority), key=lambda item: item.as_posix())),
        json_memberships=json_memberships,
    )


def _target_outputs(
    spec: ProjectSpec,
    configured: Path,
    target_plan_path: Path | None,
) -> dict[str, str]:
    plan_path = target_plan_path or configured / "reprobit-target-plan.json"
    if not plan_path.is_absolute():
        plan_path = configured / plan_path
    plan_path = plan_path.resolve(strict=False)
    try:
        plan_path.relative_to(configured)
    except ValueError as error:
        raise CMakeGraphError(
            "target plan must remain beneath the configured build root"
        ) from error
    if plan_path.is_symlink() or not plan_path.is_file():
        raise CMakeGraphError(f"target plan is absent or redirected: {plan_path}")
    target_plan = CMakeExportPlan.read(plan_path)
    if target_plan.link_admissions:
        raise CMakeGraphError(
            "target plan declares link admissions that the direct producer graph "
            "cannot encode; remove them before extraction"
        )
    project_targets = {target.id for target in spec.targets}
    plan_targets = {target.artifact_id for target in target_plan.targets}
    if len(plan_targets) != len(target_plan.targets) or plan_targets != project_targets:
        missing = sorted(project_targets - plan_targets)
        extra = sorted(plan_targets - project_targets)
        raise CMakeGraphError(f"target-plan artifact mismatch; missing={missing}, extra={extra}")

    outputs: dict[str, str] = {}
    target_specs = {target.id: target for target in spec.targets}
    for target in target_plan.targets:
        raw_output = Path(target.output)
        candidate = raw_output if raw_output.is_absolute() else configured / raw_output
        candidate = candidate.resolve(strict=False)
        try:
            relative = candidate.relative_to(configured)
        except ValueError as error:
            raise CMakeGraphError(
                f"target-plan output escapes configured build: {target.output!r}"
            ) from error
        expected_artifact = target_specs[target.artifact_id].artifact
        graph_artifact = f"build/{relative.as_posix()}"
        if graph_artifact != expected_artifact:
            raise CMakeGraphError(
                f"target-plan output for {target.artifact_id!r} is "
                f"{graph_artifact!r}; project artifact is {expected_artifact!r}"
            )
        outputs[target.artifact_id] = relative.as_posix()
    return outputs


def _directive_inputs(
    declarations: Sequence[str],
    *,
    project_targets: set[str],
) -> dict[str, tuple[str, ...]]:
    inputs: dict[str, list[str]] = {}
    seen: set[tuple[str, str]] = set()
    for declaration in declarations:
        target_id, separator, library = declaration.partition("=")
        if not separator or not target_id or not library or "=" in library:
            raise CMakeGraphError("--directive-input must use the exact TARGET=LIBRARY form")
        if target_id not in project_targets:
            raise CMakeGraphError(f"--directive-input names unknown target {target_id!r}")
        if re.fullmatch(r"[A-Za-z0-9_.+@-]+", library) is None:
            raise CMakeGraphError("--directive-input library must be one bare library name")
        normalized_library = library.casefold()
        if not normalized_library.endswith(".lib"):
            normalized_library += ".lib"
        try:
            reference = graph_reference("system-library", normalized_library)
        except ValueError as error:
            raise CMakeGraphError(
                f"invalid --directive-input library {library!r}: {error}"
            ) from error
        identity = (target_id.casefold(), reference.casefold())
        if identity in seen:
            raise CMakeGraphError(f"duplicate --directive-input {target_id}={normalized_library}")
        seen.add(identity)
        inputs.setdefault(target_id, []).append(reference)
    return {
        target_id: tuple(sorted(references, key=str.casefold))
        for target_id, references in sorted(inputs.items(), key=lambda item: item[0].casefold())
    }


def record_cmake_graph(
    *,
    project_root: Path,
    configured_build_root: Path,
    effective_source_root: Path,
    expected_effective_source_digest: Digest,
    toolchain_root: Path,
    target_plan: Path | None = None,
    cmake: str = "cmake",
    configuration: str = "RelWithDebInfo",
    timeout_seconds: float = 600.0,
    cmake_defines: Sequence[str] = (),
    directive_inputs: Sequence[str] = (),
    derive_translation_units: bool = False,
) -> CMakeGraphResult:
    """Commit closed graph and optional fresh TU shards in one CAS transaction."""

    root = _real_directory(project_root, label="project root")
    spec = load_project(root)
    if not isinstance(spec.build, ProducerGraphBuildAdapter):
        raise CMakeGraphError("producer-graph extraction requires a producer-graph project")
    configured = _real_directory(
        configured_build_root,
        label="configured build root",
    )
    effective = _real_directory(
        effective_source_root,
        label="effective source root",
    )
    toolchain = _real_directory(toolchain_root, label="toolchain root")
    if effective_source_digest(effective) != expected_effective_source_digest:
        raise CMakeGraphError(
            "effective source changed after CMake configuration; configure a fresh workspace"
        )

    source_path = safe_project_path(root, spec.layout.source_manifest)
    lock_path = safe_project_path(root, spec.toolchain.lock_file)
    for authority_path, label in (
        (source_path, "source manifest"),
        (lock_path, "toolchain lock"),
    ):
        if authority_path.is_symlink() or not authority_path.is_file():
            raise CMakeGraphError(f"{label} is absent or redirected: {authority_path}")
    source_document = SourceManifestDocument.model_validate_json(
        canonical_json(strict_load(source_path))
    )
    lock_document = ToolchainLock.model_validate_json(canonical_json(strict_load(lock_path)))
    if not source_document.complete:
        raise CMakeGraphError("producer-graph extraction requires a complete source manifest")
    if lock_document.profile != spec.toolchain.profile:
        raise CMakeGraphError("toolchain lock profile differs from reprobit.toml")

    outputs = _target_outputs(spec, configured, target_plan)
    cmake_define_arguments(cmake_defines)
    directives = _directive_inputs(
        directive_inputs,
        project_targets={target.id for target in spec.targets},
    )
    graph = extract_cmake_makefiles_graph(
        configured_build_root=configured,
        effective_source_root=effective,
        toolchain_root=toolchain,
        toolchain_lock_digest=toolchain_document_digest(lock_document),
        path_profile_id=spec.paths.id,
        target_outputs=outputs,
        directive_inputs=directives,
    )
    graph = graph.model_copy(
        update={
            "import_recipe": CMakeImportRecipe(
                cmake=cmake,
                configuration=configuration,
                timeout_seconds=timeout_seconds,
                cmake_defines=tuple(cmake_defines),
                directive_inputs=tuple(directive_inputs),
            )
        }
    )
    graph_relative = relative_output(root, spec.layout.producer_graph)
    graph_data = canonical_json(graph)
    snapshot = _validation_snapshot(root, spec, graph_data)
    base_bundle = validate_project_files(snapshot.files)
    translation_units = None
    if derive_translation_units:
        from reprobit.classic_orchestration import (
            classic_compiler_translation_unit_authority,
        )

        translation_units = imported_translation_unit_authority(root, base_bundle, graph)
    validation_files = dict(snapshot.files)
    preimages = dict(snapshot.preimages)
    replacement_files = {} if translation_units is None else translation_units.files
    for replacement_relative, data in replacement_files.items():
        if replacement_relative.is_absolute() or any(
            part in {"", ".", ".."} for part in replacement_relative.parts
        ):
            raise CMakeGraphError(
                f"graph-validation replacement is not canonical: {replacement_relative}"
            )
        transaction_relative = Path(*replacement_relative.parts)
        if transaction_relative not in preimages:
            path = _project_path(
                root,
                replacement_relative,
                label="graph-validation replacement",
            )
            if os.path.lexists(path):
                if path.is_symlink() or not path.is_file():
                    raise CMakeGraphError(f"graph-validation replacement is redirected: {path}")
                preimages[transaction_relative] = path.read_bytes()
            else:
                preimages[transaction_relative] = None
        validation_files[replacement_relative] = data
    validated_bundle = validate_project_files(validation_files)
    if translation_units is not None:
        classic_compiler_translation_unit_authority(validated_bundle, graph)

    writes = {
        Path(*relative.parts): data
        for relative, data in ({} if translation_units is None else translation_units.files).items()
    }
    writes[graph_relative] = graph_data
    previous = {relative: preimages[relative] for relative in writes}
    if effective_source_digest(effective) != expected_effective_source_digest:
        raise CMakeGraphError(
            "effective source changed while the CMake graph was recorded; "
            "configure a fresh workspace"
        )
    transaction = CASTransaction(root)
    for directory, members in sorted(
        snapshot.json_memberships.items(), key=lambda item: item[0].as_posix()
    ):
        transaction.assert_json_members(directory, expected_members=members)
    for transaction_relative in snapshot.authority:
        if transaction_relative not in writes:
            preimage = preimages[transaction_relative]
            if preimage is None:
                raise CMakeGraphError("present graph-validation authority has no preimage")
            transaction.assert_unchanged(
                transaction_relative,
                expected_sha256=Digest.from_bytes(preimage).value,
            )
    for output_relative, data in sorted(writes.items(), key=lambda item: item[0].as_posix()):
        preimage = preimages[output_relative]
        transaction.write(
            output_relative,
            data,
            expected_sha256=(None if preimage is None else Digest.from_bytes(preimage).value),
        )
    result = transaction.commit()
    try:
        if effective_source_digest(effective) != expected_effective_source_digest:
            raise CMakeGraphError(
                "effective source changed while the CMake graph commit completed; "
                "configure a fresh workspace"
            )
        load_project_tree(root)
    except BaseException as error:
        try:
            rollback = CASTransaction(root)
            for rollback_relative, data in sorted(
                writes.items(), key=lambda item: item[0].as_posix()
            ):
                old_data = previous[rollback_relative]
                if old_data is None:
                    rollback.delete(
                        rollback_relative,
                        expected_sha256=Digest.from_bytes(data).value,
                    )
                else:
                    rollback.write(
                        rollback_relative,
                        old_data,
                        expected_sha256=Digest.from_bytes(data).value,
                    )
            rollback.commit()
        except Exception as rollback_error:
            error.add_note(f"producer graph rollback also failed: {rollback_error}")
        raise
    return CMakeGraphResult(
        graph=graph,
        output=graph_relative,
        transaction_id=result.transaction_id,
        translation_units=(None if translation_units is None else translation_units.planned),
        skipped_translation_units=(
            None if translation_units is None else translation_units.skipped
        ),
    )


__all__ = [
    "CMakeGraphError",
    "CMakeGraphResult",
    "record_cmake_graph",
]
