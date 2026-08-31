"""Reviewed authority created by the guided CMake import workflow."""

from __future__ import annotations

import os
import tomllib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from reprobit.cli_output import human_command
from reprobit.cli_paths import CLIError, relative_output, safe_project_path
from reprobit.model import Digest
from reprobit.producer_graph import ProducerGraphDocument, ProducerRole
from reprobit.schema import (
    BuildPlanDocument,
    ClassicTargetGate,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    OracleDocument,
    ProjectBundle,
    ProjectSpec,
    ProofDocument,
    SourceManifestDocument,
    ToolchainLock,
    source_manifest_digest,
)
from reprobit.secure_paths import digest_relative_file, read_relative_file
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction


@dataclass(frozen=True, slots=True)
class CMakeScaffold:
    """Files created before CMake configuration and their CAS transaction."""

    files: dict[Path, bytes]
    transaction_id: str | None


@dataclass(frozen=True, slots=True)
class ImportedTranslationUnits:
    """Candidate authority derived from unambiguous compiler graph lanes."""

    files: dict[PurePosixPath, bytes]
    planned: int
    skipped: int


def json_authority_paths(root: Path, relative: str) -> tuple[Path, ...]:
    """Return canonical regular JSON files beneath one project authority."""

    directory = safe_project_path(root, relative)
    lexical = root.joinpath(*PurePosixPath(relative.replace("\\", "/")).parts)
    if lexical.is_symlink() or (lexical.exists() and not lexical.is_dir()):
        raise CLIError(f"project authority is redirected or not a directory: {lexical}")
    if not directory.exists():
        return ()
    paths = tuple(sorted(directory.rglob("*.json"), key=lambda item: item.as_posix()))
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise CLIError(f"project authority contains a redirected JSON document: {directory}")
    return paths


def _target_gates(
    spec: ProjectSpec,
    declarations: list[str],
) -> tuple[ClassicTargetGate, ...]:
    known = {target.id for target in spec.targets}
    selected = {target.id: target.id for target in spec.targets}
    seen: set[str] = set()
    for declaration in declarations:
        target_id, separator, cmake_target = declaration.partition("=")
        if not separator or not target_id or not cmake_target or "=" in cmake_target:
            raise CLIError("--target must use the exact TARGET=CMAKE_TARGET form")
        if target_id not in known:
            raise CLIError(f"--target names unknown ReproBit target {target_id!r}")
        if target_id in seen:
            raise CLIError(f"--target repeats ReproBit target {target_id!r}")
        seen.add(target_id)
        selected[target_id] = cmake_target
    try:
        return tuple(
            ClassicTargetGate(target_id=target.id, build_target=selected[target.id])
            for target in spec.targets
        )
    except ValueError as error:
        raise CLIError(f"invalid CMake target mapping: {error}") from error


def scaffold_cmake_authority(
    root: Path,
    spec: ProjectSpec,
    target_declarations: list[str],
) -> CMakeScaffold:
    """Create only the empty authority a fresh CMake import can know honestly."""

    plan_path = safe_project_path(root, spec.layout.build_plan)
    if plan_path.is_file() and not plan_path.is_symlink():
        if target_declarations:
            raise CLIError("--target can only be used while creating the initial CMake build plan")
        return CMakeScaffold({}, None)
    if plan_path.exists() or plan_path.is_symlink():
        raise CLIError(f"build plan is redirected or not a regular file: {plan_path}")

    graph_path = safe_project_path(root, spec.layout.producer_graph)
    if os.path.lexists(graph_path):
        raise CLIError("a producer graph exists without a build plan; review that partial setup")

    existing_documents = tuple(
        path
        for relative in (
            spec.layout.interventions,
            spec.layout.proofs,
            spec.layout.oracles,
        )
        for path in json_authority_paths(root, relative)
    )
    if existing_documents:
        rendered = ", ".join(path.relative_to(root).as_posix() for path in existing_documents)
        raise CLIError(
            "cannot scaffold over partial reviewed authority; finish or remove these files: "
            f"{rendered}"
        )

    source_path = safe_project_path(root, spec.layout.source_manifest)
    if source_path.is_symlink() or not source_path.is_file():
        raise CLIError(
            f"source lock is missing; run {human_command(('rbit', 'source', 'preview', root))}"
        )
    try:
        source_data, source_receipt = read_relative_file(root, spec.layout.source_manifest)
        source = SourceManifestDocument.model_validate_json(source_data)
    except (OSError, ValueError) as error:
        raise CLIError(f"source lock is invalid: {error}") from error
    if not source.complete:
        raise CLIError(
            f"source review is incomplete; run {human_command(('rbit', 'source', 'preview', root))}"
        )

    lock_path = safe_project_path(root, spec.toolchain.lock_file)
    if lock_path.is_symlink() or not lock_path.is_file():
        raise CLIError(f"compiler lock is missing; run {human_command(('rbit', 'setup', root))}")
    try:
        lock_data, lock_receipt = read_relative_file(root, spec.toolchain.lock_file)
        project_data, project_receipt = read_relative_file(root, "reprobit.toml")
    except OSError as error:
        raise CLIError(f"project setup authority is missing or unsafe: {error}") from error
    try:
        received_spec = ProjectSpec.model_validate_json(
            canonical_json(tomllib.loads(project_data.decode("utf-8")))
        )
    except (UnicodeError, tomllib.TOMLDecodeError, ValueError) as error:
        raise CLIError(f"reprobit.toml is invalid: {error}") from error
    if received_spec != spec:
        raise CLIError("reprobit.toml changed after the project was loaded; retry the import")
    try:
        received_lock = ToolchainLock.model_validate_json(lock_data)
    except ValueError as error:
        raise CLIError(f"compiler lock is invalid: {error}") from error
    if received_lock.profile != spec.toolchain.profile:
        raise CLIError("compiler lock profile differs from reprobit.toml")

    plan = BuildPlanDocument(
        schema_version=3,
        source_manifest_digest=source_manifest_digest(source),
        translation_units=(),
        source_overlay_digest=Digest.from_bytes(b"no source overlays"),
        source_overlay_interventions=(),
        archives=(),
        target_gates=_target_gates(spec, target_declarations),
    )
    files: dict[Path, bytes] = {relative_output(root, spec.layout.build_plan): canonical_json(plan)}
    reference_digests: dict[str, str] = {}
    for target in spec.targets:
        try:
            reference = digest_relative_file(root, target.oracle)
        except OSError as error:
            raise CLIError(
                f"reference for {target.id!r} is missing or unsafe at {target.oracle!r}"
            ) from error
        if reference.size == 0:
            raise CLIError(f"reference for {target.id!r} is empty: {target.oracle}")
        reference_digests[target.oracle] = reference.digest.value
        intervention_path = PurePosixPath(spec.layout.interventions) / f"{target.id}.json"
        proof_path = PurePosixPath(spec.layout.proofs) / f"{target.id}.json"
        oracle_path = PurePosixPath(spec.layout.oracles) / f"{target.id}.json"
        files[Path(*intervention_path.parts)] = canonical_json(
            InterventionDocument(schema_version=3, target_id=target.id)
        )
        files[Path(*proof_path.parts)] = canonical_json(
            ProofDocument(schema_version=3, target_id=target.id)
        )
        files[Path(*oracle_path.parts)] = canonical_json(
            OracleDocument(
                schema_version=3,
                target_id=target.id,
                image_size=reference.size,
                image_digest=reference.digest,
            )
        )

    transaction = CASTransaction(root)
    transaction.assert_unchanged(
        relative_output(root, "reprobit.toml"),
        expected_sha256=project_receipt.digest.value,
    )
    transaction.assert_unchanged(
        relative_output(root, spec.layout.source_manifest),
        expected_sha256=source_receipt.digest.value,
    )
    transaction.assert_unchanged(
        relative_output(root, spec.toolchain.lock_file),
        expected_sha256=lock_receipt.digest.value,
    )
    for authority_directory in (
        spec.layout.interventions,
        spec.layout.proofs,
        spec.layout.oracles,
    ):
        transaction.assert_json_members(
            relative_output(root, authority_directory),
            expected_members=(),
        )
    for reference_path, digest in reference_digests.items():
        transaction.assert_unchanged(
            relative_output(root, reference_path),
            expected_sha256=digest,
        )
    for output_relative, data in sorted(files.items(), key=lambda item: item[0].as_posix()):
        transaction.write(output_relative, data, expected_sha256=None)
    result = transaction.commit()

    scaffold = CMakeScaffold(files, result.transaction_id)
    try:
        expected_documents = {
            relative.as_posix()
            for relative in files
            if relative.suffix.casefold() == ".json"
            and relative.as_posix() != spec.layout.build_plan.replace("\\", "/")
        }
        actual_documents = {
            path.relative_to(root).as_posix()
            for relative in (
                spec.layout.interventions,
                spec.layout.proofs,
                spec.layout.oracles,
            )
            for path in json_authority_paths(root, relative)
        }
        if actual_documents != expected_documents:
            raise CLIError("project authority changed while the CMake scaffold was committed")
    except BaseException as error:
        try:
            rollback_cmake_scaffold(root, scaffold)
        except Exception as rollback_error:
            error.add_note(f"CMake scaffold rollback also failed: {rollback_error}")
        raise
    return scaffold


def rollback_cmake_scaffold(root: Path, scaffold: CMakeScaffold) -> None:
    """Remove an unchanged scaffold after a failed guided import."""

    transaction = CASTransaction(root)
    for relative, data in sorted(scaffold.files.items(), key=lambda item: item[0].as_posix()):
        transaction.delete(relative, expected_sha256=Digest.from_bytes(data).value)
    transaction.commit()


def imported_translation_unit_authority(
    root: Path,
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
) -> ImportedTranslationUnits:
    """Derive TU authority only for unambiguous compiler lanes in a fresh plan."""

    from reprobit.classic_orchestration import (
        compiler_source,
        compiler_terminal_consumer_targets,
    )
    from reprobit.classic_project import ClassicProjectError

    plan = bundle.build_plan
    manifest = bundle.source_manifest
    if plan is None or manifest is None:
        raise CLIError("CMake import requires build-plan and source authority")
    if plan.translation_units:
        return ImportedTranslationUnits({}, len(plan.translation_units), 0)

    try:
        consumers = compiler_terminal_consumer_targets(graph)
        compiler_sources = {
            node.id: compiler_source(node)
            for node in graph.nodes
            if node.role is ProducerRole.COMPILER
        }
    except ClassicProjectError as error:
        raise CLIError(
            f"imported compiler graph cannot be mapped to source files: {error}"
        ) from error
    identity_counts = Counter(
        (node.owner.casefold(), compiler_sources[node.id].casefold())
        for node in graph.nodes
        if node.role is ProducerRole.COMPILER
    )
    source_entries = {entry.path.casefold(): entry for entry in manifest.entries}
    units: list[ClassicTranslationUnitPlan] = []
    skipped = 0
    for node in sorted(graph.nodes, key=lambda item: (item.id.casefold(), item.id)):
        if node.role is not ProducerRole.COMPILER:
            continue
        source = compiler_sources[node.id]
        targets = consumers[node.id]
        identity = (node.owner.casefold(), source.casefold())
        entry = source_entries.get(source.casefold())
        if len(targets) != 1 or identity_counts[identity] != 1 or entry is None:
            skipped += 1
            continue
        target_id = next(iter(targets))
        identity_digest = Digest.from_bytes(
            canonical_json(
                {
                    "schema": 1,
                    "target": target_id,
                    "build_target": node.owner,
                    "source": entry.path,
                }
            )
        ).value
        units.append(
            ClassicTranslationUnitPlan(
                id=f"tu.{identity_digest[:24]}",
                target_id=target_id,
                build_target=node.owner,
                source=entry.path,
                source_digest=entry.digest,
            )
        )
    units.sort(key=lambda item: (item.id.casefold(), item.id))
    if len({unit.id.casefold() for unit in units}) != len(units):
        raise CLIError("imported translation-unit identities collide")

    plan_data = plan.model_dump(mode="python")
    plan_data["translation_units"] = tuple(units)
    updated_plan = BuildPlanDocument.model_validate(plan_data)
    plan_relative = PurePosixPath(bundle.spec.layout.build_plan.replace("\\", "/"))
    files: dict[PurePosixPath, bytes] = {plan_relative: canonical_json(updated_plan)}
    for unit in units:
        intervention = PurePosixPath(bundle.spec.layout.interventions) / f"{unit.id}.json"
        proof = PurePosixPath(bundle.spec.layout.proofs) / f"{unit.id}.json"
        for relative in (intervention, proof):
            path = safe_project_path(root, relative.as_posix())
            if os.path.lexists(path):
                raise CLIError(
                    "CMake import will not replace an existing TU authority file: "
                    f"{relative.as_posix()}"
                )
        files[intervention] = canonical_json(
            InterventionDocument(
                schema_version=3,
                target_id=unit.target_id,
                translation_unit_id=unit.id,
                source=unit.source,
                source_digest=unit.source_digest,
                build_target=unit.build_target,
            )
        )
        files[proof] = canonical_json(
            ProofDocument(
                schema_version=3,
                target_id=unit.target_id,
                translation_unit_id=unit.id,
            )
        )
    return ImportedTranslationUnits(files, len(units), skipped)


__all__ = [
    "CMakeScaffold",
    "ImportedTranslationUnits",
    "imported_translation_unit_authority",
    "json_authority_paths",
    "rollback_cmake_scaffold",
    "scaffold_cmake_authority",
]
