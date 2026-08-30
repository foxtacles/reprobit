"""Project-aware inputs and private staging for bounded discovery grind runs."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from reprobit.classic_orchestration import (
    classic_compiler_translation_unit_authority,
)
from reprobit.classic_project import ClassicProjectError
from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationShapeSearch,
    DiscoveryError,
    DiscoveryPlan,
    InclusiveRange,
    MosaicLimits,
    enumerate_declaration_states,
)
from reprobit.model import Digest, Identifier, StrictModel
from reprobit.paths import normalize_logical_path
from reprobit.producer_graph import ProducerNode, ProducerRole
from reprobit.project_loader import load_project_tree
from reprobit.schema import (
    ClassicRecipeIntervention,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    LegacyOracleInstallIntervention,
    ProjectBundle,
    ProofDocument,
)
from reprobit.source_lock import receipt_source_input
from reprobit.state import KeepWorkspace, RunArena
from reprobit.strict_json import canonical_json, strict_load


class ProjectDiscoveryError(RuntimeError):
    """A project cannot safely run or publish a discovery grind."""


def _portable_relative(value: str, *, label: str) -> str:
    if "\0" in value or "\\" in value:
        raise ValueError(f"{label} must be canonical POSIX relative text")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} must be canonical POSIX relative text")
    # Reuse the compiler path contract's conservative DOS component checks.
    normalize_logical_path("R:\\" + value.replace("/", "\\"))
    return value


class ProjectGrindPlan(StrictModel):
    """One deliberately small, project-aware declaration search."""

    schema_version: Literal[1] = 1
    reference_object: Annotated[str, Field(min_length=1, max_length=8192)]
    target: Identifier
    translation_unit: Identifier
    symbol: Annotated[str, Field(min_length=1, max_length=2048)]
    classes: InclusiveRange
    functions: InclusiveRange

    @field_validator("reference_object")
    @classmethod
    def safe_reference(cls, value: str) -> str:
        return _portable_relative(value, label="reference object")

    @model_validator(mode="after")
    def lean_initial_scope(self) -> ProjectGrindPlan:
        try:
            enumerate_declaration_states(self.plan)
        except DiscoveryError as exc:
            raise ValueError(
                "project grind v1 must contain 1 to 64 legal declaration states"
            ) from exc
        return self

    @property
    def plan(self) -> DiscoveryPlan:
        """Translate the small public plan into the shared bounded enumerator."""

        return DiscoveryPlan(
            target=self.target,
            translation_unit=self.translation_unit,
            symbols=(self.symbol,),
            searches=(
                DeclarationShapeSearch(
                    family=DeclarationFamily.DECLARATION_SHAPE,
                    classes=self.classes,
                    functions=self.functions,
                ),
            ),
            max_cells=64,
            mosaic=MosaicLimits(enabled=False),
        )


@dataclass(frozen=True, slots=True)
class ProjectGrindContext:
    root: Path
    config_path: Path
    config_relative: str
    config: ProjectGrindPlan
    bundle: ProjectBundle
    unit_index: int
    intervention_index: int
    proof_index: int
    intervention_path: Path
    proof_path: Path
    compiler_node: ProducerNode
    reference_path: Path

    @property
    def unit(self) -> ClassicTranslationUnitPlan:
        assert self.bundle.build_plan is not None
        return self.bundle.build_plan.translation_units[self.unit_index]

    @property
    def intervention_document(self) -> InterventionDocument:
        return self.bundle.intervention_documents[self.intervention_index]

    @property
    def proof_document(self) -> ProofDocument:
        return self.bundle.proof_documents[self.proof_index]

    @property
    def symbol(self) -> str:
        return self.config.symbol


@dataclass(frozen=True, slots=True)
class ProjectFileSnapshot:
    relative_path: str
    digest: Digest
    payload: bytes


@dataclass(frozen=True, slots=True)
class ProjectDirectorySnapshot:
    relative_path: str
    json_members: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProjectGrindSnapshot:
    files: tuple[ProjectFileSnapshot, ...]
    authority_directories: tuple[ProjectDirectorySnapshot, ...]


def _safe_project_path(root: Path, relative: str) -> Path:
    relative = _portable_relative(relative, label="project path")
    candidate = root.joinpath(*PurePosixPath(relative).parts)
    current = root
    for component in PurePosixPath(relative).parts:
        current /= component
        if current.is_symlink():
            raise ProjectDiscoveryError(f"project input is redirected: {relative!r}")
    try:
        candidate.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise ProjectDiscoveryError(f"project input escapes its root: {relative!r}") from exc
    return candidate


def discovery_state_root(root: Path, state_dir: str) -> Path:
    """Resolve the owned local-state root used by discovery workspaces."""

    return _safe_project_path(root.resolve(strict=True), state_dir)


def _document_paths(root: Path, relative: str) -> tuple[Path, ...]:
    directory = _safe_project_path(root, relative)
    if not directory.is_dir() or directory.is_symlink():
        raise ProjectDiscoveryError(f"project document directory is unavailable: {directory}")
    entries = tuple(directory.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise ProjectDiscoveryError(f"project document directory is redirected: {directory}")
    paths = tuple(
        sorted(
            (path for path in entries if path.suffix.casefold() == ".json"),
            key=lambda item: item.as_posix(),
        )
    )
    if any(not path.is_file() for path in paths):
        raise ProjectDiscoveryError(f"project document entry is not a file: {directory}")
    return paths


def _relative_to(root: Path, path: Path) -> str:
    return PurePosixPath(*path.relative_to(root).parts).as_posix()


def _function_authority_ids(
    document: InterventionDocument,
    symbol: str,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            item.id
            for item in document.interventions
            if isinstance(
                item,
                (ClassicRecipeIntervention, LegacyOracleInstallIntervention),
            )
            and item.scope.function == symbol
        )
    )


def load_project_grind_plan(
    root: Path,
    *,
    relative: str = "reprobit/discovery.json",
) -> tuple[Path, ProjectGrindPlan]:
    root = root.resolve(strict=True)
    path = _safe_project_path(root, relative)
    if path.is_symlink() or not path.is_file():
        raise ProjectDiscoveryError(
            f"project discovery plan is absent: {relative}; start from the small "
            "project-grind example documented in docs/discovery.md"
        )
    try:
        value = strict_load(path)
        return path, ProjectGrindPlan.model_validate_json(canonical_json(value))
    except ValueError as exc:
        raise ProjectDiscoveryError(f"invalid project discovery plan {path}: {exc}") from exc


def resolve_project_grind_context(
    root: Path,
    *,
    config_relative: str = "reprobit/discovery.json",
) -> ProjectGrindContext:
    root = root.resolve(strict=True)
    config_path, config = load_project_grind_plan(root, relative=config_relative)
    bundle = load_project_tree(root)
    build_plan = bundle.build_plan
    graph = bundle.producer_graph
    if build_plan is None or graph is None:
        raise ProjectDiscoveryError("project grind requires a complete producer graph")
    if config.target not in {target.id for target in bundle.spec.targets}:
        raise ProjectDiscoveryError(f"discovery target is not in the project: {config.target!r}")
    unit_matches = tuple(
        index
        for index, unit in enumerate(build_plan.translation_units)
        if unit.id == config.translation_unit and unit.target_id == config.target
    )
    if len(unit_matches) != 1:
        raise ProjectDiscoveryError(
            "project discovery plan does not identify one target translation unit"
        )
    unit_index = unit_matches[0]
    unit = build_plan.translation_units[unit_index]

    intervention_matches = tuple(
        index
        for index, document in enumerate(bundle.intervention_documents)
        if document.translation_unit_id == unit.id
    )
    proof_matches = tuple(
        index
        for index, document in enumerate(bundle.proof_documents)
        if document.translation_unit_id == unit.id
    )
    if len(intervention_matches) != 1 or len(proof_matches) != 1:
        raise ProjectDiscoveryError(
            "translation unit does not have exactly one intervention file and one proof file"
        )
    intervention_index = intervention_matches[0]
    proof_index = proof_matches[0]
    intervention_paths = _document_paths(root, bundle.spec.layout.interventions)
    proof_paths = _document_paths(root, bundle.spec.layout.proofs)
    if len(intervention_paths) != len(bundle.intervention_documents) or len(proof_paths) != len(
        bundle.proof_documents
    ):
        raise ProjectDiscoveryError(
            "project intervention or proof file paths changed after validation"
        )

    try:
        compiler_authority = classic_compiler_translation_unit_authority(bundle, graph)
    except ClassicProjectError as exc:
        raise ProjectDiscoveryError(f"saved compiler steps are invalid: {exc}") from exc
    compiler_matches = tuple(
        node_id
        for node_id, planned_unit in compiler_authority.items()
        if planned_unit.id == unit.id
    )
    if len(compiler_matches) != 1:
        raise ProjectDiscoveryError(
            "translation unit does not have exactly one saved compiler step"
        )
    compiler_node_id = compiler_matches[0]
    compiler_node = next(
        (node for node in graph.nodes if node.id == compiler_node_id),
        None,
    )
    if compiler_node is None or compiler_node.role is not ProducerRole.COMPILER:
        raise ProjectDiscoveryError("saved translation-unit step is not a compiler step")
    current = bundle.intervention_documents[intervention_index]
    existing_authority = _function_authority_ids(current, config.symbol)
    if existing_authority:
        raise ProjectDiscoveryError(
            f"symbol already has saved adjustment records: "
            f"{config.symbol!r} ({', '.join(existing_authority)})"
        )
    reference_path = _safe_project_path(root, config.reference_object)
    if reference_path.is_symlink() or not reference_path.is_file():
        raise ProjectDiscoveryError(f"reference COFF object is absent: {config.reference_object!r}")

    return ProjectGrindContext(
        root=root,
        config_path=config_path,
        config_relative=config_relative,
        config=config,
        bundle=bundle,
        unit_index=unit_index,
        intervention_index=intervention_index,
        proof_index=proof_index,
        intervention_path=intervention_paths[intervention_index],
        proof_path=proof_paths[proof_index],
        compiler_node=compiler_node,
        reference_path=reference_path,
    )


def capture_project_grind_inputs(
    context: ProjectGrindContext,
) -> ProjectGrindSnapshot:
    """Capture the complete staged project and commit-time CAS preimages."""

    bundle = context.bundle
    assert bundle.source_manifest is not None
    authority_directories: list[ProjectDirectorySnapshot] = []
    authority_paths: list[Path] = []
    for relative in (
        bundle.spec.layout.interventions,
        bundle.spec.layout.proofs,
        bundle.spec.layout.oracles,
    ):
        paths = _document_paths(context.root, relative)
        directory = _safe_project_path(context.root, relative)
        authority_paths.extend(paths)
        authority_directories.append(
            ProjectDirectorySnapshot(
                relative_path=relative,
                json_members=tuple(
                    sorted(
                        (_relative_to(directory, path) for path in paths),
                        key=lambda item: (item.casefold(), item),
                    )
                ),
            )
        )
    relatives = {
        "reprobit.toml",
        bundle.spec.toolchain.lock_file,
        bundle.spec.layout.source_manifest,
        bundle.spec.layout.build_plan,
        bundle.spec.layout.producer_graph,
        context.config_relative,
        context.config.reference_object,
        *(entry.path for entry in bundle.source_manifest.entries),
        *(target.oracle for target in bundle.spec.targets),
        *(_relative_to(context.root, path) for path in authority_paths),
    }
    canonical = tuple(sorted(relatives, key=str.casefold))
    if len({item.casefold() for item in canonical}) != len(canonical):
        raise ProjectDiscoveryError("project grind inputs collide under DOS case folding")
    snapshots: list[ProjectFileSnapshot] = []
    for relative in canonical:
        try:
            size, digest, payload = receipt_source_input(
                context.root,
                relative,
                capture=True,
            )
        except ValueError as exc:
            raise ProjectDiscoveryError(
                f"cannot seal project grind input {relative!r}: {exc}"
            ) from exc
        assert payload is not None
        if size != len(payload):
            raise ProjectDiscoveryError(f"project grind input changed: {relative!r}")
        snapshots.append(ProjectFileSnapshot(relative, digest, payload))
    for snapshot in authority_directories:
        current = _document_paths(context.root, snapshot.relative_path)
        directory = _safe_project_path(context.root, snapshot.relative_path)
        members = tuple(
            sorted(
                (_relative_to(directory, path) for path in current),
                key=lambda item: (item.casefold(), item),
            )
        )
        if members != snapshot.json_members:
            raise ProjectDiscoveryError(
                f"project authority membership changed: {snapshot.relative_path!r}"
            )
    return ProjectGrindSnapshot(tuple(snapshots), tuple(authority_directories))


class StagedProject:
    """An explicit private copy of every sealed input needed by certification."""

    def __init__(
        self,
        project_root: Path,
        state_dir: str,
        snapshots: tuple[ProjectFileSnapshot, ...],
    ) -> None:
        root = project_root.resolve(strict=True)
        self.arena = RunArena(
            discovery_state_root(root, state_dir),
            kind="grind",
            keep=KeepWorkspace.NEVER,
        )
        self.snapshots = snapshots

    def __enter__(self) -> Path:
        arena = self.arena.__enter__()
        root = arena.path / "project"
        try:
            root.mkdir()
            for snapshot in self.snapshots:
                destination = root.joinpath(*PurePosixPath(snapshot.relative_path).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open("xb") as stream:
                    stream.write(snapshot.payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                if Digest.from_path(destination) != snapshot.digest:
                    raise ProjectDiscoveryError(
                        f"staged project input differs: {snapshot.relative_path!r}"
                    )
        except BaseException:
            arena.finish(succeeded=False)
            raise
        return root

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.arena.__exit__(exc_type, exc, traceback)


__all__ = [
    "ProjectDirectorySnapshot",
    "ProjectDiscoveryError",
    "ProjectFileSnapshot",
    "ProjectGrindContext",
    "ProjectGrindPlan",
    "ProjectGrindSnapshot",
    "StagedProject",
    "capture_project_grind_inputs",
    "discovery_state_root",
    "load_project_grind_plan",
    "resolve_project_grind_context",
]
