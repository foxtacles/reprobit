"""Strict loading and cross-validation of committed project authority."""

from __future__ import annotations

import os
import tempfile
import tomllib
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, TypeVar

from reprobit.model import StrictModel
from reprobit.producer_graph import read_producer_graph
from reprobit.schema import (
    BuildPlanDocument,
    InterventionDocument,
    OracleDocument,
    ProjectBundle,
    ProjectSpec,
    ProofDocument,
    SchemaError,
    SchemaVersionError,
    SourceManifestDocument,
    ToolchainLock,
)
from reprobit.strict_json import StrictJSONError, canonical_json, strict_load

if TYPE_CHECKING:
    from reprobit.classic_overlay import ClassicOverlayRenderSession


ModelT = TypeVar("ModelT", bound=StrictModel)


def _load_json_model(path: Path, model: type[ModelT]) -> ModelT:
    try:
        value = strict_load(path)
        return model.model_validate_json(canonical_json(value))
    except (StrictJSONError, ValueError) as exc:
        if isinstance(exc, SchemaError):
            raise
        raise SchemaError(f"invalid {path}: {exc}") from exc


def load_project(path: str | Path) -> ProjectSpec:
    """Load a strict ``reprobit.toml`` entry point."""

    source = Path(path)
    if source.is_dir():
        source = source / "reprobit.toml"
    try:
        document = tomllib.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise SchemaError(f"cannot load {source}: {exc}") from exc
    version = document.get("schema_version")
    if version != 3:
        raise SchemaVersionError(f"{source} uses schema {version!r}; runtime accepts only schema 3")
    try:
        # TOML arrays are lists; round-tripping through JSON retains strict scalar
        # types while allowing immutable tuple fields to consume array syntax.
        return ProjectSpec.model_validate_json(canonical_json(document))
    except ValueError as exc:
        raise SchemaError(f"invalid {source}: {exc}") from exc


def _safe_child(root: Path, relative: str) -> Path:
    candidate = root.joinpath(*relative.replace("\\", "/").split("/"))
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise SchemaError(f"path escapes project root: {relative}") from exc
    return resolved


def _document_paths(root: Path, relative: str) -> tuple[Path, ...]:
    directory = _safe_child(root, relative)
    if not directory.is_dir():
        raise SchemaError(f"manifest directory does not exist: {directory}")
    paths = tuple(sorted(directory.rglob("*.json"), key=lambda item: item.as_posix()))
    for path in paths:
        resolved = path.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise SchemaError(f"manifest path escapes project root: {path}") from exc
    return paths


def load_project_tree(
    root: str | Path,
    *,
    verify_source_authority: bool = True,
    overlay_render_session: ClassicOverlayRenderSession | None = None,
    include_producer_graph: bool = True,
) -> ProjectBundle:
    """Load and cross-validate committed schema-v3 project authority.

    ``include_producer_graph=False`` is reserved for the non-certifying graph
    migration path.  It lets that path configure a replacement after an
    independently reviewed toolchain lock changes; normal project loading and
    every certifying build continue to require the committed graph.
    """

    project_root = Path(root).resolve()
    if not project_root.is_dir():
        raise SchemaError(f"project root is not a directory: {project_root}")
    spec = load_project(project_root / "reprobit.toml")
    lock_path = _safe_child(project_root, spec.toolchain.lock_file)
    toolchain_lock = _load_json_model(lock_path, ToolchainLock)
    from reprobit.toolchains import (
        TOOLCHAIN_PROFILES,
        ToolchainError,
        validate_toolchain_lock,
    )

    if toolchain_lock.profile in TOOLCHAIN_PROFILES:
        try:
            validate_toolchain_lock(toolchain_lock)
        except ToolchainError as exc:
            raise SchemaError(f"invalid {lock_path}: {exc}") from exc
    source_manifest_path = _safe_child(project_root, spec.layout.source_manifest)
    source_manifest = _load_json_model(source_manifest_path, SourceManifestDocument)
    build_plan_path = _safe_child(project_root, spec.layout.build_plan)
    build_plan = (
        _load_json_model(build_plan_path, BuildPlanDocument) if build_plan_path.is_file() else None
    )
    producer_graph_path = _safe_child(project_root, spec.layout.producer_graph)
    producer_graph = (
        read_producer_graph(producer_graph_path)
        if include_producer_graph and producer_graph_path.is_file()
        else None
    )
    intervention_documents = tuple(
        _load_json_model(path, InterventionDocument)
        for path in _document_paths(project_root, spec.layout.interventions)
    )
    proof_documents = tuple(
        _load_json_model(path, ProofDocument)
        for path in _document_paths(project_root, spec.layout.proofs)
    )
    oracle_documents = tuple(
        _load_json_model(path, OracleDocument)
        for path in _document_paths(project_root, spec.layout.oracles)
    )
    try:
        bundle = ProjectBundle(
            root=os.fspath(project_root),
            spec=spec,
            toolchain_lock=toolchain_lock,
            source_manifest=source_manifest,
            build_plan=build_plan,
            producer_graph=producer_graph,
            intervention_documents=intervention_documents,
            proof_documents=proof_documents,
            oracle_documents=oracle_documents,
        )
        if verify_source_authority:
            from reprobit.source_authority import validate_source_authority

            validate_source_authority(
                bundle,
                project_root,
                render_session=overlay_render_session,
            )
        return bundle
    except ValueError as exc:
        raise SchemaError(f"invalid project tree: {exc}") from exc


def validate_project_files(
    files: Mapping[PurePosixPath, bytes],
) -> ProjectBundle:
    """Load and cross-validate one complete in-memory schema-v3 project."""

    with tempfile.TemporaryDirectory(prefix="reprobit-project-candidate-") as directory:
        root = Path(directory)
        for relative, data in files.items():
            destination = root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        return load_project_tree(root, verify_source_authority=False)
