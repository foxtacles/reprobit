"""Plain-language readiness checks for a ReproBit project tree."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from reprobit.cli_output import human_command
from reprobit.project_loader import load_project, load_project_tree
from reprobit.schema import SourceManifestDocument


@dataclass(frozen=True, slots=True)
class ReadinessItem:
    """One honest setup condition and, when possible, its next command."""

    id: str
    label: str
    ready: bool
    detail: str
    next_command: str | None = None


@dataclass(frozen=True, slots=True)
class ProjectReadiness:
    root: Path
    items: tuple[ReadinessItem, ...]

    @property
    def ready(self) -> bool:
        return bool(self.items) and all(item.ready for item in self.items)

    @property
    def completed(self) -> int:
        return sum(item.ready for item in self.items)

    @property
    def next_command(self) -> str | None:
        first_missing = next((item for item in self.items if not item.ready), None)
        return None if first_missing is None else first_missing.next_command


def _real_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _real_directory(path: Path) -> bool:
    return path.is_dir() and not path.is_symlink()


def _json_documents(path: Path) -> tuple[Path, ...]:
    if not _real_directory(path):
        return ()
    return tuple(
        child
        for child in sorted(path.rglob("*.json"), key=lambda item: item.as_posix())
        if child.is_file() and not child.is_symlink()
    )


def inspect_project_readiness(root: Path) -> ProjectReadiness:
    """Aggregate missing authority instead of failing one file at a time."""

    candidate = root.expanduser().resolve(strict=False)
    entrypoint = candidate / "reprobit.toml"
    if not _real_file(entrypoint):
        return ProjectReadiness(
            candidate,
            (
                ReadinessItem(
                    "project",
                    "Project",
                    False,
                    "reprobit.toml has not been created",
                    human_command(("rbit", "init", candidate)),
                ),
            ),
        )

    try:
        spec = load_project(entrypoint)
    except Exception as error:
        return ProjectReadiness(
            candidate,
            (
                ReadinessItem(
                    "project",
                    "Project",
                    False,
                    f"reprobit.toml is invalid: {error}",
                    None,
                ),
            ),
        )

    def project_path(value: str) -> Path:
        return candidate.joinpath(*value.replace("\\", "/").split("/"))

    lock = project_path(spec.toolchain.lock_file)
    source = project_path(spec.layout.source_manifest)
    build_plan = project_path(spec.layout.build_plan)
    graph = project_path(spec.layout.producer_graph)
    interventions_directory = project_path(spec.layout.interventions)
    proofs_directory = project_path(spec.layout.proofs)
    oracles_directory = project_path(spec.layout.oracles)
    intervention_documents = _json_documents(interventions_directory)
    proof_documents = _json_documents(proofs_directory)
    oracle_documents = _json_documents(oracles_directory)
    references = tuple(project_path(target.oracle) for target in spec.targets)

    source_ready = False
    source_detail = f"missing {source}"
    if _real_file(source):
        try:
            source_document = SourceManifestDocument.model_validate_json(source.read_bytes())
        except (OSError, ValueError) as error:
            source_detail = f"invalid {source}: {error}"
        else:
            source_ready = source_document.complete
            source_detail = (
                "ready"
                if source_ready
                else "source review is incomplete; preview and lock the tracked files"
            )

    items: list[ReadinessItem] = [
        ReadinessItem("project", "Project", True, f"project ID {spec.project_id}"),
        ReadinessItem(
            "toolchain_lock",
            "Compiler lock",
            _real_file(lock),
            "ready" if _real_file(lock) else f"missing {lock}",
            (None if _real_file(lock) else human_command(("rbit", "setup", candidate))),
        ),
        ReadinessItem(
            "source_manifest",
            "Source lock",
            source_ready,
            source_detail,
            (
                None
                if source_ready
                else human_command(("rbit", "source", "preview", "--project", candidate))
            ),
        ),
    ]

    missing_references = tuple(path for path in references if not _real_file(path))
    if not missing_references:
        reference_detail = f"{len(references)} reference file(s) ready"
    elif len(missing_references) == 1:
        reference_detail = f"Place the original at {missing_references[0]}"
    else:
        reference_detail = "Place the originals at " + ", ".join(
            str(path) for path in missing_references
        )
    items.append(
        ReadinessItem(
            "references",
            "Protected references",
            not missing_references,
            reference_detail,
        )
    )

    import_command = human_command(("rbit", "import", "cmake", candidate))
    for identifier, label, path in (
        ("build_plan", "Build plan", build_plan),
        ("producer_graph", "Build graph", graph),
    ):
        present = _real_file(path)
        items.append(
            ReadinessItem(
                identifier,
                label,
                present,
                "ready" if present else f"missing {path}",
                None if present or missing_references else import_command,
            )
        )
    for identifier, label, documents, directory, documents_required in (
        (
            "interventions",
            "Interventions",
            intervention_documents,
            interventions_directory,
            False,
        ),
        ("proofs", "Proofs", proof_documents, proofs_directory, False),
        (
            "oracles",
            "Reference metadata",
            oracle_documents,
            oracles_directory,
            True,
        ),
    ):
        directory_ready = _real_directory(directory)
        ready = directory_ready and (bool(documents) or not documents_required)
        if documents:
            detail = f"{len(documents)} document(s)"
        elif not directory_ready:
            detail = f"create the folder {directory}"
        elif documents_required:
            detail = f"add reviewed JSON documents beneath {directory}"
        elif identifier == "interventions":
            detail = "0 documents (valid when no build adjustment is needed)"
        else:
            detail = "0 documents (valid when there is nothing to prove)"
        items.append(
            ReadinessItem(
                identifier,
                label,
                ready,
                detail,
            )
        )
    prerequisites_ready = all(item.ready for item in items)
    validation_detail = "finish the missing steps above"
    validated = False
    repairable_source_drift = False
    if prerequisites_ready:
        try:
            load_project_tree(candidate)
        except Exception as error:
            validation_detail = str(error)
            repairable_source_drift = "run rbit repair ." in validation_detail
        else:
            validated = True
            validation_detail = "all saved project files agree"
    items.append(
        ReadinessItem(
            "authority",
            "Final project check",
            validated,
            validation_detail,
            (
                None
                if validated
                else human_command(
                    ("rbit", "repair" if repairable_source_drift else "validate", candidate)
                )
            ),
        )
    )
    return ProjectReadiness(candidate, tuple(items))


def render_project_readiness(readiness: ProjectReadiness, *, include_ready: bool = False) -> str:
    """Render a compact checklist with one next action."""

    if readiness.ready:
        summary = f"Project files ready: {readiness.completed}/{len(readiness.items)} checks passed"
        if not include_ready:
            return summary
    else:
        summary = f"Project files: {readiness.completed}/{len(readiness.items)} checks ready"
    lines = [summary]
    for item in readiness.items:
        if item.ready and not include_ready:
            continue
        marker = "ok" if item.ready else "  "
        lines.append(f"[{marker}] {item.label}: {item.detail}")
    if readiness.next_command is not None:
        lines.append(f"Next: {readiness.next_command}")
    return "\n".join(lines)


__all__ = [
    "ProjectReadiness",
    "ReadinessItem",
    "inspect_project_readiness",
    "render_project_readiness",
]
