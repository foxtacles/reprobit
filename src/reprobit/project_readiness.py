"""Plain-language readiness checks for a ReproBit project tree."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from reprobit.project_loader import load_project, load_project_tree


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


def _json_documents(path: Path) -> tuple[Path, ...]:
    if path.is_symlink() or not path.is_dir():
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
                    f"rbit init {candidate}",
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
    intervention_documents = _json_documents(project_path(spec.layout.interventions))
    proof_documents = _json_documents(project_path(spec.layout.proofs))
    oracle_documents = _json_documents(project_path(spec.layout.oracles))
    references = tuple(project_path(target.oracle) for target in spec.targets)

    structural = (
        ("toolchain_lock", "Compiler lock", _real_file(lock), str(lock)),
        ("source_manifest", "Source lock", _real_file(source), str(source)),
        ("build_plan", "Build plan", _real_file(build_plan), str(build_plan)),
        ("producer_graph", "Build graph", _real_file(graph), str(graph)),
    )
    items: list[ReadinessItem] = [
        ReadinessItem("project", "Project", True, f"{spec.project_id} uses schema 3")
    ]
    next_commands = {
        "toolchain_lock": f"rbit setup {candidate}",
        "source_manifest": f"rbit source lock --project {candidate}",
        "producer_graph": f"rbit graph configure --project {candidate}",
    }
    for identifier, label, present, path in structural:
        items.append(
            ReadinessItem(
                identifier,
                label,
                present,
                "ready" if present else f"missing {path}",
                None if present else next_commands.get(identifier),
            )
        )
    for identifier, label, documents, directory in (
        (
            "interventions",
            "Interventions",
            intervention_documents,
            project_path(spec.layout.interventions),
        ),
        ("proofs", "Proofs", proof_documents, project_path(spec.layout.proofs)),
        ("oracles", "Reference metadata", oracle_documents, project_path(spec.layout.oracles)),
    ):
        items.append(
            ReadinessItem(
                identifier,
                label,
                bool(documents),
                (
                    f"{len(documents)} document(s)"
                    if documents
                    else f"add reviewed JSON documents beneath {directory}"
                ),
            )
        )
    missing_references = tuple(path for path in references if not _real_file(path))
    items.append(
        ReadinessItem(
            "references",
            "Protected references",
            not missing_references,
            (
                f"{len(references)} reference file(s) ready"
                if not missing_references
                else "missing " + ", ".join(str(path) for path in missing_references)
            ),
        )
    )

    prerequisites_ready = all(item.ready for item in items)
    validation_detail = "complete the missing items above"
    validated = False
    if prerequisites_ready:
        try:
            load_project_tree(candidate)
        except Exception as error:
            validation_detail = str(error)
        else:
            validated = True
            validation_detail = "all committed authority agrees"
    items.append(
        ReadinessItem(
            "authority",
            "Authority",
            validated,
            validation_detail,
            None if validated else f"rbit validate {candidate}",
        )
    )
    return ProjectReadiness(candidate, tuple(items))


def render_project_readiness(readiness: ProjectReadiness, *, include_ready: bool = False) -> str:
    """Render a compact checklist with one next action."""

    if readiness.ready:
        return f"Project ready: {readiness.completed}/{len(readiness.items)} checks passed"
    lines = [
        f"Project setup: {readiness.completed}/{len(readiness.items)} checks ready",
    ]
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
