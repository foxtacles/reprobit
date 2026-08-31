"""Plain-language readiness checks for a ReproBit project tree."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from reprobit.cli_output import count_phrase, human_command
from reprobit.project_loader import load_project, load_project_tree
from reprobit.schema import SourceManifestDocument, ToolchainLock
from reprobit.toolchains import ClassicMSVCToolchain, ToolchainError
from reprobit.user_config import UserConfigError, resolve_toolchain_root


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
    def next_item(self) -> ReadinessItem | None:
        return next((item for item in self.items if not item.ready), None)

    @property
    def next_command(self) -> str | None:
        return None if self.next_item is None else self.next_item.next_command

    @property
    def next_step(self) -> str | None:
        """Return the first actionable command or manual setup instruction."""

        item = self.next_item
        if item is None:
            return None
        return item.next_command or item.detail


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


def inspect_project_readiness(
    root: Path,
    *,
    check_local_environment: bool = False,
    local_toolchain_root: str | Path | None = None,
) -> ProjectReadiness:
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
    ]
    if check_local_environment:
        setup_command = human_command(("rbit", "setup", candidate))
        lock_document: ToolchainLock | None = None
        lock_error: OSError | ValueError | None = None
        if _real_file(lock):
            try:
                lock_document = ToolchainLock.model_validate_json(lock.read_bytes())
            except (OSError, ValueError) as error:
                lock_error = error
        try:
            selected_root = resolve_toolchain_root(
                spec.toolchain.profile,
                local_toolchain_root,
                require=False,
            )
        except UserConfigError as error:
            local_ready = False
            local_detail = f"machine setting needs attention: {error}"
        else:
            if not selected_root.is_dir():
                local_ready = False
                local_detail = f"not available on this machine at {selected_root}"
            elif lock_error is not None:
                local_ready = False
                local_detail = f"saved compiler lock needs attention: {lock_error}"
            else:
                try:
                    doctor = ClassicMSVCToolchain(
                        spec.toolchain.profile,
                        selected_root,
                    ).doctor(lock_document)
                except ToolchainError as error:
                    local_ready = False
                    local_detail = f"incomplete at {selected_root}: {error}"
                except OSError as error:
                    local_ready = False
                    local_detail = f"cannot inspect {selected_root}: {error}"
                else:
                    local_ready = doctor.ok
                    if local_ready:
                        local_detail = f"available at {selected_root}"
                    else:
                        first_failure = next(check for check in doctor.checks if not check.passed)
                        local_detail = (
                            f"incomplete at {selected_root}: "
                            f"{first_failure.path}: {first_failure.detail}"
                        )
        items.append(
            ReadinessItem(
                "local_toolchain",
                "Local compiler",
                local_ready,
                local_detail,
                None if local_ready else setup_command,
            )
        )
    items.extend(
        [
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
                (None if source_ready else human_command(("rbit", "source", "preview", candidate))),
            ),
        ]
    )

    missing_references = tuple(path for path in references if not _real_file(path))
    if not missing_references:
        reference_detail = f"{count_phrase(len(references), 'reference file')} ready"
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
            detail = count_phrase(len(documents), "document")
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
    prerequisites_ready = all(item.ready for item in items if item.id != "local_toolchain")
    validation_detail = "finish the missing steps above"
    validated = False
    repairable_source_drift = False
    if prerequisites_ready:
        try:
            load_project_tree(candidate)
        except Exception as error:
            validation_detail = str(error)
            repair_hint = "run rbit repair ."
            repairable_source_drift = repair_hint in validation_detail
            if repairable_source_drift:
                validation_detail = validation_detail.removeprefix("invalid project tree: ")
                validation_detail = validation_detail.replace(f"; {repair_hint}", ".")
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

    scope = (
        "Project and machine"
        if any(item.id == "local_toolchain" for item in readiness.items)
        else "Project files"
    )
    if readiness.ready:
        summary = f"{scope} ready: {readiness.completed}/{len(readiness.items)} checks passed"
        if not include_ready:
            return summary
    else:
        summary = f"{scope}: {readiness.completed}/{len(readiness.items)} checks ready"
    lines = [summary]
    for item in readiness.items:
        if item.ready and not include_ready:
            continue
        marker = "ok" if item.ready else "  "
        lines.append(f"[{marker}] {item.label}: {item.detail}")
    if readiness.next_step is not None:
        lines.append(f"Next: {readiness.next_step}")
    return "\n".join(lines)


__all__ = [
    "ProjectReadiness",
    "ReadinessItem",
    "inspect_project_readiness",
    "render_project_readiness",
]
