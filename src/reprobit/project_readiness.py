"""Plain-language readiness checks for a ReproBit project tree."""

from __future__ import annotations

import json
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
    broken: bool = False
    """A saved file exists but cannot be read; ``rbit validate`` explains it."""
    pending: bool = False
    """The check cannot run until the items before it are ready."""


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


def _unparseable_json(documents: tuple[Path, ...]) -> tuple[Path, ...]:
    """Return the documents that are not JSON at all (no schema validation)."""

    broken: list[Path] = []
    for document in documents:
        try:
            json.loads(document.read_bytes())
        except (OSError, ValueError):
            broken.append(document)
    return tuple(broken)


def _relative(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


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
                    broken=True,
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
    setup_command = human_command(("rbit", "setup", candidate))
    validate_command = human_command(("rbit", "validate", candidate))

    source_ready = False
    source_broken = False
    source_detail = f"run rbit source preview to create {_relative(candidate, source)}"
    if _real_file(source):
        try:
            source_document = SourceManifestDocument.model_validate_json(source.read_bytes())
        except (OSError, ValueError) as error:
            source_broken = True
            source_detail = f"{_relative(candidate, source)} is not valid: {error}"
        else:
            source_ready = source_document.complete
            source_detail = (
                "ready"
                if source_ready
                else "run rbit source preview to finish reviewing and locking the tracked files"
            )

    items: list[ReadinessItem] = [
        ReadinessItem("project", "Project", True, f"project ID {spec.project_id}"),
    ]
    if check_local_environment:
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
                (
                    "ready"
                    if _real_file(lock)
                    else f"run rbit setup to create {_relative(candidate, lock)}"
                ),
                None if _real_file(lock) else setup_command,
            ),
            ReadinessItem(
                "source_manifest",
                "Source lock",
                source_ready,
                source_detail,
                (
                    None
                    if source_ready
                    else (
                        validate_command
                        if source_broken
                        else human_command(("rbit", "source", "preview", candidate))
                    )
                ),
                broken=source_broken,
            ),
        ]
    )

    missing_references = tuple(path for path in references if not _real_file(path))
    if not missing_references:
        reference_detail = f"{count_phrase(len(references), 'reference file')} ready"
    elif len(missing_references) == 1:
        reference_detail = f"place the original at {_relative(candidate, missing_references[0])}"
    else:
        reference_detail = "place the originals at " + ", ".join(
            _relative(candidate, path) for path in missing_references
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
                (
                    "ready"
                    if present
                    else f"run rbit import cmake to create {_relative(candidate, path)}"
                ),
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
        unparseable = _unparseable_json(documents)
        ready = directory_ready and (bool(documents) or not documents_required)
        ready = ready and not unparseable
        next_command = None
        if unparseable:
            detail = f"{_relative(candidate, unparseable[0])} is not valid JSON; run rbit validate"
            next_command = validate_command
        elif documents:
            detail = count_phrase(len(documents), "document")
        elif not directory_ready:
            detail = f"run rbit import cmake to create {_relative(candidate, directory)}/"
        elif documents_required:
            detail = (
                "run rbit import cmake to add reviewed JSON documents beneath "
                f"{_relative(candidate, directory)}/"
            )
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
                next_command,
                broken=bool(unparseable),
            )
        )
    prerequisites_ready = all(item.ready for item in items if item.id != "local_toolchain")
    validation_detail = "not checked until the project files above are ready"
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
                if validated or not prerequisites_ready
                else human_command(
                    ("rbit", "repair" if repairable_source_drift else "validate", candidate)
                )
            ),
            pending=not prerequisites_ready,
        )
    )
    return ProjectReadiness(candidate, tuple(items))


def render_project_readiness(readiness: ProjectReadiness, *, include_ready: bool = False) -> str:
    """Render a compact checklist with one next action.

    The project root appears once in the header; rows name files relative to
    it. ``[ok]`` passed, ``[  ]`` is still missing, ``[!!]`` exists but cannot
    be read. A pending check (one that waits for the rows above it) is counted
    but not listed, because it carries no information of its own yet.
    """

    scope = (
        "Project and machine"
        if any(item.id == "local_toolchain" for item in readiness.items)
        else "Project files"
    )
    header = f"Project: {readiness.root}"
    if readiness.ready:
        summary = f"{scope} ready: {readiness.completed}/{len(readiness.items)} checks passed"
        if not include_ready:
            return "\n".join((header, summary))
    else:
        summary = f"{scope}: {readiness.completed}/{len(readiness.items)} checks ready"
    lines = [header, summary]
    for item in readiness.items:
        if (item.ready and not include_ready) or item.pending:
            continue
        marker = "ok" if item.ready else ("!!" if item.broken else "  ")
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
