"""Production command-line interface for ReproBit project workflows."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from enum import Enum
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from threading import Lock
from typing import TYPE_CHECKING, Any, TextIO

from pydantic import BaseModel
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from reprobit.backends import (
    POSIX_WINE_BACKEND,
    WINDOWS_NATIVE_BACKEND,
    ExecutionBackend,
    NativeWindowsBackend,
    PosixWineBackend,
    backend_for_host,
)
from reprobit.build import BuildPlan, BuildStep
from reprobit.costs import CostBreakdown, InterventionCost, calculate_cost
from reprobit.model import AuthenticityPolicy, Digest
from reprobit.producer_graph import (
    ProducerGraphDocument,
    extract_cmake_unix_makefiles_graph,
    graph_reference,
    producer_graph_accepts_source,
    producer_graph_digest,
    source_topology_digest,
    toolchain_document_digest,
)
from reprobit.progress import ProgressEmitter, ProgressEvent, ProgressKind
from reprobit.schema import (
    BuildPlanDocument,
    CommandBuildAdapter,
    Intervention,
    LogicalPathProfile,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    ProjectSpec,
    SourceManifestDocument,
    SourceManifestEntry,
    TargetSpec,
    ToolchainRef,
    load_project,
    load_project_tree,
    source_manifest_digest,
)
from reprobit.state import KeepWorkspace, RunArena, StateStore, human_bytes
from reprobit.strict_json import canonical_json, strict_load
from reprobit.toolchains import TOOLCHAIN_PROFILES, ClassicMSVCToolchain, ToolchainLock
from reprobit.transactions import CASTransaction

if TYPE_CHECKING:
    from reprobit.classic_runtime import ClassicProducerGraphPreparedRun
    from reprobit.incremental import IncrementalBuildSummary


class CLIError(RuntimeError):
    """A command cannot honestly complete with the supplied inputs."""


try:
    _VERSION = version("reprobit")
except PackageNotFoundError:
    _VERSION = "0.1.0.dev0"


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", exclude_none=True)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_jsonable(item) for item in value]
    return value


@dataclass(slots=True)
class _Output:
    output_format: str
    stdout: TextIO
    stderr: TextIO
    heartbeat_seconds: float = 5.0
    _progress: ProgressEmitter = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._progress = ProgressEmitter(
            self._observe_progress,
            heartbeat_seconds=self.heartbeat_seconds,
        )

    @property
    def _interactive(self) -> bool:
        return bool(getattr(self.stderr, "isatty", lambda: False)())

    def _observe_progress(self, progress_event: ProgressEvent) -> None:
        if self.output_format == "ndjson":
            event_name = (
                "producer_progress"
                if progress_event.kind
                in {
                    ProgressKind.UNIT_FINISHED,
                    ProgressKind.CACHE_HIT,
                    ProgressKind.CACHE_MISS,
                }
                else "workflow_progress"
            )
            document = {"event": event_name, **progress_event.as_dict()}
            self.stdout.write(
                json.dumps(
                    document,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
            self.stdout.flush()
            return
        if self._interactive or progress_event.kind in {
            ProgressKind.UNIT_FINISHED,
            ProgressKind.CACHE_HIT,
            ProgressKind.CACHE_MISS,
        }:
            return
        if progress_event.kind is ProgressKind.PHASE_STARTED:
            rendered = f"{progress_event.message}..."
        elif progress_event.kind is ProgressKind.HEARTBEAT:
            rendered = (
                f"{progress_event.message}... "
                f"({progress_event.elapsed_seconds:.1f}s elapsed)"
            )
        elif progress_event.kind is ProgressKind.PHASE_FINISHED:
            rendered = (
                f"{progress_event.message}: complete "
                f"({progress_event.elapsed_seconds:.1f}s elapsed)"
            )
        elif progress_event.kind is ProgressKind.PHASE_FAILED:
            rendered = f"{progress_event.message}: failed"
        else:
            rendered = progress_event.message
        self.stderr.write(rendered + "\n")
        self.stderr.flush()

    def emit(
        self,
        event: str,
        message: str,
        *,
        diagnostic: bool = False,
        **fields: Any,
    ) -> None:
        if self.output_format == "ndjson":
            document = {"event": event, "message": message, **fields}
            self.stdout.write(
                json.dumps(
                    _jsonable(document),
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )
        else:
            stream = self.stderr if diagnostic else self.stdout
            stream.write(message + "\n")
            stream.flush()
            return
        self.stdout.flush()

    def incremental_summary(self, summary: IncrementalBuildSummary) -> None:
        """Emit one compact warm-build cache/runtime outcome."""

        message = (
            f"incremental build: {summary.hits} hit, {summary.misses} miss "
            f"({summary.hit_rate:.1%}); {summary.runtime_init_count} runtime lane(s); "
            f"{summary.elapsed_seconds:.2f}s"
        )
        if summary.published_targets or summary.unchanged_targets:
            message += (
                f"; targets: {summary.unchanged_targets} unchanged, "
                f"{summary.published_targets} updated"
            )
        if self.output_format == "text" and summary.invalidations:
            visible = summary.invalidations[:8]
            lines = [message, "cache invalidations:"]
            lines.extend(f"  {node_id}: {reason}" for node_id, reason in visible)
            remaining = len(summary.invalidations) - len(visible)
            if remaining:
                lines.append(f"  ... and {remaining} more")
            message = "\n".join(lines)
        self.emit(
            "incremental_build_summary",
            message,
            producer_hits=summary.producer_hits,
            producer_misses=summary.producer_misses,
            transform_hits=summary.transform_hits,
            transform_misses=summary.transform_misses,
            hits=summary.hits,
            misses=summary.misses,
            hit_rate=summary.hit_rate,
            elapsed_seconds=summary.elapsed_seconds,
            runtime_init_count=summary.runtime_init_count,
            published_targets=summary.published_targets,
            unchanged_targets=summary.unchanged_targets,
            invalidations=[
                {"node_id": node_id, "reason": reason}
                for node_id, reason in summary.invalidations
            ],
        )

    @contextmanager
    def activity(self, description: str, *, phase: str = "work") -> Iterator[None]:
        with self._progress.phase(phase, description):
            if self.output_format != "text" or not self._interactive:
                yield
                return
            console = Console(file=self.stderr)
            with Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,
            ) as progress:
                progress.add_task(description, total=None)
                yield

    @contextmanager
    def producer_activity(
        self, description: str
    ) -> Iterator[Callable[..., None]]:
        """Render serialized producer progress without corrupting machine output."""

        lock = Lock()
        with self._progress.phase("execute", description) as phase_scope:
            if self.output_format == "ndjson":

                def emit_ndjson(
                    completed: int,
                    total: int,
                    phase: str,
                    node_id: str,
                    kind: ProgressKind = ProgressKind.UNIT_FINISHED,
                    reason: str | None = None,
                ) -> None:
                    if kind in {ProgressKind.CACHE_HIT, ProgressKind.CACHE_MISS}:
                        phase_scope.cache(
                            hit=kind is ProgressKind.CACHE_HIT,
                            completed=completed,
                            total=total,
                            phase=phase,
                            node_id=node_id,
                            reason=reason,
                        )
                    else:
                        phase_scope.advance(
                            completed=completed,
                            total=total,
                            phase=phase,
                            node_id=node_id,
                        )

                yield emit_ndjson
                return
            if self._interactive:
                console = Console(file=self.stderr)
                with Progress(
                    TextColumn("{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    console=console,
                    transient=True,
                ) as progress:
                    task = progress.add_task(description, total=None)

                    def update_tty(
                        completed: int,
                        total: int,
                        phase: str,
                        node_id: str,
                        kind: ProgressKind = ProgressKind.UNIT_FINISHED,
                        reason: str | None = None,
                    ) -> None:
                        if kind in {ProgressKind.CACHE_HIT, ProgressKind.CACHE_MISS}:
                            phase_scope.cache(
                                hit=kind is ProgressKind.CACHE_HIT,
                                completed=completed,
                                total=total,
                                phase=phase,
                                node_id=node_id,
                                reason=reason,
                            )
                            disposition = (
                                "hit" if kind is ProgressKind.CACHE_HIT else "miss"
                            )
                        else:
                            phase_scope.advance(
                                completed=completed,
                                total=total,
                                phase=phase,
                                node_id=node_id,
                            )
                            disposition = "complete"
                        with lock:
                            progress.update(
                                task,
                                total=total,
                                completed=completed,
                                description=f"{phase}: {node_id} ({disposition})",
                            )

                    yield update_tty
                return

            last_decile = -1
            cache_hits = 0
            cache_misses = 0
            latest: tuple[int, int, str, str] | None = None
            last_rendered_completed: int | None = None

            def emit_text(
                completed: int,
                total: int,
                phase: str,
                node_id: str,
                kind: ProgressKind = ProgressKind.UNIT_FINISHED,
                reason: str | None = None,
            ) -> None:
                nonlocal cache_hits, cache_misses, last_decile
                nonlocal latest, last_rendered_completed
                if kind in {ProgressKind.CACHE_HIT, ProgressKind.CACHE_MISS}:
                    hit = kind is ProgressKind.CACHE_HIT
                    cache_hits += int(hit)
                    cache_misses += int(not hit)
                    phase_scope.cache(
                        hit=hit,
                        completed=completed,
                        total=total,
                        phase=phase,
                        node_id=node_id,
                        reason=reason,
                    )
                else:
                    phase_scope.advance(
                        completed=completed,
                        total=total,
                        phase=phase,
                        node_id=node_id,
                    )
                latest = (completed, total, phase, node_id)
                decile = 10 if completed == total else (completed * 10) // max(total, 1)
                if completed != 1 and decile <= last_decile:
                    return
                with lock:
                    if completed != 1 and decile <= last_decile:
                        return
                    last_decile = decile
                    cache = (
                        f"; cache {cache_hits} hit/{cache_misses} miss"
                        if cache_hits or cache_misses
                        else ""
                    )
                    self.stderr.write(
                        f"{description}: {completed}/{total} "
                        f"({phase}: {node_id}{cache})\n"
                    )
                    self.stderr.flush()
                    last_rendered_completed = completed

            try:
                yield emit_text
            except BaseException:
                with lock:
                    if latest is not None and latest[0] != last_rendered_completed:
                        completed, total, phase, node_id = latest
                        cache = (
                            f"; cache {cache_hits} hit/{cache_misses} miss"
                            if cache_hits or cache_misses
                            else ""
                        )
                        self.stderr.write(
                            f"{description}: failed after {completed}/{total} "
                            f"(last completed: {phase}: {node_id}{cache})\n"
                        )
                        self.stderr.flush()
                raise


def _project_root(value: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_dir() or path.is_symlink():
        raise CLIError(f"project root is not an existing real directory: {path}")
    return path.resolve(strict=True)


def _safe_project_path(root: Path, value: str) -> Path:
    path = (root / value.replace("\\", "/")).resolve(strict=False)
    try:
        path.relative_to(root)
    except ValueError as error:
        raise CLIError(f"path escapes the project root: {value}") from error
    return path


def _relative_output(root: Path, value: str) -> Path:
    candidate = Path(value)
    absolute = candidate if candidate.is_absolute() else root / candidate
    absolute = absolute.resolve(strict=False)
    try:
        return absolute.relative_to(root)
    except ValueError as error:
        raise CLIError(f"transaction output is outside the project: {absolute}") from error


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _render_initial_project(spec: ProjectSpec) -> bytes:
    assert isinstance(spec.build, ProducerGraphBuildAdapter)
    target = spec.targets[0]
    lines = [
        "schema_version = 3",
        f"project_id = {_toml_string(spec.project_id)}",
        f"state_dir = {_toml_string(spec.state_dir)}",
        "",
        "[build]",
        'kind = "producer-graph"',
        "",
        "[toolchain]",
        'adapter = "classic-msvc"',
        f"profile = {_toml_string(spec.toolchain.profile)}",
        f"lock_file = {_toml_string(spec.toolchain.lock_file)}",
        "",
        "[paths]",
        f"id = {_toml_string(spec.paths.id)}",
        f"source = {_toml_string(spec.paths.source)}",
        f"build = {_toml_string(spec.paths.build)}",
        f"toolchain = {_toml_string(spec.paths.toolchain)}",
        "",
        "[verifier]",
        'kind = "literal"',
        "",
        "[authenticity]",
        'policy = "clean"',
        "",
        "[[targets]]",
        f"id = {_toml_string(target.id)}",
        f"artifact = {_toml_string(target.artifact)}",
        f"oracle = {_toml_string(target.oracle)}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _command_init(args: argparse.Namespace, output: _Output) -> int:
    root = Path(args.path).expanduser().resolve(strict=False)
    if root.exists() and (not root.is_dir() or root.is_symlink()):
        raise CLIError(f"initialization target is not a real directory: {root}")
    root.mkdir(parents=True, exist_ok=True)
    spec = ProjectSpec(
        schema_version=3,
        project_id=args.project_id,
        build=ProducerGraphBuildAdapter(),
        toolchain=ToolchainRef(profile=args.profile),
        paths=LogicalPathProfile(
            source=args.logical_source,
            build=args.logical_build,
            toolchain=args.logical_toolchain,
        ),
        targets=(TargetSpec(id=args.target, artifact=args.artifact, oracle=args.oracle),),
    )
    project_data = _render_initial_project(spec)
    initial_manifest = SourceManifestDocument(
        schema_version=3,
        complete=True,
        entries=(
            SourceManifestEntry(
                path="reprobit.toml",
                size=len(project_data),
                digest=Digest.from_bytes(project_data),
            ),
        ),
    )
    transaction = CASTransaction(root)
    transaction.write("reprobit.toml", project_data, expected_sha256=None)
    transaction.write(
        spec.layout.source_manifest,
        canonical_json(initial_manifest),
        expected_sha256=None,
    )
    result = transaction.commit()
    output.emit(
        "initialized",
        f"initialized schema-v3 project at {root}",
        project_root=root,
        changed_paths=result.changed_paths,
    )
    return 0


def _explicit_source_paths(root: Path, values: Sequence[str]) -> tuple[str, ...]:
    paths: list[str] = []
    for value in values:
        relative = _relative_output(root, value)
        candidate = root / relative
        if candidate.is_symlink() or not candidate.exists():
            raise CLIError(f"source lock input is absent or redirected: {relative}")
        if candidate.is_file():
            paths.append(relative.as_posix())
            continue
        for child in sorted(candidate.rglob("*"), key=lambda item: item.as_posix()):
            if child.is_symlink():
                raise CLIError(f"source lock tree contains a symlink: {child}")
            if child.is_file():
                paths.append(child.relative_to(root).as_posix())
    return tuple(paths)


def _build_source_document(
    root: Path,
    spec: ProjectSpec,
    values: Sequence[str],
    output: _Output,
) -> SourceManifestDocument:
    from reprobit.source_lock import build_source_manifest, git_tracked_paths

    paths = (
        _explicit_source_paths(root, values)
        if values
        else git_tracked_paths(root)
    )
    with output.activity("hashing the complete project source read set"):
        return build_source_manifest(root, paths, spec=spec, complete=True)


def _load_source_manifest(path: Path) -> SourceManifestDocument:
    return SourceManifestDocument.model_validate_json(canonical_json(strict_load(path)))


def _load_build_plan(path: Path) -> BuildPlanDocument:
    return BuildPlanDocument.model_validate_json(canonical_json(strict_load(path)))


def _source_changes(
    before: SourceManifestDocument,
    after: SourceManifestDocument,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[dict[str, Any], ...]]:
    old = {item.path: item for item in before.entries}
    new = {item.path: item for item in after.entries}
    added = tuple(sorted(set(new) - set(old), key=lambda item: (item.casefold(), item)))
    removed = tuple(sorted(set(old) - set(new), key=lambda item: (item.casefold(), item)))
    changed = tuple(
        {
            "path": path,
            "before_digest": old[path].digest.value,
            "after_digest": new[path].digest.value,
            "before_size": old[path].size,
            "after_size": new[path].size,
        }
        for path in sorted(set(old) & set(new), key=lambda item: (item.casefold(), item))
        if old[path].digest != new[path].digest or old[path].size != new[path].size
    )
    return added, removed, changed


def _inspect_candidate_source_authority(
    root: Path,
    spec: ProjectSpec,
    document: SourceManifestDocument,
    document_digest: Digest,
) -> tuple[BuildPlanDocument | None, Any | None]:
    build_plan_path = _safe_project_path(root, spec.layout.build_plan)
    if not build_plan_path.is_file():
        return None, None
    plan = _load_build_plan(build_plan_path).model_copy(
        update={"source_manifest_digest": document_digest}
    )
    bundle = load_project_tree(root, verify_source_authority=False)
    from reprobit.source_authority import inspect_source_authority

    return plan, inspect_source_authority(
        bundle,
        root,
        source_manifest=document,
        build_plan=plan,
    )


def _stale_tu_fields(report: Any | None) -> tuple[dict[str, Any], ...]:
    if report is None:
        return ()
    return tuple(
        {
            "translation_unit_id": item.translation_unit_id,
            "source": item.source,
            "expected_digest": item.expected_digest,
            "actual_digest": item.actual_digest,
        }
        for item in report.stale_translation_units
    )


def _source_preview_message(
    *,
    added: Sequence[str],
    removed: Sequence[str],
    changed: Sequence[Mapping[str, Any]],
    entries: int,
    graph_invalidation_required: bool,
    authority_checked: bool,
    authority_error: str | None,
    stale_units: Sequence[Mapping[str, Any]],
) -> str:
    lines = [
        f"source preview: +{len(added)} -{len(removed)} ~{len(changed)}; "
        f"{entries} admitted input(s)"
    ]
    if added:
        lines.append("  add: " + ", ".join(added))
    if removed:
        lines.append("  remove: " + ", ".join(removed))
    if changed:
        lines.append("  change: " + ", ".join(str(item["path"]) for item in changed))
    if graph_invalidation_required:
        lines.append("  producer graph: invalidation and re-extraction required")
    if authority_error is not None:
        lines.append("  authority regeneration required: " + authority_error)
    elif stale_units:
        rendered = ", ".join(
            f"{item['translation_unit_id']} ({item['source']})" for item in stale_units
        )
        lines.append("  authority regeneration required for: " + rendered)
    elif not authority_checked:
        lines.append("  no build plan; no TU or source-overlay pins were checked")
    else:
        lines.append("  reviewed TU and source-overlay pins remain valid")
    return "\n".join(lines)


def _command_source_preview(args: argparse.Namespace, output: _Output) -> int:
    root = _project_root(args.project)
    spec = load_project(root)
    document = _build_source_document(root, spec, args.path, output)
    document_digest = source_manifest_digest(document)
    current = _load_source_manifest(_safe_project_path(root, spec.layout.source_manifest))
    current_digest = source_manifest_digest(current)
    added, removed, changed = _source_changes(current, document)

    producer_graph_path = _safe_project_path(root, spec.layout.producer_graph)
    graph_invalidation_required = False
    if producer_graph_path.is_file():
        from reprobit.producer_graph import read_producer_graph

        graph_invalidation_required = not producer_graph_accepts_source(
            read_producer_graph(producer_graph_path),
            manifest_digest=document_digest,
            paths=(item.path for item in document.entries),
        )

    authority_error: str | None = None
    report: Any | None = None
    try:
        _, report = _inspect_candidate_source_authority(
            root, spec, document, document_digest
        )
    except ValueError as exc:
        from reprobit.source_authority import SourceAuthorityError

        if not isinstance(exc, SourceAuthorityError):
            raise
        authority_error = str(exc)
    stale_units = _stale_tu_fields(report)
    output.emit(
        "source_preview",
        _source_preview_message(
            added=added,
            removed=removed,
            changed=changed,
            entries=len(document.entries),
            graph_invalidation_required=graph_invalidation_required,
            authority_checked=report is not None,
            authority_error=authority_error,
            stale_units=stale_units,
        ),
        before_source_manifest_digest=current_digest.value,
        after_source_manifest_digest=document_digest.value,
        entries=len(document.entries),
        added=added,
        removed=removed,
        changed=changed,
        unchanged=len(document.entries) - len(added) - len(changed),
        producer_graph_invalidation_required=graph_invalidation_required,
        checked_overlay_outputs=(
            report.overlay_outputs if report is not None else ()
        ),
        authority_checked=report is not None,
        stale_translation_units=stale_units,
        authority_regeneration_required=bool(authority_error or stale_units),
        authority_error=authority_error,
    )
    return 0


def _command_source_lock(args: argparse.Namespace, output: _Output) -> int:
    root = _project_root(args.project)
    spec = load_project(root)
    document = _build_source_document(root, spec, args.path, output)
    document_digest = source_manifest_digest(document)

    plan: BuildPlanDocument | None = None
    report: Any | None = None
    try:
        plan, report = _inspect_candidate_source_authority(
            root, spec, document, document_digest
        )
    except ValueError as exc:
        from reprobit.source_authority import SourceAuthorityError

        if not isinstance(exc, SourceAuthorityError):
            raise
        raise CLIError(
            "source lock refused because reviewed source-overlay authority must be "
            f"regenerated: {exc}"
        ) from exc
    stale_units = _stale_tu_fields(report)
    if stale_units:
        rendered = ", ".join(
            f"{item['translation_unit_id']} ({item['source']})" for item in stale_units
        )
        raise CLIError(
            "source lock refused because effective translation-unit bytes changed; "
            "regenerate the affected intervention and proof authority instead of "
            f"repinning it: {rendered}"
        )

    producer_graph_path = _safe_project_path(root, spec.layout.producer_graph)
    graph_invalidated = False
    graph_present = producer_graph_path.is_file()
    if producer_graph_path.is_file():
        from reprobit.producer_graph import read_producer_graph

        graph = read_producer_graph(producer_graph_path)
        if not producer_graph_accepts_source(
            graph,
            manifest_digest=document_digest,
            paths=(item.path for item in document.entries),
        ):
            if not args.invalidate_producer_graph:
                raise CLIError(
                    "source authority changed while a producer graph is committed; "
                    "rerun with --invalidate-producer-graph, reconfigure the project, "
                    "then run `rbit graph extract`"
                )
            graph_invalidated = True

    transaction = CASTransaction(root)
    transaction.write(spec.layout.source_manifest, canonical_json(document))
    if plan is not None:
        transaction.write(spec.layout.build_plan, canonical_json(plan))
    if graph_invalidated:
        transaction.delete(spec.layout.producer_graph)
    elif graph_present:
        transaction.assert_unchanged(spec.layout.producer_graph)
    for entry in document.entries:
        transaction.assert_unchanged(entry.path, expected_sha256=entry.digest.value)
    result = transaction.commit()
    output.emit(
        "source_locked",
        f"locked {len(document.entries)} project source input(s)",
        output=spec.layout.source_manifest,
        entries=len(document.entries),
        source_manifest_digest=document_digest.value,
        producer_graph_invalidated=graph_invalidated,
        transaction_id=result.transaction_id,
    )
    return 0


def _selected_backend(args: argparse.Namespace) -> ExecutionBackend:
    if args.backend == "auto":
        return backend_for_host()
    if args.backend == POSIX_WINE_BACKEND:
        return PosixWineBackend(wine=args.wine, wineserver=args.wineserver)
    return NativeWindowsBackend()


def _command_doctor(args: argparse.Namespace, output: _Output) -> int:
    backend = _selected_backend(args)
    report = backend.doctor(execute_probe=args.execute_probe)
    okay = report.ok
    for backend_check in report.checks:
        output.emit(
            "doctor_check",
            f"{'ok' if backend_check.passed else 'FAIL'} "
            f"backend/{backend_check.name}: {backend_check.detail}",
            component="backend",
            name=backend_check.name,
            passed=backend_check.passed,
            required=backend_check.required,
            detail=backend_check.detail,
        )
    project = Path(args.project).expanduser().resolve(strict=False)
    if (project / "reprobit.toml").is_file():
        spec = load_project(project)
        if (
            args.toolchain_profile is not None
            and args.toolchain_profile != spec.toolchain.profile
        ):
            raise CLIError(
                "requested toolchain profile differs from reprobit.toml: "
                f"{args.toolchain_profile} != {spec.toolchain.profile}"
            )
        output.emit(
            "doctor_check",
            f"ok project/schema: {spec.project_id}",
            component="project",
            name="schema",
            passed=True,
        )
        if args.toolchain_root is not None:
            installation = ClassicMSVCToolchain(
                spec.toolchain.profile,
                Path(args.toolchain_root).expanduser().resolve(strict=True),
            )
            runtime_lock = None
            lock_path = _safe_project_path(project, spec.toolchain.lock_file)
            if lock_path.is_file():
                from reprobit.schema import ToolchainLock as SchemaToolchainLock

                schema_lock = SchemaToolchainLock.model_validate_json(
                    canonical_json(strict_load(lock_path))
                )
                runtime_lock = ToolchainLock.from_schema_v3(schema_lock)
            tool_report = installation.doctor(runtime_lock)
            okay = okay and tool_report.ok
            for tool_check in tool_report.checks:
                output.emit(
                    "doctor_check",
                    f"{'ok' if tool_check.passed else 'FAIL'} "
                    f"toolchain/{tool_check.path}: {tool_check.detail}",
                    component="toolchain",
                    name=tool_check.path,
                    passed=tool_check.passed,
                    detail=tool_check.detail,
                )
    elif args.toolchain_root is not None:
        if args.toolchain_profile is None:
            raise CLIError("--toolchain-root requires --toolchain-profile without a project")
        installation = ClassicMSVCToolchain(
            args.toolchain_profile,
            Path(args.toolchain_root).expanduser().resolve(strict=True),
        )
        tool_report = installation.doctor()
        okay = okay and tool_report.ok
        for tool_check in tool_report.checks:
            output.emit(
                "doctor_check",
                f"{'ok' if tool_check.passed else 'FAIL'} "
                f"toolchain/{tool_check.path}: {tool_check.detail}",
                component="toolchain",
                name=tool_check.path,
                passed=tool_check.passed,
                detail=tool_check.detail,
            )
    output.emit(
        "doctor_result",
        "doctor checks passed" if okay else "doctor checks failed",
        passed=okay,
        backend=backend.identifier,
        executed_probe=report.executed_probe,
    )
    return 0 if okay else 1


def _command_toolchain_lock(args: argparse.Namespace, output: _Output) -> int:
    root = _project_root(args.project)
    config_path = root / "reprobit.toml"
    spec = load_project(config_path) if config_path.is_file() else None
    identifier = args.profile or (spec.toolchain.profile if spec is not None else None)
    if identifier is None:
        raise CLIError("toolchain profile is required without reprobit.toml")
    installation = ClassicMSVCToolchain(
        identifier, Path(args.root).expanduser().resolve(strict=True)
    )
    with output.activity("hashing toolchain producers and input trees"):
        runtime_lock = installation.create_lock(
            include_trees=True,
            runtime_paths=args.runtime_file,
        )
    document = runtime_lock.to_schema_v3()
    data = canonical_json(document)
    default_output = (
        spec.toolchain.lock_file if spec is not None else "reprobit/toolchain.lock.json"
    )
    relative = _relative_output(root, args.output or default_output)
    transaction = CASTransaction(root)
    transaction.write(relative, data)
    result = transaction.commit()
    output.emit(
        "toolchain_locked",
        f"locked {identifier} to {relative}",
        profile=identifier,
        output=relative,
        tools=len(document.tools),
        runtime_files=len(document.runtime_files),
        input_trees=len(document.input_trees),
        transaction_id=result.transaction_id,
    )
    return 0


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
        path = _safe_project_path(root, relative.as_posix())
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
        directory = _safe_project_path(root, directory_text)
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


def _command_graph_configure(args: argparse.Namespace, output: _Output) -> int:
    """Create a fresh, non-certifying CMake tree for graph extraction."""

    from reprobit.classic_migration import configure_classic_producer_graph

    root = _project_root(args.project)
    bundle = load_project_tree(root)
    workspace = Path(args.workspace_root).expanduser()
    if not workspace.is_absolute():
        workspace = Path.cwd() / workspace
    toolchain = _real_directory(args.toolchain_root, label="toolchain root")
    cmake = Path(_resolve_program(args.cmake, root))

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


def _command_graph_extract(args: argparse.Namespace, output: _Output) -> int:
    """Commit a reviewed direct-producer graph from one configured CMake tree.

    This is deliberately a migration command. Certifying builds consume its
    committed result and never execute CMake or another project build system.
    """

    from reprobit.cmake import CMakeExportPlan
    from reprobit.schema import ToolchainLock as SchemaToolchainLock

    root = _project_root(args.project)
    spec = load_project(root)
    if not isinstance(spec.build, ProducerGraphBuildAdapter):
        raise CLIError("producer-graph extraction requires a producer-graph project")
    configured = _real_directory(
        args.configured_build_root, label="configured build root"
    )
    effective = _real_directory(
        args.effective_source_root, label="effective source root"
    )
    toolchain = _real_directory(args.toolchain_root, label="toolchain root")

    source_path = _safe_project_path(root, spec.layout.source_manifest)
    lock_path = _safe_project_path(root, spec.toolchain.lock_file)
    for authority_path, label in (
        (source_path, "source manifest"),
        (lock_path, "toolchain lock"),
    ):
        if authority_path.is_symlink() or not authority_path.is_file():
            raise CLIError(f"{label} is absent or redirected: {authority_path}")
    source_document = SourceManifestDocument.model_validate_json(
        canonical_json(strict_load(source_path))
    )
    lock_document = SchemaToolchainLock.model_validate_json(
        canonical_json(strict_load(lock_path))
    )
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
            raise CLIError(
                "--directive-input must use the exact TARGET=LIBRARY form"
            )
        if target_id not in project_targets:
            raise CLIError(
                f"--directive-input names unknown target {target_id!r}"
            )
        if re.fullmatch(r"[A-Za-z0-9_.+@-]+", library) is None:
            raise CLIError(
                "--directive-input library must be one bare library name"
            )
        normalized_library = library.casefold()
        if not normalized_library.endswith(".lib"):
            normalized_library += ".lib"
        try:
            reference = graph_reference("system-library", normalized_library)
        except ValueError as exc:
            raise CLIError(
                f"invalid --directive-input library {library!r}: {exc}"
            ) from exc
        identity = (target_id.casefold(), reference.casefold())
        if identity in seen_directives:
            raise CLIError(
                f"duplicate --directive-input {target_id}={normalized_library}"
            )
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
    relative_output = _relative_output(root, spec.layout.producer_graph)
    graph_data = canonical_json(graph)
    validation_files, validation_authority = _producer_graph_validation_files(
        root, spec, graph_data
    )
    _validate_migration(validation_files)
    previous_graph = (
        (root / relative_output).read_bytes() if (root / relative_output).is_file() else None
    )
    transaction = CASTransaction(root)
    for authority_relative in validation_authority:
        transaction.assert_unchanged(Path(*authority_relative.parts))
    transaction.write(relative_output, graph_data)
    result = transaction.commit()
    try:
        load_project_tree(root)
    except Exception:
        rollback = CASTransaction(root)
        if previous_graph is None:
            rollback.delete(relative_output, expected_sha256=Digest.from_bytes(graph_data).value)
        else:
            rollback.write(
                relative_output,
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
        f"committed {len(graph.nodes)} direct producer(s) to {relative_output}",
        output=relative_output,
        extractor=graph.extractor,
        nodes=len(graph.nodes),
        roles=role_counts,
        graph_digest=producer_graph_digest(graph).value,
        transaction_id=result.transaction_id,
        certification_runtime="direct-locked-producers",
    )
    return 0


def _command_graph_upgrade(args: argparse.Namespace, output: _Output) -> int:
    """Transactionally replace a current v1 content binding with v2 topology."""

    root = _project_root(args.project)
    with output.activity("validating producer graph upgrade", phase="validate"):
        bundle = load_project_tree(root)
    graph = bundle.producer_graph
    manifest = bundle.source_manifest
    if graph is None or manifest is None:
        raise CLIError("producer graph upgrade requires a complete project tree")
    if graph.schema_version == 2:
        output.emit(
            "producer_graph_upgraded",
            "producer graph is already schema v2",
            changed=False,
            graph_digest=producer_graph_digest(graph).value,
        )
        return 0
    manifest_digest = source_manifest_digest(manifest)
    if graph.source_manifest_digest != manifest_digest:
        raise CLIError("v1 producer graph does not bind the current source manifest")
    values = graph.model_dump(mode="json", exclude_none=True)
    values.pop("source_manifest_digest", None)
    values.update(
        {
            "schema_version": 2,
            "source_topology_digest": source_topology_digest(
                item.path for item in manifest.entries
            ).model_dump(mode="json"),
        }
    )
    upgraded = ProducerGraphDocument.model_validate_json(canonical_json(values))
    graph_data = canonical_json(upgraded)
    graph_relative = Path(*PurePosixPath(bundle.spec.layout.producer_graph).parts)
    manifest_relative = Path(*PurePosixPath(bundle.spec.layout.source_manifest).parts)
    before = _safe_project_path(root, bundle.spec.layout.producer_graph).read_bytes()
    manifest_before = _safe_project_path(
        root, bundle.spec.layout.source_manifest
    ).read_bytes()
    transaction = CASTransaction(root)
    transaction.assert_unchanged(
        manifest_relative,
        expected_sha256=Digest.from_bytes(manifest_before).value,
    )
    transaction.write(
        graph_relative,
        graph_data,
        expected_sha256=Digest.from_bytes(before).value,
    )
    result = transaction.commit()
    try:
        load_project_tree(root)
    except Exception:
        rollback = CASTransaction(root)
        rollback.write(
            graph_relative,
            before,
            expected_sha256=Digest.from_bytes(graph_data).value,
        )
        rollback.commit()
        raise
    output.emit(
        "producer_graph_upgraded",
        "upgraded producer graph to schema v2 source-topology binding",
        changed=True,
        graph_digest=producer_graph_digest(upgraded).value,
        source_topology_digest=upgraded.source_topology_digest,
        transaction_id=result.transaction_id,
    )
    return 0


def _validate_migration(files: Mapping[PurePosixPath, bytes]) -> Any:
    with tempfile.TemporaryDirectory(prefix="reprobit-migration-") as directory:
        root = Path(directory)
        for relative, data in files.items():
            destination = root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        return load_project_tree(root, verify_source_authority=False)


def _command_manifest_migrate(args: argparse.Namespace, output: _Output) -> int:
    from reprobit.migration import migration_output

    source = Path(args.source).expanduser().resolve(strict=True)
    with output.activity("converting and validating schema-v2 manifest"):
        result = migration_output(source)
        candidate = _validate_migration(result.files)
    output.emit(
        "migration_preview",
        f"migration produces {len(result.files)} files, "
        f"{result.intervention_count} interventions, and {result.proof_count} proofs",
        source=source,
        source_sha256=result.source_sha256,
        files=len(result.files),
        interventions=result.intervention_count,
        proofs=result.proof_count,
        apply=args.apply,
    )
    for relative, data in sorted(result.files.items(), key=lambda item: item[0].as_posix()):
        output.emit(
            "migration_file",
            f"  {relative.as_posix()} ({len(data)} bytes)",
            path=relative.as_posix(),
            size=len(data),
        )
    if not args.apply:
        return 0
    root = _project_root(args.project_root)
    manifest = candidate.source_manifest
    assert manifest is not None
    from reprobit.source_lock import receipt_source_input

    generated_paths = {item.as_posix() for item in result.files}
    source_preconditions: list[tuple[str, str]] = []
    for entry in manifest.entries:
        if entry.path in generated_paths:
            generated = result.files[PurePosixPath(entry.path)]
            if len(generated) != entry.size or Digest.from_bytes(generated) != entry.digest:
                raise CLIError(
                    "migration would overwrite an admitted source with different bytes: "
                    f"{entry.path!r}"
                )
            continue
        size, digest, _ = receipt_source_input(root, entry.path)
        if size != entry.size or digest != entry.digest:
            raise CLIError(
                "migration source authority differs at apply time: "
                f"{entry.path!r}"
            )
        source_preconditions.append((entry.path, entry.digest.value))
    transaction = CASTransaction(root)
    for relative, data in sorted(result.files.items(), key=lambda item: item[0].as_posix()):
        transaction.write(Path(*relative.parts), data)
    for source_relative, source_digest_value in source_preconditions:
        transaction.assert_unchanged(
            source_relative,
            expected_sha256=source_digest_value,
        )
    committed = transaction.commit()
    output.emit(
        "migration_applied",
        f"applied migration transaction {committed.transaction_id}",
        transaction_id=committed.transaction_id,
        changed_paths=committed.changed_paths,
    )
    return 0


def _command_validate(args: argparse.Namespace, output: _Output) -> int:
    root = _project_root(args.project)
    bundle = load_project_tree(root)
    if (
        isinstance(bundle.spec.build, ProducerGraphBuildAdapter)
        and bundle.producer_graph is None
    ):
        raise CLIError(
            "producer-graph project has no committed graph; run the migration "
            "extractor before validation"
        )
    output.emit(
        "validated",
        f"validated {bundle.spec.project_id}: {len(bundle.spec.targets)} target(s), "
        f"{len(bundle.interventions)} intervention(s)",
        project_id=bundle.spec.project_id,
        targets=len(bundle.spec.targets),
        interventions=len(bundle.interventions),
        proofs=sum(len(item.expected_observations) for item in bundle.proof_documents),
    )
    return 0


def _scope_text(scope: Any) -> str:
    values = [scope.target]
    if scope.translation_unit is not None:
        values.append(scope.translation_unit)
    if scope.function is not None:
        values.append(scope.function)
    return "/".join(values)


def _human_intervention_detail(item: Intervention, cost: InterventionCost) -> str:
    units = ", ".join(
        f"{unit.kind.value}: {unit.count} x {unit.unit_cost} = {unit.cost}"
        for unit in cost.units
    )
    dependencies = ", ".join(item.dependencies) or "none"
    return "\n".join(
        (
            f"{item.id}: {item.kind}, cost={cost.cost}, scope={_scope_text(item.scope)}",
            f"  cost class: {cost.cost_class.value}",
            f"  typed units: {units}",
            f"  dependencies: {dependencies}",
            f"  rationale: {item.rationale}",
        )
    )


def _human_cost_breakdown(result: CostBreakdown) -> str:
    lines = [f"project cost: {result.project_total} (model v{result.model_version})"]
    if result.by_target:
        lines.append("targets:")
        lines.extend(
            f"  {item.target}: {item.cost} "
            f"(interventions={item.interventions}, units={item.units})"
            for item in result.by_target
        )
    if result.by_class:
        lines.append("classes:")
        lines.extend(
            f"  {item.cost_class.value}: {item.cost} "
            f"(interventions={item.interventions}, units={item.units})"
            for item in result.by_class
        )
    return "\n".join(lines)


def _command_explain(args: argparse.Namespace, output: _Output) -> int:
    bundle = load_project_tree(
        _project_root(args.project), verify_source_authority=False
    )
    costs = {
        item.intervention_id: item
        for item in calculate_cost(bundle.interventions).interventions
    }
    selected = tuple(
        item
        for item in bundle.interventions
        if args.intervention is None or item.id == args.intervention
    )
    if args.intervention is not None and not selected:
        raise CLIError(f"unknown intervention: {args.intervention}")
    for item in selected:
        cost = costs[item.id]
        summary = f"{item.id}: {item.kind}, cost={cost.cost}, scope={_scope_text(item.scope)}"
        output.emit(
            "intervention",
            (
                _human_intervention_detail(item, cost)
                if args.intervention is not None and output.output_format == "text"
                else summary
            ),
            id=item.id,
            kind=item.kind,
            cost=cost.cost,
            cost_class=cost.cost_class.value,
            units=cost.units,
            scope=item.scope,
            rationale=item.rationale,
            dependencies=item.dependencies,
        )
    return 0


def _command_cost(args: argparse.Namespace, output: _Output) -> int:
    bundle = load_project_tree(
        _project_root(args.project), verify_source_authority=False
    )
    result = calculate_cost(bundle.interventions)
    output.emit(
        "cost",
        (
            _human_cost_breakdown(result)
            if output.output_format == "text"
            else f"project cost: {result.project_total} (model v{result.model_version})"
        ),
        breakdown=result,
    )
    return 0


def _resolve_program(value: str, cwd: Path) -> str:
    candidate = Path(value)
    if candidate.is_absolute():
        resolved = candidate.resolve(strict=True)
    elif "/" in value or "\\" in value:
        resolved = (cwd / candidate).resolve(strict=True)
    else:
        located = shutil.which(value)
        if located is None:
            raise CLIError(f"build executable is not available: {value}")
        resolved = Path(located).resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise CLIError(f"build executable is absent or unsafe: {resolved}")
    return str(resolved)


def _host_environment(programs: Sequence[str], temporary: Path) -> tuple[tuple[str, str], ...]:
    directories = [str(Path(item).parent) for item in programs]
    directories.extend(os.defpath.split(os.pathsep))
    values = {
        "PATH": os.pathsep.join(dict.fromkeys(directories)),
        "LANG": "C",
        "LC_ALL": "C",
        "TMP": str(temporary),
        "TEMP": str(temporary),
    }
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        values["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return tuple(sorted(values.items()))


def _runtime_plan(
    spec: ProjectSpec,
    root: Path,
    temporary: Path,
) -> BuildPlan:
    outputs = tuple(str(_safe_project_path(root, target.artifact)) for target in spec.targets)
    if not isinstance(spec.build, CommandBuildAdapter):
        raise CLIError(f"unsupported build adapter: {type(spec.build).__name__}")
    declared = (*spec.build.configure, *spec.build.build)
    steps: list[BuildStep] = []
    for index, command in enumerate(declared):
        cwd = _safe_project_path(root, command.cwd)
        program = _resolve_program(command.argv[0], cwd)
        step = BuildStep(
            id=f"command.{index:04d}",
            argv=(program, *command.argv[1:]),
            cwd=str(cwd),
            depends_on=(steps[-1].id,) if steps else (),
            outputs=outputs if index == len(declared) - 1 else (),
            environment=_host_environment((program,), temporary),
            timeout_seconds=command.timeout_seconds,
        )
        steps.append(step)
    return BuildPlan(tuple(steps))


def _prepare_producer_graph_run(
    args: argparse.Namespace,
    bundle: ProjectBundle,
    *,
    project_root: Path,
    session_root: Path,
    progress: Callable[[int, int, str, str], None],
) -> ClassicProducerGraphPreparedRun:
    """Prepare the closed built-in direct runtime from CLI authority."""

    from reprobit.classic_runtime import prepare_classic_producer_graph_run

    if args.toolchain_root is None:
        raise CLIError("producer-graph execution requires --toolchain-root")
    if (args.compiler_transport is None) != (args.resource_transport is None):
        raise CLIError(
            "--compiler-transport and --resource-transport must be supplied together"
        )
    return prepare_classic_producer_graph_run(
        bundle,
        project_root=project_root,
        session_root=session_root,
        toolchain_root=Path(args.toolchain_root).expanduser().resolve(strict=True),
        backend=_selected_backend(args),
        jobs=args.jobs,
        compiler_transport=(
            Path(args.compiler_transport).expanduser()
            if args.compiler_transport is not None
            else None
        ),
        resource_transport=(
            Path(args.resource_transport).expanduser()
            if args.resource_transport is not None
            else None
        ),
        initialization_timeout=args.initialization_timeout,
        compile_timeout=args.compile_timeout,
        link_timeout=args.link_timeout,
        cleanup_timeout=args.cleanup_timeout,
        progress=progress,
    )


def _state_path(root: Path, spec: ProjectSpec) -> Path:
    lexical = root.joinpath(*PurePosixPath(spec.state_dir.replace("\\", "/")).parts)
    if lexical.is_symlink():
        raise CLIError(f"state directory is a symlink: {lexical}")
    return _safe_project_path(root, spec.state_dir)


def _state_root(root: Path, spec: ProjectSpec) -> Path:
    state = _state_path(root, spec)
    state.mkdir(parents=True, exist_ok=True)
    return state


def _legacy_oracle_targets(bundle: ProjectBundle) -> frozenset[str]:
    """Return the temporary classic bridge's exact oracle capability set."""

    from reprobit.classic_orchestration import (
        _temporary_classic_legacy_action_authority,
    )

    actions_by_unit = _temporary_classic_legacy_action_authority(bundle)
    return frozenset(
        action.oracle_target
        for actions in actions_by_unit.values()
        for action in actions
    )


def _command_build(args: argparse.Namespace, output: _Output) -> int:
    from reprobit.engine import BuildPlanExecutor

    root = _project_root(args.project)
    with output.activity("loading and validating project authority", phase="validate"):
        if args.cold:
            # Cold developer builds retain the exact committed source pins and
            # stay wholly outside the incremental cache implementation.
            bundle = load_project_tree(root)
            developer_authority = None
        else:
            committed = load_project_tree(root, verify_source_authority=False)
            if isinstance(committed.spec.build, ProducerGraphBuildAdapter):
                # This invocation-local view is created before state/cache or
                # runtime work.  It never rewrites committed authority.
                from reprobit.incremental import current_worktree_authority

                developer_authority = current_worktree_authority(committed, root)
                bundle = developer_authority.bundle
            else:
                # Non-producer adapters have no dependency-aware warm authority.
                # Preserve their existing strict source validation.
                bundle = load_project_tree(root)
                developer_authority = None
    state = _state_root(root, bundle.spec)
    required = tuple(_safe_project_path(root, item.artifact) for item in bundle.spec.targets)
    arena = RunArena(
        state,
        kind="build",
        keep=KeepWorkspace(args.keep_workspace),
    )
    try:
        with arena:
            run_root = arena.path
            if isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
                if args.cold:
                    with output.producer_activity("executing cold producer graph") as progress:
                        prepared = _prepare_producer_graph_run(
                            args,
                            bundle,
                            project_root=root,
                            session_root=run_root / "classic",
                            progress=progress,
                        )
                        with ExitStack() as stack:
                            stack.callback(prepared.close)
                            from reprobit.legacy import bind_pe32_oracle
                            from reprobit.verify import seal_file_oracle

                            legacy_targets = _legacy_oracle_targets(bundle)
                            prepared.executor.bind_legacy_oracles(
                                {
                                    target.id: bind_pe32_oracle(
                                        stack.enter_context(
                                            seal_file_oracle(
                                                _safe_project_path(root, target.oracle)
                                            )
                                        )
                                    )
                                    for target in bundle.spec.targets
                                    if target.id in legacy_targets
                                }
                            )
                            receipt = prepared.executor.execute(
                                prepared.plan,
                                cold=True,
                                required_outputs=required,
                            )
                    incremental_summary = None
                else:
                    assert developer_authority is not None
                    if args.toolchain_root is None:
                        raise CLIError("producer-graph execution requires --toolchain-root")
                    if (args.compiler_transport is None) != (args.resource_transport is None):
                        raise CLIError(
                            "--compiler-transport and --resource-transport must be supplied "
                            "together"
                        )
                    from reprobit.classic_incremental import (
                        execute_classic_incremental_build,
                    )

                    with output.producer_activity(
                        "executing incremental producer graph"
                    ) as progress:

                        def incremental_progress(
                            kind: ProgressKind,
                            completed: int,
                            total: int,
                            phase: str,
                            node_id: str,
                            reason: str | None,
                        ) -> None:
                            progress(completed, total, phase, node_id, kind, reason)

                        incremental = execute_classic_incremental_build(
                            developer_authority,
                            project_root=root,
                            session_root=run_root / "incremental",
                            state_root=state,
                            toolchain_root=Path(args.toolchain_root)
                            .expanduser()
                            .resolve(strict=True),
                            backend=_selected_backend(args),
                            jobs=args.jobs,
                            compiler_transport=(
                                Path(args.compiler_transport).expanduser()
                                if args.compiler_transport is not None
                                else None
                            ),
                            resource_transport=(
                                Path(args.resource_transport).expanduser()
                                if args.resource_transport is not None
                                else None
                            ),
                            initialization_timeout=args.initialization_timeout,
                            compile_timeout=args.compile_timeout,
                            link_timeout=args.link_timeout,
                            cleanup_timeout=args.cleanup_timeout,
                            progress=incremental_progress,
                        )
                    receipt = incremental.receipt
                    incremental_summary = incremental.summary
            else:
                temporary = run_root / "host-tmp"
                temporary.mkdir()
                plan = _runtime_plan(bundle.spec, root, temporary)
                with output.activity("executing build plan", phase="execute"):
                    receipt = BuildPlanExecutor(
                        run_root=run_root / "tasks",
                        max_workers=args.jobs,
                    ).execute(plan, cold=args.cold, required_outputs=required)
                incremental_summary = None
    except BaseException:
        if arena.path.is_dir():
            output.emit(
                "workspace_retained",
                f"retained failed build workspace: {arena.path}",
                path=arena.path,
                outcome="failed",
                diagnostic=True,
            )
        raise
    if arena.path.is_dir():
        output.emit(
            "workspace_retained",
            f"retained successful build workspace: {arena.path}",
            path=arena.path,
            outcome="succeeded",
            diagnostic=True,
        )
    if incremental_summary is not None:
        output.incremental_summary(incremental_summary)
        completion_message = (
            "incremental build completed: "
            f"{incremental_summary.hits + incremental_summary.misses} node(s), "
            f"{len(receipt.outputs)} output(s)"
        )
        completion_fields: dict[str, Any] = {
            "nodes": incremental_summary.hits + incremental_summary.misses,
            "hits": incremental_summary.hits,
            "misses": incremental_summary.misses,
        }
    else:
        completion_message = (
            f"build completed: {len(receipt.steps)} step(s), "
            f"{len(receipt.outputs)} output(s)"
        )
        completion_fields = {"steps": len(receipt.steps)}
    output.emit(
        "build_complete",
        completion_message,
        cold=receipt.cold,
        **completion_fields,
        outputs=[
            {"path": item.path, "sha256": item.digest.value, "size": item.size}
            for item in receipt.outputs
        ],
    )
    return 0


def _command_verify(args: argparse.Namespace, output: _Output) -> int:
    from reprobit.engine import (
        EngineRequest,
        ReportDestinations,
        ReproductionEngine,
        TargetOracle,
    )
    from reprobit.verify import seal_file_oracle

    root = _project_root(args.project)
    with output.activity("loading and validating project authority", phase="validate"):
        bundle = load_project_tree(root)
    requested_policy = (
        AuthenticityPolicy(args.policy)
        if args.policy is not None
        else bundle.spec.authenticity.policy
    )
    if (
        requested_policy is AuthenticityPolicy.ALLOW_QUARANTINE
        and bundle.spec.authenticity.policy is AuthenticityPolicy.CLEAN
    ):
        raise CLIError(
            "requested authenticity policy would broaden the committed clean policy"
        )
    if isinstance(bundle.spec.build, CommandBuildAdapter):
        raise CLIError(
            "cold verification refuses command adapters without declared input/output receipts"
        )
    if not isinstance(bundle.spec.build, ProducerGraphBuildAdapter):
        raise CLIError(f"unsupported certification adapter: {type(bundle.spec.build).__name__}")
    state = _state_root(root, bundle.spec)
    if args.report_dir:
        report_directory = _safe_project_path(root, args.report_dir)
        report_json = report_directory / "report.json"
        report_html = report_directory / "report.html"
    else:
        report_json = state / "reports" / "report.json"
        report_html = state / "reports" / "report.html"
    if (args.action_receipt is None) != (args.action_nonce is None):
        raise CLIError("--action-receipt and --action-nonce must be supplied together")
    action_receipt = (
        Path(args.action_receipt).expanduser().resolve(strict=False)
        if args.action_receipt is not None
        else None
    )
    arena = RunArena(
        state,
        kind="verify",
        keep=KeepWorkspace(args.keep_workspace),
    )
    try:
        with arena:
            run_root = arena.path
            with output.producer_activity(
                "building, verifying, and auditing direct producers"
            ) as progress:
                prepared = _prepare_producer_graph_run(
                    args,
                    bundle,
                    project_root=root,
                    session_root=run_root / "classic",
                    progress=progress,
                )
                with ExitStack() as stack:
                    stack.callback(prepared.close)
                    oracles = tuple(
                        TargetOracle(
                            target.id,
                            stack.enter_context(
                                seal_file_oracle(_safe_project_path(root, target.oracle))
                            ),
                        )
                        for target in bundle.spec.targets
                    )
                    from reprobit.legacy import bind_pe32_oracle

                    legacy_targets = _legacy_oracle_targets(bundle)
                    prepared.executor.bind_legacy_oracles(
                        {
                            oracle.target_id: bind_pe32_oracle(oracle.capability)
                            for oracle in oracles
                            if oracle.target_id in legacy_targets
                        }
                    )
                    request = EngineRequest(
                        bundle=bundle,
                        build_plan=prepared.plan,
                        project_root=root,
                        run_root=run_root,
                        oracles=oracles,
                        jobs=args.jobs,
                        cold=True,
                        reports=ReportDestinations(json=report_json, html=report_html),
                        evidence_providers=(prepared.evidence_provider,),
                        build_executor=prepared.executor,
                    )
                    result = ReproductionEngine().run(request)
        if action_receipt is not None and args.action_nonce is not None:
            from reprobit.action_summary import publish_action_completion

            publish_action_completion(
                result.report,
                report_path=report_json,
                html_path=report_html,
                receipt_path=action_receipt,
                nonce=args.action_nonce,
            )
    except BaseException:
        if arena.path.is_dir():
            output.emit(
                "workspace_retained",
                f"retained failed verification workspace: {arena.path}",
                path=arena.path,
                outcome="failed",
                diagnostic=True,
            )
        raise
    if arena.path.is_dir():
        output.emit(
            "workspace_retained",
            f"retained successful verification workspace: {arena.path}",
            path=arena.path,
            outcome="succeeded",
            diagnostic=True,
        )
    accepted = result.accepts(requested_policy)
    output.emit(
        "verification",
        "verification accepted by policy"
        if accepted
        else "verification did not satisfy authenticity policy",
        verdict=result.verdict,
        policy=requested_policy,
        accepted=accepted,
        origin_integrity=result.evidence.origin_integrity,
        report_json=report_json,
        report_html=report_html,
        total_cost=result.report.costs.project_total,
    )
    return 0 if accepted else 1


def _command_report(args: argparse.Namespace, output: _Output) -> int:
    from reprobit.report import read_report_json, write_report_html

    source = Path(args.input).expanduser().resolve(strict=True)
    destination = (
        Path(args.html).expanduser().resolve(strict=False)
        if args.html
        else source.with_suffix(".html")
    )
    report = read_report_json(source)
    write_report_html(report, destination)
    output.emit(
        "report_written",
        f"wrote self-contained report to {destination}",
        input=source,
        html=destination,
        clean=report.verdict.clean,
        total_cost=report.costs.project_total,
    )
    return 0


def _command_state_status(args: argparse.Namespace, output: _Output) -> int:
    root = _project_root(args.project)
    spec = load_project(root)
    state = _state_path(root, spec)
    with output.activity("inspecting local ReproBit state", phase="state"):
        status = StateStore(state, create=False).status()
    active = sum(item.active for item in status.runs)
    retained = len(status.runs) - active
    lines = [
        f"state: {human_bytes(status.total_bytes)} in {status.total_files} file(s)",
        f"  runs: {len(status.runs)} ({active} active, {retained} retained), "
        f"{human_bytes(status.run_bytes)}",
        f"  cache: {status.cache_records} record(s), {status.cache_blobs} blob(s), "
        f"{human_bytes(status.cache_bytes)}",
        f"  cache leases: {status.cache_active_leases} active, "
        f"{status.cache_stale_leases} stale",
    ]
    output.emit(
        "state_status",
        "\n".join(lines),
        root=status.root,
        total_bytes=status.total_bytes,
        total_files=status.total_files,
        run_bytes=status.run_bytes,
        run_files=status.run_files,
        cache_bytes=status.cache_bytes,
        cache_files=status.cache_files,
        cache_records=status.cache_records,
        cache_blobs=status.cache_blobs,
        cache_active_leases=status.cache_active_leases,
        cache_stale_leases=status.cache_stale_leases,
        runs=[
            {
                "path": item.path,
                "kind": item.kind,
                "active": item.active,
                "outcome": item.outcome,
                "bytes": item.bytes,
                "files": item.files,
                "modified_ns": item.modified_ns,
            }
            for item in status.runs
        ],
    )
    return 0


def _command_state_gc(args: argparse.Namespace, output: _Output) -> int:
    root = _project_root(args.project)
    spec = load_project(root)
    state = _state_path(root, spec)
    age_seconds = args.older_than_hours * 3600.0
    store = StateStore(state, create=False)
    description = (
        "previewing local state cleanup"
        if args.dry_run
        else "garbage-collecting retained runs and incremental cache"
    )
    with output.activity(description, phase="cleanup"):
        result = store.gc(
            older_than_seconds=age_seconds,
            dry_run=args.dry_run,
        )
    if args.dry_run:
        output.emit(
            "state_gc_preview",
            f"would remove {len(result.removed)} retained run(s), "
            f"{result.cache_removed_records} cache record(s), and "
            f"{result.cache_removed_blobs} unreferenced blob(s); reclaimable "
            f"{human_bytes(result.reclaimed_bytes)}",
            candidates=result.removed,
            cache_records=result.cache_removed_records,
            cache_blobs=result.cache_removed_blobs,
            active_cache_leases=result.cache_active_leases,
            reclaimable_bytes=result.reclaimed_bytes,
            older_than_hours=args.older_than_hours,
        )
        return 0
    output.emit(
        "state_gc",
        f"removed {len(result.removed)} retained run(s), "
        f"{result.cache_removed_records} cache record(s), and "
        f"{result.cache_removed_blobs} blob(s); reclaimed "
        f"{human_bytes(result.reclaimed_bytes)}; "
        f"skipped {len(result.skipped_active)} active and "
        f"{len(result.skipped_recent)} recent run(s), plus "
        f"{result.cache_active_leases} active cache lease(s)",
        removed=result.removed,
        reclaimed_bytes=result.reclaimed_bytes,
        skipped_active=result.skipped_active,
        skipped_recent=result.skipped_recent,
        cache_records=result.cache_removed_records,
        cache_blobs=result.cache_removed_blobs,
        active_cache_leases=result.cache_active_leases,
        skipped_recent_cache_records=result.cache_skipped_recent_records,
        older_than_hours=args.older_than_hours,
    )
    return 0


def _command_cmake_module(args: argparse.Namespace, output: _Output) -> int:
    from reprobit.cmake import cmake_module_path

    directory = cmake_module_path()
    value = directory / "ReproBit.cmake" if args.file else directory
    output.emit("cmake_module", str(value), path=value)
    return 0


Handler = Callable[[argparse.Namespace, _Output], int]


def _positive_seconds(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number of seconds") from error
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return seconds


def _nonnegative_hours(value: str) -> float:
    try:
        hours = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number of hours") from error
    if not math.isfinite(hours) or hours < 0:
        raise argparse.ArgumentTypeError("must be a finite number at least zero")
    return hours


def _add_execution_options(
    command: argparse.ArgumentParser,
    *,
    cold_option: bool,
) -> None:
    command.add_argument(
        "--jobs",
        type=int,
        default=1,
        metavar="COUNT",
        help="maximum direct producer workers (default: 1)",
    )
    if cold_option:
        command.add_argument(
            "--cold",
            action="store_true",
            help="require a fresh isolated execution with no incremental cache access",
        )
    command.add_argument(
        "--keep-workspace",
        choices=tuple(item.value for item in KeepWorkspace),
        default=KeepWorkspace.ON_FAILURE.value,
        help=(
            "retain run-private diagnostics never, on failure, or always "
            "(default: on-failure)"
        ),
    )
    command.add_argument(
        "--backend",
        choices=("auto", POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND),
        default="auto",
        help="execution backend (default: select from the host platform)",
    )
    command.add_argument("--wine", default="wine", help="POSIX Wine executable or PATH name")
    command.add_argument(
        "--wineserver",
        default="wineserver",
        help="POSIX wineserver executable or PATH name",
    )
    command.add_argument(
        "--toolchain-root",
        metavar="DIRECTORY",
        help="physical root of the locally provisioned locked toolchain",
    )
    command.add_argument(
        "--compiler-transport",
        metavar="PATH",
        help="POSIX transport selector for the locked compiler (paired with resource transport)",
    )
    command.add_argument(
        "--resource-transport",
        metavar="PATH",
        help="POSIX transport selector for the locked resource compiler",
    )
    command.add_argument(
        "--initialization-timeout",
        type=_positive_seconds,
        default=600.0,
        metavar="SECONDS",
        help="limit for each isolated execution-lane initialization (default: 600)",
    )
    command.add_argument(
        "--compile-timeout",
        type=_positive_seconds,
        default=600.0,
        metavar="SECONDS",
        help="limit for each compiler or resource producer (default: 600)",
    )
    command.add_argument(
        "--link-timeout",
        type=_positive_seconds,
        default=900.0,
        metavar="SECONDS",
        help="limit for each librarian or linker producer (default: 900)",
    )
    command.add_argument(
        "--cleanup-timeout",
        type=_positive_seconds,
        default=10.0,
        metavar="SECONDS",
        help="limit for draining each isolated execution lane (default: 10)",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rbit", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {_VERSION}")
    parser.add_argument("--format", choices=("text", "ndjson"), default="text")
    subcommands = parser.add_subparsers(dest="command", required=True)

    init = subcommands.add_parser("init", help="create a minimal schema-v3 project entry point")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--project-id", required=True)
    init.add_argument("--profile", choices=tuple(TOOLCHAIN_PROFILES), default="msvc_4_2")
    init.add_argument("--target", default="program")
    init.add_argument("--artifact", default="build/program.exe")
    init.add_argument("--oracle", default="reference/program.exe")
    init.add_argument("--logical-source", default=r"R:\source")
    init.add_argument("--logical-build", default=r"R:\build")
    init.add_argument("--logical-toolchain", default=r"R:\toolchain")
    init.set_defaults(handler=_command_init)

    doctor = subcommands.add_parser("doctor", help="inspect backend and toolchain capabilities")
    doctor.add_argument("project", nargs="?", default=".")
    doctor.add_argument(
        "--backend",
        choices=("auto", POSIX_WINE_BACKEND, WINDOWS_NATIVE_BACKEND),
        default="auto",
    )
    doctor.add_argument("--wine", default="wine")
    doctor.add_argument("--wineserver", default="wineserver")
    doctor.add_argument("--execute-probe", action="store_true")
    doctor.add_argument("--toolchain-profile", choices=tuple(TOOLCHAIN_PROFILES))
    doctor.add_argument("--toolchain-root")
    doctor.set_defaults(handler=_command_doctor)

    toolchain = subcommands.add_parser("toolchain", help="manage classic toolchain receipts")
    toolchain_commands = toolchain.add_subparsers(dest="toolchain_command", required=True)
    lock = toolchain_commands.add_parser("lock", help="write the canonical schema-v3 lock")
    lock.add_argument("--project", default=".")
    lock.add_argument("--profile", choices=tuple(TOOLCHAIN_PROFILES))
    lock.add_argument("--root", required=True)
    lock.add_argument(
        "--runtime-file",
        action="append",
        default=[],
        metavar="RELATIVE_PATH",
        help="pin an additional wrapper or runtime dependency (repeatable)",
    )
    lock.add_argument("--output")
    lock.set_defaults(handler=_command_toolchain_lock)

    source = subcommands.add_parser("source", help="manage the portable project read set")
    source_commands = source.add_subparsers(dest="source_command", required=True)
    source_preview = source_commands.add_parser(
        "preview", help="show source changes and stale reviewed authority without writing"
    )
    source_preview.add_argument("--project", default=".")
    source_preview.add_argument(
        "--path",
        action="append",
        default=[],
        help="project-relative file or tree to inspect (repeatable; defaults to Git tracked files)",
    )
    source_preview.set_defaults(handler=_command_source_preview)
    source_lock = source_commands.add_parser(
        "lock", help="transactionally lock tracked or explicitly named source inputs"
    )
    source_lock.add_argument("--project", default=".")
    source_lock.add_argument(
        "--path",
        action="append",
        default=[],
        help="project-relative file or tree to admit (repeatable; defaults to Git tracked files)",
    )
    source_lock.add_argument(
        "--invalidate-producer-graph",
        action="store_true",
        help="remove a stale generated graph in the same transaction after source changes",
    )
    source_lock.set_defaults(handler=_command_source_lock)

    graph = subcommands.add_parser(
        "graph", help="manage committed direct-producer authority"
    )
    graph_commands = graph.add_subparsers(dest="graph_command", required=True)
    graph_configure = graph_commands.add_parser(
        "configure",
        help="create a fresh migration-only Unix Makefiles tree without building",
    )
    graph_configure.add_argument(
        "--project", default=".", help="project containing reprobit.toml (default: .)"
    )
    graph_configure.add_argument(
        "--workspace-root",
        required=True,
        metavar="EMPTY_DIRECTORY",
        help="new or empty workspace that will receive fixed source/ and build/ trees",
    )
    graph_configure.add_argument(
        "--toolchain-root",
        required=True,
        metavar="DIRECTORY",
        help="physical root of the locally provisioned locked toolchain",
    )
    graph_configure.add_argument(
        "--compiler-transport",
        required=True,
        metavar="PATH",
        help="admitted compiler frontend used only for CMake feature detection",
    )
    graph_configure.add_argument(
        "--resource-transport",
        required=True,
        metavar="PATH",
        help="admitted resource-compiler frontend paired with the compiler transport",
    )
    graph_configure.add_argument(
        "--cmake",
        default="cmake",
        metavar="PATH_OR_NAME",
        help="CMake executable (default: resolve cmake from PATH)",
    )
    graph_configure.add_argument(
        "--configuration",
        default="RelWithDebInfo",
        help="single-configuration CMake build type (default: RelWithDebInfo)",
    )
    graph_configure.add_argument(
        "--timeout",
        type=_positive_seconds,
        default=600.0,
        metavar="SECONDS",
        help="bounded configure deadline (default: 600)",
    )
    graph_configure.set_defaults(handler=_command_graph_configure)
    graph_extract = graph_commands.add_parser(
        "extract",
        help="commit a closed producer graph from a migration-only Unix Makefiles tree",
    )
    graph_extract.add_argument(
        "--project", default=".", help="project containing reprobit.toml (default: .)"
    )
    graph_extract.add_argument(
        "--configured-build-root",
        required=True,
        metavar="DIRECTORY",
        help="CMake Unix Makefiles tree created by `rbit graph configure`",
    )
    graph_extract.add_argument(
        "--effective-source-root",
        required=True,
        metavar="DIRECTORY",
        help="migration source tree whose physical paths match the configured commands",
    )
    graph_extract.add_argument(
        "--toolchain-root",
        required=True,
        metavar="DIRECTORY",
        help="physical root matching the committed logical toolchain seat",
    )
    graph_extract.add_argument(
        "--target-plan",
        help="path beneath the configured build (defaults to reprobit-target-plan.json)",
    )
    graph_extract.add_argument(
        "--directive-input",
        action="append",
        default=[],
        metavar="TARGET=LIBRARY",
        help=(
            "commit one prelink-discovered DEFAULTLIB edge; repeat for each target/library"
        ),
    )
    graph_extract.set_defaults(handler=_command_graph_extract)
    graph_upgrade = graph_commands.add_parser(
        "upgrade",
        help="upgrade a current v1 graph to v2 source-topology binding without CMake",
    )
    graph_upgrade.add_argument(
        "--project", default=".", help="project containing reprobit.toml (default: .)"
    )
    graph_upgrade.set_defaults(handler=_command_graph_upgrade)

    manifest = subcommands.add_parser("manifest", help="manage manifest schema transitions")
    manifest_commands = manifest.add_subparsers(dest="manifest_command", required=True)
    migrate = manifest_commands.add_parser("migrate", help="preview or apply schema-v2 migration")
    migrate.add_argument("source")
    migrate.add_argument("--project-root", default=".")
    migrate.add_argument("--apply", action="store_true")
    migrate.set_defaults(handler=_command_manifest_migrate)

    for name, help_text, handler in (
        ("validate", "strictly validate a complete schema-v3 tree", _command_validate),
        ("cost", "calculate the stable intervention cost model", _command_cost),
    ):
        command = subcommands.add_parser(name, help=help_text)
        command.add_argument("project", nargs="?", default=".")
        command.set_defaults(handler=handler)

    explain = subcommands.add_parser("explain", help="explain committed interventions")
    explain.add_argument("project", nargs="?", default=".")
    explain.add_argument("--intervention")
    explain.set_defaults(handler=_command_explain)

    build = subcommands.add_parser(
        "build",
        help="incrementally build the committed producer graph without invoking CMake",
    )
    build.add_argument("project", nargs="?", default=".")
    _add_execution_options(build, cold_option=True)
    build.set_defaults(handler=_command_build)

    verify = subcommands.add_parser(
        "verify", help="cold-build every target and derive an authenticity verdict"
    )
    verify.add_argument("project", nargs="?", default=".")
    _add_execution_options(verify, cold_option=False)
    verify.add_argument(
        "--policy",
        choices=tuple(policy.value for policy in AuthenticityPolicy),
        help="optionally narrow the project's committed authenticity policy",
    )
    verify.add_argument(
        "--report-dir",
        metavar="PROJECT_RELATIVE_DIRECTORY",
        help="write report.json and report.html beneath this project directory",
    )
    verify.add_argument(
        "--action-receipt",
        metavar="PATH",
        help="publish a nonce-bound completion receipt after both reports finalize",
    )
    verify.add_argument(
        "--action-nonce",
        metavar="LOWERCASE_SHA256",
        help="64-hex invocation nonce paired with --action-receipt",
    )
    verify.set_defaults(handler=_command_verify)

    state = subcommands.add_parser(
        "state", help="inspect or garbage-collect local run and cache state"
    )
    state_commands = state.add_subparsers(dest="state_command", required=True)
    state_status = state_commands.add_parser(
        "status", help="show retained runs, active leases, cache size, and disk usage"
    )
    state_status.add_argument("project", nargs="?", default=".")
    state_status.set_defaults(handler=_command_state_status)
    state_gc = state_commands.add_parser(
        "gc", help="remove old retained runs and cache records without racing leases"
    )
    state_gc.add_argument("project", nargs="?", default=".")
    state_gc.add_argument(
        "--older-than-hours",
        type=_nonnegative_hours,
        default=168.0,
        metavar="HOURS",
        help="remove runs/cache records at least this old (default: 168; 0 for all)",
    )
    state_gc.add_argument(
        "--dry-run",
        action="store_true",
        help="report reclaimable inactive runs and cache entries without removing them",
    )
    state_gc.set_defaults(handler=_command_state_gc)

    report = subcommands.add_parser("report", help="validate JSON and render self-contained HTML")
    report.add_argument("input")
    report.add_argument("--html")
    report.set_defaults(handler=_command_report)

    module = subcommands.add_parser("cmake-module", help="print the packaged CMake module path")
    module.add_argument("--file", action="store_true")
    module.set_defaults(handler=_command_cmake_module)
    return parser


def _silence_broken_pipe(stream: TextIO) -> None:
    """Redirect a closed standard stream so interpreter shutdown stays quiet."""

    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError, ValueError):
        return
    null_descriptor = -1
    try:
        null_descriptor = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null_descriptor, descriptor)
    except OSError:
        return
    finally:
        if null_descriptor >= 0:
            os.close(null_descriptor)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output = _Output(args.format, sys.stdout, sys.stderr)
    handler: Handler = args.handler
    if getattr(args, "jobs", 1) < 1:
        output.emit(
            "error",
            "error: --jobs must be at least one",
            error_type="CLIError",
            diagnostic=True,
        )
        return 2
    try:
        return handler(args, output)
    except KeyboardInterrupt:
        output.emit(
            "interrupted",
            "interrupted; active child processes were asked to drain",
            error_type="KeyboardInterrupt",
            exit_code=130,
            diagnostic=True,
        )
        return 130
    except BrokenPipeError:
        # A downstream pager or selector (for example, ``head``) consumed all
        # the output it requested.  Do not turn that normal pipeline close
        # into a traceback, and do not attempt a second write to the same pipe.
        _silence_broken_pipe(output.stdout)
        return 0
    except Exception as error:
        output.emit(
            "error",
            f"error: {error}",
            error_type=type(error).__name__,
            diagnostic=True,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CLIError", "main"]
