"""One-lifetime, streamed donor compiler probes for classic repair."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path

from reprobit.classic_execution_records import ClassicActiveCompilerEpoch
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_repair_probe_cache import (
    ClassicDonorCompileOutcome,
    ClassicDonorCompileRefusal,
    ClassicDonorCompileStore,
    ProbeSeatKey,
    compile_epoch_digest,
)
from reprobit.classic_runtime_files import _require_unchanged_tree, _tree_file_seal
from reprobit.classic_runtime_probe import (
    ClassicDonorProbeInput,
    ClassicDonorProbeOutput,
    ClassicDonorProbeProgress,
    ClassicProbeExecution,
)
from reprobit.classic_runtime_receipts import _step_receipt
from reprobit.model import Digest
from reprobit.process import (
    CancellationToken,
    CommandFailed,
    ProcessOutputLimitExceeded,
    ProcessSupervisor,
    ProcessTimedOut,
)
from reprobit.strict_json import canonical_json

ClassicDonorWindowEvaluator = Callable[[tuple[ClassicDonorCompileOutcome, ...]], bool]
ClassicDonorCompileCache = ClassicDonorCompileStore
"""Replay store for seats compiled earlier; see :mod:`classic_repair_probe_cache`."""
ClassicDonorSourceSeal = Mapping[Path, tuple[int, Digest]]

_EXPECTED_COMPILE_FAILURES = (
    ClassicProjectError,
    CommandFailed,
    ProcessOutputLimitExceeded,
    ProcessTimedOut,
)


def prepare_donor_probe_source_epoch(
    probes: ClassicProbeExecution,
) -> ClassicDonorSourceSeal:
    """Materialize one reusable probe runtime's effective source tree once."""

    source_seal = _tree_file_seal(probes.effective_root)
    if probes.overlay.overlay_witnesses:
        _, source_seal = probes.overlay.materialize_certified_project_overlay_epoch(source_seal)
        if probes.overlay.generated_translation_units:
            _, source_seal = probes.overlay.materialize_generated_input_epoch(source_seal)
    _require_unchanged_tree(
        source_seal,
        root=probes.effective_root,
        label="donor repair probe source epoch",
    )
    return source_seal


def donor_request_identity(request: object) -> str:
    """Digest every private compiler input of one donor request.

    The compiler seat names the arena a carrier occupies, but two carriers can
    share a seat while rendering different sources (a forward run placed before
    or after the file, say).  A replayed compile must have read exactly the same
    bytes, so the identity covers the rendered inputs, the staged files, the
    include layout and the carrier identifiers as well as the seat.
    """

    additions = getattr(request, "compiler_additions", None)
    projection = getattr(additions, "include_projection", "")
    material = {
        "build_target": str(getattr(request, "build_target", "")),
        "carrier_identifiers": sorted(getattr(request, "carrier_identifiers", ()) or ()),
        "compiler_seat": str(getattr(request, "compiler_seat", "")).casefold(),
        "family": str(getattr(getattr(request, "family", ""), "value", "")),
        "files": sorted(
            (relative, sha256(payload).hexdigest())
            for relative, payload in (getattr(request, "files", None) or {}).items()
        ),
        "force_includes": list(getattr(additions, "force_includes", ()) or ()),
        "include_directories": list(getattr(additions, "include_directories", ()) or ()),
        "include_projection": str(getattr(projection, "value", projection)),
        "logical_outputs": sorted(
            (path, sha256(payload).hexdigest())
            for path, payload in (getattr(request, "logical_outputs", None) or {}).items()
        ),
        "logical_source": str(getattr(request, "logical_source", "")),
        "staged_source": str(getattr(request, "staged_source", "")),
    }
    return sha256(canonical_json(material)).hexdigest()


def _seat_key(unit: ClassicPreparedUnit, donor_index: int) -> ProbeSeatKey:
    donor = unit.donors[donor_index]
    return (
        unit.plan.build_target.casefold(),
        unit.plan.source.casefold(),
        donor_request_identity(donor.request),
    )


def _arena_key(unit: ClassicPreparedUnit, donor_index: int) -> tuple[str, str, str]:
    donor = unit.donors[donor_index]
    return (
        unit.plan.build_target.casefold(),
        unit.plan.source.casefold(),
        donor.request.compiler_seat.casefold(),
    )


def _prepared_donors(
    units: Sequence[ClassicPreparedUnit],
) -> dict[str, tuple[ClassicPreparedUnit, int]]:
    prepared: dict[str, tuple[ClassicPreparedUnit, int]] = {}
    compiler_seats: dict[tuple[str, str, str], str] = {}
    for unit in units:
        for donor_index, donor in enumerate(unit.donors):
            donor_id = donor.intervention.id
            if donor_id in prepared:
                raise ClassicProjectError(f"classic prepared donor ID is ambiguous: {donor_id!r}")
            seat = _arena_key(unit, donor_index)
            previous = compiler_seats.get(seat)
            if previous is not None:
                raise ClassicProjectError(
                    "classic donor repair candidates share a compiler arena: "
                    f"{previous!r}, {donor_id!r}"
                )
            compiler_seats[seat] = donor_id
            prepared[donor_id] = (unit, donor_index)
    return prepared


def _validate_windows(
    windows: Iterable[Sequence[str]],
    prepared: dict[str, tuple[ClassicPreparedUnit, int]],
) -> Iterable[tuple[str, ...]]:
    seen: set[str] = set()
    for raw_window in windows:
        window = tuple(raw_window)
        if not window or len(window) != len(set(window)):
            raise ClassicProjectError("classic donor repair probe window must contain unique IDs")
        repeated = seen.intersection(window)
        if repeated:
            raise ClassicProjectError(
                "classic donor repair probe repeats candidates: "
                + ", ".join(sorted(repeated, key=str.casefold))
            )
        unknown = sorted(set(window) - set(prepared), key=str.casefold)
        if unknown:
            raise ClassicProjectError(
                f"classic donor repair probe names unknown prepared donors: {unknown}"
            )
        seen.update(window)
        yield window


def _compile_output(
    probes: ClassicProbeExecution,
    prepared: dict[str, tuple[ClassicPreparedUnit, int]],
    supervisor: ProcessSupervisor,
    cancellation: CancellationToken,
    compiler_epoch: ClassicActiveCompilerEpoch,
    ordinal: int,
    donor_id: str,
) -> ClassicDonorProbeOutput:
    unit, donor_index = prepared[donor_id]
    donor = unit.donors[donor_index]
    invocation = probes.donors.invoke_donor_compiler(
        supervisor,
        unit,
        donor_index,
        cancellation,
        step_id=f"probe.repair-donor.{ordinal:04d}.{donor_id}",
        compiler_epoch=compiler_epoch,
    )
    try:
        rendered_inputs = tuple(
            ClassicDonorProbeInput(
                logical_path,
                Digest.from_bytes(payload),
                len(payload),
                payload,
            )
            for logical_path, payload in sorted(
                donor.request.logical_outputs.items(),
                key=lambda item: item[0].casefold(),
            )
        )
        if not rendered_inputs:
            raise ClassicProjectError(f"classic donor {donor_id!r} lacks logical rendered inputs")
        output = ClassicDonorProbeOutput(
            donor_id,
            unit.plan.id,
            donor.request.build_target,
            donor.request.logical_source,
            invocation.record.node_id,
            rendered_inputs,
            Digest.from_bytes(invocation.object_payload),
            Digest.from_bytes(invocation.pdb_payload),
            invocation.object_payload,
            invocation.pdb_payload,
            _step_receipt(invocation.step_id, invocation.result, invocation.spec),
        )
    except BaseException as original:
        try:
            probes.donors.release_probe_invocation(invocation)
        except BaseException as cleanup_error:
            original.add_note(f"classic donor probe arena cleanup also failed: {cleanup_error}")
        raise
    probes.donors.release_probe_invocation(invocation)
    return output


def _stream_compiles(
    probes: ClassicProbeExecution,
    prepared: dict[str, tuple[ClassicPreparedUnit, int]],
    supervisor: ProcessSupervisor,
    cancellation: CancellationToken,
    compiler_epoch: ClassicActiveCompilerEpoch,
    windows: Iterable[tuple[str, ...]],
    *,
    evaluate: ClassicDonorWindowEvaluator,
    progress: ClassicDonorProbeProgress | None,
    planned_candidates: int,
    cache: ClassicDonorCompileStore | None,
    epoch: str,
    jobs: int,
) -> tuple[str, ...]:
    """Keep ``jobs`` compiles in flight and evaluate each outcome as it lands.

    Candidates are pulled lazily from ``windows`` only when a worker is free, so
    the window generator still sees every selection made so far when it builds
    the next window.  Once ``evaluate`` reports completion no further candidate
    is started; compiles already running finish and are recorded like any other.
    """

    candidates = (donor_id for window in windows for donor_id in window)
    donor_ids: list[str] = []
    running: dict[Future[ClassicDonorProbeOutput], tuple[str, ProbeSeatKey]] = {}
    submitted = 0
    settled = False
    exhausted = False

    def record(outcome: ClassicDonorCompileOutcome) -> None:
        nonlocal settled
        donor_ids.append(outcome.donor_id)
        if progress is not None:
            progress(len(donor_ids), planned_candidates, outcome.donor_id)
        if evaluate((outcome,)):
            settled = True

    worker_count = max(1, jobs)
    with ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="reprobit-repair-probe",
    ) as pool:
        while True:
            while not settled and not exhausted and len(running) < worker_count:
                try:
                    donor_id = next(candidates)
                except StopIteration:
                    exhausted = True
                    break
                key = _seat_key(*prepared[donor_id])
                cached = None if cache is None else cache.get(epoch, key, donor_id=donor_id)
                if cached is not None:
                    record(cached)
                    continue
                future = pool.submit(
                    _compile_output,
                    probes,
                    prepared,
                    supervisor,
                    cancellation,
                    compiler_epoch,
                    submitted,
                    donor_id,
                )
                submitted += 1
                running[future] = (donor_id, key)
            if not running:
                break
            done, _pending = wait(running, return_when=FIRST_COMPLETED)
            for future in done:
                donor_id, key = running.pop(future)
                outcome: ClassicDonorCompileOutcome
                try:
                    outcome = future.result()
                except _EXPECTED_COMPILE_FAILURES as exc:
                    outcome = ClassicDonorCompileRefusal(donor_id, str(exc))
                if cache is not None:
                    cache.put(epoch, key, outcome)
                record(outcome)
    return tuple(donor_ids)


def probe_donor_compile_windows(
    probes: ClassicProbeExecution,
    units: Sequence[ClassicPreparedUnit],
    windows: Iterable[Sequence[str]],
    *,
    evaluate: ClassicDonorWindowEvaluator,
    progress: ClassicDonorProbeProgress | None = None,
    planned_candidates: int,
    cache: ClassicDonorCompileStore | None = None,
    close_runtime: bool = True,
    materialize_source_epoch: bool = True,
    source_seal: ClassicDonorSourceSeal | None = None,
    namespace_id: str = "noncertifying-donor-repair-probe",
) -> tuple[str, ...]:
    """Compile lazy candidate windows inside one consumed non-certifying runtime.

    ``cache`` replays outcomes of seats compiled earlier under the same compile
    epoch instead of compiling them again; see :mod:`classic_repair_probe_cache`.
    A supplied ``source_seal`` reuses an epoch already prepared by the caller.

    ``evaluate`` receives each full outcome on the coordinating thread and may
    stop the search before more candidates are requested.  Only completed
    candidate IDs are retained and returned, in completion order.  Progress is
    cumulative; its total is an upper bound because a successful cheap tier
    stops early.  No runtime evidence, cache entry, or report is issued.
    """

    if type(planned_candidates) is not int or planned_candidates < 1:
        raise ClassicProjectError("classic donor repair probe needs a positive candidate bound")
    prepared = _prepared_donors(units)
    if not probes.producer.is_open:
        raise ClassicProjectError("classic donor repair probe requires one unused prepared run")
    probes.producer.begin_developer()
    donor_ids: tuple[str, ...] = ()
    try:
        if source_seal is None:
            source_seal = (
                prepare_donor_probe_source_epoch(probes)
                if materialize_source_epoch
                else _tree_file_seal(probes.effective_root)
            )
        with ExitStack() as stack, ProcessSupervisor() as supervisor:
            authority = stack.enter_context(probes.producer.authority_namespace_lease())
            source = stack.enter_context(probes.producer.source_namespace_lease())
            namespace = probes.producer.capture_compiler_namespace(
                namespace_id,
                source=source.snapshot,
                authority=authority.snapshot,
            )
            compiler_epoch = ClassicActiveCompilerEpoch(
                namespace.evidence.namespace_id,
                probes.producer.include_authority(),
                source_seal,
                bool(probes.overlay.generated_translation_units),
            )
            epoch = (
                compile_epoch_digest(
                    probes.graph,
                    probes.producer.lane_pool.compiler_environment_digest,
                    compiler_epoch,
                    effective_root=probes.effective_root,
                )
                if cache is not None
                else ""
            )
            cancellation = CancellationToken()
            donor_ids = _stream_compiles(
                probes,
                prepared,
                supervisor,
                cancellation,
                compiler_epoch,
                _validate_windows(windows, prepared),
                evaluate=evaluate,
                progress=progress,
                planned_candidates=planned_candidates,
                cache=cache,
                epoch=epoch,
                jobs=probes.producer.jobs,
            )
        _require_unchanged_tree(
            source_seal,
            root=probes.effective_root,
            label="donor repair probe source epoch",
        )
    except BaseException as original:
        try:
            probes.close()
        except BaseException as cleanup_error:
            original.add_note(f"classic donor repair probe cleanup also failed: {cleanup_error}")
        raise
    if close_runtime:
        probes.close()
    return donor_ids


__all__ = [
    "ClassicDonorCompileCache",
    "ClassicDonorSourceSeal",
    "ClassicDonorWindowEvaluator",
    "donor_request_identity",
    "prepare_donor_probe_source_epoch",
    "probe_donor_compile_windows",
]
