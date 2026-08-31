"""One-lifetime, windowed donor compiler probes for classic repair."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import dataclass

from reprobit.classic_execution_records import ClassicActiveCompilerEpoch
from reprobit.classic_orchestration import ClassicPreparedUnit
from reprobit.classic_project import ClassicProjectError
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


@dataclass(frozen=True, slots=True)
class ClassicDonorCompileRefusal:
    """One expected candidate-specific compiler refusal, without a traceback."""

    donor_id: str
    reason: str


ClassicDonorCompileOutcome = ClassicDonorProbeOutput | ClassicDonorCompileRefusal
ClassicDonorWindowEvaluator = Callable[[tuple[ClassicDonorCompileOutcome, ...]], bool]


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
            seat = (
                unit.plan.build_target.casefold(),
                unit.plan.source.casefold(),
                donor.request.compiler_seat.casefold(),
            )
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
    return ClassicDonorProbeOutput(
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


def _compile_window(
    probes: ClassicProbeExecution,
    prepared: dict[str, tuple[ClassicPreparedUnit, int]],
    supervisor: ProcessSupervisor,
    cancellation: CancellationToken,
    compiler_epoch: ClassicActiveCompilerEpoch,
    window: tuple[str, ...],
    *,
    first_ordinal: int,
) -> tuple[ClassicDonorCompileOutcome, ...]:
    outcomes: list[ClassicDonorCompileOutcome | None] = [None] * len(window)
    worker_count = min(probes.producer.jobs, len(window))
    with ThreadPoolExecutor(
        max_workers=worker_count,
        thread_name_prefix="reprobit-repair-probe",
    ) as pool:
        running: dict[Future[ClassicDonorProbeOutput], tuple[int, str]] = {
            pool.submit(
                _compile_output,
                probes,
                prepared,
                supervisor,
                cancellation,
                compiler_epoch,
                first_ordinal + index,
                donor_id,
            ): (index, donor_id)
            for index, donor_id in enumerate(window)
        }
        for future, (index, donor_id) in running.items():
            try:
                outcomes[index] = future.result()
            except (
                ClassicProjectError,
                CommandFailed,
                ProcessOutputLimitExceeded,
                ProcessTimedOut,
            ) as exc:
                outcomes[index] = ClassicDonorCompileRefusal(donor_id, str(exc))
    if any(item is None for item in outcomes):
        raise AssertionError("classic donor repair probe omitted a window outcome")
    return tuple(item for item in outcomes if item is not None)


def probe_donor_compile_windows(
    probes: ClassicProbeExecution,
    units: Sequence[ClassicPreparedUnit],
    windows: Iterable[Sequence[str]],
    *,
    evaluate: ClassicDonorWindowEvaluator,
    progress: ClassicDonorProbeProgress | None = None,
    planned_candidates: int,
) -> tuple[ClassicDonorCompileOutcome, ...]:
    """Compile lazy candidate windows inside one consumed non-certifying runtime.

    Expected compiler failures are returned per candidate.  ``evaluate`` runs
    on the coordinating thread after each complete window and may stop the
    search before the next, more expensive window is requested from the lazy
    iterable.  Progress is cumulative; its total is an upper bound because a
    successful cheap tier stops early.  No runtime evidence, cache entry, or
    report is issued.
    """

    if type(planned_candidates) is not int or planned_candidates < 1:
        raise ClassicProjectError("classic donor repair probe needs a positive candidate bound")
    prepared = _prepared_donors(units)
    if not probes.producer.is_open:
        raise ClassicProjectError("classic donor repair probe requires one unused prepared run")
    probes.producer.begin_developer()
    outcomes: list[ClassicDonorCompileOutcome] = []
    completed = 0
    try:
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
        with ExitStack() as stack, ProcessSupervisor() as supervisor:
            authority = stack.enter_context(probes.producer.authority_namespace_lease())
            source = stack.enter_context(probes.producer.source_namespace_lease())
            namespace = probes.producer.capture_compiler_namespace(
                "noncertifying-donor-repair-probe",
                source=source.snapshot,
                authority=authority.snapshot,
            )
            compiler_epoch = ClassicActiveCompilerEpoch(
                namespace.evidence.namespace_id,
                probes.producer.include_authority(),
                source_seal,
                bool(probes.overlay.generated_translation_units),
            )
            cancellation = CancellationToken()
            checked_windows = _validate_windows(windows, prepared)
            for window in checked_windows:
                window_outcomes = _compile_window(
                    probes,
                    prepared,
                    supervisor,
                    cancellation,
                    compiler_epoch,
                    window,
                    first_ordinal=completed,
                )
                outcomes.extend(window_outcomes)
                for outcome in window_outcomes:
                    completed += 1
                    if progress is not None:
                        progress(completed, planned_candidates, outcome.donor_id)
                if evaluate(window_outcomes):
                    break
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
    probes.close()
    return tuple(outcomes)


__all__ = [
    "ClassicDonorCompileOutcome",
    "ClassicDonorCompileRefusal",
    "ClassicDonorWindowEvaluator",
    "probe_donor_compile_windows",
]
