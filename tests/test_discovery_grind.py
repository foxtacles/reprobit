from __future__ import annotations

import gc
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

import pytest

import reprobit.discovery_grind as grind
from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationParameter,
    DeclarationState,
    DiscoveryError,
    declaration_state_id,
)
from reprobit.discovery_grind import (
    ColdTrialEvidence,
    ProjectGrindCallbacks,
    run_project_grind,
)
from reprobit.model import Digest


def _state(classes: int, functions: int) -> DeclarationState:
    return DeclarationState(
        family=DeclarationFamily.DECLARATION_SHAPE,
        parameters=(
            DeclarationParameter(name="classes", value=classes),
            DeclarationParameter(name="functions", value=functions),
        ),
    )


def _donor_id(classes: int, functions: int) -> str:
    return f"donor.{classes}.{functions}"


def _state_shape_for_test(state: DeclarationState) -> tuple[int, int]:
    classes = state.parameter("classes")
    functions = state.parameter("functions")
    assert type(classes) is int and type(functions) is int
    return classes, functions


@dataclass
class _Trace:
    seed_calls: list[tuple[Path, str]] = field(default_factory=list)
    donor_calls: list[tuple[Path, tuple[str, ...]]] = field(default_factory=list)
    cold_calls: list[Path] = field(default_factory=list)
    donor_authoring: list[tuple[str, str, str, int, int]] = field(default_factory=list)
    equal_body_authoring: list[tuple[str, str, str, str, int, int]] = field(default_factory=list)
    reference_objects: list[bytes] = field(default_factory=list)
    publication_calls: int = 0


@dataclass
class _ColdReport:
    run_id: Digest
    rejection_reason: str | None


def _context(
    root: Path,
    *,
    label: str,
    plan: object,
    reference: bytes,
) -> SimpleNamespace:
    root.mkdir(parents=True)
    reference_path = root / "reference.obj"
    reference_path.write_bytes(reference)
    return SimpleNamespace(
        root=root,
        config=SimpleNamespace(plan=plan),
        bundle=SimpleNamespace(
            spec=SimpleNamespace(
                project_id=f"project.{label}",
                state_dir=".reprobit-state",
            ),
            interventions=(),
        ),
        unit=SimpleNamespace(
            target_id=f"target.{label}",
            id=f"tu.{label}",
            build_target=f"build.{label}",
        ),
        intervention_document=SimpleNamespace(interventions=()),
        proof_document=object(),
        intervention_path=root / "reprobit/interventions/tu.json",
        proof_path=root / "reprobit/proofs/tu.json",
        compiler_node=SimpleNamespace(id=f"compiler.{label}"),
        reference_path=reference_path,
        symbol=f"_{label}_symbol",
    )


def _install_grind_fixture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    live_states: tuple[DeclarationState, ...],
    staged_states: tuple[DeclarationState, ...] | None = None,
    existing_donor_ids: tuple[str, ...] = (),
    qualification_rejections: frozenset[tuple[int, int]] = frozenset(),
    cold_reasons: tuple[str | None, ...] = (None,),
) -> tuple[Path, Path, _Trace, ProjectGrindCallbacks]:
    staged_states = live_states if staged_states is None else staged_states
    live_root = tmp_path / "live"
    staged_root = tmp_path / "sealed"
    live_plan = object()
    staged_plan = object()
    live = _context(
        live_root,
        label="live",
        plan=live_plan,
        reference=b"live reference",
    )
    staged = _context(
        staged_root,
        label="sealed",
        plan=staged_plan,
        reference=b"sealed reference",
    )
    for context in (live, staged):
        existing = tuple(SimpleNamespace(id=donor_id) for donor_id in existing_donor_ids)
        context.bundle.interventions = existing
        context.intervention_document.interventions = existing
    trace = _Trace()
    cold_results = iter(cold_reasons)

    def resolve(root: Path, *, config_relative: str) -> SimpleNamespace:
        assert config_relative == "reprobit/discovery.json"
        if root == live_root:
            return live
        assert root == staged_root
        return staged

    def enumerate_states(plan: object) -> tuple[DeclarationState, ...]:
        return live_states if plan is live_plan else staged_states

    def capture(context: object) -> SimpleNamespace:
        assert context is live
        return SimpleNamespace(files=(object(),), authority_directories=())

    @contextmanager
    def stage(
        root: Path,
        state_dir: str,
        snapshots: tuple[object, ...],
    ) -> Iterator[Path]:
        assert root == live_root
        assert state_dir == ".reprobit-state"
        assert len(snapshots) == 1
        yield staged_root

    def donor_authoring(
        *,
        target_id: str,
        translation_unit_id: str,
        build_target: str,
        classes: int,
        functions: int,
    ) -> SimpleNamespace:
        trace.donor_authoring.append(
            (
                target_id,
                translation_unit_id,
                build_target,
                classes,
                functions,
            )
        )
        return SimpleNamespace(intervention=SimpleNamespace(id=_donor_id(classes, functions)))

    def equal_body_authoring(
        *,
        target_id: str,
        translation_unit_id: str,
        build_target: str,
        symbol: str,
        classes: int,
        functions: int,
        seed_object: bytes,
        donor_object: bytes,
    ) -> SimpleNamespace:
        assert seed_object == b"sealed seed"
        assert donor_object == f"donor object {classes}.{functions}".encode()
        trace.equal_body_authoring.append(
            (
                target_id,
                translation_unit_id,
                build_target,
                symbol,
                classes,
                functions,
            )
        )
        donor = SimpleNamespace(intervention=SimpleNamespace(id=_donor_id(classes, functions)))
        function = SimpleNamespace(
            intervention=SimpleNamespace(id=f"function.{classes}.{functions}")
        )
        return SimpleNamespace(
            donor=donor,
            function=function,
            candidate_object=f"candidate {classes}.{functions}".encode(),
            records=(donor, function),
        )

    def qualify(
        *,
        reference_object: bytes,
        candidate_object: bytes,
        symbol: str,
    ) -> None:
        trace.reference_objects.append(reference_object)
        assert reference_object == b"sealed reference"
        assert symbol == "_sealed_symbol"
        key = tuple(int(part) for part in candidate_object.decode().split()[1].split("."))
        if key in qualification_rejections:
            raise DiscoveryError("fixture compatibility rejection")

    def seed(root: Path, compiler_id: str) -> bytes:
        trace.seed_calls.append((root, compiler_id))
        return b"sealed seed"

    def donors(
        root: Path,
        donor_ids: tuple[str, ...],
        progress: grind.DonorProgress | None,
    ) -> dict[str, bytes]:
        trace.donor_calls.append((root, donor_ids))
        assert progress is not None
        for index, donor_id in enumerate(donor_ids, start=1):
            progress(index, len(donor_ids), donor_id)
        return {
            donor_id: f"donor object {donor_id.removeprefix('donor.')}".encode()
            for donor_id in donor_ids
        }

    def cold(root: Path) -> ColdTrialEvidence:
        trace.cold_calls.append(root)
        reason = next(cold_results)
        report = SimpleNamespace(
            run_id=Digest.from_bytes(f"cold {len(trace.cold_calls)}".encode()),
            rejection_reason=reason,
        )
        return ColdTrialEvidence(accepted=reason is None, report=report)

    def publish(*_args: object, **_kwargs: object) -> str:
        trace.publication_calls += 1
        return "transaction.fixture"

    monkeypatch.setattr(grind, "resolve_project_grind_context", resolve)
    monkeypatch.setattr(grind, "capture_project_grind_inputs", capture)
    monkeypatch.setattr(grind, "enumerate_declaration_states", enumerate_states)
    monkeypatch.setattr(grind, "StagedProject", stage)
    monkeypatch.setattr(grind, "build_declaration_shape_donor", donor_authoring)
    monkeypatch.setattr(grind, "build_declaration_shape_equal_body", equal_body_authoring)
    monkeypatch.setattr(grind, "qualify_msvc_reference_object", qualify)

    def merge_records(
        interventions: object,
        proofs: object,
        records: tuple[object, ...],
    ) -> tuple[object, object]:
        merged = {item.id: item for item in interventions.interventions}
        merged.update((record.intervention.id, record.intervention) for record in records)
        return SimpleNamespace(interventions=tuple(merged.values())), proofs

    monkeypatch.setattr(grind, "merge_authored_records", merge_records)
    monkeypatch.setattr(grind, "_write_staged_documents", lambda *_args: None)
    published_ids = tuple(
        SimpleNamespace(id=identifier)
        for state in staged_states
        for identifier in (
            _donor_id(*_state_shape_for_test(state)),
            f"function.{'.'.join(str(value) for value in _state_shape_for_test(state))}",
        )
    )
    monkeypatch.setattr(
        grind,
        "load_project_tree",
        lambda _root: SimpleNamespace(interventions=published_ids),
    )
    monkeypatch.setattr(
        grind,
        "calculate_cost",
        lambda interventions: SimpleNamespace(
            project_total=sum(1 if item.id.startswith("donor.") else 25 for item in interventions)
        ),
    )
    monkeypatch.setattr(
        grind,
        "_validate_cold_report",
        lambda evidence, **_kwargs: (
            evidence.report.rejection_reason,
            evidence.report.rejection_reason is None,
        ),
    )
    monkeypatch.setattr(grind, "_publish_solution", publish)
    callbacks = ProjectGrindCallbacks(seed, donors, cold)
    return live_root, staged_root, trace, callbacks


def test_grind_uses_the_sealed_context_after_capture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    live_state = _state(1, 1)
    sealed_state = _state(2, 2)
    second_sealed_state = _state(3, 3)
    live_root, staged_root, trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=(live_state,),
        staged_states=(sealed_state, second_sealed_state),
    )

    result = run_project_grind(live_root, callbacks=callbacks)

    assert result.solution is not None
    assert result.solution.state == sealed_state
    assert result.project_id == "project.sealed"
    assert result.target_id == "target.sealed"
    assert result.translation_unit_id == "tu.sealed"
    assert result.symbol == "_sealed_symbol"
    assert trace.seed_calls == [(staged_root, "compiler.sealed")]
    assert trace.donor_calls == [(staged_root, ("donor.2.2", "donor.3.3"))]
    assert trace.cold_calls == [staged_root]
    assert trace.reference_objects == [b"sealed reference", b"sealed reference"]
    assert trace.donor_authoring == [
        ("target.sealed", "tu.sealed", "build.sealed", 2, 2),
        ("target.sealed", "tu.sealed", "build.sealed", 3, 3),
    ]
    assert trace.equal_body_authoring == [
        (
            "target.sealed",
            "tu.sealed",
            "build.sealed",
            "_sealed_symbol",
            2,
            2,
        ),
        (
            "target.sealed",
            "tu.sealed",
            "build.sealed",
            "_sealed_symbol",
            3,
            3,
        ),
    ]


def test_exact_preview_never_calls_publication_without_acceptance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    live_root, _staged_root, trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=(_state(1, 1),),
    )

    result = run_project_grind(live_root, callbacks=callbacks, accept_exact=False)

    assert result.exact
    assert not result.published
    assert result.transaction_id is None
    assert trace.publication_calls == 0


@pytest.mark.parametrize(
    ("accept_exact", "accept_progress", "published"),
    (
        (False, False, False),
        (True, False, False),
        (False, True, True),
    ),
)
def test_local_progress_requires_its_explicit_publication_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    accept_exact: bool,
    accept_progress: bool,
    published: bool,
) -> None:
    live_root, _staged_root, trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=(_state(1, 1),),
    )
    monkeypatch.setattr(
        grind,
        "_validate_cold_report",
        lambda _evidence, **_kwargs: (None, False),
    )

    result = run_project_grind(
        live_root,
        callbacks=callbacks,
        accept_exact=accept_exact,
        accept_progress=accept_progress,
    )

    assert result.locally_qualified
    assert not result.exact
    assert result.published is published
    assert (result.transaction_id is not None) is published
    assert trace.publication_calls == int(published)


def test_progress_acceptance_stops_after_the_cheapest_cold_proven_candidate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    states = (_state(1, 1), _state(2, 2))
    live_root, _staged_root, trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=states,
    )
    monkeypatch.setattr(
        grind,
        "_validate_cold_report",
        lambda _evidence, **_kwargs: (None, False),
    )

    result = run_project_grind(
        live_root,
        callbacks=callbacks,
        accept_progress=True,
    )

    assert result.published
    assert result.locally_qualified
    assert not result.exact
    assert result.solution is not None
    assert result.solution.state == states[0]
    assert result.cold_trials == 1
    assert len(trace.cold_calls) == 1


def test_grind_rejects_ambiguous_acceptance_modes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    live_root, _staged_root, _trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=(_state(1, 1),),
    )

    with pytest.raises(grind.GrindError, match="mutually exclusive"):
        run_project_grind(
            live_root,
            callbacks=callbacks,
            accept_exact=True,
            accept_progress=True,
        )


def test_exact_preview_reuses_and_recertifies_an_identical_existing_donor(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    live_root, staged_root, trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=(_state(1, 1),),
        existing_donor_ids=("donor.1.1",),
    )

    result = run_project_grind(live_root, callbacks=callbacks)

    assert result.solution is not None
    assert result.solution.reused_donor is True
    assert result.solution.added_interventions == 1
    assert result.solution.added_cost == 25
    assert trace.donor_calls == [(staged_root, ("donor.1.1",))]
    assert trace.cold_calls == [staged_root]


def test_progress_is_monotonic_and_finishes_its_bounded_total(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    states = (_state(1, 1), _state(2, 2), _state(3, 3))
    live_root, _staged_root, _trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=states,
        qualification_rejections=frozenset({(1, 1)}),
        cold_reasons=("cold mismatch", None),
    )
    progress: list[tuple[int, int]] = []

    result = run_project_grind(
        live_root,
        callbacks=callbacks,
        progress=lambda completed, total, *_args: progress.append((completed, total)),
    )

    assert result.exact
    assert result.qualified_candidates == 2
    assert result.cold_trials == 2
    assert len(result.rejections) == 2
    assert {total for _completed, total in progress} == {11}
    assert [completed for completed, _total in progress] == sorted(
        completed for completed, _total in progress
    )
    assert progress[-1] == (11, 11)


def test_early_exact_result_skips_remaining_qualified_states_cleanly(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    live_root, _staged_root, trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=(_state(1, 1), _state(2, 2)),
    )
    events: list[tuple[int, int, str, str]] = []

    result = run_project_grind(
        live_root,
        callbacks=callbacks,
        progress=lambda completed, total, phase, item, *_args: events.append(
            (completed, total, phase, item)
        ),
    )

    assert result.exact
    assert result.cold_trials == 1
    assert len(trace.cold_calls) == 1
    skipped = [item for _completed, _total, phase, item in events if phase == "grind-skip"]
    assert declaration_state_id(_state(2, 2)) in skipped
    assert events[-1][:2] == (8, 8)


def test_rejected_cold_report_is_released_before_the_next_verifier(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    live_root, staged_root, _trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=(_state(1, 1), _state(2, 2)),
    )
    report_refs: list[weakref.ReferenceType[_ColdReport]] = []

    def cold(root: Path) -> ColdTrialEvidence:
        assert root == staged_root
        if report_refs:
            gc.collect()
            assert report_refs[-1]() is None
        reason = "cold mismatch" if not report_refs else None
        report = _ColdReport(
            Digest.from_bytes(f"cold {len(report_refs)}".encode()),
            reason,
        )
        report_refs.append(weakref.ref(report))
        return ColdTrialEvidence(accepted=reason is None, report=report)

    result = run_project_grind(
        live_root,
        callbacks=ProjectGrindCallbacks(
            callbacks.probe_seed,
            callbacks.probe_donors,
            cold,
        ),
    )

    assert result.solution is not None
    assert report_refs[0]() is None
    assert report_refs[1]() is result.solution.report


def test_no_solution_never_publishes_even_with_advance_acceptance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    live_root, _staged_root, trace, callbacks = _install_grind_fixture(
        monkeypatch,
        tmp_path,
        live_states=(_state(1, 1), _state(2, 2)),
        qualification_rejections=frozenset({(1, 1)}),
        cold_reasons=("still not byte-identical",),
    )

    result = run_project_grind(live_root, callbacks=callbacks, accept_exact=True)

    assert not result.exact
    assert result.solution is None
    assert not result.published
    assert result.cold_trials == 1
    assert len(result.rejections) == 2
    assert trace.publication_calls == 0
