from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import reprobit.classic.repair_probe as subject
import reprobit.classic.repair_probe_candidates as candidate_support
from reprobit.classic.measured_pin_repair import MeasuredPinRepairError
from reprobit.classic.repair_session import ClassicRepairRefusal
from reprobit.classic_donors import generate_declaration_shape, prepare_donor_compile_request
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_runtime_probe import ClassicDonorProbeInput, ClassicDonorProbeOutput
from reprobit.execution import StepExecutionReceipt
from reprobit.model import Digest, Scope
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTranslationUnitPlan,
)

SOURCE = b"int reprobit_fixture;\n"


def _donor() -> ClassicRecipeIntervention:
    generated = generate_declaration_shape(2, 3)
    return ClassicRecipeIntervention(
        id="donor.fixture",
        scope=Scope(target="program", translation_unit="unit.fixture"),
        rationale="Exercise a bounded repair candidate without changing its byte goal.",
        beneficiaries=(
            Scope(
                target="program",
                translation_unit="unit.fixture",
                function="?First@@YAXXZ",
            ),
            Scope(
                target="program",
                translation_unit="unit.fixture",
                function="?Second@@YAXXZ",
            ),
        ),
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
        parameters=tuple(
            ClassicField(name=name, value=value)
            for name, value in sorted(
                {
                    "classes": 2,
                    "emission_policy": "non_emitting_declarations_only",
                    "functions": 3,
                    "generated_header_sha256": Digest.from_bytes(generated).value,
                    "role_policy": "cross_tu_complete_target_only_v1",
                }.items()
            )
        ),
    )


def _action(identifier: str, symbol: str) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id=identifier,
        scope=Scope(target="program", translation_unit="unit.fixture", function=symbol),
        rationale="Exercise ordinary candidate selection after a benign source edit.",
        dependencies=("donor.fixture",),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=symbol,
    )


def _receipt(
    intervention: ClassicRecipeIntervention,
    identifier: str,
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id=identifier,
        intervention_id=intervention.id,
        family=intervention.family,
    )


def _fixture(
    action_count: int = 1,
) -> tuple[ClassicPreparedUnit, tuple[ClassicRepairRefusal, ...]]:
    donor = _donor()
    donor_receipt = _receipt(donor, "proof.donor")
    request = prepare_donor_compile_request(
        donor,
        source_path="src/unit.cpp",
        clean_source=SOURCE,
        effective_source=SOURCE,
        receipts=(donor_receipt,),
    )
    actions = tuple(
        _action(f"function.{index}", f"?Function{index}@@YAXXZ") for index in range(action_count)
    )
    action_receipts = tuple(
        _receipt(action, f"proof.function.{index}") for index, action in enumerate(actions)
    )
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(SOURCE),
        ),
        (ClassicPreparedDonor(donor, request),),
        actions,
        (),
        actions,
        (donor_receipt, *action_receipts),
    )
    failures = tuple(
        ClassicRepairRefusal(
            unit_id=unit.plan.id,
            action_index=index,
            intervention=action,
            receipt=action_receipts[index],
            materials=ClassicDispatchMaterials(
                seed_object=b"seed",
                donor_object=b"saved donor",
            ),
            unit=unit,
            reason="saved donor no longer composes",
        )
        for index, action in enumerate(actions)
    )
    return unit, failures


_COMPILE_WINDOWS: list[tuple[str, ...]] = []


def _probe_output(
    donor_id: str,
    unit: ClassicPreparedUnit,
    ordinal: int,
) -> ClassicDonorProbeOutput:
    request = unit.donors[0].request
    object_payload = f"candidate-{ordinal}".encode()
    pdb_payload = f"pdb-{ordinal}".encode()
    digest = Digest.from_bytes(b"step")
    return ClassicDonorProbeOutput(
        donor_id,
        unit.plan.id,
        request.build_target,
        request.logical_source,
        "compiler.fixture",
        tuple(
            ClassicDonorProbeInput(path, Digest.from_bytes(payload), len(payload), payload)
            for path, payload in request.logical_outputs.items()
        ),
        Digest.from_bytes(object_payload),
        Digest.from_bytes(pdb_payload),
        object_payload,
        pdb_payload,
        StepExecutionReceipt("probe", 0, 1, 0.0, digest, digest),
    )


def _fake_compile_windows(
    _probes: object,
    units: tuple[ClassicPreparedUnit, ...],
    windows: Any,
    *,
    evaluate: Any,
    progress: subject.ClassicDonorProbeProgress | None = None,
    planned_candidates: int,
) -> tuple[ClassicDonorProbeOutput, ...]:
    by_id = {unit.donors[0].intervention.id: unit for unit in units}
    outputs: list[ClassicDonorProbeOutput] = []
    for window in windows:
        donor_ids = tuple(window)
        _COMPILE_WINDOWS.append(donor_ids)
        window_outputs = tuple(
            _probe_output(donor_id, by_id[donor_id], len(outputs) + index)
            for index, donor_id in enumerate(donor_ids, start=1)
        )
        outputs.extend(window_outputs)
        if progress is not None:
            already_completed = len(outputs) - len(window_outputs)
            for completed, donor_id in enumerate(donor_ids, start=already_completed + 1):
                progress(completed, planned_candidates, donor_id)
        if evaluate(window_outputs):
            break
    return tuple(outputs)


class _ProbeHandle:
    def __init__(self) -> None:
        self.graph = object()
        self.producer = SimpleNamespace(is_open=True)
        self.overlay = object()
        self.donors = object()
        self.warm = object()
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        self.producer.is_open = False


def _probe_handle() -> Any:
    return _ProbeHandle()


def test_candidate_windows_are_fair_and_drop_selected_groups() -> None:
    first_group = ("tu.first", "donor.first")
    second_group = ("tu.second", "donor.second")

    def attempt(group: tuple[str, str], probe_id: str) -> Any:
        return subject._PreparedAttempt(
            group,
            SimpleNamespace(distance=1),
            None,
            probe_id,
        )

    attempts = (
        attempt(first_group, "first.1"),
        attempt(first_group, "first.2"),
        attempt(first_group, "first.3"),
        attempt(second_group, "second.1"),
        attempt(second_group, "second.2"),
        attempt(second_group, "second.3"),
    )
    selected: dict[tuple[str, str], Any] = {}
    windows = iter(
        subject._candidate_windows(
            attempts,
            selected,
            window_size=2,
            candidate_budget=6,
        )
    )

    assert next(windows) == ("first.1", "second.1")
    selected[first_group] = object()
    assert tuple(windows) == (("second.2", "second.3"),)


def test_best_refusal_prefers_the_candidate_that_reached_ordinary_validation() -> None:
    measurement_only = subject.ClassicDonorRetuneRefusal(
        "tu.measurement",
        "donor.measurement",
        ("function.measurement",),
        12,
        "all measured candidates differed",
        (
            subject.ClassicDonorRetuneAttemptRefusal(
                1,
                (),
                "measurement",
                "body still differs",
            ),
        ),
    )
    ordinary = subject.ClassicDonorRetuneRefusal(
        "tu.ordinary",
        "donor.ordinary",
        ("function.ordinary",),
        3,
        "ordinary checks refused the nearest candidate",
        (
            subject.ClassicDonorRetuneAttemptRefusal(
                3,
                (),
                "ordinary_validation",
                "retail relocation target changed",
            ),
        ),
    )

    result = subject.ClassicDonorRetuneProbeResult((), (measurement_only, ordinary), 15)

    assert result.best_refusal is ordinary
    assert ordinary.best_attempt is ordinary.attempts[0]


def test_best_attempt_uses_distance_then_original_order_for_stable_ties() -> None:
    farther = subject.ClassicDonorRetuneAttemptRefusal(
        3,
        (),
        "ordinary_validation",
        "farther",
    )
    nearest_first = subject.ClassicDonorRetuneAttemptRefusal(
        1,
        (),
        "ordinary_validation",
        "nearest first",
    )
    nearest_second = subject.ClassicDonorRetuneAttemptRefusal(
        1,
        (),
        "ordinary_validation",
        "nearest second",
    )
    refusal = subject.ClassicDonorRetuneRefusal(
        "tu.fixture",
        "donor.fixture",
        ("function.fixture",),
        3,
        "no candidate worked",
        (farther, nearest_first, nearest_second),
    )

    assert refusal.best_attempt is nearest_first
    assert subject.ClassicDonorRetuneProbeResult((), (refusal,), 3).best_refusal is refusal
    assert subject.ClassicDonorRetuneProbeResult((), (), 0).best_refusal is None


def test_retune_uses_small_windows_and_stops_after_first_ordinary_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _unit, failures = _fixture()
    _COMPILE_WINDOWS.clear()
    monkeypatch.setattr(subject, "probe_donor_compile_windows", _fake_compile_windows)
    validations = 0

    def repair(
        _action: ClassicRecipeIntervention,
        receipt: ClassicProofReceipt,
        materials: ClassicDispatchMaterials,
    ) -> Any:
        nonlocal validations
        validations += 1
        if materials.donor_object == b"candidate-1":
            raise MeasuredPinRepairError("nearest candidate still differs")
        return SimpleNamespace(receipt=receipt)

    monkeypatch.setattr(candidate_support, "repair_measured_pins", repair)
    progress: list[tuple[int, int, str]] = []

    result = subject.probe_bounded_donor_retunes(
        _probe_handle(),
        failures,
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        radius=2,
        limit=3,
        window_size=1,
        progress=lambda completed, total, donor_id: progress.append((completed, total, donor_id)),
    )

    assert len(_COMPILE_WINDOWS) == 2
    assert all(len(window) == 1 for window in _COMPILE_WINDOWS)
    assert progress[-1][:2] == (2, 3)
    assert validations == 2
    assert result.compiled_candidates == 2
    assert result.refusals == ()
    assert len(result.repairs) == 1
    selected = result.repairs[0]
    assert selected.attempts == 2
    assert selected.action_ids == ("function.0",)
    assert selected.intervention_edits[0].before.id == "donor.fixture"
    assert selected.intervention_edits[0].after is not None
    assert selected.intervention_edits[0].after != selected.intervention_edits[0].before


def test_retune_stops_at_the_remaining_command_wide_candidate_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _unit, failures = _fixture()
    _COMPILE_WINDOWS.clear()
    monkeypatch.setattr(subject, "probe_donor_compile_windows", _fake_compile_windows)
    monkeypatch.setattr(
        candidate_support,
        "repair_measured_pins",
        lambda *_args: (_ for _ in ()).throw(MeasuredPinRepairError("still differs")),
    )
    progress: list[tuple[int, int, str]] = []

    result = subject.probe_bounded_donor_retunes(
        _probe_handle(),
        failures,
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        radius=2,
        limit=3,
        window_size=8,
        candidate_budget=2,
        progress=lambda completed, total, donor_id: progress.append((completed, total, donor_id)),
    )

    assert [len(window) for window in _COMPILE_WINDOWS] == [2]
    assert result.compiled_candidates == 2
    assert result.repairs == ()
    assert "command-wide donor-candidate budget was exhausted" in result.refusals[0].reason
    assert progress[-1][:2] == (2, 2)


def test_probe_preserves_an_ordinary_validation_refusal_through_action_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _unit, failures = _fixture()
    _COMPILE_WINDOWS.clear()
    monkeypatch.setattr(subject, "probe_donor_compile_windows", _fake_compile_windows)
    monkeypatch.setattr(
        candidate_support,
        "repair_measured_pins",
        lambda *_args: (_ for _ in ()).throw(
            MeasuredPinRepairError(
                "retail relocation target changed",
                stage="ordinary_validation",
            )
        ),
    )

    result = subject.probe_bounded_donor_retunes(
        _probe_handle(),
        failures,
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        limit=1,
        window_size=1,
    )

    assert result.repairs == ()
    assert result.refusals[0].best_attempt is not None
    assert result.refusals[0].best_attempt.stage == "ordinary_validation"
    assert "action 'function.0' rejected candidate" in result.refusals[0].best_attempt.reason


def test_shared_donor_candidate_must_restore_every_failed_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _unit, failures = _fixture(2)
    _COMPILE_WINDOWS.clear()
    monkeypatch.setattr(subject, "probe_donor_compile_windows", _fake_compile_windows)
    calls: list[tuple[str, bytes | None]] = []

    def repair(
        action: ClassicRecipeIntervention,
        receipt: ClassicProofReceipt,
        materials: ClassicDispatchMaterials,
    ) -> Any:
        calls.append((action.id, materials.donor_object))
        if action.id == "function.1" and materials.donor_object == b"candidate-1":
            raise MeasuredPinRepairError("second consumer still differs")
        return SimpleNamespace(receipt=receipt)

    monkeypatch.setattr(candidate_support, "repair_measured_pins", repair)

    result = subject.probe_bounded_donor_retunes(
        _probe_handle(),
        tuple(reversed(failures)),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        radius=1,
        limit=2,
        window_size=1,
    )

    assert len(_COMPILE_WINDOWS) == 2
    assert all(len(window) == 1 for window in _COMPILE_WINDOWS)
    assert calls == [
        ("function.0", b"candidate-1"),
        ("function.1", b"candidate-1"),
        ("function.0", b"candidate-2"),
        ("function.1", b"candidate-2"),
    ]
    assert result.repairs[0].action_ids == ("function.0", "function.1")
    assert result.repairs[0].attempts == 2


def test_unsupported_donor_returns_clear_refusal_and_closes_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _unit, failures = _fixture()
    monkeypatch.setattr(subject, "enumerate_donor_retune_candidates", lambda *_args, **_kw: ())
    probes = _probe_handle()

    result = subject.probe_bounded_donor_retunes(
        probes,
        failures,
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
    )

    assert result.repairs == ()
    assert result.compiled_candidates == 0
    assert result.refusals[0].reason == "donor family has no bounded retune candidates"
    assert probes.close_calls == 1


def test_invalid_request_still_closes_probe() -> None:
    _unit, failures = _fixture()
    probes = _probe_handle()

    with pytest.raises(subject.ClassicDonorRetuneProbeError, match="window_size"):
        subject.probe_bounded_donor_retunes(
            probes,
            failures,
            clean_sources={"src/unit.cpp": SOURCE},
            effective_sources={"src/unit.cpp": SOURCE},
            window_size=0,
        )

    assert probes.close_calls == 1

    probes = _probe_handle()
    with pytest.raises(subject.ClassicDonorRetuneProbeError, match="candidate_budget"):
        subject.probe_bounded_donor_retunes(
            probes,
            failures,
            clean_sources={"src/unit.cpp": SOURCE},
            effective_sources={"src/unit.cpp": SOURCE},
            candidate_budget=0,
        )

    assert probes.close_calls == 1


def test_one_candidate_compile_refusal_does_not_abort_later_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _unit, failures = _fixture()

    def compile_with_first_refusal(
        _probes: object,
        units: tuple[ClassicPreparedUnit, ...],
        windows: Any,
        *,
        evaluate: Any,
        progress: subject.ClassicDonorProbeProgress | None = None,
        planned_candidates: int,
    ) -> tuple[subject.ClassicDonorCompileOutcome, ...]:
        del planned_candidates, progress
        by_id = {unit.donors[0].intervention.id: unit for unit in units}
        outcomes: list[subject.ClassicDonorCompileOutcome] = []
        for window_index, window in enumerate(windows):
            donor_id = next(iter(window))
            outcome: subject.ClassicDonorCompileOutcome
            if window_index == 0:
                outcome = subject.ClassicDonorCompileRefusal(
                    donor_id,
                    "compiler exited without an object",
                )
            else:
                outcome = _probe_output(donor_id, by_id[donor_id], window_index + 1)
            outcomes.append(outcome)
            if evaluate((outcome,)):
                break
        return tuple(outcomes)

    monkeypatch.setattr(subject, "probe_donor_compile_windows", compile_with_first_refusal)
    monkeypatch.setattr(
        candidate_support,
        "repair_measured_pins",
        lambda _action, receipt, _materials: SimpleNamespace(receipt=receipt),
    )

    result = subject.probe_bounded_donor_retunes(
        _probe_handle(),
        failures,
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        limit=2,
        window_size=1,
    )

    assert len(result.repairs) == 1
    assert result.repairs[0].attempts == 2
    assert result.compiled_candidates == 2
    assert result.refusals == ()
