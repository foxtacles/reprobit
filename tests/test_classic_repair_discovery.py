from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from types import SimpleNamespace
from typing import Any

import pytest
import test_classic_register_bijection_reencoding_full as coff_fixture

import reprobit.classic_repair_discovery as subject
from reprobit.classic_donors import (
    generate_declaration_shape,
    generate_forward_run,
    prepare_donor_compile_request,
)
from reprobit.classic_orchestration import ClassicPreparedDonor, ClassicPreparedUnit
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_repair_session import ClassicRepairRefusal
from reprobit.classic_runtime_probe import ClassicDonorProbeInput, ClassicDonorProbeOutput
from reprobit.coff_format import CoffObject, coff_body
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
SYMBOL = coff_fixture.TARGET_SYMBOL


def _body(payload: bytes) -> bytes:
    obj = CoffObject(payload)
    return bytes(coff_body(obj, obj.function_section(SYMBOL)))


def _saved_donor(classes: int, functions: int) -> ClassicRecipeIntervention:
    generated = generate_declaration_shape(classes, functions)
    return ClassicRecipeIntervention(
        id="donor.saved",
        scope=Scope(target="program", translation_unit="unit.fixture"),
        rationale="Framework-generated declaration-only compiler-state shape for the fixture.",
        beneficiaries=(Scope(target="program", translation_unit="unit.fixture", function=SYMBOL),),
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
        parameters=tuple(
            ClassicField(name=name, value=value)
            for name, value in sorted(
                {
                    "classes": classes,
                    "emission_policy": "non_emitting_declarations_only",
                    "functions": functions,
                    "generated_header_sha256": Digest.from_bytes(generated).value,
                }.items()
            )
        ),
    )


def _receipt(intervention: ClassicRecipeIntervention, **values: object) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id=f"proof.{intervention.id}",
        intervention_id=intervention.id,
        family=intervention.family,
        expected_values=dict(values),
    )


def _prepared(donor: ClassicRecipeIntervention) -> ClassicPreparedDonor:
    return ClassicPreparedDonor(
        donor,
        prepare_donor_compile_request(
            donor,
            source_path="src/unit.cpp",
            clean_source=SOURCE,
            effective_source=SOURCE,
            receipts=(_receipt(donor),),
        ),
    )


def _goal_object() -> bytes:
    goal_body = bytearray(coff_fixture.BODY)
    goal_body[0] = 0x90
    return coff_fixture.make_coff(body=bytes(goal_body))


GOAL = _goal_object()
GOAL_DIGEST = sha256(_body(GOAL)).hexdigest()


def _fixture(
    family: ClassicRecipeFamily, **values: object
) -> tuple[ClassicRepairRefusal, bytes, bytes]:
    seed = coff_fixture.make_coff()
    goal = GOAL
    donor = _saved_donor(1, 1)
    prepared = _prepared(donor)
    action = ClassicRecipeIntervention(
        id="function.saved",
        scope=Scope(target="program", translation_unit="unit.fixture", function=SYMBOL),
        rationale="Saved record whose donor no longer emits the body it needs.",
        dependencies=("donor.saved",),
        family=family,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol=SYMBOL,
    )
    action_receipt = _receipt(action, **values)
    unit = ClassicPreparedUnit(
        ClassicTranslationUnitPlan(
            id="unit.fixture",
            target_id="program",
            build_target="program",
            source="src/unit.cpp",
            source_digest=Digest.from_bytes(SOURCE),
        ),
        (prepared,),
        (action,),
        (),
        (action,),
        (_receipt(donor), action_receipt),
    )
    refusal = ClassicRepairRefusal(
        unit_id="unit.fixture",
        action_index=0,
        intervention=action,
        receipt=action_receipt,
        materials=ClassicDispatchMaterials(seed_object=seed, donor_object=seed),
        unit=unit,
        reason="fresh donor body no longer matches its pin",
        unit_donor_objects={"donor.saved": seed},
    )
    return refusal, seed, goal


def _probe_output(
    donor_id: str, unit: ClassicPreparedUnit, payload: bytes
) -> ClassicDonorProbeOutput:
    request = unit.donors[0].request
    digest = Digest.from_bytes(b"step")
    return ClassicDonorProbeOutput(
        donor_id,
        unit.plan.id,
        request.build_target,
        request.logical_source,
        "compiler.fixture",
        tuple(
            ClassicDonorProbeInput(path, Digest.from_bytes(data), len(data), data)
            for path, data in request.logical_outputs.items()
        ),
        Digest.from_bytes(payload),
        Digest.from_bytes(b"pdb"),
        payload,
        b"pdb",
        StepExecutionReceipt("probe", 0, 1, 0.0, digest, digest),
    )


class _Handle:
    def __init__(self) -> None:
        self.producer = SimpleNamespace(is_open=True)
        self.closed = 0

    def close(self) -> None:
        self.closed += 1
        self.producer.is_open = False


def _fake_windows(objects: dict[int, bytes], compiled: list[str]) -> Any:
    def fake(
        _probes: object,
        units: tuple[ClassicPreparedUnit, ...],
        windows: Any,
        *,
        evaluate: Any,
        ordered_outcomes: bool,
        progress: Any = None,
        planned_candidates: int,
        cache: Any = None,
        close_runtime: bool = True,
        materialize_source_epoch: bool = True,
        source_seal: object | None = None,
        namespace_id: str = "noncertifying-donor-repair-probe",
    ) -> tuple[str, ...]:
        del close_runtime, materialize_source_epoch, source_seal, namespace_id
        by_id = {unit.donors[0].intervention.id: unit for unit in units}
        outputs: list[ClassicDonorProbeOutput] = []
        for window in windows:
            batch = []
            for donor_id in window:
                compiled.append(donor_id)
                payload = objects.get(len(compiled), objects["default"])  # type: ignore[call-overload]
                batch.append(_probe_output(donor_id, by_id[donor_id], payload))
            outputs.extend(batch)
            if progress is not None:
                progress(len(outputs), planned_candidates, batch[-1].donor_id)
            if evaluate(tuple(batch)):
                break
        return tuple(output.donor_id for output in outputs)

    return fake


def test_discovery_reauthors_a_record_on_the_first_fresh_shape_carrying_its_goal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, seed, goal = _fixture(
        ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT, expected_body_sha256=GOAL_DIGEST
    )
    compiled: list[str] = []
    # The first two fresh shapes still emit the seed's body; the third carries the goal.
    monkeypatch.setattr(
        subject, "probe_donor_compile_windows", _fake_windows({"default": seed, 3: goal}, compiled)
    )
    handle = _Handle()

    result = subject.probe_carrier_discovery(
        handle,  # type: ignore[arg-type]
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=8,
        window_size=1,
    )

    assert handle.closed == 1
    assert result.unresolved == ()
    assert result.compiled_candidates == 3
    assert len(result.repairs) == 1
    repair = result.repairs[0]
    assert [item.how for item in repair.resolutions] == ["reauthor"]
    assert repair.resolutions[0].family == "equal_body_strict"
    added = {item.intervention.role: item.intervention for item in repair.additions}
    assert {
        item.replaces_intervention_id
        for item in repair.additions
        if item.intervention.role is ClassicRecipeRole.FUNCTION
    } == {"function.saved"}
    donor = added[ClassicRecipeRole.DONOR]
    function = added[ClassicRecipeRole.FUNCTION]
    # The saved donor is (1,1); cheapest-first the untried shapes run (1,2), (1,3), (2,2), ...
    shape = {f.name: f.value for f in donor.parameters}
    assert (shape["classes"], shape["functions"]) == (2, 2)
    assert [scope.function for scope in donor.beneficiaries] == [SYMBOL]
    assert function.dependencies == (donor.id,)
    assert {edit.before.id: edit.after for edit in repair.intervention_edits} == {
        "function.saved": None,
        "donor.saved": None,
    }
    assert repair.dependency_edits == ()


def test_discovery_reauthors_an_exact_cross_tu_normalized_goal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, _seed, goal = _fixture(
        ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE,
        expected_normalized_body_sha256=GOAL_DIGEST,
    )
    monkeypatch.setattr(
        subject,
        "probe_donor_compile_windows",
        _fake_windows({"default": goal}, []),
    )

    result = subject.probe_carrier_discovery(
        _Handle(),  # type: ignore[arg-type]
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=1,
        window_size=1,
    )

    assert result.unresolved == ()
    assert result.repairs[0].resolutions[0].family == ClassicRecipeFamily.EQUAL_BODY_STRICT.value


def test_discovery_never_downgrades_a_semantic_mosaic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, _seed, goal = _fixture(
        ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
        expected_body_sha256=GOAL_DIGEST,
    )
    action = refusal.intervention.model_copy(
        update={
            "parameters": (
                ClassicField(name="instruction_ranges", value=[]),
                ClassicField(name="target_source_refactor", value={"kind": "fixture"}),
            )
        }
    )
    receipt = refusal.receipt.model_copy(update={"family": action.family})
    unit = replace(
        refusal.unit,
        functions=(action,),
        actions=(action,),
        receipts=tuple(
            receipt if item.intervention_id == action.id else item for item in refusal.unit.receipts
        ),
    )
    guarded = replace(
        refusal,
        intervention=action,
        receipt=receipt,
        unit=unit,
        retail_body=_body(goal),
    )
    attempted: list[str] = []

    def reject_mosaic(
        *_args: object,
        donor_objects: dict[str, bytes],
        donor_interventions: dict[str, ClassicRecipeIntervention],
        donor_sources: dict[str, bytes | None],
        donor_shape_identifiers: dict[str, frozenset[str]],
    ) -> None:
        fresh = set(donor_objects) - {"donor.saved"}
        assert len(fresh) == 1
        (donor_id,) = fresh
        assert donor_objects[donor_id] == goal
        assert donor_id in donor_interventions
        assert donor_sources[donor_id] == SOURCE
        assert donor_id in donor_shape_identifiers
        attempted.append(donor_id)
        raise subject.MosaicRepairError("fixture mosaic refusal")

    monkeypatch.setattr(subject, "reauthor_instruction_mosaic", reject_mosaic)
    monkeypatch.setattr(
        subject,
        "build_measured_function_record",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("semantic downgrade")),
    )
    monkeypatch.setattr(
        subject,
        "probe_donor_compile_windows",
        _fake_windows({"default": goal}, []),
    )

    result = subject.probe_carrier_discovery(
        _Handle(),  # type: ignore[arg-type]
        (guarded,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=1,
        window_size=1,
    )

    assert attempted
    assert result.repairs == ()
    assert "saved mosaic semantics could not be preserved" in result.unresolved[0][2]


def test_discovery_reauthoring_retires_orphaned_auxiliary_donors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, seed, goal = _fixture(
        ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT,
        expected_body_sha256=GOAL_DIGEST,
    )
    parameter_donor = _saved_donor(2, 2).model_copy(update={"id": "donor.parameter"})
    receipt_donor = _saved_donor(2, 3).model_copy(update={"id": "donor.receipt"})
    action = refusal.intervention.model_copy(
        update={
            "parameters": (ClassicField(name="target_donor", value=parameter_donor.id),),
        }
    )
    receipt = refusal.receipt.model_copy(
        update={
            "expected_values": {
                **refusal.receipt.expected_values,
                "complete_donor": receipt_donor.id,
            }
        }
    )
    unit = replace(
        refusal.unit,
        donors=(*refusal.unit.donors, _prepared(parameter_donor), _prepared(receipt_donor)),
        functions=(action,),
        actions=(action,),
        receipts=(
            *(
                item
                for item in refusal.unit.receipts
                if item.intervention_id != refusal.intervention.id
            ),
            _receipt(parameter_donor),
            _receipt(receipt_donor),
            receipt,
        ),
    )
    refusal = replace(
        refusal,
        intervention=action,
        receipt=receipt,
        unit=unit,
        unit_donor_objects={
            **refusal.unit_donor_objects,
            parameter_donor.id: seed,
            receipt_donor.id: seed,
        },
    )
    monkeypatch.setattr(
        subject,
        "probe_donor_compile_windows",
        _fake_windows({"default": seed, 1: goal}, []),
    )

    result = subject.probe_carrier_discovery(
        _Handle(),  # type: ignore[arg-type]
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=1,
        window_size=1,
    )

    edits = {edit.before.id: edit.after for edit in result.repairs[0].intervention_edits}
    assert edits[parameter_donor.id] is None
    assert edits[receipt_donor.id] is None
    assert {edit.before.id for edit in result.repairs[0].receipt_edits} >= {
        f"proof.{parameter_donor.id}",
        f"proof.{receipt_donor.id}",
    }


def test_discovery_repoints_a_rewriting_record_whose_donor_body_comes_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, _seed, goal = _fixture(
        ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING,
        expected_body_sha256="f" * 64,
        expected_donor_body_sha256=GOAL_DIGEST,
    )
    compiled: list[str] = []
    monkeypatch.setattr(
        subject, "probe_donor_compile_windows", _fake_windows({"default": goal}, compiled)
    )
    repaired_receipt = refusal.receipt.model_copy(
        update={"expected_values": {**refusal.receipt.expected_values, "expected_seed_length": 1}}
    )

    def repair_repoint(action: Any, _receipt: Any, materials: Any) -> Any:
        if action.dependencies[0] == "donor.saved" or materials.donor_object != goal:
            pytest.fail("re-pointing must validate against the discovered donor object")
        assert materials.donor_source == SOURCE
        assert materials.target_donor_source == SOURCE
        assert materials.shape_identifiers
        return SimpleNamespace(
            receipt=repaired_receipt,
            changed_keys=("expected_seed_length",),
            candidate=object(),
        )

    monkeypatch.setattr(
        subject,
        "repair_measured_pins",
        repair_repoint,
    )

    result = subject.probe_carrier_discovery(
        _Handle(),  # type: ignore[arg-type]
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=4,
        window_size=2,
    )

    assert result.unresolved == ()
    assert result.compiled_candidates == 2  # one window of two, stopped after the first success
    repair = result.repairs[0]
    assert [item.how for item in repair.resolutions] == ["repoint"]
    assert len(repair.dependency_edits) == 1
    assert repair.dependency_edits[0].before.id == "function.saved"
    assert repair.dependency_edits[0].donor_id == repair.resolutions[0].donor_id
    assert {edit.before.id: edit.after for edit in repair.receipt_edits} == {
        "proof.function.saved": repaired_receipt,
        "proof.donor.saved": None,
    }
    # The record itself is not removed; its previous donor loses its only consumer.
    assert {edit.before.id: edit.after for edit in repair.intervention_edits} == {
        "donor.saved": None
    }


def test_discovery_reports_units_no_fresh_shape_could_settle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, seed, _goal = _fixture(
        ClassicRecipeFamily.EQUAL_BODY_STRICT, expected_body_sha256="0" * 64
    )
    compiled: list[str] = []
    monkeypatch.setattr(
        subject, "probe_donor_compile_windows", _fake_windows({"default": seed}, compiled)
    )

    result = subject.probe_carrier_discovery(
        _Handle(),  # type: ignore[arg-type]
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=3,
        window_size=8,
    )

    assert result.repairs == ()
    assert result.compiled_candidates == 3
    assert result.unresolved == (
        (
            "unit.fixture",
            "function.saved",
            "no compiled declaration shape carried the record's body",
        ),
    )


def test_discovery_skips_shapes_already_tried_in_this_command_and_reports_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, seed, _goal = _fixture(
        ClassicRecipeFamily.EQUAL_BODY_STRICT, expected_body_sha256="0" * 64
    )
    compiled: list[str] = []
    monkeypatch.setattr(
        subject, "probe_donor_compile_windows", _fake_windows({"default": seed}, compiled)
    )
    already = "shape::" + Digest.from_bytes(generate_declaration_shape(1, 2)).value

    result = subject.probe_carrier_discovery(
        _Handle(),  # type: ignore[arg-type]
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=2,
        window_size=8,
        tried_states={"unit.fixture": frozenset({already})},
    )

    # (1,1) is the saved donor and (1,2) was tried before: (1,3) and (2,2) are compiled.
    assert result.compiled_candidates == 2
    assert result.tried_states == {
        "unit.fixture": frozenset(
            "shape::" + Digest.from_bytes(generate_declaration_shape(*shape)).value
            for shape in ((1, 3), (2, 2))
        )
    }
    assert already not in result.tried_states["unit.fixture"]


def test_discovery_continues_with_forward_declaration_runs_once_every_shape_was_tried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, seed, goal = _fixture(
        ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT, expected_body_sha256=GOAL_DIGEST
    )
    compiled: list[str] = []
    # Every shape was tried earlier in the command; the third forward run carries the goal.
    monkeypatch.setattr(
        subject, "probe_donor_compile_windows", _fake_windows({"default": seed, 3: goal}, compiled)
    )
    every_shape = frozenset(
        "shape::" + Digest.from_bytes(generate_declaration_shape(*shape)).value
        for shape in subject._shape_states()
    )

    result = subject.probe_carrier_discovery(
        _Handle(),  # type: ignore[arg-type]
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=8,
        window_size=1,
        tried_states={"unit.fixture": every_shape},
    )

    assert result.compiled_candidates == 3
    assert len(result.repairs) == 1
    added = {item.intervention.role: item.intervention for item in result.repairs[0].additions}
    donor = added[ClassicRecipeRole.DONOR]
    assert donor.family is ClassicRecipeFamily.FORWARD_DECLARATION_RUN
    values = {f.name: f.value for f in donor.parameters}
    # Runs of one declaration at suffix and prefix come first (the fixture source has no
    # include seat, so after_includes is skipped); the third compile, suffix n=2, settled.
    assert (values["placement"], values["count"]) == ("suffix", 3)
    assert values["prefix"] == "RbDsc"
    assert [scope.function for scope in donor.beneficiaries] == [SYMBOL]
    assert added[ClassicRecipeRole.FUNCTION].dependencies == (donor.id,)
    assert (
        values["generated_header_sha256"]
        == Digest.from_bytes(generate_forward_run("RbDsc", 3, 3)).value
    )
    one = Digest.from_bytes(generate_forward_run("RbDsc", 1, 3)).value
    two = Digest.from_bytes(generate_forward_run("RbDsc", 2, 3)).value
    # A run of one count occupies one compiler arena whatever its placement, so
    # only the first placement of each count is compiled.
    assert result.tried_states["unit.fixture"] == {
        f"forward_run:suffix:{one}",
        f"forward_run:suffix:{two}",
        f"forward_run:suffix:{values['generated_header_sha256']}",
    }
    assert len(subject._carrier_states()) == subject.MAX_DISCOVERY_CANDIDATES


def test_saved_forward_runs_are_not_rediscovered_at_their_own_placement() -> None:
    generated = generate_forward_run("RbDsc", 2, 3)
    donor = _saved_donor(1, 1).model_copy(
        update={
            "family": ClassicRecipeFamily.FORWARD_DECLARATION_RUN,
            "parameters": tuple(
                ClassicField(name=name, value=value)
                for name, value in sorted(
                    {
                        "count": 2,
                        "emission_policy": "non_emitting_declarations_only",
                        "generated_header_sha256": Digest.from_bytes(generated).value,
                        "placement": "prefix",
                        "prefix": "RbDsc",
                        "width": 3,
                    }.items()
                )
            ),
        }
    )
    unit = SimpleNamespace(donors=[SimpleNamespace(intervention=donor)])
    assert subject._existing_state_identities(unit) == {  # type: ignore[arg-type]
        f"forward_run:prefix:{Digest.from_bytes(generated).value}"
    }


def test_discovery_never_prepares_two_states_that_share_a_compiler_arena() -> None:
    refusal, _seed, _goal = _fixture(
        ClassicRecipeFamily.EQUAL_BODY_STRICT, expected_body_sha256=GOAL_DIGEST
    )
    work = subject._group_units((refusal,))

    order = subject._prepare_attempts(
        work,
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=subject.MAX_DISCOVERY_CANDIDATES,
    )

    entry = work["unit.fixture"]
    seats = [prepared.request.compiler_seat.casefold() for _id, _donor, prepared in entry.attempts]
    assert len(seats) == len(set(seats))
    assert len(order) == len(entry.attempts)
    # The saved donor's own arena is never proposed again either.
    saved_seat = refusal.unit.donors[0].request.compiler_seat.casefold()
    assert saved_seat not in seats
    # Forward runs of one count are rendered at three placements; a source with no
    # include directive renders two of them identically, so one is dropped.
    forward_runs = [
        identity for identity in entry.identities.values() if identity.startswith("forward_run:")
    ]
    assert forward_runs
    assert len(forward_runs) < 3 * 500


def test_discovery_caps_preparation_at_the_command_candidate_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal, _seed, _goal = _fixture(
        ClassicRecipeFamily.EQUAL_BODY_STRICT,
        expected_body_sha256=GOAL_DIGEST,
    )
    prepared_limits: list[int] = []

    def prepare_spy(*args: object, **kwargs: object) -> tuple[tuple[str, str], ...]:
        del args
        prepared_limits.append(kwargs["per_unit"])  # type: ignore[arg-type]
        return ()

    monkeypatch.setattr(subject, "_prepare_attempts", prepare_spy)

    result = subject.probe_carrier_discovery(
        _Handle(),  # type: ignore[arg-type]
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=32,
        candidate_budget=3,
    )

    assert prepared_limits == [3]
    assert result.compiled_candidates == 0


def test_discovery_repoints_a_goal_body_no_closed_family_can_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from reprobit.discovery_authoring import DiscoveryAuthoringError

    refusal, _seed, goal = _fixture(
        ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT, expected_body_sha256=GOAL_DIGEST
    )
    monkeypatch.setattr(
        subject,
        "build_measured_function_record",
        lambda **_kwargs: (_ for _ in ()).throw(DiscoveryAuthoringError("lengths differ")),
    )
    repointed: list[str] = []

    def repoint(moved: Any, receipt: Any, materials: Any) -> Any:
        repointed.append(moved.dependencies[0])
        assert materials.donor_object == goal
        return SimpleNamespace(receipt=receipt)

    monkeypatch.setattr(subject, "repair_measured_pins", repoint)
    handle = _Handle()
    compiled: list[str] = []
    monkeypatch.setattr(
        subject, "probe_donor_compile_windows", _fake_windows({"default": goal}, compiled)
    )

    result = subject.probe_carrier_discovery(
        handle,  # type: ignore[arg-type]
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=4,
        candidate_budget=4,
    )

    assert compiled
    (repair,) = result.repairs
    (resolution,) = repair.resolutions
    assert resolution.how == "repoint"
    assert resolution.family == ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT.value
    assert repointed == [resolution.donor_id]
    (dependency,) = repair.dependency_edits
    assert dependency.donor_id == resolution.donor_id
    assert repair.additions[0].intervention.id == resolution.donor_id


def test_discovery_releases_processed_candidate_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import gc
    import weakref
    from dataclasses import fields

    class TrackedOutput(ClassicDonorProbeOutput):
        pass

    refusal, seed, _goal = _fixture(
        ClassicRecipeFamily.EQUAL_BODY_STRICT, expected_body_sha256=GOAL_DIGEST
    )
    references: list[weakref.ReferenceType[TrackedOutput]] = []

    def fake_windows(_probes, units, windows, *, evaluate, **_kwargs):  # type: ignore[no-untyped-def]
        by_id = {unit.donors[0].intervention.id: unit for unit in units}
        completed = []
        for window in windows:
            for donor_id in window:
                original = _probe_output(donor_id, by_id[donor_id], seed)
                output = TrackedOutput(
                    **{field.name: getattr(original, field.name) for field in fields(original)}
                )
                references.append(weakref.ref(output))
                assert not evaluate((output,))
                completed.append(donor_id)
                del output
                gc.collect()
                assert all(reference() is None for reference in references)
        return tuple(completed)

    monkeypatch.setattr(subject, "probe_donor_compile_windows", fake_windows)
    result = subject.probe_carrier_discovery(
        _Handle(),
        (refusal,),
        clean_sources={"src/unit.cpp": SOURCE},
        effective_sources={"src/unit.cpp": SOURCE},
        per_unit=8,
        window_size=1,
    )
    assert result.compiled_candidates == 8
