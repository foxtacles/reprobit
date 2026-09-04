from __future__ import annotations

import argparse
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import reprobit.repair_workflow as subject
from reprobit.classic_donor_retune_candidates import DonorRetuneChange
from reprobit.classic_legacy_repair import (
    LegacyInstallRepair,
    LegacyNoWindowError,
    LegacyOracleMaterial,
)
from reprobit.classic_project import ClassicDispatchMaterials
from reprobit.classic_redundant_action_repair import RedundantActionRepairError
from reprobit.classic_repair_discovery import ClassicDiscoveryResult
from reprobit.classic_repair_probe import (
    ClassicDonorRetuneAttemptRefusal,
    ClassicDonorRetuneProbeResult,
    ClassicDonorRetuneRefusal,
)
from reprobit.classic_repair_session import LegacyRepairRefusal
from reprobit.model import ByteRange, Digest, Scope
from reprobit.schema import (
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    LegacyOracleInstallIntervention,
    OracleInstallRange,
)

_ORIGINAL_DISCOVERY = subject.probe_classic_carrier_discovery


def _analysis(
    *,
    completed: bool,
    measured: tuple[object, ...] = (),
    refusals: tuple[object, ...] = (),
) -> object:
    return SimpleNamespace(
        completed=completed,
        measured_repairs=measured,
        structural_refusals=refusals,
    )


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    analyses: list[object],
    *,
    progress_descriptions: list[str] | None = None,
    settle_target_ids: frozenset[str] = frozenset(),
) -> subject.RepairWorkflowResult:
    bundle_counter = iter(range(100))
    interventions: list[object] = []
    seen_interventions: set[int] = set()
    for analysis in analyses:
        for refusal in analysis.structural_refusals:
            intervention = refusal.intervention
            if id(intervention) in seen_interventions:
                continue
            seen_interventions.add(id(intervention))
            interventions.append(intervention)
    monkeypatch.setattr(
        subject,
        "load_project_tree",
        lambda *_args, **_kwargs: SimpleNamespace(
            spec=cast(Any, object()),
            intervention_documents=(
                SimpleNamespace(model_dump=lambda **_kwargs: {"pass": next(bundle_counter)}),
            ),
            proof_documents=(),
            interventions=tuple(interventions),
        ),
    )

    def analyze(*_args: object, **kwargs: object) -> object:
        if progress_descriptions is not None:
            progress_descriptions.append(str(kwargs["progress_description"]))
        return analyses.pop(0)

    monkeypatch.setattr(subject, "analyze_classic_repair", analyze)
    if subject.probe_classic_carrier_discovery is _ORIGINAL_DISCOVERY:
        # Fresh-shape discovery needs a compiler runtime; workflow tests mock it out
        # unless a test installs its own double.
        monkeypatch.setattr(
            subject,
            "probe_classic_carrier_discovery",
            lambda *_args, **_kwargs: ClassicDiscoveryResult((), (), 0),
        )
    return subject.repair_classic_records(
        argparse.Namespace(project=str(tmp_path)),
        cast(Any, object()),
        staged_root=tmp_path,
        spec=cast(Any, object()),
        cache_root=tmp_path / "state",
        settle_target_ids=settle_target_ids,
    )


def test_workflow_persists_measured_repairs_then_requires_a_clean_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repair = SimpleNamespace(unit_id="tu.one")
    progress_descriptions: list[str] = []
    monkeypatch.setattr(
        subject,
        "apply_classic_receipt_repairs",
        lambda *_args: ("reprobit/proofs/one.json",),
    )

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=True, measured=(repair,)),
            _analysis(completed=True),
        ],
        progress_descriptions=progress_descriptions,
    )

    assert result.changed_records == ("reprobit/proofs/one.json",)
    assert result.affected_units == ("tu.one",)
    assert result.measured_checks == 1
    assert result.passes == 2
    assert progress_descriptions == [
        "repair pass 1: checking affected source files",
        "repair pass 2: checking again (refreshed 1 saved check)",
    ]


def test_workflow_rejects_measured_repair_that_changes_no_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repair = SimpleNamespace(unit_id="tu.one")
    monkeypatch.setattr(subject, "apply_classic_receipt_repairs", lambda *_args: ())

    with pytest.raises(subject.RepairWorkflowError, match="measured repair reported success"):
        _run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=True, measured=(repair,))],
        )


def test_workflow_applies_source_layout_then_regenerates_and_checks_again(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay = ClassicRecipeIntervention(
        id="project.fixture",
        scope=Scope(target="program"),
        rationale="Render one project source overlay.",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="program",
    )
    refusal = SimpleNamespace(unit_id="tu.existing", intervention=overlay)
    repair = SimpleNamespace(source_path="src/unit.cpp")
    source_results = iter(
        (
            SimpleNamespace(
                checked=True,
                repair=repair,
                compiled_candidates=3,
                source_path="src/unit.cpp",
                reason=None,
            ),
            SimpleNamespace(
                checked=True,
                repair=None,
                compiled_candidates=0,
                source_path=None,
                reason=None,
            ),
        )
    )
    events: list[str] = []

    def probe_source(*_args: object, **kwargs: object) -> object:
        events.append(f"settle:{sorted(cast(frozenset[str], kwargs['settle_target_ids']))}")
        return next(source_results)

    monkeypatch.setattr(
        subject,
        "probe_classic_project_overlay_repairs",
        probe_source,
    )
    monkeypatch.setattr(
        subject,
        "apply_classic_project_overlay_repair",
        lambda *_args, **_kwargs: (
            events.append("apply") or ("reprobit/interventions/project.json",)
        ),
    )
    regeneration = SimpleNamespace(changed_documents=("reprobit/interventions/regenerated.json",))
    monkeypatch.setattr(
        subject,
        "plan_source_regeneration",
        lambda *_args, **_kwargs: events.append("plan-regeneration") or regeneration,
    )
    monkeypatch.setattr(
        subject,
        "apply_source_regeneration",
        lambda *_args, **_kwargs: events.append("apply-regeneration"),
    )

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=True, refusals=(refusal,)),
            _analysis(completed=True, refusals=(refusal,)),
        ],
    )

    assert events == [
        "settle:[]",
        "apply",
        "plan-regeneration",
        "apply-regeneration",
        "settle:[]",
    ]
    assert result.changed_records == (
        "reprobit/interventions/project.json",
        "reprobit/interventions/regenerated.json",
    )
    assert result.affected_units == ("tu.existing",)
    assert result.source_retunes == 1
    assert result.compiled_candidates == 3
    assert result.passes == 2
    assert result.adjustment_rounds == 1


def test_workflow_consumes_one_cold_targeted_source_adjustment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay = ClassicRecipeIntervention(
        id="project.fixture",
        scope=Scope(target="program"),
        rationale="Render one project source overlay.",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="program",
    )
    refusal = SimpleNamespace(unit_id="tu.existing", intervention=overlay)
    repair = SimpleNamespace(source_path="src/unit.cpp")
    source_results = iter(
        (
            SimpleNamespace(
                checked=True,
                repair=repair,
                compiled_candidates=1,
                source_path="src/unit.cpp",
                reason=None,
            ),
            SimpleNamespace(
                checked=True,
                repair=None,
                compiled_candidates=0,
                source_path=None,
                reason=None,
            ),
        )
    )
    targets: list[frozenset[str]] = []

    def probe_source(*_args: object, **kwargs: object) -> object:
        targets.append(cast(frozenset[str], kwargs["settle_target_ids"]))
        return next(source_results)

    monkeypatch.setattr(subject, "probe_classic_project_overlay_repairs", probe_source)
    monkeypatch.setattr(
        subject,
        "apply_classic_project_overlay_repair",
        lambda *_args, **_kwargs: ("reprobit/interventions/project.json",),
    )
    regeneration = SimpleNamespace(changed_documents=())
    monkeypatch.setattr(subject, "plan_source_regeneration", lambda *_args, **_kwargs: regeneration)
    monkeypatch.setattr(subject, "apply_source_regeneration", lambda *_args, **_kwargs: None)

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=True, refusals=(refusal,)),
            _analysis(completed=True, refusals=(refusal,)),
        ],
        settle_target_ids=frozenset({"program"}),
    )

    assert targets == [frozenset({"program"}), frozenset({"program"})]
    assert result.source_retunes == 1
    assert result.adjustment_rounds == 1


def test_workflow_names_shared_budget_when_source_layout_search_exhausts_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overlay = ClassicRecipeIntervention(
        id="project.fixture",
        scope=Scope(target="program"),
        rationale="Render one project source overlay.",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="program",
    )
    refusal = SimpleNamespace(unit_id="tu.existing", intervention=overlay)
    monkeypatch.setattr(
        subject,
        "probe_classic_project_overlay_repairs",
        lambda *_args, **_kwargs: SimpleNamespace(
            checked=True,
            repair=None,
            compiled_candidates=256,
            source_path="src/unit.cpp",
            reason="the bounded search ended",
            exhausted=True,
        ),
    )

    with pytest.raises(
        subject.RepairWorkflowError,
        match="command-wide --donor-candidates limit after testing 256 repair choices",
    ):
        _run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=True, refusals=(refusal,))],
        )


@pytest.mark.parametrize("reported_candidates", (-1, 257))
def test_workflow_rejects_invalid_source_layout_candidate_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reported_candidates: int,
) -> None:
    overlay = ClassicRecipeIntervention(
        id="project.fixture",
        scope=Scope(target="program"),
        rationale="Render one project source overlay.",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="program",
    )
    refusal = SimpleNamespace(unit_id="tu.existing", intervention=overlay)
    monkeypatch.setattr(
        subject,
        "probe_classic_project_overlay_repairs",
        lambda *_args, **_kwargs: SimpleNamespace(
            checked=True,
            repair=None,
            compiled_candidates=reported_candidates,
            source_path="src/unit.cpp",
            reason="no candidate worked",
            exhausted=False,
        ),
    )

    with pytest.raises(
        subject.RepairWorkflowError,
        match="source-layout repair exceeded its remaining command-wide candidate budget",
    ):
        _run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=True, refusals=(refusal,))],
        )


def test_workflow_retires_one_proven_redundant_action_before_donor_search(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(
        unit_id="tu.one",
        intervention=SimpleNamespace(role=ClassicRecipeRole.FUNCTION, dependencies=("donor",)),
        receipt=object(),
        materials=object(),
        reason="saved function action no longer composes",
    )
    plan = SimpleNamespace(
        intervention_edits=(object(),),
        receipt_edits=(object(),),
        removed_donors=("donor",),
    )
    monkeypatch.setattr(subject, "plan_redundant_action_retirements", lambda *_args: plan)
    monkeypatch.setattr(
        subject,
        "apply_classic_authority_edits",
        lambda *_args, **_kwargs: ("reprobit/interventions/one.json",),
    )
    monkeypatch.setattr(
        subject,
        "probe_classic_donor_repairs",
        lambda *_args: pytest.fail("redundant action must be retired before donor search"),
    )

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=False, refusals=(refusal,)),
            _analysis(completed=True),
        ],
    )

    assert result.retired_actions == 1
    assert result.removed_donors == 1
    assert result.donor_retunes == 0
    assert result.passes == 2


def test_workflow_rejects_redundant_retirement_that_changes_no_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(
        unit_id="tu.one",
        intervention=SimpleNamespace(
            role=ClassicRecipeRole.FUNCTION,
            dependencies=("donor",),
        ),
        receipt=object(),
        materials=object(),
        reason="saved function action no longer composes",
    )
    plan = SimpleNamespace(
        intervention_edits=(object(),),
        receipt_edits=(object(),),
        removed_donors=(),
    )
    monkeypatch.setattr(subject, "plan_redundant_action_retirements", lambda *_args: plan)
    monkeypatch.setattr(subject, "apply_classic_authority_edits", lambda *_args, **_kwargs: ())

    with pytest.raises(
        subject.RepairWorkflowError,
        match="redundant-action retirement reported success",
    ):
        _run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=False, refusals=(refusal,))],
        )


def test_workflow_applies_bounded_donor_repairs_and_rechecks_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress_descriptions: list[str] = []
    refusal = SimpleNamespace(
        unit_id="tu.shared",
        intervention=SimpleNamespace(role=ClassicRecipeRole.FUNCTION, dependencies=("donor",)),
        receipt=object(),
        materials=object(),
        reason="donor declaration shape moved",
    )
    monkeypatch.setattr(
        subject,
        "plan_redundant_action_retirements",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    repair = object()
    monkeypatch.setattr(
        subject,
        "probe_classic_donor_repairs",
        lambda *_args, **_kwargs: SimpleNamespace(
            repairs=(repair,),
            refusals=(),
            compiled_candidates=7,
        ),
    )
    monkeypatch.setattr(
        subject,
        "apply_classic_donor_repairs",
        lambda *_args: (
            "reprobit/interventions/shared.json",
            "reprobit/proofs/shared.json",
        ),
    )

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=False, refusals=(refusal,)),
            _analysis(completed=True),
        ],
        progress_descriptions=progress_descriptions,
    )

    assert result.donor_retunes == 1
    assert result.compiled_candidates == 7
    assert result.affected_units == ("tu.shared",)
    assert result.passes == 2
    assert progress_descriptions == [
        "repair pass 1: checking affected source files",
        "repair pass 2: checking again (adjusted 1 compiler choice)",
    ]


def test_legacy_fallback_is_published_only_after_donor_search_finds_no_improvement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = ClassicProofReceipt(
        id="proof.legacy",
        intervention_id="legacy.install",
        family=ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
    )
    authority_range = OracleInstallRange(
        preimage_range=ByteRange(offset=1, length=1),
        output_range=ByteRange(offset=1, length=1),
        oracle_range=ByteRange(offset=1, length=1),
    )
    action = LegacyOracleInstallIntervention.freeze(
        id="legacy.install",
        scope=Scope(target="program", translation_unit="tu.legacy", function="?f@@YAXXZ"),
        rationale="Finite fixture quarantine.",
        dependencies=("donor.legacy",),
        proof_receipt_digest=Digest.from_bytes(b"old proof"),
        preimage_digest=Digest.from_bytes(b"old body"),
        oracle_body_digest=Digest.from_bytes(b"retail"),
        oracle_target="program",
        oracle_address=0x401000,
        ranges=(authority_range,),
        byte_count=1,
        maximum_oracle_payload_bytes=6,
    )
    refusal = LegacyRepairRefusal(
        unit_id="tu.legacy",
        action_index=0,
        intervention=action,
        receipt=receipt,
        materials=ClassicDispatchMaterials(seed_object=b"seed", donor_object=b"donor"),
        unit=cast(Any, SimpleNamespace()),
        reason="saved legacy action no longer composes",
        legacy_oracle=LegacyOracleMaterial(b"retail", {}),
    )
    fallback = LegacyInstallRepair(action, receipt, b"output")
    events: list[str] = []

    def reauthor(*_args: object) -> LegacyInstallRepair:
        events.append("baseline")
        return fallback

    def probe(_args: object, _output: object, refusals: tuple[Any, ...], **_kwargs: object):
        events.append("probe")
        assert refusals[0].baseline_repair is fallback
        return ClassicDonorRetuneProbeResult((), (), 1)

    def apply(*_args: object, **kwargs: object) -> tuple[str, ...]:
        events.append("fallback")
        assert kwargs["legacy_interventions"]
        assert kwargs["receipts"]
        return ("reprobit.toml", "reprobit/interventions/legacy.json")

    monkeypatch.setattr(subject, "reauthor_legacy_simulated_elision", reauthor)
    monkeypatch.setattr(subject, "probe_classic_donor_repairs", probe)
    monkeypatch.setattr(
        subject,
        "LegacyInterventionEdit",
        lambda before, after: SimpleNamespace(before=before, after=after),
    )
    monkeypatch.setattr(
        subject,
        "ClassicReceiptEdit",
        lambda before, after: SimpleNamespace(before=before, after=after),
    )
    monkeypatch.setattr(subject, "apply_classic_authority_edits", apply)

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=False, refusals=(refusal,)),
            _analysis(completed=True),
        ],
    )

    assert events == ["baseline", "probe", "fallback"]
    assert result.reauthored_actions == 1
    assert result.donor_retunes == 0


@pytest.mark.parametrize("replaced", [False, True])
def test_zero_window_legacy_resolution_runs_before_any_donor_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    replaced: bool,
) -> None:
    receipt = ClassicProofReceipt(
        id="proof.legacy.zero",
        intervention_id="legacy.zero",
        family=ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
    )
    authority_range = OracleInstallRange(
        preimage_range=ByteRange(offset=1, length=1),
        output_range=ByteRange(offset=1, length=1),
        oracle_range=ByteRange(offset=1, length=1),
    )
    action = LegacyOracleInstallIntervention.freeze(
        id="legacy.zero",
        scope=Scope(target="program", translation_unit="tu.zero", function="?f@@YAXXZ"),
        rationale="Finite fixture quarantine.",
        dependencies=("donor.zero",),
        proof_receipt_digest=Digest.from_bytes(b"old proof"),
        preimage_digest=Digest.from_bytes(b"old body"),
        oracle_body_digest=Digest.from_bytes(b"retail"),
        oracle_target="program",
        oracle_address=0x401000,
        ranges=(authority_range,),
        byte_count=1,
        maximum_oracle_payload_bytes=6,
    )
    refusal = LegacyRepairRefusal(
        unit_id="tu.zero",
        action_index=0,
        intervention=action,
        receipt=receipt,
        materials=ClassicDispatchMaterials(seed_object=b"seed", donor_object=b"donor"),
        unit=cast(Any, SimpleNamespace(plan=SimpleNamespace(build_target="program"))),
        reason="saved legacy action no longer composes",
        legacy_oracle=LegacyOracleMaterial(b"retail", {}),
    )
    resolution = SimpleNamespace(
        replaced=replaced,
        removed_donors=("donor.zero",) if not replaced else (),
    )
    events: list[str] = []

    def no_windows(*_args: object) -> object:
        raise LegacyNoWindowError("no windows")

    def plan(*_args: object, **kwargs: object) -> object:
        events.append("plan")
        assert kwargs["intervention"] is action
        return resolution

    monkeypatch.setattr(subject, "reauthor_legacy_simulated_elision", no_windows)
    monkeypatch.setattr(subject, "plan_legacy_no_window_resolution", plan)
    monkeypatch.setattr(
        subject,
        "_publish_legacy_no_window_resolution",
        lambda *_args: events.append("publish") or ("reprobit.toml",),
    )
    monkeypatch.setattr(
        subject,
        "probe_classic_donor_repairs",
        lambda *_args, **_kwargs: pytest.fail("zero-window resolution must not compile probes"),
    )

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=False, refusals=(refusal,)),
            _analysis(completed=True),
        ],
    )

    assert events == ["plan", "publish"]
    assert result.compiled_candidates == 0
    assert result.reauthored_actions == int(replaced)
    assert result.retired_actions == int(not replaced)
    assert result.removed_donors == int(not replaced)


@pytest.mark.parametrize(
    "reason",
    [
        "oracle capture failed: saved oracle file is missing",
        "oracle capture failed: saved oracle bytes differ from their pin",
    ],
)
def test_unavailable_legacy_oracle_fails_before_donor_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    receipt = ClassicProofReceipt(
        id="proof.legacy.unavailable",
        intervention_id="legacy.unavailable",
        family=ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
    )
    authority_range = OracleInstallRange(
        preimage_range=ByteRange(offset=1, length=1),
        output_range=ByteRange(offset=1, length=1),
        oracle_range=ByteRange(offset=1, length=1),
    )
    action = LegacyOracleInstallIntervention.freeze(
        id="legacy.unavailable",
        scope=Scope(target="program", translation_unit="tu.legacy", function="?f@@YAXXZ"),
        rationale="Finite fixture quarantine.",
        dependencies=("donor.legacy",),
        proof_receipt_digest=Digest.from_bytes(b"old proof"),
        preimage_digest=Digest.from_bytes(b"old body"),
        oracle_body_digest=Digest.from_bytes(b"retail"),
        oracle_target="program",
        oracle_address=0x401000,
        ranges=(authority_range,),
        byte_count=1,
        maximum_oracle_payload_bytes=6,
    )
    refusal = LegacyRepairRefusal(
        unit_id="tu.legacy",
        action_index=0,
        intervention=action,
        receipt=receipt,
        materials=ClassicDispatchMaterials(seed_object=b"seed", donor_object=b"donor"),
        unit=cast(Any, SimpleNamespace()),
        reason=reason,
        legacy_oracle=None,
    )
    monkeypatch.setattr(
        subject,
        "probe_classic_donor_repairs",
        lambda *_args, **_kwargs: pytest.fail("an unavailable oracle must not spend probe budget"),
    )

    with pytest.raises(subject.RepairWorkflowError, match="before donor search"):
        _run(tmp_path, monkeypatch, [_analysis(completed=False, refusals=(refusal,))])


def test_workflow_passes_one_cumulative_candidate_budget_to_donor_probes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(
        unit_id="tu.shared",
        intervention=SimpleNamespace(
            role=ClassicRecipeRole.FUNCTION,
            dependencies=("donor",),
        ),
        receipt=object(),
        materials=object(),
        reason="donor declaration shape moved",
    )
    monkeypatch.setattr(
        subject,
        "plan_redundant_action_retirements",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    budgets: list[int] = []

    def probe(
        *_args: object,
        candidate_budget: int,
        **_kwargs: object,
    ) -> object:
        budgets.append(candidate_budget)
        compiled = 250 if len(budgets) == 1 else 6
        return SimpleNamespace(
            repairs=(object(),),
            refusals=(),
            compiled_candidates=compiled,
        )

    monkeypatch.setattr(subject, "probe_classic_donor_repairs", probe)
    monkeypatch.setattr(
        subject,
        "apply_classic_donor_repairs",
        lambda *_args: ("reprobit/interventions/shared.json",),
    )

    with pytest.raises(
        subject.RepairWorkflowError,
        match="command-wide --donor-candidates limit after testing 256 repair choices",
    ):
        _run(
            tmp_path,
            monkeypatch,
            [
                _analysis(completed=False, refusals=(refusal,)),
                _analysis(completed=False, refusals=(refusal,)),
                _analysis(completed=False, refusals=(refusal,)),
            ],
        )

    assert budgets == [256, 6]


@pytest.mark.parametrize("reported_candidates", (-1, 257))
def test_workflow_rejects_invalid_post_donor_discovery_candidate_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reported_candidates: int,
) -> None:
    refusal = SimpleNamespace(
        unit_id="tu.shared",
        intervention=SimpleNamespace(
            role=ClassicRecipeRole.FUNCTION,
            dependencies=("donor",),
        ),
        receipt=object(),
        materials=object(),
        reason="donor declaration shape moved",
    )
    monkeypatch.setattr(
        subject,
        "plan_redundant_action_retirements",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    monkeypatch.setattr(
        subject,
        "probe_classic_donor_repairs",
        lambda *_args, **_kwargs: ClassicDonorRetuneProbeResult((), (), 0),
    )
    monkeypatch.setattr(
        subject,
        "probe_classic_carrier_discovery",
        lambda *_args, **_kwargs: ClassicDiscoveryResult((), (), reported_candidates),
    )

    with pytest.raises(
        subject.RepairWorkflowError,
        match="carrier discovery exceeded its remaining command-wide candidate budget",
    ):
        _run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=False, refusals=(refusal,))],
        )


def test_workflow_rejects_donor_repair_that_changes_no_records(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(
        unit_id="tu.shared",
        intervention=SimpleNamespace(
            role=ClassicRecipeRole.FUNCTION,
            dependencies=("donor",),
        ),
        receipt=object(),
        materials=object(),
        reason="donor declaration shape moved",
    )
    monkeypatch.setattr(
        subject,
        "plan_redundant_action_retirements",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    monkeypatch.setattr(
        subject,
        "probe_classic_donor_repairs",
        lambda *_args, **_kwargs: SimpleNamespace(
            repairs=(object(),),
            refusals=(),
            compiled_candidates=1,
        ),
    )
    monkeypatch.setattr(subject, "apply_classic_donor_repairs", lambda *_args: ())

    with pytest.raises(subject.RepairWorkflowError, match="donor repair reported success"):
        _run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=False, refusals=(refusal,))],
        )


def test_workflow_reports_the_candidate_that_reached_the_strongest_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(
        unit_id="tu.one",
        intervention=SimpleNamespace(role=ClassicRecipeRole.FUNCTION, dependencies=("donor",)),
        receipt=object(),
        materials=object(),
        reason="current function cannot be adjusted safely",
    )
    monkeypatch.setattr(
        subject,
        "plan_redundant_action_retirements",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    monkeypatch.setattr(
        subject,
        "probe_classic_donor_repairs",
        lambda *_args, **_kwargs: ClassicDonorRetuneProbeResult(
            (),
            (
                ClassicDonorRetuneRefusal(
                    "tu.one",
                    "donor.one",
                    ("function.one",),
                    8,
                    "no nearby donor setting worked",
                    (
                        ClassicDonorRetuneAttemptRefusal(
                            2,
                            (
                                DonorRetuneChange(
                                    ("parameters", "classes"),
                                    6,
                                    8,
                                ),
                            ),
                            "ordinary_validation",
                            "retail relocation target changed",
                        ),
                    ),
                ),
            ),
            8,
        ),
    )

    with pytest.raises(subject.RepairWorkflowError) as raised:
        _run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=False, refusals=(refusal,))],
        )

    message = str(raised.value)
    assert (
        "Automatic repair could not prove a safe result for affected build `tu.one` after testing "
        "8 nearby compiler choices." in message
    )
    assert "Closest compiler choice tried: `classes` 6 -> 8." in message
    assert "Why it was rejected: retail relocation target changed" in message
    assert raised.value.diagnostic == {
        "unit_id": "tu.one",
        "donor_id": "donor.one",
        "action_ids": ["function.one"],
        "candidates_tried": 8,
        "reason": "no nearby donor setting worked",
        "best_candidate": {
            "distance": 2,
            "stage": "ordinary_validation",
            "reason": "retail relocation target changed",
            "changes": [
                {
                    "path": ["parameters", "classes"],
                    "before": 6,
                    "after": 8,
                    "kind": "knob",
                }
            ],
        },
    }


def test_workflow_stops_when_authority_state_repeats(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = SimpleNamespace(model_dump=lambda **_kwargs: {"state": "same"})
    bundle = SimpleNamespace(
        intervention_documents=(document,),
        proof_documents=(),
        interventions=(),
    )
    repair = SimpleNamespace(unit_id="tu.one")
    analyses = [_analysis(completed=True, measured=(repair,))]
    monkeypatch.setattr(subject, "load_project_tree", lambda *_args, **_kwargs: bundle)
    monkeypatch.setattr(
        subject,
        "analyze_classic_repair",
        lambda *_args, **_kwargs: analyses.pop(0),
    )
    monkeypatch.setattr(
        subject,
        "apply_classic_receipt_repairs",
        lambda *_args: ("reprobit/proofs/one.json",),
    )

    with pytest.raises(subject.RepairWorkflowError, match="previously checked"):
        subject.repair_classic_records(
            argparse.Namespace(project=str(tmp_path)),
            cast(Any, object()),
            staged_root=tmp_path,
            spec=cast(Any, object()),
            cache_root=tmp_path / "state",
        )


def test_workflow_allows_a_clean_check_after_twenty_four_adjustment_rounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repair = SimpleNamespace(unit_id="tu.one")
    analyses = [
        *(
            _analysis(completed=True, measured=(repair,))
            for _ in range(subject.MAX_REPAIR_ADJUSTMENT_ROUNDS)
        ),
        _analysis(completed=True),
    ]
    monkeypatch.setattr(
        subject,
        "apply_classic_receipt_repairs",
        lambda *_args: ("reprobit/proofs/one.json",),
    )

    result = _run(tmp_path, monkeypatch, analyses)

    assert result.measured_checks == 24
    assert result.passes == 25


def test_workflow_refuses_a_twenty_fifth_adjustment_round(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repair = SimpleNamespace(unit_id="tu.one")
    analyses = [
        _analysis(completed=True, measured=(repair,))
        for _ in range(subject.MAX_REPAIR_ADJUSTMENT_ROUNDS + 1)
    ]
    applications = 0

    def apply(*_args: object) -> tuple[str, ...]:
        nonlocal applications
        applications += 1
        return ("reprobit/proofs/one.json",)

    monkeypatch.setattr(subject, "apply_classic_receipt_repairs", apply)

    with pytest.raises(subject.RepairWorkflowError, match="limit of 24"):
        _run(tmp_path, monkeypatch, analyses)

    assert applications == 24
    assert analyses == []


def test_workflow_batches_every_visible_redundant_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusals = tuple(
        SimpleNamespace(
            unit_id=f"tu.{index}",
            intervention=SimpleNamespace(
                id=f"function.{index}",
                role=ClassicRecipeRole.FUNCTION,
                dependencies=("donor.shared",),
            ),
            receipt=SimpleNamespace(id=f"proof.function.{index}"),
            materials=object(),
            reason="fresh source already emits the saved function",
        )
        for index in range(30)
    )
    candidate_counts: list[int] = []

    def plan(_interventions: object, _receipts: object, candidates: tuple[object, ...]) -> object:
        candidate_counts.append(len(candidates))
        return SimpleNamespace(
            intervention_edits=(object(),),
            receipt_edits=(object(),),
            removed_donors=("donor.shared",),
        )

    applications = 0

    def apply(*_args: object, **_kwargs: object) -> tuple[str, ...]:
        nonlocal applications
        applications += 1
        return ("reprobit/interventions/functions.json",)

    monkeypatch.setattr(subject, "plan_redundant_action_retirements", plan)
    monkeypatch.setattr(subject, "apply_classic_authority_edits", apply)

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=False, refusals=refusals),
            _analysis(completed=True),
        ],
    )

    assert candidate_counts == [1] * 30 + [30]
    assert applications == 1
    assert result.retired_actions == 30
    assert result.removed_donors == 1
    assert result.passes == 2


def test_retirement_only_rounds_do_not_consume_the_adjustment_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusals = tuple(
        SimpleNamespace(
            unit_id=f"tu.{index}",
            intervention=SimpleNamespace(
                id=f"function.{index}",
                role=ClassicRecipeRole.FUNCTION,
                dependencies=("donor.shared",),
            ),
            receipt=SimpleNamespace(id=f"proof.function.{index}"),
            materials=object(),
            reason="fresh source already emits the saved function",
        )
        for index in range(25)
    )
    plan = SimpleNamespace(
        intervention_edits=(object(),),
        receipt_edits=(object(),),
        removed_donors=(),
    )
    monkeypatch.setattr(subject, "plan_redundant_action_retirements", lambda *_args: plan)
    monkeypatch.setattr(
        subject,
        "apply_classic_authority_edits",
        lambda *_args, **_kwargs: ("reprobit/interventions/functions.json",),
    )

    result = _run(
        tmp_path,
        monkeypatch,
        [
            *(_analysis(completed=False, refusals=(refusal,)) for refusal in refusals),
            _analysis(completed=True),
        ],
    )

    assert result.retired_actions == 25
    assert result.passes == 26


def test_workflow_defers_exhausted_donor_groups_until_the_final_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refusal(donor: str) -> object:
        return SimpleNamespace(
            unit_id="tu.shared",
            intervention=SimpleNamespace(role=ClassicRecipeRole.FUNCTION, dependencies=(donor,)),
            receipt=object(),
            materials=object(),
            reason="donor declaration shape moved",
        )

    stubborn = refusal("donor.stubborn")
    easy = refusal("donor.easy")
    later = refusal("donor.later")
    monkeypatch.setattr(
        subject,
        "plan_redundant_action_retirements",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    probed: list[tuple[str, ...]] = []

    def probe(
        _args: object, _output: object, refusals: tuple[Any, ...], **_kwargs: object
    ) -> object:
        excluded = _kwargs.get("excluded_groups", frozenset())
        donors = tuple(
            item.intervention.dependencies[0]
            for item in refusals
            if (item.unit_id, item.intervention.dependencies[0]) not in excluded
        )
        probed.append(donors)
        repairs = tuple(object() for donor in donors if donor != "donor.stubborn")
        stubborn_refusal = (
            ClassicDonorRetuneRefusal(
                "tu.shared",
                "donor.stubborn",
                ("function.stubborn",),
                2048,
                "none of 2048 compiler choices restored the expected output",
                (),
                exhausted=True,
            ),
        )
        return ClassicDonorRetuneProbeResult(
            cast(Any, repairs),
            stubborn_refusal if "donor.stubborn" in donors else (),
            len(donors),
        )

    monkeypatch.setattr(subject, "probe_classic_donor_repairs", probe)
    monkeypatch.setattr(
        subject,
        "apply_classic_donor_repairs",
        lambda *_args: ("reprobit/interventions/shared.json",),
    )

    with pytest.raises(subject.RepairWorkflowError, match="could not prove a safe result"):
        _run(
            tmp_path,
            monkeypatch,
            [
                _analysis(completed=False, refusals=(stubborn, easy)),
                _analysis(completed=False, refusals=(stubborn, later)),
                _analysis(completed=False, refusals=(stubborn,)),
            ],
        )

    # Round 1 probes everything and exhausts the stubborn donor; round 2 probes only the fresh
    # group; round 3 has nothing fresh left, so the stubborn donor gets its final attempt.
    assert probed == [
        ("donor.stubborn", "donor.easy"),
        ("donor.later",),
        ("donor.stubborn",),
    ]


def test_workflow_keeps_auxiliary_search_when_the_primary_is_exhausted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    action = ClassicRecipeIntervention(
        id="function.auxiliary",
        scope=Scope(target="program", translation_unit="tu.shared", function="?f@@YAXXZ"),
        rationale="Exercise an auxiliary donor after the primary search is exhausted.",
        dependencies=("donor.primary",),
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="program",
        symbol="?f@@YAXXZ",
    )
    receipt = ClassicProofReceipt(
        id="proof.function.auxiliary",
        intervention_id=action.id,
        family=action.family,
        expected_values={"target_donor": "donor.auxiliary"},
    )
    refusal = SimpleNamespace(
        unit_id="tu.shared",
        intervention=action,
        receipt=receipt,
        materials=object(),
        reason="donor combination moved",
    )
    easy = SimpleNamespace(
        unit_id="tu.easy",
        intervention=SimpleNamespace(
            role=ClassicRecipeRole.FUNCTION,
            dependencies=("donor.easy",),
        ),
        receipt=object(),
        materials=object(),
        reason="easy donor moved",
    )
    monkeypatch.setattr(
        subject,
        "plan_redundant_action_retirements",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    monkeypatch.setattr(
        subject,
        "plan_function_reauthoring",
        lambda _refusals: SimpleNamespace(reauthorings=()),
    )
    calls: list[tuple[tuple[object, ...], frozenset[tuple[str, str]]]] = []

    def probe(
        _args: object,
        _output: object,
        refusals: tuple[object, ...],
        **kwargs: object,
    ) -> ClassicDonorRetuneProbeResult:
        calls.append((refusals, cast(Any, kwargs["excluded_groups"])))
        if len(calls) == 1:
            primary_refusal = ClassicDonorRetuneRefusal(
                "tu.shared",
                "donor.primary",
                (action.id,),
                1,
                "primary exhausted",
                exhausted=True,
            )
            return ClassicDonorRetuneProbeResult(
                cast(Any, (object(),)),
                (primary_refusal,),
                1,
            )
        return ClassicDonorRetuneProbeResult(cast(Any, (object(),)), (), 1)

    monkeypatch.setattr(subject, "probe_classic_donor_repairs", probe)
    monkeypatch.setattr(
        subject,
        "apply_classic_donor_repairs",
        lambda *_args: ("reprobit/interventions/shared.json",),
    )

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=False, refusals=(refusal, easy)),
            _analysis(completed=False, refusals=(refusal,)),
            _analysis(completed=True),
        ],
    )

    assert calls[0][1] == frozenset()
    assert calls[1] == (
        (refusal,),
        frozenset({("tu.shared", "donor.primary")}),
    )
    assert result.donor_retunes == 2


def test_workflow_reauthors_functions_from_captured_donors_before_probing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(
        unit_id="tu.shared",
        intervention=SimpleNamespace(role=ClassicRecipeRole.FUNCTION, dependencies=("donor",)),
        receipt=object(),
        materials=object(),
        reason="fresh donor body no longer matches immutable expected_body_sha256 goal",
    )
    monkeypatch.setattr(
        subject,
        "plan_redundant_action_retirements",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    plan = SimpleNamespace(
        reauthorings=(object(),),
        intervention_edits=("edit",),
        receipt_edits=("receipt",),
        additions=("addition",),
        skipped=(),
        dependency_edits=("dependency",),
    )
    applied: list[dict[str, object]] = []
    monkeypatch.setattr(subject, "plan_function_reauthoring", lambda _refusals: plan)
    monkeypatch.setattr(
        subject,
        "apply_classic_authority_edits",
        lambda *_args, **kwargs: applied.append(kwargs) or ("reprobit/interventions/tu.json",),
    )
    monkeypatch.setattr(
        subject,
        "probe_classic_donor_repairs",
        lambda *_args, **_kwargs: pytest.fail("re-authoring must run before any donor probe"),
    )

    result = _run(
        tmp_path,
        monkeypatch,
        [
            _analysis(completed=False, refusals=(refusal,)),
            _analysis(completed=True),
        ],
    )

    assert result.reauthored_actions == 1
    assert result.donor_retunes == 0 and result.compiled_candidates == 0
    assert applied == [
        {
            "interventions": ("edit",),
            "receipts": ("receipt",),
            "additions": ("addition",),
            "dependencies": ("dependency",),
        }
    ]
    assert result.changed_records == ("reprobit/interventions/tu.json",)


def _ledger_root(tmp_path: Path) -> Path:
    from reprobit.composition_ledger import (
        COMPOSED_BODY_LEDGER_RELATIVE,
        ComposedBodyLedger,
        write_ledger,
    )

    cache_root = tmp_path / "state"
    write_ledger(
        cache_root.joinpath(*COMPOSED_BODY_LEDGER_RELATIVE),
        ComposedBodyLedger(graph_digest="0" * 64),
    )
    return cache_root


def _census_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    analyses: list[Any],
    censuses: list[Any],
) -> tuple[subject.RepairWorkflowResult, list[dict[str, object]]]:
    cache_root = _ledger_root(tmp_path)
    bundle_counter = iter(range(100))
    monkeypatch.setattr(
        subject,
        "load_project_tree",
        lambda *_args, **_kwargs: SimpleNamespace(
            intervention_documents=(
                SimpleNamespace(model_dump=lambda **_kwargs: {"pass": next(bundle_counter)}),
            ),
            proof_documents=(),
            interventions=(),
        ),
    )
    analyze_calls: list[dict[str, object]] = []

    def analyze(*_args: object, **kwargs: object) -> object:
        analyze_calls.append(kwargs)
        return analyses.pop(0)

    monkeypatch.setattr(subject, "analyze_classic_repair", analyze)
    monkeypatch.setattr(subject, "plan_repair_census", lambda *_args, **_kwargs: censuses.pop(0))
    result = subject.repair_classic_records(
        argparse.Namespace(project=str(tmp_path)),
        cast(Any, object()),
        staged_root=tmp_path,
        spec=cast(Any, object()),
        cache_root=cache_root,
    )
    return result, analyze_calls


def test_workflow_records_unrecorded_fallout_found_by_the_ledger_census(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(unit_id="tu.one")
    censuses = [
        SimpleNamespace(refusals=(refusal,), unplanned=(), missing=()),
        SimpleNamespace(refusals=(), unplanned=(), missing=()),
    ]
    discovered: list[tuple[object, ...]] = []

    def discover(
        _args: object, _output: object, refusals: tuple[object, ...], **_kwargs: object
    ) -> ClassicDiscoveryResult:
        discovered.append(refusals)
        return ClassicDiscoveryResult(
            cast(Any, (SimpleNamespace(unit_id="tu.one", resolutions=("settled",)),)),
            (),
            3,
            {"tu.one": frozenset({"shape"})},
        )

    monkeypatch.setattr(subject, "probe_classic_carrier_discovery", discover)
    monkeypatch.setattr(
        subject,
        "apply_classic_discovery_repairs",
        lambda *_args: ("reprobit/interventions/tus/one.json",),
    )

    result, analyze_calls = _census_run(
        tmp_path,
        monkeypatch,
        [_analysis(completed=True), _analysis(completed=True)],
        censuses,
    )

    assert [call["seed_census"] for call in analyze_calls] == [True, True]
    assert discovered == [(refusal,)]
    assert result.passes == 2
    assert result.discovered_actions == 1
    assert result.compiled_candidates == 3
    assert result.changed_records == ("reprobit/interventions/tus/one.json",)
    assert result.affected_units == ("tu.one",)
    assert censuses == []


def test_workflow_names_shared_budget_when_census_search_exhausts_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(unit_id="tu.one")
    censuses = [
        SimpleNamespace(refusals=(refusal,), unplanned=(), missing=()),
        SimpleNamespace(refusals=(refusal,), unplanned=(), missing=()),
    ]
    probe_calls = 0

    def discover(*_args: object, **_kwargs: object) -> ClassicDiscoveryResult:
        nonlocal probe_calls
        probe_calls += 1
        repair = SimpleNamespace(resolutions=("settled",))
        return ClassicDiscoveryResult(cast(Any, (repair,)), (), 256)

    monkeypatch.setattr(subject, "probe_classic_carrier_discovery", discover)
    monkeypatch.setattr(
        subject,
        "apply_classic_discovery_repairs",
        lambda *_args: ("reprobit/interventions/tus/one.json",),
    )

    with pytest.raises(
        subject.RepairWorkflowError,
        match="command-wide --donor-candidates limit after testing 256 repair choices",
    ):
        _census_run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=True), _analysis(completed=True)],
            censuses,
        )

    assert probe_calls == 1


@pytest.mark.parametrize("reported_candidates", (-1, 257))
def test_workflow_rejects_invalid_census_discovery_candidate_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reported_candidates: int,
) -> None:
    refusal = SimpleNamespace(unit_id="tu.one")
    monkeypatch.setattr(
        subject,
        "probe_classic_carrier_discovery",
        lambda *_args, **_kwargs: ClassicDiscoveryResult((), (), reported_candidates),
    )

    with pytest.raises(
        subject.RepairWorkflowError,
        match=(
            "newly affected function discovery exceeded its remaining command-wide candidate budget"
        ),
    ):
        _census_run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=True)],
            [SimpleNamespace(refusals=(refusal,), unplanned=(), missing=())],
        )


def test_workflow_admits_units_with_unplanned_census_fallout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entry = SimpleNamespace(source="src/other.cpp", symbol="?f@@YAXXZ")
    censuses = [
        SimpleNamespace(refusals=(), unplanned=(entry,), missing=()),
        SimpleNamespace(refusals=(), unplanned=(), missing=()),
    ]
    planned: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        subject,
        "plan_translation_unit_admissions",
        lambda _bundle, entries: planned.append(entries) or ("tu.new",),
    )
    monkeypatch.setattr(
        subject,
        "apply_translation_unit_admissions",
        lambda *_args: ("reprobit/build-plan.json", "reprobit/interventions/tu.new.json"),
    )

    result, _calls = _census_run(
        tmp_path,
        monkeypatch,
        [_analysis(completed=True), _analysis(completed=True)],
        censuses,
    )

    assert planned == [(entry,)]
    assert result.admitted_units == 1
    assert result.passes == 2
    assert result.changed_records == (
        "reprobit/build-plan.json",
        "reprobit/interventions/tu.new.json",
    )


def test_workflow_reports_a_unit_it_cannot_admit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from reprobit.repair_unit_admission import TranslationUnitAdmissionError

    entry = SimpleNamespace(source="src/other.cpp", symbol="?f@@YAXXZ")
    censuses = [SimpleNamespace(refusals=(), unplanned=(entry,), missing=())]

    def refuse(*_args: object) -> tuple[object, ...]:
        raise TranslationUnitAdmissionError("src/other.cpp is not in the locked source manifest")

    monkeypatch.setattr(subject, "plan_translation_unit_admissions", refuse)

    with pytest.raises(subject.RepairWorkflowError, match=re.escape("src/other.cpp:?f@@YAXXZ")):
        _census_run(tmp_path, monkeypatch, [_analysis(completed=True)], censuses)


def test_workflow_refuses_census_fallout_no_carrier_state_settles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    refusal = SimpleNamespace(unit_id="tu.one")
    censuses = [SimpleNamespace(refusals=(refusal,), unplanned=(), missing=())]
    monkeypatch.setattr(
        subject,
        "probe_classic_carrier_discovery",
        lambda *_args, **_kwargs: ClassicDiscoveryResult(
            (), (("tu.one", "census.deadbeef", "no state carried the body"),), 5
        ),
    )

    with pytest.raises(
        subject.RepairWorkflowError, match="could not restore newly affected functions"
    ):
        _census_run(tmp_path, monkeypatch, [_analysis(completed=True)], censuses)


def test_workflow_without_a_ledger_does_not_census(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    analyses = [_analysis(completed=True)]

    def analyze(*_args: object, **kwargs: object) -> object:
        calls.append(kwargs)
        return analyses.pop(0)

    monkeypatch.setattr(
        subject,
        "load_project_tree",
        lambda *_args, **_kwargs: SimpleNamespace(
            intervention_documents=(SimpleNamespace(model_dump=lambda **_kwargs: {}),),
            proof_documents=(),
            interventions=(),
        ),
    )
    monkeypatch.setattr(subject, "analyze_classic_repair", analyze)
    monkeypatch.setattr(
        subject, "plan_repair_census", lambda *_args, **_kwargs: pytest.fail("no census expected")
    )

    result = subject.repair_classic_records(
        argparse.Namespace(project=str(tmp_path)),
        cast(Any, object()),
        staged_root=tmp_path,
        spec=cast(Any, object()),
        cache_root=tmp_path / "state",
    )

    assert result.passes == 1
    assert [call["seed_census"] for call in calls] == [False]


class _AttemptStage:
    def __init__(self, root: Path) -> None:
        self.root = root

    def __enter__(self) -> Path:
        return self.root

    def __exit__(self, *_args: object) -> None:
        return None


def _attempt_workflow(
    record: str,
    *,
    candidates: int,
    rounds: int,
    source_retunes: int = 0,
) -> subject.RepairWorkflowResult:
    return subject.RepairWorkflowResult(
        changed_records=(record,),
        affected_units=(f"unit.{record}",),
        measured_checks=1,
        retired_actions=0,
        removed_donors=0,
        donor_retunes=0,
        compiled_candidates=candidates,
        passes=1,
        source_retunes=source_retunes,
        adjustment_rounds=rounds,
    )


def _wire_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    report: object,
) -> tuple[object, dict[str, list[object]]]:
    staged_root = tmp_path / "staged"
    staged_root.mkdir()
    snapshot = SimpleNamespace(
        root=tmp_path / "public",
        spec=SimpleNamespace(
            layout=SimpleNamespace(
                source_manifest="reprobit/source-manifest.json",
                build_plan="reprobit/build-plan.json",
                producer_graph="reprobit/producer-graph.json",
            )
        ),
    )
    calls: dict[str, list[object]] = {
        "captures": [],
        "collects": [],
        "publishes": [],
    }
    regeneration = SimpleNamespace(changed_documents=("reprobit/interventions/source.json",))
    monkeypatch.setattr(
        subject, "stage_repair_project", lambda *_args, **_kwargs: _AttemptStage(staged_root)
    )
    monkeypatch.setattr(subject, "plan_source_regeneration", lambda *_args, **_kwargs: regeneration)
    monkeypatch.setattr(subject, "apply_source_regeneration", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(subject, "command_source_lock", lambda *_args, **_kwargs: 0)

    def capture(*_args: object, **_kwargs: object) -> tuple[object, ...]:
        paths = frozenset(cast(set[str], _args[2]))
        calls["captures"].append(paths)
        return (paths,)

    def collect(*_args: object, **kwargs: object) -> object:
        calls["collects"].append(kwargs["record_postimages"])
        return SimpleNamespace(records={}, outputs={})

    def publish(*_args: object, **_kwargs: object) -> object:
        calls["publishes"].append(object())
        return SimpleNamespace(changed_paths=())

    monkeypatch.setattr(subject, "capture_repair_record_postimages", capture)
    monkeypatch.setattr(subject, "collect_repair_candidate", collect)
    monkeypatch.setattr(subject, "publish_repair_candidate", publish)
    monkeypatch.setattr(subject, "read_report_json", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(subject, "_cold_link_layout_hint", lambda *_args, **_kwargs: None)
    return snapshot, calls


def test_attempt_retries_only_the_targets_failed_by_private_cold_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = SimpleNamespace(
        verdict=SimpleNamespace(cold=True, logic_certified=True, byte_exact=False),
        targets=(
            SimpleNamespace(id="program", byte_exact=False),
            SimpleNamespace(id="library", byte_exact=True),
        ),
    )
    snapshot, calls = _wire_attempt(tmp_path, monkeypatch, report=report)
    workflows = iter(
        (
            _attempt_workflow("first.json", candidates=4, rounds=2),
            _attempt_workflow(
                "settled.json",
                candidates=3,
                rounds=1,
                source_retunes=1,
            ),
        )
    )
    repair_args: list[argparse.Namespace] = []
    repair_targets: list[frozenset[str]] = []
    repair_hints: list[object] = []
    hint = object()
    monkeypatch.setattr(subject, "_cold_link_layout_hint", lambda *_args: hint)

    def repair(args: argparse.Namespace, *_args: object, **kwargs: object) -> object:
        repair_args.append(args)
        repair_targets.append(cast(frozenset[str], kwargs["settle_target_ids"]))
        repair_hints.append(kwargs["link_layout_hint"])
        return next(workflows)

    statuses = iter((1, 0))
    result = subject.execute_repair_attempt(
        argparse.Namespace(donor_candidates=10, adjustment_rounds=5),
        cast(Any, object()),
        snapshot=cast(Any, snapshot),
        selected_paths=("src/unit.cpp",),
        cache_root=tmp_path / "cache",
        candidate_report_directory="candidate-report",
        final_report_directory="final-report",
        report_preimages=(),
        keep=subject.KeepWorkspace.NEVER,
        verify_command=lambda *_args: next(statuses),
        repair_records=cast(Any, repair),
    )

    assert len(repair_args) == 2
    assert repair_args[1].donor_candidates == 6
    assert repair_args[1].adjustment_rounds == 3
    assert repair_targets == [frozenset(), frozenset({"program"})]
    assert repair_hints == [None, hint]
    assert result.workflow.changed_records == ("first.json", "settled.json")
    assert result.workflow.compiled_candidates == 7
    assert result.workflow.adjustment_rounds == 3
    assert result.workflow.source_retunes == 1
    assert len(calls["captures"]) == 2
    assert len(calls["collects"]) == 2
    assert len(calls["publishes"]) == 1


@pytest.mark.parametrize(
    ("cold", "logic_certified", "byte_exact"),
    ((False, True, False), (True, False, False), (True, True, True)),
)
def test_attempt_does_not_retry_without_certified_cold_byte_fallout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cold: bool,
    logic_certified: bool,
    byte_exact: bool,
) -> None:
    report = SimpleNamespace(
        verdict=SimpleNamespace(
            cold=cold,
            logic_certified=logic_certified,
            byte_exact=byte_exact,
        ),
        targets=(SimpleNamespace(id="program", byte_exact=byte_exact),),
    )
    snapshot, calls = _wire_attempt(tmp_path, monkeypatch, report=report)
    repair_calls = 0

    def repair(*_args: object, **_kwargs: object) -> object:
        nonlocal repair_calls
        repair_calls += 1
        return _attempt_workflow("first.json", candidates=1, rounds=1)

    with pytest.raises(subject.RepairAttemptFailure) as raised:
        subject.execute_repair_attempt(
            argparse.Namespace(donor_candidates=10, adjustment_rounds=5),
            cast(Any, object()),
            snapshot=cast(Any, snapshot),
            selected_paths=(),
            cache_root=tmp_path / "cache",
            candidate_report_directory="candidate-report",
            final_report_directory="final-report",
            report_preimages=(),
            keep=subject.KeepWorkspace.NEVER,
            verify_command=lambda *_args: 1,
            repair_records=cast(Any, repair),
        )

    assert isinstance(raised.value.error, subject.RepairError)
    assert repair_calls == 1
    assert len(calls["collects"]) == 1
    assert calls["publishes"] == []


def test_attempt_requires_real_source_progress_before_rechecking_cold_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = SimpleNamespace(
        verdict=SimpleNamespace(cold=True, logic_certified=True, byte_exact=False),
        targets=(SimpleNamespace(id="program", byte_exact=False),),
    )
    snapshot, calls = _wire_attempt(tmp_path, monkeypatch, report=report)
    workflows = iter(
        (
            _attempt_workflow("first.json", candidates=1, rounds=1),
            _attempt_workflow("unchanged.json", candidates=0, rounds=0),
        )
    )
    verifies = 0

    def verify(*_args: object) -> int:
        nonlocal verifies
        verifies += 1
        return 1

    with pytest.raises(subject.RepairAttemptFailure, match="no safe automatic source adjustment"):
        subject.execute_repair_attempt(
            argparse.Namespace(donor_candidates=10, adjustment_rounds=5),
            cast(Any, object()),
            snapshot=cast(Any, snapshot),
            selected_paths=(),
            cache_root=tmp_path / "cache",
            candidate_report_directory="candidate-report",
            final_report_directory="final-report",
            report_preimages=(),
            keep=subject.KeepWorkspace.NEVER,
            verify_command=verify,
            repair_records=cast(Any, lambda *_args, **_kwargs: next(workflows)),
        )

    assert verifies == 1
    assert len(calls["collects"]) == 1
    assert calls["publishes"] == []
