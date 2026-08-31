from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import reprobit.repair_workflow as subject
from reprobit.classic.redundant_action_repair import RedundantActionRepairError
from reprobit.schema import ClassicRecipeRole


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
) -> subject.RepairWorkflowResult:
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
    monkeypatch.setattr(
        subject,
        "analyze_classic_repair",
        lambda *_args, **_kwargs: analyses.pop(0),
    )
    return subject.repair_classic_records(
        argparse.Namespace(project=str(tmp_path)),
        cast(Any, object()),
        staged_root=tmp_path,
        spec=cast(Any, object()),
        cache_root=tmp_path / "state",
    )


def test_workflow_persists_measured_repairs_then_requires_a_clean_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repair = SimpleNamespace(unit_id="tu.one")
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
    )

    assert result.changed_records == ("reprobit/proofs/one.json",)
    assert result.affected_units == ("tu.one",)
    assert result.measured_checks == 1
    assert result.passes == 2


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
    monkeypatch.setattr(subject, "plan_redundant_action_retirement", lambda *_args: plan)
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
    monkeypatch.setattr(subject, "plan_redundant_action_retirement", lambda *_args: plan)
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
    refusal = SimpleNamespace(
        unit_id="tu.shared",
        intervention=SimpleNamespace(role=ClassicRecipeRole.FUNCTION, dependencies=("donor",)),
        receipt=object(),
        materials=object(),
        reason="donor declaration shape moved",
    )
    monkeypatch.setattr(
        subject,
        "plan_redundant_action_retirement",
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
    )

    assert result.donor_retunes == 1
    assert result.compiled_candidates == 7
    assert result.affected_units == ("tu.shared",)
    assert result.passes == 2


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
        "plan_redundant_action_retirement",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    budgets: list[int] = []

    def probe(
        *_args: object,
        candidate_budget: int,
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

    with pytest.raises(subject.RepairWorkflowError, match="command-wide budget of 256"):
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
        "plan_redundant_action_retirement",
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


def test_workflow_reports_a_plain_bounded_failure(
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
        "plan_redundant_action_retirement",
        lambda *_args: (_ for _ in ()).throw(RedundantActionRepairError("not redundant")),
    )
    monkeypatch.setattr(
        subject,
        "probe_classic_donor_repairs",
        lambda *_args, **_kwargs: SimpleNamespace(
            repairs=(),
            refusals=(SimpleNamespace(reason="no nearby donor setting worked"),),
            compiled_candidates=8,
        ),
    )

    with pytest.raises(subject.RepairWorkflowError, match="bounded, ordinarily validated"):
        _run(
            tmp_path,
            monkeypatch,
            [_analysis(completed=False, refusals=(refusal,))],
        )


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


def test_workflow_has_a_small_explicit_pass_ceiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repair = SimpleNamespace(unit_id="tu.one")
    analyses = [
        _analysis(completed=True, measured=(repair,)) for _ in range(subject.MAX_REPAIR_PASSES)
    ]
    monkeypatch.setattr(
        subject,
        "apply_classic_receipt_repairs",
        lambda *_args: ("reprobit/proofs/one.json",),
    )

    with pytest.raises(subject.RepairWorkflowError, match="after 24 bounded passes"):
        _run(tmp_path, monkeypatch, analyses)

    assert analyses == []
