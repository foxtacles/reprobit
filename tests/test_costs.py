from __future__ import annotations

import pytest

from reprobit.costs import (
    CostClass,
    CostModelV1,
    CostModelV2,
    CostUnitKind,
    calculate_cost,
)
from reprobit.model import Scope
from reprobit.schema import (
    ClassicField,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    LinkOrderingIntervention,
    SemanticRewriteIntervention,
    SemanticRewriteMethod,
    StateCarrierIntervention,
)


def test_cost_model_weights_are_fixed() -> None:
    assert CostModelV1.version == 1
    assert CostModelV2.version == 2
    assert CostModelV1.weights[CostClass.STATE_CARRIER] == 1
    assert CostModelV1.weights[CostClass.ORACLE_INSTALL] == 10_000
    with pytest.raises(TypeError):
        CostModelV1.weights[CostClass.STATE_CARRIER] = 0  # type: ignore[index]


def test_calculate_cost_counts_unique_nodes_once_and_allocates_shared_rationally() -> None:
    first = Scope(target="program", translation_unit="main", function="first()")
    second = Scope(target="program", translation_unit="main", function="second()")
    direct = SemanticRewriteIntervention(
        id="rewrite-first",
        scope=first,
        rationale="certified instruction form",
        method=SemanticRewriteMethod.INSTRUCTION_FORM,
        source_artifact="donor-object",
        rewrite_digest={"value": "0" * 64},
    )
    shared = LinkOrderingIntervention(
        id="library-order",
        scope=Scope(target="program"),
        rationale="preserve member order",
        item_ids=("one", "two"),
        beneficiaries=(first, second),
    )
    unallocated = StateCarrierIntervention(
        id="state",
        scope=Scope(target="program", translation_unit="main"),
        rationale="preserve compiler state",
        carrier="declaration",
    )
    result = calculate_cost((direct, shared, unallocated, direct))
    assert result.project_total == 261
    assert result.unallocated_shared_cost == 1
    assert [item.intervention_id for item in result.interventions] == [
        "library-order",
        "rewrite-first",
        "state",
    ]
    by_function = {item.scope.function: item for item in result.by_function}
    assert by_function["first()"].direct_cost == 250
    assert by_function["first()"].allocated_shared_cost.numerator == 5
    assert by_function["first()"].exposure_cost == 10
    assert by_function["second()"].allocated_shared_cost.numerator == 5


def test_conflicting_duplicate_intervention_id_is_rejected() -> None:
    one = StateCarrierIntervention(
        id="same",
        scope=Scope(target="program"),
        rationale="one",
        carrier="first",
    )
    two = StateCarrierIntervention(
        id="same",
        scope=Scope(target="program"),
        rationale="two",
        carrier="second",
    )
    with pytest.raises(ValueError, match="conflicting"):
        calculate_cost((one, two))


def test_cost_beneficiaries_are_canonical_function_scopes_in_one_authority() -> None:
    function = Scope(target="program", translation_unit="main", function="work()")
    with pytest.raises(ValueError, match="must name a function"):
        LinkOrderingIntervention(
            id="invalid-target-beneficiary",
            scope=Scope(target="program"),
            rationale="invalid allocation fixture",
            item_ids=("one", "two"),
            beneficiaries=(Scope(target="program"),),
        )
    with pytest.raises(ValueError, match="within the intervention target"):
        LinkOrderingIntervention(
            id="invalid-cross-target-beneficiary",
            scope=Scope(target="program"),
            rationale="invalid allocation fixture",
            item_ids=("one", "two"),
            beneficiaries=(Scope(target="other", translation_unit="main", function="work()"),),
        )
    with pytest.raises(ValueError, match="unique and canonically ordered"):
        LinkOrderingIntervention(
            id="invalid-duplicate-beneficiary",
            scope=Scope(target="program"),
            rationale="invalid allocation fixture",
            item_ids=("one", "two"),
            beneficiaries=(function, function),
        )


def _source_overlay(
    identifier: str,
    *,
    edits: int,
    generated_translation_units: int = 0,
    link_admissions: int = 0,
) -> ClassicRecipeIntervention:
    outputs = [
        {
            "path": "src/unit.cpp",
            "ops": [{"op": "insert", "ordinal": index} for index in range(edits)],
        }
    ]
    graph = {
        "generated_tus": [
            {"path": f"generated/unit-{index}.cpp"} for index in range(generated_translation_units)
        ],
        "link_admissions": [{"archive": f"archive-{index}"} for index in range(link_admissions)],
    }
    return ClassicRecipeIntervention(
        id=identifier,
        scope=Scope(target="program"),
        rationale="typed source-overlay work",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="app",
        parameters=(
            ClassicField(name="graph", value=graph),
            ClassicField(name="outputs", value=outputs),
            ClassicField(name="schema", value=2),
        ),
    )


def test_source_overlay_cost_uses_typed_units_so_bundling_cannot_lower_it() -> None:
    bundled = calculate_cost((_source_overlay("overlay.bundled", edits=2),))
    split = calculate_cost(
        (
            _source_overlay("overlay.first", edits=1),
            _source_overlay("overlay.second", edits=1),
        )
    )

    assert bundled.model_version == 2
    assert bundled.project_total == split.project_total == 200
    assert bundled.interventions[0].units[0].kind is CostUnitKind.SOURCE_OVERLAY_EDIT
    assert bundled.interventions[0].units[0].count == 2
    assert bundled.by_class[0].units == split.by_class[0].units == 2


def test_source_overlay_graph_actions_are_separate_typed_units() -> None:
    result = calculate_cost(
        (
            _source_overlay(
                "overlay.graph",
                edits=1,
                generated_translation_units=1,
                link_admissions=1,
            ),
        )
    )

    assert result.project_total == 300
    assert [(unit.kind, unit.count, unit.cost) for unit in result.interventions[0].units] == [
        (CostUnitKind.SOURCE_OVERLAY_EDIT, 1, 100),
        (CostUnitKind.GENERATED_TRANSLATION_UNIT, 1, 100),
        (CostUnitKind.LINK_ADMISSION, 1, 100),
    ]
    assert result.by_target[0].units == 3
