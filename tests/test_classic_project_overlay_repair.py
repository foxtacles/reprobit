from __future__ import annotations

from dataclasses import dataclass, replace
from types import SimpleNamespace
from typing import Any, cast

import pytest

from reprobit.artifacts import digest_bytes
from reprobit.classic.coff_evidence import _CoffObject, _CoffSection, _CoffSymbol
from reprobit.classic.overlay_document import render_classic_overlay_proposal
from reprobit.classic.overlay_tokens import ClassicOverlayRenderSession
from reprobit.classic.semantic_contracts import (
    CompilerEpochInvocation,
    ProjectOverlayCompilerEpochPlan,
    ProjectOverlayCounterfactualAudit,
    ProjectOverlaySourcePair,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic_link_layout_repair import ClassicLinkLayoutHint
from reprobit.classic_project_overlay_repair import (
    ClassicProjectOverlayRepairError,
    _candidate_plan_reduction,
    _epoch_compiler_outputs,
    _flat_inert_knob,
    _link_layout_object_state,
    _raw_candidates,
    _RawCandidate,
    _retained_pair_regressed,
    _with_candidate_output,
    probe_project_overlay_repair,
)
from reprobit.classic_source_regeneration import (
    _ClassicRegenerationContext,
    _refresh_source_overlays,
)
from reprobit.model import Digest, Scope
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole
from reprobit.schema import (
    ClassicField,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)


def _mixed_operations() -> list[dict[str, object]]:
    return [
        {
            "op": "insert",
            "anchor": {"at": "end", "ctx": "0" * 64, "a": 0},
            "gen": {
                "k": "seq",
                "lines": 11,
                "items": [
                    {
                        "arguments": [{"kind": "integer", "value": 0}],
                        "at": [4, 5, 6, 7, 8, 9],
                        "k": "member_probe",
                        "line": 2,
                        "lines": 10,
                        "function_identifier": "Probe",
                        "inline_depth": 0,
                        "qualified_member": ["Thing", "Method"],
                        "receiver_type": "Thing",
                        "return_type": "int",
                    },
                    {"k": "empty_class", "line": 11, "id": "Unused010"},
                ],
            },
        }
    ]


def test_link_layout_object_state_refuses_code_comdats() -> None:
    section = _CoffSection(
        1,
        ".text",
        b"body",
        0x60001020,
        (),
        (),
        2,
        0,
    )
    symbol = _CoffSymbol(0, "?first@@", 0, 1, 0, 2, 0, b"")
    coff = _CoffObject(
        "fixture",
        Digest.from_bytes(b"coff"),
        0,
        (section,),
        (symbol,),
    )

    with pytest.raises(ClassicSemanticError, match="not an independent COMDAT"):
        _link_layout_object_state(
            coff,
            ClassicLinkLayoutHint("compiler.program.0000", ("?first@@", "?second@@")),
        )


def test_candidate_neighborhood_adds_one_fresh_inert_tail_without_touching_helper() -> None:
    operations = _mixed_operations()
    identifiers = frozenset(f"Unused{index:03d}" for index in range(19))

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 1)}),
        identifiers=identifiers,
        radius=1,
        limit=8,
    )

    added = next(item for item in candidates if item.description.startswith("added Unused019 "))
    sequence = cast(dict[str, object], added.operations[0]["gen"])
    items = cast(list[dict[str, object]], sequence["items"])
    original_sequence = cast(dict[str, object], operations[0]["gen"])
    original_items = cast(list[dict[str, object]], original_sequence["items"])
    assert items[0] == original_items[0]
    assert items[-1] == {"id": "Unused019", "k": "empty_class", "line": 12}
    assert sequence["lines"] == 12
    assert ("src/unit.cpp#0", 2) in added.selected_leaf_keys
    assert added.description == "added Unused019 to layout 1"


def test_candidate_neighborhood_can_seed_a_sequence_with_no_selected_inert_tail() -> None:
    operations = _mixed_operations()
    sequence = cast(dict[str, object], operations[0]["gen"])
    sequence["items"] = cast(list[object], sequence["items"])[:1]
    sequence["lines"] = 10

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset(),
        identifiers=frozenset(),
        radius=2,
        limit=16,
    )

    added = next(
        item for item in candidates if item.description.startswith("added ReprobitUnusedClass000 ")
    )
    assert added.selected_leaf_keys == frozenset({("src/unit.cpp#0", 1)})
    two_added = next(
        item for item in candidates if item.description.startswith("added 2 inert declarations ")
    )
    added_sequence = cast(dict[str, object], two_added.operations[0]["gen"])
    added_items = cast(list[dict[str, object]], added_sequence["items"])
    assert added_items[-2:] == [
        {"id": "ReprobitUnusedClass000", "k": "empty_class", "line": 11},
        {"id": "ReprobitUnusedClass001", "k": "empty_class", "line": 12},
    ]
    assert added_sequence["lines"] == 12
    assert two_added.selected_leaf_keys == frozenset({("src/unit.cpp#0", 1), ("src/unit.cpp#0", 2)})


def test_candidate_neighborhood_extends_a_forward_declaration_family() -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 5,
                "items": [
                    {"k": "lines", "line": 1, "n": 1},
                    {"k": "fwd", "id": "SpareAY", "line": 2, "tag": "struct"},
                ],
            },
        }
    ]
    occupied = frozenset(
        f"Spare{first}{second}"
        for first in "ABCDEFG"
        for second in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        if f"{first}{second}" <= "GX"
    )

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 0), ("src/unit.cpp#0", 1)}),
        identifiers=occupied,
        radius=2,
        limit=16,
    )

    added = next(
        candidate
        for candidate in candidates
        if candidate.description.startswith("added 2 inert declarations")
    )
    sequence = cast(dict[str, object], added.operations[0]["gen"])
    items = cast(list[dict[str, object]], sequence["items"])
    assert items[-2:] == [
        {"id": "SpareGY", "k": "fwd", "line": 3, "tag": "struct"},
        {"id": "SpareGZ", "k": "fwd", "line": 4, "tag": "struct"},
    ]
    assert sequence["lines"] == 7


@pytest.mark.parametrize(
    ("existing", "fresh"),
    (("SpareA", "SpareB"), ("SpareAAAAA", "SpareAAAAB")),
)
def test_candidate_neighborhood_accepts_any_fixed_width_forward_family(
    existing: str,
    fresh: str,
) -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 5,
                "items": [
                    {"k": "fwd", "id": existing, "line": 2, "tag": "class"},
                ],
            },
        }
    ]

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 0)}),
        identifiers=frozenset({existing}),
        radius=1,
        limit=8,
    )

    added = next(
        candidate for candidate in candidates if candidate.description.startswith(f"added {fresh} ")
    )
    sequence = cast(dict[str, object], added.operations[0]["gen"])
    items = cast(list[dict[str, object]], sequence["items"])
    assert items[-1] == {"id": fresh, "k": "fwd", "line": 3, "tag": "class"}
    assert sequence["lines"] == 6


def test_candidate_neighborhood_refuses_an_ambiguous_forward_family() -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 2,
                "items": [
                    {"k": "fwd", "id": "FirstAA", "line": 1},
                    {"k": "fwd", "id": "SecondAA", "line": 2},
                ],
            },
        }
    ]

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 0), ("src/unit.cpp#0", 1)}),
        identifiers=frozenset({"FirstAA", "SecondAA"}),
        radius=1,
        limit=8,
    )

    assert not any(candidate.description.startswith("added ") for candidate in candidates)


def test_candidate_neighborhood_reuses_an_owning_output_identifier_family() -> None:
    operations = _mixed_operations()
    mixed = cast(dict[str, object], operations[0]["gen"])
    mixed["items"] = cast(list[object], mixed["items"])[:1]
    mixed["lines"] = 10
    operations.insert(
        0,
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "1" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 1,
                "items": [{"k": "empty_class", "id": "MxUnusedRecord010", "line": 1}],
            },
        },
    )

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset(),
        identifiers=frozenset(f"MxUnusedRecord{index:03d}" for index in range(19)),
        radius=1,
        limit=8,
    )

    def second_operation_item_count(candidate: _RawCandidate) -> int:
        generator = cast(dict[str, object], candidate.operations[1]["gen"])
        return len(cast(list[object], generator["items"]))

    candidate = next(item for item in candidates if second_operation_item_count(item) == 2)
    sequence = cast(dict[str, object], candidate.operations[1]["gen"])
    assert cast(list[dict[str, object]], sequence["items"])[-1]["id"] == ("MxUnusedRecord019")


def test_candidate_neighborhood_reuses_only_closed_family_identifiers() -> None:
    operations = _mixed_operations()
    identifiers = frozenset(f"Unused{index:03d}" for index in range(21))

    reusable = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 1)}),
        identifiers=identifiers,
        reusable_identifiers=frozenset({"Unused009", "Unused011", "Unused019"}),
        radius=1,
        limit=8,
    )
    assert any(item.description.startswith("added Unused009 ") for item in reusable)
    assert any(item.description.startswith("added Unused019 ") for item in reusable)

    fresh_only = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 1)}),
        identifiers=identifiers,
        reusable_identifiers=frozenset(),
        radius=1,
        limit=8,
    )
    assert any(item.description.startswith("added Unused021 ") for item in fresh_only)
    assert not any(item.description.startswith("added Unused019 ") for item in fresh_only)


def test_candidate_neighborhood_keeps_identifier_families_local_to_each_sequence() -> None:
    operations = [
        {
            "id": "family-a",
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 1,
                "items": [{"k": "empty_class", "id": "FamilyA010", "line": 1}],
            },
        },
        {
            "id": "family-b",
            "op": "insert",
            "anchor": {"at": "end", "ctx": "1" * 64, "a": 0},
            "gen": {
                "k": "seq",
                "lines": 1,
                "items": [{"k": "empty_class", "id": "FamilyB010", "line": 1}],
            },
        },
    ]

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("family-a", 0), ("family-b", 0)}),
        identifiers=frozenset({"FamilyA010", "FamilyA011", "FamilyB010", "FamilyB011"}),
        reusable_identifiers=frozenset({"FamilyA011", "FamilyB011"}),
        radius=1,
        limit=8,
    )

    assert any(item.description == "added FamilyA011 to family-a" for item in candidates)
    assert any(item.description == "added FamilyB011 to family-b" for item in candidates)


def test_candidate_neighborhood_interleaves_additions_knobs_and_removals() -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 2,
                "items": [
                    {"k": "fwd_run", "line": 1, "stem": "Forward", "first": 0, "count": 1},
                    {"k": "empty_class", "id": "Unused010", "line": 2},
                ],
            },
        }
    ]

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 0), ("src/unit.cpp#0", 1)}),
        identifiers=frozenset({"Unused010", "Unused011", "Unused012"}),
        reusable_identifiers=frozenset({"Unused011", "Unused012"}),
        radius=1,
        limit=4,
    )

    assert len(candidates) == 4
    assert candidates[0].description.startswith("added ")
    assert candidates[1].description.startswith("adjusted ")
    assert candidates[3].description == "removed 1 inert declaration from layout 1"


def test_unselected_inert_knob_is_available_but_helper_knob_is_not() -> None:
    operations = _mixed_operations()
    sequence = cast(dict[str, object], operations[0]["gen"])
    items = cast(list[dict[str, object]], sequence["items"])
    items.append({"k": "fwd_run", "line": 12, "stem": "Forward", "first": 0, "count": 1})
    sequence["lines"] = 12

    assert _flat_inert_knob(operations, 0, 2) is True
    assert _flat_inert_knob(operations, 0, 0) is False

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset(),
        identifiers=frozenset({"Unused010", "Unused011"}),
        radius=1,
        limit=8,
    )
    assert any(
        candidate.description == "adjusted declaration count by +1 in layout 1"
        for candidate in candidates
    )


def test_source_knob_move_preserves_existing_trailing_canvas_slack() -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 7,
                "items": [
                    {"k": "fwd_run", "line": 1, "stem": "Forward", "first": 0, "count": 4},
                    {"k": "empty_class", "id": "Unused010", "line": 5},
                ],
            },
        }
    ]

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 0), ("src/unit.cpp#0", 1)}),
        identifiers=frozenset({"Unused010"}),
        radius=2,
        limit=16,
    )

    grown = next(
        candidate
        for candidate in candidates
        if candidate.description == "adjusted declaration count by +2 in layout 1"
    )
    sequence = cast(dict[str, object], grown.operations[0]["gen"])
    items = cast(list[dict[str, object]], sequence["items"])
    assert items[0]["count"] == 6
    assert items[1]["line"] == 7
    assert sequence["lines"] == 9


def test_source_candidate_names_padding_and_member_counts() -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 7,
                "items": [
                    {
                        "k": "class",
                        "line": 1,
                        "id": "Unused010",
                        "inline": True,
                        "members": [{"count": 2, "first": 0, "stem": "Member"}],
                    },
                    {"k": "lines", "line": 5, "n": 2},
                ],
            },
        }
    ]

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 0), ("src/unit.cpp#0", 1)}),
        identifiers=frozenset({"Unused010"}),
        radius=1,
        limit=16,
    )
    descriptions = {candidate.description for candidate in candidates}
    assert "adjusted class member count by +1 in layout 1" in descriptions
    assert "adjusted blank-line count by +1 in layout 1" in descriptions


def test_retained_pair_regression_preserves_projection_and_raw_code_equality() -> None:
    def pair(*, projection_equal: bool, changed_code: int) -> object:
        return SimpleNamespace(
            projection=SimpleNamespace(byte_equal=projection_equal),
            coff_trace={"changed_code_section_count": changed_code},
        )

    exact_projection = pair(projection_equal=True, changed_code=1)
    moved_projection = pair(projection_equal=False, changed_code=1)
    assert _retained_pair_regressed(  # type: ignore[arg-type]
        exact_projection,
        moved_projection,
    )

    exact_code = pair(projection_equal=False, changed_code=0)
    moved_code = pair(projection_equal=False, changed_code=1)
    assert _retained_pair_regressed(exact_code, moved_code)  # type: ignore[arg-type]
    assert not _retained_pair_regressed(exact_code, exact_code)  # type: ignore[arg-type]


def test_candidate_neighborhood_does_not_invent_cpp_declarations_in_c_source() -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 2,
                "items": [
                    {"k": "fwd_run", "line": 1, "stem": "Forward", "first": 0, "count": 1},
                    {"k": "empty_class", "id": "Unused010", "line": 2},
                ],
            },
        }
    ]
    candidates = _raw_candidates(
        path="src/unit.c",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.c#0", 0), ("src/unit.c#0", 1)}),
        identifiers=frozenset({"Unused010", "Unused011"}),
        radius=1,
        limit=8,
    )

    assert candidates
    assert not any(candidate.description.startswith("added ") for candidate in candidates)
    assert any(candidate.description.startswith("adjusted ") for candidate in candidates)
    assert any(candidate.description.startswith("removed ") for candidate in candidates)


def test_candidate_neighborhood_can_remove_an_unselected_inert_tail() -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 5,
                "items": [
                    {"k": "lines", "n": 1, "line": 1},
                    {"k": "empty_class", "id": "Unused010", "line": 2},
                    {"k": "empty_class", "id": "Unused011", "line": 3},
                    {"k": "empty_class", "id": "Unused012", "line": 4},
                ],
            },
        }
    ]

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 0)}),
        identifiers=frozenset({"Unused010", "Unused011", "Unused012"}),
        radius=3,
        limit=32,
    )

    removed = next(
        item
        for item in candidates
        if item.description == "removed 3 inert declarations from layout 1"
        and len(cast(dict[str, object], item.operations[0]["gen"])["items"]) == 1
    )
    assert removed.selected_leaf_keys == frozenset({("src/unit.cpp#0", 0)})
    assert cast(dict[str, object], removed.operations[0]["gen"])["lines"] == 2


def test_candidate_plan_reduction_is_limited_to_settled_affected_readers() -> None:
    baseline = ProjectOverlayCompilerEpochPlan(
        {"src/unit.cpp": b"declaration"},
        frozenset({"compiler.a", "compiler.b"}),
        frozenset({"compiler.a"}),
        {},
    )
    reduced = replace(
        baseline,
        declaration_outputs={"src/unit.cpp": b"settled"},
        audit_node_ids=frozenset({"compiler.b"}),
        runtime_projection_node_ids=frozenset(),
    )
    common = {
        "baseline_generated_tus": frozenset(),
        "candidate_generated_tus": frozenset(),
        "source_path": "src/unit.cpp",
        "effective_outputs": {"src/unit.cpp": b"settled"},
        "counterfactual_outputs": {"src/unit.cpp": b"settled"},
    }

    assert _candidate_plan_reduction(
        baseline,
        reduced,
        affected_node_ids=("compiler.a",),
        **common,
    ) == frozenset({"compiler.a"})
    assert (
        _candidate_plan_reduction(
            baseline,
            replace(reduced, audit_node_ids=frozenset({"compiler.b", "compiler.c"})),
            affected_node_ids=("compiler.a", "compiler.c"),
            **common,
        )
        is None
    )
    assert (
        _candidate_plan_reduction(
            baseline,
            reduced,
            affected_node_ids=("compiler.b",),
            **common,
        )
        is None
    )
    assert (
        _candidate_plan_reduction(
            baseline,
            reduced,
            affected_node_ids=("compiler.a",),
            **{
                **common,
                "counterfactual_outputs": {"src/unit.cpp": b"different"},
            },
        )
        is None
    )
    assert (
        _candidate_plan_reduction(
            baseline,
            replace(reduced, runtime_projection_node_ids=frozenset({"compiler.a"})),
            affected_node_ids=("compiler.a",),
            **common,
        )
        is None
    )


def test_candidate_neighborhood_cannot_hide_a_later_knob_distance() -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 2,
                "items": [
                    {"k": "fwd_run", "line": 1, "stem": "Forward", "first": 0, "count": 3},
                    {"k": "empty_class", "id": "Unused300", "line": 2},
                ],
            },
        }
    ]
    reusable = frozenset(f"Unused{index:03d}" for index in range(300))

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 0), ("src/unit.cpp#0", 1)}),
        identifiers=reusable | {"Unused300"},
        reusable_identifiers=reusable,
        radius=3,
        limit=64,
    )

    assert any(
        item.description == "adjusted declaration count by +3 in layout 1" for item in candidates
    )


def test_candidate_neighborhood_keeps_a_later_identifier_across_multiple_layouts() -> None:
    operations: list[dict[str, object]] = []
    selected: set[tuple[str, int]] = set()
    local_identifiers: set[str] = set()
    for operation_index in range(3):
        first_identifier = 10 + operation_index * 3
        empty_classes = [
            {
                "k": "empty_class",
                "id": f"Unused{first_identifier + offset:03d}",
                "line": 4 + offset,
            }
            for offset in range(3)
        ]
        local_identifiers.update(cast(str, item["id"]) for item in empty_classes)
        operations.append(
            {
                "op": "insert",
                "anchor": {
                    "at": "start",
                    "ctx": str(operation_index) * 64,
                    "b": 0,
                },
                "gen": {
                    "k": "seq",
                    "lines": 6,
                    "items": [
                        {
                            "k": "fwd_run",
                            "line": 1,
                            "stem": f"Forward{operation_index}",
                            "first": 0,
                            "count": 3,
                        },
                        *empty_classes,
                    ],
                },
            }
        )
        selected.update(
            (f"src/unit.cpp#{operation_index}", leaf_index)
            for leaf_index in range(4)
            if operation_index != 2 or leaf_index != 0
        )
    reusable = frozenset(f"Unused{index:03d}" for index in range(19, 32))

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset(selected),
        identifiers=frozenset(local_identifiers) | reusable,
        reusable_identifiers=reusable,
        radius=3,
        limit=64,
    )

    assert any(item.description == "added Unused027 to layout 3" for item in candidates)
    assert any(
        item.description.startswith("adjusted declaration count by +3 in layout ")
        for item in candidates
    )


def _invocation(namespace_id: str) -> CompilerEpochInvocation:
    return CompilerEpochInvocation(
        "compiler",
        Digest.from_bytes(b"compiler"),
        ("/c",),
        r"R:\build",
        Digest.from_bytes(b"environment"),
        Digest.from_bytes(b"paths"),
        Digest.from_bytes(f"invocation:{namespace_id}".encode()),
        namespace_id,
        Digest.from_bytes(f"namespace:{namespace_id}".encode()),
        1,
    )


def test_epoch_compiler_outputs_rejects_a_swapped_namespace() -> None:
    epoch = SimpleNamespace(
        namespace=SimpleNamespace(namespace_id="effective"),
        compiler_outputs=(
            SimpleNamespace(
                node_id="compiler.program.0000",
                compiler_invocation=_invocation("counterfactual"),
            ),
        ),
    )

    with pytest.raises(ClassicSemanticError, match="wrong source epoch"):
        _epoch_compiler_outputs(cast(Any, epoch))


def test_candidate_neighborhood_moves_selected_and_unselected_inert_knobs() -> None:
    operations = [
        {
            "op": "insert",
            "anchor": {"at": "start", "ctx": "0" * 64, "b": 0},
            "gen": {
                "k": "seq",
                "lines": 5,
                "items": [
                    {"k": "fwd_run", "line": 1, "stem": "A", "first": 0, "count": 2},
                    {"k": "fwd_run", "line": 3, "stem": "B", "first": 0, "count": 2},
                ],
            },
        }
    ]

    candidates = _raw_candidates(
        path="src/unit.cpp",
        operations=operations,
        selected_leaf_keys=frozenset({("src/unit.cpp#0", 1)}),
        identifiers=frozenset(),
        radius=1,
        limit=8,
    )

    moved = [item for item in candidates if item.description.startswith("adjusted")]
    assert moved
    count_pairs = {
        tuple(
            cast(int, item["count"])
            for item in cast(
                list[dict[str, object]],
                cast(dict[str, object], candidate.operations[0]["gen"])["items"],
            )
        )
        for candidate in moved
    }
    assert count_pairs == {(1, 2), (2, 1), (2, 3), (3, 2)}


@dataclass(frozen=True)
class _Document:
    interventions: tuple[ClassicRecipeIntervention, ...]

    def model_copy(self, *, update: dict[str, object]) -> _Document:
        return replace(
            self,
            interventions=cast(tuple[ClassicRecipeIntervention, ...], update["interventions"]),
        )


@dataclass(frozen=True)
class _Bundle:
    intervention_documents: tuple[_Document, ...]

    def model_copy(self, *, update: dict[str, object]) -> _Bundle:
        return replace(
            self,
            intervention_documents=cast(tuple[_Document, ...], update["intervention_documents"]),
        )


class _Reader:
    def __init__(self, source: bytes) -> None:
        self.source = source

    def read(self, relative: str, *, wanted_by: str) -> bytes:
        assert relative == "src/unit.cpp"
        return self.source

    def read_clean_preimage(self, relative: str, *, expected_sha256: str) -> bytes | None:
        assert relative == "src/unit.cpp"
        return self.source if digest_bytes(self.source) == expected_sha256 else None


def _overlay_intervention(
    source: bytes,
    *,
    path: str = "src/unit.cpp",
    intervention_id: str = "project.fixture",
) -> ClassicRecipeIntervention:
    operations = [
        {
            "id": "op_layout",
            "op": "insert",
            "anchor": {
                "ctx": digest_bytes(b"<SEAT>\0int\0value\0;"),
                "b": 0,
                "a": 3,
                "at": "start",
            },
            "gen": {
                "k": "seq",
                "lines": 1,
                "items": [{"k": "empty_class", "id": "Unused000", "line": 1}],
            },
        }
    ]
    declaration = {
        "path": path,
        "clean": digest_bytes(source),
        "effective": "0" * 64,
        "size": 0,
        "ops": operations,
    }
    rendered = render_classic_overlay_proposal([declaration], {path: source})
    declaration["effective"] = rendered.receipts[0].output_digest
    declaration["size"] = rendered.receipts[0].output_size
    values = {
        "schema": 2,
        "outputs": [declaration],
        "graph": {"generated_tus": [], "link_admissions": []},
    }
    return ClassicRecipeIntervention(
        id=intervention_id,
        scope=Scope(target="program"),
        rationale="Render one source overlay.",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="program",
        parameters=tuple(
            ClassicField(name=name, value=value)  # type: ignore[arg-type]
            for name, value in sorted(values.items())
        ),
    )


def _parameter(intervention: ClassicRecipeIntervention, name: str) -> object:
    return next(field.value for field in intervention.parameters if field.name == name)


def test_candidate_publication_keeps_stale_pins_for_normal_regeneration() -> None:
    source = b"int value;\n"
    intervention = _overlay_intervention(source)
    original_output = cast(list[dict[str, object]], _parameter(intervention, "outputs"))[0]
    operations = cast(list[dict[str, object]], original_output["ops"])
    changed_operations = [dict(operations[0])]
    changed_generator = dict(cast(dict[str, object], operations[0]["gen"]))
    changed_generator["items"] = [
        *cast(list[object], changed_generator["items"]),
        {"k": "empty_class", "id": "Unused001", "line": 2},
    ]
    changed_generator["lines"] = 2
    changed_operations[0]["gen"] = changed_generator
    bundle = _Bundle((_Document((intervention,)),))

    with ClassicOverlayRenderSession() as session:
        edit, proven_bundle, payload = _with_candidate_output(
            cast(object, bundle),  # type: ignore[arg-type]
            intervention,
            path="src/unit.cpp",
            operations=changed_operations,
            clean_payload=source,
            session=session,
        )

    published_output = cast(list[dict[str, object]], _parameter(edit.after, "outputs"))[0]
    proven_intervention = cast(
        ClassicRecipeIntervention,
        proven_bundle.intervention_documents[0].interventions[0],
    )
    proven_output = cast(list[dict[str, object]], _parameter(proven_intervention, "outputs"))[0]
    assert published_output["effective"] == original_output["effective"]
    assert published_output["size"] == original_output["size"]
    assert proven_output["effective"] == digest_bytes(payload)
    assert proven_output["effective"] != original_output["effective"]

    raw_overlay = edit.after.model_dump(mode="json", warnings=False)
    context = _ClassicRegenerationContext(
        documents={"tu.json": {"interventions": [raw_overlay]}},
        plan_relative="reprobit/build-plan.json",
        reader=_Reader(source),
        error_type=ValueError,
    )
    _refresh_source_overlays(context)

    refreshed_output = cast(
        list[dict[str, object]],
        next(item["value"] for item in raw_overlay["parameters"] if item["name"] == "outputs"),
    )[0]
    assert refreshed_output["effective"] == proven_output["effective"]
    assert refreshed_output["size"] == proven_output["size"]
    assert context.stale_paths == {"src/unit.cpp": original_output["clean"]}


def test_project_overlay_probe_coordinates_header_owners_and_proof_gates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = b"int value;\n"
    first_path = "include/layout.inc"
    second_path = "include/layout.inl"
    first_overlay = _overlay_intervention(
        source,
        path=first_path,
        intervention_id="project.first",
    )
    second_overlay = _overlay_intervention(
        source,
        path=second_path,
        intervention_id="project.second",
    )
    nodes = tuple(
        ProducerNode(
            id=f"compiler.program.000{index}",
            role=ProducerRole.COMPILER,
            owner="program",
            arguments=("/c", f"${{SOURCE}}/src/unit{index}.cpp"),
            inputs=(f"source/src/unit{index}.cpp",),
            outputs=(f"build/unit{index}.obj", f"build/unit{index}.pdb"),
        )
        for index in range(2)
    )
    graph = ProducerGraphDocument(
        schema_version=3,
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-makefiles-v1",
        nodes=nodes,
    )
    leaf_keys = {
        first_overlay.id: (("op_layout", 0),),
        second_overlay.id: (("op_layout", 0),),
    }
    baseline_declarations = {
        first_path: b"counterfactual:first",
        second_path: b"counterfactual:second",
    }
    plan = ProjectOverlayCompilerEpochPlan(
        baseline_declarations,
        frozenset(node.id for node in nodes),
        frozenset(node.id for node in nodes),
        leaf_keys,
    )
    validation = SimpleNamespace(
        compiler_epoch_plan=plan,
        macro_sensitive_identifiers=frozenset(),
        global_declaration_identifiers=frozenset(),
    )
    bundle = SimpleNamespace(interventions=(first_overlay, second_overlay))
    source_pairs = (
        ProjectOverlaySourcePair(first_path, source, b"effective:first"),
        ProjectOverlaySourcePair(second_path, source, b"effective:second"),
    )
    epoch_ids: list[str] = []
    epoch_nodes: list[tuple[str, ...]] = []
    prepared_descriptions: list[str] = []
    pair_orientations: list[tuple[bytes, bytes]] = []
    namespace_cache_calls: list[tuple[frozenset[str], frozenset[str], int, int]] = []
    pair_mode = {
        "link_state": False,
        "eligible": True,
        "nonprojection": False,
        "baseline_settled": False,
    }

    class Probes:
        def __init__(self) -> None:
            self.graph = graph
            self.overlay = SimpleNamespace(
                compiler_epoch_plan=plan,
                project_source_pairs=source_pairs,
            )
            self.producer = SimpleNamespace(toolchain_root="toolchain")
            self.closed = False

        def close(self) -> None:
            self.closed = True

        def probe_compiler_source_epochs(
            self,
            epochs: object,
            *,
            retain: object,
        ) -> tuple[object, ...]:
            for epoch in cast(Any, epochs):
                epoch_ids.append(epoch.epoch_id)
                epoch_nodes.append(epoch.node_ids)
                namespace_id = f"namespace-{epoch.epoch_id}"
                output = SimpleNamespace(
                    epoch_id=epoch.epoch_id,
                    namespace=SimpleNamespace(namespace_id=namespace_id),
                    compiler_outputs=tuple(
                        SimpleNamespace(
                            node_id=node_id,
                            object_payload=f"{epoch.epoch_id}:{node_id}".encode(),
                            compiler_invocation=_invocation(namespace_id),
                        )
                        for node_id in epoch.node_ids
                    ),
                )
                if cast(Any, retain)(output):
                    break
            self.closed = True
            return ()

    probes = Probes()

    def raw_candidates(
        *, path: str, operations: object, **kwargs: object
    ) -> tuple[_RawCandidate, ...]:
        del operations, kwargs
        descriptions = (
            ("prep-invalid",)
            if path == first_path
            else (
                "pair-fail",
                "full-plan",
                "fallback-plan",
                "first-valid",
                "regresses-reader",
                "shrink-unsettled",
                "later-valid",
            )
        )
        return tuple(
            _RawCandidate(
                ({"tag": description},),
                frozenset(),
                3 if description == "prep-invalid" else 1,
                description,
            )
            for description in descriptions
        )

    def candidate_payload(tag: str, view: str) -> bytes:
        if tag in {"shrink-unsettled", "later-valid"}:
            return f"settled:{tag}".encode()
        return f"{view}:{tag}".encode()

    def with_candidate(
        candidate_bundle: object,
        intervention: object,
        *,
        path: str,
        operations: object,
        **kwargs: object,
    ) -> tuple[object, object, bytes]:
        del candidate_bundle, intervention, kwargs
        tag = cast(list[dict[str, str]], list(cast(Any, operations)))[0]["tag"]
        prepared_descriptions.append(tag)
        if tag == "prep-invalid":
            raise ClassicProjectOverlayRepairError("invalid prepared neighbor")
        return (
            SimpleNamespace(tag=tag),
            SimpleNamespace(
                tag=tag,
                changed_path=path,
                interventions=(first_overlay, second_overlay),
            ),
            candidate_payload(tag, "effective"),
        )

    def counterfactual_outputs(
        *, candidate_bundle: object, path: str, **kwargs: object
    ) -> dict[str, bytes]:
        del kwargs
        tag = cast(Any, candidate_bundle).tag
        return {**baseline_declarations, path: candidate_payload(tag, "counterfactual")}

    def derive(
        candidate_bundle: object, *args: object, **kwargs: object
    ) -> tuple[object, object, frozenset[str]]:
        del args, kwargs
        tag = getattr(candidate_bundle, "tag", None)
        if tag is None:
            return plan, validation, frozenset()
        declarations = dict(baseline_declarations)
        path = cast(str, candidate_bundle.changed_path)
        declarations[path] = candidate_payload(tag, "counterfactual")
        if tag == "full-plan":
            declarations[path] = b"different-full-plan"
        audit_node_ids = plan.audit_node_ids
        runtime_projection_node_ids = plan.runtime_projection_node_ids
        if tag in {"shrink-unsettled", "later-valid"}:
            audit_node_ids -= {nodes[1].id}
            runtime_projection_node_ids -= {nodes[1].id}
        candidate_plan = ProjectOverlayCompilerEpochPlan(
            declarations,
            audit_node_ids,
            runtime_projection_node_ids,
            leaf_keys,
            ("reader-closure-changed",) if tag == "fallback-plan" else (),
        )
        return (
            candidate_plan,
            SimpleNamespace(
                compiler_epoch_plan=candidate_plan,
                macro_sensitive_identifiers=(
                    frozenset({f"macro:{tag}"})
                    if tag in {"first-valid", "later-valid"}
                    else frozenset()
                ),
                global_declaration_identifiers=(
                    frozenset({f"declaration:{tag}"})
                    if tag in {"first-valid", "later-valid"}
                    else frozenset()
                ),
            ),
            frozenset(),
        )

    def validate_shared_pair(**kwargs: object) -> object:
        audit = cast(ProjectOverlayCounterfactualAudit, kwargs["audit"])
        effective = cast(Any, kwargs["effective"])
        node = cast(ProducerNode, kwargs["node"])
        pair_orientations.append((audit.counterfactual_payload, effective.payload))
        if pair_mode["link_state"]:
            payload = audit.counterfactual_payload
            if payload.startswith(b"baseline.counterfactual"):
                code_equal = node == nodes[1] or (
                    node == nodes[0] and pair_mode["baseline_settled"]
                )
                projection_equal = False
                linker_dependencies = (
                    (SimpleNamespace(),) if pair_mode["eligible"] and node == nodes[0] else ()
                )
            elif b"candidate.0000.counterfactual" in payload:
                code_equal = node == nodes[1]
                projection_equal = False
                linker_dependencies = ()
            elif b"candidate.0001.counterfactual" in payload:
                code_equal = node == nodes[0]
                projection_equal = False
                linker_dependencies = ()
            else:
                code_equal = True
                projection_equal = False
                linker_dependencies = ()
            return SimpleNamespace(
                projection=SimpleNamespace(byte_equal=projection_equal),
                decision=SimpleNamespace(proven=True),
                coff_trace={"changed_code_section_count": 0 if code_equal else 1},
                crt_pull_dependencies=(),
                ordered_archive_seed_dependencies=linker_dependencies,
            )
        if audit.counterfactual_payload.startswith(b"baseline.counterfactual") and node == nodes[0]:
            raise ClassicSemanticError("baseline compiler mismatch")
        if (
            b"candidate.0000.counterfactual" in audit.counterfactual_payload
            and not pair_mode["nonprojection"]
        ):
            raise ClassicSemanticError("candidate compiler mismatch")
        equivalent = not (
            (b"candidate.0003.counterfactual" in audit.counterfactual_payload and node == nodes[1])
            or (
                b"candidate.0004.counterfactual" in audit.counterfactual_payload
                and node == nodes[0]
            )
            or pair_mode["nonprojection"]
        )
        byte_equal = equivalent and not (
            b"candidate.0005.counterfactual" in audit.counterfactual_payload and node == nodes[1]
        )
        return SimpleNamespace(
            projection=SimpleNamespace(byte_equal=byte_equal, equivalent=equivalent),
            decision=SimpleNamespace(proven=True),
            coff_trace={"changed_code_section_count": 0 if byte_equal else 1},
            crt_pull_dependencies=(),
            ordered_archive_seed_dependencies=(),
        )

    def validate_namespaces(**kwargs: object) -> dict[str, object]:
        namespace_cache_calls.append(
            (
                cast(frozenset[str], kwargs["sensitive_identifiers"]),
                cast(frozenset[str], kwargs["global_declaration_identifiers"]),
                id(kwargs["preprocessor_cache"]),
                id(kwargs["identifier_cache"]),
            )
        )
        return {
            item.namespace_id.casefold(): SimpleNamespace()
            for item in cast(Any, kwargs["evidences"])
        }

    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._toolchain_include_reader_payloads",
        lambda *args, **kwargs: {},
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._derive_project_overlay_compiler_epoch",
        derive,
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair.compiler_terminal_consumer_targets",
        lambda _graph: {nodes[0].id: frozenset({"program"})},
    )
    monkeypatch.setattr("reprobit.classic_project_overlay_repair._raw_candidates", raw_candidates)
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._with_candidate_output", with_candidate
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._candidate_counterfactual_outputs",
        counterfactual_outputs,
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._validate_compiler_namespaces",
        validate_namespaces,
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._require_namespace_source_authority",
        lambda *args, **kwargs: None,
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._validate_project_compiler_epoch_pair",
        validate_shared_pair,
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._parse_coff",
        lambda payload, label: SimpleNamespace(payload=payload, label=label),
    )
    progress: list[tuple[int, int, str]] = []

    result = probe_project_overlay_repair(
        cast(Any, probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=7,
        radius=1,
        candidate_limit=7,
        progress=lambda completed, total, detail: progress.append((completed, total, detail)),
    )

    assert result.checked is True
    assert result.compiled_candidates == 7
    assert result.repair is not None
    assert result.repair.source_path == second_path
    assert result.repair.affected_node_ids == tuple(node.id for node in nodes)
    assert result.repair.description == "later-valid"
    assert prepared_descriptions == [
        "prep-invalid",
        "pair-fail",
        "full-plan",
        "fallback-plan",
        "first-valid",
        "regresses-reader",
        "shrink-unsettled",
        "later-valid",
    ]
    assert pair_orientations
    assert all(b".counterfactual:" in item[0] for item in pair_orientations)
    assert all(b".effective:" in item[1] for item in pair_orientations)
    cache_ids_by_key: dict[tuple[frozenset[str], frozenset[str]], set[tuple[int, int]]] = {}
    for sensitive, declarations, preprocessor_id, identifier_id in namespace_cache_calls:
        cache_ids_by_key.setdefault((sensitive, declarations), set()).add(
            (preprocessor_id, identifier_id)
        )
    assert set(cache_ids_by_key) == {
        (frozenset(), frozenset()),
        (
            frozenset({"macro:first-valid"}),
            frozenset({"declaration:first-valid"}),
        ),
        (
            frozenset({"macro:later-valid"}),
            frozenset({"declaration:later-valid"}),
        ),
    }
    assert all(len(cache_ids) == 1 for cache_ids in cache_ids_by_key.values())
    assert (
        len(
            {
                preprocessor_id
                for cache_ids in cache_ids_by_key.values()
                for preprocessor_id, _identifier_id in cache_ids
            }
        )
        == 1
    )
    identifier_ids_by_declarations: dict[frozenset[str], set[int]] = {}
    for _sensitive, declarations, _preprocessor_id, identifier_id in namespace_cache_calls:
        identifier_ids_by_declarations.setdefault(declarations, set()).add(identifier_id)
    assert all(len(cache_ids) == 1 for cache_ids in identifier_ids_by_declarations.values())
    assert (
        len({next(iter(cache_ids)) for cache_ids in identifier_ids_by_declarations.values()}) == 3
    )
    assert epoch_ids == [
        "baseline.effective",
        "baseline.counterfactual",
        "candidate.0000.effective",
        "candidate.0000.counterfactual",
        "candidate.0001.effective",
        "candidate.0001.counterfactual",
        "candidate.0002.effective",
        "candidate.0002.counterfactual",
        "candidate.0003.effective",
        "candidate.0003.counterfactual",
        "candidate.0004.effective",
        "candidate.0004.counterfactual",
        "candidate.0005.effective",
        "candidate.0005.counterfactual",
        "candidate.0006.effective",
        "candidate.0006.counterfactual",
    ]
    assert all(item == tuple(node.id for node in nodes) for item in epoch_nodes)
    assert progress == [
        (1, 7, f"{second_path}: pair-fail"),
        (2, 7, f"{second_path}: full-plan"),
        (3, 7, f"{second_path}: fallback-plan"),
        (4, 7, f"{second_path}: first-valid"),
        (5, 7, f"{second_path}: regresses-reader"),
        (6, 7, f"{second_path}: shrink-unsettled"),
        (7, 7, f"{second_path}: later-valid"),
    ]
    assert probes.closed is True

    epoch_ids.clear()
    epoch_nodes.clear()
    progress.clear()
    exhausted_probes = Probes()
    exhausted = probe_project_overlay_repair(
        cast(Any, exhausted_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=1,
        radius=1,
        candidate_limit=4,
    )
    assert exhausted.repair is None
    assert exhausted.compiled_candidates == 1
    assert exhausted.exhausted is True
    assert exhausted.reason is not None and "--candidate-limit" in exhausted.reason
    assert exhausted_probes.closed is True

    epoch_ids.clear()
    epoch_nodes.clear()
    truncated_probes = Probes()
    truncated = probe_project_overlay_repair(
        cast(Any, truncated_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=4,
        radius=1,
        candidate_limit=1,
    )
    assert truncated.repair is None
    assert truncated.compiled_candidates == 1
    assert truncated.exhausted is False
    assert truncated.reason is not None and "--retune-candidates limit" in truncated.reason
    assert truncated_probes.closed is True

    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._raw_candidates",
        lambda **kwargs: (
            _RawCandidate(({"tag": "prep-invalid"},), frozenset(), 1, "prep-invalid"),
        ),
    )
    unprepared_probes = Probes()
    unprepared = probe_project_overlay_repair(
        cast(Any, unprepared_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=4,
        radius=1,
        candidate_limit=4,
    )
    assert unprepared.repair is None
    assert unprepared.compiled_candidates == 0
    assert unprepared.reason == (
        "no nearby source layout could be prepared safely: invalid prepared neighbor"
    )
    assert unprepared_probes.closed is True

    desired_order = ("?beta@@", "?alpha@@")

    def validate_layout_pair(**kwargs: object) -> object:
        return SimpleNamespace(
            effective=kwargs["effective"],
            projection=SimpleNamespace(byte_equal=True, equivalent=True),
            decision=SimpleNamespace(proven=True),
            coff_trace={"changed_code_section_count": 0},
            crt_pull_dependencies=(),
            ordered_archive_seed_dependencies=(),
        )

    def layout_state(coff: object, _hint: object) -> object:
        payload = cast(bytes, coff.payload)
        is_candidate = b"candidate.000" in payload
        order = desired_order if is_candidate else desired_order[::-1]
        beta_identity = b"changed" if b"candidate.0000.effective" in payload else b"beta"
        return SimpleNamespace(
            order=order,
            identities=(("?beta@@", beta_identity), ("?alpha@@", b"alpha")),
        )

    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._validate_project_compiler_epoch_pair",
        validate_layout_pair,
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._link_layout_object_state",
        layout_state,
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._raw_candidates",
        lambda *, path, **kwargs: (
            ()
            if path == first_path
            else (
                _RawCandidate(({"tag": "changed-data"},), frozenset(), 1, "changed-data"),
                _RawCandidate(({"tag": "right-order"},), frozenset(), 1, "right-order"),
            )
        ),
    )
    epoch_ids.clear()
    prepared_descriptions.clear()
    layout_probes = Probes()
    layout_result = probe_project_overlay_repair(
        cast(Any, layout_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=2,
        radius=1,
        candidate_limit=2,
        link_layout_hint=ClassicLinkLayoutHint(nodes[0].id, desired_order),
    )
    assert layout_result.repair is not None
    assert layout_result.repair.description == "right-order"
    assert layout_result.compiled_candidates == 2
    assert prepared_descriptions == ["changed-data", "right-order"]
    assert layout_probes.closed is True

    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._validate_project_compiler_epoch_pair",
        validate_shared_pair,
    )

    pair_mode["link_state"] = True
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._raw_candidates",
        lambda *, path, **kwargs: (
            ()
            if path == first_path
            else tuple(
                _RawCandidate(({"tag": tag},), frozenset(), 1, tag)
                for tag in (
                    "still-unsettled",
                    "regresses-reader",
                    "settled",
                    "later-valid",
                )
            )
        ),
    )
    epoch_ids.clear()
    epoch_nodes.clear()
    prepared_descriptions.clear()
    ordinary_probes = Probes()
    ordinary = probe_project_overlay_repair(
        cast(Any, ordinary_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=4,
        radius=1,
        candidate_limit=4,
    )
    assert ordinary.repair is None
    assert ordinary.compiled_candidates == 0
    assert epoch_ids == ["baseline.effective", "baseline.counterfactual"]
    assert prepared_descriptions == []
    assert ordinary_probes.closed is True

    epoch_ids.clear()
    wrong_target_probes = Probes()
    wrong_target = probe_project_overlay_repair(
        cast(Any, wrong_target_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=4,
        radius=1,
        candidate_limit=4,
        settle_target_ids=frozenset({"other-program"}),
    )
    assert wrong_target.repair is None
    assert wrong_target.compiled_candidates == 0
    assert wrong_target_probes.closed is True

    pair_mode["baseline_settled"] = True
    epoch_ids.clear()
    prepared_descriptions.clear()
    already_settled_probes = Probes()
    already_settled = probe_project_overlay_repair(
        cast(Any, already_settled_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=4,
        radius=1,
        candidate_limit=4,
        settle_target_ids=frozenset({"program"}),
    )
    assert already_settled.repair is None
    assert already_settled.compiled_candidates == 0
    assert epoch_ids == ["baseline.effective", "baseline.counterfactual"]
    assert prepared_descriptions == []
    assert already_settled_probes.closed is True
    pair_mode["baseline_settled"] = False

    epoch_ids.clear()
    limited_settlement_probes = Probes()
    limited_settlement = probe_project_overlay_repair(
        cast(Any, limited_settlement_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=1,
        radius=1,
        candidate_limit=4,
        settle_target_ids=frozenset({"program"}),
    )
    assert limited_settlement.repair is None
    assert limited_settlement.compiled_candidates == 1
    assert limited_settlement.exhausted is True
    assert limited_settlement.reason is not None
    assert "--candidate-limit" in limited_settlement.reason
    assert limited_settlement_probes.closed is True

    epoch_ids.clear()
    prepared_descriptions.clear()
    settling_probes = Probes()
    settled = probe_project_overlay_repair(
        cast(Any, settling_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=4,
        radius=1,
        candidate_limit=4,
        settle_target_ids=frozenset({"program"}),
    )
    assert settled.repair is not None
    assert settled.repair.description == "settled"
    assert settled.compiled_candidates == 3
    assert prepared_descriptions == [
        "still-unsettled",
        "regresses-reader",
        "settled",
    ]
    assert settling_probes.closed is True

    pair_mode["eligible"] = False
    epoch_ids.clear()
    prepared_descriptions.clear()
    clean_probes = Probes()
    clean = probe_project_overlay_repair(
        cast(Any, clean_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=4,
        radius=1,
        candidate_limit=4,
        settle_target_ids=frozenset({"program"}),
    )
    assert clean.repair is None
    assert clean.compiled_candidates == 0
    assert clean.reason is None
    assert epoch_ids == ["baseline.effective", "baseline.counterfactual"]
    assert prepared_descriptions == []
    assert clean_probes.closed is True

    pair_mode.update(link_state=False, nonprojection=True)
    nonprojection_plan = replace(plan, runtime_projection_node_ids=frozenset())
    nonprojection_validation = SimpleNamespace(
        compiler_epoch_plan=nonprojection_plan,
        macro_sensitive_identifiers=frozenset(),
        global_declaration_identifiers=frozenset(),
    )

    def derive_nonprojection(
        candidate_bundle: object, *args: object, **kwargs: object
    ) -> tuple[object, object, frozenset[str]]:
        del args, kwargs
        tag = getattr(candidate_bundle, "tag", None)
        if tag is None:
            return nonprojection_plan, nonprojection_validation, frozenset()
        declarations = dict(baseline_declarations)
        path = cast(str, candidate_bundle.changed_path)
        declarations[path] = f"counterfactual:{tag}".encode()
        candidate_plan = replace(nonprojection_plan, declaration_outputs=declarations)
        return (
            candidate_plan,
            SimpleNamespace(
                compiler_epoch_plan=candidate_plan,
                macro_sensitive_identifiers=frozenset(),
                global_declaration_identifiers=frozenset(),
            ),
            frozenset(),
        )

    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._derive_project_overlay_compiler_epoch",
        derive_nonprojection,
    )
    monkeypatch.setattr(
        "reprobit.classic_project_overlay_repair._raw_candidates",
        lambda *, path, **kwargs: (
            ()
            if path == first_path
            else (
                _RawCandidate(
                    ({"tag": "nonprojection-valid"},),
                    frozenset(),
                    1,
                    "nonprojection-valid",
                ),
            )
        ),
    )
    prepared_descriptions.clear()
    nonprojection_probes = Probes()
    nonprojection_probes.overlay.compiler_epoch_plan = nonprojection_plan
    nonprojection = probe_project_overlay_repair(
        cast(Any, nonprojection_probes),
        cast(Any, bundle),
        clean_sources={
            first_path: source,
            second_path: source,
            "src/unit0.cpp": b"int unit0;\n",
            "src/unit1.cpp": b"int unit1;\n",
        },
        candidate_budget=1,
        radius=1,
        candidate_limit=1,
    )
    assert nonprojection.repair is not None
    assert nonprojection.repair.description == "nonprojection-valid"
    assert nonprojection.compiled_candidates == 1
    assert prepared_descriptions == ["nonprojection-valid"]
    assert nonprojection_probes.closed is True
