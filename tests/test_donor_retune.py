from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from typing import Any, cast

import pytest

from reprobit.classic.overlay_document import render_classic_overlay_proposal
from reprobit.classic.overlay_generator import render_classic_overlay_generator
from reprobit.classic_donor_retune_candidates import (
    DonorRetuneCandidate,
    DonorRetuneChange,
    DonorRetuneError,
    _copy_with_parameters,
    enumerate_donor_retune_candidates,
)
from reprobit.classic_donor_retune_materialization import (
    materialize_donor_retune_candidate,
)
from reprobit.classic_donors import (
    generate_declaration_shape,
    generate_extern_run,
    generate_forward_run,
    generate_pad_shape,
)
from reprobit.model import Digest, Scope
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import JsonValue


def _donor(
    family: ClassicRecipeFamily,
    parameters: dict[str, JsonValue],
) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id="donor_saved",
        scope=Scope(target="program", translation_unit="tu_main"),
        rationale="Saved donor authority must retain its human review context.",
        dependencies=("donor_parent",),
        beneficiaries=(
            Scope(target="program", translation_unit="tu_main", function="?First@@YAXXZ"),
            Scope(target="program", translation_unit="tu_main", function="?Second@@YAXXZ"),
        ),
        family=family,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
        parameters=tuple(
            ClassicField(name=name, value=value) for name, value in sorted(parameters.items())
        ),
    )


def _declaration_donor(classes: int = 6, functions: int = 58) -> ClassicRecipeIntervention:
    return _donor(
        ClassicRecipeFamily.DECLARATION_SHAPE,
        {
            "classes": classes,
            "emission_policy": "non_emitting_declarations_only",
            "functions": functions,
            "generated_header_sha256": Digest.from_bytes(
                generate_declaration_shape(classes, functions)
            ).value,
            "role_policy": "cross_tu_complete_target_only_v1",
        },
    )


def _triple_donor(
    pre: int = 4,
    post: int = 3,
    eof: int = 8,
) -> ClassicRecipeIntervention:
    width = 2
    generated = b"".join(
        generate_forward_run(prefix, count, width)
        for prefix, count in (("Pre", pre), ("Post", post), ("End", eof))
        if count
    )
    return _donor(
        ClassicRecipeFamily.DECLARATION_RUN_TRIPLE,
        {
            "emission_policy": "non_emitting_declarations_only",
            "eof_count": eof,
            "eof_prefix": "End",
            "generated_header_sha256": Digest.from_bytes(generated).value,
            "post_count": post,
            "post_prefix": "Post",
            "pre_count": pre,
            "pre_prefix": "Pre",
            "width": width,
        },
    )


def _parameters(intervention: ClassicRecipeIntervention) -> dict[str, JsonValue]:
    return {field.name: field.value for field in intervention.parameters}


def _overlay_donor() -> ClassicRecipeIntervention:
    renderings: list[JsonValue] = [
        {
            "path": "src/main.cpp",
            "clean_sha256": "a" * 64,
            "rendered_sha256": "b" * 64,
            "operations": [
                {
                    "id": "op_header",
                    "op": "insert",
                    "anchor": {"at": "start", "ctx": "c" * 64},
                    "gen": {
                        "k": "seq",
                        "lines": 4,
                        "items": [
                            {
                                "k": "extern_run",
                                "line": 1,
                                "prefix": "g_h",
                                "count": 2,
                                "width": 2,
                            }
                        ],
                    },
                },
                {
                    "id": "op_direct",
                    "op": "insert",
                    "anchor": {"at": "start", "ctx": "d" * 64},
                    "gen": {
                        "k": "extern_run",
                        "prefix": "ignored",
                        "count": 9,
                        "width": 2,
                    },
                },
                {
                    "id": "op_forward",
                    "op": "insert",
                    "anchor": {"at": "start", "ctx": "9" * 64},
                    "gen": {
                        "k": "seq",
                        "lines": 8,
                        "items": [
                            {
                                "k": "fwd_run",
                                "line": 1,
                                "stem": "HeaderForward",
                                "first": 0,
                                "count": 8,
                            }
                        ],
                    },
                },
            ],
        },
        {
            "path": "src/shared.h",
            "clean_sha256": "e" * 64,
            "rendered_sha256": "f" * 64,
            "operations": [
                {
                    "id": "op_seat",
                    "op": "insert",
                    "anchor": {"at": "start", "ctx": "1" * 64},
                    "gen": {
                        "k": "seq",
                        "lines": 1,
                        "items": [
                            {
                                "k": "extern_run",
                                "line": 1,
                                "prefix": "g_p",
                                "count": 1,
                                "width": 1,
                            },
                            {
                                "k": "seq",
                                "line": 1,
                                "lines": 1,
                                "items": [
                                    {
                                        "k": "extern_run",
                                        "line": 1,
                                        "prefix": "nested",
                                        "count": 7,
                                        "width": 1,
                                    }
                                ],
                            },
                        ],
                    },
                }
            ],
        },
    ]
    return _donor(
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        {
            "emission_policy": "donor_private_rendering_only",
            "rendering_identity_sha256": sha256(
                (json.dumps(renderings, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "renderings": renderings,
        },
    )


def _materializable_overlay_donor() -> tuple[
    ClassicRecipeIntervention,
    ClassicProofReceipt,
    dict[str, bytes],
    list[dict[str, JsonValue]],
]:
    path = "src/main.cpp"
    clean = b"int value;\n"
    operations: list[JsonValue] = [
        {
            "id": "op_donor_declarations",
            "op": "append",
            "gen": {
                "k": "seq",
                "lines": 4,
                "items": [
                    {
                        "k": "extern_run",
                        "line": 1,
                        "prefix": "g_h",
                        "count": 2,
                        "width": 2,
                    }
                ],
            },
        }
    ]
    canonical_operations: list[dict[str, JsonValue]] = [
        {"id": "op_canonical", "op": "append", "gen": {"k": "lines", "n": 1}}
    ]
    rendered = clean + b"\nextern int g_h00;\nextern int g_h01;\n\n\n"
    pinned_rendering: dict[str, JsonValue] = {
        "path": path,
        "operations": operations,
        "clean_sha256": Digest.from_bytes(clean).value,
        "rendered_sha256": Digest.from_bytes(rendered).value,
    }
    identity_claim = {
        "canonical_overlay_replay": "owning_translation_unit_v1",
        "renderings": [pinned_rendering],
    }
    donor = _donor(
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        {
            "canonical_overlay_replay": "owning_translation_unit_v1",
            "emission_policy": "donor_private_rendering_only",
            "include_projection": "source_root_mirror_only_v1",
            "rendering_identity_sha256": sha256(
                (json.dumps(identity_claim, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "renderings": [{"path": path, "operations": operations}],
        },
    )
    receipt = ClassicProofReceipt(
        id="proof_donor_saved",
        intervention_id=donor.id,
        family=donor.family,
        expected_values={
            "renderings[0].clean_sha256": Digest.from_bytes(clean).value,
            "renderings[0].rendered_sha256": Digest.from_bytes(rendered).value,
        },
        status="compiler_generated_current_source",
        authenticity="synthetic_baseline_only",
    )
    return donor, receipt, {path: clean}, canonical_operations


def _materializable_two_op_overlay_donor() -> tuple[
    ClassicRecipeIntervention,
    ClassicProofReceipt,
    dict[str, bytes],
    list[dict[str, JsonValue]],
]:
    """An overlay with a slack extern run and a packed forward run in one rendering."""

    path = "src/main.cpp"
    clean = b"int value;\n"
    operations: list[JsonValue] = [
        {
            "id": "op_externs",
            "op": "append",
            "gen": {
                "k": "seq",
                "lines": 4,
                "items": [{"k": "extern_run", "line": 1, "prefix": "g_h", "count": 2, "width": 2}],
            },
        },
        {
            "id": "op_forwards",
            "op": "append",
            "gen": {
                "k": "seq",
                "lines": 2,
                "items": [
                    {"k": "fwd_run", "line": 1, "stem": "Fwd", "first": 0, "count": 2, "width": 1}
                ],
            },
        },
    ]
    canonical_operations: list[dict[str, JsonValue]] = [
        {"id": "op_canonical", "op": "append", "gen": {"k": "lines", "n": 1}}
    ]
    rendered = render_classic_overlay_proposal(
        [
            {
                "path": path,
                "clean": Digest.from_bytes(clean).value,
                "effective": "0" * 64,
                "ops": [*deepcopy(canonical_operations), *deepcopy(operations)],
            }
        ],
        {path: clean},
    ).outputs[path]
    pinned_rendering: dict[str, JsonValue] = {
        "path": path,
        "operations": operations,
        "clean_sha256": Digest.from_bytes(clean).value,
        "rendered_sha256": Digest.from_bytes(rendered).value,
    }
    identity_claim = {
        "canonical_overlay_replay": "owning_translation_unit_v1",
        "renderings": [pinned_rendering],
    }
    donor = _donor(
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        {
            "canonical_overlay_replay": "owning_translation_unit_v1",
            "emission_policy": "donor_private_rendering_only",
            "include_projection": "source_root_mirror_only_v1",
            "rendering_identity_sha256": sha256(
                (json.dumps(identity_claim, indent=2, sort_keys=True) + "\n").encode()
            ).hexdigest(),
            "renderings": [{"path": path, "operations": operations}],
        },
    )
    receipt = ClassicProofReceipt(
        id="proof_donor_saved",
        intervention_id=donor.id,
        family=donor.family,
        expected_values={
            "renderings[0].clean_sha256": Digest.from_bytes(clean).value,
            "renderings[0].rendered_sha256": Digest.from_bytes(rendered).value,
        },
        status="compiler_generated_current_source",
        authenticity="synthetic_baseline_only",
    )
    return donor, receipt, {path: clean}, canonical_operations


def _json_leaf_differences(
    before: JsonValue,
    after: JsonValue,
    path: tuple[str | int, ...] = (),
) -> list[tuple[tuple[str | int, ...], JsonValue, JsonValue]]:
    if isinstance(before, dict) and isinstance(after, dict) and before.keys() == after.keys():
        result: list[tuple[tuple[str | int, ...], JsonValue, JsonValue]] = []
        for name in before:
            result.extend(_json_leaf_differences(before[name], after[name], (*path, name)))
        return result
    if isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        result = []
        for index, (old_item, new_item) in enumerate(zip(before, after, strict=True)):
            result.extend(_json_leaf_differences(old_item, new_item, (*path, index)))
        return result
    return [] if before == after else [(path, before, after)]


def test_declaration_shape_uses_canonical_manhattan_shells_and_covers_pr864() -> None:
    intervention = _declaration_donor()

    candidates = enumerate_donor_retune_candidates(intervention)
    states = [
        (
            cast(int, _parameters(candidate.intervention)["classes"]),
            cast(int, _parameters(candidate.intervention)["functions"]),
        )
        for candidate in candidates
    ]

    assert candidates == enumerate_donor_retune_candidates(intervention)
    assert len(states) == len(set(states))
    assert [candidate.distance for candidate in candidates] == sorted(
        candidate.distance for candidate in candidates
    )
    assert states[:3] == [(6, 57), (6, 59), (7, 58)]
    assert (7, 56) in states
    pr864 = candidates[states.index((7, 56))]
    assert pr864.distance == 3
    assert [change.path for change in pr864.changes[:2]] == [
        ("parameters", "classes"),
        ("parameters", "functions"),
    ]


def test_declaration_shape_allows_bounded_radius_eight_escalation() -> None:
    intervention = _declaration_donor(classes=6, functions=54)

    candidates = enumerate_donor_retune_candidates(intervention, radius=8)
    states = [
        (
            cast(int, _parameters(candidate.intervention)["classes"]),
            cast(int, _parameters(candidate.intervention)["functions"]),
        )
        for candidate in candidates
    ]

    candidate = candidates[states.index((8, 49))]
    assert candidate.distance == 7
    assert len(candidates) <= 64


def test_declaration_shape_changes_only_knobs_and_derived_digest() -> None:
    intervention = _declaration_donor(classes=2, functions=6)
    before = intervention.model_dump(mode="json")

    candidates = enumerate_donor_retune_candidates(intervention, radius=1)

    assert intervention.model_dump(mode="json") == before
    for candidate in candidates:
        parameters = _parameters(candidate.intervention)
        classes = cast(int, parameters["classes"])
        functions = cast(int, parameters["functions"])
        assert 1 <= classes <= 10
        assert classes <= functions <= 10 * classes
        assert (
            parameters["generated_header_sha256"]
            == Digest.from_bytes(generate_declaration_shape(classes, functions)).value
        )
        assert parameters["emission_policy"] == "non_emitting_declarations_only"
        assert parameters["role_policy"] == "cross_tu_complete_target_only_v1"
        assert candidate.intervention.id == intervention.id
        assert candidate.intervention.rationale == intervention.rationale
        assert candidate.intervention.dependencies == intervention.dependencies
        assert candidate.intervention.beneficiaries == intervention.beneficiaries
        assert candidate.changes[-1].kind == "derived"
        assert candidate.changes[-1].path == (
            "parameters",
            "generated_header_sha256",
        )


def test_declaration_run_triple_covers_nearest_shared_header_repair() -> None:
    intervention = _triple_donor()
    before = intervention.model_dump(mode="json")

    candidates = enumerate_donor_retune_candidates(intervention, radius=1)

    states = [
        tuple(
            cast(int, _parameters(candidate.intervention)[f"{seat}_count"])
            for seat in ("pre", "post", "eof")
        )
        for candidate in candidates
    ]
    assert states == [
        (3, 3, 8),
        (5, 3, 8),
        (4, 2, 8),
        (4, 4, 8),
        (4, 3, 7),
        (4, 3, 9),
    ]
    repaired = candidates[0]
    assert repaired.distance == 1
    assert [change.path for change in repaired.changes] == [
        ("parameters", "pre_count"),
        ("parameters", "generated_header_sha256"),
    ]
    assert repaired.changes[-1].kind == "derived"
    assert intervention.model_dump(mode="json") == before


def test_declaration_run_triple_materialization_preserves_matching_receipt() -> None:
    saved = _triple_donor()
    receipt = ClassicProofReceipt(
        id="proof_donor_saved",
        intervention_id=saved.id,
        family=saved.family,
        status="compiler_generated_current_source",
        authenticity="synthetic_baseline_only",
    )
    candidate = enumerate_donor_retune_candidates(saved, radius=1)[0]

    materialized = materialize_donor_retune_candidate(candidate, receipt)

    assert materialized.intervention == candidate.intervention
    assert materialized.receipt is receipt
    assert materialized.changes == candidate.changes


def test_overlay_moves_one_knob_then_two_and_keeps_packed_canvases_fitting() -> None:
    intervention = _overlay_donor()
    before_model = intervention.model_dump(mode="json")
    before_parameters = deepcopy(_parameters(intervention))

    candidates = enumerate_donor_retune_candidates(intervention, radius=2)

    def item_path(operation: int, leaf: str) -> tuple[str | int, ...]:
        return ("parameters", "renderings", 0, "operations", operation, "gen", "items", 0, leaf)

    header, header_canvas = item_path(0, "count"), (*item_path(0, "count")[:6], "lines")
    forward, forward_canvas = item_path(2, "count"), (*item_path(2, "count")[:6], "lines")
    seat = ("parameters", "renderings", 1, "operations", 0, "gen", "items", 0, "count")
    observed = [
        (candidate.distance, [(c.path, c.before, c.after, c.kind) for c in candidate.changes])
        for candidate in candidates
    ]
    # op_header has slack (2 declarations on a 4-line canvas): the knob moves alone.
    # op_forward is packed (8 declarations on 8 lines): its canvas follows the count.
    # op_seat cannot render (a nested run leaves its canvas): the knob moves alone, as before.
    # After every single-knob move, two knobs of one rendering move together by distance.
    assert observed == [
        (1, [(header, 2, 1, "knob")]),
        (1, [(header, 2, 3, "knob")]),
        (1, [(forward, 8, 7, "knob"), (forward_canvas, 8, 7, "derived")]),
        (1, [(forward, 8, 9, "knob"), (forward_canvas, 8, 9, "derived")]),
        (1, [(seat, 1, 2, "knob")]),
        (2, [(header, 2, 4, "knob")]),
        (2, [(forward, 8, 6, "knob"), (forward_canvas, 8, 6, "derived")]),
        (2, [(forward, 8, 10, "knob"), (forward_canvas, 8, 10, "derived")]),
        (2, [(seat, 1, 3, "knob")]),
        (2, [(header, 2, 1, "knob"), (forward, 8, 7, "knob"), (forward_canvas, 8, 7, "derived")]),
        (2, [(header, 2, 1, "knob"), (forward, 8, 9, "knob"), (forward_canvas, 8, 9, "derived")]),
        (2, [(header, 2, 3, "knob"), (forward, 8, 7, "knob"), (forward_canvas, 8, 7, "derived")]),
        (2, [(header, 2, 3, "knob"), (forward, 8, 9, "knob"), (forward_canvas, 8, 9, "derived")]),
    ]
    assert header_canvas not in {c.path for candidate in candidates for c in candidate.changes}
    assert intervention.model_dump(mode="json") == before_model
    for candidate in candidates:
        knobs = [c for c in candidate.changes if c.kind == "knob"]
        assert sum(abs(cast(int, c.after) - cast(int, c.before)) for c in knobs) == (
            candidate.distance
        )
        assert sorted(
            _json_leaf_differences(
                before_parameters, _parameters(candidate.intervention), ("parameters",)
            )
        ) == sorted((c.path, c.before, c.after) for c in candidate.changes)
        assert candidate.intervention.id == intervention.id
        assert candidate.intervention.rationale == intervention.rationale
        assert candidate.intervention.dependencies == intervention.dependencies
        assert candidate.intervention.beneficiaries == intervention.beneficiaries


def _class_chain_donor(canvas: int) -> ClassicRecipeIntervention:
    def record_class(identifier: str, line: int, count: int) -> JsonValue:
        return {
            "k": "class",
            "line": line,
            "id": identifier,
            "inline": True,
            "members": [{"count": count, "first": 0, "stem": "Record"}],
        }

    # A class of n members renders n + 2 lines: two stacked classes of 3 fill lines 1..10.
    renderings: list[JsonValue] = [
        {
            "path": "src/main.cpp",
            "clean_sha256": "a" * 64,
            "rendered_sha256": "b" * 64,
            "operations": [
                {
                    "id": "op_dial",
                    "op": "insert",
                    "anchor": {"at": "start", "ctx": "c" * 64},
                    "gen": {
                        "k": "seq",
                        "lines": canvas,
                        "items": [
                            record_class("MxUnkRecW00", 1, 3),
                            record_class("MxUnkRecW01", 6, 3),
                            {"k": "lines", "line": 11, "n": 2},
                        ],
                    },
                }
            ],
        }
    ]
    return _donor(
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        {
            "canonical_overlay_replay": "owning_translation_unit_v1",
            "emission_policy": "donor_private_rendering_only",
            "include_projection": "source_root_mirror_only_v1",
            "rendering_identity_sha256": "0" * 64,
            "renderings": renderings,
        },
    )


def test_overlay_member_and_padding_knobs_shift_later_items_and_a_packed_canvas() -> None:
    packed = _class_chain_donor(canvas=12)
    items = ("parameters", "renderings", 0, "operations", 0, "gen", "items")
    canvas = ("parameters", "renderings", 0, "operations", 0, "gen", "lines")

    candidates = enumerate_donor_retune_candidates(packed, radius=1)

    singles = [c for c in candidates if len([x for x in c.changes if x.kind == "knob"]) == 1]
    by_knob = {c.changes[0].path: c for c in singles}
    first_members = (*items, 0, "members", 0, "count")
    second_members = (*items, 1, "members", 0, "count")
    padding = (*items, 2, "n")
    assert set(by_knob) == {first_members, second_members, padding}
    grown = [c for c in singles if c.changes[0].path == first_members and c.changes[0].after == 4]
    assert [(c.path, c.before, c.after, c.kind) for c in grown[0].changes] == [
        (first_members, 3, 4, "knob"),
        ((*items, 1, "line"), 6, 7, "derived"),
        ((*items, 2, "line"), 11, 12, "derived"),
        (canvas, 12, 13, "derived"),
    ]
    shrunk_padding = [
        c for c in singles if c.changes[0].path == padding and c.changes[0].after == 1
    ]
    assert [(c.path, c.before, c.after, c.kind) for c in shrunk_padding[0].changes] == [
        (padding, 2, 1, "knob"),
        (canvas, 12, 11, "derived"),
    ]
    pairs = [c for c in candidates if len([x for x in c.changes if x.kind == "knob"]) == 2]
    assert pairs == []  # two knobs need distance two

    slack = _class_chain_donor(canvas=14)
    grown_slack = next(
        c
        for c in enumerate_donor_retune_candidates(slack, radius=1)
        if c.changes[0].path == first_members and c.changes[0].after == 4
    )
    # Two lines of slack absorb one more member: later items shift, the canvas stays.
    assert [c.path for c in grown_slack.changes] == [
        first_members,
        (*items, 1, "line"),
        (*items, 2, "line"),
    ]


def test_overlay_pair_moves_are_bounded_and_render_both_knobs() -> None:
    packed = _class_chain_donor(canvas=12)
    items = ("parameters", "renderings", 0, "operations", 0, "gen", "items")
    canvas = ("parameters", "renderings", 0, "operations", 0, "gen", "lines")

    pairs = [
        c
        for c in enumerate_donor_retune_candidates(packed, radius=2)
        if len([x for x in c.changes if x.kind == "knob"]) == 2
    ]

    assert pairs and all(c.distance == 2 for c in pairs)
    first_members = (*items, 0, "members", 0, "count")
    second_members = (*items, 1, "members", 0, "count")
    both_grow = [
        c
        for c in pairs
        if [(x.path, x.after) for x in c.changes if x.kind == "knob"]
        == [(first_members, 4), (second_members, 4)]
    ]
    # Knobs first in move order, then the later items' line shifts, then the canvas.
    assert [(c.path, c.before, c.after, c.kind) for c in both_grow[0].changes] == [
        (first_members, 3, 4, "knob"),
        (second_members, 3, 4, "knob"),
        ((*items, 1, "line"), 6, 7, "derived"),
        ((*items, 2, "line"), 11, 13, "derived"),
        (canvas, 12, 14, "derived"),
    ]
    rendered = render_classic_overlay_generator(
        cast(
            dict[str, object],
            cast(list[JsonValue], _parameters(both_grow[0].intervention)["renderings"])[0][
                "operations"
            ][0]["gen"],  # type: ignore[index, call-overload]
        )
    )
    assert rendered.count(b"inline void Record") == 8
    assert len(rendered.split(b"\n")) == 15  # 14 canvas lines plus the trailing newline


def test_overlay_enumeration_is_deterministic_and_strictly_bounded() -> None:
    intervention = _overlay_donor()

    first = enumerate_donor_retune_candidates(intervention, limit=3)
    second = enumerate_donor_retune_candidates(intervention, limit=3)

    assert first == second
    assert len(first) == 3
    with pytest.raises(DonorRetuneError, match="radius"):
        enumerate_donor_retune_candidates(intervention, radius=65)
    with pytest.raises(DonorRetuneError, match="limit"):
        enumerate_donor_retune_candidates(intervention, limit=4097)
    with pytest.raises(DonorRetuneError, match="radius"):
        enumerate_donor_retune_candidates(intervention, radius=True)


def test_eligible_malformed_donor_is_refused_and_other_families_are_ignored() -> None:
    stale = _declaration_donor()
    stale_parameters = _parameters(stale)
    stale_parameters["generated_header_sha256"] = "0" * 64
    stale = _donor(ClassicRecipeFamily.DECLARATION_SHAPE, stale_parameters)
    unsupported = _donor(
        ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN,
        {
            "emission_policy": "non_emitting_declarations_only",
            "extern_count": 3,
            "extern_prefix": "g_e",
            "extern_width": 2,
            "forward_count": 2,
            "forward_prefix": "Fwd",
            "forward_width": 2,
            "generated_header_sha256": "0" * 64,
            "rendered_source_line_count": 1,
            "rendered_source_sha256": "1" * 64,
            "rendered_source_size": 10,
            "seat_proof": {},
        },
    )

    with pytest.raises(DonorRetuneError, match="digest differs"):
        enumerate_donor_retune_candidates(stale)
    assert enumerate_donor_retune_candidates(unsupported) == ()


def test_declaration_shape_materialization_preserves_matching_receipt() -> None:
    saved = _declaration_donor(classes=6, functions=58)
    receipt = ClassicProofReceipt(
        id="proof_donor_saved",
        intervention_id=saved.id,
        family=saved.family,
        status="compiler_generated_current_source",
        authenticity="synthetic_baseline_only",
    )
    candidate = enumerate_donor_retune_candidates(saved, radius=1)[0]

    materialized = materialize_donor_retune_candidate(candidate, receipt)

    assert materialized.intervention == candidate.intervention
    assert materialized.receipt is receipt
    assert materialized.distance == candidate.distance
    assert materialized.changes == candidate.changes
    assert saved.model_dump(mode="json") != materialized.intervention.model_dump(mode="json")


def test_overlay_materialization_refreshes_only_existing_derived_pins() -> None:
    saved, receipt, clean_sources, canonical_operations = _materializable_overlay_donor()
    candidate = enumerate_donor_retune_candidates(saved, radius=1)[1]
    saved_intervention = saved.model_dump(mode="json")
    saved_receipt = receipt.model_dump(mode="json")

    materialized = materialize_donor_retune_candidate(
        candidate,
        receipt,
        clean_sources=clean_sources,
        canonical_overlay_operations=canonical_operations,
    )

    assert saved.model_dump(mode="json") == saved_intervention
    assert receipt.model_dump(mode="json") == saved_receipt
    intervention_differences = _json_leaf_differences(
        saved_intervention,
        materialized.intervention.model_dump(mode="json"),
    )
    assert [path for path, _before, _after in intervention_differences] == [
        ("parameters", 3, "value"),
        ("parameters", 4, "value", 0, "operations", 0, "gen", "items", 0, "count"),
    ]
    receipt_differences = _json_leaf_differences(
        saved_receipt,
        materialized.receipt.model_dump(mode="json"),
    )
    assert [path for path, _before, _after in receipt_differences] == [
        ("expected_values", "renderings[0].rendered_sha256")
    ]
    assert materialized.receipt.status == receipt.status
    assert materialized.receipt.authenticity == receipt.authenticity
    assert [change.kind for change in materialized.changes] == [
        "knob",
        "derived",
        "derived",
    ]
    assert [change.path for change in materialized.changes] == [
        candidate.changes[0].path,
        ("receipt", "expected_values", "renderings[0].rendered_sha256"),
        ("parameters", "rendering_identity_sha256"),
    ]
    parameters = _parameters(materialized.intervention)
    assert parameters["include_projection"] == "source_root_mirror_only_v1"
    assert parameters["canonical_overlay_replay"] == "owning_translation_unit_v1"
    assert parameters["emission_policy"] == "donor_private_rendering_only"


@pytest.mark.parametrize(
    ("change", "message"),
    (
        ("missing_replay", "replay operations are required"),
        ("changed_clean", "clean source differs"),
        ("extra_source", "clean-source universe differs"),
        ("missing_pin", "schema differs"),
    ),
)
def test_overlay_materialization_refuses_unauthenticated_inputs(
    change: str,
    message: str,
) -> None:
    saved, receipt, clean_sources, canonical_operations = _materializable_overlay_donor()
    candidate = enumerate_donor_retune_candidates(saved, radius=1)[0]
    operations_arg: list[dict[str, JsonValue]] | None = canonical_operations
    if change == "missing_replay":
        operations_arg = None
    elif change == "changed_clean":
        clean_sources["src/main.cpp"] = b"int changed;\n"
    elif change == "extra_source":
        clean_sources["src/extra.h"] = b""
    else:
        expected = dict(receipt.expected_values)
        del expected["renderings[0].rendered_sha256"]
        receipt = receipt.model_copy(update={"expected_values": expected})

    with pytest.raises(DonorRetuneError, match=message):
        materialize_donor_retune_candidate(
            candidate,
            receipt,
            clean_sources=clean_sources,
            canonical_overlay_operations=operations_arg,
        )


def test_materialization_authenticates_saved_candidate_and_matching_receipt() -> None:
    saved = _declaration_donor()
    receipt = ClassicProofReceipt(
        id="proof_other",
        intervention_id="other_donor",
        family=saved.family,
    )
    candidate = enumerate_donor_retune_candidates(saved)[0]

    with pytest.raises(DonorRetuneError, match="different intervention"):
        materialize_donor_retune_candidate(candidate, receipt)

    forged_parameters = _parameters(candidate.intervention)
    forged_parameters["emission_policy"] = "unreviewed_policy"
    forged = candidate.intervention.model_copy(
        update={
            "parameters": tuple(
                ClassicField(name=name, value=value)
                for name, value in sorted(forged_parameters.items())
            )
        }
    )
    forged_candidate = candidate.__class__(forged, candidate.distance, candidate.changes)
    matching = receipt.model_copy(update={"intervention_id": saved.id})
    with pytest.raises(DonorRetuneError, match="emission policy differs"):
        materialize_donor_retune_candidate(forged_candidate, matching)


def _receipt(
    intervention: ClassicRecipeIntervention, expected_values: dict[str, JsonValue]
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id="proof_donor_saved",
        intervention_id=intervention.id,
        family=intervention.family,
        status="compiler_generated_current_source",
        authenticity="synthetic_baseline_only",
        expected_values=expected_values,
    )


def _forward_run_donor(count: int = 32) -> ClassicRecipeIntervention:
    return _donor(
        ClassicRecipeFamily.FORWARD_DECLARATION_RUN,
        {
            "count": count,
            "emission_policy": "non_emitting_declarations_only",
            "generated_header_sha256": Digest.from_bytes(
                generate_forward_run("MxUnkRecVC", count, 3)
            ).value,
            "placement": "suffix",
            "prefix": "MxUnkRecVC",
            "width": 3,
        },
    )


def _pad_donor(classes: int = 2, per_class: int = 3) -> ClassicRecipeIntervention:
    return _donor(
        ClassicRecipeFamily.PAD_SHAPE,
        {
            "classes": classes,
            "emission_policy": "non_emitting_declarations_only",
            "functions_per_class": per_class,
            "generated_header_sha256": Digest.from_bytes(
                generate_pad_shape(classes, per_class)
            ).value,
        },
    )


def _extern_pair_donor(header: int = 10, seat: int = 8) -> ClassicRecipeIntervention:
    pieces = [
        generate_extern_run(prefix, count, 2)
        for prefix, count in (("g_h", header), ("g_p", seat))
        if count
    ]
    return _donor(
        ClassicRecipeFamily.EXTERN_RUN_PAIR,
        {
            "emission_policy": "non_emitting_declarations_only",
            "generated_header_sha256": Digest.from_bytes(b"".join(pieces)).value,
            "header_count": header,
            "header_prefix": "g_h",
            "seat_count": seat,
            "seat_prefix": "g_p",
            "width": 2,
        },
    )


def _run_with_shape_donor(
    count: int = 12, classes: int = 2, functions: int = 5, *, cross: bool = False
) -> ClassicRecipeIntervention:
    parameters: dict[str, JsonValue] = {
        "classes": classes,
        "count": count,
        "emission_policy": "non_emitting_declarations_only",
        "functions": functions,
        "generated_header_sha256": Digest.from_bytes(
            generate_forward_run("Rk", count, 2) + generate_declaration_shape(classes, functions)
        ).value,
        "placement": "prefix",
        "prefix": "Rk",
        "width": 2,
    }
    if cross:
        parameters.update(
            {
                "donor_source": "src/other.cpp",
                "donor_effective_source_sha256": "1" * 64,
                "rendered_source_sha256": "2" * 64,
                "rendered_source_size": 10,
                "rendered_source_line_count": 1,
                "role_policy": "cross_tu_complete_target_only_v1",
            }
        )
    return _donor(ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE, parameters)


def _knob_values(candidates: tuple[object, ...], name: str) -> list[object]:
    values: list[object] = []
    for candidate in candidates:
        for change in candidate.changes:  # type: ignore[attr-defined]
            if change.path == ("parameters", name):
                values.append(change.after)
    return values


def test_forward_declaration_run_retunes_its_count_by_distance() -> None:
    candidates = enumerate_donor_retune_candidates(_forward_run_donor(), radius=3)
    assert [candidate.distance for candidate in candidates] == [1, 1, 2, 2, 3, 3]
    assert _knob_values(candidates, "count") == [31, 33, 30, 34, 29, 35]
    for candidate in candidates:
        parameters = _parameters(candidate.intervention)
        assert (
            parameters["generated_header_sha256"]
            == Digest.from_bytes(
                generate_forward_run("MxUnkRecVC", cast(int, parameters["count"]), 3)
            ).value
        )
        assert {change.kind for change in candidate.changes} == {"knob", "derived"}
    # A count of one cannot go lower and the width bounds the upper end.
    low = enumerate_donor_retune_candidates(_forward_run_donor(1), radius=1)
    assert _knob_values(low, "count") == [2]
    high = enumerate_donor_retune_candidates(_forward_run_donor(999), radius=1)
    assert _knob_values(high, "count") == [998]


def test_pad_shape_retunes_both_knobs_on_manhattan_shells() -> None:
    candidates = enumerate_donor_retune_candidates(_pad_donor(), radius=1)
    shapes = {
        (
            cast(int, _parameters(candidate.intervention)["classes"]),
            cast(int, _parameters(candidate.intervention)["functions_per_class"]),
        )
        for candidate in candidates
    }
    assert shapes == {(1, 3), (2, 2), (2, 4), (3, 3)}
    corner = enumerate_donor_retune_candidates(_pad_donor(1, 1), radius=1)
    assert {
        (
            _parameters(candidate.intervention)["classes"],
            _parameters(candidate.intervention)["functions_per_class"],
        )
        for candidate in corner
    } == {(1, 2), (2, 1)}


def test_extern_run_pair_retunes_counts_but_never_empties_both_runs() -> None:
    candidates = enumerate_donor_retune_candidates(_extern_pair_donor(1, 0), radius=1)
    pairs = {
        (
            _parameters(candidate.intervention)["header_count"],
            _parameters(candidate.intervention)["seat_count"],
        )
        for candidate in candidates
    }
    assert pairs == {(2, 0), (1, 1)}
    for candidate in candidates:
        parameters = _parameters(candidate.intervention)
        pieces = [
            generate_extern_run(prefix, cast(int, parameters[f"{seat}_count"]), 2)
            for seat, prefix in (("header", "g_h"), ("seat", "g_p"))
            if parameters[f"{seat}_count"]
        ]
        assert parameters["generated_header_sha256"] == Digest.from_bytes(b"".join(pieces)).value


def test_forward_run_with_shape_retunes_count_then_shape_per_distance() -> None:
    candidates = enumerate_donor_retune_candidates(_run_with_shape_donor(), radius=1)
    described = [
        tuple(
            (change.path[-1], change.after) for change in candidate.changes if change.kind == "knob"
        )
        for candidate in candidates
    ]
    # Count knob first, then the shape shell in sorted (classes, functions) order.
    assert described == [
        (("count", 11),),
        (("count", 13),),
        (("classes", 1),),
        (("functions", 4),),
        (("functions", 6),),
        (("classes", 3),),
    ]
    materialized = materialize_donor_retune_candidate(
        candidates[0],
        _receipt(_run_with_shape_donor(), {}),
    )
    assert materialized.intervention == candidates[0].intervention


def test_cross_tu_forward_run_with_shape_is_refused_not_guessed() -> None:
    with pytest.raises(DonorRetuneError, match="re-rendering"):
        enumerate_donor_retune_candidates(_run_with_shape_donor(cross=True), radius=1)


def test_new_family_materialization_authenticates_the_saved_digest() -> None:
    for donor in (_forward_run_donor(), _pad_donor(), _extern_pair_donor()):
        candidate = enumerate_donor_retune_candidates(donor, radius=1)[0]
        materialized = materialize_donor_retune_candidate(candidate, _receipt(donor, {}))
        assert materialized.intervention == candidate.intervention
        assert materialized.receipt == _receipt(donor, {})
        stale = _parameters(donor)
        stale["generated_header_sha256"] = "0" * 64
        with pytest.raises(DonorRetuneError, match="digest differs"):
            enumerate_donor_retune_candidates(
                donor.model_copy(
                    update={
                        "parameters": tuple(
                            ClassicField(name=name, value=value)
                            for name, value in sorted(stale.items())
                        )
                    }
                ),
                radius=1,
            )


def test_radius_up_to_sixty_four_is_bounded_not_refused() -> None:
    candidates = enumerate_donor_retune_candidates(_forward_run_donor(100), radius=64, limit=4096)
    assert len(candidates) == 128
    assert max(candidate.distance for candidate in candidates) == 64


def test_overlay_materialization_renders_a_two_knob_move_with_its_canvas() -> None:
    saved, receipt, clean_sources, canonical_operations = _materializable_two_op_overlay_donor()
    candidates = enumerate_donor_retune_candidates(saved, radius=2)
    pair = next(
        c
        for c in candidates
        if [(x.path[4], x.after) for x in c.changes if x.kind == "knob"] == [(0, 3), (1, 3)]
    )

    materialized = materialize_donor_retune_candidate(
        pair,
        receipt,
        clean_sources=clean_sources,
        canonical_overlay_operations=canonical_operations,
    )

    assert materialized.distance == 2
    assert [(c.kind, c.path[-1]) for c in materialized.changes] == [
        ("knob", "count"),
        ("knob", "count"),
        ("derived", "lines"),
        ("derived", "renderings[0].rendered_sha256"),
        ("derived", "rendering_identity_sha256"),
    ]
    parameters = _parameters(materialized.intervention)
    renderings = cast(list[JsonValue], parameters["renderings"])
    operations = cast(list[JsonValue], cast(dict[str, JsonValue], renderings[0])["operations"])
    forwards = cast(dict[str, JsonValue], cast(dict[str, JsonValue], operations[1])["gen"])
    assert (forwards["lines"], cast(list[Any], forwards["items"])[0]["count"]) == (3, 3)
    fresh = render_classic_overlay_proposal(
        [
            {
                "path": "src/main.cpp",
                "clean": Digest.from_bytes(clean_sources["src/main.cpp"]).value,
                "effective": "0" * 64,
                "ops": [*deepcopy(canonical_operations), *deepcopy(operations)],
            }
        ],
        clean_sources,
    ).outputs["src/main.cpp"]
    assert fresh.count(b"extern int g_h") == 3
    assert fresh.count(b"class Fwd") == 3
    assert materialized.receipt.expected_values["renderings[0].rendered_sha256"] == (
        Digest.from_bytes(fresh).value
    )
    assert (
        parameters["rendering_identity_sha256"] != _parameters(saved)["rendering_identity_sha256"]
    )


def _relabelled(candidate: DonorRetuneCandidate) -> DonorRetuneCandidate:
    """The same parameters, but every change claims to be derived: no knob moved."""

    return replace(candidate, changes=tuple(replace(c, kind="derived") for c in candidate.changes))


def _with_foreign_derived_change(candidate: DonorRetuneCandidate) -> DonorRetuneCandidate:
    parameters = _parameters(candidate.intervention)
    parameters["include_projection"] = "source_root_mirror_v1"
    return replace(
        candidate,
        intervention=_copy_with_parameters(candidate.intervention, parameters),
        changes=(
            *candidate.changes,
            DonorRetuneChange(
                ("parameters", "include_projection"),
                "source_root_mirror_only_v1",
                "source_root_mirror_v1",
                "derived",
            ),
        ),
    )


def _with_prefix_knob(candidate: DonorRetuneCandidate) -> DonorRetuneCandidate:
    parameters = _parameters(candidate.intervention)
    renderings = cast(list[Any], parameters["renderings"])
    item = renderings[0]["operations"][0]["gen"]["items"][0]
    item["count"] = candidate.changes[0].before  # undo the count move
    item["prefix"] = "g_x"
    return replace(
        candidate,
        intervention=_copy_with_parameters(candidate.intervention, parameters),
        changes=(DonorRetuneChange((*candidate.changes[0].path[:8], "prefix"), "g_h", "g_x"),),
    )


@pytest.mark.parametrize(
    ("mutate", "message"),
    (
        (_relabelled, "one or two admitted knobs"),
        (_with_foreign_derived_change, "outside its layout"),
        (lambda c: replace(c, distance=c.distance + 1), "total knob movement"),
        (_with_prefix_knob, "bounded declaration-run count"),
    ),
)
def test_overlay_materialization_refuses_moves_outside_the_admitted_shape(
    mutate: Callable[[DonorRetuneCandidate], DonorRetuneCandidate], message: str
) -> None:
    saved, receipt, clean_sources, canonical_operations = _materializable_two_op_overlay_donor()
    candidate = enumerate_donor_retune_candidates(saved, radius=1)[0]

    with pytest.raises(DonorRetuneError, match=message):
        materialize_donor_retune_candidate(
            mutate(candidate),
            receipt,
            clean_sources=clean_sources,
            canonical_overlay_operations=canonical_operations,
        )


def test_overlay_single_moves_at_every_distance_precede_pair_moves() -> None:
    candidates = enumerate_donor_retune_candidates(_overlay_donor(), radius=4, limit=4096)

    knob_counts = [sum(c.kind == "knob" for c in candidate.changes) for candidate in candidates]
    first_pair = knob_counts.index(2)
    assert set(knob_counts[:first_pair]) == {1}
    assert set(knob_counts[first_pair:]) == {2}
    singles = candidates[:first_pair]
    assert [c.distance for c in singles] == sorted(c.distance for c in singles)
    assert max(c.distance for c in singles) == 4
    pairs = candidates[first_pair:]
    assert [c.distance for c in pairs] == sorted(c.distance for c in pairs)
    assert (pairs[0].distance, pairs[-1].distance) == (2, 4)


def test_overlay_insertion_candidates_follow_the_singles_of_their_distance() -> None:
    saved, _receipt, clean_sources, _operations = _materializable_overlay_donor()

    without = enumerate_donor_retune_candidates(saved, radius=2, limit=64)
    with_sources = enumerate_donor_retune_candidates(
        saved, radius=2, limit=64, carrier_sources=clean_sources
    )

    assert [c.changes[0].kind for c in without] == ["knob"] * len(without)
    kinds = [(c.distance, c.changes[0].kind) for c in with_sources]
    # distance 1: the two singles of the extern-run knob, then end and start insertions
    assert kinds[:4] == [(1, "knob"), (1, "knob"), (1, "insert"), (1, "insert")]
    assert (2, "insert") in kinds
    inserted = [c for c in with_sources if c.changes[0].kind == "insert"]
    assert [json.loads(str(c.changes[0].after))["anchor"]["at"] for c in inserted[:2]] == [
        "end",
        "start",
    ]
    end_candidate = inserted[0]
    change = end_candidate.changes[0]
    assert change.path == ("parameters", "renderings", 0, "operations", 1)
    assert change.before == ""
    operation = json.loads(str(change.after))
    assert operation["id"] == "op_rbit_carrier_end"
    assert operation["gen"] == {
        "items": [
            {
                "count": 1,
                "first": 0,
                "k": "fwd_run",
                "line": 1,
                "stem": "RbCarrierRun",
                "width": 3,
            }
        ],
        "k": "seq",
        "lines": 1,
    }
    renderings = _parameters(end_candidate.intervention)["renderings"]
    assert isinstance(renderings, list)
    assert renderings[0]["operations"][1] == operation  # type: ignore[index]
    # The distance-2 insertion carries two names on a two-line canvas.
    two = next(c for c in inserted if c.distance == 2)
    assert json.loads(str(two.changes[0].after))["gen"]["lines"] == 2
    assert json.loads(str(two.changes[0].after))["gen"]["items"][0]["count"] == 2
    # A donor that already carries an inserted run offers no second insertion.
    again = enumerate_donor_retune_candidates(
        end_candidate.intervention, radius=1, limit=64, carrier_sources=clean_sources
    )
    assert all(c.changes[0].kind == "knob" for c in again)
    assert any(c.changes[0].path[-1] == "count" and c.changes[0].path[4] == 1 for c in again)


def test_overlay_insertion_materializes_with_its_run_rendered_at_the_boundary() -> None:
    saved, receipt, clean_sources, canonical_operations = _materializable_overlay_donor()
    candidates = enumerate_donor_retune_candidates(
        saved, radius=2, limit=64, carrier_sources=clean_sources
    )
    end_candidate = next(c for c in candidates if c.changes[0].kind == "insert" and c.distance == 2)
    start_candidate = next(
        c
        for c in candidates
        if c.changes[0].kind == "insert"
        and json.loads(str(c.changes[0].after))["anchor"]["at"] == "start"
    )

    materialized = materialize_donor_retune_candidate(
        end_candidate,
        receipt,
        clean_sources=clean_sources,
        canonical_overlay_operations=canonical_operations,
    )

    assert [change.kind for change in materialized.changes] == ["insert", "derived", "derived"]
    assert materialized.distance == 2
    rendered_pin = materialized.receipt.expected_values["renderings[0].rendered_sha256"]
    assert rendered_pin != receipt.expected_values["renderings[0].rendered_sha256"]
    parameters = _parameters(materialized.intervention)
    assert (
        parameters["rendering_identity_sha256"] != _parameters(saved)["rendering_identity_sha256"]
    )
    operations = parameters["renderings"][0]["operations"]  # type: ignore[index]
    assert [op["id"] for op in operations] == ["op_donor_declarations", "op_rbit_carrier_end"]  # type: ignore[index]

    from reprobit.classic.overlay_document import render_classic_overlay_proposal

    rendered = render_classic_overlay_proposal(
        [
            {
                "path": "src/main.cpp",
                "clean": Digest.from_bytes(clean_sources["src/main.cpp"]).value,
                "effective": rendered_pin,
                "ops": [*canonical_operations, *operations],
            }
        ],
        clean_sources,
    ).outputs["src/main.cpp"]
    assert rendered.endswith(b"class RbCarrierRun000;\nclass RbCarrierRun001;\n")
    assert Digest.from_bytes(rendered).value == rendered_pin

    started = materialize_donor_retune_candidate(
        start_candidate,
        receipt,
        clean_sources=clean_sources,
        canonical_overlay_operations=canonical_operations,
    )
    assert started.changes[0].kind == "insert"


def test_overlay_insertion_is_refused_when_mixed_with_knob_moves_or_misdescribed() -> None:
    from reprobit.classic_donor_retune_candidates import DonorRetuneCandidate, DonorRetuneChange

    saved, receipt, clean_sources, canonical_operations = _materializable_overlay_donor()
    candidates = enumerate_donor_retune_candidates(
        saved, radius=1, limit=64, carrier_sources=clean_sources
    )
    knob = next(c for c in candidates if c.changes[0].kind == "knob")
    inserted = next(c for c in candidates if c.changes[0].kind == "insert")

    from reprobit.classic_donor_retune_materialization import _replace_candidate_path

    knob_change = next(change for change in knob.changes if change.kind == "knob")
    mixed_intervention = _replace_candidate_path(
        inserted.intervention,
        knob_change.path,
        expected=knob_change.before,
        replacement=knob_change.after,
    )
    mixed = DonorRetuneCandidate(mixed_intervention, 2, (knob_change, *inserted.changes))
    with pytest.raises(DonorRetuneError, match="only change"):
        materialize_donor_retune_candidate(
            mixed,
            receipt,
            clean_sources=clean_sources,
            canonical_overlay_operations=canonical_operations,
        )

    wrong_distance = DonorRetuneCandidate(inserted.intervention, 2, inserted.changes)
    with pytest.raises(DonorRetuneError, match="candidate distance"):
        materialize_donor_retune_candidate(
            wrong_distance,
            receipt,
            clean_sources=clean_sources,
            canonical_overlay_operations=canonical_operations,
        )

    misdescribed = DonorRetuneCandidate(
        inserted.intervention,
        1,
        (
            DonorRetuneChange(
                inserted.changes[0].path,
                "",
                json.dumps(
                    {
                        "anchor": {"at": "end", "ctx": "0" * 64},
                        "gen": {
                            "k": "seq",
                            "items": [
                                {"k": "fwd_run", "count": 1, "line": 1, "stem": "X", "first": 0}
                            ],
                            "lines": 1,
                        },
                        "id": "other",
                        "op": "insert",
                    }
                ),
                "insert",
            ),
        ),
    )
    with pytest.raises(DonorRetuneError, match="does not describe its operation"):
        materialize_donor_retune_candidate(
            misdescribed,
            receipt,
            clean_sources=clean_sources,
            canonical_overlay_operations=canonical_operations,
        )


def test_declaration_run_triple_moves_two_seats_together_after_their_singles() -> None:
    intervention = _triple_donor()

    candidates = enumerate_donor_retune_candidates(intervention, radius=2, limit=4096)

    def knobs(candidate: DonorRetuneCandidate) -> int:
        return sum(change.kind == "knob" for change in candidate.changes)

    by_distance: dict[int, list[int]] = {}
    for candidate in candidates:
        by_distance.setdefault(candidate.distance, []).append(knobs(candidate))
    assert by_distance[1] == [1] * 6
    # Distance 2: the six single-seat moves first, then every two-seat move (3 pairs by 4 signs).
    assert by_distance[2][:6] == [1] * 6
    assert by_distance[2][6:] == [2] * 12
    pair = next(candidate for candidate in candidates if knobs(candidate) == 2)
    states = _parameters(pair.intervention)
    assert (states["pre_count"], states["post_count"], states["eof_count"]) == (3, 2, 8)
    assert [change.path[-1] for change in pair.changes] == [
        "pre_count",
        "post_count",
        "generated_header_sha256",
    ]
    assert pair.changes[-1].kind == "derived"


def test_overlay_insertions_continue_past_the_retune_radius() -> None:
    saved, receipt, clean_sources, canonical_operations = _materializable_overlay_donor()

    candidates = enumerate_donor_retune_candidates(
        saved, radius=2, limit=4096, carrier_sources=clean_sources
    )

    inserted = [c for c in candidates if c.changes[0].kind == "insert"]
    counts = sorted({c.distance for c in inserted})
    assert counts[:3] == [1, 2, 3] and counts[-1] == 500
    # Knob moves and pairs of the radius all precede the longer runs.
    last_knob = max(i for i, c in enumerate(candidates) if c.changes[0].kind == "knob")
    first_long = min(i for i, c in enumerate(candidates) if c.distance > 2)
    assert last_knob < first_long
    long_run = next(c for c in inserted if c.distance == 40)
    materialized = materialize_donor_retune_candidate(
        long_run,
        receipt,
        clean_sources=clean_sources,
        canonical_overlay_operations=canonical_operations,
    )
    assert materialized.distance == 40
    assert json.loads(str(materialized.changes[0].after))["gen"]["lines"] == 40
