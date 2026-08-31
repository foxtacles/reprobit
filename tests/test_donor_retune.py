from __future__ import annotations

import json
from copy import deepcopy
from hashlib import sha256
from typing import cast

import pytest

from reprobit.classic.donor_retune_candidates import (
    DonorRetuneError,
    enumerate_donor_retune_candidates,
)
from reprobit.classic.donor_retune_materialization import (
    materialize_donor_retune_candidate,
)
from reprobit.classic_donors import generate_declaration_shape, generate_forward_run
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


def test_overlay_changes_one_existing_sequence_declaration_count_per_candidate() -> None:
    intervention = _overlay_donor()
    before_model = intervention.model_dump(mode="json")
    before_parameters = deepcopy(_parameters(intervention))

    candidates = enumerate_donor_retune_candidates(intervention, radius=2)

    observed = [
        (
            candidate.distance,
            candidate.changes[0].path,
            candidate.changes[0].before,
            candidate.changes[0].after,
        )
        for candidate in candidates
    ]
    header_path = candidates[0].changes[0].path
    forward_path = candidates[2].changes[0].path
    seat_path = candidates[4].changes[0].path
    assert observed == [
        (1, header_path, 2, 1),
        (1, header_path, 2, 3),
        (1, forward_path, 8, 7),
        (1, forward_path, 8, 9),
        (1, seat_path, 1, 2),
        (2, header_path, 2, 4),
        (2, forward_path, 8, 6),
        (2, forward_path, 8, 10),
        (2, seat_path, 1, 3),
    ]
    assert forward_path == (
        "parameters",
        "renderings",
        0,
        "operations",
        2,
        "gen",
        "items",
        0,
        "count",
    )
    assert intervention.model_dump(mode="json") == before_model
    for candidate in candidates:
        assert len(candidate.changes) == 1
        change = candidate.changes[0]
        assert change.kind == "knob"
        assert abs(cast(int, change.after) - cast(int, change.before)) == candidate.distance
        assert _json_leaf_differences(
            before_parameters, _parameters(candidate.intervention), ("parameters",)
        ) == [(change.path, change.before, change.after)]
        assert candidate.intervention.id == intervention.id
        assert candidate.intervention.rationale == intervention.rationale
        assert candidate.intervention.dependencies == intervention.dependencies
        assert candidate.intervention.beneficiaries == intervention.beneficiaries


def test_overlay_enumeration_is_deterministic_and_strictly_bounded() -> None:
    intervention = _overlay_donor()

    first = enumerate_donor_retune_candidates(intervention, limit=3)
    second = enumerate_donor_retune_candidates(intervention, limit=3)

    assert first == second
    assert len(first) == 3
    with pytest.raises(DonorRetuneError, match="radius"):
        enumerate_donor_retune_candidates(intervention, radius=9)
    with pytest.raises(DonorRetuneError, match="limit"):
        enumerate_donor_retune_candidates(intervention, limit=65)
    with pytest.raises(DonorRetuneError, match="radius"):
        enumerate_donor_retune_candidates(intervention, radius=True)


def test_eligible_malformed_donor_is_refused_and_other_families_are_ignored() -> None:
    stale = _declaration_donor()
    stale_parameters = _parameters(stale)
    stale_parameters["generated_header_sha256"] = "0" * 64
    stale = _donor(ClassicRecipeFamily.DECLARATION_SHAPE, stale_parameters)
    unsupported = _donor(
        ClassicRecipeFamily.PAD_SHAPE,
        {
            "classes": 2,
            "emission_policy": "non_emitting_declarations_only",
            "functions_per_class": 3,
            "generated_header_sha256": "0" * 64,
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
