from __future__ import annotations

import json
from hashlib import sha256
from typing import Any, cast

import pytest

from reprobit.classic_donors import (
    DONOR_FAMILIES,
    DonorCompileRequest,
    DonorIncludeProjection,
    DonorSourceError,
    donor_overlay_clean_input_pins,
    generate_declaration_shape,
    generate_extern_run,
    generate_forward_run,
    generate_pad_shape,
    matching_candidate_constraints,
    merge_candidate_constraints,
    prepare_donor_compile_request,
    validate_donor_recipe,
)
from reprobit.model import Scope
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)


def _digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def _intervention(
    family: ClassicRecipeFamily, parameters: dict[str, Any]
) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id="donor_sample",
        scope=Scope(target="sample", translation_unit="unit"),
        rationale=("Framework-owned declaration-only compiler state changes no program payload."),
        family=family,
        role=ClassicRecipeRole.DONOR,
        build_target="sample",
        parameters=tuple(
            ClassicField(name=name, value=value) for name, value in sorted(parameters.items())
        ),
    )


def _receipt(
    family: ClassicRecipeFamily, expected: dict[str, Any] | None = None
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id="proof_sample",
        intervention_id="donor_sample",
        family=family,
        expected_values=expected or {},
    )


def _carrier_parameters(generated: bytes, **values: Any) -> dict[str, Any]:
    digest = _digest(generated)
    return {
        "emission_policy": "non_emitting_declarations_only",
        "generated_header_sha256": digest,
        **values,
    }


def _seat_proof(source: bytes) -> dict[str, Any]:
    physical = source.splitlines(keepends=True)
    include_index = next(
        index for index, line in enumerate(physical) if line.startswith(b"#include")
    )
    seat = sum(len(line) for line in physical[: include_index + 1])
    first_end = source.index(b"\n")
    return {
        "kind": "prefix_and_after_last_include_seats_v1",
        "prefix_offset": 0,
        "prefix_input_sha256": _digest(b""),
        "prefix_following_line_sha256": _digest(source[: first_end + 1]),
        "prefix_context_sha256": _digest(source[:64]),
        "after_includes_offset": seat,
        "preceding_line_sha256": _digest(physical[include_index]),
        "following_line_sha256": _digest(physical[include_index + 1]),
        "centered_context_sha256": _digest(source[seat - 32 : seat + 32]),
    }


def _ordinary_cases(source: bytes) -> list[ClassicRecipeIntervention]:
    shape = generate_declaration_shape(2, 3)
    pad = generate_pad_shape(2, 2)
    forward = generate_forward_run("Spare", 3, 2)
    header = generate_extern_run("g_head", 2, 2)
    seat = generate_extern_run("g_tail", 2, 2)
    stacked_forward = generate_forward_run("Stacked", 2, 2)
    triple = b"".join(generate_forward_run(prefix, 1, 1) for prefix in ("Pre", "Post", "End"))
    mixed_forward = generate_forward_run("Mixed", 2, 2)
    mixed_extern = generate_extern_run("g_mixed", 2, 2)
    mixed_rendered = mixed_forward + source.split(b"#include", maxsplit=1)[0]
    # The actual mixed rendering is calculated explicitly using the authenticated seat.
    lines = source.split(b"\n")
    include_row = next(index for index, line in enumerate(lines) if line.startswith(b"#include"))
    extern_lines = mixed_extern.rstrip(b"\n").split(b"\n")
    mixed_rendered = mixed_forward + b"\n".join(
        lines[: include_row + 1] + extern_lines + lines[include_row + 1 :]
    )
    return [
        _intervention(
            ClassicRecipeFamily.DECLARATION_SHAPE,
            _carrier_parameters(shape, classes=2, functions=3),
        ),
        _intervention(
            ClassicRecipeFamily.PAD_SHAPE,
            _carrier_parameters(pad, classes=2, functions_per_class=2),
        ),
        _intervention(
            ClassicRecipeFamily.FORWARD_DECLARATION_RUN,
            _carrier_parameters(forward, placement="prefix", prefix="Spare", count=3, width=2),
        ),
        _intervention(
            ClassicRecipeFamily.EXTERN_RUN_PAIR,
            _carrier_parameters(
                header + seat,
                header_prefix="g_head",
                header_count=2,
                seat_prefix="g_tail",
                seat_count=2,
                width=2,
            ),
        ),
        _intervention(
            ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE,
            _carrier_parameters(
                stacked_forward + shape,
                placement="suffix",
                prefix="Stacked",
                count=2,
                width=2,
                classes=2,
                functions=3,
            ),
        ),
        _intervention(
            ClassicRecipeFamily.DECLARATION_RUN_TRIPLE,
            _carrier_parameters(
                triple,
                width=1,
                pre_prefix="Pre",
                pre_count=1,
                post_prefix="Post",
                post_count=1,
                eof_prefix="End",
                eof_count=1,
            ),
        ),
        _intervention(
            ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN,
            _carrier_parameters(
                mixed_forward + mixed_extern,
                forward_prefix="Mixed",
                forward_count=2,
                forward_width=2,
                extern_prefix="g_mixed",
                extern_count=2,
                extern_width=2,
                seat_proof=_seat_proof(source),
                rendered_source_sha256=_digest(mixed_rendered),
                rendered_source_size=len(mixed_rendered),
                rendered_source_line_count=mixed_rendered.count(b"\n"),
            ),
        ),
    ]


def test_all_declaration_carrier_families_produce_closed_requests() -> None:
    source = (
        b"// prefix witness with enough bytes to authenticate the exact first seat\n"
        b'#include "sample.h"\n' + b"int sample_value = 0;\n" * 8
    )
    interventions = _ordinary_cases(source)

    requests = [
        prepare_donor_compile_request(
            intervention,
            source_path="src/unit.cpp",
            clean_source=source,
            effective_source=source,
            receipts=[_receipt(intervention.family)],
        )
        for intervention in interventions
    ]

    assert {request.family for request in requests} == DONOR_FAMILIES - {
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY
    }
    assert all(request.staged_source == "s.cpp" for request in requests)
    assert all(request.intervention_id == "donor_sample" for request in requests)
    for intervention, request in zip(interventions, requests, strict=True):
        carrier_identity = cast(
            str,
            next(
                field.value
                for field in intervention.parameters
                if field.name == "generated_header_sha256"
            ),
        )
        assert request.compiler_seat == f"d_{carrier_identity[:12]}"
    assert all("s.cpp" in request.files for request in requests)
    assert all("source.cpp" not in request.files for request in requests)
    assert all(request.receipt.output_digests for request in requests)
    by_family = {request.family: request for request in requests}
    assert by_family[ClassicRecipeFamily.PAD_SHAPE].carrier_identifiers == frozenset(
        {
            "ClassPad00",
            "ClassPad01",
            "FunctionPad00x00",
            "FunctionPad00x01",
            "FunctionPad01x00",
            "FunctionPad01x01",
        }
    )
    assert by_family[ClassicRecipeFamily.FORWARD_DECLARATION_RUN].carrier_identifiers == frozenset(
        {"Spare00", "Spare01", "Spare02"}
    )
    assert all(isinstance(request.carrier_identifiers, frozenset) for request in requests)
    assert all(request.carrier_identifiers for request in requests)
    assert all(not hasattr(request.compiler_additions, "required_define") for request in requests)
    force_include_families = {
        ClassicRecipeFamily.DECLARATION_SHAPE,
        ClassicRecipeFamily.PAD_SHAPE,
        ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE,
    }
    assert {
        request.family for request in requests if request.compiler_additions.force_includes
    } == force_include_families
    assert all(
        request.compiler_additions.force_includes == ("run.h",) and "run.h" in request.files
        for request in requests
        if request.family in force_include_families
    )


def test_donor_authority_rejects_the_removed_define_lane_selector() -> None:
    generated = generate_declaration_shape(1, 1)
    parameters = _carrier_parameters(generated, classes=1, functions=1)
    parameters["compile_lane"] = {"required_define": "SAMPLE_BUILD"}
    intervention = _intervention(ClassicRecipeFamily.DECLARATION_SHAPE, parameters)

    with pytest.raises(DonorSourceError, match="unknown=\\['compile_lane'\\]"):
        validate_donor_recipe(
            intervention,
            matching_candidate_constraints(
                intervention,
                [_receipt(intervention.family)],
            ),
        )


def test_donor_compiler_target_is_bound_into_its_receipt() -> None:
    source = b"int fixture;\n"
    generated = generate_declaration_shape(1, 1)
    intervention = _intervention(
        ClassicRecipeFamily.DECLARATION_SHAPE,
        _carrier_parameters(generated, classes=1, functions=1),
    )
    cross_target = intervention.model_copy(update={"build_target": "config"})

    owner_request = prepare_donor_compile_request(
        intervention,
        source_path="src/unit.cpp",
        clean_source=source,
        effective_source=source,
        receipts=[_receipt(intervention.family)],
    )
    cross_target_request = prepare_donor_compile_request(
        cross_target,
        source_path="src/unit.cpp",
        clean_source=source,
        effective_source=source,
        receipts=[_receipt(cross_target.family)],
    )

    assert owner_request.compiler_seat == cross_target_request.compiler_seat
    assert owner_request.files == cross_target_request.files
    assert (
        owner_request.receipt.compiler_additions_digest
        != cross_target_request.receipt.compiler_additions_digest
    )


def test_donor_authority_rejects_the_removed_legacy_recipe_identity() -> None:
    generated = generate_declaration_shape(1, 1)
    parameters = _carrier_parameters(generated, classes=1, functions=1)
    parameters["legacy_recipe_id"] = "d_obsolete"
    intervention = _intervention(ClassicRecipeFamily.DECLARATION_SHAPE, parameters)

    with pytest.raises(DonorSourceError, match="unknown=\\['legacy_recipe_id'\\]"):
        validate_donor_recipe(
            intervention,
            matching_candidate_constraints(
                intervention,
                [_receipt(intervention.family)],
            ),
        )


def _seat_digest(tokens: list[str]) -> str:
    return _digest("\0".join(tokens).encode("ascii"))


def test_donor_private_overlay_uses_the_shared_typed_renderer() -> None:
    source = b"int value;\n"
    header = b"int header_value;\n"
    generated = b"class Spare;\n"
    generated_header = b"class HeaderSpare;\n"
    effective = generated + source
    effective_header = generated_header + header
    operations: list[dict[str, Any]] = [
        {
            "op": "insert",
            "anchor": {
                "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
                "b": 0,
                "a": 3,
                "at": "start",
            },
            "gen": {"k": "fwd", "id": "Spare"},
        }
    ]
    header_operations: list[dict[str, Any]] = [
        {
            "op": "insert",
            "anchor": {
                "ctx": _seat_digest(["<SEAT>", "int", "header_value", ";"]),
                "b": 0,
                "a": 3,
                "at": "start",
            },
            "gen": {"k": "fwd", "id": "HeaderSpare"},
        }
    ]
    renderings = [
        {"path": "src/unit.cpp", "operations": operations},
        {"path": "src/unit.h", "operations": header_operations},
    ]
    identity_claim = [
        {
            "path": "src/unit.cpp",
            "operations": operations,
            "clean_sha256": _digest(source),
            "rendered_sha256": _digest(effective),
        },
        {
            "path": "src/unit.h",
            "operations": header_operations,
            "clean_sha256": _digest(header),
            "rendered_sha256": _digest(effective_header),
        },
    ]
    identity = _digest((json.dumps(identity_claim, indent=2, sort_keys=True) + "\n").encode())
    intervention = _intervention(
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        {
            "emission_policy": "donor_private_rendering_only",
            "include_projection": "source_root_mirror_only_v1",
            "rendering_identity_sha256": identity,
            "renderings": renderings,
        },
    )
    receipt = _receipt(
        intervention.family,
        {
            "renderings[0].clean_sha256": _digest(source),
            "renderings[0].rendered_sha256": _digest(effective),
            "renderings[1].clean_sha256": _digest(header),
            "renderings[1].rendered_sha256": _digest(effective_header),
        },
    )
    pins = donor_overlay_clean_input_pins(intervention, (receipt,))
    assert {path: item.value for path, item in pins.items()} == {
        "src/unit.cpp": _digest(source),
        "src/unit.h": _digest(header),
    }

    request = prepare_donor_compile_request(
        intervention,
        source_path="src/unit.cpp",
        clean_source=source,
        effective_source=source,
        receipts=[receipt],
        clean_sources={"src/unit.cpp": source, "src/unit.h": header},
    )

    assert request.files["s.cpp"] == effective
    assert "inc/source/src/unit.cpp" not in request.files
    assert request.files["inc/source/src/unit.h"] == effective_header
    assert "inc/unit.h" not in request.files
    assert request.compiler_additions.include_projection is (
        DonorIncludeProjection.SOURCE_ROOT_MIRROR_ONLY
    )
    assert request.compiler_additions.include_directories == ("inc", "inc/source/src")
    assert request.carrier_identifiers == frozenset()
    assert request.compiler_seat == f"d_{identity[:12]}"


def _overlay_carrier_request(carrier: dict[str, Any]) -> DonorCompileRequest:
    source = b'#include "sample.h"\nint value;\n'
    effective = b'#include "sample.h"\nclass Spare;\nint value;\n'
    operations = [
        {
            "op": "insert",
            "anchor": {
                "ctx": _seat_digest(["<SEAT>", "int", "value", ";"]),
                "b": 0,
                "a": 3,
                "at": "before_token",
            },
            "gen": {"k": "fwd", "id": "Spare"},
        }
    ]
    rendering = {
        "path": "src/unit.cpp",
        "operations": operations,
        "clean_sha256": _digest(source),
        "rendered_sha256": _digest(effective),
    }
    identity_claim = {
        "renderings": [rendering],
        "compiler_state_carrier": carrier,
    }
    identity = _digest((json.dumps(identity_claim, indent=2, sort_keys=True) + "\n").encode())
    intervention = _intervention(
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        {
            "compiler_state_carrier": carrier,
            "emission_policy": "donor_private_rendering_only",
            "rendering_identity_sha256": identity,
            "renderings": [{"path": "src/unit.cpp", "operations": operations}],
        },
    )
    return prepare_donor_compile_request(
        intervention,
        source_path="src/unit.cpp",
        clean_source=source,
        effective_source=source,
        receipts=[
            _receipt(
                intervention.family,
                {
                    "renderings[0].clean_sha256": _digest(source),
                    "renderings[0].rendered_sha256": _digest(effective),
                },
            )
        ],
        clean_sources={"src/unit.cpp": source},
    )


@pytest.mark.parametrize(
    ("carrier", "expected_identifiers", "force_payload"),
    (
        (
            {
                "kind": "force_included_pad_shape_v1",
                "placement": "force_include_v1",
                "generated_declarations_sha256": _digest(generate_pad_shape(1, 2)),
                "classes": 1,
                "functions_per_class": 2,
            },
            frozenset({"ClassPad00", "FunctionPad00x00", "FunctionPad00x01"}),
            generate_pad_shape(1, 2),
        ),
        (
            {
                "kind": "extern_run_pair_v1",
                "placement": "after_includes_and_eof_v1",
                "generated_declarations_sha256": _digest(
                    generate_extern_run("Head", 2, 2) + generate_extern_run("Seat", 1, 2)
                ),
                "width": 2,
                "header_prefix": "Head",
                "header_count": 2,
                "seat_prefix": "Seat",
                "seat_count": 1,
            },
            frozenset({"Head00", "Head01", "Seat00"}),
            None,
        ),
        (
            {
                "kind": "declaration_run_triple_v1",
                "placement": "start_after_includes_and_eof_v1",
                "generated_declarations_sha256": _digest(
                    generate_forward_run("Pre", 1, 1)
                    + generate_forward_run("Post", 1, 1)
                    + generate_forward_run("End", 1, 1)
                ),
                "width": 1,
                "pre_prefix": "Pre",
                "pre_count": 1,
                "post_prefix": "Post",
                "post_count": 1,
                "eof_prefix": "End",
                "eof_count": 1,
            },
            frozenset({"Pre0", "Post0", "End0"}),
            None,
        ),
    ),
)
def test_overlay_carriers_expose_exact_identifiers(
    carrier: dict[str, Any],
    expected_identifiers: frozenset[str],
    force_payload: bytes | None,
) -> None:
    request = _overlay_carrier_request(carrier)

    assert request.carrier_identifiers == expected_identifiers
    if force_payload is None:
        assert "run.h" not in request.files
    else:
        assert request.files["run.h"] == force_payload


def test_expected_values_merge_deeply_and_remain_immutable() -> None:
    intervention = _intervention(
        ClassicRecipeFamily.DECLARATION_SHAPE,
        _carrier_parameters(
            generate_declaration_shape(1, 1),
            classes=1,
            functions=1,
            observations=[{"name": "sample"}],
        ),
    )
    receipt = _receipt(
        intervention.family,
        {"observations[0].expected_count": 3, "expected_body_sha256": "a" * 64},
    )

    constraints = merge_candidate_constraints(intervention, receipt)
    materialized = constraints.materialize()
    observations = cast(list[dict[str, Any]], materialized["observations"])

    assert observations[0]["expected_count"] == 3
    assert materialized["expected_body_sha256"] == "a" * 64
    with pytest.raises(TypeError):
        constraints.values["new"] = 1  # type: ignore[index]
    observations[0]["expected_count"] = 4
    rematerialized = constraints.materialize()
    assert cast(list[dict[str, Any]], rematerialized["observations"])[0]["expected_count"] == 3


def test_constraint_receipt_cross_checks_identity_family_and_payloads() -> None:
    intervention = _intervention(
        ClassicRecipeFamily.DECLARATION_SHAPE,
        _carrier_parameters(generate_declaration_shape(1, 1), classes=1, functions=1),
    )
    wrong_family = _receipt(ClassicRecipeFamily.PAD_SHAPE)
    with pytest.raises(DonorSourceError, match="family differs"):
        merge_candidate_constraints(intervention, wrong_family)
    with pytest.raises(DonorSourceError, match="payload-shaped"):
        merge_candidate_constraints(
            intervention,
            _receipt(intervention.family, {"nested.oracle_payload": "00"}),
        )
    with pytest.raises(DonorSourceError, match="one proof receipt"):
        matching_candidate_constraints(intervention, [])
