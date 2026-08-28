from __future__ import annotations

from dataclasses import replace

import pytest

from reprobit.classic_identity_migration import (
    ClassicIdentityMigrationError,
    DeclarationIdentityRequest,
    preview_declaration_identities,
)


def _request(
    identifier: str = "FreshRecord00",
    *,
    target: str = "program",
    source: str = "src/unit.cpp",
    operation: str = "op_records",
) -> DeclarationIdentityRequest:
    return DeclarationIdentityRequest(target, source, operation, identifier)


def test_preview_is_canonical_deterministic_and_same_length() -> None:
    first = _request("FreshRecord00", source="src/first.cpp")
    second = _request("FreshRecord01", source="src/second.cpp")
    occupied = {
        "program": (
            "CleanRecord",
            first.original_identifier,
            second.original_identifier,
        )
    }

    forward = preview_declaration_identities((first, second), occupied_by_target=occupied)
    reverse = preview_declaration_identities((second, first), occupied_by_target=occupied)

    assert forward == reverse
    assert forward.algorithm == "classic-target-unique-same-length-identifier-v1"
    assert forward.occupied_census_digest.value
    assert [item.source_path for item in forward.migrations] == [
        "src/first.cpp",
        "src/second.cpp",
    ]
    replacements = {item.replacement_identifier.casefold() for item in forward.migrations}
    assert len(replacements) == 2
    for item in forward.migrations:
        assert len(item.replacement_identifier) == len(item.original_identifier)
        assert item.replacement_identifier.casefold() not in {
            value.casefold() for value in occupied["program"]
        }
        assert item.derivation_digest.value
    assert forward.statement_digest.value


def test_preview_skips_a_casefold_collision_from_the_complete_target_census() -> None:
    request = _request("QqM0")
    initial = preview_declaration_identities(
        (request,), occupied_by_target={"program": (request.original_identifier,)}
    ).migrations[0]

    changed = preview_declaration_identities(
        (request,),
        occupied_by_target={
            "program": (
                request.original_identifier,
                initial.replacement_identifier.swapcase(),
            )
        },
    ).migrations[0]

    assert changed.replacement_identifier.casefold() != initial.replacement_identifier.casefold()


def test_preview_binds_target_source_operation_and_candidate_round() -> None:
    request = _request("QqM0")
    occupied = {"program": (request.original_identifier,)}
    baseline = preview_declaration_identities((request,), occupied_by_target=occupied)
    next_round = preview_declaration_identities(
        (request,), occupied_by_target=occupied, candidate_round=1
    )
    moved = preview_declaration_identities(
        (replace(request, source_path="src/other.cpp"),),
        occupied_by_target=occupied,
    )

    assert baseline.statement_digest != next_round.statement_digest
    assert baseline.statement_digest != moved.statement_digest
    assert next_round.migrations[0].candidate_round == 1


def test_preview_binds_the_complete_occupied_census() -> None:
    input_request = _request("QqM0")
    baseline = preview_declaration_identities(
        (input_request,), occupied_by_target={"program": ("QqM0",)}
    )
    expanded = preview_declaration_identities(
        (input_request,),
        occupied_by_target={"program": ("QqM0", "AnotherRecord")},
    )

    assert baseline.occupied_census_digest != expanded.occupied_census_digest
    assert baseline.statement_digest != expanded.statement_digest


@pytest.mark.parametrize(
    ("input_request", "occupied", "message"),
    (
        (_request("_Reserved"), {"program": ()}, "non-reserved"),
        (_request("class"), {"program": ()}, "non-reserved"),
        (
            _request(source="../unit.cpp"),
            {"program": ()},
            "portable relative path",
        ),
        (_request(), {}, "no complete exposure census"),
    ),
)
def test_preview_rejects_malformed_or_incomplete_authority(
    input_request: DeclarationIdentityRequest,
    occupied: dict[str, tuple[str, ...]],
    message: str,
) -> None:
    with pytest.raises(ClassicIdentityMigrationError, match=message):
        preview_declaration_identities((input_request,), occupied_by_target=occupied)


def test_preview_rejects_duplicate_requests_and_casefold_occupied_aliases() -> None:
    request = _request()
    with pytest.raises(ClassicIdentityMigrationError, match="duplicated"):
        preview_declaration_identities(
            (request, request),
            occupied_by_target={"program": (request.original_identifier,)},
        )
    with pytest.raises(ClassicIdentityMigrationError, match="casefold collision"):
        preview_declaration_identities(
            (request,),
            occupied_by_target={"program": ("CleanRecord", "cleanrecord")},
        )


def test_preview_rejects_an_original_absent_from_the_target_census() -> None:
    with pytest.raises(ClassicIdentityMigrationError, match="is absent"):
        preview_declaration_identities(
            (_request("FreshRecord"),),
            occupied_by_target={"program": ("OtherRecord",)},
        )
