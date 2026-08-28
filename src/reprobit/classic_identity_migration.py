"""Deterministic previews for classic declaration-identity migrations.

This module does not issue semantic evidence and does not edit manifests.  It
only proposes same-length C++ identifiers from explicit project coordinates,
then collision-checks those proposals against a caller-supplied complete
target exposure census.  The normal semantic validator remains responsible
for proving freshness, seating, target exposure, and ODR compatibility of the
rendered result.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

from reprobit.model import Digest
from reprobit.strict_json import canonical_json


class ClassicIdentityMigrationError(ValueError):
    """A deterministic declaration-identity preview cannot be constructed."""


@dataclass(frozen=True, slots=True)
class DeclarationIdentityRequest:
    """One generated spelling that must become unique within a target."""

    target_id: str
    source_path: str
    operation_id: str
    original_identifier: str


@dataclass(frozen=True, slots=True)
class DeclarationIdentityMigration:
    """One auditable, noncertifying identifier substitution proposal."""

    target_id: str
    source_path: str
    operation_id: str
    original_identifier: str
    replacement_identifier: str
    candidate_round: int
    derivation_digest: Digest


@dataclass(frozen=True, slots=True)
class DeclarationIdentityMigrationPreview:
    """Canonical result returned by :func:`preview_declaration_identities`."""

    algorithm: str
    occupied_census_digest: Digest
    migrations: tuple[DeclarationIdentityMigration, ...]
    statement_digest: Digest


_ALGORITHM = "classic-target-unique-same-length-identifier-v1"
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
_CPP_KEYWORDS = frozenset(
    {
        "alignas",
        "alignof",
        "and",
        "and_eq",
        "asm",
        "auto",
        "bitand",
        "bitor",
        "bool",
        "break",
        "case",
        "catch",
        "char",
        "class",
        "compl",
        "const",
        "const_cast",
        "continue",
        "default",
        "delete",
        "do",
        "double",
        "dynamic_cast",
        "else",
        "enum",
        "explicit",
        "export",
        "extern",
        "false",
        "float",
        "for",
        "friend",
        "goto",
        "if",
        "inline",
        "int",
        "long",
        "mutable",
        "namespace",
        "new",
        "not",
        "not_eq",
        "operator",
        "or",
        "or_eq",
        "private",
        "protected",
        "public",
        "register",
        "reinterpret_cast",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "static_cast",
        "struct",
        "switch",
        "template",
        "this",
        "throw",
        "true",
        "try",
        "typedef",
        "typeid",
        "typename",
        "union",
        "unsigned",
        "using",
        "virtual",
        "void",
        "volatile",
        "wchar_t",
        "while",
        "xor",
        "xor_eq",
    }
)
_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_DIGITS = "0123456789"
_FALLBACK_LIMIT = 4096


def _nonempty_text(value: str, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ClassicIdentityMigrationError(f"{label} is empty or malformed")
    return value


def _identifier(value: str, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or _IDENTIFIER.fullmatch(value) is None
        or value.casefold() in _CPP_KEYWORDS
        or value.startswith("_")
        or "__" in value
    ):
        raise ClassicIdentityMigrationError(f"{label} is not a non-reserved closed C++ identifier")
    return value


def _source_path(value: str) -> str:
    text = _nonempty_text(value, label="request source path")
    path = PurePosixPath(text)
    if (
        "\\" in text
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != text
    ):
        raise ClassicIdentityMigrationError(
            "request source path is not a normalized portable relative path"
        )
    return text


def _request_statement(
    request: DeclarationIdentityRequest,
    *,
    candidate_round: int,
    occupied_census_digest: Digest,
) -> dict[str, object]:
    return {
        "algorithm": _ALGORITHM,
        "candidate_round": candidate_round,
        "operation_id": request.operation_id,
        "occupied_census_digest": occupied_census_digest.model_dump(mode="json"),
        "original_identifier": request.original_identifier,
        "source_path": request.source_path,
        "target_id": request.target_id,
    }


def _replacement_alphabet(character: str, *, first: bool) -> str:
    if first or character.isalpha():
        return _LETTERS
    if character.isdigit():
        return _DIGITS
    # An underscore is legal after the first byte.  Replacing it with a letter
    # keeps the result inside the conservative non-reserved identifier subset.
    return _LETTERS


def _single_edit_candidates(
    request: DeclarationIdentityRequest,
    *,
    candidate_round: int,
    occupied_census_digest: Digest,
) -> tuple[str, ...]:
    statement = canonical_json(
        _request_statement(
            request,
            candidate_round=candidate_round,
            occupied_census_digest=occupied_census_digest,
        )
    )
    original = request.original_identifier
    ranked: list[tuple[bytes, str]] = []
    for index, character in enumerate(original):
        for replacement in _replacement_alphabet(character, first=index == 0):
            candidate = original[:index] + replacement + original[index + 1 :]
            if candidate.casefold() == original.casefold():
                continue
            rank = hashlib.sha256(statement + b"\0single\0" + candidate.encode("ascii")).digest()
            ranked.append((rank, candidate))
    return tuple(candidate for _rank, candidate in sorted(ranked))


def _fallback_candidate(
    request: DeclarationIdentityRequest,
    *,
    candidate_round: int,
    nonce: int,
    occupied_census_digest: Digest,
) -> str:
    statement = canonical_json(
        {
            **_request_statement(
                request,
                candidate_round=candidate_round,
                occupied_census_digest=occupied_census_digest,
            ),
            "nonce": nonce,
        }
    )
    material = bytearray()
    counter = 0
    while len(material) < len(request.original_identifier):
        material.extend(hashlib.sha256(statement + counter.to_bytes(4, "little")).digest())
        counter += 1
    result: list[str] = []
    for index, (character, raw) in enumerate(
        zip(
            request.original_identifier,
            material[: len(request.original_identifier)],
            strict=True,
        )
    ):
        alphabet = _replacement_alphabet(character, first=index == 0)
        result.append(alphabet[raw % len(alphabet)])
    return "".join(result)


def _candidate_stream(
    request: DeclarationIdentityRequest,
    *,
    candidate_round: int,
    occupied_census_digest: Digest,
) -> Iterable[str]:
    yield from _single_edit_candidates(
        request,
        candidate_round=candidate_round,
        occupied_census_digest=occupied_census_digest,
    )
    for nonce in range(_FALLBACK_LIMIT):
        yield _fallback_candidate(
            request,
            candidate_round=candidate_round,
            nonce=nonce,
            occupied_census_digest=occupied_census_digest,
        )


def preview_declaration_identities(
    requests: Sequence[DeclarationIdentityRequest],
    *,
    occupied_by_target: Mapping[str, Iterable[str]],
    candidate_round: int = 0,
) -> DeclarationIdentityMigrationPreview:
    """Propose canonical same-length identifiers without changing project state.

    ``occupied_by_target`` must be the caller's complete clean and generated
    identifier exposure census for every requested target.  The helper cannot
    certify that completeness; its result is intentionally only a preview.
    Requests are normalized canonically, so input order cannot affect output.
    """

    if (
        not isinstance(candidate_round, int)
        or isinstance(candidate_round, bool)
        or not 0 <= candidate_round <= 1_000_000
    ):
        raise ClassicIdentityMigrationError("candidate round is outside its bound")
    occupied: dict[str, set[str]] = {}
    for target_id, identifiers in occupied_by_target.items():
        canonical_target = _nonempty_text(target_id, label="occupied target id")
        folded_target = canonical_target.casefold()
        if folded_target in occupied:
            raise ClassicIdentityMigrationError(
                f"occupied target census repeats {canonical_target!r}"
            )
        values: set[str] = set()
        if isinstance(identifiers, (str, bytes)):
            raise ClassicIdentityMigrationError(
                f"occupied target {canonical_target!r} census is not an identifier sequence"
            )
        for index, raw_identifier in enumerate(identifiers):
            value = _identifier(raw_identifier, label=f"occupied identifier {index}")
            folded = value.casefold()
            if folded in values:
                raise ClassicIdentityMigrationError(
                    f"occupied target {canonical_target!r} has a casefold collision"
                )
            values.add(folded)
        occupied[folded_target] = values

    occupied_census_digest = Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "targets": {
                    target: sorted(identifiers) for target, identifiers in sorted(occupied.items())
                },
            }
        )
    )

    canonical_requests: list[DeclarationIdentityRequest] = []
    request_keys: set[tuple[str, str, str, str]] = set()
    for index, raw_request in enumerate(requests):
        if not isinstance(raw_request, DeclarationIdentityRequest):
            raise ClassicIdentityMigrationError(f"request {index} is malformed")
        request = DeclarationIdentityRequest(
            _nonempty_text(raw_request.target_id, label="request target id"),
            _source_path(raw_request.source_path),
            _nonempty_text(raw_request.operation_id, label="request operation id"),
            _identifier(
                raw_request.original_identifier,
                label="request original identifier",
            ),
        )
        key = (
            request.target_id.casefold(),
            request.source_path.casefold(),
            request.operation_id.casefold(),
            request.original_identifier.casefold(),
        )
        if key in request_keys:
            raise ClassicIdentityMigrationError("migration request is duplicated")
        request_keys.add(key)
        if request.target_id.casefold() not in occupied:
            raise ClassicIdentityMigrationError(
                f"request target {request.target_id!r} has no complete exposure census"
            )
        if request.original_identifier.casefold() not in occupied[request.target_id.casefold()]:
            raise ClassicIdentityMigrationError(
                f"request original {request.original_identifier!r} is absent from "
                f"target {request.target_id!r} exposure census"
            )
        canonical_requests.append(request)
    canonical_requests.sort(
        key=lambda item: (
            item.target_id.casefold(),
            item.source_path.casefold(),
            item.operation_id.casefold(),
            item.original_identifier.casefold(),
        )
    )

    migrations: list[DeclarationIdentityMigration] = []
    for request in canonical_requests:
        target_occupied = occupied[request.target_id.casefold()]
        replacement: str | None = None
        for candidate in _candidate_stream(
            request,
            candidate_round=candidate_round,
            occupied_census_digest=occupied_census_digest,
        ):
            if (
                len(candidate) == len(request.original_identifier)
                and candidate.casefold() not in target_occupied
                and _IDENTIFIER.fullmatch(candidate) is not None
                and candidate.casefold() not in _CPP_KEYWORDS
                and not candidate.startswith("_")
                and "__" not in candidate
            ):
                replacement = candidate
                break
        if replacement is None:
            raise ClassicIdentityMigrationError(
                f"no same-length identity is available for "
                f"{request.original_identifier!r} in target {request.target_id!r}"
            )
        target_occupied.add(replacement.casefold())
        statement = {
            **_request_statement(
                request,
                candidate_round=candidate_round,
                occupied_census_digest=occupied_census_digest,
            ),
            "replacement_identifier": replacement,
        }
        migrations.append(
            DeclarationIdentityMigration(
                request.target_id,
                request.source_path,
                request.operation_id,
                request.original_identifier,
                replacement,
                candidate_round,
                Digest.from_bytes(canonical_json(statement)),
            )
        )

    wire = [
        {
            "candidate_round": item.candidate_round,
            "derivation_digest": item.derivation_digest.model_dump(mode="json"),
            "operation_id": item.operation_id,
            "original_identifier": item.original_identifier,
            "replacement_identifier": item.replacement_identifier,
            "source_path": item.source_path,
            "target_id": item.target_id,
        }
        for item in migrations
    ]
    return DeclarationIdentityMigrationPreview(
        _ALGORITHM,
        occupied_census_digest,
        tuple(migrations),
        Digest.from_bytes(
            canonical_json(
                {
                    "algorithm": _ALGORITHM,
                    "occupied_census_digest": occupied_census_digest.model_dump(mode="json"),
                    "migrations": wire,
                }
            )
        ),
    )


__all__ = [
    "ClassicIdentityMigrationError",
    "DeclarationIdentityMigration",
    "DeclarationIdentityMigrationPreview",
    "DeclarationIdentityRequest",
    "preview_declaration_identities",
]
