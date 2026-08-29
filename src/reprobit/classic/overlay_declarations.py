"""Closed declaration grammar and target-scoped ODR validation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

_DECLARATION_GENERATORS = frozenset(
    {
        "class",
        "empty_class",
        "enum",
        "extern_run",
        "fwd",
        "fwd_run",
        "fwd_seq",
        "proto",
        "typedef",
    }
)


@dataclass(frozen=True, slots=True)
class _DeclarationEntity:
    """One entity introduced by the closed declaration grammar."""

    primary_identifier: str
    introduced_identifiers: tuple[str, ...]
    disposition: str
    tag: str | None
    semantic_digest: Digest


@dataclass(frozen=True, slots=True)
class _DeclarationFact:
    """One target-exposed spelling used for ODR compatibility checks."""

    identifier: str
    primary_identifier: str
    disposition: str
    tag: str | None
    semantic_digest: Digest
    source_path: str
    targets: frozenset[str]


def _expanded_names(value: object) -> tuple[str, ...]:
    if isinstance(value, dict):
        if (
            set(value) != {"count", "first", "kind", "stem", "width"}
            or value.get("kind") != "identifier_run"
        ):
            raise ClassicSemanticError("source-overlay identifier run is malformed")
        stem = value.get("stem")
        first = value.get("first")
        count = value.get("count")
        width = value.get("width")
        if (
            not isinstance(stem, str)
            or not isinstance(first, int)
            or isinstance(first, bool)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not isinstance(width, int)
            or isinstance(width, bool)
            or first < 0
            or count < 1
            or not 1 <= width <= 8
        ):
            raise ClassicSemanticError("source-overlay identifier run is malformed")
        return tuple(stem + str(index).zfill(width) for index in range(first, first + count))
    if not isinstance(value, list):
        raise ClassicSemanticError("source-overlay declaration name run is malformed")
    result: list[str] = []
    for item in value:
        if isinstance(item, str):
            result.append(item)
            continue
        if not isinstance(item, dict):
            raise ClassicSemanticError("source-overlay declaration name run is malformed")
        stem = item.get("stem")
        first = item.get("first")
        count = item.get("count")
        width = item.get("width", len(str(first)))
        if (
            not isinstance(stem, str)
            or not isinstance(first, int)
            or isinstance(first, bool)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not isinstance(width, int)
            or isinstance(width, bool)
        ):
            raise ClassicSemanticError("source-overlay declaration name run is malformed")
        if first < 0 or count < 1 or not 1 <= width <= 8:
            raise ClassicSemanticError("source-overlay declaration name run is out of range")
        result.extend(stem + str(index).zfill(width) for index in range(first, first + count))
    if len(result) != len(set(result)):
        raise ClassicSemanticError("source-overlay declaration name run repeats")
    return tuple(result)


_DECLARATION_LAYOUT_KEYS = frozenset({"at", "blank_indent", "indent", "lines", "nl"})


def _declaration_statement(
    generator: Mapping[str, object],
    *,
    disposition: str,
    primary_identifier: str,
) -> dict[str, object]:
    """Return the layout-free statement whose equality discharges ODR identity."""

    return {
        "disposition": disposition,
        "primary_identifier": primary_identifier,
        "generator": {
            key: value
            for key, value in sorted(generator.items())
            if key not in _DECLARATION_LAYOUT_KEYS
        },
    }


def _declaration_entity(
    *,
    primary_identifier: str,
    introduced_identifiers: tuple[str, ...],
    disposition: str,
    tag: str | None,
    statement: Mapping[str, object],
) -> _DeclarationEntity:
    if len(introduced_identifiers) != len(set(introduced_identifiers)):
        raise ClassicSemanticError(
            f"declaration {primary_identifier!r} repeats an introduced spelling"
        )
    return _DeclarationEntity(
        primary_identifier,
        introduced_identifiers,
        disposition,
        tag,
        Digest.from_bytes(canonical_json(statement)),
    )


def _forward_run_identifiers(generator: Mapping[str, object]) -> tuple[str, ...]:
    stem = generator.get("stem")
    first = generator.get("first")
    count = generator.get("count")
    width = generator.get("width", len(str(first)))
    if (
        not isinstance(stem, str)
        or not isinstance(first, int)
        or isinstance(first, bool)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or not isinstance(width, int)
        or isinstance(width, bool)
        or first < 0
        or count < 1
        or not 1 <= width <= 8
    ):
        raise ClassicSemanticError("source-overlay forward run is malformed")
    return tuple(stem + str(index).zfill(width) for index in range(first, first + count))


def _declaration_entities(
    generator: Mapping[str, object],
) -> tuple[_DeclarationEntity, ...]:
    """Expand the closed generator grammar into declaration entities."""

    kind = generator["k"]
    if kind in {"fwd", "fwd_seq", "fwd_run"}:
        identifiers: tuple[str, ...]
        if kind == "fwd":
            identifier = generator.get("id")
            if not isinstance(identifier, str):
                raise ClassicSemanticError("forward declaration lacks its identifier")
            identifiers = (identifier,)
        elif kind == "fwd_seq":
            identifiers = _expanded_names(generator.get("identifiers"))
        else:
            identifiers = _forward_run_identifiers(generator)
        tag = generator.get("tag", "class")
        if tag not in {"class", "struct", "union"}:
            raise ClassicSemanticError("forward declaration tag is outside the closed enum")
        return tuple(
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=(identifier,),
                disposition="record-forward",
                tag=str(tag),
                statement={
                    "disposition": "record-forward",
                    "primary_identifier": identifier,
                    "tag": tag,
                },
            )
            for identifier in identifiers
        )
    if kind in {"empty_class", "class"}:
        identifier = generator.get("id")
        tag = generator.get("tag", "class")
        if not isinstance(identifier, str) or tag not in {"class", "struct"}:
            raise ClassicSemanticError(f"{kind} declaration is malformed")
        return (
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=(identifier,),
                disposition="record-definition",
                tag=str(tag),
                statement=_declaration_statement(
                    generator,
                    disposition="record-definition",
                    primary_identifier=identifier,
                ),
            ),
        )
    if kind == "enum":
        identifier = generator.get("id")
        if not isinstance(identifier, str):
            raise ClassicSemanticError("source-overlay enum lacks its identifier")
        enum_identifiers = (identifier, *_expanded_names(generator.get("members")))
        return (
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=enum_identifiers,
                disposition="enum-definition",
                tag=None,
                statement=_declaration_statement(
                    generator,
                    disposition="enum-definition",
                    primary_identifier=identifier,
                ),
            ),
        )
    if kind in {"typedef", "proto"}:
        identifier = generator.get("id")
        if not isinstance(identifier, str):
            raise ClassicSemanticError(f"{kind} declaration lacks its identifier")
        disposition = "alias-declaration" if kind == "typedef" else "function-declaration"
        return (
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=(identifier,),
                disposition=disposition,
                tag=None,
                statement=_declaration_statement(
                    generator,
                    disposition=disposition,
                    primary_identifier=identifier,
                ),
            ),
        )
    if kind == "extern_run":
        prefix = generator.get("prefix")
        count = generator.get("count")
        width = generator.get("width")
        if (
            not isinstance(prefix, str)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or not isinstance(width, int)
            or isinstance(width, bool)
            or count < 1
            or not 1 <= width <= 3
        ):
            raise ClassicSemanticError("source-overlay extern run is malformed")
        extern_identifiers = tuple(prefix + str(index).zfill(width) for index in range(count))
        return tuple(
            _declaration_entity(
                primary_identifier=identifier,
                introduced_identifiers=(identifier,),
                disposition="object-declaration",
                tag=None,
                statement={
                    "disposition": "object-declaration",
                    "primary_identifier": identifier,
                    "type": "int",
                },
            )
            for identifier in extern_identifiers
        )
    if kind == "record_header":
        recipe = generator.get("typed_recipe")
        if not isinstance(recipe, dict) or not isinstance(recipe.get("items"), list):
            raise ClassicSemanticError("source-overlay record header is malformed")
        recipe_kind = recipe.get("kind")
        result: list[_DeclarationEntity] = []
        if recipe_kind == "enum_one_enumerator":
            for item in recipe["items"]:
                if not isinstance(item, dict):
                    raise ClassicSemanticError("record-header enum item is malformed")
                name = item.get("name")
                enumerator = item.get("enumerator")
                if not isinstance(name, str) or not isinstance(enumerator, str):
                    raise ClassicSemanticError("record-header enum item is malformed")
                result.append(
                    _declaration_entity(
                        primary_identifier=name,
                        introduced_identifiers=(name, enumerator),
                        disposition="enum-definition",
                        tag=None,
                        statement={
                            "disposition": "enum-definition",
                            "primary_identifier": name,
                            "members": [enumerator],
                        },
                    )
                )
        elif recipe_kind == "unused_class_with_inline_void_methods":
            methods = recipe.get("methods_per_class")
            policy = recipe.get("method_identifier_policy")
            if (
                not isinstance(methods, int)
                or isinstance(methods, bool)
                or methods < 1
                or policy not in {"single_unindexed_record", "zero_based_indexed_record"}
            ):
                raise ClassicSemanticError("record-header class recipe is malformed")
            for item in recipe["items"]:
                if not isinstance(item, str):
                    raise ClassicSemanticError("record-header class item is malformed")
                result.append(
                    _declaration_entity(
                        primary_identifier=item,
                        introduced_identifiers=(item,),
                        disposition="record-definition",
                        tag="class",
                        statement={
                            "disposition": "record-definition",
                            "primary_identifier": item,
                            "method_identifier_policy": policy,
                            "methods_per_class": methods,
                            "tag": "class",
                        },
                    )
                )
        else:
            raise ClassicSemanticError("record-header recipe kind is unsupported")
        return tuple(result)
    raise ClassicSemanticError(f"generator {kind!r} is not a declaration generator")


def _declared_identifiers(generator: Mapping[str, object]) -> tuple[str, ...]:
    return tuple(
        identifier
        for entity in _declaration_entities(generator)
        for identifier in entity.introduced_identifiers
    )


def _declaration_owned_identifiers(generator: Mapping[str, object]) -> tuple[str, ...]:
    """Return every identifier whose spelling is owned by a declaration generator.

    Entity identifiers participate in the global origin/ODR theorem.  Member
    and parameter identifiers have narrower C++ scopes, but they remain macro
    capture surfaces and therefore belong to the compiler-namespace census.
    """

    owned = list(_declared_identifiers(generator))
    kind = generator.get("k")
    if kind == "class":
        raw_members = generator.get("members")
        if not isinstance(raw_members, list):
            raise ClassicSemanticError("class declaration member list is malformed")
        for raw_member in raw_members:
            if isinstance(raw_member, str):
                owned.append(raw_member)
            elif isinstance(raw_member, dict) and isinstance(raw_member.get("decl"), str):
                owned.append(str(raw_member["decl"]))
            elif isinstance(raw_member, dict) and isinstance(raw_member.get("id"), str):
                owned.append(str(raw_member["id"]))
            elif isinstance(raw_member, dict) and "stem" in raw_member:
                owned.extend(_expanded_names([raw_member]))
            else:
                raise ClassicSemanticError("class declaration member is malformed")
    elif kind == "proto":
        raw_parameters = generator.get("parameters")
        if not isinstance(raw_parameters, list):
            raise ClassicSemanticError("function declaration parameters are malformed")
        for raw_parameter in raw_parameters:
            if not isinstance(raw_parameter, dict):
                raise ClassicSemanticError("function declaration parameter is malformed")
            identifier = raw_parameter.get("identifier")
            if identifier is not None:
                if not isinstance(identifier, str):
                    raise ClassicSemanticError(
                        "function declaration parameter identifier is malformed"
                    )
                owned.append(identifier)
    elif kind == "record_header":
        recipe = generator.get("typed_recipe")
        if not isinstance(recipe, dict):
            raise ClassicSemanticError("record-header recipe is malformed")
        guard = recipe.get("guard")
        if not isinstance(guard, str):
            raise ClassicSemanticError("record-header guard is malformed")
        owned.append(guard)
        if recipe.get("kind") == "unused_class_with_inline_void_methods":
            methods = recipe.get("methods_per_class")
            policy = recipe.get("method_identifier_policy")
            if not isinstance(methods, int) or isinstance(methods, bool) or methods < 1:
                raise ClassicSemanticError("record-header method count is malformed")
            if policy == "single_unindexed_record":
                owned.append("Record")
            elif policy == "zero_based_indexed_record":
                owned.extend(f"Record{index}" for index in range(methods))
            else:
                raise ClassicSemanticError("record-header method policy is malformed")
    return tuple(dict.fromkeys(owned))


def _declaration_facts_compatible(left: _DeclarationFact, right: _DeclarationFact) -> bool:
    """Return whether two same-target global declarations satisfy the ODR."""

    defining = frozenset({"record-definition", "enum-definition", "enumerator-definition"})
    if (
        left.source_path.casefold() == right.source_path.casefold()
        and left.disposition in defining
        and right.disposition in defining
    ):
        return False
    if not left.targets.intersection(right.targets):
        return True
    dispositions = {left.disposition, right.disposition}
    if dispositions <= {"record-forward", "record-definition"}:
        if left.tag != right.tag:
            return False
        if left.disposition == right.disposition == "record-forward":
            return True
        if left.disposition == right.disposition == "record-definition":
            return (
                left.source_path.casefold() != right.source_path.casefold()
                and left.semantic_digest == right.semantic_digest
            )
        return True
    if left.disposition != right.disposition:
        return False
    if left.disposition in {
        "alias-declaration",
        "function-declaration",
        "object-declaration",
    }:
        return left.semantic_digest == right.semantic_digest
    if left.disposition in {"enum-definition", "enumerator-definition"}:
        return (
            left.source_path.casefold() != right.source_path.casefold()
            and left.primary_identifier == right.primary_identifier
            and left.semantic_digest == right.semantic_digest
        )
    return False


def _declaration_odr_analysis(
    facts_by_identifier: Mapping[str, Sequence[_DeclarationFact]],
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    repeated = 0
    canonical_facts: list[dict[str, object]] = []
    conflicts: list[dict[str, object]] = []
    for identifier, facts in sorted(facts_by_identifier.items()):
        if len(facts) > 1:
            repeated += 1
        for index, left in enumerate(facts):
            canonical_facts.append(
                {
                    "identifier": identifier,
                    "primary_identifier": left.primary_identifier,
                    "disposition": left.disposition,
                    "tag": left.tag,
                    "semantic_digest": left.semantic_digest.model_dump(mode="json"),
                    "source_path": left.source_path,
                    "targets": sorted(left.targets, key=str.casefold),
                }
            )
            for right in facts[index + 1 :]:
                if not _declaration_facts_compatible(left, right):
                    overlap = sorted(left.targets.intersection(right.targets), key=str.casefold)
                    conflicts.append(
                        {
                            "identifier": identifier,
                            "left_source": left.source_path,
                            "right_source": right.source_path,
                            "left_disposition": left.disposition,
                            "right_disposition": right.disposition,
                            "targets": overlap,
                        }
                    )
    statement = {
        "schema": 1,
        "facts": sorted(
            canonical_facts,
            key=lambda item: (
                str(item["identifier"]).casefold(),
                str(item["source_path"]).casefold(),
                str(item["disposition"]),
                str(item["semantic_digest"]),
            ),
        ),
    }
    return (
        {
            "theorem": "target-closed-global-declaration-odr-v1",
            "fact_count": len(canonical_facts),
            "identifier_count": len(facts_by_identifier),
            "repeated_identifier_count": repeated,
            "statement_digest": Digest.from_bytes(canonical_json(statement)).model_dump(
                mode="json"
            ),
        },
        tuple(conflicts),
    )


def _odr_conflict_summary(conflicts: Sequence[Mapping[str, object]]) -> str:
    identifiers = sorted({str(item["identifier"]) for item in conflicts}, key=str.casefold)
    sources = sorted(
        {str(item[key]) for item in conflicts for key in ("left_source", "right_source")},
        key=str.casefold,
    )
    return f"pair_count={len(conflicts)}, identifiers={identifiers}, sources={sources}"


def _validate_declaration_odr(
    facts_by_identifier: Mapping[str, Sequence[_DeclarationFact]],
) -> dict[str, object]:
    trace, conflicts = _declaration_odr_analysis(facts_by_identifier)
    if conflicts:
        raise ClassicSemanticError(
            "generated global declarations violate target ODR compatibility: "
            + _odr_conflict_summary(conflicts)
        )
    return trace
