"""Semantic boundary for donor-private source refactors.

The classic overlay renderer proves *what bytes* a typed operation produced.
This module proves the smaller, complementary claim needed before those bytes
may influence a composed object:

* the six source refactors used by the current project are bound to one
  source-aware consumer and to the declarations that make the rewrite
  logic-equivalent; and
* the two dead-local carrier forms are kept in the weaker, honest category of
  donor-private compiler state.  They are structurally inert local work, but
  are not promoted to a whole-program source-equivalence claim.

There is deliberately no general C++ rewriting language here.  A new refactor
kind needs a new closed proof rule and tests.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import cast

from reprobit.classic.overlay_declarations import _declaration_owned_identifiers
from reprobit.classic.source_proofs import (
    require_source_overlay_range_pin,
    require_target_source_refactor_identity,
    select_source_permutation_window,
    source_overlay_tokens,
)
from reprobit.classic_overlay_types import (
    ClassicOverlayOperationReceipt,
    ClassicOverlayOutputReceipt,
)
from reprobit.model import Digest
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)
from reprobit.strict_json import canonical_json


class SourceRefactorSemanticError(ValueError):
    """A donor source mutation lacks its closed semantic witness."""


@dataclass(frozen=True, slots=True)
class SourceRefactorSemanticProof:
    """Compact planning evidence for one checked donor source mutation."""

    intervention_id: str
    classification: str
    generator_kinds: tuple[str, ...]
    operation_ids: tuple[str, ...]
    statement_digest: Digest


_TRUE_REFACTOR_KINDS = frozenset(
    {
        "for_init_decl",
        "fixed_array_fill",
        "fixed_array_shuffle_countdown",
        "inclusive_extent",
        "ctor_alloc_lift",
        "capture_tail",
    }
)
_PRIVATE_STATE_KINDS = frozenset({"dead_updates", "default_ctor_dead_updates"})
_SEMANTIC_KINDS = _TRUE_REFACTOR_KINDS | _PRIVATE_STATE_KINDS | {"member_sig"}
_SAFE_ENTROPY_LEAVES = frozenset(
    {
        "lines",
        "include",
        "include_seat",
        "fwd",
        "fwd_run",
        "empty_class",
        "class",
        "enum",
        "typedef",
        "proto",
        "extern_run",
    }
)
_BUILTIN_INTEGRAL_TOKEN_FORMS = frozenset(
    tuple(item.split())
    for item in {
        "char",
        "signed char",
        "unsigned char",
        "short",
        "short int",
        "signed short",
        "signed short int",
        "unsigned short",
        "unsigned short int",
        "int",
        "signed",
        "signed int",
        "unsigned",
        "unsigned int",
        "long",
        "long int",
        "signed long",
        "signed long int",
        "unsigned long",
        "unsigned long int",
    }
)
_SHA_RE = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _fail(message: str) -> None:
    raise SourceRefactorSemanticError(message)


def _need(condition: bool, message: str) -> None:
    if not condition:
        _fail(message)


def _object(value: object, context: str) -> dict[str, object]:
    _need(isinstance(value, Mapping), f"{context} must be an object")
    return {str(key): child for key, child in cast(Mapping[object, object], value).items()}


def _array(value: object, context: str) -> list[object]:
    _need(isinstance(value, (list, tuple)), f"{context} must be an array")
    return list(cast(Sequence[object], value))


def _keys(
    value: Mapping[str, object],
    required: set[str],
    context: str,
    *,
    optional: set[str] | frozenset[str] = frozenset(),
) -> None:
    actual = set(value)
    missing = required - actual
    unknown = actual - required - set(optional)
    _need(
        not missing and not unknown,
        f"{context} schema differs; missing={sorted(missing)} unknown={sorted(unknown)}",
    )


def _identifier(value: object, context: str) -> str:
    _need(
        isinstance(value, str) and _IDENTIFIER_RE.fullmatch(value) is not None,
        f"{context} must be an identifier",
    )
    return cast(str, value)


def _string(value: object, context: str) -> str:
    _need(isinstance(value, str) and value.isascii(), f"{context} must be ASCII text")
    return cast(str, value)


def _integer(value: object, context: str) -> int:
    _need(type(value) is int, f"{context} must be an exact integer")
    return cast(int, value)


def _parameters(intervention: ClassicRecipeIntervention) -> dict[str, object]:
    return {field.name: field.value for field in intervention.parameters}


def _significant(data: bytes) -> list[tuple[str, int, int]]:
    return list(source_overlay_tokens(data))


def _token_text(data: bytes) -> list[str]:
    return [token for token, _, _ in _significant(data)]


def _type_text(value: object, context: str) -> str:
    text = _string(value, context)
    _need(bool(text) and bool(_token_text(text.encode("ascii"))), f"{context} is empty")
    return text


def _type_tokens(value: object, context: str) -> list[str]:
    return _token_text(_type_text(value, context).encode("ascii"))


def _pin_schema(value: object, context: str) -> dict[str, object]:
    pin = _object(value, context)
    _keys(
        pin,
        {
            "baseline_sha256",
            "baseline_size",
            "baseline_line_count",
            "baseline_significant_token_sha256",
        },
        context,
    )
    _need(
        isinstance(pin["baseline_sha256"], str)
        and _SHA_RE.fullmatch(pin["baseline_sha256"]) is not None,
        f"{context}.baseline_sha256 differs",
    )
    _need(
        isinstance(pin["baseline_significant_token_sha256"], str)
        and _SHA_RE.fullmatch(pin["baseline_significant_token_sha256"]) is not None,
        f"{context}.baseline_significant_token_sha256 differs",
    )
    for name in ("baseline_size", "baseline_line_count"):
        _need(type(pin[name]) is int and cast(int, pin[name]) >= 0, f"{context}.{name} differs")
    return pin


def _pin(data: bytes, value: object, context: str) -> None:
    try:
        require_source_overlay_range_pin(data, _pin_schema(value, context), context)
    except ValueError as exc:
        raise SourceRefactorSemanticError(str(exc)) from exc


def _source(
    clean_sources: Mapping[str, bytes], spec_value: object, context: str
) -> tuple[str, bytes, dict[str, object]]:
    spec = _object(spec_value, context)
    path = spec.get("path")
    digest = spec.get("source_sha256")
    _need(isinstance(path, str) and path in clean_sources, f"{context}.path is absent")
    _need(
        isinstance(digest, str) and _SHA_RE.fullmatch(digest) is not None,
        f"{context}.source_sha256 differs",
    )
    data = clean_sources[cast(str, path)]
    _need(type(data) is bytes, f"{context} source must be immutable bytes")
    _need(sha256(data).hexdigest() == digest, f"{context} source differs from its pin")
    return cast(str, path), data, spec


def _leaf_generators(value: object) -> list[dict[str, object]]:
    generator = _object(value, "source generator")
    kind = generator.get("k")
    _need(isinstance(kind, str), "source generator kind is absent")
    if kind != "seq":
        return [generator]
    items = _array(generator.get("items"), "source generator sequence")
    result: list[dict[str, object]] = []
    for raw in items:
        item = _object(raw, "source generator sequence item")
        item.pop("line", None)
        result.extend(_leaf_generators(item))
    return result


@dataclass(frozen=True, slots=True)
class _Operation:
    path: str
    value: Mapping[str, object]
    leaves: tuple[Mapping[str, object], ...]
    receipt_key: str

    @property
    def operation_id(self) -> str | None:
        value = self.value.get("id")
        return value if isinstance(value, str) else None

    @property
    def action(self) -> str:
        value = self.value.get("op")
        return value if isinstance(value, str) else ""


def _operations(parameters: Mapping[str, object]) -> tuple[_Operation, ...]:
    renderings = _array(parameters.get("renderings"), "donor renderings")
    result: list[_Operation] = []
    paths: set[str] = set()
    for rendering_index, raw_rendering in enumerate(renderings):
        rendering = _object(raw_rendering, f"donor renderings[{rendering_index}]")
        path = rendering.get("path")
        _need(isinstance(path, str) and path not in paths, "donor rendering path differs")
        paths.add(cast(str, path))
        for operation_index, raw_operation in enumerate(
            _array(rendering.get("operations"), f"donor rendering {path!r} operations")
        ):
            operation = _object(
                raw_operation, f"donor rendering {path!r} operation {operation_index}"
            )
            result.append(
                _Operation(
                    cast(str, path),
                    MappingProxyType(operation),
                    tuple(
                        MappingProxyType(item) for item in _leaf_generators(operation.get("gen"))
                    ),
                    (
                        cast(str, operation["id"])
                        if isinstance(operation.get("id"), str)
                        else f"{path}#{operation_index}"
                    ),
                )
            )
    return tuple(result)


def _semantic_operations(operations: Sequence[_Operation]) -> tuple[_Operation, ...]:
    return tuple(
        operation
        for operation in operations
        if any(
            leaf.get("k") in _PRIVATE_STATE_KINDS | _TRUE_REFACTOR_KINDS
            or (leaf.get("k") == "member_sig" and leaf.get("kind") == "constructor")
            for leaf in operation.leaves
        )
    )


def _receipt_index(
    receipts: Sequence[ClassicOverlayOutputReceipt],
) -> Mapping[tuple[str, str], ClassicOverlayOperationReceipt]:
    result: dict[tuple[str, str], ClassicOverlayOperationReceipt] = {}
    for output in receipts:
        for operation in output.operations:
            key = (output.path, operation.operation_id)
            _need(key not in result, "overlay operation receipt identity repeats")
            result[key] = operation
    return MappingProxyType(result)


def _safe_nonsemantic_operations(
    operations: Sequence[_Operation], semantic: frozenset[int], owning_source: str
) -> None:
    for operation in operations:
        if id(operation) in semantic:
            continue
        kinds = {cast(str, leaf.get("k")) for leaf in operation.leaves}
        _need(
            bool(kinds) and kinds <= _SAFE_ENTROPY_LEAVES,
            "source refactor carries active entropy",
        )
        if operation.path == owning_source:
            _need(
                operation.action in {"insert", "append"}
                or (operation.action == "replace" and kinds <= {"lines", "include"}),
                "source refactor has an unbound destructive owning-TU operation",
            )
        else:
            _need(
                PurePosixPath(operation.path).suffix.casefold() in {".h", ".hh", ".hpp", ".hxx"},
                "source refactor extra rendering is not a header",
            )


def _prove_true_refactor_entropy(
    *,
    operations: Sequence[_Operation],
    semantic_operations: Sequence[_Operation],
    owning_source: str,
    clean_sources: Mapping[str, bytes],
    receipts: Mapping[tuple[str, str], ClassicOverlayOperationReceipt],
    target_start: int,
    target_end: int,
) -> None:
    """Keep unbound donor entropy non-emitting and outside the target."""

    semantic = frozenset(map(id, semantic_operations))
    introduced: set[str] = set()
    nondeclaration_kinds = {"lines", "include", "include_seat"}
    for operation in operations:
        if id(operation) in semantic:
            continue
        if operation.path == owning_source:
            _need(
                operation.action in {"insert", "append"},
                "source refactor has an unbound destructive owning-TU operation",
            )
            if operation.action == "insert":
                receipt = receipts.get((operation.path, operation.receipt_key))
                _need(
                    receipt is not None and bool(receipt.anchors),
                    "source refactor entropy lacks a receipt",
                )
                assert receipt is not None
                seat = receipt.anchors[0].byte_offset
                _need(
                    seat < target_start or seat >= target_end,
                    "source refactor entropy overlaps its target",
                )
        clean = clean_sources.get(operation.path)
        _need(clean is not None, f"source refactor entropy source {operation.path!r} is absent")
        clean_tokens = set(_token_text(cast(bytes, clean)))
        for leaf in operation.leaves:
            kind = cast(str, leaf.get("k"))
            if kind in nondeclaration_kinds:
                continue
            try:
                owned = _declaration_owned_identifiers(leaf)
            except ValueError as exc:
                raise SourceRefactorSemanticError(str(exc)) from exc
            for identifier in owned:
                if "::" in identifier:
                    continue
                _need(
                    identifier not in clean_tokens,
                    f"source refactor declaration collides with clean source: {identifier!r}",
                )
                _need(
                    identifier not in introduced,
                    f"source refactor declaration repeats: {identifier!r}",
                )
                introduced.add(identifier)


def _unique_bytes(haystack: bytes, needle: bytes, context: str) -> int:
    _need(bool(needle) and haystack.count(needle) == 1, f"{context} is absent or ambiguous")
    return haystack.index(needle)


def _unique_tokens(
    tokens: Sequence[tuple[str, int, int]], wanted: Sequence[str], context: str
) -> tuple[int, int, int]:
    matches = [
        index
        for index in range(len(tokens) - len(wanted) + 1)
        if [item[0] for item in tokens[index : index + len(wanted)]] == list(wanted)
    ]
    _need(len(matches) == 1, f"{context} is absent or ambiguous")
    index = matches[0]
    return index, tokens[index][1], tokens[index + len(wanted) - 1][2]


def _unique_class_body(
    data: bytes, identifier: str, context: str
) -> tuple[list[tuple[str, int, int]], int, int, int]:
    tokens = _significant(data)
    candidates: list[tuple[int, int, int]] = []
    for index in range(len(tokens) - 2):
        if tokens[index][0] not in {"class", "struct"} or tokens[index + 1][0] != identifier:
            continue
        opening = next(
            (cursor for cursor in range(index + 2, len(tokens)) if tokens[cursor][0] in {"{", ";"}),
            None,
        )
        if opening is None or tokens[opening][0] != "{":
            continue
        depth = 1
        closing = None
        for cursor in range(opening + 1, len(tokens)):
            if tokens[cursor][0] == "{":
                depth += 1
            elif tokens[cursor][0] == "}":
                depth -= 1
                if depth == 0:
                    closing = cursor
                    break
        _need(closing is not None, f"{context} is unbalanced")
        candidates.append((index, opening, cast(int, closing)))
    _need(len(candidates) == 1, f"{context} is absent or ambiguous")
    start, opening, closing = candidates[0]
    return tokens, start, opening, closing


def _class_level_range(
    tokens: Sequence[tuple[str, int, int]],
    opening: int,
    closing: int,
    wanted: Sequence[str],
    context: str,
) -> tuple[int, int]:
    matches: list[tuple[int, int]] = []
    depth = 1
    for index in range(opening + 1, closing):
        token = tokens[index][0]
        if depth == 1 and [item[0] for item in tokens[index : index + len(wanted)]] == list(wanted):
            matches.append((tokens[index][1], tokens[index + len(wanted) - 1][2]))
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
    _need(len(matches) == 1, f"{context} is absent or ambiguous")
    return matches[0]


def _line(data: bytes, token_range: tuple[int, int]) -> bytes:
    start, end = token_range
    line_start = data.rfind(b"\n", 0, start) + 1
    newline = data.find(b"\n", end)
    return data[line_start : len(data) if newline < 0 else newline + 1]


def _include_edge(
    clean_sources: Mapping[str, bytes],
    including_path: str,
    including_data: bytes,
    included_path: str,
    pin: object,
    context: str,
) -> None:
    basename = PurePosixPath(included_path).name
    candidates = [path for path in clean_sources if PurePosixPath(path).name == basename]
    _need(candidates == [included_path], f"{context} included basename is not unique")
    wanted = ["#", "include", f'"{basename}"']
    lines = [
        line for line in including_data.splitlines(keepends=True) if _token_text(line) == wanted
    ]
    _need(len(lines) == 1, f"{context} include edge is absent or ambiguous")
    _pin(lines[0], pin, f"{context} include line")


def _quoted_include_closure(
    clean_sources: Mapping[str, bytes], start_path: str
) -> Mapping[str, bytes]:
    """Resolve the unambiguous quoted-include closure inside source authority."""

    pending = [start_path]
    result: dict[str, bytes] = {}
    while pending:
        current = pending.pop()
        if current in result:
            continue
        data = clean_sources.get(current)
        _need(data is not None, f"integral-type include source {current!r} is absent")
        result[current] = cast(bytes, data)
        for line in cast(bytes, data).splitlines():
            tokens = _token_text(line)
            if (
                len(tokens) != 3
                or tokens[:2] != ["#", "include"]
                or len(tokens[2]) < 2
                or not tokens[2].startswith('"')
                or not tokens[2].endswith('"')
            ):
                continue
            include_name = tokens[2][1:-1]
            relative = (PurePosixPath(current).parent / include_name).as_posix()
            if relative in clean_sources:
                pending.append(relative)
                continue
            suffix = f"/{include_name}"
            matches = sorted(
                path for path in clean_sources if path == include_name or path.endswith(suffix)
            )
            if len(matches) == 1:
                pending.append(matches[0])
    return MappingProxyType(result)


def _require_integral_type(
    clean_sources: Mapping[str, bytes], start_path: str, type_text: str, context: str
) -> None:
    """Prove a spelling reaches a built-in integral type through typedefs."""

    initial = tuple(_type_tokens(type_text, context))
    closure = _quoted_include_closure(clean_sources, start_path)
    current = initial
    seen: set[tuple[str, ...]] = set()
    while current not in _BUILTIN_INTEGRAL_TOKEN_FORMS:
        _need(
            len(current) == 1 and _IDENTIFIER_RE.fullmatch(current[0]) is not None,
            f"{context} is not a built-in integral type or a simple typedef",
        )
        _need(current not in seen, f"{context} typedef chain is cyclic")
        seen.add(current)
        alias = current[0]
        candidates: list[tuple[str, ...]] = []
        for data in closure.values():
            tokens = _significant(data)
            for index, (token, _start, _end) in enumerate(tokens):
                if token != alias or index + 1 >= len(tokens) or tokens[index + 1][0] != ";":
                    continue
                cursor = index - 1
                while cursor >= 0 and tokens[cursor][0] not in {";", "{", "}"}:
                    if tokens[cursor][0] == "typedef":
                        candidates.append(tuple(item[0] for item in tokens[cursor + 1 : index]))
                        break
                    cursor -= 1
        _need(
            len(candidates) == 1 and bool(candidates[0]),
            f"{context} typedef is absent or ambiguous in its include closure",
        )
        current = candidates[0]


def _owner_from_mangled(mangled: object, context: str) -> str:
    text = _string(mangled, context)
    constructor = re.match(r"^\?\?[01]([A-Za-z_][A-Za-z0-9_]*)@@", text)
    ordinary = re.match(r"^\?[A-Za-z_][A-Za-z0-9_]*@([A-Za-z_][A-Za-z0-9_]*)@@", text)
    match = constructor or ordinary
    _need(match is not None, f"{context} is outside the closed member form")
    return cast(re.Match[str], match).group(1)


def _source_owner(target: bytes, expected: str, context: str) -> None:
    tokens = _significant(target)
    opening = next((index for index, item in enumerate(tokens) if item[0] == "{"), None)
    _need(opening is not None, f"{context} has no body")
    qualifiers = [
        index for index, item in enumerate(tokens[: cast(int, opening)]) if item[0] == "::"
    ]
    _need(
        bool(qualifiers) and tokens[qualifiers[-1] - 1][0] == expected,
        f"{context} owner differs",
    )


def _lexical_stack(
    tokens: Sequence[tuple[str, int, int]], position: int, context: str
) -> tuple[int, ...]:
    stack: list[int] = []
    serial = 0
    for token, start, _end in tokens:
        if start >= position:
            break
        if token == "{":
            serial += 1
            stack.append(serial)
        elif token == "}":
            _need(bool(stack), f"{context} braces are unbalanced")
            stack.pop()
    return tuple(stack)


def _require_identifier_fresh_at_seat(
    target: bytes, seat: int, identifier: str, context: str
) -> None:
    """Reject only identifiers visible from the destination lexical block."""

    _need(0 <= seat <= len(target), f"{context} seat leaves its target")
    tokens = _significant(target)
    scopes: list[list[int | None]] = []
    stack: list[list[int | None]] = []
    for token, start, end in tokens:
        if token == "{":
            scope: list[int | None] = [end, None]
            scopes.append(scope)
            stack.append(scope)
        elif token == "}":
            _need(bool(stack), f"{context} braces are unbalanced")
            stack.pop()[1] = start
    _need(
        not stack and bool(scopes) and all(scope[1] is not None for scope in scopes),
        f"{context} braces are unbalanced",
    )

    def contains(scope: Sequence[int | None], position: int) -> bool:
        return cast(int, scope[0]) <= position <= cast(int, scope[1])

    ancestors = [scope for scope in scopes if contains(scope, seat)]
    _need(bool(ancestors), f"{context} seat has no lexical scope")
    target_scope = min(
        ancestors,
        key=lambda scope: cast(int, scope[1]) - cast(int, scope[0]),
    )
    ancestor_ids = {id(scope) for scope in ancestors}
    for token, position, _end in tokens:
        if token != identifier:
            continue
        _need(
            not contains(target_scope, position),
            f"{context} local is not fresh in its destination block",
        )
        containing = [scope for scope in scopes if contains(scope, position)]
        _need(bool(containing), f"{context} local collides with the function declaration")
        occurrence_scope = min(
            containing,
            key=lambda scope: cast(int, scope[1]) - cast(int, scope[0]),
        )
        _need(
            id(occurrence_scope) not in ancestor_ids,
            f"{context} local collides with a visible ancestor",
        )


def _for_fragments(gen: Mapping[str, object]) -> tuple[bytes, bytes, str]:
    _keys(
        gen,
        {"k", "form", "type", "id", "container", "begin", "end", "declaration_indent"},
        "for-initializer refactor",
    )
    form = gen["form"]
    _need(
        form in {"standalone_then_assignment_v1", "declaration_in_initializer_v1"},
        "for-initializer form differs",
    )
    indent = _string(gen["declaration_indent"], "for-initializer indentation")
    type_text = _type_text(gen["type"], "for-initializer type")
    identifier = _identifier(gen["id"], "for-initializer identifier")
    container = _identifier(gen["container"], "for-initializer container")
    begin = _identifier(gen["begin"], "for-initializer begin member")
    end = _identifier(gen["end"], "for-initializer end member")
    in_initializer = (
        f"{indent}for ({type_text} {identifier} = {container}.{begin}(); "
        f"{identifier} != {container}.{end}(); {identifier}++) {{\n"
    ).encode("ascii")
    standalone = (
        f"{indent}{type_text} {identifier};\n\n"
        f"{indent}for ({identifier} = {container}.{begin}(); "
        f"{identifier} != {container}.{end}(); {identifier}++) {{\n"
    ).encode("ascii")
    return (
        (in_initializer, standalone, identifier)
        if form == "standalone_then_assignment_v1"
        else (standalone, in_initializer, identifier)
    )


def _prove_for_initializer(
    clean_target: bytes, donor_target: bytes, gen: Mapping[str, object]
) -> None:
    baseline, output, identifier = _for_fragments(gen)
    start = _unique_bytes(clean_target, baseline, "for-initializer seed form")
    _unique_bytes(donor_target, output, "for-initializer donor form")
    tokens = _significant(clean_target)
    opening_positions = [
        index
        for index, (token, token_start, _end) in enumerate(tokens)
        if token == "{" and start <= token_start < start + len(baseline)
    ]
    _need(len(opening_positions) == 1, "for-initializer loop opening differs")
    depth = 0
    loop_end = None
    for token, _token_start, token_end in tokens[opening_positions[0] :]:
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth == 0:
                loop_end = token_end
                break
    _need(loop_end is not None, "for-initializer loop is unbalanced")
    uses = [token_start for token, token_start, _end in tokens if token == identifier]
    _need(
        len(uses) >= 4 and all(start <= item < cast(int, loop_end) for item in uses),
        "for-initializer variable escapes its loop",
    )


def _fill_fragments(gen: Mapping[str, object]) -> tuple[bytes, bytes]:
    _keys(
        gen,
        {"k", "array", "index", "index_type", "count", "value", "declaration_indent"},
        "fixed-array fill",
    )
    array = _identifier(gen["array"], "fixed-array fill array")
    index = _identifier(gen["index"], "fixed-array fill index")
    index_type = _type_text(gen["index_type"], "fixed-array fill index type")
    count = _integer(gen["count"], "fixed-array fill count")
    _need(gen["value"] == -1 and count > 0, "fixed-array fill value/count differs")
    indent = _string(gen["declaration_indent"], "fixed-array fill indentation")
    return (
        f"{indent}memset({array}, -1, sizeof({array}));\n".encode("ascii"),
        (
            f"{indent}for ({index_type} {index} = 0; {index} < {count}; "
            f"{index}++) {array}[{index}] = -1;\n"
        ).encode("ascii"),
    )


def _prove_fixed_fill(
    *,
    clean_sources: Mapping[str, bytes],
    owning_source: str,
    unit_data: bytes,
    clean_target: bytes,
    donor_target: bytes,
    proof: Mapping[str, object],
    gen: Mapping[str, object],
) -> None:
    baseline, output = _fill_fragments(gen)
    _unique_bytes(clean_target, baseline, "fixed-array fill seed form")
    _unique_bytes(donor_target, output, "fixed-array fill donor form")
    array = cast(str, gen["array"])
    index = cast(str, gen["index"])
    tokens = _significant(clean_target)
    _need(not any(token == index for token, _, _ in tokens), "fixed-array fill index is not fresh")
    expected_uses = sum(token == array for token, _, _ in _significant(baseline))
    _need(
        expected_uses == 2 and sum(token == array for token, _, _ in tokens) == 2,
        "fixed-array fill member is shadowed or used outside its statement",
    )

    declaration = _object(proof.get("array_declaration"), "fixed-array declaration witness")
    _keys(
        declaration,
        {
            "path",
            "source_sha256",
            "owner",
            "array",
            "element_type",
            "extent",
            "direct_include_range_pin",
            "declaration_range_pin",
        },
        "fixed-array declaration witness",
    )
    element_type = _type_text(declaration["element_type"], "fixed-array element type")
    _need(
        declaration["array"] == array and declaration["extent"] == gen["count"],
        "fixed-array bound differs from its declaration",
    )
    owner = _identifier(declaration["owner"], "fixed-array declaration owner")
    _need(
        owner == _owner_from_mangled(proof.get("source_owner_mangled"), "fixed-array owner"),
        "fixed-array declaration owner differs from the target",
    )
    _source_owner(clean_target, owner, "fixed-array target")
    header_path, header, _spec = _source(
        clean_sources, declaration, "fixed-array declaration header"
    )
    _require_integral_type(clean_sources, header_path, element_type, "fixed-array element type")
    _include_edge(
        clean_sources,
        owning_source,
        unit_data,
        header_path,
        declaration["direct_include_range_pin"],
        "fixed-array unit-to-header",
    )
    header_tokens, _start, opening, closing = _unique_class_body(
        header, owner, "fixed-array owner class"
    )
    member_range = _class_level_range(
        header_tokens,
        opening,
        closing,
        [
            *_type_tokens(element_type, "fixed-array element type"),
            array,
            "[",
            str(gen["count"]),
            "]",
            ";",
        ],
        "fixed-array member declaration",
    )
    _pin(
        _line(header, member_range),
        declaration["declaration_range_pin"],
        "fixed-array member declaration",
    )


def _shuffle_fragments(gen: Mapping[str, object]) -> tuple[bytes, bytes]:
    required = {
        "k",
        "array",
        "index",
        "index_type",
        "pointer",
        "element_type",
        "swap",
        "swap_type",
        "temporary",
        "temporary_type",
        "random_function",
        "count",
        "declaration_indent",
    }
    _keys(gen, required, "fixed-array shuffle")
    names = {
        name: _identifier(gen[name], f"fixed-array shuffle {name}")
        for name in ("array", "index", "pointer", "swap", "temporary", "random_function")
    }
    _need(len(set(names.values())) == len(names), "fixed-array shuffle roles collide")
    index_type = _type_text(gen["index_type"], "fixed-array shuffle index type")
    element_type = _type_text(gen["element_type"], "fixed-array shuffle element type")
    swap_type = _type_text(gen["swap_type"], "fixed-array shuffle swap type")
    temporary_type = _type_text(gen["temporary_type"], "fixed-array shuffle temporary type")
    _need(
        index_type == swap_type and element_type == temporary_type,
        "fixed-array shuffle paired types differ",
    )
    count = _integer(gen["count"], "fixed-array shuffle count")
    _need(count >= 2, "fixed-array shuffle count differs")
    indent = _string(gen["declaration_indent"], "fixed-array shuffle indentation")
    inner = indent + "\t"
    array, index, pointer = names["array"], names["index"], names["pointer"]
    swap, temporary, random_function = names["swap"], names["temporary"], names["random_function"]
    baseline = (
        f"{indent}for ({index} = 0; {index} < {count}; {index}++) {{\n"
        f"{inner}{swap_type} {swap} = {random_function}() % {count};\n"
        f"{inner}{temporary_type} {temporary} = {array}[{index}];\n"
        f"{inner}{array}[{index}] = {array}[{swap}];\n"
        f"{inner}{array}[{swap}] = {temporary};\n"
        f"{indent}}}\n"
    ).encode("ascii")
    output = (
        f"{indent}{element_type}* {pointer} = {array};\n"
        f"{indent}for ({index} = {count}; {index} != 0; {index}--) {{\n"
        f"{inner}{pointer}++;\n"
        f"{inner}{swap_type} {swap} = {random_function}() % {count};\n"
        f"{inner}{temporary_type} {temporary} = {pointer}[-1];\n"
        f"{inner}{pointer}[-1] = {array}[{swap}];\n"
        f"{inner}{array}[{swap}] = {temporary};\n"
        f"{indent}}}\n"
    ).encode("ascii")
    return baseline, output


def _prove_shuffle(
    *,
    clean_sources: Mapping[str, bytes],
    overlaid_paths: frozenset[str],
    owning_source: str,
    unit_data: bytes,
    clean_target: bytes,
    donor_target: bytes,
    proof: Mapping[str, object],
    gen: Mapping[str, object],
) -> None:
    baseline, output = _shuffle_fragments(gen)
    input_start = _unique_bytes(clean_target, baseline, "fixed-array shuffle seed form")
    _unique_bytes(donor_target, output, "fixed-array shuffle donor form")
    input_end = input_start + len(baseline)
    witness = _object(proof.get("semantic_witness"), "fixed-array shuffle witness")
    _keys(
        witness,
        {
            "source_owner",
            "array_member",
            "element_type",
            "extent",
            "index_identifier",
            "index_type",
            "owner_header",
            "base_header",
            "types_header",
            "next_index_overwrite_range_pin",
        },
        "fixed-array shuffle witness",
    )
    _need(
        witness["array_member"] == gen["array"]
        and witness["element_type"] == gen["element_type"] == gen["temporary_type"]
        and witness["index_identifier"] == gen["index"]
        and witness["index_type"] == gen["index_type"] == gen["swap_type"]
        and witness["extent"] == gen["count"],
        "fixed-array shuffle roles/types/extent differ",
    )
    owner = _identifier(witness["source_owner"], "fixed-array shuffle owner")
    _need(
        owner
        == _owner_from_mangled(proof.get("source_owner_mangled"), "fixed-array shuffle owner"),
        "fixed-array shuffle target owner differs",
    )
    _source_owner(clean_target, owner, "fixed-array shuffle target")
    tokens = _significant(clean_target)
    pointer = cast(str, gen["pointer"])
    _need(
        not any(token == pointer for token, _, _ in tokens),
        "fixed-array shuffle pointer is not fresh",
    )
    for identifier in (cast(str, gen["swap"]), cast(str, gen["temporary"])):
        expected = sum(token == identifier for token, _, _ in _significant(baseline))
        positions = [start for token, start, _ in tokens if token == identifier]
        _need(
            expected > 0
            and len(positions) == expected
            and all(input_start <= item < input_end for item in positions),
            f"fixed-array shuffle local {identifier!r} escapes its loop",
        )
    index_type = cast(str, gen["index_type"])
    index_identifier = cast(str, gen["index"])
    _decl_index, declaration_start, _decl_end = _unique_tokens(
        tokens,
        [*_type_tokens(index_type, "fixed-array shuffle index type"), index_identifier, ";"],
        "fixed-array shuffle index declaration",
    )
    _need(declaration_start < input_start, "fixed-array shuffle index is declared after use")
    next_lines = [
        line for line in clean_target[input_end:].splitlines(keepends=True) if _token_text(line)
    ]
    _need(bool(next_lines), "fixed-array shuffle has no following index overwrite")
    next_line = next_lines[0]
    _pin(next_line, witness["next_index_overwrite_range_pin"], "fixed-array shuffle next overwrite")
    _need(
        _token_text(next_line)[:6] == ["for", "(", index_identifier, "=", "0", ";"],
        "fixed-array shuffle index is read before overwrite",
    )
    next_start = clean_target.index(next_line, input_end)
    _need(
        _lexical_stack(tokens, declaration_start, "fixed-array shuffle")
        == _lexical_stack(tokens, input_start, "fixed-array shuffle")
        == _lexical_stack(tokens, next_start, "fixed-array shuffle"),
        "fixed-array shuffle declaration/use/overwrite scopes differ",
    )

    header_specs: dict[str, tuple[set[str], dict[str, object]]] = {
        "owner_header": (
            {
                "path",
                "source_sha256",
                "unit_include_range_pin",
                "base_include_range_pin",
                "array_declaration_range_pin",
                "member_block_range_pin",
            },
            {},
        ),
        "base_header": ({"path", "source_sha256", "types_include_range_pin"}, {}),
        "types_header": (
            {
                "path",
                "source_sha256",
                "element_typedef_range_pin",
                "index_typedef_range_pin",
            },
            {},
        ),
    }
    loaded: dict[str, tuple[str, bytes, dict[str, object]]] = {}
    for name, (keys, _unused) in header_specs.items():
        path, data, spec = _source(clean_sources, witness.get(name), f"shuffle {name}")
        _keys(spec, keys, f"shuffle {name}")
        _need(path not in overlaid_paths, f"shuffle witness header {path!r} is overlaid")
        loaded[name] = (path, data, spec)
    owner_path, owner_data, owner_spec = loaded["owner_header"]
    base_path, base_data, base_spec = loaded["base_header"]
    types_path, types_data, types_spec = loaded["types_header"]
    _need(len({owner_path, base_path, types_path}) == 3, "shuffle witness headers repeat")
    _include_edge(
        clean_sources,
        owning_source,
        unit_data,
        owner_path,
        owner_spec["unit_include_range_pin"],
        "shuffle unit-to-owner",
    )
    _include_edge(
        clean_sources,
        owner_path,
        owner_data,
        base_path,
        owner_spec["base_include_range_pin"],
        "shuffle owner-to-base",
    )
    _include_edge(
        clean_sources,
        base_path,
        base_data,
        types_path,
        base_spec["types_include_range_pin"],
        "shuffle base-to-types",
    )
    owner_tokens, _owner_start, owner_open, owner_close = _unique_class_body(
        owner_data, owner, "shuffle owner class"
    )
    member_range = _class_level_range(
        owner_tokens,
        owner_open,
        owner_close,
        [
            *_type_tokens(witness["element_type"], "shuffle element type"),
            cast(str, witness["array_member"]),
            "[",
            str(witness["extent"]),
            "]",
            ";",
        ],
        "shuffle array member",
    )
    declaration_line = _line(owner_data, member_range)
    _pin(declaration_line, owner_spec["array_declaration_range_pin"], "shuffle array member")
    declaration_line_start = owner_data.rfind(b"\n", 0, member_range[0]) + 1
    block_start = owner_data.rfind(b"\n", 0, max(0, declaration_line_start - 1)) + 1
    first_end = owner_data.find(b"\n", member_range[1])
    second_end = owner_data.find(b"\n", first_end + 1) if first_end >= 0 else -1
    _need(second_end >= 0, "shuffle member block is unterminated")
    _pin(
        owner_data[block_start : second_end + 1],
        owner_spec["member_block_range_pin"],
        "shuffle member block",
    )
    type_tokens = _significant(types_data)
    element = cast(str, witness["element_type"])
    index_type_text = cast(str, witness["index_type"])
    for name, underlying, pin_name in (
        (element, ["unsigned", "short"], "element_typedef_range_pin"),
        (index_type_text, ["signed", "int"], "index_typedef_range_pin"),
    ):
        _index, start, end = _unique_tokens(
            type_tokens, ["typedef", *underlying, name, ";"], f"shuffle typedef {name}"
        )
        _pin(_line(types_data, (start, end)), types_spec[pin_name], f"shuffle typedef {name}")


def _inclusive_fragments(gen: Mapping[str, object]) -> tuple[bytes, bytes]:
    _keys(
        gen,
        {
            "k",
            "type",
            "id",
            "source",
            "seed_extent_accessor",
            "upper_endpoint_accessor",
            "lower_endpoint_accessor",
            "destination",
            "declaration_indent",
            "barrier",
        },
        "inclusive extent",
    )
    _need(
        gen["barrier"] == "msvc_i386_empty_inline_assembly_v1", "inclusive-extent barrier differs"
    )
    source = _object(gen["source"], "inclusive-extent source")
    destination = _object(gen["destination"], "inclusive-extent destination")
    _keys(source, {"object", "aggregate_accessor"}, "inclusive-extent source")
    _keys(destination, {"object", "member"}, "inclusive-extent destination")
    coordinate_type = _type_text(gen["type"], "inclusive-extent coordinate type")
    identifier = _identifier(gen["id"], "inclusive-extent local")
    source_object = _identifier(source["object"], "inclusive-extent source object")
    aggregate = _identifier(source["aggregate_accessor"], "inclusive-extent aggregate accessor")
    destination_object = _identifier(destination["object"], "inclusive-extent destination object")
    destination_member = _identifier(destination["member"], "inclusive-extent destination member")
    seed = _identifier(gen["seed_extent_accessor"], "inclusive-extent seed accessor")
    upper = _identifier(gen["upper_endpoint_accessor"], "inclusive-extent upper accessor")
    lower = _identifier(gen["lower_endpoint_accessor"], "inclusive-extent lower accessor")
    indent = _string(gen["declaration_indent"], "inclusive-extent indentation")
    source_expression = f"{source_object}.{aggregate}()"
    destination_expression = f"{destination_object}.{destination_member}"
    baseline = f"{indent}{destination_expression} = {source_expression}.{seed}();\n".encode("ascii")
    output = (
        f"{indent}{coordinate_type} {identifier} = {source_expression}.{upper}() - "
        f"{source_expression}.{lower}();\n"
        f"{indent}++{identifier};\n"
        "#if defined(_MSC_VER) && defined(_M_IX86)\n"
        f"{indent}__asm {{\n"
        f"{indent}}}\n"
        "#endif\n"
        f"{indent}{destination_expression} = {identifier};\n"
    ).encode("ascii")
    return baseline, output


def _prove_inclusive(
    *,
    clean_sources: Mapping[str, bytes],
    overlaid_paths: frozenset[str],
    owning_source: str,
    unit_data: bytes,
    clean_target: bytes,
    donor_target: bytes,
    proof: Mapping[str, object],
    gen: Mapping[str, object],
) -> None:
    baseline, output = _inclusive_fragments(gen)
    baseline_position = _unique_bytes(clean_target, baseline, "inclusive-extent seed form")
    _unique_bytes(donor_target, output, "inclusive-extent donor form")
    witness = _object(proof.get("semantic_witness"), "inclusive-extent witness")
    _keys(
        witness,
        {
            "source_owner",
            "source_member",
            "source_member_type",
            "aggregate_accessor",
            "aggregate_member",
            "aggregate_type",
            "coordinate_type",
            "lower_accessor",
            "lower_member",
            "upper_accessor",
            "upper_member",
            "extent_accessor",
            "source_owner_header",
            "source_accessor_header",
            "extent_header",
        },
        "inclusive-extent witness",
    )
    source = cast(Mapping[str, object], gen["source"])
    role_pairs = (
        (source["object"], witness["source_member"]),
        (source["aggregate_accessor"], witness["aggregate_accessor"]),
        (gen["seed_extent_accessor"], witness["extent_accessor"]),
        (gen["upper_endpoint_accessor"], witness["upper_accessor"]),
        (gen["lower_endpoint_accessor"], witness["lower_accessor"]),
        (gen["type"], witness["coordinate_type"]),
    )
    _need(all(left == right for left, right in role_pairs), "inclusive-extent roles differ")
    coordinate = _type_text(witness["coordinate_type"], "inclusive-extent coordinate type")
    owner = _identifier(witness["source_owner"], "inclusive-extent owner")
    _need(
        owner == _owner_from_mangled(proof.get("source_owner_mangled"), "inclusive-extent owner"),
        "inclusive-extent target owner differs",
    )
    _source_owner(clean_target, owner, "inclusive-extent target")
    local = cast(str, gen["id"])
    _require_identifier_fresh_at_seat(
        clean_target,
        baseline_position,
        local,
        "inclusive-extent local",
    )

    expected_specs = {
        "source_owner_header": {
            "path",
            "source_sha256",
            "unit_include_range_pin",
            "member_declaration_range_pin",
        },
        "source_accessor_header": {
            "path",
            "source_sha256",
            "owner_include_range_pin",
            "accessor_range_pin",
        },
        "extent_header": {
            "path",
            "source_sha256",
            "accessor_include_range_pin",
            "concrete_inheritance_range_pin",
            "concrete_class_range_pin",
            "lower_accessor_range_pin",
            "upper_accessor_range_pin",
            "extent_accessor_range_pin",
        },
    }
    loaded: dict[str, tuple[str, bytes, dict[str, object]]] = {}
    for name, keys in expected_specs.items():
        path, data, spec = _source(clean_sources, witness.get(name), f"inclusive {name}")
        _keys(spec, keys, f"inclusive {name}")
        _need(path not in overlaid_paths, f"inclusive witness header {path!r} is overlaid")
        loaded[name] = path, data, spec
    owner_path, owner_data, owner_spec = loaded["source_owner_header"]
    accessor_path, accessor_data, accessor_spec = loaded["source_accessor_header"]
    extent_path, extent_data, extent_spec = loaded["extent_header"]
    _require_integral_type(
        clean_sources,
        extent_path,
        coordinate,
        "inclusive-extent coordinate type",
    )
    _need(len({owner_path, accessor_path, extent_path}) == 3, "inclusive witness headers repeat")
    _include_edge(
        clean_sources,
        owning_source,
        unit_data,
        owner_path,
        owner_spec["unit_include_range_pin"],
        "inclusive unit-to-owner",
    )
    _include_edge(
        clean_sources,
        owner_path,
        owner_data,
        accessor_path,
        accessor_spec["owner_include_range_pin"],
        "inclusive owner-to-accessor",
    )
    _include_edge(
        clean_sources,
        accessor_path,
        accessor_data,
        extent_path,
        extent_spec["accessor_include_range_pin"],
        "inclusive accessor-to-extent",
    )

    owner_tokens, _owner_start, owner_open, owner_close = _unique_class_body(
        owner_data, owner, "inclusive owner class"
    )
    member_range = _class_level_range(
        owner_tokens,
        owner_open,
        owner_close,
        [
            *_type_tokens(witness["source_member_type"], "inclusive source member type"),
            cast(str, witness["source_member"]),
            ";",
        ],
        "inclusive source member",
    )
    _pin(
        _line(owner_data, member_range),
        owner_spec["member_declaration_range_pin"],
        "inclusive source member",
    )
    accessor_tokens, _accessor_start, accessor_open, accessor_close = _unique_class_body(
        accessor_data, cast(str, witness["source_member_type"]), "inclusive accessor class"
    )
    accessor_range = _class_level_range(
        accessor_tokens,
        accessor_open,
        accessor_close,
        [
            cast(str, witness["aggregate_type"]),
            "&",
            cast(str, witness["aggregate_accessor"]),
            "(",
            ")",
            "{",
            "return",
            cast(str, witness["aggregate_member"]),
            ";",
            "}",
        ],
        "inclusive aggregate accessor",
    )
    _pin(
        _line(accessor_data, accessor_range),
        accessor_spec["accessor_range_pin"],
        "inclusive aggregate accessor",
    )
    aggregate_type = cast(str, witness["aggregate_type"])
    concrete_tokens, concrete_start, concrete_open, concrete_close = _unique_class_body(
        extent_data, aggregate_type, "inclusive concrete extent class"
    )
    coordinate_tokens = _type_tokens(coordinate, "inclusive coordinate type")
    inheritance_tail = [item[0] for item in concrete_tokens[concrete_start + 2 : concrete_open + 1]]
    _need(
        len(inheritance_tail) == len(coordinate_tokens) + 6
        and inheritance_tail[:2] == [":", "public"]
        and _IDENTIFIER_RE.fullmatch(inheritance_tail[2]) is not None
        and inheritance_tail[3:4] == ["<"]
        and inheritance_tail[4:-2] == coordinate_tokens
        and inheritance_tail[-2:] == [">", "{"],
        "inclusive concrete inheritance differs",
    )
    extent_template = inheritance_tail[2]
    extent_tokens, template_start, extent_open, extent_close = _unique_class_body(
        extent_data, extent_template, "inclusive extent template"
    )
    _need(
        template_start >= 5
        and [item[0] for item in extent_tokens[template_start - 5 : template_start - 2]]
        == ["template", "<", "class"]
        and _IDENTIFIER_RE.fullmatch(extent_tokens[template_start - 2][0]) is not None
        and extent_tokens[template_start - 1][0] == ">",
        "inclusive extent template declaration differs",
    )
    parameter = extent_tokens[template_start - 2][0]
    lower_range = _class_level_range(
        extent_tokens,
        extent_open,
        extent_close,
        [
            parameter,
            cast(str, witness["lower_accessor"]),
            "(",
            ")",
            "const",
            "{",
            "return",
            cast(str, witness["lower_member"]),
            ";",
            "}",
        ],
        "inclusive lower accessor",
    )
    upper_range = _class_level_range(
        extent_tokens,
        extent_open,
        extent_close,
        [
            parameter,
            cast(str, witness["upper_accessor"]),
            "(",
            ")",
            "const",
            "{",
            "return",
            cast(str, witness["upper_member"]),
            ";",
            "}",
        ],
        "inclusive upper accessor",
    )
    extent_range = _class_level_range(
        extent_tokens,
        extent_open,
        extent_close,
        [
            parameter,
            cast(str, witness["extent_accessor"]),
            "(",
            ")",
            "const",
            "{",
            "return",
            "(",
            cast(str, witness["upper_member"]),
            "-",
            cast(str, witness["lower_member"]),
            "+",
            "1",
            ")",
            ";",
            "}",
        ],
        "inclusive extent accessor",
    )
    inheritance = [
        "class",
        aggregate_type,
        ":",
        "public",
        extent_template,
        "<",
        *coordinate_tokens,
        ">",
        "{",
    ]
    _index, inheritance_start, inheritance_end = _unique_tokens(
        extent_tokens, inheritance, "inclusive concrete inheritance"
    )
    _pin(
        _line(extent_data, (inheritance_start, inheritance_end)),
        extent_spec["concrete_inheritance_range_pin"],
        "inclusive concrete inheritance",
    )
    _pin(
        _line(extent_data, lower_range),
        extent_spec["lower_accessor_range_pin"],
        "inclusive lower accessor",
    )
    _pin(
        _line(extent_data, upper_range),
        extent_spec["upper_accessor_range_pin"],
        "inclusive upper accessor",
    )
    _pin(
        _line(extent_data, extent_range),
        extent_spec["extent_accessor_range_pin"],
        "inclusive extent accessor",
    )
    _need(
        concrete_close + 1 < len(concrete_tokens) and concrete_tokens[concrete_close + 1][0] == ";",
        "inclusive concrete class terminator differs",
    )
    concrete_begin = extent_data.rfind(b"\n", 0, concrete_tokens[concrete_start][1]) + 1
    concrete_newline = extent_data.find(b"\n", concrete_tokens[concrete_close + 1][2])
    concrete_end = len(extent_data) if concrete_newline < 0 else concrete_newline + 1
    _pin(
        extent_data[concrete_begin:concrete_end],
        extent_spec["concrete_class_range_pin"],
        "inclusive concrete class",
    )
    direct = []
    depth = 1
    for token, _start, _end in concrete_tokens[concrete_open + 1 : concrete_close]:
        if depth == 1:
            direct.append(token)
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
    _need(
        not set(direct).intersection(
            {
                cast(str, witness["lower_accessor"]),
                cast(str, witness["upper_accessor"]),
                cast(str, witness["extent_accessor"]),
            }
        ),
        "inclusive concrete class shadows an inherited accessor",
    )


def _capture_fragment(gen: Mapping[str, object], *, output: bool) -> bytes:
    role = gen.get("role")
    if role == "capture_declaration":
        _keys(gen, {"k", "role", "type", "capture", "declaration_indent"}, "capture declaration")
        return (
            (
                f"{_string(gen['declaration_indent'], 'capture indentation')}"
                f"{_type_text(gen['type'], 'capture type')} "
                f"{_identifier(gen['capture'], 'capture identifier')};\n"
            ).encode("ascii")
            if output
            else b""
        )
    if role == "capture_assignment":
        _keys(gen, {"k", "role", "capture", "source", "declaration_indent"}, "capture assignment")
        return (
            (
                f"{_string(gen['declaration_indent'], 'capture indentation')}"
                f"{_identifier(gen['capture'], 'capture identifier')} = "
                f"{_identifier(gen['source'], 'capture source')};\n"
            ).encode("ascii")
            if output
            else b""
        )
    if role == "read_reseat":
        _keys(gen, {"k", "role", "capture", "source", "nl"}, "capture read reseat")
        _need(gen["nl"] is False, "capture read reseat must be unterminated")
        value = gen["capture"] if output else gen["source"]
        return _identifier(value, "capture read identity").encode("ascii")
    if role == "return_to_goto":
        _keys(gen, {"k", "role", "source", "label", "nl"}, "capture return branch")
        _need(gen["nl"] is False, "capture return branch must be unterminated")
        return (
            f"goto {_identifier(gen['label'], 'capture label')};"
            if output
            else f"return {_identifier(gen['source'], 'capture source')};"
        ).encode("ascii")
    _need(role == "tail_return", "capture tail role differs")
    _keys(gen, {"k", "role", "capture", "label", "declaration_indent"}, "capture tail return")
    if not output:
        return b""
    return (
        f"\n{_identifier(gen['label'], 'capture label')}:\n"
        f"{_string(gen['declaration_indent'], 'capture indentation')}"
        f"return {_identifier(gen['capture'], 'capture identifier')};\n"
    ).encode("ascii")


def _prove_capture(
    clean_target: bytes,
    donor_target: bytes,
    clean_unit: bytes,
    semantic_operations: Sequence[_Operation],
    clean_positions: Mapping[str, int],
) -> None:
    roles: dict[str, Mapping[str, object]] = {}
    donor_positions: dict[str, int] = {}
    for operation in semantic_operations:
        _need(len(operation.leaves) == 1, "capture operation must carry one generator")
        gen = operation.leaves[0]
        _need(gen.get("k") == "capture_tail", "capture operation kind differs")
        role = cast(str, gen.get("role"))
        _need(role not in roles, f"capture role repeats: {role!r}")
        expected_action = "replace" if role in {"read_reseat", "return_to_goto"} else "insert"
        _need(operation.action == expected_action, f"capture role {role!r} action differs")
        seed_fragment = _capture_fragment(gen, output=False)
        donor_fragment = _capture_fragment(gen, output=True)
        if seed_fragment:
            # The exact removed bytes are authenticated by the renderer
            # receipt.  Requiring their typed digest avoids pretending that a
            # common identifier must be globally unique in the function.
            removed = _object(operation.value.get("removed"), f"capture removed role {role}")
            _need(
                removed.get("sha256") == sha256(seed_fragment).hexdigest()
                and removed.get("size") == len(seed_fragment),
                f"capture seed role {role} differs",
            )
        # Common one-token fragments need not be unique.  The clean anchor
        # receipt supplies their authoritative order; the full donor target
        # pin and fragment digest still authenticate the rendered side.
        _need(donor_fragment in donor_target, f"capture donor role {role} is absent")
        donor_positions[role] = clean_positions[cast(str, operation.operation_id)]
        roles[role] = gen
    ordered = [
        "capture_declaration",
        "capture_assignment",
        "read_reseat",
        "return_to_goto",
        "tail_return",
    ]
    _need(set(roles) == set(ordered), "capture role set is incomplete")
    _need(
        [donor_positions[role] for role in ordered] == sorted(donor_positions.values()),
        "capture roles are reordered",
    )
    declaration, assignment, read, branch, tail = (roles[role] for role in ordered)
    capture = declaration["capture"]
    source = assignment["source"]
    label = branch["label"]
    _need(
        assignment["capture"] == capture
        and read["capture"] == capture
        and tail["capture"] == capture
        and read["source"] == source
        and branch["source"] == source
        and tail["label"] == label,
        "capture identities diverge",
    )
    clean_tokens = _token_text(clean_target)
    clean_unit_tokens = _token_text(clean_unit)
    _need(
        capture not in clean_tokens
        and label not in clean_tokens
        and capture not in clean_unit_tokens,
        "capture identity is not fresh",
    )


def _ctor_call_input(gen: Mapping[str, object]) -> bytes:
    indent = cast(str, gen["declaration_indent"])
    element = cast(str, gen["element_type"])
    caller = cast(str, gen["caller_result_identifier"])
    parameter = cast(str, gen["parameter_identifier"])
    null_position = cast(int, gen["null_argument_position"])
    null_members = cast(list[object], gen["null_members"])
    arguments = ", ".join(
        "NULL" if index == null_position else caller for index in range(len(null_members) + 1)
    )
    return (
        f"{indent}{element}* {caller} = new {element}[{gen['extent_function']}({parameter}) + 1];\n"
        f"{indent}{gen['copy_function']}({caller}, {parameter});\n\n"
        f"{indent}{gen['iterator_type']} {gen['iterator_identifier']} = "
        f"{gen['container_identifier']}.{gen['find_member']}({gen['class_identifier']}({arguments}));\n"
    ).encode("ascii")


def _ctor_call_output(gen: Mapping[str, object]) -> bytes:
    return (
        f"{gen['declaration_indent']}{gen['iterator_type']} {gen['iterator_identifier']} = "
        f"{gen['container_identifier']}.{gen['find_member']}({gen['class_identifier']}({gen['parameter_identifier']}));\n"
    ).encode("ascii")


def _ctor_body_output(gen: Mapping[str, object]) -> bytes:
    lines = [
        f"\t{gen['buffer_member']} = new {gen['element_type']}["
        f"{gen['extent_function']}({gen['parameter_identifier']}) + 1];",
        f"\t{gen['copy_function']}(({gen['buffer_cast_type']}) "
        f"{gen['buffer_member']}, {gen['parameter_identifier']});",
    ]
    lines.extend(f"\t{member} = NULL;" for member in cast(list[object], gen["null_members"]))
    return ("\n{\n" + "\n".join(lines) + "\n}\n\n").encode("ascii")


_CTOR_FIELDS = {
    "k",
    "role",
    "buffer_cast_type",
    "buffer_member",
    "caller_result_identifier",
    "caller_result_type",
    "class_identifier",
    "container_identifier",
    "copy_function",
    "declaration_indent",
    "element_type",
    "extent_function",
    "find_member",
    "iterator_identifier",
    "iterator_type",
    "null_argument_position",
    "null_members",
    "parameter_identifier",
}


def _prove_constructor_lift(
    *,
    clean_sources: Mapping[str, bytes],
    overlaid_paths: frozenset[str],
    owning_source: str,
    unit_data: bytes,
    clean_target: bytes,
    donor_target: bytes,
    donor_unit: bytes,
    proof: Mapping[str, object],
    consumer_parameters: Mapping[str, object],
    semantic_operations: Sequence[_Operation],
    rendered_sources: Mapping[str, bytes],
) -> None:
    roles: dict[str, tuple[_Operation, Mapping[str, object]]] = {}
    for operation in semantic_operations:
        _need(len(operation.leaves) == 1, "allocation-lift operation must carry one generator")
        gen = operation.leaves[0]
        if gen.get("k") == "member_sig":
            role = (
                "class_declaration"
                if gen.get("form") == "in_class_declaration"
                else "definition_header"
            )
        else:
            _need(gen.get("k") == "ctor_alloc_lift", "allocation-lift generator differs")
            role = cast(str, gen.get("role"))
        _need(role not in roles, f"allocation-lift role repeats: {role!r}")
        roles[role] = operation, gen
    _need(
        set(roles) == {"class_declaration", "definition_header", "constructor_body", "call_site"},
        "allocation-lift role set is incomplete",
    )
    declaration_op, declaration = roles["class_declaration"]
    definition_op, definition = roles["definition_header"]
    body_op, body = roles["constructor_body"]
    call_op, call = roles["call_site"]
    _need(
        declaration_op.action == definition_op.action == body_op.action == "insert"
        and call_op.action == "replace",
        "allocation-lift operation actions differ",
    )
    _need(
        definition_op.value.get("anchor") == body_op.value.get("anchor"),
        "allocation-lift definition header and body do not share one seat",
    )
    _keys(call, _CTOR_FIELDS, "allocation-lift call site")
    _keys(body, _CTOR_FIELDS, "allocation-lift constructor body")
    call_common = {key: value for key, value in call.items() if key != "role"}
    body_common = {key: value for key, value in body.items() if key != "role"}
    _need(call_common == body_common, "allocation-lift body and call roles diverge")
    baseline = _ctor_call_input(call)
    donor_call = _ctor_call_output(call)
    donor_body = _ctor_body_output(body)
    input_start = _unique_bytes(clean_target, baseline, "allocation-lift seed form")
    _unique_bytes(donor_target, donor_call, "allocation-lift donor call")
    _unique_bytes(donor_unit, donor_body, "allocation-lift donor body")
    input_end = input_start + len(baseline)

    witness = _object(proof.get("semantic_witness"), "allocation-lift witness")
    _keys(
        witness,
        {
            "source_owner",
            "entry_class",
            "buffer_member",
            "buffer_member_type",
            "null_members",
            "null_argument_position",
            "baseline_constructor_parameter_identifiers",
            "owner_header",
            "target_parameter_range_pin",
        },
        "allocation-lift witness",
    )
    null_members = _array(witness["null_members"], "allocation-lift null members")
    _need(len(null_members) == 1, "allocation-lift must null exactly one member")
    normalized_nulls = []
    for raw in null_members:
        item = _object(raw, "allocation-lift null member")
        _keys(item, {"identifier", "type"}, "allocation-lift null member")
        normalized_nulls.append(item)
    _need(
        witness["entry_class"] == call["class_identifier"]
        and witness["buffer_member"] == call["buffer_member"]
        and witness["null_argument_position"] == call["null_argument_position"]
        and [item["identifier"] for item in normalized_nulls] == call["null_members"],
        "allocation-lift witness roles differ",
    )
    member_type = _type_text(witness["buffer_member_type"], "allocation-lift buffer member type")
    cast_type = _type_text(call["buffer_cast_type"], "allocation-lift buffer cast type")
    _need(
        member_type.startswith("const ") and member_type[6:] == cast_type,
        "allocation-lift cast is not a const strip",
    )
    owner = _identifier(witness["source_owner"], "allocation-lift source owner")
    entry_class = _identifier(witness["entry_class"], "allocation-lift entry class")
    _need(
        owner == _owner_from_mangled(proof.get("source_owner_mangled"), "allocation-lift owner"),
        "allocation-lift target owner differs",
    )
    _source_owner(clean_target, owner, "allocation-lift target")
    target_tokens = _significant(clean_target)
    caller = cast(str, call["caller_result_identifier"])
    expected_count = sum(token == caller for token, _, _ in _significant(baseline))
    caller_positions = [start for token, start, _ in target_tokens if token == caller]
    _need(
        expected_count > 0
        and len(caller_positions) == expected_count
        and all(input_start <= item < input_end for item in caller_positions),
        "allocation-lift removed local escapes its range",
    )
    opening = next(index for index, item in enumerate(target_tokens) if item[0] == "{")
    open_paren = next(
        (index for index in range(opening - 1, -1, -1) if target_tokens[index][0] == "("), None
    )
    _need(open_paren is not None, "allocation-lift target has no parameter list")
    depth = 0
    close_paren = None
    for index in range(cast(int, open_paren), opening):
        if target_tokens[index][0] == "(":
            depth += 1
        elif target_tokens[index][0] == ")":
            depth -= 1
            if depth == 0:
                close_paren = index
                break
    _need(close_paren is not None, "allocation-lift parameter list is unbalanced")
    parameter = cast(str, call["parameter_identifier"])
    parameter_tokens = [
        item[0] for item in target_tokens[cast(int, open_paren) + 1 : cast(int, close_paren)]
    ]
    _need(
        parameter_tokens.count(parameter) == 1,
        "allocation-lift substituted identifier is not a target parameter",
    )
    _pin(
        _line(
            clean_target,
            (target_tokens[cast(int, open_paren)][1], target_tokens[cast(int, close_paren)][2]),
        ),
        witness["target_parameter_range_pin"],
        "allocation-lift target parameter list",
    )

    owner_path, owner_data, owner_spec = _source(
        clean_sources, witness.get("owner_header"), "allocation-lift owner header"
    )
    _keys(
        owner_spec,
        {
            "path",
            "source_sha256",
            "unit_include_range_pin",
            "class_body_range_pin",
            "buffer_member_declaration_range_pin",
            "null_member_declaration_range_pins",
            "baseline_constructor_range_pin",
            "destructor_body_range_pin",
        },
        "allocation-lift owner header",
    )
    _need(owner_path not in overlaid_paths, "allocation-lift witness header is overlaid")
    _include_edge(
        clean_sources,
        owning_source,
        unit_data,
        owner_path,
        owner_spec["unit_include_range_pin"],
        "allocation-lift unit-to-owner",
    )
    owner_tokens, class_start, class_open, class_close = _unique_class_body(
        owner_data, entry_class, "allocation-lift entry class"
    )
    class_begin = owner_data.rfind(b"\n", 0, owner_tokens[class_start][1]) + 1
    class_newline = owner_data.find(b"\n", owner_tokens[class_close][2])
    _need(class_newline >= 0, "allocation-lift entry class line is unterminated")
    _pin(
        owner_data[class_begin : class_newline + 1],
        owner_spec["class_body_range_pin"],
        "allocation-lift entry class",
    )
    buffer_range = _class_level_range(
        owner_tokens,
        class_open,
        class_close,
        [
            *_type_tokens(member_type, "allocation-lift buffer type"),
            cast(str, witness["buffer_member"]),
            ";",
        ],
        "allocation-lift buffer member",
    )
    _pin(
        _line(owner_data, buffer_range),
        owner_spec["buffer_member_declaration_range_pin"],
        "allocation-lift buffer member",
    )
    null_pins = _array(
        owner_spec["null_member_declaration_range_pins"], "allocation-lift null member pins"
    )
    _need(len(null_pins) == len(normalized_nulls), "allocation-lift null member pin count differs")
    for item, pin in zip(normalized_nulls, null_pins, strict=True):
        member_range = _class_level_range(
            owner_tokens,
            class_open,
            class_close,
            [
                *_type_tokens(item["type"], "allocation-lift null member type"),
                cast(str, item["identifier"]),
                ";",
            ],
            f"allocation-lift null member {item['identifier']}",
        )
        _pin(
            _line(owner_data, member_range),
            pin,
            f"allocation-lift null member {item['identifier']}",
        )
    parameter_ids = _array(
        witness["baseline_constructor_parameter_identifiers"],
        "allocation-lift constructor parameters",
    )
    _need(
        len(parameter_ids) == 2 and all(isinstance(item, str) for item in parameter_ids),
        "allocation-lift baseline constructor parameters differ",
    )
    argument_members = [
        normalized_nulls[0]
        if position == witness["null_argument_position"]
        else {"identifier": witness["buffer_member"], "type": witness["buffer_member_type"]}
        for position in range(2)
    ]
    wanted = [entry_class, "("]
    for position, member in enumerate(argument_members):
        if position:
            wanted.append(",")
        wanted.extend(_type_tokens(member["type"], "allocation-lift constructor argument type"))
        wanted.append(cast(str, parameter_ids[position]))
    wanted.extend([")", ":"])
    for position, member in enumerate(argument_members):
        if position:
            wanted.append(",")
        wanted.extend(
            [cast(str, member["identifier"]), "(", cast(str, parameter_ids[position]), ")"]
        )
    wanted.extend(["{", "}"])
    ctor_range = _class_level_range(
        owner_tokens, class_open, class_close, wanted, "allocation-lift baseline constructor"
    )
    _pin(
        _line(owner_data, ctor_range),
        owner_spec["baseline_constructor_range_pin"],
        "allocation-lift baseline constructor",
    )
    destructor_start, _destructor_end = _class_level_range(
        owner_tokens,
        class_open,
        class_close,
        ["~", entry_class, "(", ")"],
        "allocation-lift destructor",
    )
    body_open = next(
        (
            index
            for index, item in enumerate(owner_tokens)
            if item[1] >= destructor_start and item[0] == "{"
        ),
        None,
    )
    _need(body_open is not None, "allocation-lift destructor has no body")
    depth = 0
    body_close = None
    for index in range(cast(int, body_open), class_close):
        if owner_tokens[index][0] == "{":
            depth += 1
        elif owner_tokens[index][0] == "}":
            depth -= 1
            if depth == 0:
                body_close = index
                break
    _need(body_close is not None, "allocation-lift destructor is unbalanced")
    null_identifier = cast(str, normalized_nulls[0]["identifier"])
    expected_guard = [
        "if",
        "(",
        null_identifier,
        "==",
        "NULL",
        "&&",
        cast(str, witness["buffer_member"]),
        "!=",
        "NULL",
        ")",
        "{",
        "delete",
        "[",
        "]",
        "const_cast",
        "<",
        *_type_tokens(cast_type, "allocation-lift cast type"),
        ">",
        "(",
        cast(str, witness["buffer_member"]),
        ")",
        ";",
        "}",
    ]
    _need(
        [item[0] for item in owner_tokens[cast(int, body_open) + 1 : cast(int, body_close)]]
        == expected_guard,
        "allocation-lift destructor ownership guard differs",
    )
    _pin(
        owner_data[owner_tokens[cast(int, body_open)][1] : owner_tokens[cast(int, body_close)][2]],
        owner_spec["destructor_body_range_pin"],
        "allocation-lift destructor body",
    )

    signature = _object(proof.get("constructor_signature"), "allocation-lift constructor signature")
    _keys(signature, {"class_identifier", "parameters"}, "allocation-lift constructor signature")
    signature_parameters = _array(signature["parameters"], "allocation-lift signature parameters")
    _need(
        signature["class_identifier"] == entry_class and len(signature_parameters) == 1,
        "allocation-lift constructor signature differs",
    )
    signature_parameter = _object(signature_parameters[0], "allocation-lift signature parameter")
    _keys(signature_parameter, {"identifier", "type"}, "allocation-lift signature parameter")
    for member_signature, expected_form in (
        (declaration, "in_class_declaration"),
        (definition, "qualified_definition_header"),
    ):
        _need(
            member_signature.get("kind") == "constructor"
            and member_signature.get("form") == expected_form
            and member_signature.get("class_identifier") == entry_class
            and member_signature.get("member_identifier") == entry_class
            and member_signature.get("parameters") == signature_parameters,
            "allocation-lift member signature differs from its proof",
        )
    # The checked-in class must not already declare this new overload.
    signature_tokens = [
        entry_class,
        "(",
        *_type_tokens(signature_parameter["type"], "allocation-lift new parameter type"),
        cast(str, signature_parameter["identifier"]),
        ")",
    ]
    depth = 1
    overloads = 0
    for index in range(class_open + 1, class_close):
        if (
            depth == 1
            and [item[0] for item in owner_tokens[index : index + len(signature_tokens)]]
            == signature_tokens
        ):
            overloads += 1
        if owner_tokens[index][0] == "{":
            depth += 1
        elif owner_tokens[index][0] == "}":
            depth -= 1
    _need(overloads == 0, "allocation-lift constructor overload already exists")
    rendered_header = rendered_sources.get(owner_path)
    _need(rendered_header is not None, "allocation-lift rendered owner header is absent")
    rendered_tokens, _rendered_start, rendered_open, rendered_close = _unique_class_body(
        cast(bytes, rendered_header), entry_class, "allocation-lift rendered entry class"
    )
    _class_level_range(
        rendered_tokens,
        rendered_open,
        rendered_close,
        [*signature_tokens, ";"],
        "allocation-lift rendered constructor declaration",
    )
    baseline_tokens = _significant(baseline)
    called_seed = {
        token
        for index, (token, _start, _end) in enumerate(baseline_tokens)
        if _IDENTIFIER_RE.fullmatch(token)
        and index + 1 < len(baseline_tokens)
        and baseline_tokens[index + 1][0] == "("
    }
    body_tokens = _significant(donor_body)
    called_body = {
        token
        for index, (token, _start, _end) in enumerate(body_tokens)
        if _IDENTIFIER_RE.fullmatch(token)
        and index + 1 < len(body_tokens)
        and body_tokens[index + 1][0] == "("
    }
    _need(called_body <= called_seed, "allocation-lift body introduces a new call")
    local_delta = _object(
        consumer_parameters.get("local_set_delta"), "allocation-lift local-set delta"
    )
    _keys(local_delta, {"kind", "removed_records"}, "allocation-lift local-set delta")
    removed_records = _array(local_delta["removed_records"], "allocation-lift removed records")
    removed_ids = {
        _object(item, "allocation-lift removed record").get("identifier")
        for item in removed_records
    }
    _need(
        local_delta["kind"] == "removed_caller_locals_v1" and removed_ids == {caller},
        "allocation-lift local-set delta differs from its removed local",
    )


def _prove_private_state(
    *,
    donor: ClassicRecipeIntervention,
    operations: Sequence[_Operation],
    semantic_operations: Sequence[_Operation],
    owning_source: str,
    clean_sources: Mapping[str, bytes],
    rendered_sources: Mapping[str, bytes],
) -> SourceRefactorSemanticProof:
    kinds: list[str] = []
    operation_ids: list[str] = []
    seen_paths: set[str] = set()
    for operation in semantic_operations:
        _need(
            len(operation.leaves) == 1, "private compiler-state operation must carry one generator"
        )
        gen = operation.leaves[0]
        kind = cast(str, gen.get("k"))
        _need(kind in _PRIVATE_STATE_KINDS, "private compiler-state donor mixes a source refactor")
        _need(operation.operation_id is not None, "private compiler-state operation lacks an id")
        _need(operation.path not in seen_paths, "private compiler-state header repeats")
        seen_paths.add(operation.path)
        _need(
            PurePosixPath(operation.path).suffix.casefold() in {".h", ".hh", ".hpp", ".hxx"},
            "private compiler-state mutation is not in a header",
        )
        clean = clean_sources.get(operation.path)
        rendered = rendered_sources.get(operation.path)
        _need(
            clean is not None and rendered is not None,
            "private compiler-state header bytes are absent",
        )
        local = _identifier(gen.get("id"), "private compiler-state local")
        _need(
            local not in _token_text(cast(bytes, clean)),
            "private compiler-state local is not fresh",
        )
        if kind == "dead_updates":
            _keys(gen, {"k", "id", "initial", "increment", "repeat", "nl"}, "dead-local update")
            _need(
                operation.action == "replace" and gen["nl"] is False,
                "dead-local update must replace one inline body",
            )
            removed = _object(operation.value.get("removed"), "dead-local removed range")
            _keys(removed, {"sha256", "size"}, "dead-local removed range")
            _need(
                removed == {"sha256": sha256(b"{}").hexdigest(), "size": 2},
                "dead-local update does not replace exactly '{}'",
            )
        else:
            _keys(
                gen,
                {"k", "class", "id", "initial", "increment", "repeat"},
                "default-constructor dead update",
            )
            _need(operation.action == "insert", "default-constructor dead update must be inserted")
            class_identifier = _identifier(gen["class"], "default-constructor class")
            clean_tokens, _start, clean_open, clean_close = _unique_class_body(
                cast(bytes, clean), class_identifier, "default-constructor class"
            )
            direct_constructor = 0
            depth = 1
            for index in range(clean_open + 1, clean_close):
                if (
                    depth == 1
                    and clean_tokens[index][0] == class_identifier
                    and index + 1 < clean_close
                    and clean_tokens[index + 1][0] == "("
                ):
                    direct_constructor += 1
                if clean_tokens[index][0] == "{":
                    depth += 1
                elif clean_tokens[index][0] == "}":
                    depth -= 1
            _need(
                direct_constructor == 0, "default-constructor class already declares a constructor"
            )
            rendered_tokens, _rendered_start, rendered_open, rendered_close = _unique_class_body(
                cast(bytes, rendered), class_identifier, "rendered default-constructor class"
            )
            _class_level_range(
                rendered_tokens,
                rendered_open,
                rendered_close,
                [class_identifier, "(", ")", "{", "int", local, "="],
                "rendered default constructor",
            )
        initial = _integer(gen.get("initial"), "private compiler-state initial value")
        increment = _integer(gen.get("increment"), "private compiler-state increment")
        repeat = _integer(gen.get("repeat"), "private compiler-state repeat")
        _need(
            increment != 0
            and 0 <= repeat <= 64
            and -(1 << 31) <= initial + increment * repeat < (1 << 31),
            "private compiler-state arithmetic can overflow",
        )
        kinds.append(kind)
        operation_ids.append(cast(str, operation.operation_id))
    _safe_nonsemantic_operations(operations, frozenset(map(id, semantic_operations)), owning_source)
    statement = {
        "intervention": donor.id,
        "classification": "donor_private_compiler_state_v1",
        "generator_kinds": sorted(kinds),
        "operation_ids": sorted(operation_ids),
    }
    return SourceRefactorSemanticProof(
        donor.id,
        "donor_private_compiler_state_v1",
        tuple(sorted(kinds)),
        tuple(sorted(operation_ids)),
        Digest.from_bytes(canonical_json(statement)),
    )


def validate_donor_source_semantics(
    donor: ClassicRecipeIntervention,
    consumers: Sequence[ClassicRecipeIntervention],
    *,
    owning_source: str,
    clean_sources: Mapping[str, bytes],
    rendered_sources: Mapping[str, bytes],
    overlaid_paths: frozenset[str] = frozenset(),
    overlay_receipts: Sequence[ClassicOverlayOutputReceipt] = (),
) -> SourceRefactorSemanticProof | None:
    """Validate the closed semantic claim of one rendered overlay donor.

    Declaration-only donors return ``None``.  Any donor carrying one of the
    admitted source mutation generators must have exactly one reviewed
    consumer.  Unknown future refactor kinds are not inferred here: they must
    add an explicit rule before being admitted.
    """

    if donor.family is not ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        return None
    _need(donor.role is ClassicRecipeRole.DONOR, "source semantics require a donor")
    parameters = _parameters(donor)
    operations = _operations(parameters)
    semantic_operations = _semantic_operations(operations)
    if not semantic_operations:
        return None
    receipts = _receipt_index(overlay_receipts)
    _need(bool(receipts), "source-mutating donor lacks overlay operation receipts")
    for operation in semantic_operations:
        operation_id = operation.operation_id
        _need(operation_id is not None, "source-mutating operation lacks an id")
        _need(
            (operation.path, operation_id) in receipts,
            f"source refactor operation {operation_id!r} lacks a receipt",
        )
    _need(len(consumers) == 1, "source-mutating donor must have exactly one consumer")
    consumer = consumers[0]
    _need(
        consumer.role is ClassicRecipeRole.FUNCTION and donor.id in consumer.dependencies,
        "source-mutating donor consumer binding differs",
    )
    consumer_parameters = _parameters(consumer)
    kinds = {
        cast(str, leaf.get("k"))
        for operation in semantic_operations
        for leaf in operation.leaves
        if leaf.get("k") != "member_sig"
    }
    if kinds <= _PRIVATE_STATE_KINDS:
        _need(
            "target_source_refactor" not in consumer_parameters,
            "private compiler-state donor is mislabeled as a target refactor",
        )
        return _prove_private_state(
            donor=donor,
            operations=operations,
            semantic_operations=semantic_operations,
            owning_source=owning_source,
            clean_sources=clean_sources,
            rendered_sources=rendered_sources,
        )

    _need(
        not kinds.intersection(_PRIVATE_STATE_KINDS),
        "source refactor mixes private compiler-state operations",
    )
    _need(len(kinds) == 1 and kinds <= _TRUE_REFACTOR_KINDS, "source refactor kind set differs")
    proof = _object(
        consumer_parameters.get("target_source_refactor"), "target source refactor proof"
    )
    proof_kind = proof.get("kind")
    expected_kind = {
        "for_initializer_declaration_reseat_v1": "for_init_decl",
        "fixed_array_fill_loop_v1": "fixed_array_fill",
        "fixed_array_shuffle_pointer_countdown_v1": "fixed_array_shuffle_countdown",
        "inclusive_extent_assignment_v1": "inclusive_extent",
        "constructor_allocation_lift_v1": "ctor_alloc_lift",
        "captured_pointer_tail_return_v1": "capture_tail",
    }.get(cast(str, proof_kind))
    _need(
        expected_kind is not None and kinds == {expected_kind},
        "source refactor proof kind differs from its generator",
    )
    common_keys = {
        "kind",
        "selector",
        "start_marker",
        "source_owner_mangled",
        "seed_range_pin",
        "donor_range_pin",
        "operation_ids",
    }
    additions = {
        "fixed_array_fill_loop_v1": {"array_declaration"},
        "fixed_array_shuffle_pointer_countdown_v1": {"semantic_witness"},
        "inclusive_extent_assignment_v1": {"semantic_witness"},
        "constructor_allocation_lift_v1": {"semantic_witness", "constructor_signature"},
    }.get(cast(str, proof_kind), set())
    _keys(proof, common_keys | additions, "target source refactor proof")
    _need(
        proof["selector"] == "brace_balanced_function_after_marker_v1",
        "target source refactor selector differs",
    )
    _need(
        proof["source_owner_mangled"] == consumer.symbol,
        "target source refactor owner differs from its consumer",
    )
    operation_ids = _array(proof["operation_ids"], "target source refactor operation ids")
    _need(
        bool(operation_ids)
        and len(operation_ids) == len(set(operation_ids))
        and all(isinstance(item, str) for item in operation_ids),
        "target source refactor operation ids differ",
    )
    actual_ids = [operation.operation_id for operation in semantic_operations]
    _need(
        None not in actual_ids and set(actual_ids) == set(operation_ids),
        "target source refactor operation set is incomplete",
    )
    expected_counts = {
        "for_init_decl": 1,
        "fixed_array_fill": 1,
        "fixed_array_shuffle_countdown": 1,
        "inclusive_extent": 1,
        "capture_tail": 5,
        "ctor_alloc_lift": 4,
    }
    _need(
        len(semantic_operations) == expected_counts[cast(str, expected_kind)],
        "target source refactor operation count differs",
    )
    _safe_nonsemantic_operations(operations, frozenset(map(id, semantic_operations)), owning_source)
    _need(
        owning_source in clean_sources and owning_source in rendered_sources,
        "source refactor owning-TU bytes are absent",
    )
    clean_unit = clean_sources[owning_source]
    donor_unit = rendered_sources[owning_source]
    try:
        require_target_source_refactor_identity(
            clean_unit,
            donor_unit,
            proof,
            f"donor {donor.id} source refactor",
        )
        clean_target = select_source_permutation_window(
            clean_unit, proof, f"donor {donor.id} clean target"
        )
        donor_target = select_source_permutation_window(
            donor_unit, proof, f"donor {donor.id} donor target"
        )
    except ValueError as exc:
        raise SourceRefactorSemanticError(str(exc)) from exc
    target_start = clean_unit.index(clean_target)
    target_end = target_start + len(clean_target)
    _prove_true_refactor_entropy(
        operations=operations,
        semantic_operations=semantic_operations,
        owning_source=owning_source,
        clean_sources=clean_sources,
        receipts=receipts,
        target_start=target_start,
        target_end=target_end,
    )
    clean_positions: dict[str, int] = {}
    for operation in semantic_operations:
        _need(
            operation.path == owning_source
            or (
                expected_kind == "ctor_alloc_lift" and operation.leaves[0].get("k") == "member_sig"
            ),
            "source refactor operation leaves its owning TU",
        )
        operation_id = cast(str, operation.operation_id)
        receipt = receipts.get((operation.path, operation_id))
        _need(receipt is not None, f"source refactor operation {operation_id!r} lacks a receipt")
        assert receipt is not None
        receipt_anchors = receipt.anchors
        _need(bool(receipt_anchors), f"source refactor operation {operation_id!r} has no anchor")
        start = receipt_anchors[0].byte_offset
        if operation.path == owning_source:
            end = receipt_anchors[-1].byte_offset
            definition_seat = expected_kind == "ctor_alloc_lift" and (
                operation.leaves[0].get("role") == "constructor_body"
                or (
                    operation.leaves[0].get("k") == "member_sig"
                    and operation.leaves[0].get("form") == "qualified_definition_header"
                )
            )
            if definition_seat:
                _need(
                    start == end and start <= target_start,
                    f"source refactor operation {operation_id!r} has the wrong definition seat",
                )
            else:
                _need(
                    target_start <= start <= end <= target_end,
                    f"source refactor operation {operation_id!r} leaves its target",
                )
            clean_positions[operation_id] = start
    primary_generators = [
        operation.leaves[0]
        for operation in semantic_operations
        if operation.leaves[0].get("k") == expected_kind
    ]
    if expected_kind == "for_init_decl":
        _prove_for_initializer(clean_target, donor_target, primary_generators[0])
    elif expected_kind == "fixed_array_fill":
        _prove_fixed_fill(
            clean_sources=clean_sources,
            owning_source=owning_source,
            unit_data=clean_unit,
            clean_target=clean_target,
            donor_target=donor_target,
            proof=proof,
            gen=primary_generators[0],
        )
    elif expected_kind == "fixed_array_shuffle_countdown":
        _need(
            consumer.family
            in {
                ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC,
                ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY,
            }
            and isinstance(consumer_parameters.get("source_fpo_identity"), Mapping)
            and "ordinary_fpo_identity" not in consumer_parameters,
            "fixed-array shuffle lacks its isolated source-FPO consumer",
        )
        _prove_shuffle(
            clean_sources=clean_sources,
            overlaid_paths=overlaid_paths,
            owning_source=owning_source,
            unit_data=clean_unit,
            clean_target=clean_target,
            donor_target=donor_target,
            proof=proof,
            gen=primary_generators[0],
        )
    elif expected_kind == "inclusive_extent":
        _prove_inclusive(
            clean_sources=clean_sources,
            overlaid_paths=overlaid_paths,
            owning_source=owning_source,
            unit_data=clean_unit,
            clean_target=clean_target,
            donor_target=donor_target,
            proof=proof,
            gen=primary_generators[0],
        )
    elif expected_kind == "capture_tail":
        _prove_capture(
            clean_target,
            donor_target,
            clean_unit,
            semantic_operations,
            clean_positions,
        )
    else:
        _need(
            consumer.family is ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT,
            "allocation lift lacks its retail-exact divergent consumer",
        )
        _prove_constructor_lift(
            clean_sources=clean_sources,
            overlaid_paths=overlaid_paths,
            owning_source=owning_source,
            unit_data=clean_unit,
            clean_target=clean_target,
            donor_target=donor_target,
            donor_unit=donor_unit,
            proof=proof,
            consumer_parameters=consumer_parameters,
            semantic_operations=semantic_operations,
            rendered_sources=rendered_sources,
        )
    statement = {
        "intervention": donor.id,
        "consumer": consumer.id,
        "classification": "logic_equivalent_target_source_refactor_v1",
        "generator_kinds": sorted(kinds),
        "operation_ids": sorted(cast(list[str], operation_ids)),
    }
    return SourceRefactorSemanticProof(
        donor.id,
        "logic_equivalent_target_source_refactor_v1",
        tuple(sorted(kinds)),
        tuple(sorted(cast(list[str], operation_ids))),
        Digest.from_bytes(canonical_json(statement)),
    )


__all__ = [
    "SourceRefactorSemanticError",
    "SourceRefactorSemanticProof",
    "validate_donor_source_semantics",
]
