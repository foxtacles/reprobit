"""Source-language claims and leaf-level safety checks for classic overlays."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal

from reprobit.classic.overlay_declarations import (
    _declaration_entities,
    _declaration_owned_identifiers,
    _DeclarationFact,
)
from reprobit.classic.overlay_types import ClassicOverlayOperationReceipt
from reprobit.classic.semantic_contracts import CleanSourceInput
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic.source_proofs import iter_source_overlay_tokens, source_overlay_tokens
from reprobit.model import Digest
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole
from reprobit.schema import ClassicRecipeIntervention

_SOURCE_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx"})
_HEADER_SUFFIXES = frozenset({".h", ".hh", ".hpp", ".hxx", ".inc", ".inl"})
_CPP_SOURCE_SUFFIXES = _SOURCE_SUFFIXES | _HEADER_SUFFIXES
_INTEGRAL_TYPE_TOKENS = frozenset(
    {"bool", "char", "int", "long", "short", "signed", "unsigned", "wchar_t"}
)
_UNREACHABLE_HELPER_GENERATORS = frozenset(
    {"crt_pull", "cursor_probe", "local_probe", "member_probe", "seed_seq"}
)
_ORDERED_ARCHIVE_SEED_HELPER = "SeedOrder"
_ORDERED_ARCHIVE_SEED_POLICY = "reverse_statement_order_msvc_4_20"
_FUNCTION_CLAIM_GENERATORS = frozenset(
    {"assert_reseat", "empty_scopes", "literal_alias", "local_ids", "noop_assign"}
)


def _relative(value: str, *, label: str) -> str:
    if not value or "\x00" in value or "\\" in value:
        raise ClassicSemanticError(f"{label} is not a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ClassicSemanticError(f"{label} is not a normalized relative path")
    return path.as_posix()


@dataclass(frozen=True, slots=True)
class _ScalarBinding:
    identifier: str
    type_spelling: str
    initialized: bool


@dataclass(frozen=True, slots=True)
class _FunctionScopeClaim:
    operation_id: str
    leaf_index: int
    function: str
    range_digest: Digest
    range_size: int
    bindings: tuple[_ScalarBinding, ...]


@dataclass(frozen=True, slots=True)
class _LogicalHeaderClaim:
    operation_id: str
    leaf_index: int
    logical_path: str


_SemanticClaim = _FunctionScopeClaim | _LogicalHeaderClaim


def _claim_key(operation_id: str, leaf_index: int) -> str:
    return f"{operation_id.casefold()}\0{leaf_index:08d}"


def _parse_semantic_claims(
    intervention: ClassicRecipeIntervention,
) -> dict[str, _SemanticClaim]:
    values = {item.name: item.value for item in intervention.parameters}
    raw = values.get("semantic_claims")
    if not isinstance(raw, dict) or set(raw) != {"bindings", "schema"} or raw.get("schema") != 1:
        raise ClassicSemanticError(
            f"overlay {intervention.id!r} lacks closed semantic_claims schema 1"
        )
    bindings = raw.get("bindings")
    if not isinstance(bindings, list):
        raise ClassicSemanticError(f"overlay {intervention.id!r} semantic claims are malformed")
    result: dict[str, _SemanticClaim] = {}
    order: list[tuple[str, str]] = []
    for index, item in enumerate(bindings):
        if not isinstance(item, dict):
            raise ClassicSemanticError(
                f"overlay {intervention.id!r} semantic claim {index} is malformed"
            )
        kind = item.get("kind")
        operation = item.get("operation")
        if not isinstance(operation, str) or not operation or "\x00" in operation:
            raise ClassicSemanticError("semantic claim operation identity is malformed")
        leaf = item.get("leaf")
        if not isinstance(leaf, int) or isinstance(leaf, bool) or leaf < 0:
            raise ClassicSemanticError("semantic claim leaf index is malformed")
        key = _claim_key(operation, leaf)
        if key in result:
            raise ClassicSemanticError("semantic claims repeat an operation leaf")
        if kind == "logical_header":
            if set(item) != {"kind", "leaf", "logical_path", "operation"} or not isinstance(
                item.get("logical_path"), str
            ):
                raise ClassicSemanticError("logical-header claim is malformed")
            claim: _SemanticClaim = _LogicalHeaderClaim(
                operation,
                leaf,
                _relative(str(item["logical_path"]), label="logical header claim"),
            )
        elif kind == "function_scope":
            if set(item) != {
                "bindings",
                "function",
                "kind",
                "leaf",
                "operation",
                "range_sha256",
                "range_size",
            }:
                raise ClassicSemanticError("function-scope claim is not closed")
            function = item.get("function")
            digest = item.get("range_sha256")
            size = item.get("range_size")
            raw_scalar_bindings = item.get("bindings")
            if (
                not isinstance(function, str)
                or not function
                or re.fullmatch(r"[0-9a-f]{64}", str(digest)) is None
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size <= 0
                or not isinstance(raw_scalar_bindings, list)
            ):
                raise ClassicSemanticError("function-scope claim is malformed")
            scalar_bindings: list[_ScalarBinding] = []
            for raw_binding in raw_scalar_bindings:
                if not isinstance(raw_binding, dict) or set(raw_binding) != {
                    "identifier",
                    "initialized",
                    "type",
                }:
                    raise ClassicSemanticError("scalar binding claim is malformed")
                identifier = raw_binding.get("identifier")
                type_spelling = raw_binding.get("type")
                initialized = raw_binding.get("initialized")
                if (
                    not isinstance(identifier, str)
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier) is None
                    or not isinstance(type_spelling, str)
                    or not type_spelling
                    or not isinstance(initialized, bool)
                ):
                    raise ClassicSemanticError("scalar binding claim is malformed")
                scalar_bindings.append(_ScalarBinding(identifier, type_spelling, initialized))
            if scalar_bindings != sorted(
                scalar_bindings, key=lambda binding: binding.identifier.casefold()
            ) or len({binding.identifier.casefold() for binding in scalar_bindings}) != len(
                scalar_bindings
            ):
                raise ClassicSemanticError("scalar bindings are not canonical")
            claim = _FunctionScopeClaim(
                operation,
                leaf,
                function,
                Digest(value=str(digest)),
                size,
                tuple(scalar_bindings),
            )
        else:
            raise ClassicSemanticError(f"unknown semantic claim kind {kind!r}")
        result[key] = claim
        order.append((operation.casefold(), f"{leaf:08d}:{kind}"))
    if order != sorted(order):
        raise ClassicSemanticError("semantic claims are not canonically ordered")
    return result


def _token_texts(payload: bytes) -> tuple[str, ...]:
    return tuple(token for token, _start, _end in source_overlay_tokens(payload))


def _matching_token_index(
    tokens: Sequence[tuple[str, int, int]], start: int, opening: str, closing: str
) -> int | None:
    depth = 0
    for index in range(start, len(tokens)):
        token = tokens[index][0]
        if token == opening:
            depth += 1
        elif token == closing:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return None
    return None


def _function_body_range(payload: bytes, function: str) -> tuple[int, int]:
    tokens = source_overlay_tokens(payload)
    name_tokens = tuple(part for part in re.split(r"(::)", function) if part)
    if not name_tokens or any(not part for part in name_tokens):
        raise ClassicSemanticError(f"function claim has an invalid name: {function!r}")
    candidates: list[tuple[int, int]] = []
    for index in range(len(tokens) - len(name_tokens)):
        if tuple(item[0] for item in tokens[index : index + len(name_tokens)]) != name_tokens:
            continue
        opening_paren = index + len(name_tokens)
        if opening_paren >= len(tokens) or tokens[opening_paren][0] != "(":
            continue
        closing_paren = _matching_token_index(tokens, opening_paren, "(", ")")
        if closing_paren is None:
            continue
        opening_brace: int | None = None
        cursor = closing_paren + 1
        while cursor < len(tokens) and tokens[cursor][0] not in {";", "{"}:
            cursor += 1
        if cursor < len(tokens) and tokens[cursor][0] == "{":
            opening_brace = cursor
        if opening_brace is None:
            continue
        closing_brace = _matching_token_index(tokens, opening_brace, "{", "}")
        if closing_brace is None:
            raise ClassicSemanticError(f"function {function!r} has unbalanced braces")
        candidates.append((tokens[opening_brace][1], tokens[closing_brace][2]))
    if len(candidates) != 1:
        raise ClassicSemanticError(
            f"function claim {function!r} resolves {len(candidates)} definitions"
        )
    return candidates[0]


def _validate_function_claim(
    *,
    claim: _FunctionScopeClaim,
    payload: bytes,
    anchor_offsets: Sequence[int],
) -> tuple[int, int]:
    start, end = _function_body_range(payload, claim.function)
    selected = payload[start:end]
    if len(selected) != claim.range_size or Digest.from_bytes(selected) != claim.range_digest:
        raise ClassicSemanticError(f"function claim range changed for {claim.function!r}")
    if not anchor_offsets or any(offset < start or offset > end for offset in anchor_offsets):
        raise ClassicSemanticError(
            f"operation {claim.operation_id!r} is outside function {claim.function!r}"
        )
    return start, end


def _type_tokens(type_spelling: str) -> tuple[str, ...]:
    try:
        encoded = type_spelling.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ClassicSemanticError("scalar type spelling is not ASCII") from exc
    tokens = _token_texts(encoded)
    if not tokens or any(token in {";", "{", "}"} for token in tokens):
        raise ClassicSemanticError("scalar type spelling is malformed")
    return tokens


def _typedef_underlyings(
    clean_sources: Mapping[str, CleanSourceInput], alias: str
) -> set[tuple[str, ...]]:
    results: set[tuple[str, ...]] = set()
    for source in clean_sources.values():
        tokens = source_overlay_tokens(source.payload)
        for index, (token, _start, _end) in enumerate(tokens):
            if token != alias:
                continue
            left = index - 1
            while left >= 0 and tokens[left][0] not in {";", "{", "}"}:
                left -= 1
            right = index + 1
            while right < len(tokens) and tokens[right][0] != ";":
                if tokens[right][0] in {"{", "}"}:
                    break
                right += 1
            statement = tuple(item[0] for item in tokens[left + 1 : right])
            typedef_index = max(
                (offset for offset, item in enumerate(statement) if item == "typedef"),
                default=-1,
            )
            if typedef_index >= 0 and statement[-1] == alias:
                underlying = statement[typedef_index + 1 : -1]
                if underlying and all(token not in {"(", ")", "[", "]"} for token in underlying):
                    results.add(underlying)
            using_index = max(
                (offset for offset, item in enumerate(statement) if item == "using"),
                default=-1,
            )
            if statement[using_index : using_index + 3] == ("using", alias, "="):
                results.add(statement[using_index + 3 :])
    return results


def _is_nonvolatile_integral_type(
    type_spelling: str,
    clean_sources: Mapping[str, CleanSourceInput],
    *,
    seen: frozenset[str] = frozenset(),
) -> bool:
    tokens = tuple(token for token in _type_tokens(type_spelling) if token != "const")
    if "volatile" in tokens or any(token in {"*", "&", "[", "]"} for token in tokens):
        return False
    if tokens and set(tokens) <= _INTEGRAL_TYPE_TOKENS:
        return True
    if len(tokens) != 1 or tokens[0] in seen:
        return False
    alias = tokens[0]
    underlyings = _typedef_underlyings(clean_sources, alias)
    return bool(underlyings) and all(
        _is_nonvolatile_integral_type(" ".join(underlying), clean_sources, seen=seen | {alias})
        for underlying in underlyings
    )


def _validate_scalar_binding(
    *,
    claim: _ScalarBinding,
    payload: bytes,
    function_range: tuple[int, int],
    before_offset: int,
    clean_sources: Mapping[str, CleanSourceInput],
) -> None:
    if not _is_nonvolatile_integral_type(claim.type_spelling, clean_sources):
        raise ClassicSemanticError(
            f"scalar binding {claim.identifier!r} is not a proven integral type"
        )
    tokens = source_overlay_tokens(payload)
    type_tokens = _type_tokens(claim.type_spelling)
    candidates = 0
    for index, (token, start, _end) in enumerate(tokens):
        if token != claim.identifier or not (
            function_range[0] < start < min(function_range[1], before_offset)
        ):
            continue
        left = index - 1
        while left >= 0 and tokens[left][0] not in {";", "{", "}"}:
            left -= 1
        right = index + 1
        while right < len(tokens) and tokens[right][0] not in {";", "{", "}"}:
            right += 1
        statement = tuple(item[0] for item in tokens[left + 1 : right])
        prefix = statement[: statement.index(claim.identifier)]
        if not any(
            prefix[offset : offset + len(type_tokens)] == type_tokens
            for offset in range(len(prefix) - len(type_tokens) + 1)
        ):
            continue
        if "volatile" in statement:
            continue
        suffix = statement[statement.index(claim.identifier) + 1 :]
        initialized = "=" in suffix
        if initialized != claim.initialized:
            continue
        candidates += 1
    if candidates != 1:
        raise ClassicSemanticError(
            f"scalar binding {claim.identifier!r} resolves {candidates} declarations"
        )


def _compiler_include_roots(node: ProducerNode) -> tuple[str, ...]:
    roots: list[str] = []
    arguments = node.arguments
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        value: str | None = None
        folded = argument.casefold()
        if folded in {"-i", "/i"} and index + 1 < len(arguments):
            index += 1
            value = arguments[index]
        elif folded.startswith("-i") or folded.startswith("/i"):
            value = argument[2:]
        if value in {"${SOURCE}", "${SOURCE}/"}:
            roots.append("")
        elif value is not None and value.startswith("${SOURCE}/"):
            roots.append(_relative(value.removeprefix("${SOURCE}/"), label="include root"))
        index += 1
    return tuple(roots)


def _resolve_logical_header(
    *,
    source_path: str,
    header: str,
    style: object,
    compiler_nodes: Sequence[ProducerNode],
    authority_paths: Mapping[str, str],
) -> str:
    candidates: set[str] = set()
    for node in compiler_nodes:
        search_roots: list[str] = []
        if style == "quote":
            parent = PurePosixPath(source_path).parent.as_posix()
            if parent != ".":
                search_roots.append(parent)
        elif style != "angle":
            raise ClassicSemanticError("include style is outside the closed enum")
        search_roots.extend(_compiler_include_roots(node))
        resolved: str | None = None
        for root in search_roots:
            candidate = PurePosixPath(root, header).as_posix()
            actual = authority_paths.get(candidate.casefold())
            if actual is not None:
                resolved = actual
                break
        if resolved is None:
            raise ClassicSemanticError(
                f"include {header!r} from {source_path!r} has no admitted resolution"
            )
        candidates.add(resolved)
    if len(candidates) != 1:
        raise ClassicSemanticError(
            f"include {header!r} from {source_path!r} resolves inconsistently"
        )
    return next(iter(candidates))


def _standard_assert_header_is_unshadowed(
    compiler_nodes: Sequence[ProducerNode],
    authority_paths: Mapping[str, str],
) -> bool:
    """Prove that project include roots cannot precede the locked ``assert.h``."""

    return all(
        PurePosixPath(root, "assert.h").as_posix().casefold() not in authority_paths
        for node in compiler_nodes
        for root in _compiler_include_roots(node)
    )


def _brace_depth_at(payload: bytes, offset: int) -> int:
    depth = 0
    for token, start, _end in source_overlay_tokens(payload):
        if start >= offset:
            break
        if token == "{":
            depth += 1
        elif token == "}":
            depth -= 1
            if depth < 0:
                raise ClassicSemanticError("clean source has unbalanced braces")
    return depth


def _source_neighbors(payload: bytes, offset: int) -> tuple[str | None, str | None, int, int]:
    """Return significant neighbors and expression nesting at a byte boundary."""

    tokens = source_overlay_tokens(payload)
    previous: str | None = None
    following: str | None = None
    parenthesis_depth = 0
    bracket_depth = 0
    for token, start, end in tokens:
        if start < offset < end:
            raise ClassicSemanticError("source-overlay seat splits a significant token")
        if end <= offset:
            previous = token
            if token == "(":
                parenthesis_depth += 1
            elif token == ")":
                parenthesis_depth -= 1
            elif token == "[":
                bracket_depth += 1
            elif token == "]":
                bracket_depth -= 1
            if parenthesis_depth < 0 or bracket_depth < 0:
                raise ClassicSemanticError("source-overlay seat has unbalanced delimiters")
            continue
        following = token
        break
    return previous, following, parenthesis_depth, bracket_depth


def _previous_physical_line_is_directive(payload: bytes, offset: int) -> bool:
    line_start = payload.rfind(b"\n", 0, offset) + 1
    if payload[line_start:offset].strip():
        return False
    end = line_start - 1
    while end >= 0:
        start = payload.rfind(b"\n", 0, end) + 1
        raw_line = payload[start:end].removesuffix(b"\r")
        line = raw_line.strip()
        if line:
            return line.startswith(b"#") and not _contains_physical_line_splice((raw_line,))
        end = start - 1
    return False


def _previous_significant_physical_line(
    payload: bytes, offset: int
) -> tuple[tuple[str, ...], tuple[bytes, ...]]:
    """Return the nearest earlier token-bearing physical line.

    Comments and blank lines have no source-overlay tokens, so this remains a
    lexical query instead of growing a second comment parser.  The raw line is
    retained to reject phase-one trigraph and phase-two backslash/newline
    splicing across intervening comment or blank lines.
    """

    current_line_start = payload.rfind(b"\n", 0, offset) + 1
    if payload[current_line_start:offset].strip():
        return (), ()
    tokens = tuple(source_overlay_tokens(payload))
    previous = next(
        (
            (token, start, end)
            for token, start, end in reversed(tokens)
            if end <= current_line_start
        ),
        None,
    )
    if previous is None:
        return (), ()
    previous_line_start = payload.rfind(b"\n", 0, previous[1]) + 1
    previous_line_end = payload.find(b"\n", previous[2])
    if previous_line_end < 0:
        previous_line_end = len(payload)
    line_tokens = tuple(
        token for token, start, _end in tokens if previous_line_start <= start < previous_line_end
    )
    physical_lines = tuple(
        line.removesuffix(b"\r")
        for line in payload[previous_line_start:current_line_start].split(b"\n")[:-1]
    )
    return line_tokens, physical_lines


def _contains_physical_line_splice(lines: Sequence[bytes]) -> bool:
    return any(line.endswith((b"\\", b"??/")) for line in lines)


def _complete_function_like_macro_line(tokens: Sequence[str]) -> bool:
    """Recognize one complete, semicolon-less function-like macro seat."""

    if (
        len(tokens) < 3
        or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[0]) is None
        or tokens[1] != "("
        or tokens[-1] != ")"
        or any(token in {"#", ";", "{", "}"} for token in tokens)
    ):
        return False
    depth = 0
    for index, token in enumerate(tokens[1:], start=1):
        if token == "(":
            depth += 1
        elif token == ")":
            depth -= 1
            if depth < 0:
                return False
            if depth == 0 and index != len(tokens) - 1:
                return False
    return depth == 0


def _extended_global_declaration_line_seat(payload: bytes, offset: int) -> str | None:
    """Recognize one narrow global line seat outside token-neighbor grammar.

    Old projects commonly place declarations after a function-like assertion
    macro whose expansion owns its terminator, or after comments following a
    preprocessor directive.  Raw significant-token neighbors cannot prove
    those boundaries alone.  Both forms require a distinct, unspliced
    physical line at global scope.  The caller additionally requires a direct
    compiler owner and a closed typed runtime-projection theorem for the
    macro-expansion form.
    """

    previous, following, parentheses, brackets = _source_neighbors(payload, offset)
    if (
        previous is None
        or parentheses
        or brackets
        or _brace_depth_at(payload, offset) != 0
        or following in _CONTROL_CONTINUATIONS
    ):
        return None
    line_tokens, physical_lines = _previous_significant_physical_line(payload, offset)
    if not line_tokens or not physical_lines or _contains_physical_line_splice(physical_lines):
        return None
    if line_tokens[0] == "#":
        return "preprocessor-directive"
    if _complete_function_like_macro_line(line_tokens):
        return "function-like-macro-invocation"
    return None


_CONTROL_CONTINUATIONS = frozenset({"else", "while", "catch", "__except", "__finally"})
_FRAME_OBSERVATION_TOKENS = frozenset(
    {
        "asm",
        "_asm",
        "__asm",
        "alloca",
        "_alloca",
        "setjmp",
        "_setjmp",
        "longjmp",
        "_longjmp",
        "reinterpret_cast",
        "_AddressOfReturnAddress",
        "_ReturnAddress",
        "_emit",
        "__emit",
    }
)


def _require_declaration_seat(payload: bytes, offset: int, *, operation: str) -> None:
    previous, following, parentheses, brackets = _source_neighbors(payload, offset)
    boundary = previous in {None, "{", "}", ";"} or (
        _previous_physical_line_is_directive(payload, offset)
    )
    if parentheses or brackets or not boundary or following in _CONTROL_CONTINUATIONS:
        raise ClassicSemanticError(
            f"operation {operation!r} is not at a closed declaration boundary"
        )


def _require_statement_list_seat(
    payload: bytes,
    offset: int,
    *,
    function_range: tuple[int, int],
    operation: str,
) -> None:
    if not function_range[0] < offset < function_range[1]:
        raise ClassicSemanticError(
            f"operation {operation!r} is outside its function statement list"
        )
    previous, following, parentheses, brackets = _source_neighbors(payload, offset)
    if (
        parentheses
        or brackets
        or previous not in {"{", "}", ";"}
        or following in _CONTROL_CONTINUATIONS
    ):
        raise ClassicSemanticError(
            f"operation {operation!r} is not at a closed compound-statement boundary"
        )


def _require_no_frame_observation(
    payload: bytes,
    *,
    function_range: tuple[int, int],
    operation: str,
) -> None:
    function_tokens = set(_token_texts(payload[function_range[0] : function_range[1]]))
    hazards = sorted(function_tokens & _FRAME_OBSERVATION_TOKENS)
    if hazards:
        raise ClassicSemanticError(
            f"operation {operation!r} can perturb observed frame state: {hazards}"
        )


def _preprocessor_mutations(
    clean_sources: Mapping[str, CleanSourceInput],
) -> frozenset[tuple[str, str]]:
    return _payload_preprocessor_mutations(source.payload for source in clean_sources.values())


_PREPROCESSOR_DIRECTIVE_CANDIDATE = re.compile(
    rb"(?<![A-Za-z0-9_])(?:define|undef)(?![A-Za-z0-9_])"
)


def _translation_phase_preprocessor_payload(payload: bytes) -> bytes:
    """Normalize the spellings that can form directives before tokenization.

    VC4 accepts the standard trigraph/digraph spellings and removes escaped
    physical newlines before recognizing directives.  The semantic census is
    conservative, so normalizing these spellings before the existing lexer is
    preferable to silently treating them as ordinary source text.
    """

    normalized = payload.replace(b"??=", b"#").replace(b"??/", b"\\")
    normalized = re.sub(rb"\\(?:\r\n|\n|\r)", b"", normalized)
    normalized = normalized.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return normalized.replace(b"%:", b"#")


def _preprocessor_include_operands(payload: bytes) -> tuple[str | None, ...]:
    """Return literal include operands; ``None`` denotes a dynamic include."""

    if not any(marker in payload for marker in (b"#", b"??=", b"%:")):
        return ()
    normalized = _translation_phase_preprocessor_payload(payload)
    if b"include" not in normalized:
        return ()
    tokens = tuple(iter_source_overlay_tokens(normalized))
    operands: list[str | None] = []
    previous_line_start: int | None = None
    for index, (token, start, _end) in enumerate(tokens):
        line_start = normalized.rfind(b"\n", 0, start) + 1
        first_on_line = previous_line_start != line_start
        previous_line_start = line_start
        if token != "#":
            continue
        if not first_on_line:
            continue
        if index + 2 >= len(tokens) or tokens[index + 1][0] != "include":
            continue
        operand, operand_start, _operand_end = tokens[index + 2]
        line_end = normalized.find(b"\n", operand_start)
        if line_end < 0:
            line_end = len(normalized)
        if operand_start >= line_end:
            operands.append(None)
            continue
        if len(operand) >= 2 and operand.startswith('"') and operand.endswith('"'):
            operands.append(operand[1:-1])
            continue
        if operand == "<":
            pieces: list[str] = []
            closed = False
            for following, following_start, _following_end in tokens[index + 3 :]:
                if following_start >= line_end:
                    break
                if following == ">":
                    closed = True
                    break
                pieces.append(following)
            operands.append("".join(pieces) if closed and pieces else None)
            continue
        operands.append(None)
    return tuple(operands)


def _has_unconditional_standard_assert_include(payload: bytes, *, before_offset: int) -> bool:
    """Recognize a direct, unconditional ``#include <assert.h>`` before a source seat."""

    if before_offset < 0 or before_offset > len(payload):
        return False
    normalized = _translation_phase_preprocessor_payload(payload[:before_offset])
    tokens_by_line: dict[int, list[str]] = {}
    for token, start, _end in iter_source_overlay_tokens(normalized):
        line_start = normalized.rfind(b"\n", 0, start) + 1
        tokens_by_line.setdefault(line_start, []).append(token)

    conditional_depth = 0
    for line_start in sorted(tokens_by_line):
        tokens = tuple(tokens_by_line[line_start])
        if len(tokens) < 2 or tokens[0] != "#":
            continue
        directive = tokens[1]
        if directive in {"if", "ifdef", "ifndef"}:
            conditional_depth += 1
            continue
        if directive == "endif":
            if conditional_depth == 0:
                return False
            conditional_depth -= 1
            continue
        if (
            directive == "include"
            and conditional_depth == 0
            and tokens
            == (
                "#",
                "include",
                "<",
                "assert",
                ".",
                "h",
                ">",
            )
        ):
            return True
    return False


def _compiler_force_include_operands(node: ProducerNode) -> tuple[str, ...]:
    operands: list[str] = []
    arguments = node.arguments
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        folded = argument.casefold()
        if folded in {"/fi", "-fi"}:
            if index + 1 >= len(arguments):
                raise ClassicSemanticError(
                    f"compiler {node.id!r} has an incomplete force-include option"
                )
            operands.append(arguments[index + 1])
            index += 2
            continue
        if folded.startswith(("/fi", "-fi")) and len(argument) > 3:
            operands.append(argument[3:])
        index += 1
    return tuple(operands)


def _reader_operand_matches_path(operand: str, relative: str) -> bool:
    normalized = operand.strip().strip('"<>').replace("\\", "/").casefold()
    normalized = normalized.replace("${source}/", "").removeprefix("source/")
    target = relative.replace("\\", "/").casefold()
    return (
        normalized == target
        or normalized.endswith("/" + target)
        or PurePosixPath(normalized).name == PurePosixPath(target).name
    )


def _sparse_source_reader_fallbacks(
    *,
    graph: ProducerGraphDocument,
    effective_sources: Mapping[str, bytes],
    strict_paths: frozenset[str],
) -> tuple[str, ...]:
    """Explain when a strict source requires the all-reader fallback.

    Header deltas already audit every ordinary compiler.  A strict C/C++
    source normally has one graph owner, but C permits textual and forced
    inclusion of another source file.  Any uncertain or secondary-reader form
    widens the audit to every ordinary compiler instead of rejecting an
    otherwise valid project.
    """

    strict_sources = tuple(
        sorted(
            (
                path
                for path in strict_paths
                if PurePosixPath(path).suffix.casefold() in _SOURCE_SUFFIXES
            ),
            key=str.casefold,
        )
    )
    if not strict_sources:
        return ()
    fallback_reasons: set[str] = set()
    for source_path, payload in sorted(effective_sources.items(), key=lambda item: item[0]):
        for operand in _preprocessor_include_operands(payload):
            if operand is None:
                fallback_reasons.add(f"dynamic-include:{source_path}")
                break
            matched = tuple(
                path for path in strict_sources if _reader_operand_matches_path(operand, path)
            )
            if matched:
                fallback_reasons.add(f"textual-secondary:{source_path}:{','.join(matched)}")
    for node in sorted(
        (item for item in graph.nodes if item.role is ProducerRole.COMPILER),
        key=lambda item: item.id.casefold(),
    ):
        for operand in _compiler_force_include_operands(node):
            matched = tuple(
                path for path in strict_sources if _reader_operand_matches_path(operand, path)
            )
            if matched:
                fallback_reasons.add(f"forced-secondary:{node.id}:{','.join(matched)}")
    return tuple(sorted(fallback_reasons, key=str.casefold))


def _payload_preprocessor_mutations(
    payloads: Iterable[bytes],
    *,
    prevalidated_digests: Iterable[Digest] | None = None,
    cache: dict[tuple[Digest, int], frozenset[tuple[str, str]]] | None = None,
) -> frozenset[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    digest_iterator = iter(prevalidated_digests) if prevalidated_digests is not None else None
    for payload in payloads:
        if type(payload) is not bytes:
            raise ClassicSemanticError("preprocessor census input is not immutable bytes")
        digest: Digest | None = None
        if digest_iterator is not None:
            try:
                digest = next(digest_iterator)
            except StopIteration as exc:
                raise ClassicSemanticError(
                    "preprocessor census has fewer prevalidated digests than payloads"
                ) from exc
            if not isinstance(digest, Digest):
                raise ClassicSemanticError("preprocessor census digest is malformed")
        elif cache is not None:
            digest = Digest.from_bytes(payload)
        cache_key = (digest, len(payload)) if digest is not None else None
        if cache is not None and cache_key is not None and cache_key in cache:
            result.update(cache[cache_key])
            continue
        mutations: set[tuple[str, str]] = set()
        # Both byte patterns are necessary for the existing Latin-1 lexer to
        # produce the significant-token window ``# (define|undef) ID``.  This
        # filter may deliberately admit comments, strings, and high-byte word
        # continuations as false positives; every candidate still goes through
        # the exact lexer below.  It therefore avoids pointless binary-archive
        # tokenization without narrowing the conservative namespace theorem.
        normalized = _translation_phase_preprocessor_payload(payload)
        if b"#" in normalized and _PREPROCESSOR_DIRECTIVE_CANDIDATE.search(normalized):
            previous: str | None = None
            directive: str | None = None
            for token, _start, _end in iter_source_overlay_tokens(normalized):
                if previous == "#" and token in {"define", "undef"}:
                    directive = token
                elif directive is not None:
                    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
                        mutations.add((directive, token))
                    directive = None
                else:
                    directive = None
                previous = token
        frozen = frozenset(mutations)
        if cache is not None and cache_key is not None:
            cache[cache_key] = frozen
        result.update(frozen)
    if digest_iterator is not None:
        try:
            next(digest_iterator)
        except StopIteration:
            pass
        else:
            raise ClassicSemanticError(
                "preprocessor census has more prevalidated digests than payloads"
            )
    return frozenset(result)


def _compiler_has_define(node: ProducerNode, identifier: str) -> bool:
    def name(value: str) -> str:
        return re.split(r"[=(#]", value, maxsplit=1)[0]

    arguments = node.arguments
    for index, argument in enumerate(arguments):
        folded = argument.casefold()
        if (
            folded in {"/d", "-d"}
            and index + 1 < len(arguments)
            and name(arguments[index + 1]) == identifier
        ):
            return True
        if (
            folded.startswith(("/d", "-d"))
            and len(argument) > 2
            and name(argument[2:]) == identifier
        ):
            return True
    return False


def _compiler_has_undefine(node: ProducerNode, identifier: str) -> bool:
    def name(value: str) -> str:
        return re.split(r"[=(#]", value, maxsplit=1)[0]

    arguments = node.arguments
    for index, argument in enumerate(arguments):
        folded = argument.casefold()
        if (
            folded in {"/u", "-u"}
            and index + 1 < len(arguments)
            and name(arguments[index + 1]) == identifier
        ):
            return True
        if (
            folded.startswith(("/u", "-u"))
            and len(argument) > 2
            and name(argument[2:]) == identifier
        ):
            return True
    return False


def _require_no_compiler_macro_capture(
    nodes: Iterable[ProducerNode],
    sensitive_identifiers: frozenset[str],
) -> None:
    """Reject command-line definitions on every compiler epoch, including carriers."""

    for node in sorted(nodes, key=lambda item: item.id.casefold()):
        collisions = sorted(
            identifier
            for identifier in sensitive_identifiers
            if _compiler_has_define(node, identifier)
        )
        if collisions:
            raise ClassicSemanticError(
                f"compiler {node.id!r} can macro-capture source-overlay identifiers; "
                f"command_line={collisions}"
            )


def _reserved_cpp_identifier(identifier: str) -> bool:
    """Return whether an injected spelling is reserved to the implementation."""

    return identifier.startswith("_") or "__" in identifier


@dataclass(frozen=True, slots=True)
class _DeclarationLeafDelta:
    """Project-state changes proven by one declaration leaf."""

    declared: tuple[str, ...]
    guard: str | None
    facts: tuple[_DeclarationFact, ...]
    seat_failures: tuple[tuple[str, str, str, str], ...]
    extended_line_seat: tuple[str, str, str, str, bool] | None
    projection_required: bool
    unused_typedefs: tuple[dict[str, object], ...]
    unused_typedef_source: bool
    macro_sensitive_identifiers: frozenset[str]


def _validate_declaration_leaf(
    *,
    leaf: Mapping[str, object],
    kind: str,
    action: object,
    path: str,
    operation_id: str,
    clean_payload: bytes | None,
    anchor_offsets: Sequence[int],
    declaration_targets: frozenset[str],
    token_census: Mapping[str, int],
    effective_token_census: Mapping[str, int],
    preprocessor_mutations: frozenset[tuple[str, str]],
    introduced: AbstractSet[str],
    exclusive_declaration_identifiers: AbstractSet[str],
    helper_identifiers: AbstractSet[str],
) -> _DeclarationLeafDelta:
    """Validate one declaration generator without mutating project state."""

    entities = _declaration_entities(leaf)
    declared = tuple(
        identifier for entity in entities for identifier in entity.introduced_identifiers
    )
    declaration_depth: int | None = None
    projection_required = False
    seat_failures: list[tuple[str, str, str, str]] = []
    extended_line_seat: tuple[str, str, str, str, bool] | None = None
    if clean_payload is not None:
        if not anchor_offsets:
            raise ClassicSemanticError(f"declaration generator {kind!r} has no source seat")
        seat_offset = min(anchor_offsets)
        try:
            _require_declaration_seat(
                clean_payload,
                seat_offset,
                operation=operation_id,
            )
        except ClassicSemanticError as exc:
            predecessor = _extended_global_declaration_line_seat(clean_payload, seat_offset)
            projection_required = predecessor == "function-like-macro-invocation"
            if predecessor is None:
                seat_failures.append((path, operation_id, kind, str(exc)))
            else:
                extended_line_seat = (
                    path,
                    operation_id,
                    kind,
                    predecessor,
                    projection_required,
                )
        declaration_depth = _brace_depth_at(clean_payload, seat_offset)
        if declaration_depth != 0 and kind != "typedef":
            seat_failures.append((path, operation_id, kind, "declaration is not at global scope"))

    guard: str | None = None
    if kind == "record_header":
        recipe = leaf.get("typed_recipe")
        if isinstance(recipe, dict) and isinstance(recipe.get("guard"), str):
            guard = str(recipe["guard"])
        else:
            raise ClassicSemanticError("record-header guard is malformed")
    fresh = all(
        token_census.get(identifier, 0) == 0
        and identifier not in exclusive_declaration_identifiers
        and identifier not in helper_identifiers
        and all(mutation[1] != identifier for mutation in preprocessor_mutations)
        for identifier in declared
    )
    if not fresh:
        raise ClassicSemanticError(
            f"declaration generator {kind!r} is not globally fresh: {sorted(declared)}"
        )

    unused_typedefs: tuple[dict[str, object], ...] = ()
    unused_typedef_source = False
    if kind == "typedef":
        aliased_type = leaf.get("aliased_type")
        if (
            action != "insert"
            or clean_payload is None
            or aliased_type != "int"
            or declaration_depth is None
        ):
            raise ClassicSemanticError(
                "unused typedef theorem admits only a clean-backed exact 'typedef int' insertion"
            )
        used_identifiers = sorted(
            identifier for identifier in declared if effective_token_census.get(identifier, 0) != 1
        )
        if used_identifiers:
            raise ClassicSemanticError(
                f"generated typedef is not target-closed and unused: {used_identifiers}"
            )
        unused_typedef_source = True
        unused_typedefs = tuple(
            {
                "theorem": "complete-census-fresh-unused-typedef-int-v1",
                "identifier": identifier,
                "aliased_type": "int",
                "source_path": path,
                "clean_occurrences": 0,
                "effective_occurrences": 1,
                "closed_declaration_boundary": True,
                "lexical_brace_depth": declaration_depth,
                "macro_sensitive_tokens": ["typedef", "int", identifier],
            }
            for identifier in declared
        )

    if guard is not None and (
        token_census.get(guard, 0)
        or effective_token_census.get(guard, 0) != 2
        or guard in introduced
        or any(mutation[1] == guard for mutation in preprocessor_mutations)
    ):
        raise ClassicSemanticError(f"record-header guard is not globally fresh: {guard!r}")

    facts: list[_DeclarationFact] = []
    if declaration_depth in {None, 0}:
        for entity in entities:
            for identifier in entity.introduced_identifiers:
                disposition = (
                    entity.disposition
                    if identifier == entity.primary_identifier
                    else "enumerator-definition"
                )
                facts.append(
                    _DeclarationFact(
                        identifier,
                        entity.primary_identifier,
                        disposition,
                        entity.tag,
                        entity.semantic_digest,
                        path,
                        declaration_targets,
                    )
                )
    macro_sensitive = set(_declaration_owned_identifiers(leaf))
    if kind == "typedef":
        macro_sensitive.update(("typedef", "int"))
    if guard is not None:
        macro_sensitive.add(guard)
    return _DeclarationLeafDelta(
        declared,
        guard,
        tuple(facts),
        tuple(seat_failures),
        extended_line_seat,
        projection_required,
        unused_typedefs,
        unused_typedef_source,
        frozenset(macro_sensitive),
    )


@dataclass(frozen=True, slots=True)
class _IncludeLeafDelta:
    logical_path: str
    consumes_claim: bool


def _validate_include_leaf(
    *,
    kind: str,
    leaf: Mapping[str, object],
    action: object,
    claim: _SemanticClaim | None,
    path: str,
    operation_id: str,
    clean_payload: bytes | None,
    anchor_offsets: Sequence[int],
    source_compilers: Sequence[ProducerNode],
    authority_paths: Mapping[str, str],
) -> _IncludeLeafDelta:
    """Resolve one include leaf against its exact compiler search universe."""

    if action != "insert" or clean_payload is None or not source_compilers:
        raise ClassicSemanticError("include generator lacks a compiler owner")
    expected_logical: object
    consumes_claim = False
    if kind == "include":
        if not isinstance(claim, _LogicalHeaderClaim):
            raise ClassicSemanticError(
                f"include operation {operation_id!r} lacks a logical-header binding"
            )
        header = leaf.get("header")
        expected_logical = claim.logical_path
        consumes_claim = True
    else:
        if claim is not None:
            raise ClassicSemanticError("include_seat cannot override its logical header")
        header = leaf.get("basename")
        expected_logical = leaf.get("logical_header")
    if not isinstance(header, str) or not isinstance(expected_logical, str):
        raise ClassicSemanticError("logical include binding is malformed")
    _require_declaration_seat(
        clean_payload,
        min(anchor_offsets),
        operation=operation_id,
    )
    resolved = _resolve_logical_header(
        source_path=path,
        header=header,
        style=leaf.get("style"),
        compiler_nodes=source_compilers,
        authority_paths=authority_paths,
    )
    if resolved != expected_logical:
        raise ClassicSemanticError(f"logical include binding changed for {path!r}: {resolved!r}")
    return _IncludeLeafDelta(resolved, consumes_claim)


@dataclass(frozen=True, slots=True)
class _LiteralAliasEvent:
    key: tuple[str, str, str, str]
    role: str
    offset: int


@dataclass(frozen=True, slots=True)
class _FunctionLeafDelta:
    counterfactual_policy: Literal["retain", "project"]
    introduced_locals: frozenset[tuple[str, str, str]] = frozenset()
    macro_sensitive_identifiers: frozenset[str] = frozenset()
    literal_alias_event: _LiteralAliasEvent | None = None
    assert_insertion: tuple[str, frozenset[str]] | None = None
    assert_deletion: tuple[str, str] | None = None


def _assert_reseat_removed_tokens(
    *,
    leaf: Mapping[str, object],
    operation_receipt: ClassicOverlayOperationReceipt,
    clean_payload: bytes,
    function_range: tuple[int, int],
) -> tuple[str, ...]:
    """Derive the one assertion expression authorized by a reseat deletion."""

    anchors_by_role = {anchor.role: anchor.byte_offset for anchor in operation_receipt.anchors}
    start = anchors_by_role.get("start")
    end = anchors_by_role.get("end")
    restore = leaf.get("restore_seat")
    if (
        not isinstance(start, int)
        or not isinstance(end, int)
        or start < function_range[0]
        or end > function_range[1]
        or start >= end
        or not isinstance(restore, Mapping)
    ):
        raise ClassicSemanticError("assert reseat deletion range is malformed")

    restore_kind = restore.get("kind")
    identifiers: tuple[str, ...]
    if restore_kind == "after_new_assignment":
        identifier = restore.get("target_identifier")
        identifiers = (identifier,) if isinstance(identifier, str) else ()
    elif restore_kind == "after_local_declaration":
        identifier = restore.get("identifier")
        identifiers = (identifier,) if isinstance(identifier, str) else ()
    elif restore_kind == "after_local_declaration_sequence":
        declarations = restore.get("declarations")
        identifiers = (
            tuple(
                declaration["identifier"]
                for declaration in declarations
                if isinstance(declaration, Mapping)
                and isinstance(declaration.get("identifier"), str)
            )
            if isinstance(declarations, list)
            else ()
        )
        if not isinstance(declarations, list) or len(identifiers) != len(declarations):
            identifiers = ()
    else:
        identifiers = ()
    if not identifiers:
        raise ClassicSemanticError("assert reseat restore binding is malformed")

    condition = leaf.get("condition")
    expected_condition = "_and_".join(identifiers)
    expected_expression = tuple(
        token
        for index, identifier in enumerate(identifiers)
        for token in (("&&",) if index else ()) + (identifier,)
    )
    removed_tokens = tuple(
        token for token, _start, _end in source_overlay_tokens(clean_payload[start:end])
    )
    if condition != expected_condition or removed_tokens != (
        "assert",
        "(",
        *expected_expression,
        ")",
        ";",
    ):
        raise ClassicSemanticError("assert reseat deletion is not its declared assertion")
    return identifiers


def _validate_function_leaf(
    *,
    kind: str,
    leaf: Mapping[str, object],
    action: object,
    claim: _SemanticClaim | None,
    path: str,
    operation_receipt: ClassicOverlayOperationReceipt,
    leaf_index: int,
    clean_payload: bytes | None,
    source_compilers: Sequence[ProducerNode],
    authority_paths: Mapping[str, str],
    clean_sources: Mapping[str, CleanSourceInput],
    preprocessor_mutations: frozenset[tuple[str, str]],
    introduced_locals: AbstractSet[tuple[str, str, str]],
) -> _FunctionLeafDelta:
    """Validate one function-scoped generator and return its ordered effects."""

    if clean_payload is None or not isinstance(claim, _FunctionScopeClaim):
        raise ClassicSemanticError(
            f"operation leaf {operation_receipt.operation_id!r}/{leaf_index} "
            "lacks a function-scope binding"
        )
    anchor_offsets = tuple(anchor.byte_offset for anchor in operation_receipt.anchors)
    function_range = _validate_function_claim(
        claim=claim,
        payload=clean_payload,
        anchor_offsets=anchor_offsets,
    )
    if kind != "literal_alias" or "type" in leaf:
        _require_statement_list_seat(
            clean_payload,
            min(anchor_offsets),
            function_range=function_range,
            operation=operation_receipt.operation_id,
        )
    if kind == "noop_assign":
        target = leaf.get("assignment_target")
        if (
            action != "insert"
            or not isinstance(target, str)
            or len(claim.bindings) != 1
            or claim.bindings[0].identifier != target
            or not claim.bindings[0].initialized
        ):
            raise ClassicSemanticError("scalar identity claim differs")
        _validate_scalar_binding(
            claim=claim.bindings[0],
            payload=clean_payload,
            function_range=function_range,
            before_offset=min(anchor_offsets),
            clean_sources=clean_sources,
        )
        return _FunctionLeafDelta(
            counterfactual_policy="retain",
            macro_sensitive_identifiers=frozenset({target}),
        )
    if claim.bindings:
        raise ClassicSemanticError(f"{kind} function claim has unauthorized scalar bindings")
    if kind == "empty_scopes":
        if action != "insert":
            raise ClassicSemanticError("empty scopes are not an insertion")
        return _FunctionLeafDelta(counterfactual_policy="retain")
    if kind == "local_ids":
        _require_no_frame_observation(
            clean_payload,
            function_range=function_range,
            operation=operation_receipt.operation_id,
        )
        identifiers = leaf.get("identifiers")
        type_spelling = leaf.get("type")
        if (
            action != "insert"
            or claim.function != leaf.get("function")
            or not isinstance(identifiers, list)
            or not isinstance(type_spelling, str)
            or not _is_nonvolatile_integral_type(type_spelling, clean_sources)
        ):
            raise ClassicSemanticError("dead-local theorem differs")
        function_tokens = _token_texts(clean_payload[function_range[0] : function_range[1]])
        added: set[tuple[str, str, str]] = set()
        sensitive: set[str] = set()
        for identifier in identifiers:
            local_key = (path.casefold(), claim.function, str(identifier))
            if (
                not isinstance(identifier, str)
                or identifier in function_tokens
                or any(mutation[1] == identifier for mutation in preprocessor_mutations)
                or any(_compiler_has_define(node, identifier) for node in source_compilers)
                or local_key in introduced_locals
                or local_key in added
            ):
                raise ClassicSemanticError(
                    f"dead local is not fresh in its bound function: {identifier!r}"
                )
            added.add(local_key)
            sensitive.add(identifier)
        return _FunctionLeafDelta(
            counterfactual_policy="retain",
            introduced_locals=frozenset(added),
            macro_sensitive_identifiers=frozenset(sensitive),
        )
    if kind == "literal_alias":
        owner = leaf.get("owner_function")
        literal = leaf.get("literal")
        local = leaf.get("local_identifier")
        if (
            claim.function != owner
            or not isinstance(owner, str)
            or not isinstance(literal, str)
            or not isinstance(local, str)
        ):
            raise ClassicSemanticError("literal-alias owner differs")
        key = (path, owner, literal, local)
        if "type" in leaf:
            _require_no_frame_observation(
                clean_payload,
                function_range=function_range,
                operation=operation_receipt.operation_id,
            )
            local_key = (path.casefold(), claim.function, local)
            if (
                action != "insert"
                or tuple(_type_tokens(str(leaf["type"])))
                not in {("const", "char", "*"), ("char", "const", "*")}
                or local in _token_texts(clean_payload[function_range[0] : function_range[1]])
                or any(mutation[1] == local for mutation in preprocessor_mutations)
                or any(_compiler_has_define(node, local) for node in source_compilers)
                or local_key in introduced_locals
            ):
                raise ClassicSemanticError("literal alias definition is unsafe")
            return _FunctionLeafDelta(
                counterfactual_policy="project",
                introduced_locals=frozenset({local_key}),
                macro_sensitive_identifiers=frozenset({local}),
                literal_alias_event=_LiteralAliasEvent(key, "definition", min(anchor_offsets)),
            )
        anchors_by_role = {anchor.role: anchor.byte_offset for anchor in operation_receipt.anchors}
        start = anchors_by_role.get("start")
        end = anchors_by_role.get("end")
        literal_token = f'"{literal}"'.encode("ascii")
        occurrences = [
            token_start
            for token, token_start, token_end in source_overlay_tokens(clean_payload)
            if token.encode("utf-8") == literal_token
            and function_range[0] <= token_start
            and token_end <= function_range[1]
        ]
        if (
            action != "replace"
            or leaf.get("use_ordinal") != 1
            or not isinstance(start, int)
            or not isinstance(end, int)
            or clean_payload[start:end] != literal_token
            or not occurrences
            or occurrences[0] != start
        ):
            raise ClassicSemanticError("literal alias use is unsafe")
        return _FunctionLeafDelta(
            counterfactual_policy="project",
            literal_alias_event=_LiteralAliasEvent(key, "use", start),
        )
    if kind == "assert_reseat":
        if (
            not _has_unconditional_standard_assert_include(
                clean_payload,
                before_offset=function_range[0],
            )
            or any(
                mutation in preprocessor_mutations
                for mutation in {
                    ("undef", "NDEBUG"),
                    ("define", "assert"),
                    ("undef", "assert"),
                }
            )
            or not source_compilers
            or not _standard_assert_header_is_unshadowed(source_compilers, authority_paths)
            or any(not _compiler_has_define(node, "NDEBUG") for node in source_compilers)
            or any(_compiler_has_define(node, "assert") for node in source_compilers)
            or any(
                _compiler_has_undefine(node, identifier)
                for node in source_compilers
                for identifier in ("NDEBUG", "assert")
            )
        ):
            raise ClassicSemanticError("assert reseat lacks a closed NDEBUG compiler universe")
        if action == "insert":
            _require_no_frame_observation(
                clean_payload,
                function_range=function_range,
                operation=operation_receipt.operation_id,
            )
            authentic = leaf.get("authentic_function")
            carrier = leaf.get("carrier_function")
            carrier_conditions = leaf.get("carrier_conditions")
            restored = leaf.get("restored_conditions")
            dead = leaf.get("dead_local")
            dead_identifiers = dead.get("identifiers") if isinstance(dead, dict) else None
            if (
                claim.function != carrier
                or not isinstance(authentic, str)
                or not isinstance(restored, list)
                or not restored
                or any(not isinstance(item, str) or not item for item in restored)
                or len(set(restored)) != len(restored)
                or not isinstance(carrier_conditions, list)
                or not carrier_conditions
                or any(not isinstance(item, str) or not item for item in carrier_conditions)
                or len(set(carrier_conditions)) != len(carrier_conditions)
                or not isinstance(dead, dict)
                or not isinstance(dead.get("type"), str)
                or not isinstance(dead_identifiers, list)
                or not dead_identifiers
                or any(
                    not isinstance(identifier, str)
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", identifier) is None
                    or identifier
                    in _token_texts(clean_payload[function_range[0] : function_range[1]])
                    or any(mutation[1] == identifier for mutation in preprocessor_mutations)
                    or any(_compiler_has_define(node, identifier) for node in source_compilers)
                    or (path.casefold(), claim.function, identifier) in introduced_locals
                    for identifier in dead_identifiers
                )
                or len(set(dead_identifiers)) != len(dead_identifiers)
                or not _is_nonvolatile_integral_type(str(dead["type"]), clean_sources)
            ):
                raise ClassicSemanticError("assert carrier theorem differs")
            added_locals = frozenset(
                (path.casefold(), claim.function, identifier) for identifier in dead_identifiers
            )
            return _FunctionLeafDelta(
                counterfactual_policy="retain",
                introduced_locals=added_locals,
                macro_sensitive_identifiers=frozenset(dead_identifiers),
                assert_insertion=(authentic, frozenset(restored)),
            )
        condition = leaf.get("condition")
        if action == "delete" and isinstance(condition, str):
            _assert_reseat_removed_tokens(
                leaf=leaf,
                operation_receipt=operation_receipt,
                clean_payload=clean_payload,
                function_range=function_range,
            )
            return _FunctionLeafDelta(
                counterfactual_policy="retain",
                assert_deletion=(claim.function, condition),
            )
        raise ClassicSemanticError("assert reseat action differs")
    raise AssertionError(f"unknown function-claim generator {kind!r}")


@dataclass(frozen=True, slots=True)
class _HelperLeafDelta:
    identifier: str
    crt_pull: bool
    ordered_archive_seed_policy: str | None
    projection_required: bool


def _validate_unreachable_helper_leaf(
    *,
    kind: str,
    leaf: Mapping[str, object],
    action: object,
    claim: _SemanticClaim | None,
    path: str,
    clean_payload: bytes | None,
    anchor_offsets: Sequence[int],
    token_census: Mapping[str, int],
    introduced: AbstractSet[str],
) -> _HelperLeafDelta:
    """Validate one globally unreachable helper without mutating project state."""

    helper = leaf.get("function_identifier")
    if PurePosixPath(path).suffix.casefold() in _HEADER_SUFFIXES:
        raise ClassicSemanticError(
            "unreachable helper generators require a primary source owner; "
            f"header helpers are unsupported: {path!r}"
        )
    if (
        claim is not None
        or action != "insert"
        or clean_payload is None
        or not anchor_offsets
        or _brace_depth_at(clean_payload, anchor_offsets[0]) != 0
        or not isinstance(helper, str)
        or token_census.get(helper, 0)
        or helper in introduced
    ):
        raise ClassicSemanticError(f"unreachable helper theorem is unsafe: {helper!r}")
    ordered_archive_seed_policy: str | None = None
    if kind == "seed_seq":
        policy = leaf.get("undefined_binding_order")
        if helper != _ORDERED_ARCHIVE_SEED_HELPER or policy != _ORDERED_ARCHIVE_SEED_POLICY:
            raise ClassicSemanticError("ordered archive seed theorem differs")
        ordered_archive_seed_policy = policy
    last_clean_token = max(
        (end for _token, _start, end in source_overlay_tokens(clean_payload)),
        default=0,
    )
    return _HelperLeafDelta(
        helper,
        kind == "crt_pull",
        ordered_archive_seed_policy,
        anchor_offsets[0] < last_clean_token,
    )
