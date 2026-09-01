"""Donor-private source refactor semantics: entropy-only rendering proofs."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import cast

from reprobit.classic.overlay_declarations import _declaration_owned_identifiers
from reprobit.classic.overlay_types import (
    ClassicOverlayOperationReceipt,
)

from .source_refactor_semantics_schema import (
    _SAFE_ENTROPY_LEAVES,
    SourceRefactorSemanticError,
    _identifier,
    _need,
    _Operation,
    _token_text,
)


def _prove_entropy_only_rendering(
    operations: Sequence[_Operation],
    *,
    owning_source: str,
    clean_sources: Mapping[str, bytes],
    rendered_sources: Mapping[str, bytes],
) -> None:
    """Prove a donor overlay with no semantic operations is logic-inert.

    Such a donor claims to carry only compiler-state entropy.  Its additions
    come from the closed entropy generators, but a destructive ``replace`` or
    ``delete`` also removes project text that nothing else inspects.  Recover
    each destructive operation's removed bytes through its pin and admit
    exactly four kinds of removed program text:

    - nothing (the edit removed only comments and whitespace);
    - ``#include`` directives (the include-seat entropy lever relocates and
      exchanges implementation includes; their effect on the program is
      carried by the byte-exact compile itself);
    - member relocations (``member_sig``/``reloc`` generators), whose member
      identity must agree, whose qualified definition header must be generated
      on the authenticated byte destination, and whose removed tokens must
      survive there contiguously — the moved definition reappears;
    - non-virtual function prototype declarations whose name no longer
      appears anywhere in the donor's rendered text, so nothing the
      compiler sees in these files can have resolved against them.

    Everything else is a source rewrite and must carry a semantic claim."""

    touched: set[str] = set()
    for operation in operations:
        kinds = {cast(str, leaf.get("k")) for leaf in operation.leaves}
        _need(
            bool(kinds) and kinds <= _ENTROPY_ONLY_LEAVES,
            "entropy-only donor carries an unadmitted generator",
        )
        if operation.path != owning_source:
            _need(
                PurePosixPath(operation.path).suffix.casefold() in {".h", ".hh", ".hpp", ".hxx"},
                "entropy-only donor rendering is not a header",
            )
        touched.add(operation.path)

    relocation_destinations = _relocation_destinations(operations)
    qualified_destructors = _qualified_destructor_definitions(operations)
    survivors: set[str] = set()
    rendered_tokens: dict[str, list[str]] = {}
    for rendered_path, rendered in rendered_sources.items():
        rendered_tokens[rendered_path] = _token_text(rendered)
        survivors.update(rendered_tokens[rendered_path])
    if owning_source not in rendered_sources:
        owning_clean = clean_sources.get(owning_source)
        if owning_clean is not None:
            survivors.update(_token_text(owning_clean))

    for path in sorted(touched):
        _need(
            path in rendered_sources,
            f"entropy-only donor rendering {path!r} is absent",
        )

    for operation in operations:
        if operation.action not in {"replace", "delete"}:
            continue
        clean = clean_sources.get(operation.path)
        _need(
            clean is not None,
            f"entropy-only donor edits {operation.path!r} which has no clean text",
        )
        assert clean is not None
        removed_text = _pinned_removed_text(operation, clean)
        deleted = _strip_include_directives(_token_text(removed_text))
        if not deleted:
            continue
        kinds = {cast(str, leaf.get("k")) for leaf in operation.leaves}
        if kinds & _RELOCATION_LEAVES:
            for leaf in operation.leaves:
                if leaf.get("k") != "member_sig":
                    continue
                identity = _destructor_relocation_identity(leaf)
                _need(
                    leaf.get("form") == "in_class_declaration",
                    "entropy-only donor destructive member signature is not an"
                    " in-class declaration",
                )
                destinations = relocation_destinations.get(identity, frozenset())
                _need(
                    bool(destinations),
                    f"entropy-only donor member signature {identity!r} lacks a"
                    " matching authenticated relocation",
                )
                _need(
                    bool(destinations.intersection(qualified_destructors.get(identity, ()))),
                    f"entropy-only donor member signature {identity!r} lacks a"
                    " matching qualified definition header at its relocation destination",
                )
            # A declared member relocation: the removed definition must
            # reappear as one token-for-token range at its destination.
            _need(
                any(
                    _contains_contiguous_tokens(deleted, tokens)
                    for tokens in rendered_tokens.values()
                ),
                f"entropy-only donor relocation from {operation.path!r} does not"
                " reappear in a rendered output",
            )
            continue
        _admit_entropy_deletion(deleted, operation.path, frozenset(survivors))


_RELOCATION_LEAVES = frozenset({"member_sig", "reloc"})
_ENTROPY_ONLY_LEAVES = _SAFE_ENTROPY_LEAVES | _RELOCATION_LEAVES


def _relocation_destinations(
    operations: Sequence[_Operation],
) -> Mapping[str, frozenset[str]]:
    destinations: dict[str, set[str]] = {}
    for operation in operations:
        for leaf in operation.leaves:
            if leaf.get("k") != "reloc":
                continue
            identity = leaf.get("range_identity")
            _need(
                isinstance(identity, str) and bool(identity),
                "entropy-only donor relocation lacks an authenticated range identity",
            )
            if operation.action != "insert":
                continue
            destination = leaf.get("byte_destination")
            if destination is not None:
                _need(
                    isinstance(destination, str) and destination == operation.path,
                    "entropy-only donor relocation byte destination differs",
                )
                destinations.setdefault(cast(str, identity), set()).add(cast(str, destination))
            else:
                # Renderer-validated manifests carry ``byte_destination`` on
                # both relocation halves.  The insert path keeps focused
                # validator fixtures useful without recreating that payload.
                destinations.setdefault(cast(str, identity), set()).add(operation.path)
    return MappingProxyType(
        {identity: frozenset(paths) for identity, paths in destinations.items()}
    )


def _qualified_destructor_definitions(
    operations: Sequence[_Operation],
) -> Mapping[str, frozenset[str]]:
    definitions: dict[str, set[str]] = {}
    for operation in operations:
        for leaf in operation.leaves:
            if (
                leaf.get("k") != "member_sig"
                or leaf.get("kind") != "destructor"
                or leaf.get("form") != "qualified_definition_header"
            ):
                continue
            identity = _destructor_relocation_identity(leaf)
            definitions.setdefault(identity, set()).add(operation.path)
    return MappingProxyType({identity: frozenset(paths) for identity, paths in definitions.items()})


def _destructor_relocation_identity(member_signature: Mapping[str, object]) -> str:
    _need(
        member_signature.get("kind") == "destructor",
        "entropy-only donor member signature is not a destructor relocation",
    )
    class_identifier = _identifier(
        member_signature.get("class_identifier"),
        "entropy-only donor member signature class",
    )
    member_identifier = _identifier(
        member_signature.get("member_identifier"),
        "entropy-only donor member signature member",
    )
    _need(
        class_identifier == member_identifier,
        "entropy-only donor destructor identity differs from its class",
    )
    return f"{class_identifier}::~{member_identifier}"


def _contains_contiguous_tokens(needle: list[str], haystack: list[str]) -> bool:
    width = len(needle)
    return any(
        haystack[start : start + width] == needle for start in range(len(haystack) - width + 1)
    )


def _pinned_removed_text(operation: _Operation, clean: bytes) -> bytes:
    """Recover the bytes a destructive operation removes via its pin.

    The pin commits to the removed content, not its position; any substring
    of the clean text with the pinned digest is byte-identical to what the
    renderer removed, which is all the admission rules inspect."""

    pin = operation.value.get("removed")
    _need(
        isinstance(pin, Mapping),
        f"entropy-only donor operation {operation.operation_id!r} lacks a removed pin",
    )
    assert isinstance(pin, Mapping)
    size = pin.get("size")
    digest = pin.get("sha256")
    _need(
        isinstance(size, int) and 0 < size <= len(clean) and isinstance(digest, str),
        f"entropy-only donor operation {operation.operation_id!r} removed pin is malformed",
    )
    assert isinstance(size, int) and isinstance(digest, str)
    for start in range(len(clean) - size + 1):
        window = clean[start : start + size]
        if sha256(window).hexdigest() == digest:
            return window
    _need(
        False,
        f"entropy-only donor operation {operation.operation_id!r} removed pin"
        " matches no clean text",
    )
    raise AssertionError("unreachable")


def _strip_include_directives(tokens: list[str]) -> list[str]:
    """Drop every ``#include`` directive (three tokens) from the stream.

    Adding, removing, relocating, and exchanging implementation includes is
    the admitted include-seat entropy lever; its effect on the program is
    carried by the byte-exact compile itself, so directives take no part in
    the token-preservation proof."""

    result: list[str] = []
    index = 0
    while index < len(tokens):
        if index + 2 < len(tokens) and tokens[index] == "#" and tokens[index + 1] == "include":
            index += 3
            continue
        result.append(tokens[index])
        index += 1
    return result


_PROTOTYPE_FORBIDDEN_TOKENS = frozenset({"virtual", "=", "{", "}", "operator"})


def _admit_entropy_deletion(deleted: Sequence[str], path: str, survivors: frozenset[str]) -> None:
    """Admit one run of removed significant tokens, or refuse the donor.

    Each chunk must be a non-virtual function prototype (``head ;``) or a
    complete non-virtual function definition (``head { body }``) whose name
    survives nowhere in the donor's rendered text.  The head may not carry
    default arguments or initializers; the body of a definition is free
    text, since nothing can reference it once the name is gone."""

    index = 0
    total = len(deleted)
    while index < total:
        semicolon = deleted.index(";", index) if ";" in deleted[index:] else total
        brace = deleted.index("{", index) if "{" in deleted[index:] else total
        boundary = min(semicolon, brace)
        _need(
            boundary < total,
            f"entropy-only donor removes non-declaration text in {path!r}",
        )
        head = deleted[index:boundary]
        opener = head.index("(") if "(" in head else 0
        _need(
            opener > 0 and ")" in head and not frozenset(head) & _PROTOTYPE_FORBIDDEN_TOKENS,
            f"entropy-only donor removes non-prototype text in {path!r}",
        )
        name = _identifier(head[opener - 1], "removed prototype name")
        _need(
            name not in survivors,
            f"entropy-only donor removes declaration {name!r} that is still referenced in {path!r}",
        )
        if boundary == brace:
            # A definition: consume the balanced body.
            depth = 0
            stop = boundary
            while stop < total:
                if deleted[stop] == "{":
                    depth += 1
                elif deleted[stop] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                stop += 1
            _need(
                stop < total,
                f"entropy-only donor removes an unterminated definition in {path!r}",
            )
            index = stop + 1
        else:
            index = boundary + 1


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
