"""Donor-private source refactor semantics: the record schema and its readers."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import cast

from reprobit.classic.overlay_types import (
    ClassicOverlayOperationReceipt,
    ClassicOverlayOutputReceipt,
)
from reprobit.classic.source_proofs import (
    require_source_overlay_range_pin,
    source_overlay_tokens,
)
from reprobit.model import Digest
from reprobit.schema import (
    ClassicRecipeIntervention,
)


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
