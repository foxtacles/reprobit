"""Pure scaffolding for a small, non-certifying MSVC discovery request."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import PurePosixPath

from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationShapeSearch,
    DiscoveryPlan,
    InclusiveRange,
    MosaicLimits,
)
from reprobit.msvc_discovery import MsvcDiscoveryObjectInput, MsvcDiscoveryRequest
from reprobit.strict_json import canonical_json

_DEFAULT_COMPILER_ARGUMENTS = ("/nologo", "/O2", "/Ob1", "/Gy", "/Z7")


def _relative_path(value: str, *, label: str) -> PurePosixPath:
    if not value or "\0" in value or "\\" in value:
        raise ValueError(f"{label} must be a canonical POSIX relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"{label} must be a canonical POSIX relative path")
    return path


def _reject_symbol_collisions(references: Sequence[tuple[str, str]]) -> None:
    symbols: dict[str, str] = {}
    for symbol, _object_path in references:
        folded = symbol.casefold()
        prior = symbols.get(folded)
        if prior is None:
            symbols[folded] = symbol
        elif prior == symbol:
            raise ValueError(f"discovery symbol is repeated: {symbol!r}")
        else:
            raise ValueError(
                "discovery symbols collide under case-insensitive rules: "
                f"{prior!r} and {symbol!r}"
            )


def _reject_path_collisions(source: str, references: Sequence[tuple[str, str]]) -> None:
    paths: dict[str, tuple[str, str, tuple[str, ...]]] = {}

    def add(role: str, value: str) -> None:
        path = _relative_path(value, label=f"discovery {role}")
        folded_parts = tuple(part.casefold() for part in path.parts)
        folded = "/".join(folded_parts)
        prior = paths.get(folded)
        if prior is not None:
            prior_role, prior_value, _prior_parts = prior
            if role == prior_role == "reference" and value == prior_value:
                # One COFF object may legitimately seal several symbols.
                return
            raise ValueError(
                "discovery inputs collide under case-insensitive path rules: "
                f"{prior_value!r} ({prior_role}) and {value!r} ({role})"
            )
        for prior_role, prior_value, prior_parts in paths.values():
            shorter, longer = sorted((folded_parts, prior_parts), key=len)
            if len(shorter) < len(longer) and longer[: len(shorter)] == shorter:
                raise ValueError(
                    "discovery input paths overlap as a file and descendant: "
                    f"{prior_value!r} ({prior_role}) and {value!r} ({role})"
                )
        paths[folded] = (role, value, folded_parts)

    add("source", source)
    for _symbol, object_path in references:
        add("reference", object_path)


def scaffold_msvc_discovery_request(
    *,
    source: str,
    target: str,
    translation_unit: str,
    references: Sequence[tuple[str, str]],
    compiler_arguments: Sequence[str] | None = None,
) -> bytes:
    """Return canonical JSON for one modest, declaration-only preview campaign.

    ``references`` contains ``(symbol, object_path)`` pairs. All paths are
    portable and relative to the future request file. This function only
    describes a campaign; it does not read files, compile, apply proposals, or
    create certification authority.
    """

    reference_pairs = tuple(references)
    if not reference_pairs:
        raise ValueError("discovery requires at least one symbol and reference object")
    if any(
        not isinstance(item, tuple)
        or len(item) != 2
        or not all(isinstance(value, str) for value in item)
        for item in reference_pairs
    ):
        raise ValueError("discovery references must be (symbol, object_path) string pairs")

    _reject_symbol_collisions(reference_pairs)
    _reject_path_collisions(source, reference_pairs)
    ordered = tuple(sorted(reference_pairs, key=lambda item: item[0].casefold()))
    symbols = tuple(symbol for symbol, _object_path in ordered)
    arguments = (
        _DEFAULT_COMPILER_ARGUMENTS
        if compiler_arguments is None
        else tuple(compiler_arguments)
    )
    request = MsvcDiscoveryRequest(
        source=source,
        plan=DiscoveryPlan(
            target=target,
            translation_unit=translation_unit,
            symbols=symbols,
            searches=(
                DeclarationShapeSearch(
                    family=DeclarationFamily.DECLARATION_SHAPE,
                    classes=InclusiveRange(start=1, stop=4),
                    functions=InclusiveRange(start=10, stop=10),
                ),
            ),
            max_cells=4,
            mosaic=MosaicLimits(
                max_donors=2,
                max_ranges=4,
                max_candidates_per_symbol=32,
                max_search_steps=10_000,
            ),
        ),
        references=tuple(
            MsvcDiscoveryObjectInput(symbol=symbol, object=object_path)
            for symbol, object_path in ordered
        ),
        compiler_arguments=arguments,
    )
    return canonical_json(request)


__all__ = ["scaffold_msvc_discovery_request"]
