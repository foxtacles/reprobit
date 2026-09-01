"""Project-overlay semantic ancestry proofs: carrier isolation traces."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from pathlib import PurePosixPath

from reprobit.classic.coff_evidence import (
    _coff_directive_receipt,
    _CoffObject,
    _CoffSection,
    _default_libraries_for_ordinary,
    _external_definitions,
    _external_references,
    _parse_coff,
)
from reprobit.classic.linker_identity import (
    Msvc420LinkerIdentity,
)
from reprobit.classic.semantic_contracts import (
    CompilerProduct,
    TargetLinkClosure,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest

from .project_overlay_archives import _COFF_SCN_LNK_COMDAT, _archive_semantics, _default_libraries


def _carrier_linker_control_trace(arguments: tuple[str, ...]) -> dict[str, object]:
    """Require the exact explicit controls used by the carrier theorem."""

    normalized = tuple(
        ("/" + argument[1:] if argument.startswith("-") else argument).casefold()
        for argument in arguments
    )
    incremental = [item for item in normalized if item.startswith("/incremental")]
    if incremental != ["/incremental:no"]:
        raise ClassicSemanticError(
            "generated-carrier isolation requires exactly one explicit /INCREMENTAL:NO"
        )

    opt_modes = [
        mode
        for item in normalized
        if item.startswith("/opt:")
        for mode in item.removeprefix("/opt:").split(",")
    ]
    if opt_modes != ["ref"]:
        raise ClassicSemanticError(
            "generated-carrier isolation requires one effective explicit /OPT:REF"
        )
    if any(item.startswith("/force") for item in normalized):
        raise ClassicSemanticError("generated-carrier isolation forbids /FORCE linking")
    return {
        "dead_comdat_elimination": "/OPT:REF",
        "incremental_state": "/INCREMENTAL:NO",
    }


def _carrier_comdat_root(coff: _CoffObject, section: _CoffSection) -> int:
    """Resolve one associative chain to its primary, refusing cycles and gaps."""

    current = section
    seen: set[int] = set()
    while current.comdat_selection == 5:
        if current.number in seen:
            raise ClassicSemanticError(f"carrier {coff.label!r} has a cyclic COMDAT chain")
        seen.add(current.number)
        associated = current.comdat_associated
        if associated is None or not 0 < associated <= len(coff.sections):
            raise ClassicSemanticError(f"carrier {coff.label!r} has an orphaned associative COMDAT")
        current = coff.sections[associated - 1]
    if current.comdat_selection not in {1, 2, 3, 4, 6} or not (
        current.characteristics & _COFF_SCN_LNK_COMDAT
    ):
        raise ClassicSemanticError(
            f"carrier {coff.label!r} has a malformed associative COMDAT root"
        )
    return current.number


def _validate_carrier_comdat_topology(coff: _CoffObject) -> None:
    """Validate the small LINK 4.20 COMDAT topology used by carrier objects."""

    for section in coff.sections:
        marked = bool(section.characteristics & _COFF_SCN_LNK_COMDAT)
        selection = section.comdat_selection
        associated = section.comdat_associated
        if selection in {None, 0}:
            if marked or associated not in {None, 0}:
                raise ClassicSemanticError(
                    f"carrier {coff.label!r} has inconsistent COMDAT metadata"
                )
            continue
        if selection not in {1, 2, 3, 4, 5, 6} or not marked:
            raise ClassicSemanticError(
                f"carrier {coff.label!r} has unsupported COMDAT selection {selection!r}"
            )
        if selection == 5:
            _carrier_comdat_root(coff, section)
        elif associated not in {None, 0}:
            raise ClassicSemanticError(f"carrier {coff.label!r} has an associated primary COMDAT")
        else:
            owners = [
                symbol
                for symbol in coff.symbols
                if symbol.storage == 2 and symbol.section == section.number
            ]
            if len(owners) != 1 or owners[0].value != 0:
                raise ClassicSemanticError(
                    f"carrier {coff.label!r} has an ownerless primary COMDAT"
                )


def _carrier_primary_owner(
    coff: _CoffObject,
    section: _CoffSection,
    name: str,
    *,
    selection: int | None = None,
) -> tuple[int, int]:
    """Return the exact external owner shape for one primary COMDAT."""

    if (
        not section.characteristics & _COFF_SCN_LNK_COMDAT
        or section.comdat_selection in {None, 0, 5}
        or section.comdat_associated not in {None, 0}
        or (selection is not None and section.comdat_selection != selection)
    ):
        raise ClassicSemanticError(
            f"carrier definition {name!r} in {coff.label!r} is not the required primary COMDAT"
        )
    owners = [
        symbol
        for symbol in coff.symbols
        if symbol.storage == 2 and symbol.section == section.number
    ]
    if len(owners) != 1 or owners[0].name != name or owners[0].value != 0:
        raise ClassicSemanticError(
            f"carrier definition {name!r} in {coff.label!r} has an ambiguous COMDAT owner"
        )
    return owners[0].symbol_type, owners[0].auxiliary_count


def _associated_carrier_receipt(
    coff: _CoffObject, primary: _CoffSection
) -> list[dict[str, object]]:
    return [
        {
            "section": section.number,
            "name": section.name,
            "digest": Digest.from_bytes(section.body).value,
        }
        for section in coff.sections
        if section.comdat_selection == 5 and _carrier_comdat_root(coff, section) == primary.number
    ]


def _carrier_noncomdat_trace(
    coff: _CoffObject,
    *,
    generator_kinds: tuple[str, ...],
) -> list[dict[str, object]]:
    """Classify non-COMDAT carrier sections with no generic admission path."""

    is_const_pool = generator_kinds == ("const_pool",)
    if is_const_pool and _external_definitions(coff):
        raise ClassicSemanticError(
            f"const-pool carrier {coff.label!r} unexpectedly defines an external symbol"
        )
    const_pool_sections: list[dict[str, object]] = []
    for section in coff.sections:
        if section.comdat_selection not in {None, 0}:
            continue
        folded = section.name.casefold()
        if (
            folded == ".drectve"
            and section.characteristics == 0x00100A00
            and not section.relocations
            and not section.line_numbers
        ):
            continue
        if (
            folded in {".debug$s", ".debug$t"}
            and section.characteristics == 0x42100048
            and not section.line_numbers
        ):
            continue
        if (
            is_const_pool
            and folded == ".rdata"
            and section.characteristics == 0x40400040
            and section.body
            and not section.relocations
            and not section.line_numbers
            and not any(
                symbol.storage == 2 and symbol.section == section.number for symbol in coff.symbols
            )
        ):
            const_pool_sections.append(
                {
                    "object": coff.label,
                    "section": section.number,
                    "name": section.name,
                    "size": len(section.body),
                    "digest": Digest.from_bytes(section.body).value,
                }
            )
            continue
        raise ClassicSemanticError(
            f"carrier {coff.label!r} has an unclassified non-COMDAT section {section.name!r}"
        )
    if is_const_pool and len(const_pool_sections) != 1:
        raise ClassicSemanticError(
            f"const-pool carrier {coff.label!r} does not contain one sealed .rdata section"
        )
    return const_pool_sections


def _carrier_isolation_trace(
    *,
    target: TargetLinkClosure,
    linker_arguments: tuple[str, ...],
    linker_inputs: tuple[str, ...],
    linker_identity: Msvc420LinkerIdentity | None,
    products: Mapping[str, CompilerProduct],
    carrier_node_ids: frozenset[str],
    carrier_generator_kinds: Mapping[str, tuple[str, ...]],
) -> dict[str, object]:
    if tuple(sorted(set(target.compiler_node_ids), key=str.casefold)) != (target.compiler_node_ids):
        raise ClassicSemanticError(f"target {target.target_id!r} compiler closure is not canonical")
    if not carrier_node_ids.issubset(target.compiler_node_ids):
        raise ClassicSemanticError(
            f"target {target.target_id!r} omits a generated carrier from its link closure"
        )
    if set(carrier_generator_kinds) != set(carrier_node_ids):
        raise ClassicSemanticError(
            f"target {target.target_id!r} carrier generator classification differs"
        )
    unknown_nodes = set(target.compiler_node_ids) - set(products)
    if unknown_nodes:
        raise ClassicSemanticError(
            f"target {target.target_id!r} names unknown compiler nodes {sorted(unknown_nodes)}"
        )
    if tuple(sorted(set(target.archive_refs), key=str.casefold)) != target.archive_refs:
        raise ClassicSemanticError(f"target {target.target_id!r} archives are not canonical")

    linker_control_trace: dict[str, object] | None = None
    object_occurrences: dict[str, list[int]] = defaultdict(list)
    archive_occurrences: dict[str, list[int]] = defaultdict(list)
    if carrier_node_ids:
        if linker_identity is None:
            raise ClassicSemanticError(
                "generated-carrier isolation requires the canonical LINK 4.20 identity"
            )
        linker_control_trace = _carrier_linker_control_trace(linker_arguments)
        for ordinal, reference in enumerate(linker_inputs):
            suffix = PurePosixPath(reference.split("/", 1)[-1]).suffix.casefold()
            if suffix == ".obj":
                object_occurrences[reference.casefold()].append(ordinal)
            elif suffix == ".lib":
                archive_occurrences[reference.casefold()].append(ordinal)
            elif suffix != ".res":
                raise ClassicSemanticError(
                    f"target {target.target_id!r} has an unsupported positional input {reference!r}"
                )
        undeclared_archives = set(archive_occurrences) - {
            reference.casefold() for reference in target.archive_refs
        }
        if undeclared_archives:
            raise ClassicSemanticError(
                f"target {target.target_id!r} linker sequence names unsealed archives: "
                f"{sorted(undeclared_archives)}"
            )

    parsed_products = {
        node_id: _parse_coff(products[node_id].payload, products[node_id].object_ref)
        for node_id in target.compiler_node_ids
    }
    product_node_by_object: dict[str, str] = {}
    for node_id in target.compiler_node_ids:
        object_ref = products[node_id].object_ref.casefold()
        if object_ref in product_node_by_object:
            raise ClassicSemanticError(
                f"target {target.target_id!r} compiler products alias object {object_ref!r}"
            )
        product_node_by_object[object_ref] = node_id

    carrier_objects = [
        parsed_products[node_id] for node_id in sorted(carrier_node_ids, key=str.casefold)
    ]
    ordinary_objects = [
        parsed_products[node_id]
        for node_id in target.compiler_node_ids
        if node_id not in carrier_node_ids
    ]
    const_pool_sections: list[dict[str, object]] = []
    for node_id in sorted(carrier_node_ids, key=str.casefold):
        coff = parsed_products[node_id]
        _validate_carrier_comdat_topology(coff)
        const_pool_sections.extend(
            _carrier_noncomdat_trace(
                coff,
                generator_kinds=carrier_generator_kinds[node_id],
            )
        )
        if len(object_occurrences.get(coff.label.casefold(), ())) != 1:
            raise ClassicSemanticError(
                f"generated carrier {coff.label!r} is not one unique direct linker input"
            )
    archive_objects, import_objects, archive_trace = _archive_semantics(
        target,
        compiler_digests=frozenset(
            Digest.from_bytes(products[node_id].payload) for node_id in target.compiler_node_ids
        ),
        carrier_digests=frozenset(item.digest for item in carrier_objects),
    )
    archive_ref_by_object = {
        member.coff.label.casefold(): member.archive_ref for member in archive_objects
    }
    ordinary_objects.extend(member.coff for member in archive_objects)
    if not ordinary_objects:
        raise ClassicSemanticError(f"target {target.target_id!r} has no ordinary object ancestry")

    ordinary_definitions: dict[str, list[tuple[_CoffObject, _CoffSection]]] = defaultdict(list)
    ordinary_references: set[str] = set()
    ordinary_libraries: set[str] = set()
    ordinary_directive_demands: set[str] = set()
    ordinary_directive_retention: set[str] = set()
    for coff in ordinary_objects:
        for name, section in _external_definitions(coff).items():
            ordinary_definitions[name].append((coff, section))
        ordinary_references.update(_external_references(coff))
        ordinary_libraries.update(_default_libraries_for_ordinary(coff))
        directives = _coff_directive_receipt(coff)
        ordinary_directive_demands.update(directives.include_symbols)
        ordinary_directive_retention.update(directives.export_symbols)
    import_definitions = {definition for item in import_objects for definition in item.definitions}

    carrier_definitions: dict[str, list[tuple[_CoffObject, _CoffSection]]] = defaultdict(list)
    carrier_references: set[str] = set()
    carrier_libraries: set[str] = set()
    for coff in carrier_objects:
        for name, section in _external_definitions(coff).items():
            carrier_definitions[name].append((coff, section))
        carrier_references.update(_external_references(coff))
        carrier_libraries.update(_default_libraries(coff))

    imported_collisions = set(carrier_definitions) & import_definitions
    if imported_collisions:
        raise ClassicSemanticError(
            f"target {target.target_id!r} carriers collide with imported symbols: "
            f"{sorted(imported_collisions)}"
        )

    demand_roots = set(target.demand_root_symbols) | ordinary_directive_demands
    retention_roots = set(target.retention_root_symbols) | ordinary_directive_retention
    roots = demand_roots | retention_roots
    unique_carrier = set(carrier_definitions) - set(ordinary_definitions)
    for name in sorted(unique_carrier):
        rows = carrier_definitions[name]
        owner_shapes = {_carrier_primary_owner(coff, section, name) for coff, section in rows}
        if len(owner_shapes) != 1 or (
            len(rows) > 1 and any(section.comdat_selection != 2 for _, section in rows)
        ):
            raise ClassicSemanticError(
                f"target {target.target_id!r} has an ambiguous unique carrier COMDAT {name!r}"
            )
    if not roots.isdisjoint(unique_carrier):
        raise ClassicSemanticError(
            f"target {target.target_id!r} roots a carrier definition: "
            f"{sorted(roots & unique_carrier)}"
        )
    inbound = unique_carrier & ordinary_references
    if inbound:
        raise ClassicSemanticError(
            f"target {target.target_id!r} has inbound carrier references: {sorted(inbound)}"
        )
    novel_dependencies = carrier_references - ordinary_references - set(carrier_definitions)
    if novel_dependencies:
        raise ClassicSemanticError(
            f"target {target.target_id!r} carriers add external dependencies: "
            f"{sorted(novel_dependencies)}"
        )
    novel_libraries = carrier_libraries - ordinary_libraries
    if novel_libraries:
        raise ClassicSemanticError(
            f"target {target.target_id!r} carriers add default libraries: {sorted(novel_libraries)}"
        )

    duplicate_receipts: list[dict[str, object]] = []
    for name in sorted(set(carrier_definitions) & set(ordinary_definitions)):
        carrier_rows = carrier_definitions[name]
        ordinary_rows = ordinary_definitions[name]
        if any(
            relocation.target_section > 0 and relocation.target_storage != 2
            for _, section in (*ordinary_rows, *carrier_rows)
            for relocation in section.relocations
        ):
            raise ClassicSemanticError(
                f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                "has an object-local relocation"
            )
        all_rows = [*ordinary_rows, *carrier_rows]
        for coff, _ in ordinary_rows:
            _validate_carrier_comdat_topology(coff)
        owner_shapes = {
            _carrier_primary_owner(coff, section, name, selection=2) for coff, section in all_rows
        }
        if len(owner_shapes) != 1:
            raise ClassicSemanticError(
                f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                "has inconsistent external owners"
            )

        ordinary_providers: list[tuple[int, str, _CoffObject, _CoffSection]] = []
        archive_provider_refs: set[str] = set()
        for coff, section in ordinary_rows:
            provider_node_id = product_node_by_object.get(coff.label.casefold())
            ordinals = object_occurrences.get(coff.label.casefold(), ())
            if provider_node_id is None:
                archive_ref = archive_ref_by_object.get(coff.label.casefold())
                if archive_ref is None:
                    raise ClassicSemanticError(
                        f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                        "has an unclassified ordinary provider"
                    )
                archive_provider_refs.add(archive_ref.casefold())
                continue
            if provider_node_id in carrier_node_ids or len(ordinals) != 1:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                    "lacks an unambiguous direct ordinary provider"
                )
            ordinary_providers.append((ordinals[0], provider_node_id, coff, section))

        carrier_providers: list[tuple[int, str, _CoffObject, _CoffSection]] = []
        for coff, section in carrier_rows:
            provider_node_id = product_node_by_object.get(coff.label.casefold())
            ordinals = object_occurrences.get(coff.label.casefold(), ())
            if provider_node_id not in carrier_node_ids or len(ordinals) != 1:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                    "lacks an unambiguous direct carrier provider"
                )
            if provider_node_id is None:
                raise AssertionError("carrier provider was not narrowed")
            carrier_providers.append((ordinals[0], provider_node_id, coff, section))

        if not ordinary_providers:
            raise ClassicSemanticError(
                f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                "lacks an unambiguous direct ordinary provider"
            )
        winner = min(ordinary_providers, key=lambda item: item[0])
        if any(not archive_occurrences.get(reference) for reference in archive_provider_refs):
            raise ClassicSemanticError(
                f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                "has a non-positional archive provider"
            )
        archive_ordinals = [
            ordinal
            for reference in archive_provider_refs
            for ordinal in archive_occurrences.get(reference, ())
        ]
        if any(winner[0] >= provider[0] for provider in carrier_providers) or (
            archive_ordinals and winner[0] >= min(archive_ordinals)
        ):
            raise ClassicSemanticError(
                f"target {target.target_id!r} duplicate carrier symbol {name!r} "
                "is not shadowed by the first direct LINK 4.20 select-any provider"
            )
        duplicate_receipts.append(
            {
                "theorem": "msvc420-first-select-any-provider-v1",
                "symbol": name,
                "winner": {
                    "node_id": winner[1],
                    "object": winner[2].label,
                    "linker_input_ordinal": winner[0],
                    "section": winner[3].number,
                    "section_digest": Digest.from_bytes(winner[3].body).value,
                },
                "later_archive_providers": [
                    {
                        "archive": reference,
                        "linker_input_ordinals": archive_occurrences.get(reference, ()),
                    }
                    for reference in sorted(archive_provider_refs)
                ],
                "discarded_carriers": [
                    {
                        "node_id": node_id,
                        "object": coff.label,
                        "linker_input_ordinal": ordinal,
                        "section": section.number,
                        "section_digest": Digest.from_bytes(section.body).value,
                        "associative_sections": _associated_carrier_receipt(coff, section),
                    }
                    for ordinal, node_id, coff, section in sorted(carrier_providers)
                ],
            }
        )

    return {
        "target": target.target_id,
        "carrier_objects": [
            {"label": item.label, "digest": item.digest.value}
            for item in sorted(carrier_objects, key=lambda item: item.label.casefold())
        ],
        "ordinary_object_count": len(ordinary_objects),
        "archive_count": len(target.archive_refs),
        "archives": archive_trace,
        "import_object_count": len(import_objects),
        "demand_root_symbols": sorted(demand_roots),
        "retention_root_symbols": sorted(retention_roots),
        "unique_unreferenced_definitions": sorted(unique_carrier),
        "existing_external_dependencies": sorted(carrier_references),
        "existing_default_libraries": sorted(carrier_libraries),
        "intentional_const_pool_sections": const_pool_sections,
        "linker_identity": (
            linker_identity.proof_receipt() if linker_identity is not None else None
        ),
        "linker_controls": linker_control_trace,
        "ordered_discarded_select_any_comdats": duplicate_receipts,
    }
