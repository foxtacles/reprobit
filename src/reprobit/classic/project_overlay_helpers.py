"""Project-overlay semantic ancestry proofs: helper isolation traces."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import cast

from reprobit.classic.coff_evidence import (
    _coff_directive_receipt,
    _CoffObject,
    _default_libraries_for_ordinary,
    _external_definitions,
    _external_references,
)
from reprobit.classic.coff_projection import _CrtPullLinkerDependency, _OrderedArchiveSeedDependency
from reprobit.classic.coff_projection_runtime import _FORBIDDEN_RUNTIME_SECTION_PREFIXES
from reprobit.classic.semantic_contracts import (
    CompilerProduct,
    TargetLinkClosure,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest

from .project_overlay_archives import (
    _archive_semantics,
    _ArchiveCoffMember,
    _msvc_function_auxiliary_receipt,
    _ordered_seed_demand_evidence,
)


def _helper_isolation_trace(
    *,
    target: TargetLinkClosure,
    linker_inputs: tuple[str, ...],
    products: Mapping[str, CompilerProduct],
    counterfactual_objects: Mapping[str, _CoffObject],
    effective_objects: Mapping[str, _CoffObject],
    helper_sections: Mapping[str, frozenset[int]],
    crt_pull_dependencies: Mapping[str, tuple[_CrtPullLinkerDependency, ...]],
    ordered_archive_seed_dependencies: Mapping[str, tuple[_OrderedArchiveSeedDependency, ...]],
) -> dict[str, object]:
    target_helpers = {
        node_id: helper_sections[node_id]
        for node_id in target.compiler_node_ids
        if node_id in helper_sections
    }
    if not target_helpers:
        return {
            "target": target.target_id,
            "helper_objects": [],
            "unique_unreferenced_definitions": [],
            "crt_pull_archive_provider_candidates": [],
            "ordered_archive_seed_dependencies": [],
        }
    object_occurrences: dict[str, list[tuple[int, int]]] = defaultdict(list)
    archive_occurrences: dict[str, list[tuple[int, int]]] = defaultdict(list)
    object_ordinal = 0
    library_ordinal = 0
    for ordinal, reference in enumerate(linker_inputs):
        suffix = PurePosixPath(reference.split("/", 1)[-1]).suffix.casefold()
        if suffix == ".obj":
            object_occurrences[reference.casefold()].append((ordinal, object_ordinal))
            object_ordinal += 1
        elif suffix == ".lib":
            archive_occurrences[reference.casefold()].append((ordinal, library_ordinal))
            library_ordinal += 1
        elif suffix != ".res":
            raise ClassicSemanticError(
                f"target {target.target_id!r} has a non-positional linker input {reference!r}"
            )
    undeclared_archives = set(archive_occurrences) - {
        reference.casefold() for reference in target.archive_refs
    }
    if undeclared_archives:
        raise ClassicSemanticError(
            f"target {target.target_id!r} linker sequence names unsealed archives: "
            f"{sorted(undeclared_archives)}"
        )
    products_by_object: dict[str, list[str]] = defaultdict(list)
    for node_id in target.compiler_node_ids:
        product = products[node_id]
        products_by_object[product.object_ref.casefold()].append(node_id)
    direct_node_ids: set[str] = set()
    for object_ref in object_occurrences:
        owners = products_by_object.get(object_ref, [])
        if len(owners) != 1:
            raise ClassicSemanticError(
                f"target {target.target_id!r} direct object {object_ref!r} has "
                f"{len(owners)} compiler owners"
            )
        direct_node_ids.add(owners[0])
    archive_objects, import_objects, archive_trace = _archive_semantics(
        target,
        compiler_digests=frozenset(
            Digest.from_bytes(products[node_id].payload) for node_id in target.compiler_node_ids
        ),
        carrier_digests=frozenset(),
        include_compiler_members=True,
    )
    baseline_references: set[str] = set()
    baseline_definitions: set[str] = set()
    compiler_definitions: set[str] = set()
    direct_definition_providers: dict[str, list[tuple[str, _CoffObject, int]]] = defaultdict(list)
    baseline_libraries: set[str] = set()
    baseline_directive_demands: set[str] = set()
    baseline_directive_retention: set[str] = set()
    archive_definitions: dict[str, list[_ArchiveCoffMember]] = defaultdict(list)
    seed_types: dict[str, int] = {}
    for node_id in sorted(target_helpers, key=str.casefold):
        for seed_dependency in ordered_archive_seed_dependencies.get(node_id, ()):
            previous_type = seed_types.setdefault(seed_dependency.name, seed_dependency.symbol_type)
            if previous_type != seed_dependency.symbol_type:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed dependency "
                    f"{seed_dependency.name!r} has conflicting symbol types"
                )
    baseline_seed_demands: dict[str, list[dict[str, object]]] = defaultdict(list)
    for node_id in sorted(direct_node_ids, key=str.casefold):
        baseline = counterfactual_objects.get(node_id, effective_objects.get(node_id))
        if baseline is None:
            continue
        baseline_references.update(_external_references(baseline))
        definitions = _external_definitions(baseline)
        baseline_definitions.update(definitions)
        compiler_definitions.update(definitions)
        for name, section in definitions.items():
            direct_definition_providers[name].append((node_id, baseline, section.number))
        baseline_libraries.update(_default_libraries_for_ordinary(baseline))
        baseline_directives = _coff_directive_receipt(baseline)
        baseline_directive_demands.update(baseline_directives.include_symbols)
        baseline_directive_retention.update(baseline_directives.export_symbols)
        product = products[node_id]
        occurrences = tuple(object_occurrences.get(product.object_ref.casefold(), ()))
        for name, evidence in _ordered_seed_demand_evidence(
            baseline,
            expected_types=seed_types,
        ).items():
            baseline_seed_demands[name].append(
                {
                    "kind": "direct-object",
                    "node_id": node_id,
                    "object_ref": product.object_ref,
                    "object_digest": baseline.digest.value,
                    "linker_input_ordinals": [item[0] for item in occurrences],
                    "direct_object_ordinals": [item[1] for item in occurrences],
                    **evidence,
                }
            )
    for archive in archive_objects:
        baseline_references.update(_external_references(archive.coff))
        definitions = _external_definitions(archive.coff)
        baseline_definitions.update(definitions)
        for name in definitions:
            archive_definitions[name].append(archive)
        baseline_libraries.update(_default_libraries_for_ordinary(archive.coff))
        archive_directives = _coff_directive_receipt(archive.coff)
        baseline_directive_demands.update(archive_directives.include_symbols)
        baseline_directive_retention.update(archive_directives.export_symbols)
        occurrences = tuple(archive_occurrences.get(archive.archive_ref.casefold(), ()))
        for name, evidence in _ordered_seed_demand_evidence(
            archive.coff,
            expected_types=seed_types,
        ).items():
            baseline_seed_demands[name].append(
                {
                    "kind": "archive-member",
                    "archive_ref": archive.archive_ref,
                    "member_ordinal": archive.member_index,
                    "member_name": archive.member_name,
                    "member_digest": archive.coff.digest.value,
                    "linker_input_ordinals": [item[0] for item in occurrences],
                    "library_occurrence_ordinals": [item[1] for item in occurrences],
                    **evidence,
                }
            )
    import_definitions = {definition for item in import_objects for definition in item.definitions}

    helper_definitions: set[str] = set()
    helper_references: set[str] = set()
    helper_reference_sites: dict[str, set[tuple[str, int]]] = defaultdict(set)
    helper_libraries: set[str] = set()
    inbound_references: set[str] = set()
    inbound_helper_sections: set[tuple[str, int, int]] = set()
    helper_objects_trace: list[dict[str, object]] = []
    helper_control_roots: set[str] = set()
    for node_id in target.compiler_node_ids:
        if node_id in target_helpers:
            continue
        effective = effective_objects.get(node_id)
        if effective is not None:
            inbound_references.update(_external_references(effective))
    for node_id, excluded in sorted(target_helpers.items()):
        effective = effective_objects[node_id]
        counterfactual = counterfactual_objects[node_id]
        definitions = _external_definitions(effective)
        names = {name for name, section in definitions.items() if section.number in excluded}
        if not names:
            raise ClassicSemanticError(f"helper compiler {node_id!r} has no definitions")
        helper_definitions.update(names)
        for section in effective.sections:
            if section.number in excluded:
                folded = section.name.casefold()
                if any(folded.startswith(prefix) for prefix in _FORBIDDEN_RUNTIME_SECTION_PREFIXES):
                    raise ClassicSemanticError(
                        f"helper compiler {node_id!r} introduces runtime-root section "
                        f"{section.name!r}"
                    )
                section_references = {
                    relocation.target
                    for relocation in section.relocations
                    if relocation.target_section == 0 and relocation.target_storage in {2, 105}
                }
                helper_references.update(section_references)
                for reference in section_references:
                    helper_reference_sites[reference].add((node_id, section.number))
            else:
                if not section.name.casefold().startswith(".debug"):
                    inbound_helper_sections.update(
                        (node_id, section.number, relocation.target_section)
                        for relocation in section.relocations
                        if relocation.target_section in excluded
                    )
                inbound_references.update(
                    relocation.target
                    for relocation in section.relocations
                    if relocation.target_section == 0
                )
        helper_libraries.update(_default_libraries_for_ordinary(effective))
        counterfactual_directives = _coff_directive_receipt(counterfactual)
        effective_directives = _coff_directive_receipt(effective)
        helper_control_roots.update(
            set(effective_directives.include_symbols)
            - set(counterfactual_directives.include_symbols)
        )
        helper_control_roots.update(
            set(effective_directives.export_symbols) - set(counterfactual_directives.export_symbols)
        )
        helper_objects_trace.append(
            {
                "node_id": node_id,
                "object_digest": effective.digest.value,
                "sections": sorted(excluded),
                "definitions": sorted(names),
            }
        )

    crt_pull_archive_candidates: list[dict[str, object]] = []
    for node_id in sorted(target_helpers, key=str.casefold):
        for dependency in crt_pull_dependencies.get(node_id, ()):
            if not set(dependency.helper_sections).issubset(target_helpers[node_id]):
                raise ClassicSemanticError(
                    f"target {target.target_id!r} crt_pull dependency {dependency.name!r} "
                    "escapes its excluded helper sections"
                )
            if dependency.name not in helper_references:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} loses crt_pull dependency {dependency.name!r}"
                )
            if dependency.name in compiler_definitions or dependency.name in import_definitions:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} crt_pull dependency "
                    f"{dependency.name!r} resolves before ordinary archive extraction"
                )
            providers = sorted(
                archive_definitions.get(dependency.name, ()),
                key=lambda item: (
                    item.archive_ref.casefold(),
                    item.member_index,
                    item.member_name.casefold(),
                ),
            )
            if not providers:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} crt_pull dependency "
                    f"{dependency.name!r} has no ordinary declared archive definition"
                )
            crt_pull_archive_candidates.append(
                {
                    "node_id": node_id,
                    "name": dependency.name,
                    "type": dependency.symbol_type,
                    "helper_sections": list(dependency.helper_sections),
                    "ordinary_archive_definitions": [item.coff.label for item in providers],
                }
            )

    demand_roots = set(target.demand_root_symbols)
    retention_roots = set(target.retention_root_symbols) | baseline_directive_retention
    roots = demand_roots | retention_roots | baseline_directive_demands
    ordered_archive_seed_trace: list[dict[str, object]] = []
    for node_id in sorted(target_helpers, key=str.casefold):
        dependencies = tuple(
            dependency
            for dependency in ordered_archive_seed_dependencies.get(node_id, ())
            if dependency.binding_kind == "function-rel32"
        )
        if not dependencies:
            continue
        product = products[node_id]
        owner_occurrences = object_occurrences.get(product.object_ref.casefold(), ())
        if len(owner_occurrences) != 1:
            raise ClassicSemanticError(
                f"target {target.target_id!r} ordered archive seed owner "
                f"{product.object_ref!r} has {len(owner_occurrences)} direct linker occurrences"
            )
        owner_input_ordinal, owner_object_ordinal = owner_occurrences[0]
        for seed_dependency in dependencies:
            if seed_dependency.helper_section not in target_helpers[node_id]:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed dependency "
                    f"{seed_dependency.name!r} escapes its excluded SeedOrder section"
                )
            if seed_dependency.name not in helper_references:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} loses ordered archive seed dependency "
                    f"{seed_dependency.name!r}"
                )
            if helper_reference_sites[seed_dependency.name] != {
                (node_id, seed_dependency.helper_section)
            }:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed dependency "
                    f"{seed_dependency.name!r} is referenced outside its SeedOrder owner"
                )
            retained_demands = sorted(
                baseline_seed_demands.get(seed_dependency.name, ()),
                key=lambda item: (
                    min(cast(list[int], item["linker_input_ordinals"]), default=-1),
                    str(item["kind"]).casefold(),
                    str(item.get("object_ref", item.get("archive_ref", ""))).casefold(),
                    int(item.get("member_ordinal", -1)),
                ),
            )
            retained_demand_ordinals = [
                ordinal
                for item in retained_demands
                for ordinal in cast(list[int], item["linker_input_ordinals"])
            ]
            if retained_demands and not retained_demand_ordinals:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed dependency "
                    f"{seed_dependency.name!r} has non-positional retained linker demand"
                )
            if any(ordinal <= owner_input_ordinal for ordinal in retained_demand_ordinals):
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed dependency "
                    f"{seed_dependency.name!r} has retained linker demand before its "
                    "SeedOrder owner (or in the same input)"
                )
            if seed_dependency.name in demand_roots:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed dependency "
                    f"{seed_dependency.name!r} is an initial demand linker root"
                )
            if (
                seed_dependency.name in compiler_definitions
                or seed_dependency.name in import_definitions
            ):
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed dependency "
                    f"{seed_dependency.name!r} resolves before ordinary archive extraction"
                )
            retention_linker_root = seed_dependency.name in retention_roots
            providers = sorted(
                archive_definitions.get(seed_dependency.name, ()),
                key=lambda item: (
                    item.archive_ref.casefold(),
                    item.member_index,
                    item.member_name.casefold(),
                ),
            )
            if len(providers) != 1:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed dependency "
                    f"{seed_dependency.name!r} has {len(providers)} ordinary archive providers"
                )
            provider = providers[0]
            provider_rows = [
                symbol
                for symbol in provider.coff.symbols
                if symbol.name == seed_dependency.name
                and symbol.storage == 2
                and symbol.section > 0
            ]
            if (
                len(provider_rows) != 1
                or provider_rows[0].symbol_type != seed_dependency.symbol_type
            ):
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed dependency "
                    f"{seed_dependency.name!r} has an inexact typed archive provider"
                )
            provider_auxiliary = _msvc_function_auxiliary_receipt(
                provider.coff,
                symbol=provider_rows[0],
                section=provider.coff.sections[provider_rows[0].section - 1],
            )
            provider_occurrences = tuple(
                archive_occurrences.get(provider.archive_ref.casefold(), ())
            )
            eligible_occurrences = tuple(
                occurrence
                for occurrence in provider_occurrences
                if occurrence[0] > owner_input_ordinal
            )
            if not eligible_occurrences:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed provider "
                    f"{provider.archive_ref!r} has no occurrence after owner "
                    f"{product.object_ref!r}"
                )
            ordered_archive_seed_trace.append(
                {
                    "theorem": "typed-ordered-archive-seed-dependency-v1",
                    "node_id": node_id,
                    "owner": {
                        "object_ref": product.object_ref,
                        "linker_input_ordinal": owner_input_ordinal,
                        "direct_object_ordinal": owner_object_ordinal,
                    },
                    "helper_identifier": seed_dependency.helper_identifier,
                    "helper_symbol": seed_dependency.helper_symbol,
                    "helper_section": seed_dependency.helper_section,
                    "policy": seed_dependency.policy,
                    "binding_kind": seed_dependency.binding_kind,
                    "name": seed_dependency.name,
                    "type": seed_dependency.symbol_type,
                    "relocation_offset": seed_dependency.relocation_offset,
                    "first_use_ordinal": seed_dependency.first_use_ordinal,
                    "undefined_symbol_index": seed_dependency.undefined_symbol_index,
                    "undefined_row_ordinal": seed_dependency.undefined_row_ordinal,
                    "retention_linker_root": retention_linker_root,
                    "retained_linker_demands": retained_demands,
                    "retained_demand_order": (
                        {
                            "first_linker_input_ordinal": min(retained_demand_ordinals),
                            "relative_to_seed_owner": "after",
                        }
                        if retained_demand_ordinals
                        else None
                    ),
                    "provider": {
                        "archive_ref": provider.archive_ref,
                        "all_linker_input_ordinals": [
                            occurrence[0] for occurrence in provider_occurrences
                        ],
                        "all_library_occurrence_ordinals": [
                            occurrence[1] for occurrence in provider_occurrences
                        ],
                        "eligible_linker_input_ordinals": [
                            occurrence[0] for occurrence in eligible_occurrences
                        ],
                        "eligible_library_occurrence_ordinals": [
                            occurrence[1] for occurrence in eligible_occurrences
                        ],
                        "selected_linker_input_ordinal": eligible_occurrences[0][0],
                        "selected_library_occurrence_ordinal": eligible_occurrences[0][1],
                        "member_ordinal": provider.member_index,
                        "member_name": provider.member_name,
                        "member_digest": provider.coff.digest.value,
                        "function_definition_auxiliary": provider_auxiliary,
                    },
                }
            )

    for node_id in sorted(target_helpers, key=str.casefold):
        dependencies = tuple(
            dependency
            for dependency in ordered_archive_seed_dependencies.get(node_id, ())
            if dependency.binding_kind == "data-dir32"
        )
        if not dependencies:
            continue
        product = products[node_id]
        owner_occurrences = object_occurrences.get(product.object_ref.casefold(), ())
        if len(owner_occurrences) != 1:
            raise ClassicSemanticError(
                f"target {target.target_id!r} ordered archive seed owner "
                f"{product.object_ref!r} has {len(owner_occurrences)} direct linker occurrences"
            )
        owner_input_ordinal, owner_object_ordinal = owner_occurrences[0]
        for seed_dependency in dependencies:
            name = seed_dependency.name
            if seed_dependency.helper_section not in target_helpers[node_id]:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} escapes its excluded SeedOrder section"
                )
            if helper_reference_sites[name] != {(node_id, seed_dependency.helper_section)}:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} is referenced outside its SeedOrder owner"
                )
            if name in demand_roots:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} is an initial demand linker root"
                )
            if direct_definition_providers.get(name):
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} has a direct object definition"
                )
            if name in import_definitions:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} has an import definition"
                )

            retained_demands = sorted(
                (
                    item
                    for item in baseline_seed_demands.get(name, ())
                    if item["kind"] == "direct-object"
                ),
                key=lambda item: (
                    min(cast(list[int], item["linker_input_ordinals"]), default=-1),
                    str(item["object_ref"]).casefold(),
                ),
            )
            retained_demand_ordinals = [
                ordinal
                for item in retained_demands
                for ordinal in cast(list[int], item["linker_input_ordinals"])
            ]
            if retained_demands and not retained_demand_ordinals:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} has non-positional retained linker demand"
                )
            if not retained_demand_ordinals:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} has no retained direct-object demand"
                )
            first_retained_demand = min(retained_demand_ordinals)
            if owner_input_ordinal >= first_retained_demand:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} has retained direct-object demand before its "
                    "SeedOrder owner"
                )

            providers = sorted(
                archive_definitions.get(name, ()),
                key=lambda item: (
                    item.archive_ref.casefold(),
                    item.member_index,
                    item.member_name.casefold(),
                ),
            )
            if len(providers) != 1:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} has {len(providers)} ordinary archive providers"
                )
            provider = providers[0]
            provider_rows = [
                symbol
                for symbol in provider.coff.symbols
                if symbol.name == name and symbol.storage == 2 and symbol.section > 0
            ]
            if (
                len(provider_rows) != 1
                or provider_rows[0].symbol_type != seed_dependency.symbol_type
                or provider_rows[0].auxiliary_count != 0
            ):
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data dependency "
                    f"{name!r} has an inexact typed archive provider"
                )
            provider_occurrences = tuple(
                archive_occurrences.get(provider.archive_ref.casefold(), ())
            )
            eligible_occurrences = tuple(
                occurrence
                for occurrence in provider_occurrences
                if occurrence[0] > owner_input_ordinal
            )
            if not eligible_occurrences:
                raise ClassicSemanticError(
                    f"target {target.target_id!r} ordered archive seed data provider "
                    f"{provider.archive_ref!r} has no occurrence after owner "
                    f"{product.object_ref!r}"
                )
            selected_occurrence = eligible_occurrences[0]
            ordered_archive_seed_trace.append(
                {
                    "theorem": "typed-ordered-archive-seed-dependency-v1",
                    "node_id": node_id,
                    "owner": {
                        "object_ref": product.object_ref,
                        "linker_input_ordinal": owner_input_ordinal,
                        "direct_object_ordinal": owner_object_ordinal,
                    },
                    "helper_identifier": seed_dependency.helper_identifier,
                    "helper_symbol": seed_dependency.helper_symbol,
                    "helper_section": seed_dependency.helper_section,
                    "policy": seed_dependency.policy,
                    "binding_kind": seed_dependency.binding_kind,
                    "name": name,
                    "type": seed_dependency.symbol_type,
                    "relocation_offset": seed_dependency.relocation_offset,
                    "first_use_ordinal": seed_dependency.first_use_ordinal,
                    "undefined_symbol_index": seed_dependency.undefined_symbol_index,
                    "undefined_row_ordinal": seed_dependency.undefined_row_ordinal,
                    "retention_linker_root": name in retention_roots,
                    "retained_linker_demands": retained_demands,
                    "retained_demand_order": {
                        "first_linker_input_ordinal": first_retained_demand,
                        "relative_to_seed_owner": "after",
                    },
                    "provider": {
                        "archive_ref": provider.archive_ref,
                        "all_linker_input_ordinals": [
                            occurrence[0] for occurrence in provider_occurrences
                        ],
                        "all_library_occurrence_ordinals": [
                            occurrence[1] for occurrence in provider_occurrences
                        ],
                        "eligible_linker_input_ordinals": [
                            occurrence[0] for occurrence in eligible_occurrences
                        ],
                        "eligible_library_occurrence_ordinals": [
                            occurrence[1] for occurrence in eligible_occurrences
                        ],
                        "selected_linker_input_ordinal": selected_occurrence[0],
                        "selected_library_occurrence_ordinal": selected_occurrence[1],
                        "member_ordinal": provider.member_index,
                        "member_name": provider.member_name,
                        "member_digest": provider.coff.digest.value,
                    },
                }
            )

    inbound_references.update(
        reference for archive in archive_objects for reference in _external_references(archive.coff)
    )
    imported_collisions = helper_definitions & import_definitions
    if imported_collisions:
        raise ClassicSemanticError(
            f"target {target.target_id!r} helpers collide with imports: "
            f"{sorted(imported_collisions)}"
        )
    if helper_control_roots:
        raise ClassicSemanticError(
            f"target {target.target_id!r} helpers add rooted linker controls: "
            f"{sorted(helper_control_roots)}"
        )
    if roots & helper_definitions:
        raise ClassicSemanticError(
            f"target {target.target_id!r} roots helper definitions: "
            f"{sorted(roots & helper_definitions)}"
        )
    inbound = helper_definitions & inbound_references
    if inbound:
        raise ClassicSemanticError(
            f"target {target.target_id!r} has inbound helper references: {sorted(inbound)}"
        )
    if inbound_helper_sections:
        raise ClassicSemanticError(
            f"target {target.target_id!r} has retained relocations into helper sections: "
            f"{sorted(inbound_helper_sections)}"
        )
    novel_dependencies = (
        helper_references
        - baseline_references
        - baseline_definitions
        - helper_definitions
        - import_definitions
    )
    if novel_dependencies:
        raise ClassicSemanticError(
            f"target {target.target_id!r} helpers add external dependencies: "
            f"{sorted(novel_dependencies)}"
        )
    novel_libraries = helper_libraries - baseline_libraries
    if novel_libraries:
        raise ClassicSemanticError(
            f"target {target.target_id!r} helpers add default libraries: {sorted(novel_libraries)}"
        )
    return {
        "target": target.target_id,
        "helper_objects": helper_objects_trace,
        "unique_unreferenced_definitions": sorted(helper_definitions),
        "existing_external_dependencies": sorted(helper_references),
        "existing_default_libraries": sorted(helper_libraries),
        "crt_pull_archive_provider_candidates": crt_pull_archive_candidates,
        "crt_pull_extraction_closure": "terminal-literal-link-verification",
        "ordered_archive_seed_dependencies": sorted(
            ordered_archive_seed_trace,
            key=lambda item: (
                cast(str, item["node_id"]).casefold(),
                cast(int, item["first_use_ordinal"]),
            ),
        ),
        "ordered_archive_seed_extraction_closure": (
            "locked-terminal-linker-and-literal-byte-verification"
        ),
        "archives": archive_trace,
    }
