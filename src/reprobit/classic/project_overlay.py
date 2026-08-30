"""Project-overlay semantic ancestry proofs for classic source overlays.

Source rendering is not a semantic proof.  This module admits an overlay only
when current-run evidence establishes a closed source theorem, compiler-input
congruence, and a strict COFF/link projection for every effective primary
input.  Donor-only renderings remain private.  Generated intervention units
are closed section by section: duplicate COMDATs must lose by proven LINK
order, unique COMDATs must be dead under /OPT:REF, and the one intentional
constant-pool data shape is sealed byte for byte.

The validator is intentionally conservative.  Unknown COFF constructs and
incomplete link closures are errors, never best-effort evidence.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import cast

from reprobit.classic.coff_evidence import (
    ClassicImportObjectReceipt,
    _coff_directive_receipt,
    _CoffObject,
    _CoffRelocation,
    _CoffSection,
    _CoffSymbol,
    _default_libraries_for_ordinary,
    _external_definitions,
    _external_references,
    _parse_coff,
    _parse_import_object,
)
from reprobit.classic.coff_projection import (
    _FORBIDDEN_RUNTIME_SECTION_PREFIXES,
    _CrtPullLinkerDependency,
    _OrderedArchiveSeedDependency,
)
from reprobit.classic.compiler_epoch import (
    _compiler_namespace_member_wire,
    _compiler_namespace_toolchain_readers,
    _project_compiler_audit_trace,
)
from reprobit.classic.linker_identity import (
    Msvc420LinkerIdentity,
    issue_msvc420_linker_identity,
)
from reprobit.classic.semantic_contracts import (
    SOURCE_OVERLAY_OBLIGATIONS,
    SOURCE_OVERLAY_VALIDATOR_DIGEST,
    SOURCE_OVERLAY_VALIDATOR_ID,
    ArchiveInput,
    CleanSourceInput,
    CompilerProduct,
    DonorSemanticLane,
    EffectiveOverlayReceipt,
    OverlaySemanticSnapshot,
    OverlaySemanticValidation,
    PrimarySourceOrigin,
    ProjectOverlayCounterfactualAudit,
    ProjectOverlaySourcePair,
    SemanticValidatorContract,
    SourceInputReceipt,
    TargetLinkClosure,
    _donor_input_is_authorized,
    _issue_semantic_proof,
    _statement_named_digest,
    _statement_payload_digest,
    semantic_proof_matches,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic.source_overlay import (
    _ancestor_compilers,
    _clean_source_authority,
    _compiler_epoch_wire,
    _compiler_semantic_sources,
    _compiler_shape,
    _graph_archives,
    _overlay_declaration,
    _overlay_interventions,
    _OverlaySourceValidation,
    _unique,
    _validate_project_overlay_sources,
)
from reprobit.classic.source_overlay_claims import _relative
from reprobit.formats import FormatError, parse_coff_archive
from reprobit.model import Digest, SemanticProof
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    linker_input_sequence,
    producer_graph_digest,
    toolchain_document_digest,
)
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ProjectBundle,
)
from reprobit.strict_json import canonical_json

_ADMITTED_SECTION_PREFIXES = (
    ".bss",
    ".data",
    ".debug",
    ".drectve",
    ".rdata",
    ".text",
    ".xdata",
)

_COFF_SCN_LNK_COMDAT = 0x00001000


@dataclass(frozen=True, slots=True)
class _ArchiveCoffMember:
    archive_ref: str
    member_index: int
    member_name: str
    coff: _CoffObject


@dataclass(frozen=True, slots=True)
class _OverlayOutputOwner:
    """Proof owner and sharing class for one effective overlay path."""

    intervention_id: str
    target_id: str
    generated_input: bool


def _ordered_seed_demand_evidence(
    coff: _CoffObject,
    *,
    expected_types: Mapping[str, int],
) -> dict[str, dict[str, object]]:
    """Seal exact LINK demand rows and positional ``/INCLUDE`` controls."""

    sites_by_index: dict[int, list[tuple[_CoffSection, _CoffRelocation]]] = defaultdict(list)
    for section in coff.sections:
        if section.name.casefold().startswith(".debug"):
            continue
        for relocation in section.relocations:
            if relocation.target in expected_types and relocation.target_section == 0:
                sites_by_index[relocation.target_index].append((section, relocation))

    directives = _coff_directive_receipt(coff)
    include_counts: dict[str, int] = defaultdict(int)
    for name in directives.include_symbols:
        if name in expected_types:
            include_counts[name] += 1

    undefined_rows = tuple(symbol for symbol in coff.symbols if symbol.section == 0)
    undefined_ordinals = {symbol.index: ordinal for ordinal, symbol in enumerate(undefined_rows)}
    demanded_names = set(include_counts)
    demanded_names.update(symbol.name for symbol in undefined_rows if symbol.name in expected_types)

    result: dict[str, dict[str, object]] = {}
    for name in sorted(demanded_names, key=str.casefold):
        rows = [symbol for symbol in coff.symbols if symbol.name == name]
        expected_type = expected_types[name]
        undefined = [symbol for symbol in rows if symbol.section == 0]
        row_receipt: dict[str, object] | None = None
        if undefined:
            if (
                len(rows) != 1
                or len(undefined) != 1
                or undefined[0].value != 0
                or undefined[0].symbol_type != expected_type
                or undefined[0].storage != 2
                or undefined[0].auxiliary_count != 0
            ):
                raise ClassicSemanticError(
                    f"{coff.label} has an inexact retained linker demand row for "
                    f"ordered archive seed dependency {name!r}"
                )
            row = undefined[0]
            sites = sites_by_index.get(row.index, ())
            if any(
                relocation.target != name
                or relocation.target_section != 0
                or relocation.target_value != 0
                or relocation.target_type != expected_type
                or relocation.target_storage != 2
                for _section, relocation in sites
            ):
                raise ClassicSemanticError(
                    f"{coff.label} has an inexact retained linker demand row for "
                    f"ordered archive seed dependency {name!r}"
                )
            row_receipt = {
                "symbol_index": row.index,
                "undefined_row_ordinal": undefined_ordinals[row.index],
                "relocation_sites": [
                    {
                        "section": section.number,
                        "section_name": section.name,
                        "offset": relocation.offset,
                        "type": relocation.relocation_type,
                        "addend": relocation.addend.hex(),
                    }
                    for section, relocation in sites
                ],
            }
        result[name] = {
            "undefined_external_row": row_receipt,
            "include_directive_count": include_counts.get(name, 0),
        }
    return result


def _msvc_function_auxiliary_receipt(
    coff: _CoffObject,
    *,
    symbol: _CoffSymbol,
    section: _CoffSection,
) -> dict[str, object]:
    """Classify an optional canonical MSVC function-definition auxiliary."""

    if symbol.auxiliary_count == 0:
        return {"kind": "absent"}
    if symbol.auxiliary_count != 1 or len(symbol.auxiliary) != 18:
        raise ClassicSemanticError(
            f"{coff.label} function provider {symbol.name!r} has an inexact auxiliary"
        )
    auxiliary = symbol.auxiliary
    tag_index = int.from_bytes(auxiliary[0:4], "little")
    total_size = int.from_bytes(auxiliary[4:8], "little")
    line_pointer = int.from_bytes(auxiliary[8:12], "little")
    next_function_index = int.from_bytes(auxiliary[12:16], "little")
    unused = int.from_bytes(auxiliary[16:18], "little")
    by_index = {item.index: item for item in coff.symbols}
    begin = by_index.get(tag_index)
    later_functions = tuple(
        item
        for item in coff.symbols
        if item.index > symbol.index
        and item.value == 0
        and item.section > 0
        and item.symbol_type == 0x20
        and item.storage == 2
        and item.auxiliary_count == 1
    )
    expected_next = later_functions[0] if later_functions else None
    next_function = by_index.get(next_function_index) if next_function_index else None
    first_line = section.line_numbers[0] if section.line_numbers else None
    begin_auxiliary = begin.auxiliary if begin is not None else b""
    next_tag_index = (
        int.from_bytes(next_function.auxiliary[0:4], "little")
        if next_function is not None and len(next_function.auxiliary) == 18
        else 0
    )
    if (
        symbol.value != 0
        or total_size != len(section.body)
        or not section.line_offset
        or line_pointer != section.line_offset
        or unused
        or begin is None
        or tag_index <= symbol.index
        or begin.name != ".bf"
        or begin.value != 0
        or begin.section != section.number
        or begin.symbol_type != 0
        or begin.storage != 101
        or begin.auxiliary_count != 1
        or len(begin_auxiliary) != 18
        or any(begin_auxiliary[0:4])
        or any(begin_auxiliary[6:12])
        or any(begin_auxiliary[16:18])
        or first_line is None
        or first_line.line_number != 0
        or first_line.target_index != symbol.index
        or first_line.target != symbol.name
        or first_line.target_section != section.number
        or first_line.target_value != symbol.value
        or first_line.target_type != symbol.symbol_type
        or first_line.target_storage != symbol.storage
        or next_function_index != (expected_next.index if expected_next is not None else 0)
        or int.from_bytes(begin_auxiliary[12:16], "little") != next_tag_index
        or (next_function is not None and next_tag_index <= next_function.index)
        or (
            next_function is not None
            and (
                next_function.value != 0
                or next_function.section <= 0
                or next_function.symbol_type != 0x20
                or next_function.storage != 2
                or next_function.auxiliary_count != 1
                or len(next_function.auxiliary) != 18
                or by_index.get(next_tag_index) is None
                or by_index[next_tag_index].name != ".bf"
            )
        )
    ):
        raise ClassicSemanticError(
            f"{coff.label} function provider {symbol.name!r} has an inexact auxiliary"
        )
    return {
        "kind": "msvc-function-definition",
        "tag_index": tag_index,
        "begin_source_line": int.from_bytes(begin_auxiliary[4:6], "little"),
        "total_size": total_size,
        "line_pointer": line_pointer,
        "line_zero_symbol_index": first_line.target_index,
        "next_function_index": next_function_index,
        "next_function_symbol": (next_function.name if next_function is not None else None),
    }


def _overlay_lane_input_is_authorized(
    owner: _OverlayOutputOwner,
    lane_target: str,
    *,
    certified_project_overlay: bool,
) -> bool:
    """Allow project-wide ordinary sources, but keep generated inputs private."""

    return owner.target_id == lane_target or (
        certified_project_overlay and not owner.generated_input
    )


def _archive_semantics(
    target: TargetLinkClosure,
    *,
    compiler_digests: frozenset[Digest],
    carrier_digests: frozenset[Digest],
    include_compiler_members: bool = False,
) -> tuple[
    list[_ArchiveCoffMember],
    list[ClassicImportObjectReceipt],
    list[dict[str, object]],
]:
    """Completely parse every raw archive and classify every non-linker member."""

    archives = _unique(target.archives, lambda item: item.archive_ref, "archive input")
    expected = {item.casefold() for item in target.archive_refs}
    if set(archives) != expected:
        missing = sorted(expected - set(archives))
        extra = sorted(set(archives) - expected)
        raise ClassicSemanticError(
            f"target {target.target_id!r} raw archive closure differs; "
            f"missing={missing}, extra={extra}"
        )
    objects: list[_ArchiveCoffMember] = []
    imports: list[ClassicImportObjectReceipt] = []
    traces: list[dict[str, object]] = []
    for archive_ref in target.archive_refs:
        raw_archive = archives[archive_ref.casefold()]
        if (
            not isinstance(raw_archive, ArchiveInput)
            or not isinstance(raw_archive.payload, bytes)
            or not raw_archive.payload
        ):
            raise ClassicSemanticError(f"archive {archive_ref!r} is not immutable bytes")
        try:
            parsed = parse_coff_archive(raw_archive.payload)
        except FormatError as exc:
            raise ClassicSemanticError(f"cannot parse archive {archive_ref!r}: {exc}") from exc
        ordinary_count = 0
        import_count = 0
        carrier_clone_count = 0
        compiler_clone_count = 0
        content_members = 0
        for index, member in enumerate(parsed.members):
            if member.name in {"/", "//", "/SYM64/"}:
                continue
            content_members += 1
            label = f"{archive_ref}({index}:{member.name})"
            digest = Digest.from_bytes(member.data)
            if digest in carrier_digests:
                carrier_clone_count += 1
                continue
            compiler_member = digest in compiler_digests
            if compiler_member:
                compiler_clone_count += 1
                if not include_compiler_members:
                    continue
            import_object = _parse_import_object(member.data, label)
            if import_object is not None:
                imports.append(import_object)
                import_count += 1
                continue
            objects.append(
                _ArchiveCoffMember(
                    archive_ref,
                    index,
                    member.name,
                    _parse_coff(
                        member.data,
                        label,
                        allow_archive_extensions=True,
                        allow_archive_auxless_section_anchors=True,
                    ),
                )
            )
            if not compiler_member:
                ordinary_count += 1
        if not content_members:
            raise ClassicSemanticError(f"archive {archive_ref!r} has no content members")
        if carrier_clone_count:
            raise ClassicSemanticError(
                f"archive {archive_ref!r} contains {carrier_clone_count} exact "
                "generated-carrier object clone(s)"
            )
        traces.append(
            {
                "archive_ref": archive_ref,
                "digest": Digest.from_bytes(raw_archive.payload).model_dump(mode="json"),
                "size": len(raw_archive.payload),
                "member_count": len(parsed.members),
                "content_member_count": content_members,
                "ordinary_coff_members": ordinary_count,
                "import_object_members": import_count,
                "carrier_object_clones": carrier_clone_count,
                "compiler_object_clones": compiler_clone_count,
            }
        )
    return objects, imports, traces


def _default_libraries(coff: _CoffObject) -> set[str]:
    for section in coff.sections:
        folded = section.name.casefold()
        if any(folded.startswith(prefix) for prefix in _FORBIDDEN_RUNTIME_SECTION_PREFIXES):
            raise ClassicSemanticError(
                f"carrier {coff.label!r} contains runtime-root section {section.name!r}"
            )
        if not any(folded.startswith(prefix) for prefix in _ADMITTED_SECTION_PREFIXES):
            raise ClassicSemanticError(
                f"carrier {coff.label!r} contains unknown section {section.name!r}"
            )
    directives = _coff_directive_receipt(coff)
    if (
        directives.include_symbols
        or directives.export_symbols
        or directives.merge_sections
        or directives.disallowed_libraries
    ):
        raise ClassicSemanticError(f"carrier {coff.label!r} contains a global linker control")
    return {item.casefold() for item in directives.default_libraries}


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


def overlay_semantic_run_binding(
    graph: ProducerGraphDocument, snapshot: OverlaySemanticSnapshot
) -> Digest:
    """Recompute the executor's immutable semantic-snapshot binding.

    This is ancestry integrity, not a logic theorem: it prevents a caller from
    swapping an OBJ, source epoch, or archive after the current-run receipts
    were sealed.  Logic equivalence is established separately by the source
    and COFF theorems.
    """

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "producer_graph": producer_graph_digest(graph).model_dump(mode="json"),
                "primary_sources": [
                    {
                        "path": item.path,
                        "digest": item.digest.model_dump(mode="json"),
                        "size": item.size,
                        "origin": item.origin.value,
                    }
                    for item in snapshot.primary_sources
                ],
                "compiler_products": [
                    {
                        "node": item.node_id,
                        "source_ref": item.source_ref,
                        "object_ref": item.object_ref,
                        "digest": Digest.from_bytes(item.payload).model_dump(mode="json"),
                        "size": len(item.payload),
                        "generated_inputs": list(item.generated_inputs),
                        "compiler_invocation": (
                            _compiler_epoch_wire(item.compiler_invocation)
                            if item.compiler_invocation is not None
                            else None
                        ),
                    }
                    for item in snapshot.compiler_products
                ],
                "project_source_pairs": [
                    {
                        "path": item.path,
                        "clean_digest": (
                            Digest.from_bytes(item.clean_payload).model_dump(mode="json")
                            if item.clean_payload is not None
                            else None
                        ),
                        "clean_size": (
                            len(item.clean_payload) if item.clean_payload is not None else None
                        ),
                        "effective_digest": Digest.from_bytes(item.effective_payload).model_dump(
                            mode="json"
                        ),
                        "effective_size": len(item.effective_payload),
                    }
                    for item in snapshot.project_source_pairs
                ],
                "counterfactual_compiler_audits": [
                    {
                        "node": item.node_id,
                        "source_ref": item.source_ref,
                        "object_ref": item.object_ref,
                        "digest": Digest.from_bytes(item.counterfactual_payload).model_dump(
                            mode="json"
                        ),
                        "size": len(item.counterfactual_payload),
                        "counterfactual_invocation": (
                            _compiler_epoch_wire(item.counterfactual_invocation)
                            if item.counterfactual_invocation is not None
                            else None
                        ),
                    }
                    for item in snapshot.counterfactual_compiler_audits
                ],
                "counterfactual_namespace_id": snapshot.counterfactual_namespace_id,
                "clean_source_inputs": [
                    {
                        "path": item.path,
                        "digest": Digest.from_bytes(item.payload).model_dump(mode="json"),
                        "size": len(item.payload),
                    }
                    for item in snapshot.clean_source_inputs
                ],
                "compiler_namespaces": [
                    {
                        "namespace_id": item.namespace_id,
                        "namespace_digest": item.namespace_digest.model_dump(mode="json"),
                        "input_evidence_kind": item.input_evidence_kind.value,
                        "members": [
                            _compiler_namespace_member_wire(member) for member in item.members
                        ],
                    }
                    for item in snapshot.compiler_namespaces
                ],
                "archives": [
                    {
                        "target": closure.target_id,
                        "values": [
                            {
                                "reference": archive.archive_ref,
                                "digest": Digest.from_bytes(archive.payload).model_dump(
                                    mode="json"
                                ),
                                "size": len(archive.payload),
                            }
                            for archive in closure.archives
                        ],
                    }
                    for closure in snapshot.link_closures
                ],
            }
        )
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


def prove_source_overlay_semantics(
    bundle: ProjectBundle,
    graph: ProducerGraphDocument,
    snapshot: OverlaySemanticSnapshot,
    *,
    semantic_contracts: Mapping[ClassicRecipeFamily, SemanticValidatorContract],
) -> OverlaySemanticValidation:
    """Prove every source-overlay intervention in one current-run snapshot.

    This function performs no I/O.  The classic executor must build the
    snapshot from immutable bytes while the private logical-path runtime is
    still sealed.
    """

    if graph.toolchain_lock_digest != toolchain_document_digest(bundle.toolchain_lock):
        raise ClassicSemanticError("producer graph differs from the locked toolchain identity")
    if snapshot.run_binding != overlay_semantic_run_binding(graph, snapshot):
        raise ClassicSemanticError("semantic snapshot differs from its run binding")

    overlays = _overlay_interventions(bundle)
    if not overlays:
        return OverlaySemanticValidation(MappingProxyType({}), MappingProxyType({}))
    manifest = bundle.source_manifest
    if manifest is None or not manifest.complete:
        raise ClassicSemanticError("source-overlay proof requires a complete source manifest")

    primary = _unique(snapshot.primary_sources, lambda item: item.path, "primary source")
    effective = _unique(snapshot.effective_outputs, lambda item: item.path, "effective output")
    products = _unique(snapshot.compiler_products, lambda item: item.node_id, "compiler product")
    closures = _unique(snapshot.link_closures, lambda item: item.target_id, "link closure")
    source_pairs = _unique(
        snapshot.project_source_pairs, lambda item: item.path, "project overlay source pair"
    )
    counterfactual_audits = _unique(
        snapshot.counterfactual_compiler_audits,
        lambda item: item.node_id,
        "declaration-counterfactual compiler audit",
    )
    manifest_by_path = {item.path.casefold(): item for item in manifest.entries}
    interventions = {item.id: item for item in bundle.interventions}
    certified_primary = any(
        item.origin is PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
        for item in snapshot.primary_sources
    )
    certified_evidence = bool(
        snapshot.project_source_pairs
        or snapshot.counterfactual_compiler_audits
        or snapshot.counterfactual_namespace_id is not None
        or snapshot.clean_source_inputs
        or snapshot.compiler_namespaces
    )
    if certified_primary != certified_evidence:
        raise ClassicSemanticError(
            "certified project-overlay origin and counterfactual evidence must appear together"
        )
    if certified_primary:
        if (
            not isinstance(snapshot.counterfactual_namespace_id, str)
            or not snapshot.counterfactual_namespace_id
        ):
            raise ClassicSemanticError(
                "certified project overlay lacks its counterfactual namespace identity"
            )
    elif snapshot.counterfactual_namespace_id is not None:
        raise ClassicSemanticError(
            "clean-primary overlay proof cannot name a counterfactual namespace"
        )

    graph_compilers = {node.id: node for node in graph.nodes if node.role is ProducerRole.COMPILER}
    if set(products) != {item.casefold() for item in graph_compilers}:
        raise ClassicSemanticError("compiler products do not exactly cover the producer graph")
    for raw_product in products.values():
        product = raw_product
        if not isinstance(product, CompilerProduct):
            raise AssertionError("compiler product index has an invalid value")
        source_ref, object_ref = _compiler_shape(graph_compilers[product.node_id])
        if product.source_ref != source_ref or product.object_ref != object_ref:
            raise ClassicSemanticError(
                f"compiler product {product.node_id!r} differs from committed graph paths"
            )
        if not product.payload:
            raise ClassicSemanticError(f"compiler product {product.node_id!r} is empty")

    all_output_paths: set[str] = set()
    all_generated_paths: set[str] = set()
    all_generated_inputs: set[str] = set()
    carrier_input_seals: dict[str, tuple[str, ...]] = {}
    output_owner: dict[str, _OverlayOutputOwner] = {}
    declaration_by_id: dict[
        str,
        tuple[
            dict[str, dict[str, object]],
            frozenset[str],
            frozenset[str],
        ],
    ] = {}
    for overlay in overlays:
        overlay_declaration = _overlay_declaration(overlay)
        declaration_by_id[overlay.id] = overlay_declaration
        paths, generated, generated_inputs = overlay_declaration
        overlap = {item.casefold() for item in paths} & {
            item.casefold() for item in all_output_paths
        }
        if overlap:
            raise ClassicSemanticError(f"overlay outputs overlap: {sorted(overlap)}")
        all_output_paths.update(paths)
        all_generated_paths.update(generated)
        all_generated_inputs.update(generated_inputs)
        generated_seal = tuple(sorted(generated_inputs, key=str.casefold))
        for carrier_path in generated:
            carrier_input_seals[carrier_path.casefold()] = generated_seal
        output_owner.update(
            {
                path.casefold(): _OverlayOutputOwner(
                    overlay.id,
                    overlay.scope.target,
                    path in generated_inputs,
                )
                for path in paths
            }
        )

    clean_sources: dict[str, CleanSourceInput] = {}
    semantic_clean_sources: dict[str, CleanSourceInput] = {}
    source_validation: _OverlaySourceValidation | None = None
    if certified_primary:
        if set(source_pairs) != {path.casefold() for path in all_output_paths}:
            missing = sorted({path.casefold() for path in all_output_paths} - set(source_pairs))
            extra = sorted(set(source_pairs) - {path.casefold() for path in all_output_paths})
            raise ClassicSemanticError(
                f"project overlay source-pair universe differs; missing={missing}, extra={extra}"
            )
        clean_sources = _clean_source_authority(bundle, snapshot)
        semantic_clean_sources = _compiler_semantic_sources(clean_sources)
        for overlay in overlays:
            outputs, _generated, generated_inputs = declaration_by_id[overlay.id]
            for path, declaration in outputs.items():
                raw_pair = source_pairs[path.casefold()]
                if not isinstance(raw_pair, ProjectOverlaySourcePair) or raw_pair.path != path:
                    raise ClassicSemanticError(f"project overlay source pair changed: {path!r}")
                if (
                    Digest.from_bytes(raw_pair.effective_payload).value != declaration["effective"]
                    or len(raw_pair.effective_payload) != declaration["size"]
                ):
                    raise ClassicSemanticError(
                        f"project overlay effective source changed: {path!r}"
                    )
                if path in generated_inputs:
                    if raw_pair.clean_payload is not None:
                        raise ClassicSemanticError(
                            f"generated overlay source has a clean preimage: {path!r}"
                        )
                else:
                    clean = clean_sources.get(path.casefold())
                    if (
                        clean is None
                        or raw_pair.clean_payload != clean.payload
                        or declaration.get("clean") != Digest.from_bytes(clean.payload).value
                    ):
                        raise ClassicSemanticError(
                            f"project overlay clean preimage changed: {path!r}"
                        )
        source_validation = _validate_project_overlay_sources(
            overlays=overlays,
            graph=graph,
            source_pairs={
                key: value
                for key, value in source_pairs.items()
                if isinstance(value, ProjectOverlaySourcePair)
            },
            clean_sources=semantic_clean_sources,
            declaration_by_id=declaration_by_id,
            secondary_reader_payloads=_compiler_namespace_toolchain_readers(
                bundle, snapshot.compiler_namespaces
            ),
        )
    elif (
        source_pairs
        or counterfactual_audits
        or snapshot.clean_source_inputs
        or snapshot.compiler_namespaces
    ):
        raise ClassicSemanticError(
            "clean-primary overlay proof cannot carry project-overlay epoch evidence"
        )

    expected_primary = set(manifest_by_path) | {item.casefold() for item in all_generated_inputs}
    if set(primary) != expected_primary:
        missing = sorted(expected_primary - set(primary))
        extra = sorted(set(primary) - expected_primary)
        raise ClassicSemanticError(
            f"primary source seat is not closed; missing={missing}, extra={extra}"
        )
    if set(effective) != {item.casefold() for item in all_output_paths}:
        raise ClassicSemanticError("effective output receipts do not exactly cover overlays")

    for folded, raw_receipt in primary.items():
        receipt = raw_receipt
        if not isinstance(receipt, SourceInputReceipt):
            raise AssertionError("primary source index has an invalid value")
        _relative(receipt.path, label="primary source path")
        if receipt.size < 0:
            raise ClassicSemanticError(f"primary source {receipt.path!r} has invalid size")
        manifest_entry = manifest_by_path.get(folded)
        declared_output = next(
            (
                declaration
                for outputs, _generated, _inputs in declaration_by_id.values()
                for path, declaration in outputs.items()
                if path.casefold() == folded
            ),
            None,
        )
        if manifest_entry is not None:
            if certified_primary and declared_output is not None:
                if (
                    receipt.origin is not PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
                    or receipt.digest.value != declared_output["effective"]
                    or receipt.size != declared_output["size"]
                ):
                    raise ClassicSemanticError(
                        f"primary source {receipt.path!r} is not a certified project overlay"
                    )
            elif receipt.origin is not PrimarySourceOrigin.CLEAN_MANIFEST or (
                receipt.digest != manifest_entry.digest or receipt.size != manifest_entry.size
            ):
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not the clean manifest input"
                )
        elif receipt.path in all_generated_paths:
            if receipt.origin is not PrimarySourceOrigin.GENERATED_CARRIER:
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not a generated carrier TU"
                )
        elif certified_primary and receipt.path in all_generated_inputs:
            if (
                receipt.origin is not PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
                or not isinstance(declared_output, dict)
                or receipt.digest.value != declared_output["effective"]
                or receipt.size != declared_output["size"]
            ):
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not a certified generated header"
                )
        elif receipt.path in all_generated_inputs:
            if receipt.origin is not PrimarySourceOrigin.GENERATED_CARRIER:
                raise ClassicSemanticError(
                    f"primary source {receipt.path!r} is not a generated carrier input"
                )
        else:
            raise ClassicSemanticError(
                f"primary source {receipt.path!r} is an unclassified effective input"
            )

    for overlay in overlays:
        outputs, _generated, generated_inputs = declaration_by_id[overlay.id]
        for path, output_declaration in outputs.items():
            effective_receipt = effective[path.casefold()]
            if (
                effective_receipt.digest.value != output_declaration["effective"]
                or effective_receipt.size != output_declaration["size"]
            ):
                raise ClassicSemanticError(f"effective overlay output changed: {path!r}")
            clean_value = output_declaration.get("clean")
            manifest_entry = manifest_by_path.get(path.casefold())
            if path in generated_inputs:
                primary_receipt = primary[path.casefold()]
                if not isinstance(primary_receipt, SourceInputReceipt):
                    raise AssertionError("carrier source index has an invalid value")
                expected_origin = (
                    PrimarySourceOrigin.GENERATED_CARRIER
                    if path in all_generated_paths
                    else PrimarySourceOrigin.CERTIFIED_PROJECT_OVERLAY
                    if certified_primary
                    else PrimarySourceOrigin.GENERATED_CARRIER
                )
                if (
                    primary_receipt.origin is not expected_origin
                    or primary_receipt.digest != effective_receipt.digest
                    or primary_receipt.size != effective_receipt.size
                ):
                    raise ClassicSemanticError(f"generated carrier changed: {path!r}")
            elif manifest_entry is None or clean_value != manifest_entry.digest.value:
                raise ClassicSemanticError(
                    f"ordinary overlay {path!r} lacks its exact clean manifest preimage"
                )

    compiler_by_source: dict[str, list[CompilerProduct]] = defaultdict(list)
    for raw_product in products.values():
        if not isinstance(raw_product, CompilerProduct):
            raise AssertionError("compiler product index has an invalid value")
        kind, relative = raw_product.source_ref.split("/", 1)
        if kind != "source":
            raise ClassicSemanticError(
                f"compiler {raw_product.node_id!r} reads a non-source primary input"
            )
        source_receipt = primary.get(relative.casefold())
        if source_receipt is None:
            raise ClassicSemanticError(
                f"compiler {raw_product.node_id!r} source is absent from primary seal"
            )
        normalized_generated_inputs = tuple(
            _relative(item, label="compiler generated-input path")
            for item in raw_product.generated_inputs
        )
        if normalized_generated_inputs != tuple(
            sorted(set(normalized_generated_inputs), key=str.casefold)
        ):
            raise ClassicSemanticError(
                f"compiler {raw_product.node_id!r} generated-input seal is not canonical"
            )
        expected_generated_inputs = carrier_input_seals.get(relative.casefold())
        if expected_generated_inputs is None:
            expected_generated_inputs = (
                tuple(sorted(source_validation.generated_headers, key=str.casefold))
                if source_validation is not None
                else ()
            )
        if normalized_generated_inputs != expected_generated_inputs:
            if relative.casefold() in carrier_input_seals:
                raise ClassicSemanticError(
                    f"carrier compiler {raw_product.node_id!r} lacks its exact generated epoch"
                )
            raise ClassicSemanticError(
                f"ordinary compiler {raw_product.node_id!r} has the wrong generated-header epoch"
            )
        compiler_by_source[relative.casefold()].append(raw_product)

    counterfactual_objects: dict[str, _CoffObject] = {}
    effective_objects: dict[str, _CoffObject] = {}
    helper_sections: dict[str, frozenset[int]] = {}
    crt_pull_dependencies: dict[str, tuple[_CrtPullLinkerDependency, ...]] = {}
    ordered_archive_seed_dependencies: dict[str, tuple[_OrderedArchiveSeedDependency, ...]] = {}
    compiler_audit_trace: list[dict[str, object]] = []
    compiler_namespace_trace: list[dict[str, object]] = []
    if source_validation is not None:
        (
            counterfactual_objects,
            effective_objects,
            helper_sections,
            crt_pull_dependencies,
            ordered_archive_seed_dependencies,
            compiler_audit_trace,
            compiler_namespace_trace,
        ) = _project_compiler_audit_trace(
            bundle=bundle,
            graph=graph,
            products={
                value.node_id.casefold(): value
                for value in products.values()
                if isinstance(value, CompilerProduct)
            },
            audits={
                value.node_id.casefold(): value
                for value in counterfactual_audits.values()
                if isinstance(value, ProjectOverlayCounterfactualAudit)
            },
            source_pairs={
                key: value
                for key, value in source_pairs.items()
                if isinstance(value, ProjectOverlaySourcePair)
            },
            clean_sources=clean_sources,
            generated_tus=frozenset(all_generated_paths),
            source_validation=source_validation,
            namespace_evidences=snapshot.compiler_namespaces,
            counterfactual_namespace_id=(
                snapshot.counterfactual_namespace_id
                if isinstance(snapshot.counterfactual_namespace_id, str)
                else ""
            ),
        )

    lanes_by_overlay: dict[
        str,
        list[tuple[DonorSemanticLane, tuple[EffectiveOverlayReceipt, ...]]],
    ] = defaultdict(list)
    for lane in snapshot.donor_lanes:
        if (
            tuple(
                sorted(
                    lane.overlay_inputs,
                    key=lambda item: (item.path.casefold(), item.digest.value),
                )
            )
            != lane.overlay_inputs
        ):
            raise ClassicSemanticError(
                f"donor lane {lane.donor_intervention_id!r} inputs are not canonical"
            )
        donor = interventions.get(lane.donor_intervention_id)
        consumer = interventions.get(lane.consumer_intervention_id)
        if not isinstance(donor, ClassicRecipeIntervention) or (
            donor.role is not ClassicRecipeRole.DONOR
        ):
            raise ClassicSemanticError(
                f"donor lane names invalid intervention {lane.donor_intervention_id!r}"
            )
        if not isinstance(consumer, ClassicRecipeIntervention) or (
            consumer.role is not ClassicRecipeRole.FUNCTION
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {lane.consumer_intervention_id!r} is invalid"
            )
        if donor.scope.target != lane.target_id or consumer.scope.target != lane.target_id:
            raise ClassicSemanticError("donor lane crosses target boundaries")
        raw_statement_consumer = lane.consumer_input_statement.get("intervention")
        if not isinstance(raw_statement_consumer, Mapping):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} statement omits its intervention"
            )
        try:
            statement_consumer = ClassicRecipeIntervention.model_validate_json(
                canonical_json(raw_statement_consumer)
            )
        except ValueError as exc:
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} intervention is malformed"
            ) from exc
        if statement_consumer != consumer or not _donor_input_is_authorized(
            donor,
            consumer,
            lane.consumer_input_statement,
            input_name=lane.input_name,
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} uses an unauthorized candidate input"
            )
        contract = semantic_contracts.get(consumer.family)
        if contract is None or not semantic_proof_matches(
            lane.semantic_proof, consumer.family, contract
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} lacks a registered semantic proof"
            )
        expected_input = Digest.from_bytes(canonical_json(lane.consumer_input_statement))
        expected_output = Digest.from_bytes(canonical_json(lane.consumer_output_statement))
        if lane.semantic_proof.input_statement_digest != expected_input or (
            lane.semantic_proof.output_statement_digest != expected_output
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} proof statements changed"
            )
        if (
            _statement_payload_digest(
                lane.consumer_input_statement,
                name=lane.input_name,
            )
            != lane.donor_object_digest
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} is not bound to its donor object"
            )
        if (
            _statement_named_digest(lane.consumer_input_statement, "seed", "digest")
            != lane.seed_object_digest
            or _statement_named_digest(lane.consumer_output_statement, "candidate", "digest")
            != lane.candidate_object_digest
        ):
            raise ClassicSemanticError(
                f"donor lane consumer {consumer.id!r} object lineage changed"
            )
        inputs_by_overlay: dict[str, list[EffectiveOverlayReceipt]] = defaultdict(list)
        for item in lane.overlay_inputs:
            lane_receipt = effective.get(item.path.casefold())
            if lane_receipt != item:
                raise ClassicSemanticError(
                    f"donor lane {donor.id!r} names an unsealed overlay input {item.path!r}"
                )
            owner = output_owner.get(item.path.casefold())
            if owner is None:
                raise ClassicSemanticError(
                    f"donor lane {donor.id!r} names an ownerless overlay input {item.path!r}"
                )
            if not _overlay_lane_input_is_authorized(
                owner,
                lane.target_id,
                certified_project_overlay=source_validation is not None,
            ):
                raise ClassicSemanticError(
                    f"donor lane {donor.id!r} consumes a cross-target "
                    "generated or uncertified overlay"
                )
            inputs_by_overlay[owner.intervention_id].append(item)
        for overlay_id, owned_inputs in inputs_by_overlay.items():
            lanes_by_overlay[overlay_id].append((lane, tuple(owned_inputs)))

    overlay_traces: dict[str, object] = {}
    proofs: dict[str, SemanticProof] = {}
    source_contract = _SourceOverlayContract()
    graph_linkers: dict[str, ProducerNode] = {
        node.target_id.casefold(): node
        for node in graph.nodes
        if node.role is ProducerRole.LINKER and node.target_id is not None
    }
    for overlay in overlays:
        outputs, generated, generated_inputs = declaration_by_id[overlay.id]
        closure_value = closures.get(overlay.scope.target.casefold())
        if not isinstance(closure_value, TargetLinkClosure):
            raise ClassicSemanticError(
                f"overlay target {overlay.scope.target!r} lacks a complete link closure"
            )
        graph_compiler_ids = _ancestor_compilers(graph, overlay.scope.target)
        if closure_value.compiler_node_ids != tuple(sorted(graph_compiler_ids, key=str.casefold)):
            raise ClassicSemanticError(
                f"target {overlay.scope.target!r} compiler closure differs from graph"
            )
        if closure_value.archive_refs != _graph_archives(graph, overlay.scope.target):
            raise ClassicSemanticError(
                f"target {overlay.scope.target!r} archive closure differs from graph"
            )
        terminal_linker = graph_linkers.get(overlay.scope.target.casefold())
        if terminal_linker is None:
            raise ClassicSemanticError(
                f"overlay target {overlay.scope.target!r} lacks its terminal linker"
            )
        carrier_node_ids: set[str] = set()
        carrier_generator_kinds: dict[str, tuple[str, ...]] = {}
        for path in generated:
            candidates = compiler_by_source.get(path.casefold(), [])
            if len(candidates) != 1:
                raise ClassicSemanticError(
                    f"generated carrier {path!r} has {len(candidates)} compiler products"
                )
            node_id = candidates[0].node_id
            carrier_node_ids.add(node_id)
            declaration = outputs[path]
            operations = declaration.get("ops")
            if not isinstance(operations, list):
                raise ClassicSemanticError(f"generated carrier {path!r} omits its operations")
            generator_kinds: list[str] = []
            for operation in operations:
                generator = operation.get("gen") if isinstance(operation, dict) else None
                generator_kind = generator.get("k") if isinstance(generator, dict) else None
                if not isinstance(generator_kind, str) or not generator_kind:
                    raise ClassicSemanticError(
                        f"generated carrier {path!r} has an unclassified generator"
                    )
                generator_kinds.append(generator_kind)
            carrier_generator_kinds[node_id] = tuple(generator_kinds)
        carrier_trace = _carrier_isolation_trace(
            target=closure_value,
            linker_arguments=terminal_linker.arguments,
            linker_inputs=linker_input_sequence(terminal_linker),
            linker_identity=issue_msvc420_linker_identity(bundle.toolchain_lock),
            products={
                key: value for key, value in products.items() if isinstance(value, CompilerProduct)
            },
            carrier_node_ids=frozenset(carrier_node_ids),
            carrier_generator_kinds=carrier_generator_kinds,
        )
        helper_trace = (
            _helper_isolation_trace(
                target=closure_value,
                linker_inputs=linker_input_sequence(terminal_linker),
                products={
                    value.node_id: value
                    for value in products.values()
                    if isinstance(value, CompilerProduct)
                },
                counterfactual_objects=counterfactual_objects,
                effective_objects=effective_objects,
                helper_sections=helper_sections,
                crt_pull_dependencies=crt_pull_dependencies,
                ordered_archive_seed_dependencies=ordered_archive_seed_dependencies,
            )
            if source_validation is not None
            else {
                "target": overlay.scope.target,
                "helper_objects": [],
                "unique_unreferenced_definitions": [],
                "crt_pull_archive_provider_candidates": [],
                "ordered_archive_seed_dependencies": [],
            }
        )
        lanes = sorted(
            lanes_by_overlay.get(overlay.id, []),
            key=lambda item: (
                item[0].target_id.casefold(),
                item[0].donor_intervention_id,
                item[0].consumer_intervention_id,
                item[0].input_name,
            ),
        )
        ordinary = set(outputs) - set(generated_inputs)
        used = {
            item.path
            for _lane, owned_inputs in lanes
            for item in owned_inputs
            if item.path in ordinary
        }
        # Ordinary outputs that do not enter any donor lane are harmlessly
        # discarded: the exact primary seat check above proves their effective
        # bytes are absent from every primary compiler input.
        discarded = [] if certified_primary else sorted(ordinary - used)
        trace = {
            "schema": 1,
            "run_binding": snapshot.run_binding.model_dump(mode="json"),
            "overlay_intervention": overlay.model_dump(mode="json"),
            "producer_graph_digest": producer_graph_digest(graph).model_dump(mode="json"),
            "primary_source_seal": [
                {
                    "path": item.path,
                    "digest": item.digest.model_dump(mode="json"),
                    "size": item.size,
                    "origin": item.origin.value,
                }
                for item in sorted(snapshot.primary_sources, key=lambda item: item.path.casefold())
            ],
            "effective_outputs": [
                {
                    "path": item.path,
                    "digest": item.digest.model_dump(mode="json"),
                    "size": item.size,
                    "disposition": (
                        "generated-carrier-tu"
                        if item.path in generated
                        else "certified-project-primary"
                        if certified_primary
                        else "generated-carrier-input"
                        if item.path in generated_inputs
                        else "certified-donor"
                        if item.path in used
                        else "discarded"
                    ),
                }
                for item in sorted(
                    (
                        value
                        for key, value in effective.items()
                        if key in {path.casefold() for path in outputs}
                        and isinstance(value, EffectiveOverlayReceipt)
                    ),
                    key=lambda item: item.path.casefold(),
                )
            ],
            "carrier_compile_epoch": {
                "generated_inputs": sorted(generated_inputs, key=str.casefold),
                "carrier_compilers": sorted(carrier_node_ids, key=str.casefold),
                "ordinary_generated_inputs": (
                    sorted(source_validation.generated_headers, key=str.casefold)
                    if source_validation is not None
                    else []
                ),
            },
            "project_overlay_epoch": {
                "enabled": source_validation is not None,
                "compiler_namespaces": compiler_namespace_trace,
                "compiler_audits": compiler_audit_trace,
                "source_validation": (
                    source_validation.traces.get(overlay.id)
                    if source_validation is not None
                    else None
                ),
            },
            "donor_lanes": [
                {
                    "target": lane.target_id,
                    "donor": lane.donor_intervention_id,
                    "consumer": lane.consumer_intervention_id,
                    "input_name": lane.input_name,
                    "overlay_inputs": [
                        {
                            "path": item.path,
                            "digest": item.digest.model_dump(mode="json"),
                            "size": item.size,
                        }
                        for item in owned_inputs
                    ],
                    "consumer_proof": lane.semantic_proof.evidence_digest.value,
                    "input_statement": lane.semantic_proof.input_statement_digest.value,
                }
                for lane, owned_inputs in lanes
            ],
            "discarded_outputs": discarded,
            "carrier_isolation": carrier_trace,
            "project_helper_isolation": helper_trace,
        }
        input_statement = {
            "schema": 1,
            "intervention": overlay.model_dump(mode="json"),
            "clean_manifest": {
                item.path: item.digest.model_dump(mode="json") for item in manifest.entries
            },
            "effective_outputs": {
                path: {
                    "digest": declaration["effective"],
                    "size": declaration["size"],
                }
                for path, declaration in outputs.items()
            },
        }
        proof = _issue_semantic_proof(
            family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
            contract=source_contract,
            input_statement=input_statement,
            output_statement=trace,
        )
        proofs[overlay.id] = proof
        overlay_traces[overlay.id] = trace
    return OverlaySemanticValidation(MappingProxyType(proofs), MappingProxyType(overlay_traces))


@dataclass(frozen=True, slots=True)
class _SourceOverlayContract:
    validator_id: str = SOURCE_OVERLAY_VALIDATOR_ID
    validator_digest: Digest = SOURCE_OVERLAY_VALIDATOR_DIGEST
    obligations: tuple[str, ...] = SOURCE_OVERLAY_OBLIGATIONS


__all__ = [
    "overlay_semantic_run_binding",
    "prove_source_overlay_semantics",
]
