"""Project-overlay ancestry proofs: archive members, default libraries and seed demand."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass

from reprobit.classic.coff_evidence import (
    ClassicImportObjectReceipt,
    _coff_directive_receipt,
    _CoffObject,
    _CoffRelocation,
    _CoffSection,
    _CoffSymbol,
    _parse_coff,
    _parse_import_object,
)
from reprobit.classic.coff_projection_runtime import _FORBIDDEN_RUNTIME_SECTION_PREFIXES
from reprobit.classic.semantic_contracts import (
    ArchiveInput,
    TargetLinkClosure,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.classic.source_overlay import (
    _unique,
)
from reprobit.formats import FormatError, parse_coff_archive
from reprobit.model import Digest

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
