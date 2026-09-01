"""Strict COFF projections: runtime projections, their theorem labels and certificate records."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field

from reprobit.classic.coff_evidence import (
    _CoffObject,
    _CoffRelocation,
    _CoffSection,
    _CoffSymbol,
)
from reprobit.classic.foundation import local_symbol_kind
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.strict_json import canonical_json

from .coff_projection_statements import _coff_header_statement

_FORBIDDEN_RUNTIME_SECTION_PREFIXES = (
    ".crt",
    ".edata",
    ".idata",
    ".rsrc",
    ".tls",
)


def _runtime_projection(
    coff: _CoffObject,
    *,
    excluded_sections: frozenset[int] = frozenset(),
    include_line_numbers: bool = False,
) -> dict[str, object]:
    runtime_sections = [
        section
        for section in coff.sections
        if not section.name.casefold().startswith(".debug")
        and section.number not in excluded_sections
    ]
    section_map = {section.number: index + 1 for index, section in enumerate(runtime_sections)}
    sections: list[dict[str, object]] = []
    for section in runtime_sections:
        associated = section.comdat_associated
        if associated and associated not in section_map:
            raise ClassicSemanticError(
                f"{coff.label} runtime section associates with omitted debug state"
            )
        relocations: list[dict[str, object]] = []
        for relocation in section.relocations:
            target_section = relocation.target_section
            if target_section > 0:
                if target_section not in section_map:
                    raise ClassicSemanticError(
                        f"{coff.label} runtime relocation targets debug state"
                    )
                target_section = section_map[target_section]
            relocations.append(
                {
                    "offset": relocation.offset,
                    "type": relocation.relocation_type,
                    "target": relocation.target,
                    "target_section": target_section,
                    "target_value": relocation.target_value,
                    "target_type": relocation.target_type,
                    "target_storage": relocation.target_storage,
                    "addend": relocation.addend.hex(),
                }
            )
        statement: dict[str, object] = {
            "name": section.name,
            "body": section.body.hex(),
            "characteristics": section.characteristics,
            "selection": section.comdat_selection,
            "associated": section_map.get(associated) if associated else None,
            "relocations": relocations,
        }
        if include_line_numbers:
            line_numbers: list[dict[str, object]] = []
            for line in section.line_numbers:
                if line.line_number:
                    line_numbers.append(
                        {
                            "line": line.line_number,
                            "address": line.address,
                        }
                    )
                    continue
                line_target_section = line.target_section
                if line_target_section is not None and line_target_section > 0:
                    if line_target_section not in section_map:
                        raise ClassicSemanticError(
                            f"{coff.label} line table targets omitted debug state"
                        )
                    line_target_section = section_map[line_target_section]
                line_numbers.append(
                    {
                        "line": 0,
                        "target": line.target,
                        "target_section": line_target_section,
                        "target_value": line.target_value,
                        "target_type": line.target_type,
                        "target_storage": line.target_storage,
                    }
                )
            statement["line_numbers"] = line_numbers
        sections.append(statement)
    referenced_undefined = {
        relocation.target
        for section in runtime_sections
        for relocation in section.relocations
        if relocation.target_section == 0
    }
    symbols = [
        {
            "name": symbol.name,
            "value": symbol.value,
            "section": section_map.get(symbol.section, symbol.section),
            "type": symbol.symbol_type,
            "storage": symbol.storage,
        }
        for symbol in coff.symbols
        if symbol.section < 0
        or (symbol.section == 0 and symbol.name in referenced_undefined)
        or (symbol.section in section_map and symbol.section not in excluded_sections)
    ]
    return {
        "coff_header": _coff_header_statement(coff),
        "sections": sections,
        "symbols": symbols,
    }


_EQUALITY_CMP_PROJECTION_THEOREM = "ia32-equality-compare-operand-reversal-flags-dead-v1"
_REGISTER_TRANSPOSITION_PROJECTION_THEOREM = "ia32-two-register-transposition-dead-boundaries-v1"
_COMPILER_LOCAL_ALPHA_PROJECTION_THEOREM = "compiler-local-symbol-alpha-equivalence-v1"
_DATA_COMDAT_PERMUTATION_PROJECTION_THEOREM = (
    "independent-relocation-free-data-comdat-permutation-v1"
)
_DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM = "dead-internal-rdata-prefix-carrier-reseat-v1"
_DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM = (
    "dead-internal-rdata-static-owner-permutation-alignment-repack-v1"
)
_DEAD_RDATA_REPACK_EQUALITY_COMPOSITION_THEOREM = (
    "dead-rdata-repack-plus-equality-cmp-composition-v1"
)


@dataclass(frozen=True, slots=True)
class _CodeProjectionCertificate:
    theorem: str
    digest: str
    covers_relocations: bool = False


@dataclass(frozen=True, slots=True)
class _DataProjectionCertificate:
    theorem: str
    digest: str
    object_digest: str


@dataclass(frozen=True, slots=True)
class _DataProjectionComponent:
    """One side-bound data theorem awaiting an explicit coordinator."""

    theorem: str
    clean_section_number: int
    effective_section_number: int
    certificate_digest: str
    proof: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _StaticDataOwnerImage:
    stable_name: str
    symbol: _CoffSymbol
    end: int
    image: bytes
    has_successor: bool


@dataclass(frozen=True, slots=True)
class _RuntimeProjectionEquivalence:
    equivalent: bool
    byte_equal: bool
    theorem: str | None
    clean_code_certificates: Mapping[int, _CodeProjectionCertificate]
    effective_code_certificates: Mapping[int, _CodeProjectionCertificate]
    proof: Mapping[str, object] | None
    clean_data_certificates: Mapping[int, _DataProjectionCertificate] = field(default_factory=dict)
    effective_data_certificates: Mapping[int, _DataProjectionCertificate] = field(
        default_factory=dict
    )


def _retained_runtime_sections(
    coff: _CoffObject, *, excluded_sections: frozenset[int] = frozenset()
) -> tuple[_CoffSection, ...]:
    return tuple(
        section
        for section in coff.sections
        if section.number not in excluded_sections
        and not section.name.casefold().startswith(".debug")
    )


def _relational_external_entries(
    coff: _CoffObject,
    primary: _CoffSection,
    *,
    excluded_sections: frozenset[int] = frozenset(),
) -> frozenset[int]:
    """Derive every retained-object entry into one code COMDAT.

    Entries are a caller-universe property, not an ownership-closure property:
    an unrelated retained section can hold a pointer or jump-table relocation
    to an interior label.  Such an entry must participate in CFG/liveness even
    when the referring section is not associative with the code COMDAT.
    """

    entries: set[int] = set()
    for section in coff.sections:
        if section.number in excluded_sections or section.name.casefold().startswith(".debug"):
            continue
        for relocation in section.relocations:
            if relocation.target_section != primary.number:
                continue
            # DIR32, DIR32NB, SECREL, and REL32 all retain a section-relative
            # symbol-plus-addend target.  SECTION (0x000a) denotes the section
            # ordinal itself and cannot encode an instruction entry.
            if relocation.relocation_type not in {6, 7, 11, 20}:
                continue
            addend = int.from_bytes(relocation.addend, "little", signed=True)
            target = relocation.target_value + addend
            if 0 < target < len(primary.body):
                entries.add(target)
    return frozenset(entries)


def _external_function_owner(coff: _CoffObject, section: _CoffSection) -> str | None:
    definitions = [
        symbol
        for symbol in coff.symbols
        if symbol.section == section.number and symbol.storage == 2
    ]
    if len(definitions) != 1 or definitions[0].value != 0 or definitions[0].symbol_type != 0x20:
        return None
    return definitions[0].name


def _runtime_projection_symbols(
    coff: _CoffObject,
    *,
    excluded_sections: frozenset[int],
) -> tuple[_CoffSymbol, ...]:
    retained = _retained_runtime_sections(coff, excluded_sections=excluded_sections)
    retained_numbers = {section.number for section in retained}
    referenced_undefined = {
        relocation.target
        for section in retained
        for relocation in section.relocations
        if relocation.target_section == 0
    }
    return tuple(
        symbol
        for symbol in coff.symbols
        if symbol.section < 0
        or (symbol.section == 0 and symbol.name in referenced_undefined)
        or symbol.section in retained_numbers
    )


def _copy_runtime_projection(value: Mapping[str, object]) -> dict[str, object] | None:
    raw_header = value.get("coff_header")
    raw_sections = value.get("sections")
    raw_symbols = value.get("symbols")
    if (
        not isinstance(raw_header, dict)
        or not isinstance(raw_sections, list)
        or not isinstance(raw_symbols, list)
    ):
        return None
    sections: list[dict[str, object]] = []
    for raw_section in raw_sections:
        if not isinstance(raw_section, dict):
            return None
        section = dict(raw_section)
        raw_relocations = section.get("relocations")
        if not isinstance(raw_relocations, list) or not all(
            isinstance(item, dict) for item in raw_relocations
        ):
            return None
        section["relocations"] = [dict(item) for item in raw_relocations]
        sections.append(section)
    if not all(isinstance(item, dict) for item in raw_symbols):
        return None
    return {
        "coff_header": dict(raw_header),
        "sections": sections,
        "symbols": [dict(item) for item in raw_symbols],
    }


def _alpha_normalized_runtime_projections(
    clean: _CoffObject,
    effective: _CoffObject,
    clean_projection: Mapping[str, object],
    effective_projection: Mapping[str, object],
    *,
    excluded_effective_sections: frozenset[int],
) -> tuple[dict[str, object], dict[str, object]] | None:
    """Derive a one-to-one rename for genuine defined compiler locals only.

    A rename seat is a paired static/label definition (COFF storage class 3
    or 6) with the same retained section, value, type, and auxiliary payload.
    Relocation targets are
    rewritten only when their exact symbol-table indexes resolve to that same
    paired seat.  Undefined and externally visible ``$L``/``$T`` lookalikes
    therefore remain literal and make the strict projections differ.
    """

    clean_copy = _copy_runtime_projection(clean_projection)
    effective_copy = _copy_runtime_projection(effective_projection)
    if clean_copy is None or effective_copy is None:
        return None
    clean_sections = _retained_runtime_sections(clean)
    effective_sections = _retained_runtime_sections(
        effective, excluded_sections=excluded_effective_sections
    )
    if len(clean_sections) != len(effective_sections):
        return None
    clean_section_map = {section.number: index + 1 for index, section in enumerate(clean_sections)}
    effective_section_map = {
        section.number: index + 1 for index, section in enumerate(effective_sections)
    }
    clean_symbols = _runtime_projection_symbols(clean, excluded_sections=frozenset())
    effective_symbols = _runtime_projection_symbols(
        effective, excluded_sections=excluded_effective_sections
    )
    clean_symbol_statements = clean_copy["symbols"]
    effective_symbol_statements = effective_copy["symbols"]
    if (
        not isinstance(clean_symbol_statements, list)
        or not isinstance(effective_symbol_statements, list)
        or len(clean_symbols) != len(effective_symbols)
        or len(clean_symbols) != len(clean_symbol_statements)
        or len(effective_symbols) != len(effective_symbol_statements)
    ):
        return None
    clean_name_counts: dict[str, int] = defaultdict(int)
    effective_name_counts: dict[str, int] = defaultdict(int)
    for symbol in clean_symbols:
        clean_name_counts[symbol.name] += 1
    for symbol in effective_symbols:
        effective_name_counts[symbol.name] += 1

    clean_renames: dict[int, tuple[int, dict[str, object]]] = {}
    effective_renames: dict[int, int] = {}
    clean_names: set[str] = set()
    effective_names: set[str] = set()
    for seat, (clean_symbol, effective_symbol) in enumerate(
        zip(clean_symbols, effective_symbols, strict=True)
    ):
        if clean_symbol.name == effective_symbol.name:
            continue
        clean_kind = local_symbol_kind(clean_symbol.name)
        effective_kind = local_symbol_kind(effective_symbol.name)
        if (
            clean_kind is None
            or clean_kind != effective_kind
            or clean_symbol.storage not in {3, 6}
            or effective_symbol.storage != clean_symbol.storage
            or clean_symbol.index != effective_symbol.index
            or clean_symbol.section <= 0
            or effective_symbol.section <= 0
            or clean_section_map.get(clean_symbol.section)
            != effective_section_map.get(effective_symbol.section)
            or clean_symbol.value != effective_symbol.value
            or clean_symbol.symbol_type != 0
            or clean_symbol.symbol_type != effective_symbol.symbol_type
            or clean_symbol.auxiliary_count != effective_symbol.auxiliary_count
            or clean_symbol.auxiliary != effective_symbol.auxiliary
            or clean_name_counts[clean_symbol.name] != 1
            or effective_name_counts[effective_symbol.name] != 1
            or clean_symbol.name in clean_names
            or effective_symbol.name in effective_names
        ):
            continue
        token: dict[str, object] = {
            "compiler_local_kind": clean_kind,
            "symbol_seat": seat,
        }
        clean_renames[clean_symbol.index] = (effective_symbol.index, token)
        effective_renames[effective_symbol.index] = clean_symbol.index
        clean_names.add(clean_symbol.name)
        effective_names.add(effective_symbol.name)
        clean_statement = clean_symbol_statements[seat]
        effective_statement = effective_symbol_statements[seat]
        if not isinstance(clean_statement, dict) or not isinstance(effective_statement, dict):
            return None
        clean_statement["name"] = token
        effective_statement["name"] = token

    clean_section_statements = clean_copy["sections"]
    effective_section_statements = effective_copy["sections"]
    if not isinstance(clean_section_statements, list) or not isinstance(
        effective_section_statements, list
    ):
        return None
    for clean_section, effective_section, clean_statement, effective_statement in zip(
        clean_sections,
        effective_sections,
        clean_section_statements,
        effective_section_statements,
        strict=True,
    ):
        if not isinstance(clean_statement, dict) or not isinstance(effective_statement, dict):
            return None
        clean_relocation_statements = clean_statement.get("relocations")
        effective_relocation_statements = effective_statement.get("relocations")
        if not isinstance(clean_relocation_statements, list) or not isinstance(
            effective_relocation_statements, list
        ):
            return None
        if (
            len(clean_section.relocations) != len(effective_section.relocations)
            or len(clean_section.relocations) != len(clean_relocation_statements)
            or len(effective_section.relocations) != len(effective_relocation_statements)
        ):
            continue
        for clean_relocation, effective_relocation, clean_raw, effective_raw in zip(
            clean_section.relocations,
            effective_section.relocations,
            clean_relocation_statements,
            effective_relocation_statements,
            strict=True,
        ):
            rename = clean_renames.get(clean_relocation.target_index)
            if rename is None:
                if effective_relocation.target_index in effective_renames:
                    return None
                continue
            expected_effective_index, token = rename
            if effective_relocation.target_index != expected_effective_index:
                return None
            if not isinstance(clean_raw, dict) or not isinstance(effective_raw, dict):
                return None
            clean_raw["target"] = token
            effective_raw["target"] = token
    return clean_copy, effective_copy


def _has_retained_relocation_touching(
    coff: _CoffObject,
    section: _CoffSection,
) -> bool:
    """Retained references include section-symbol-plus-addend forms."""

    return any(
        source.number == section.number or relocation.target_section == section.number
        for source in _retained_runtime_sections(coff)
        for relocation in source.relocations
    )


def _runtime_symbols_outside_section(
    coff: _CoffObject,
    section: _CoffSection,
) -> tuple[bytes, ...]:
    statements: list[bytes] = []
    for symbol in _runtime_projection_symbols(coff, excluded_sections=frozenset()):
        if symbol.section == section.number:
            continue
        statements.append(
            canonical_json(
                {
                    "name": symbol.name,
                    "value": symbol.value,
                    "section": symbol.section,
                    "type": symbol.symbol_type,
                    "storage": symbol.storage,
                }
            )
        )
    return tuple(statements)


def _relocation_target_offsets(relocation: _CoffRelocation) -> frozenset[int]:
    """Conservatively resolve in-section offsets named by one relocation."""

    values = {relocation.target_value}
    if relocation.relocation_type in {6, 7, 11, 20} and relocation.addend:
        unsigned = int.from_bytes(relocation.addend, "little", signed=False)
        signed = int.from_bytes(relocation.addend, "little", signed=True)
        values.add(relocation.target_value + unsigned)
        values.add(relocation.target_value + signed)
    return frozenset(value for value in values if value >= 0)


def _retained_relocation_entries_into(
    coff: _CoffObject,
    primary: _CoffSection,
    *,
    excluded_sections: frozenset[int] = frozenset(),
) -> frozenset[int]:
    """Resolve every retained relocation that can name the primary body."""

    return frozenset(
        target
        for section in _retained_runtime_sections(coff, excluded_sections=excluded_sections)
        for relocation in section.relocations
        if relocation.target_section == primary.number
        for target in _relocation_target_offsets(relocation)
        if target < len(primary.body)
    )
