"""Strict COFF projections and closed compiler-congruence proofs."""

from __future__ import annotations

import struct
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

from reprobit.binary import ByteIdentityError
from reprobit.classic.coff_evidence import (
    _coff_directive_receipt,
    _CoffObject,
    _CoffRelocation,
    _CoffSection,
    _CoffSymbol,
    _parse_coff,
)
from reprobit.classic.compiler_identity import Msvc420CompilerIdentity
from reprobit.classic.compiler_state_foundation import (
    CompilerStateCodePair,
    CompilerStateCompilerEvidence,
    CompilerStateDebugEvidence,
    CompilerStateFpoEvidence,
    CompilerStateProjection,
)
from reprobit.classic.compiler_state_projection import (
    derive_msvc420_compiler_state_projection,
)
from reprobit.classic.debug import local_symbol_kind
from reprobit.classic.register_bijection import apply_register_bijection
from reprobit.classic.register_semantics import (
    IA32_GENERAL_REGISTER_NAMES,
    decode_ia32_bijection_body,
)
from reprobit.classic.relational_projection import (
    derive_equality_compare_reversals,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.ia32 import supported_ia32_instruction_length
from reprobit.model import Digest
from reprobit.strict_json import canonical_json


class _SemanticCodePartitionError(ClassicSemanticError):
    """A ``.text`` payload has no closed IA-32 instruction partition."""


@dataclass(frozen=True, slots=True)
class ClassicLinkRelevantCoffProjection:
    """Exact link-relevant projection of one strict i386 COFF object.

    The projection omits only producer timestamps and sections whose names
    begin with ``.debug`` (including type-server records).  An external PDB is
    outside the COFF object and is therefore never an input to this function.
    Every remaining section byte, section characteristic and relative order,
    relocation, line-number record, COMDAT relation, linker directive, and
    external-linkage fact is retained in ``statement``.
    """

    object_digest: Digest
    projection_digest: Digest
    statement: Mapping[str, object]
    excluded_section_names: tuple[str, ...]
    normalizations: tuple[str, ...] = (
        "coff-time-date-stamp",
        "debug-section-bytes-relocations-and-symbols",
        "external-program-database",
    )


@dataclass(frozen=True, slots=True)
class ClassicCoffLineNumberDelta:
    """One ordinary retained-section COFF line-number value change."""

    section_index: int
    section_name: str
    record_index: int
    address: int
    baseline_line: int
    candidate_line: int


@dataclass(frozen=True, slots=True)
class ClassicCoffLineNumberCorrespondence:
    """Typed equality modulo ordinary COFF line-number metadata values.

    Both exact objects and both strict link-relevant projections remain bound.
    The shared invariant projection replaces only the nonzero 16-bit source
    line value of an ordinary line-table row.  Row count/order, row address,
    zero-line function targets, and every other retained projection field are
    exact.
    """

    baseline_object_digest: Digest
    baseline_size: int
    candidate_object_digest: Digest
    candidate_size: int
    baseline_projection_digest: Digest
    candidate_projection_digest: Digest
    invariant_projection_digest: Digest
    line_number_deltas: tuple[ClassicCoffLineNumberDelta, ...]
    statement_digest: Digest
    statement: Mapping[str, object]


_FORBIDDEN_RUNTIME_SECTION_PREFIXES = (
    ".crt",
    ".edata",
    ".idata",
    ".rsrc",
    ".tls",
)


@dataclass(frozen=True, slots=True)
class _CrtPullLinkerDependency:
    """One compiler-derived archive pull owned only by a dead ``crt_pull`` helper."""

    name: str
    symbol_type: int
    helper_sections: tuple[int, ...]
    relocation_sites: tuple[tuple[int, int, int, str], ...]


@dataclass(frozen=True, slots=True)
class _OrderedArchiveSeedDependency:
    """One exact undefined row in a typed MSVC 4.20 archive-order seed."""

    helper_identifier: str
    helper_symbol: str
    helper_section: int
    policy: str
    binding_kind: Literal["function-rel32", "data-dir32"]
    name: str
    symbol_type: int
    relocation_offset: int
    relocation_type: int
    addend: str
    first_use_ordinal: int
    undefined_symbol_index: int
    undefined_row_ordinal: int


_ORDERED_ARCHIVE_SEED_POLICY = "reverse_statement_order_msvc_4_20"


def _coff_header_statement(coff: _CoffObject) -> dict[str, object]:
    """Bind the parsed linker-relevant COFF file-header state once."""

    return {
        "machine": "i386",
        "characteristics": coff.header_characteristics,
    }


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


def _section_permutation_identity(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> bytes:
    """Bind one retained section independently of its raw section ordinal.

    Bodies and relocation seats remain byte-exact.  The existing topology and
    relocation statements normalize only genuine compiler-local definitions
    to their closed local kind; a separate one-to-one symbol-seat check below
    authenticates every such normalization.
    """

    return canonical_json(
        {
            "topology": _section_topology_statement(coff, section, symbols),
            "body": section.body.hex(),
            "relocations": [
                _relocation_statement(
                    coff,
                    relocation,
                    symbols,
                    include_offset=True,
                )
                for relocation in section.relocations
            ],
        }
    )


def _independent_relocation_free_data_comdat(
    coff: _CoffObject,
    section: _CoffSection,
) -> bool:
    """Recognize the deliberately tiny section-order theorem domain."""

    associated_parents = {
        item.comdat_associated for item in coff.sections if item.comdat_associated not in {None, 0}
    }
    return (
        section.name.casefold() in {".data", ".rdata"}
        and section.comdat_selection in {1, 2, 3, 4, 6, 7}
        and section.comdat_associated in {None, 0}
        and section.number not in associated_parents
        and bool(section.characteristics & 0x00001000)
        and bool(section.characteristics & 0x00000040)
        and not bool(section.characteristics & 0x00000080)
        and not section.relocations
    )


def _compiler_local_permutation_alpha_proof(
    clean: _CoffObject,
    effective: _CoffObject,
    section_pairs: Sequence[tuple[_CoffSection, _CoffSection]],
    *,
    excluded_effective_sections: frozenset[int],
) -> list[dict[str, object]] | None:
    """Authenticate compiler-local names at their exact raw symbol seats."""

    clean_locals = {
        symbol.index: symbol
        for symbol in _runtime_projection_symbols(clean, excluded_sections=frozenset())
        if _compiler_local_definition_kind(symbol) is not None
    }
    effective_locals = {
        symbol.index: symbol
        for symbol in _runtime_projection_symbols(
            effective,
            excluded_sections=excluded_effective_sections,
        )
        if _compiler_local_definition_kind(symbol) is not None
    }
    if set(clean_locals) != set(effective_locals):
        return None
    section_map = {
        clean_section.number: effective_section.number
        for clean_section, effective_section in section_pairs
    }
    clean_name_counts: dict[str, int] = defaultdict(int)
    effective_name_counts: dict[str, int] = defaultdict(int)
    for symbol in clean_locals.values():
        clean_name_counts[symbol.name] += 1
    for symbol in effective_locals.values():
        effective_name_counts[symbol.name] += 1

    renames: list[dict[str, object]] = []
    for index in sorted(clean_locals):
        clean_symbol = clean_locals[index]
        effective_symbol = effective_locals[index]
        clean_kind = _compiler_local_definition_kind(clean_symbol)
        effective_kind = _compiler_local_definition_kind(effective_symbol)
        if (
            clean_kind is None
            or effective_kind != clean_kind
            or section_map.get(clean_symbol.section) != effective_symbol.section
            or clean_symbol.value != effective_symbol.value
            or clean_symbol.symbol_type != effective_symbol.symbol_type
            or clean_symbol.storage != effective_symbol.storage
            or clean_symbol.auxiliary_count != effective_symbol.auxiliary_count
            or clean_symbol.auxiliary != effective_symbol.auxiliary
        ):
            return None
        if clean_symbol.name == effective_symbol.name:
            continue
        if (
            clean_name_counts[clean_symbol.name] != 1
            or effective_name_counts[effective_symbol.name] != 1
        ):
            return None
        renames.append(
            {
                "symbol_index": index,
                "compiler_local_kind": clean_kind,
                "clean_section": clean_symbol.section,
                "effective_section": effective_symbol.section,
                "value": clean_symbol.value,
            }
        )

    for clean_section, effective_section in section_pairs:
        if len(clean_section.relocations) != len(effective_section.relocations):
            return None
        for clean_relocation, effective_relocation in zip(
            clean_section.relocations,
            effective_section.relocations,
            strict=True,
        ):
            clean_is_local = clean_relocation.target_index in clean_locals
            effective_is_local = effective_relocation.target_index in effective_locals
            if (clean_is_local or effective_is_local) and (
                not clean_is_local
                or not effective_is_local
                or clean_relocation.target_index != effective_relocation.target_index
            ):
                return None
    return renames


def _data_comdat_permutation_proof(
    clean: _CoffObject,
    effective: _CoffObject,
    *,
    excluded_effective_sections: frozenset[int],
) -> Mapping[str, object] | None:
    """Prove only an adjacent-run permutation of independent data COMDATs.

    This is intentionally not the broad COFF-envelope fallback.  Every
    retained section has an exact body and exact relocation-seat identity;
    every order-changing seat is a relocation-free, non-associative .data or
    .rdata COMDAT and cannot cross any other kind of section.
    """

    if clean.header_characteristics != effective.header_characteristics:
        return None
    clean_sections = _retained_runtime_sections(clean)
    effective_sections = _retained_runtime_sections(
        effective,
        excluded_sections=excluded_effective_sections,
    )
    if len(clean_sections) != len(effective_sections):
        return None
    clean_symbols = _symbols_by_section(clean)
    effective_symbols = _symbols_by_section(effective)
    try:
        clean_identities = [
            _section_permutation_identity(clean, section, clean_symbols)
            for section in clean_sections
        ]
        effective_identities = [
            _section_permutation_identity(effective, section, effective_symbols)
            for section in effective_sections
        ]
        clean_envelope = _coff_semantic_envelope(clean)
        effective_envelope = _coff_semantic_envelope(
            effective,
            excluded_sections=excluded_effective_sections,
        )
    except ClassicSemanticError:
        return None
    if clean_envelope["statement"] != effective_envelope["statement"]:
        return None

    available: dict[bytes, list[int]] = defaultdict(list)
    for index, identity in enumerate(effective_identities):
        available[identity].append(index)
    mapping: dict[int, int] = {}
    # Preserve identical seats first so duplicate indistinguishable COMDATs do
    # not manufacture a permutation where none is observable.
    for index, identity in enumerate(clean_identities):
        if effective_identities[index] == identity:
            mapping[index] = index
            available[identity].remove(index)
    for index, identity in enumerate(clean_identities):
        if index in mapping:
            continue
        candidates = available.get(identity)
        if not candidates:
            return None
        mapping[index] = candidates.pop(0)
    if any(candidates for candidates in available.values()):
        return None
    moved = {index for index, target in mapping.items() if index != target}
    if not moved:
        return None
    for index in moved:
        target = mapping[index]
        if not _independent_relocation_free_data_comdat(
            clean, clean_sections[index]
        ) or not _independent_relocation_free_data_comdat(effective, effective_sections[target]):
            return None
        start, end = sorted((index, target))
        if any(
            not _independent_relocation_free_data_comdat(clean, clean_sections[seat])
            or not _independent_relocation_free_data_comdat(effective, effective_sections[seat])
            for seat in range(start, end + 1)
        ):
            return None

    section_pairs = tuple(
        (clean_sections[index], effective_sections[mapping[index]])
        for index in range(len(clean_sections))
    )
    alpha_renames = _compiler_local_permutation_alpha_proof(
        clean,
        effective,
        section_pairs,
        excluded_effective_sections=excluded_effective_sections,
    )
    if alpha_renames is None:
        return None
    envelope_digest = clean_envelope["digest"]
    if not isinstance(envelope_digest, Digest):
        raise AssertionError("COFF semantic envelope digest is malformed")
    permutations = [
        {
            "clean_section": clean_sections[index].number,
            "effective_section": effective_sections[mapping[index]].number,
            "name": clean_sections[index].name,
            "body_digest": Digest.from_bytes(clean_sections[index].body).model_dump(mode="json"),
        }
        for index in sorted(moved)
    ]
    return MappingProxyType(
        {
            "theorem": _DATA_COMDAT_PERMUTATION_PROJECTION_THEOREM,
            "clean_object": clean.digest.model_dump(mode="json"),
            "effective_object": effective.digest.model_dump(mode="json"),
            "shared_semantic_envelope_digest": envelope_digest.model_dump(mode="json"),
            "permutations": permutations,
            "compiler_local_renames": alpha_renames,
            "preserved": [
                "all-retained-section-bodies-and-relocation-seats",
                "all-code-and-compiler-control-bodies",
                "external-common-weak-and-absolute-linkage",
                "linker-directives",
                "comdat-selection-and-association",
                "one-to-one-compiler-local-symbol-seats",
                "relative-order-outside-independent-data-comdat-runs",
            ],
        }
    )


def _msvc_static_serial_stem(name: str) -> str | None:
    """Return the stable part of one MSVC ``name$S<digits>`` static."""

    marker = name.rfind("$S")
    if marker <= 0 or not name[marker + 2 :].isdigit():
        return None
    return name[:marker]


def _ordinary_readonly_rdata_section(coff: _CoffObject, section: _CoffSection) -> bool:
    associated_parents = {
        item.comdat_associated for item in coff.sections if item.comdat_associated not in {None, 0}
    }
    characteristics = section.characteristics
    return (
        section.name.casefold() == ".rdata"
        and section.comdat_selection in {None, 0}
        and section.comdat_associated in {None, 0}
        and section.number not in associated_parents
        and bool(characteristics & 0x00000040)  # initialized data
        and not bool(characteristics & 0x00000020)  # code
        and not bool(characteristics & 0x00000080)  # uninitialized data
        and not bool(characteristics & 0x00001000)  # COMDAT
        and bool(characteristics & 0x40000000)  # readable
        and not bool(characteristics & 0x20000000)  # executable
        and not bool(characteristics & 0x80000000)  # writable
        and not section.line_numbers
        and not section.relocations
    )


def _closed_static_data_owners(
    coff: _CoffObject,
    section: _CoffSection,
) -> tuple[_CoffSymbol, tuple[_CoffSymbol, ...]] | None:
    definitions = tuple(symbol for symbol in coff.symbols if symbol.section == section.number)
    section_candidates = tuple(
        symbol for symbol in definitions if symbol.storage == 3 and symbol.name == section.name
    )
    if len(section_candidates) != 1 or not _is_section_symbol(section_candidates[0], section):
        return None
    section_symbol = section_candidates[0]
    owners = tuple(
        sorted(
            (symbol for symbol in definitions if symbol is not section_symbol),
            key=lambda symbol: symbol.value,
        )
    )
    if (
        not owners
        or owners[0].value != 0
        or len({owner.value for owner in owners}) != len(owners)
        or len({owner.name for owner in owners}) != len(owners)
        or any(
            owner.storage != 3
            or owner.symbol_type != 0
            or owner.auxiliary_count
            or owner.auxiliary
            or not 0 <= owner.value < len(section.body)
            for owner in owners
        )
    ):
        return None
    return section_symbol, owners


def _coff_section_alignment(characteristics: int) -> int | None:
    """Decode the closed COFF object alignment field."""

    encoded = (characteristics & 0x00F00000) >> 20
    if not 1 <= encoded <= 14:
        return None
    return 1 << (encoded - 1)


def _static_data_owner_images(
    section: _CoffSection,
    owners: Sequence[_CoffSymbol],
) -> tuple[tuple[str, ...], Mapping[str, _StaticDataOwnerImage]] | None:
    order: list[str] = []
    images: dict[str, _StaticDataOwnerImage] = {}
    for ordinal, owner in enumerate(owners):
        stable_name = _msvc_static_serial_stem(owner.name)
        if stable_name is None or stable_name in images:
            return None
        end = owners[ordinal + 1].value if ordinal + 1 < len(owners) else len(section.body)
        if not owner.value < end <= len(section.body):
            return None
        order.append(stable_name)
        images[stable_name] = _StaticDataOwnerImage(
            stable_name=stable_name,
            symbol=owner,
            end=end,
            image=section.body[owner.value : end],
            has_successor=ordinal + 1 < len(owners),
        )
    return tuple(order), MappingProxyType(images)


def _paired_static_owner_image_proof(
    clean: _StaticDataOwnerImage,
    effective: _StaticDataOwnerImage,
    *,
    alignment: int,
) -> dict[str, object] | None:
    if clean.stable_name != effective.stable_name:
        return None
    clean_tail = b""
    effective_tail = b""
    if clean.image == effective.image:
        core = clean.image
    else:
        if len(clean.image) == len(effective.image):
            return None
        shorter, longer = (
            (clean, effective) if len(clean.image) < len(effective.image) else (effective, clean)
        )
        core = shorter.image
        if not core or not longer.image.startswith(core):
            return None
        tail = longer.image[len(core) :]
        expected_tail = (-(longer.symbol.value + len(core))) % alignment
        if (
            not tail
            or len(tail) >= alignment
            or tail != bytes(len(tail))
            or not longer.has_successor
            or longer.end % alignment
            or len(tail) != expected_tail
        ):
            return None
        if longer is clean:
            clean_tail = tail
        else:
            effective_tail = tail
    return {
        "stable_name": clean.stable_name,
        "core_size": len(core),
        "core_digest": Digest.from_bytes(core).model_dump(mode="json"),
        "clean": {
            "name": clean.symbol.name,
            "symbol_index": clean.symbol.index,
            "offset": clean.symbol.value,
            "extent": len(clean.image),
            "alignment_tail_size": len(clean_tail),
        },
        "effective": {
            "name": effective.symbol.name,
            "symbol_index": effective.symbol.index,
            "offset": effective.symbol.value,
            "extent": len(effective.image),
            "alignment_tail_size": len(effective_tail),
        },
        "serial_alpha_renamed": clean.symbol.name != effective.symbol.name,
    }


def _dead_internal_rdata_repack_component(
    clean: _CoffObject,
    effective: _CoffObject,
    *,
    excluded_effective_sections: frozenset[int],
) -> _DataProjectionComponent | None:
    """Derive one dead static-owner permutation with exact alignment repacking."""

    if (
        excluded_effective_sections
        or clean.header_characteristics != effective.header_characteristics
    ):
        return None
    clean_sections = _retained_runtime_sections(clean)
    effective_sections = _retained_runtime_sections(effective)
    if len(clean_sections) != len(effective_sections):
        return None
    if any(
        clean_section.number != effective_section.number
        for clean_section, effective_section in zip(clean_sections, effective_sections, strict=True)
    ):
        return None
    try:
        directives = (_coff_directive_receipt(clean), _coff_directive_receipt(effective))
    except ClassicSemanticError:
        return None
    if any(
        ".rdata" in {source.casefold(), target.casefold()}
        for receipt in directives
        for source, target in receipt.merge_sections
    ):
        return None

    candidates: list[_DataProjectionComponent] = []
    for clean_section, effective_section in zip(clean_sections, effective_sections, strict=True):
        if clean_section.name.casefold() != ".rdata":
            continue
        if (
            clean_section.name != effective_section.name
            or clean_section.characteristics != effective_section.characteristics
            or clean_section.comdat_selection != effective_section.comdat_selection
            or clean_section.comdat_associated != effective_section.comdat_associated
            or not _ordinary_readonly_rdata_section(clean, clean_section)
            or not _ordinary_readonly_rdata_section(effective, effective_section)
            or _has_retained_relocation_touching(clean, clean_section)
            or _has_retained_relocation_touching(effective, effective_section)
        ):
            continue
        alignment = _coff_section_alignment(clean_section.characteristics)
        if alignment is None:
            continue
        clean_ownership = _closed_static_data_owners(clean, clean_section)
        effective_ownership = _closed_static_data_owners(effective, effective_section)
        if clean_ownership is None or effective_ownership is None:
            continue
        clean_section_symbol, clean_owners = clean_ownership
        effective_section_symbol, effective_owners = effective_ownership
        if (
            clean_section_symbol.auxiliary[4:] != effective_section_symbol.auxiliary[4:]
            or len(clean_owners) != len(effective_owners)
            or len(clean_owners) < 2
        ):
            continue
        clean_images = _static_data_owner_images(clean_section, clean_owners)
        effective_images = _static_data_owner_images(effective_section, effective_owners)
        if clean_images is None or effective_images is None:
            continue
        clean_order, clean_by_name = clean_images
        effective_order, effective_by_name = effective_images
        if clean_order == effective_order or set(clean_order) != set(effective_order):
            continue
        owner_proofs: list[dict[str, object]] = []
        for stable_name in sorted(clean_by_name):
            owner_proof = _paired_static_owner_image_proof(
                clean_by_name[stable_name],
                effective_by_name[stable_name],
                alignment=alignment,
            )
            if owner_proof is None:
                break
            owner_proofs.append(owner_proof)
        else:
            proof: dict[str, object] = {
                "theorem": _DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM,
                "clean_object": clean.digest.model_dump(mode="json"),
                "effective_object": effective.digest.model_dump(mode="json"),
                "clean_section_number": clean_section.number,
                "effective_section_number": effective_section.number,
                "section": clean_section.name,
                "characteristics": clean_section.characteristics,
                "alignment": alignment,
                "clean_size": len(clean_section.body),
                "effective_size": len(effective_section.body),
                "section_definition": {
                    "clean_length": int.from_bytes(clean_section_symbol.auxiliary[:4], "little"),
                    "effective_length": int.from_bytes(
                        effective_section_symbol.auxiliary[:4], "little"
                    ),
                    "shared_non_length_auxiliary": clean_section_symbol.auxiliary[4:].hex(),
                },
                "clean_order": list(clean_order),
                "effective_order": list(effective_order),
                "owners": owner_proofs,
                "preserved": [
                    "one-to-one-internal-static-owner-stem-bijection",
                    "exact-shorter-owner-core-images",
                    "only-zero-minimal-successor-alignment-tails",
                    "zero-retained-inbound-and-outbound-relocations",
                    "ordinary-readonly-non-comdat-unmerged-rdata",
                ],
            }
            certificate_digest = Digest.from_bytes(canonical_json(proof)).value
            candidates.append(
                _DataProjectionComponent(
                    theorem=_DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM,
                    clean_section_number=clean_section.number,
                    effective_section_number=effective_section.number,
                    certificate_digest=certificate_digest,
                    proof=MappingProxyType(proof),
                )
            )
    if len(candidates) != 1:
        return None
    return candidates[0]


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


def _unique_subsequence_offset(haystack: bytes, needle: bytes) -> int | None:
    if not needle or len(needle) >= len(haystack):
        return None
    offsets: list[int] = []
    cursor = 0
    while True:
        offset = haystack.find(needle, cursor)
        if offset < 0:
            break
        offsets.append(offset)
        if len(offsets) > 1:
            return None
        cursor = offset + 1
    return offsets[0] if len(offsets) == 1 else None


def _dead_internal_rdata_prefix_projection(
    clean: _CoffObject,
    effective: _CoffObject,
    *,
    excluded_effective_sections: frozenset[int],
) -> _RuntimeProjectionEquivalence | None:
    """Prove one dead MSVC static prefix and exact clean-data reseating.

    Version one deliberately matches the narrow legacy case.  It does not
    admit suffixes, interior insertions, writable data, COMDATs, associations,
    helper-section composition, or any retained relocation into or out of the
    carrier section.
    """

    if (
        excluded_effective_sections
        or clean.header_characteristics != effective.header_characteristics
    ):
        return None
    clean_sections = _retained_runtime_sections(clean)
    effective_sections = _retained_runtime_sections(effective)
    if len(clean_sections) != len(effective_sections):
        return None
    clean_symbols = _symbols_by_section(clean)
    effective_symbols = _symbols_by_section(effective)
    changed: list[tuple[_CoffSection, _CoffSection]] = []
    try:
        for clean_section, effective_section in zip(
            clean_sections, effective_sections, strict=True
        ):
            if clean_section.number != effective_section.number:
                return None
            if _section_permutation_identity(
                clean, clean_section, clean_symbols
            ) != _section_permutation_identity(effective, effective_section, effective_symbols):
                changed.append((clean_section, effective_section))
        clean_directives = _coff_directive_receipt(clean)
        effective_directives = _coff_directive_receipt(effective)
        rdata_is_merged = any(
            ".rdata" in {source.casefold(), target.casefold()}
            for receipt in (clean_directives, effective_directives)
            for source, target in receipt.merge_sections
        )
        if (
            len(changed) != 1
            or _linkage_statement(clean, excluded_sections=frozenset())
            != _linkage_statement(effective, excluded_sections=frozenset())
            or clean_directives != effective_directives
            or rdata_is_merged
        ):
            return None
    except ClassicSemanticError:
        return None

    clean_section, effective_section = changed[0]
    if (
        clean_section.name != effective_section.name
        or clean_section.characteristics != effective_section.characteristics
        or clean_section.comdat_selection != effective_section.comdat_selection
        or clean_section.comdat_associated != effective_section.comdat_associated
        or not _ordinary_readonly_rdata_section(clean, clean_section)
        or not _ordinary_readonly_rdata_section(effective, effective_section)
        or _has_retained_relocation_touching(clean, clean_section)
        or _has_retained_relocation_touching(effective, effective_section)
        or _runtime_symbols_outside_section(clean, clean_section)
        != _runtime_symbols_outside_section(effective, effective_section)
    ):
        return None

    clean_ownership = _closed_static_data_owners(clean, clean_section)
    effective_ownership = _closed_static_data_owners(effective, effective_section)
    if clean_ownership is None or effective_ownership is None:
        return None
    clean_section_symbol, clean_owners = clean_ownership
    effective_section_symbol, effective_owners = effective_ownership
    if (
        clean_section_symbol.auxiliary[4:] != effective_section_symbol.auxiliary[4:]
        or len(effective_owners) != len(clean_owners) + 1
    ):
        return None

    added_owner = effective_owners[0]
    retained_owners = effective_owners[1:]
    prefix_size = retained_owners[0].value
    if (
        added_owner.value != 0
        or _msvc_static_serial_stem(added_owner.name) is None
        or prefix_size <= 0
        or prefix_size + len(clean_section.body) != len(effective_section.body)
        or effective_section.body[prefix_size:] != clean_section.body
        or _unique_subsequence_offset(effective_section.body, clean_section.body) != prefix_size
    ):
        return None

    retained_owner_proof: list[dict[str, object]] = []
    for clean_owner, effective_owner in zip(clean_owners, retained_owners, strict=True):
        names_match = clean_owner.name == effective_owner.name
        clean_stem = _msvc_static_serial_stem(clean_owner.name)
        effective_stem = _msvc_static_serial_stem(effective_owner.name)
        if (
            effective_owner.value != clean_owner.value + prefix_size
            or effective_owner.symbol_type != clean_owner.symbol_type
            or effective_owner.storage != clean_owner.storage
            or effective_owner.auxiliary_count != clean_owner.auxiliary_count
            or effective_owner.auxiliary != clean_owner.auxiliary
            or (not names_match and (clean_stem is None or effective_stem != clean_stem))
        ):
            return None
        retained_owner_proof.append(
            {
                "clean_name": clean_owner.name,
                "effective_name": effective_owner.name,
                "clean_offset": clean_owner.value,
                "effective_offset": effective_owner.value,
                "serial_alpha_renamed": not names_match,
            }
        )

    proof: dict[str, object] = {
        "theorem": _DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM,
        "clean_object": clean.digest.model_dump(mode="json"),
        "effective_object": effective.digest.model_dump(mode="json"),
        "clean_section_number": clean_section.number,
        "effective_section_number": effective_section.number,
        "section": clean_section.name,
        "characteristics": clean_section.characteristics,
        "section_definition": {
            "clean_length": int.from_bytes(clean_section_symbol.auxiliary[:4], "little"),
            "effective_length": int.from_bytes(effective_section_symbol.auxiliary[:4], "little"),
            "shared_non_length_auxiliary": clean_section_symbol.auxiliary[4:].hex(),
        },
        "prefix_size": prefix_size,
        "prefix_digest": Digest.from_bytes(effective_section.body[:prefix_size]).model_dump(
            mode="json"
        ),
        "clean_data_digest": Digest.from_bytes(clean_section.body).model_dump(mode="json"),
        "added_owner": {
            "name": added_owner.name,
            "offset": added_owner.value,
            "size": prefix_size,
            "storage": added_owner.storage,
            "type": added_owner.symbol_type,
        },
        "retained_owners": retained_owner_proof,
        "preserved": [
            "complete-clean-rdata-body-as-one-unique-suffix",
            "one-static-prefix-owner",
            "exact-retained-owner-bijection-and-offset-rebase",
            "zero-retained-inbound-and-outbound-relocations",
            "all-other-retained-section-bodies-topology-and-relocations",
            "external-common-weak-and-absolute-linkage",
            "linker-directives",
            "comdat-selection-and-association",
            "startup-crt-tls-and-runtime-root-sections",
        ],
    }
    certificate_digest = Digest.from_bytes(canonical_json(proof)).value
    clean_certificate = _DataProjectionCertificate(
        _DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM,
        certificate_digest,
        clean.digest.value,
    )
    effective_certificate = _DataProjectionCertificate(
        _DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM,
        certificate_digest,
        effective.digest.value,
    )
    return _RuntimeProjectionEquivalence(
        equivalent=True,
        byte_equal=False,
        theorem=_DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM,
        clean_code_certificates={},
        effective_code_certificates={},
        proof=MappingProxyType(proof),
        clean_data_certificates=MappingProxyType({clean_section.number: clean_certificate}),
        effective_data_certificates=MappingProxyType(
            {effective_section.number: effective_certificate}
        ),
    )


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


def _derive_equality_cmp_sites(
    clean: _CoffObject,
    clean_section: _CoffSection,
    effective_section: _CoffSection,
) -> tuple[list[dict[str, object]], dict[str, object]] | None:
    """Prove one exact code-body delta with the classic relational engine.

    Candidate sites are derived from the two object bodies.  This adapter is
    deliberately narrower than the underlying relational certificate: only
    an immediately consumed JE/JNE comparison is admitted, the branch bytes
    must already be identical, and the complete transformed body must equal
    the effective compiler output.
    """

    if len(clean_section.body) != len(effective_section.body):
        return None
    owner = _external_function_owner(clean, clean_section)
    if owner is None:
        return None
    try:
        relocation_symbols = {
            relocation.offset: {
                "width": _RELOCATION_WIDTHS[relocation.relocation_type],
                "target": relocation.target,
            }
            for relocation in clean_section.relocations
        }
    except KeyError:
        return None
    external_entries = _relational_external_entries(clean, clean_section)
    context = f"{clean.label} section {clean_section.name!r} owner {owner!r}"
    derived = derive_equality_compare_reversals(
        clean_section.body,
        effective_section.body,
        relocation_symbols,
        external_entries,
        context,
    )
    if derived is None:
        return None
    image, sites, proof = derived
    if image != effective_section.body:
        return None
    return sites, {
        "owner": owner,
        "section": clean_section.name,
        "clean_section_number": clean_section.number,
        "effective_section_number": effective_section.number,
        "body_size": len(clean_section.body),
        "proof": proof,
    }


def _derive_register_transposition(
    clean: _CoffObject,
    effective: _CoffObject,
    clean_section: _CoffSection,
    effective_section: _CoffSection,
    *,
    excluded_effective_sections: frozenset[int],
) -> dict[str, object] | None:
    """Derive one exact two-register transposition over the smallest region.

    There is no manifest-selected mapping or range.  The range is the span of
    whole instructions from the first changed byte through the last, and the
    only admitted mapping is a unique two-cycle whose proven whole-body image
    is exactly the effective compiler output.
    """

    if len(clean_section.body) != len(effective_section.body):
        return None
    owner = _external_function_owner(clean, clean_section)
    if owner is None or _external_function_owner(effective, effective_section) != owner:
        return None
    changed = tuple(
        index
        for index, (left, right) in enumerate(
            zip(clean_section.body, effective_section.body, strict=True)
        )
        if left != right
    )
    if not changed:
        return None
    try:
        relocation_symbols = {
            relocation.offset: {
                "width": _RELOCATION_WIDTHS[relocation.relocation_type],
                "target": relocation.target,
            }
            for relocation in clean_section.relocations
        }
    except KeyError:
        return None
    relocation_offsets = frozenset(
        relocation.offset + byte
        for relocation in clean_section.relocations
        for byte in range(_RELOCATION_WIDTHS[relocation.relocation_type])
    )
    context = f"{clean.label} section {clean_section.name!r} owner {owner!r}"
    try:
        instructions = decode_ia32_bijection_body(
            clean_section.body,
            context,
            relocation_symbols,
            len(clean_section.body),
        )
    except ByteIdentityError:
        return None
    if any(bool(item["indirect"]) for item in instructions):
        # This adapter has no jump-table completeness theorem.  A computed
        # transfer could enter the changed region without a relocation, so it
        # is outside this intentionally narrow proof even though the reusable
        # bijection primitive supports richer declared target universes.
        return None
    first = next(
        (
            item
            for item in instructions
            if int(item["offset"]) <= changed[0] < int(item["offset"]) + int(item["length"])
        ),
        None,
    )
    last = next(
        (
            item
            for item in instructions
            if int(item["offset"]) <= changed[-1] < int(item["offset"]) + int(item["length"])
        ),
        None,
    )
    if first is None or last is None:
        return None
    region = (
        int(first["offset"]),
        int(last["offset"]) + int(last["length"]),
    )
    clean_entries = _retained_relocation_entries_into(clean, clean_section)
    effective_entries = _retained_relocation_entries_into(
        effective,
        effective_section,
        excluded_sections=excluded_effective_sections,
    )
    if clean_entries != effective_entries or any(
        region[0] < entry < region[1] for entry in clean_entries
    ):
        return None

    registers = tuple(name for name in IA32_GENERAL_REGISTER_NAMES if name != "esp")
    candidates: list[tuple[dict[str, str], dict[str, object]]] = []
    for left_index, left in enumerate(registers):
        for right in registers[left_index + 1 :]:
            mapping = {left: right, right: left}
            try:
                image, proof = apply_register_bijection(
                    clean_section.body,
                    mapping,
                    region,
                    relocation_offsets,
                    context,
                    relocation_symbols,
                    len(clean_section.body),
                    clean_entries,
                )
            except ByteIdentityError:
                continue
            if image == effective_section.body:
                candidates.append((mapping, proof))
    if len(candidates) != 1:
        return None
    mapping, proof = candidates[0]
    return {
        "owner": owner,
        "section": clean_section.name,
        "clean_section_number": clean_section.number,
        "effective_section_number": effective_section.number,
        "body_size": len(clean_section.body),
        "mapping": dict(sorted(mapping.items())),
        "region": {"start": region[0], "end": region[1]},
        "changed_offsets": list(changed),
        "retained_relocation_entries": sorted(clean_entries),
        "proof": proof,
    }


def _dead_rdata_repack_equality_projection(
    clean: _CoffObject,
    effective: _CoffObject,
    *,
    excluded_effective_sections: frozenset[int],
) -> _RuntimeProjectionEquivalence | None:
    """Compose exactly one dead-data repack with existing equality-CMP proofs."""

    component = _dead_internal_rdata_repack_component(
        clean,
        effective,
        excluded_effective_sections=excluded_effective_sections,
    )
    if component is None:
        return None
    clean_sections = _retained_runtime_sections(clean)
    effective_sections = _retained_runtime_sections(effective)
    section_pairs = tuple(zip(clean_sections, effective_sections, strict=True))
    alpha_renames = _compiler_local_permutation_alpha_proof(
        clean,
        effective,
        section_pairs,
        excluded_effective_sections=excluded_effective_sections,
    )
    if alpha_renames is None:
        return None
    clean_symbols = _symbols_by_section(clean)
    effective_symbols = _symbols_by_section(effective)
    clean_code_certificates: dict[int, _CodeProjectionCertificate] = {}
    effective_code_certificates: dict[int, _CodeProjectionCertificate] = {}
    section_proofs: list[dict[str, object]] = []
    for clean_section, effective_section in section_pairs:
        if (
            clean_section.number == component.clean_section_number
            and effective_section.number == component.effective_section_number
        ):
            continue
        try:
            section_equal = _section_permutation_identity(
                clean, clean_section, clean_symbols
            ) == _section_permutation_identity(effective, effective_section, effective_symbols)
        except ClassicSemanticError:
            return None
        if section_equal:
            continue
        if not (
            clean_section.name.casefold().startswith(_CODE_SECTION_PREFIXES)
            and effective_section.name.casefold().startswith(_CODE_SECTION_PREFIXES)
        ):
            return None
        derived = _derive_equality_cmp_sites(clean, clean_section, effective_section)
        if derived is None:
            return None
        _sites, raw_section_proof = derived
        section_proof = {
            "theorem": _EQUALITY_CMP_PROJECTION_THEOREM,
            **raw_section_proof,
        }
        certificate_digest = Digest.from_bytes(canonical_json(section_proof)).value
        certificate = _CodeProjectionCertificate(
            _EQUALITY_CMP_PROJECTION_THEOREM,
            certificate_digest,
        )
        clean_code_certificates[clean_section.number] = certificate
        effective_code_certificates[effective_section.number] = certificate
        section_proofs.append(section_proof)
    if not section_proofs:
        return None

    clean_data_certificate = _DataProjectionCertificate(
        component.theorem,
        component.certificate_digest,
        clean.digest.value,
    )
    effective_data_certificate = _DataProjectionCertificate(
        component.theorem,
        component.certificate_digest,
        effective.digest.value,
    )
    clean_data_certificates = {
        component.clean_section_number: clean_data_certificate,
    }
    effective_data_certificates = {
        component.effective_section_number: effective_data_certificate,
    }
    if set(clean_code_certificates) & set(clean_data_certificates) or set(
        effective_code_certificates
    ) & set(effective_data_certificates):
        raise ClassicSemanticError(
            "dead .rdata repack and equality-CMP certificates overlap sections"
        )

    # Certificates authorize only their own components.  The ordinary
    # envelope remains the authoritative equality check for every residual
    # topology, relocation, directive, linkage, and body fact.
    try:
        clean_envelope = _coff_semantic_envelope(
            clean,
            certified_code_sections=clean_code_certificates,
            certified_data_sections=clean_data_certificates,
        )
        effective_envelope = _coff_semantic_envelope(
            effective,
            certified_code_sections=effective_code_certificates,
            certified_data_sections=effective_data_certificates,
        )
    except ClassicSemanticError:
        return None
    if clean_envelope["statement"] != effective_envelope["statement"]:
        return None

    proof: dict[str, object] = {
        "theorem": _DEAD_RDATA_REPACK_EQUALITY_COMPOSITION_THEOREM,
        "clean_object": clean.digest.model_dump(mode="json"),
        "effective_object": effective.digest.model_dump(mode="json"),
        "data_component": dict(component.proof),
        "code_theorem": _EQUALITY_CMP_PROJECTION_THEOREM,
        "code_sections": section_proofs,
        "compiler_local_alpha_renames": alpha_renames,
        "preserved": [
            "disjoint-data-and-code-certificate-section-sets",
            "complete-residual-coff-semantic-envelope",
            "external-common-weak-and-absolute-linkage",
            "linker-directives",
            "relocation-target-type-addend-and-seat-semantics",
            "startup-crt-tls-and-runtime-root-sections",
        ],
    }
    return _RuntimeProjectionEquivalence(
        equivalent=True,
        byte_equal=False,
        theorem=_DEAD_RDATA_REPACK_EQUALITY_COMPOSITION_THEOREM,
        clean_code_certificates=MappingProxyType(clean_code_certificates),
        effective_code_certificates=MappingProxyType(effective_code_certificates),
        proof=MappingProxyType(proof),
        clean_data_certificates=MappingProxyType(clean_data_certificates),
        effective_data_certificates=MappingProxyType(effective_data_certificates),
    )


def _runtime_projection_equivalence_proof(
    clean: _CoffObject,
    effective: _CoffObject,
    *,
    excluded_effective_sections: frozenset[int] = frozenset(),
) -> _RuntimeProjectionEquivalence:
    # File-header flags participate in every theorem family.  Gate once before
    # any family-specific normalization can intentionally discard unrelated
    # projection fields while comparing its narrower section delta.
    if _coff_header_statement(clean) != _coff_header_statement(effective):
        return _RuntimeProjectionEquivalence(False, False, None, {}, {}, None)
    clean_projection = _runtime_projection(clean)
    effective_projection = _runtime_projection(
        effective, excluded_sections=excluded_effective_sections
    )
    if clean_projection == effective_projection:
        return _RuntimeProjectionEquivalence(True, True, None, {}, {}, None)

    normalized = _alpha_normalized_runtime_projections(
        clean,
        effective,
        clean_projection,
        effective_projection,
        excluded_effective_sections=excluded_effective_sections,
    )
    if normalized is not None and normalized[0] == normalized[1]:
        alpha_proof: dict[str, object] = {
            "theorem": _COMPILER_LOCAL_ALPHA_PROJECTION_THEOREM,
            "clean_object": clean.digest.model_dump(mode="json"),
            "effective_object": effective.digest.model_dump(mode="json"),
            "preserved": [
                "complete-retained-section-topology-and-bodies",
                "symbol-record-order-values-types-and-storage",
                "relocation-layout-target-kinds-values-types-and-addends",
                "compiler-local-symbol-kind",
            ],
        }
        return _RuntimeProjectionEquivalence(
            True,
            False,
            _COMPILER_LOCAL_ALPHA_PROJECTION_THEOREM,
            {},
            {},
            MappingProxyType(alpha_proof),
        )

    permutation_proof = _data_comdat_permutation_proof(
        clean,
        effective,
        excluded_effective_sections=excluded_effective_sections,
    )
    if permutation_proof is not None:
        return _RuntimeProjectionEquivalence(
            True,
            False,
            _DATA_COMDAT_PERMUTATION_PROJECTION_THEOREM,
            {},
            {},
            permutation_proof,
        )
    dead_data_projection = _dead_internal_rdata_prefix_projection(
        clean,
        effective,
        excluded_effective_sections=excluded_effective_sections,
    )
    if dead_data_projection is not None:
        return dead_data_projection
    repack_projection = _dead_rdata_repack_equality_projection(
        clean,
        effective,
        excluded_effective_sections=excluded_effective_sections,
    )
    if repack_projection is not None:
        return repack_projection
    if normalized is None:
        return _RuntimeProjectionEquivalence(False, False, None, {}, {}, None)
    clean_projection, effective_projection = normalized

    clean_sections = _retained_runtime_sections(clean)
    effective_sections = _retained_runtime_sections(
        effective, excluded_sections=excluded_effective_sections
    )
    clean_statements = clean_projection.get("sections")
    effective_statements = effective_projection.get("sections")
    if (
        len(clean_sections) != len(effective_sections)
        or not isinstance(clean_statements, list)
        or not isinstance(effective_statements, list)
        or len(clean_statements) != len(clean_sections)
        or len(effective_statements) != len(effective_sections)
        or clean_projection.get("symbols") != effective_projection.get("symbols")
        or _linkage_statement(clean, excluded_sections=frozenset())
        != _linkage_statement(effective, excluded_sections=excluded_effective_sections)
        or _coff_directive_receipt(clean) != _coff_directive_receipt(effective)
    ):
        return _RuntimeProjectionEquivalence(False, False, None, {}, {}, None)

    section_proofs: list[dict[str, object]] = []
    clean_certificates: dict[int, _CodeProjectionCertificate] = {}
    effective_certificates: dict[int, _CodeProjectionCertificate] = {}
    theorem_family: str | None = None
    for clean_section, effective_section, clean_raw, effective_raw in zip(
        clean_sections,
        effective_sections,
        clean_statements,
        effective_statements,
        strict=True,
    ):
        if not isinstance(clean_raw, dict) or not isinstance(effective_raw, dict):
            return _RuntimeProjectionEquivalence(False, False, None, {}, {}, None)
        clean_statement = dict(clean_raw)
        effective_statement = dict(effective_raw)
        clean_body = clean_statement.pop("body", None)
        effective_body = effective_statement.pop("body", None)
        if clean_statement != effective_statement:
            return _RuntimeProjectionEquivalence(False, False, None, {}, {}, None)
        if clean_body == effective_body:
            continue
        if not clean_section.name.casefold().startswith(_CODE_SECTION_PREFIXES):
            return _RuntimeProjectionEquivalence(False, False, None, {}, {}, None)
        section_proof: dict[str, object] | None
        derived = _derive_equality_cmp_sites(clean, clean_section, effective_section)
        if derived is not None:
            _sites, section_proof = derived
            section_theorem = _EQUALITY_CMP_PROJECTION_THEOREM
        else:
            section_proof = _derive_register_transposition(
                clean,
                effective,
                clean_section,
                effective_section,
                excluded_effective_sections=excluded_effective_sections,
            )
            section_theorem = _REGISTER_TRANSPOSITION_PROJECTION_THEOREM
        if section_proof is None:
            return _RuntimeProjectionEquivalence(False, False, None, {}, {}, None)
        if theorem_family is not None and theorem_family != section_theorem:
            # No current object needs theorem composition. Refuse a
            # mixed proof family instead of inventing a generalized engine.
            return _RuntimeProjectionEquivalence(False, False, None, {}, {}, None)
        theorem_family = section_theorem
        section_proof = {"theorem": section_theorem, **section_proof}
        certificate = Digest.from_bytes(canonical_json(section_proof)).value
        typed_certificate = _CodeProjectionCertificate(section_theorem, certificate)
        clean_certificates[clean_section.number] = typed_certificate
        effective_certificates[effective_section.number] = typed_certificate
        section_proofs.append(section_proof)
    if not section_proofs or theorem_family is None:
        return _RuntimeProjectionEquivalence(False, False, None, {}, {}, None)
    proof: dict[str, object] = {
        "theorem": theorem_family,
        "clean_object": clean.digest.model_dump(mode="json"),
        "effective_object": effective.digest.model_dump(mode="json"),
        "sections": section_proofs,
        "preserved": [
            "complete-retained-section-topology",
            "all-non-code-section-bodies",
            "relocation-layout-targets-types-and-addends",
            "external-common-weak-and-absolute-linkage",
            "linker-directives",
            "complete-transformed-code-body-equality",
        ],
    }
    return _RuntimeProjectionEquivalence(
        True,
        False,
        theorem_family,
        MappingProxyType(clean_certificates),
        MappingProxyType(effective_certificates),
        MappingProxyType(proof),
    )


def _runtime_projection_equivalence(
    clean: _CoffObject,
    effective: _CoffObject,
    *,
    excluded_effective_sections: frozenset[int] = frozenset(),
) -> tuple[bool, bool, str | None]:
    result = _runtime_projection_equivalence_proof(
        clean,
        effective,
        excluded_effective_sections=excluded_effective_sections,
    )
    return result.equivalent, result.byte_equal, result.theorem


_CODE_SECTION_PREFIXES = (".text",)
_COMPILER_CONTROL_SECTION_PREFIXES = (".pdata", ".xdata")
_INITIALIZED_DATA_SECTION_PREFIXES = (".data", ".rdata")
_UNINITIALIZED_DATA_SECTION_PREFIXES = (".bss",)
_RELOCATION_WIDTHS = MappingProxyType({6: 4, 7: 4, 10: 2, 11: 4, 20: 4})
_IA32_DIRECTION_EQUIVALENTS = MappingProxyType(
    {
        0x03: 0x01,  # ADD r32,r/m32 <-> ADD r/m32,r32
        0x0B: 0x09,  # OR
        0x13: 0x11,  # ADC
        0x1B: 0x19,  # SBB
        0x23: 0x21,  # AND
        0x2B: 0x29,  # SUB
        0x33: 0x31,  # XOR
        0x3B: 0x39,  # CMP
        0x8B: 0x89,  # MOV
    }
)


def _is_section_symbol(symbol: _CoffSymbol, section: _CoffSection) -> bool:
    return (
        symbol.storage == 3
        and symbol.name == section.name
        and symbol.section == section.number
        and symbol.value == 0
        and symbol.symbol_type == 0
        and symbol.auxiliary_count == 1
        and len(symbol.auxiliary) == 18
        and int.from_bytes(symbol.auxiliary[:4], "little") == len(section.body)
        and int.from_bytes(symbol.auxiliary[4:6], "little") == len(section.relocations)
        and int.from_bytes(symbol.auxiliary[6:8], "little") == len(section.line_numbers)
    )


def _section_definition_symbol(
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> _CoffSymbol | None:
    candidates = tuple(
        symbol
        for symbol in symbols.get(section.number, ())
        if symbol.storage == 3 and symbol.name == section.name
    )
    if not candidates:
        return None
    if len(candidates) != 1 or not _is_section_symbol(candidates[0], section):
        raise ClassicSemanticError(
            f"section {section.number} {section.name!r} has a non-canonical or duplicate "
            "definition symbol"
        )
    return candidates[0]


def _section_definition_statement(
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object] | None:
    symbol = _section_definition_symbol(section, symbols)
    if symbol is None:
        return None
    non_length_auxiliary = bytearray(symbol.auxiliary[4:])
    if section.comdat_associated not in {None, 0}:
        # IMAGE_AUX_SYMBOL_SECTION stores the associated COMDAT's positional
        # section number in the low/high words at bytes 12 and 16.  The
        # topology statement below binds that association by the target's
        # semantic identity, so retaining the raw seat as well would make a
        # harmless global section reorder look like a control-flow change.
        raw_associated = int.from_bytes(symbol.auxiliary[12:14], "little") | (
            int.from_bytes(symbol.auxiliary[16:18], "little") << 16
        )
        if raw_associated != section.comdat_associated:
            raise ClassicSemanticError(
                f"section {section.number} {section.name!r} has inconsistent COMDAT "
                "association evidence"
            )
        non_length_auxiliary[8:10] = b"\0\0"
        non_length_auxiliary[12:14] = b"\0\0"
    return {
        "length": int.from_bytes(symbol.auxiliary[:4], "little"),
        "non_length_auxiliary": bytes(non_length_auxiliary).hex(),
    }


def _compiler_local_definition_kind(symbol: _CoffSymbol) -> str | None:
    if (
        symbol.storage not in {3, 6}
        or symbol.section <= 0
        or symbol.symbol_type != 0
        or symbol.auxiliary_count
        or symbol.auxiliary
    ):
        return None
    return local_symbol_kind(symbol.name)


def _msvc_static_definition_stem(
    section: _CoffSection,
    symbol: _CoffSymbol,
) -> str | None:
    """Recognize one linker-internal MSVC ``name$S<digits>`` datum."""

    if (
        symbol.storage != 3
        or symbol.section != section.number
        or symbol.symbol_type != 0
        or symbol.auxiliary_count
        or symbol.auxiliary
        or not 0 <= symbol.value < len(section.body)
    ):
        return None
    return _msvc_static_serial_stem(symbol.name)


def _defined_symbol_name_statement(
    section: _CoffSection,
    symbol: _CoffSymbol,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> object:
    """Bind a defined local name while removing only closed MSVC serials."""

    local_kind = _compiler_local_definition_kind(symbol)
    if local_kind is not None:
        return {"compiler_local_kind": local_kind}
    static_stem = _msvc_static_definition_stem(section, symbol)
    if static_stem is None:
        return symbol.name
    matches = [
        candidate
        for candidate in symbols.get(section.number, ())
        if _msvc_static_definition_stem(section, candidate) == static_stem
    ]
    if len(matches) != 1:
        # Keep ambiguous objects exact.  Normalizing two same-stem definitions
        # would lose the evidence needed to decide which internal symbol moved.
        return symbol.name
    return {"msvc_static_serial_stem": static_stem}


def _symbols_by_section(coff: _CoffObject) -> dict[int, tuple[_CoffSymbol, ...]]:
    result: dict[int, list[_CoffSymbol]] = defaultdict(list)
    for symbol in coff.symbols:
        if symbol.section > 0:
            if symbol.section > len(coff.sections):
                raise ClassicSemanticError(
                    f"{coff.label} symbol {symbol.name!r} has an invalid section"
                )
            result[symbol.section].append(symbol)
    return {
        number: tuple(
            sorted(
                values,
                key=lambda item: (
                    item.name,
                    item.value,
                    item.symbol_type,
                    item.storage,
                ),
            )
        )
        for number, values in result.items()
    }


def _section_owner_statement(
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> list[dict[str, object]]:
    definition = _section_definition_symbol(section, symbols)
    result: list[dict[str, object]] = []
    for symbol in symbols.get(section.number, ()):
        if definition is not None and symbol.index == definition.index:
            continue
        statement: dict[str, object] = {
            "name": _defined_symbol_name_statement(section, symbol, symbols),
            "value": symbol.value,
            "type": symbol.symbol_type,
            "storage": symbol.storage,
        }
        result.append(statement)
    return sorted(result, key=canonical_json)


def _association_statement(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object] | None:
    associated = section.comdat_associated
    if not associated:
        return None
    if not 0 < associated <= len(coff.sections):
        raise ClassicSemanticError(
            f"{coff.label} section {section.name!r} has an invalid COMDAT association"
        )
    target = coff.sections[associated - 1]
    return {
        "name": target.name,
        "selection": target.comdat_selection,
        "owners": _section_owner_statement(target, symbols),
    }


def _section_topology_statement(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object]:
    return {
        "name": section.name,
        "characteristics": section.characteristics,
        "definition": _section_definition_statement(section, symbols),
        "selection": section.comdat_selection,
        "association": _association_statement(coff, section, symbols),
        "owners": _section_owner_statement(section, symbols),
    }


def _preliminary_section_identity(
    coff: _CoffObject,
    section: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object]:
    folded = section.name.casefold()
    topology = _section_topology_statement(coff, section, symbols)
    if folded.startswith(_CODE_SECTION_PREFIXES):
        return {"kind": "code", "topology": topology}
    if folded.startswith(_COMPILER_CONTROL_SECTION_PREFIXES):
        return {"kind": "compiler-control", "topology": topology}
    masked = bytearray(section.body)
    for relocation in section.relocations:
        width = _RELOCATION_WIDTHS.get(relocation.relocation_type)
        if width is None or relocation.offset + width > len(masked):
            raise ClassicSemanticError(
                f"{coff.label} section {section.name!r} has an invalid relocation field"
            )
        masked[relocation.offset : relocation.offset + width] = bytes(width)
    return {
        "kind": "data",
        "topology": topology,
        "masked_body": bytes(masked).hex(),
    }


def _relocation_target_statement(
    coff: _CoffObject,
    relocation: _CoffRelocation,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object]:
    if relocation.target_section == 0:
        kind = (
            "weak"
            if relocation.target_storage == 105
            else "common"
            if relocation.target_storage == 2 and relocation.target_value > 0
            else "undefined"
        )
        return {
            "kind": kind,
            "name": relocation.target,
            "value": relocation.target_value,
            "type": relocation.target_type,
            "storage": relocation.target_storage,
        }
    if not 0 < relocation.target_section <= len(coff.sections):
        raise ClassicSemanticError(f"{coff.label} relocation target has an invalid section")
    target = coff.sections[relocation.target_section - 1]
    by_index = {symbol.index: symbol for symbol in coff.symbols}
    target_symbol = by_index.get(relocation.target_index)
    if target_symbol is None:
        raise ClassicSemanticError(f"{coff.label} relocation target symbol is absent")
    statement: dict[str, object] = {
        "kind": "defined",
        "symbol": {
            "name": _defined_symbol_name_statement(target, target_symbol, symbols),
            "type": relocation.target_type,
            "storage": relocation.target_storage,
            "section_symbol": (relocation.target_storage == 3 and relocation.target == target.name),
            "value": relocation.target_value,
        },
        "section": _preliminary_section_identity(coff, target, symbols),
    }
    return statement


def _relocation_statement(
    coff: _CoffObject,
    relocation: _CoffRelocation,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
    *,
    include_offset: bool,
) -> dict[str, object]:
    result: dict[str, object] = {
        "type": relocation.relocation_type,
        "target": _relocation_target_statement(coff, relocation, symbols),
        "addend": relocation.addend.hex(),
    }
    if include_offset:
        result["offset"] = relocation.offset
    return result


def _associated_eh_control_statement(
    coff: _CoffObject,
    primary: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> dict[str, object] | None:
    associated = [
        section
        for section in coff.sections
        if section.comdat_associated == primary.number
        and section.name.casefold().startswith(_COMPILER_CONTROL_SECTION_PREFIXES)
    ]
    if not associated:
        return None
    if len(associated) != 1 or associated[0].name.casefold() != ".xdata$x":
        raise ClassicSemanticError(
            f"{coff.label} code section {primary.number} has no unique paired .xdata$x control"
        )
    section = associated[0]
    return {
        "topology": _section_topology_statement(coff, section, symbols),
        "body": section.body.hex(),
        "relocations": [
            _relocation_statement(coff, relocation, symbols, include_offset=True)
            for relocation in section.relocations
        ],
    }


def _associated_fpo_evidence_statement(
    coff: _CoffObject,
    primary: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> tuple[dict[str, object], bytes] | None:
    """Return the exact FPO child receipt for the one admitted FPO closure."""

    associated = [
        section for section in coff.sections if section.comdat_associated == primary.number
    ]
    if tuple(sorted(section.name for section in associated)) != (".debug$F", ".debug$S"):
        return None
    fpo = [section for section in associated if section.name == ".debug$F"]
    if len(fpo) != 1:
        return None
    section = fpo[0]
    statement: dict[str, object] = {
        "closure": [".debug$F", ".debug$S"],
        "topology": _section_topology_statement(coff, section, symbols),
        "body": section.body.hex(),
        "relocations": [
            _relocation_statement(coff, relocation, symbols, include_offset=True)
            for relocation in section.relocations
        ],
    }
    return statement, section.body


def _associated_debug_evidence_statement(
    coff: _CoffObject,
    primary: _CoffSection,
    symbols: Mapping[int, tuple[_CoffSymbol, ...]],
) -> tuple[dict[str, object], bytes] | None:
    """Return the exact ``.debug$S`` child from the admitted FPO closure."""

    associated = [
        section for section in coff.sections if section.comdat_associated == primary.number
    ]
    if tuple(sorted(section.name for section in associated)) != (".debug$F", ".debug$S"):
        return None
    streams = [section for section in associated if section.name == ".debug$S"]
    if len(streams) != 1:
        return None
    section = streams[0]
    statement: dict[str, object] = {
        "closure": [".debug$F", ".debug$S"],
        "topology": _section_topology_statement(coff, section, symbols),
        "body": section.body.hex(),
        "relocations": [
            _relocation_statement(coff, relocation, symbols, include_offset=True)
            for relocation in section.relocations
        ],
    }
    return statement, section.body


def _compiler_state_code_pairs(
    clean: _CoffObject,
    effective: _CoffObject,
    *,
    excluded_effective_sections: frozenset[int],
) -> tuple[CompilerStateCodePair, ...]:
    clean_symbols = _symbols_by_section(clean)
    effective_symbols = _symbols_by_section(effective)

    def owned_sections(
        coff: _CoffObject,
        excluded_sections: frozenset[int],
    ) -> dict[str, _CoffSection]:
        grouped: dict[str, list[_CoffSection]] = defaultdict(list)
        for section in _retained_runtime_sections(coff, excluded_sections=excluded_sections):
            if not section.name.casefold().startswith(_CODE_SECTION_PREFIXES):
                continue
            owner = _external_function_owner(coff, section)
            if owner is not None:
                grouped[owner].append(section)
        duplicates = sorted(name for name, sections in grouped.items() if len(sections) != 1)
        if duplicates:
            raise ClassicSemanticError(
                f"{coff.label} has duplicate external code owners: {duplicates}"
            )
        return {name: sections[0] for name, sections in grouped.items()}

    clean_owned = owned_sections(clean, frozenset())
    effective_owned = owned_sections(effective, excluded_effective_sections)
    result: list[CompilerStateCodePair] = []
    for owner in sorted(
        set(clean_owned) & set(effective_owned), key=lambda item: (item.casefold(), item)
    ):
        clean_section = clean_owned[owner]
        effective_section = effective_owned[owner]
        if clean_section.body == effective_section.body:
            continue
        clean_topology = _section_topology_statement(clean, clean_section, clean_symbols)
        effective_topology = _section_topology_statement(
            effective, effective_section, effective_symbols
        )
        if clean_topology != effective_topology:
            raise ClassicSemanticError(
                f"MSVC 4.20 compiler-state code pair {owner!r} changes section topology"
            )
        clean_entries = tuple(sorted(_relational_external_entries(clean, clean_section)))
        effective_entries = tuple(
            sorted(
                _relational_external_entries(
                    effective,
                    effective_section,
                    excluded_sections=excluded_effective_sections,
                )
            )
        )
        if clean_entries != effective_entries:
            raise ClassicSemanticError(
                f"MSVC 4.20 compiler-state code pair {owner!r} changes external entry offsets"
            )
        clean_control = _associated_eh_control_statement(clean, clean_section, clean_symbols)
        effective_control = _associated_eh_control_statement(
            effective, effective_section, effective_symbols
        )
        if clean_control != effective_control:
            raise ClassicSemanticError(
                f"MSVC 4.20 compiler-state code pair {owner!r} changes paired EH control"
            )
        clean_fpo = _associated_fpo_evidence_statement(clean, clean_section, clean_symbols)
        effective_fpo = _associated_fpo_evidence_statement(
            effective, effective_section, effective_symbols
        )
        fpo_evidence: CompilerStateFpoEvidence | None = None
        if (
            clean_fpo is not None
            and effective_fpo is not None
            and {key: value for key, value in clean_fpo[0].items() if key != "body"}
            == {key: value for key, value in effective_fpo[0].items() if key != "body"}
        ):
            fpo_topology = {key: value for key, value in clean_fpo[0].items() if key != "body"}
            fpo_evidence = CompilerStateFpoEvidence(
                receipt_digest=Digest.from_bytes(canonical_json(fpo_topology)).value,
                clean_body=clean_fpo[1],
                effective_body=effective_fpo[1],
            )
        clean_debug = _associated_debug_evidence_statement(clean, clean_section, clean_symbols)
        effective_debug = _associated_debug_evidence_statement(
            effective, effective_section, effective_symbols
        )
        debug_evidence: CompilerStateDebugEvidence | None = None
        if (
            clean_debug is not None
            and effective_debug is not None
            and {key: value for key, value in clean_debug[0].items() if key != "body"}
            == {key: value for key, value in effective_debug[0].items() if key != "body"}
        ):
            debug_topology = {key: value for key, value in clean_debug[0].items() if key != "body"}
            debug_evidence = CompilerStateDebugEvidence(
                receipt_digest=Digest.from_bytes(canonical_json(debug_topology)).value,
                clean_body=clean_debug[1],
                effective_body=effective_debug[1],
            )
        result.append(
            CompilerStateCodePair(
                owner=owner,
                clean_section_number=clean_section.number,
                effective_section_number=effective_section.number,
                topology_digest=Digest.from_bytes(canonical_json(clean_topology)).value,
                clean_body=clean_section.body,
                effective_body=effective_section.body,
                clean_relocations=tuple(
                    _relocation_statement(clean, relocation, clean_symbols, include_offset=True)
                    for relocation in clean_section.relocations
                ),
                effective_relocations=tuple(
                    _relocation_statement(
                        effective,
                        relocation,
                        effective_symbols,
                        include_offset=True,
                    )
                    for relocation in effective_section.relocations
                ),
                eh_control_digest=(
                    Digest.from_bytes(canonical_json(clean_control)).value
                    if clean_control is not None
                    else None
                ),
                external_entries=clean_entries,
                fpo_evidence=fpo_evidence,
                debug_evidence=debug_evidence,
            )
        )
    return tuple(result)


def _canonical_multiset(values: Sequence[object]) -> list[dict[str, object]]:
    counts: dict[bytes, int] = defaultdict(int)
    for value in values:
        counts[canonical_json(value)] += 1
    return [
        {
            "value": Digest.from_bytes(encoded).model_dump(mode="json"),
            "count": count,
        }
        for encoded, count in sorted(counts.items())
    ]


def _canonical_ia32_instruction(encoded: bytes) -> str:
    """Normalize only proven direction-bit register/register encodings."""

    result = bytearray(encoded)
    opcode_index = 0
    while opcode_index < len(result) and result[opcode_index] in {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0xF0,
        0xF2,
        0xF3,
    }:
        opcode_index += 1
    if opcode_index + 1 >= len(result):
        return result.hex()
    canonical_opcode = _IA32_DIRECTION_EQUIVALENTS.get(result[opcode_index])
    if canonical_opcode is None:
        return result.hex()
    modrm_index = opcode_index + 1
    modrm = result[modrm_index]
    if modrm >> 6 != 3:
        # Swapping a register with a memory operand is not the same operation.
        return result.hex()
    result[opcode_index] = canonical_opcode
    result[modrm_index] = (modrm & 0xC0) | ((modrm & 0x07) << 3) | ((modrm >> 3) & 0x07)
    return result.hex()


def _semantic_code_stream(
    coff: _CoffObject, section: _CoffSection
) -> tuple[list[str], tuple[tuple[int, int], ...]]:
    masked = bytearray(section.body)
    for relocation in section.relocations:
        width = _RELOCATION_WIDTHS[relocation.relocation_type]
        masked[relocation.offset : relocation.offset + width] = bytes(width)
    result: list[str] = []
    boundaries: list[tuple[int, int]] = []
    cursor = 0
    while cursor < len(masked):
        try:
            length = supported_ia32_instruction_length(
                bytes(masked[cursor:]),
                f"{coff.label} section {section.name!r} at {cursor}",
            )
        except ByteIdentityError as exc:
            raise _SemanticCodePartitionError(
                f"{coff.label} code section has no closed IA-32 partition"
            ) from exc
        if length <= 0 or cursor + length > len(masked):
            raise _SemanticCodePartitionError(
                f"{coff.label} code section has an invalid IA-32 partition"
            )
        result.append(_canonical_ia32_instruction(bytes(masked[cursor : cursor + length])))
        boundaries.append((cursor, cursor + length))
        cursor += length
    return result, tuple(boundaries)


def _weak_external_statement(coff: _CoffObject, symbol: _CoffSymbol) -> object:
    if (
        symbol.section != 0
        or symbol.value != 0
        or symbol.auxiliary_count != 1
        or (len(symbol.auxiliary) != 18)
    ):
        raise ClassicSemanticError(f"{coff.label} weak external {symbol.name!r} is malformed")
    tag_index, characteristics = struct.unpack_from("<II", symbol.auxiliary)
    by_index = {item.index: item for item in coff.symbols}
    fallback = by_index.get(tag_index)
    if fallback is None or fallback.storage not in {2, 105}:
        raise ClassicSemanticError(
            f"{coff.label} weak external {symbol.name!r} has an invalid fallback"
        )
    if any(symbol.auxiliary[8:]):
        raise ClassicSemanticError(
            f"{coff.label} weak external {symbol.name!r} has unknown auxiliary state"
        )
    return {
        "name": symbol.name,
        "fallback": fallback.name,
        "characteristics": characteristics,
        "type": symbol.symbol_type,
    }


def _linkage_statement(
    coff: _CoffObject,
    *,
    excluded_sections: frozenset[int],
    excluded_undefineds: frozenset[tuple[str, int]] = frozenset(),
) -> dict[str, object]:
    symbols = _symbols_by_section(coff)
    definitions: list[dict[str, object]] = []
    undefineds: list[dict[str, object]] = []
    commons: list[dict[str, object]] = []
    weaks: list[object] = []
    absolute: list[dict[str, object]] = []
    for symbol in coff.symbols:
        if symbol.storage == 105:
            weaks.append(_weak_external_statement(coff, symbol))
            continue
        if symbol.storage != 2:
            continue
        if symbol.section > 0:
            if symbol.section in excluded_sections:
                continue
            section = coff.sections[symbol.section - 1]
            definitions.append(
                {
                    "name": symbol.name,
                    "value": symbol.value,
                    "type": symbol.symbol_type,
                    "section": _section_topology_statement(coff, section, symbols),
                }
            )
        elif symbol.section == 0 and symbol.value > 0:
            commons.append(
                {
                    "name": symbol.name,
                    "size": symbol.value,
                    "type": symbol.symbol_type,
                }
            )
        elif symbol.section == 0:
            if (symbol.name, symbol.symbol_type) not in excluded_undefineds:
                undefineds.append(
                    {
                        "name": symbol.name,
                        "type": symbol.symbol_type,
                    }
                )
        elif symbol.section < 0:
            absolute.append(
                {
                    "name": symbol.name,
                    "value": symbol.value,
                    "section": symbol.section,
                    "type": symbol.symbol_type,
                }
            )
    relocation_dependencies = sorted(
        {
            relocation.target
            for section in coff.sections
            if section.number not in excluded_sections
            and not section.name.casefold().startswith(".debug")
            for relocation in section.relocations
            if relocation.target_section == 0
            and relocation.target_storage in {2, 105}
            and not (relocation.target_storage == 2 and relocation.target_value > 0)
        }
    )
    return {
        "definitions": sorted(definitions, key=lambda item: str(item["name"])),
        "undefineds": sorted(undefineds, key=lambda item: canonical_json(item)),
        "relocation_dependencies": relocation_dependencies,
        "commons": sorted(commons, key=lambda item: str(item["name"])),
        "weaks": sorted(weaks, key=lambda item: canonical_json(item)),
        "absolutes": sorted(absolute, key=lambda item: str(item["name"])),
    }


def classic_link_relevant_coff_projection(
    payload: bytes,
    *,
    label: str,
) -> ClassicLinkRelevantCoffProjection:
    """Return the exact non-debug linker view of one strict i386 COFF object.

    This is a diagnostic correspondence primitive, not a source-semantics
    proof.  Equality establishes that the linker receives the same ordinary
    COFF state after explicitly documented debug/timestamp normalization; it
    cannot establish that two source programs have the same behavior.
    """

    if type(payload) is not bytes or not payload:
        raise ClassicSemanticError(f"{label} is not immutable COFF bytes")
    if not label or "\x00" in label:
        raise ClassicSemanticError("COFF projection label is malformed")
    coff = _parse_coff(payload, label)
    excluded_sections = frozenset(
        section.number for section in coff.sections if section.name.casefold().startswith(".debug")
    )
    runtime = _runtime_projection(coff, include_line_numbers=True)
    directives = _coff_directive_receipt(coff)
    statement: dict[str, object] = {
        "schema": 1,
        "kind": "classic-coff-link-relevant-projection",
        "coff_header": _coff_header_statement(coff),
        # `_runtime_projection` retains original relative section order and
        # exact bodies/relocations while renumbering only across omitted debug
        # sections.  Its broader local-symbol view is intentionally not used:
        # all external linkage is closed below and every referenced local
        # symbol is already bound by the exact relocation statement.
        "sections": runtime["sections"],
        "linkage": _linkage_statement(coff, excluded_sections=excluded_sections),
        "directives": {
            "tokens": list(directives.tokens),
            "default_libraries": list(directives.default_libraries),
            "include_symbols": list(directives.include_symbols),
            "export_symbols": list(directives.export_symbols),
            "merge_sections": [list(item) for item in directives.merge_sections],
            "disallowed_libraries": list(directives.disallowed_libraries),
        },
    }
    return ClassicLinkRelevantCoffProjection(
        object_digest=coff.digest,
        projection_digest=Digest.from_bytes(canonical_json(statement)),
        statement=statement,
        excluded_section_names=tuple(
            section.name for section in coff.sections if section.number in excluded_sections
        ),
    )


def _coff_line_number_invariant_projection(
    projection: ClassicLinkRelevantCoffProjection,
) -> tuple[dict[str, object], tuple[tuple[int, str, int, int, int], ...]]:
    """Copy a strict projection while replacing only ordinary line values."""

    statement = dict(projection.statement)
    raw_sections = statement.get("sections")
    if not isinstance(raw_sections, list):
        raise AssertionError("strict COFF projection has no section list")
    sections: list[dict[str, object]] = []
    values: list[tuple[int, str, int, int, int]] = []
    for section_index, raw_section in enumerate(raw_sections, start=1):
        if not isinstance(raw_section, dict):
            raise AssertionError("strict COFF projection section is malformed")
        section = dict(raw_section)
        section_name = section.get("name")
        raw_lines = section.get("line_numbers")
        if not isinstance(section_name, str) or not isinstance(raw_lines, list):
            raise AssertionError("strict COFF projection line table is malformed")
        line_numbers: list[dict[str, object]] = []
        for record_index, raw_line in enumerate(raw_lines):
            if not isinstance(raw_line, dict):
                raise AssertionError("strict COFF projection line record is malformed")
            line = dict(raw_line)
            line_number = line.get("line")
            if (
                not isinstance(line_number, int)
                or isinstance(line_number, bool)
                or not 0 <= line_number <= 0xFFFF
            ):
                raise AssertionError("strict COFF projection line value is malformed")
            if line_number:
                address = line.get("address")
                if (
                    set(line) != {"address", "line"}
                    or not isinstance(address, int)
                    or isinstance(address, bool)
                ):
                    raise AssertionError("ordinary COFF line record is malformed")
                values.append((section_index, section_name, record_index, address, line_number))
                line["line"] = "ordinary-coff-line-number-value"
            elif set(line) != {
                "line",
                "target",
                "target_section",
                "target_storage",
                "target_type",
                "target_value",
            }:
                raise AssertionError("COFF function line record is malformed")
            line_numbers.append(line)
        section["line_numbers"] = line_numbers
        sections.append(section)
    statement["sections"] = sections
    return statement, tuple(values)


def _coff_retained_symbol_records(coff: _CoffObject) -> list[dict[str, object]]:
    """Bind every non-debug symbol record beyond the public linker projection."""

    retained_sections = [
        section for section in coff.sections if not section.name.casefold().startswith(".debug")
    ]
    section_map = {section.number: index + 1 for index, section in enumerate(retained_sections)}
    return [
        {
            "name": symbol.name,
            "value": symbol.value,
            "section": section_map.get(symbol.section, symbol.section),
            "type": symbol.symbol_type,
            "storage": symbol.storage,
            "auxiliary_count": symbol.auxiliary_count,
            "auxiliary": symbol.auxiliary.hex(),
        }
        for symbol in coff.symbols
        if symbol.section <= 0 or symbol.section in section_map
    ]


def prove_classic_coff_line_number_correspondence(
    baseline: bytes,
    candidate: bytes,
    *,
    baseline_label: str,
    candidate_label: str,
) -> ClassicCoffLineNumberCorrespondence:
    """Prove strict COFF equality modulo ordinary source-line values only.

    Timestamp, whole ``.debug*`` state, and an external PDB are normalized by
    :func:`classic_link_relevant_coff_projection`.  Within every retained
    section, this theorem additionally permits only the nonzero 16-bit source
    line value in a COFF line-table row to change.  In particular, it binds
    every row address and zero-line function-symbol target exactly.

    This receipt is not independently a source-semantics proof.  A caller must
    pair it with a closed source theorem, such as the complete-census fresh and
    unused ``typedef int`` theorem issued by the project-overlay validator.
    """

    baseline_projection = classic_link_relevant_coff_projection(baseline, label=baseline_label)
    candidate_projection = classic_link_relevant_coff_projection(candidate, label=candidate_label)
    baseline_coff = _parse_coff(baseline, baseline_label)
    candidate_coff = _parse_coff(candidate, candidate_label)
    baseline_invariant, baseline_values = _coff_line_number_invariant_projection(
        baseline_projection
    )
    candidate_invariant, candidate_values = _coff_line_number_invariant_projection(
        candidate_projection
    )
    # The public projection deliberately excludes unreferenced local symbols.
    # This narrower theorem is stronger: aside from symbols owned by normalized
    # debug sections, every primary symbol record and auxiliary payload is exact.
    baseline_invariant["retained_symbol_records"] = _coff_retained_symbol_records(baseline_coff)
    candidate_invariant["retained_symbol_records"] = _coff_retained_symbol_records(candidate_coff)
    if baseline_invariant != candidate_invariant:
        raise ClassicSemanticError(
            f"{candidate_label} differs from {baseline_label} outside ordinary "
            "COFF line-number metadata values"
        )
    if len(baseline_values) != len(candidate_values):
        raise AssertionError("equal line-number invariants have unequal ordinary rows")
    deltas: list[ClassicCoffLineNumberDelta] = []
    for baseline_value, candidate_value in zip(baseline_values, candidate_values, strict=True):
        if baseline_value[:4] != candidate_value[:4]:
            raise AssertionError("equal line-number invariants have unequal row identities")
        if baseline_value[4] == candidate_value[4]:
            continue
        deltas.append(
            ClassicCoffLineNumberDelta(
                section_index=baseline_value[0],
                section_name=baseline_value[1],
                record_index=baseline_value[2],
                address=baseline_value[3],
                baseline_line=baseline_value[4],
                candidate_line=candidate_value[4],
            )
        )
    invariant_digest = Digest.from_bytes(canonical_json(baseline_invariant))
    statement: dict[str, object] = {
        "schema": 1,
        "kind": "classic-coff-line-number-correspondence",
        "baseline_object": {
            "digest": baseline_projection.object_digest.model_dump(mode="json"),
            "size": len(baseline),
        },
        "candidate_object": {
            "digest": candidate_projection.object_digest.model_dump(mode="json"),
            "size": len(candidate),
        },
        "strict_projections": {
            "baseline_digest": baseline_projection.projection_digest.model_dump(mode="json"),
            "candidate_digest": candidate_projection.projection_digest.model_dump(mode="json"),
            "shared_invariant_digest": invariant_digest.model_dump(mode="json"),
        },
        "inherited_normalizations": list(baseline_projection.normalizations),
        "excluded_debug_sections": {
            "baseline": list(baseline_projection.excluded_section_names),
            "candidate": list(candidate_projection.excluded_section_names),
        },
        "allowed_delta": "retained-section-ordinary-coff-line-number-value",
        "line_number_deltas": [
            {
                "section_index": delta.section_index,
                "section_name": delta.section_name,
                "record_index": delta.record_index,
                "address": delta.address,
                "baseline_line": delta.baseline_line,
                "candidate_line": delta.candidate_line,
            }
            for delta in deltas
        ],
    }
    statement_digest = Digest.from_bytes(canonical_json(statement))
    return ClassicCoffLineNumberCorrespondence(
        baseline_object_digest=baseline_projection.object_digest,
        baseline_size=len(baseline),
        candidate_object_digest=candidate_projection.object_digest,
        candidate_size=len(candidate),
        baseline_projection_digest=baseline_projection.projection_digest,
        candidate_projection_digest=candidate_projection.projection_digest,
        invariant_projection_digest=invariant_digest,
        line_number_deltas=tuple(deltas),
        statement_digest=statement_digest,
        statement=MappingProxyType(statement),
    )


def _coff_semantic_envelope(
    coff: _CoffObject,
    *,
    excluded_sections: frozenset[int] = frozenset(),
    excluded_undefineds: frozenset[tuple[str, int]] = frozenset(),
    certified_code_sections: Mapping[int, _CodeProjectionCertificate] | None = None,
    certified_data_sections: Mapping[int, _DataProjectionCertificate] | None = None,
) -> dict[str, object]:
    certified_code_sections = certified_code_sections or {}
    certified_data_sections = certified_data_sections or {}
    certificate_overlap = sorted(set(certified_code_sections) & set(certified_data_sections))
    if certificate_overlap:
        raise ClassicSemanticError(
            f"{coff.label} code and data certificates overlap sections: {certificate_overlap}"
        )
    symbols = _symbols_by_section(coff)
    topology: list[object] = []
    code_relocations: list[object] = []
    initialized_data: list[object] = []
    uninitialized_data: list[object] = []
    compiler_control: list[object] = []
    runtime_roots: list[object] = []
    code_bodies: list[tuple[bytes, int]] = []
    seen_code_certificates: set[int] = set()
    seen_data_certificates: set[int] = set()
    for section in coff.sections:
        if section.number in excluded_sections or section.name.casefold().startswith(".debug"):
            continue
        folded = section.name.casefold()
        data_certificate = certified_data_sections.get(section.number)
        data_certificate_statement: dict[str, object] | None = None
        if data_certificate is not None:
            section_definition = _section_definition_statement(section, symbols)
            if (
                data_certificate.theorem
                not in {
                    _DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM,
                    _DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM,
                }
                or data_certificate.object_digest != coff.digest.value
                or not _ordinary_readonly_rdata_section(coff, section)
                or section_definition is None
            ):
                raise ClassicSemanticError(
                    f"{coff.label} data certificate does not bind ordinary read-only "
                    f".rdata section {section.number}"
                )
            seen_data_certificates.add(section.number)
            data_certificate_statement = {
                "theorem": data_certificate.theorem,
                "certificate": data_certificate.digest,
            }
            section_topology = {
                "name": section.name,
                "characteristics": section.characteristics,
                "definition": {
                    "length": {"semantic_projection": data_certificate_statement},
                    "non_length_auxiliary": section_definition["non_length_auxiliary"],
                },
                "selection": section.comdat_selection,
                "association": None,
                "owners": [{"semantic_projection": data_certificate_statement}],
            }
        else:
            section_topology = _section_topology_statement(coff, section, symbols)
        if folded == ".drectve":
            topology.append(section_topology)
            continue
        topology.append(section_topology)
        relocations = [
            _relocation_statement(
                coff,
                item,
                symbols,
                include_offset=not folded.startswith(_CODE_SECTION_PREFIXES),
            )
            for item in section.relocations
        ]
        if folded.startswith(_FORBIDDEN_RUNTIME_SECTION_PREFIXES):
            runtime_roots.append(
                {
                    "topology": section_topology,
                    "body": section.body.hex(),
                    "relocations": relocations,
                }
            )
        elif folded.startswith(_CODE_SECTION_PREFIXES):
            if not section_topology["owners"]:
                raise ClassicSemanticError(f"{coff.label} code section has no closed symbol owner")
            instruction_stream: list[str] | None
            instruction_boundaries: tuple[tuple[int, int], ...]
            try:
                instruction_stream, instruction_boundaries = _semantic_code_stream(coff, section)
            except _SemanticCodePartitionError:
                instruction_stream = None
                instruction_boundaries = ()
            seated_relocations: list[dict[str, object]] = []
            if instruction_stream is not None:
                for relocation, statement in zip(section.relocations, relocations, strict=True):
                    width = _RELOCATION_WIDTHS[relocation.relocation_type]
                    seats = [
                        (index, start)
                        for index, (start, end) in enumerate(instruction_boundaries)
                        if start <= relocation.offset and relocation.offset + width <= end
                    ]
                    if len(seats) != 1:
                        instruction_stream = None
                        seated_relocations = []
                        break
                    instruction_index, instruction_start = seats[0]
                    seated_relocations.append(
                        {
                            **statement,
                            "instruction_index": instruction_index,
                            "field_offset": relocation.offset - instruction_start,
                        }
                    )
            if instruction_stream is None:
                if section.number in certified_code_sections:
                    raise ClassicSemanticError(
                        f"{coff.label} certified code section {section.number} has no "
                        "closed instruction partition"
                    )
                # MSVC may place switch tables, inline constants, and padding
                # inside a section named ``.text``.  Without a closed code/data
                # partition, instruction normalization would be an invented
                # theorem.  Retain the section conservatively instead: only an
                # exact relocation-aware runtime image (modulo compiler-local
                # symbol alpha-renaming) can compare equal.
                masked = bytearray(section.body)
                for relocation in section.relocations:
                    width = _RELOCATION_WIDTHS[relocation.relocation_type]
                    masked[relocation.offset : relocation.offset + width] = bytes(width)
                code_relocations.append(
                    {
                        "mode": "opaque-exact",
                        "section": section_topology,
                        "opaque_exact": {
                            "theorem": "relocation-aware-exact-text-section-v1",
                            "masked_body": bytes(masked).hex(),
                            "relocations": [
                                _relocation_statement(
                                    coff,
                                    relocation,
                                    symbols,
                                    include_offset=True,
                                )
                                for relocation in section.relocations
                            ],
                        },
                    }
                )
            else:
                certificate = certified_code_sections.get(section.number)
                if certificate is not None:
                    seen_code_certificates.add(section.number)
                certificate_statement = (
                    {
                        "theorem": certificate.theorem,
                        "certificate": certificate.digest,
                    }
                    if certificate is not None
                    else None
                )
                code_relocations.append(
                    {
                        "mode": "semantic-instructions",
                        "section": section_topology,
                        "instruction_stream": (
                            instruction_stream if certificate is None else [certificate_statement]
                        ),
                        "relocations": (
                            _canonical_multiset(seated_relocations)
                            if certificate is None or not certificate.covers_relocations
                            else _canonical_multiset([certificate_statement])
                        ),
                    }
                )
            code_bodies.append((section.body, section.number))
        elif folded.startswith(_INITIALIZED_DATA_SECTION_PREFIXES):
            if data_certificate_statement is not None:
                initialized_data.append(
                    {
                        "section": section_topology,
                        "semantic_projection": data_certificate_statement,
                    }
                )
            else:
                masked = bytearray(section.body)
                for relocation in section.relocations:
                    width = _RELOCATION_WIDTHS[relocation.relocation_type]
                    masked[relocation.offset : relocation.offset + width] = bytes(width)
                initialized_data.append(
                    {
                        "section": section_topology,
                        "masked_body": bytes(masked).hex(),
                        "relocations": relocations,
                    }
                )
        elif folded.startswith(_UNINITIALIZED_DATA_SECTION_PREFIXES):
            uninitialized_data.append(
                {
                    "section": section_topology,
                    "size": len(section.body),
                    "relocations": relocations,
                }
            )
        elif folded.startswith(_COMPILER_CONTROL_SECTION_PREFIXES):
            compiler_control.append(
                {
                    "section": section_topology,
                    # Unwind/control payloads can change runtime behavior.
                    # A family-specific EH theorem may normalize them before
                    # this boundary; the generic envelope retains them exact.
                    "body": section.body.hex(),
                    "relocations": _canonical_multiset(relocations),
                }
            )
        else:
            raise ClassicSemanticError(
                f"{coff.label} contains unknown runtime section {section.name!r}"
            )
    unused_code_certificates = sorted(set(certified_code_sections) - seen_code_certificates)
    if unused_code_certificates:
        raise ClassicSemanticError(
            f"{coff.label} code certificates do not bind retained code sections: "
            f"{unused_code_certificates}"
        )
    unused_data_certificates = sorted(set(certified_data_sections) - seen_data_certificates)
    if unused_data_certificates:
        raise ClassicSemanticError(
            f"{coff.label} data certificates do not bind retained data sections: "
            f"{unused_data_certificates}"
        )
    directives = _coff_directive_receipt(coff)
    statement = {
        "coff_header": _coff_header_statement(coff),
        "linkage": _linkage_statement(
            coff,
            excluded_sections=excluded_sections,
            excluded_undefineds=excluded_undefineds,
        ),
        "directives": {
            "tokens": list(directives.tokens),
            "default_libraries": list(directives.default_libraries),
            "include_symbols": list(directives.include_symbols),
            "export_symbols": list(directives.export_symbols),
            "merge_sections": [list(item) for item in directives.merge_sections],
            "disallowed_libraries": list(directives.disallowed_libraries),
        },
        "topology": _canonical_multiset(topology),
        "code_relocations": _canonical_multiset(code_relocations),
        "initialized_data": _canonical_multiset(initialized_data),
        "uninitialized_data": _canonical_multiset(uninitialized_data),
        "compiler_control": _canonical_multiset(compiler_control),
        "runtime_roots": _canonical_multiset(runtime_roots),
    }
    return {
        "statement": statement,
        "digest": Digest.from_bytes(canonical_json(statement)),
        "code_bodies": tuple(code_bodies),
    }


def _coff_compiler_congruence_trace(
    clean: _CoffObject,
    effective: _CoffObject,
    *,
    excluded_effective_sections: frozenset[int],
    projection_equivalence: _RuntimeProjectionEquivalence | None = None,
    crt_pull_dependencies: Sequence[_CrtPullLinkerDependency] = (),
    ordered_archive_seed_dependencies: Sequence[_OrderedArchiveSeedDependency] = (),
    compiler_state_identity: Msvc420CompilerIdentity | None = None,
    compiler_state_evidence: CompilerStateCompilerEvidence | None = None,
    compiler_state_projection_required: bool = False,
) -> dict[str, object]:
    if type(compiler_state_projection_required) is not bool:
        raise ClassicSemanticError("compiler-state projection gate is not an exact boolean")
    clean_certificates: dict[int, _CodeProjectionCertificate] = dict(
        projection_equivalence.clean_code_certificates if projection_equivalence is not None else {}
    )
    effective_certificates: dict[int, _CodeProjectionCertificate] = dict(
        projection_equivalence.effective_code_certificates
        if projection_equivalence is not None
        else {}
    )
    clean_data_certificates: dict[int, _DataProjectionCertificate] = dict(
        projection_equivalence.clean_data_certificates if projection_equivalence is not None else {}
    )
    effective_data_certificates: dict[int, _DataProjectionCertificate] = dict(
        projection_equivalence.effective_data_certificates
        if projection_equivalence is not None
        else {}
    )
    invalid_seed_binding_kinds = sorted(
        {
            dependency.binding_kind
            for dependency in ordered_archive_seed_dependencies
            if dependency.binding_kind not in {"function-rel32", "data-dir32"}
        }
    )
    if invalid_seed_binding_kinds:
        raise ClassicSemanticError(
            "ordered archive seed dependencies have unknown binding kinds: "
            f"{invalid_seed_binding_kinds}"
        )
    seed_policies = {dependency.policy for dependency in ordered_archive_seed_dependencies}
    if ordered_archive_seed_dependencies and seed_policies != {_ORDERED_ARCHIVE_SEED_POLICY}:
        raise ClassicSemanticError(
            "ordered archive seed dependencies do not use the exact MSVC 4.20 policy"
        )
    dependency_names = [
        *(dependency.name for dependency in crt_pull_dependencies),
        *(dependency.name for dependency in ordered_archive_seed_dependencies),
    ]
    if len(set(dependency_names)) != len(dependency_names):
        raise ClassicSemanticError("typed helper linker dependency names overlap")
    typed_dependencies = [
        *((dependency.name, dependency.symbol_type) for dependency in crt_pull_dependencies),
        *(
            (dependency.name, dependency.symbol_type)
            for dependency in ordered_archive_seed_dependencies
        ),
    ]
    if len(set(typed_dependencies)) != len(typed_dependencies):
        raise ClassicSemanticError("typed helper linker dependencies overlap")
    data_projection_active = bool(clean_data_certificates or effective_data_certificates)
    if data_projection_active:
        clean_overlap = set(clean_certificates) & set(clean_data_certificates)
        effective_overlap = set(effective_certificates) & set(effective_data_certificates)
        if clean_overlap or effective_overlap:
            raise ClassicSemanticError(
                "dead internal .rdata and code projection certificates overlap sections"
            )
        clean_data_theorems = {
            certificate.theorem for certificate in clean_data_certificates.values()
        }
        effective_data_theorems = {
            certificate.theorem for certificate in effective_data_certificates.values()
        }
        clean_code_theorems = {certificate.theorem for certificate in clean_certificates.values()}
        effective_code_theorems = {
            certificate.theorem for certificate in effective_certificates.values()
        }
        prefix_only = (
            projection_equivalence is not None
            and projection_equivalence.equivalent
            and projection_equivalence.theorem == _DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM
            and clean_data_theorems == {_DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM}
            and effective_data_theorems == {_DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM}
            and not clean_certificates
            and not effective_certificates
        )
        repack_plus_equality = (
            projection_equivalence is not None
            and projection_equivalence.equivalent
            and projection_equivalence.theorem == _DEAD_RDATA_REPACK_EQUALITY_COMPOSITION_THEOREM
            and clean_data_theorems == {_DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM}
            and effective_data_theorems == {_DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM}
            and clean_code_theorems == {_EQUALITY_CMP_PROJECTION_THEOREM}
            and effective_code_theorems == {_EQUALITY_CMP_PROJECTION_THEOREM}
            and bool(clean_certificates)
            and bool(effective_certificates)
        )
        if (
            not (prefix_only or repack_plus_equality)
            or len(clean_data_certificates) != 1
            or len(effective_data_certificates) != 1
            or excluded_effective_sections
            or crt_pull_dependencies
            or ordered_archive_seed_dependencies
        ):
            raise ClassicSemanticError(
                "dead internal .rdata projection has no exact permitted composition "
                "or carries a helper-section exclusion"
            )
    compiler_state_projection: CompilerStateProjection | None = None
    projection_already_proven = bool(
        projection_equivalence is not None and projection_equivalence.equivalent
    )
    if compiler_state_projection_required and not projection_already_proven:
        pairs = _compiler_state_code_pairs(
            clean,
            effective,
            excluded_effective_sections=excluded_effective_sections,
        )
        if pairs:
            if type(compiler_state_identity) is not Msvc420CompilerIdentity:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state code projection lacks its validated compiler identity"
                )
            if compiler_state_evidence is None:
                raise ClassicSemanticError(
                    "MSVC 4.20 compiler-state code projection lacks its locked compiler invocation"
                )
            compiler_state_projection = derive_msvc420_compiler_state_projection(
                pairs,
                compiler_identity=compiler_state_identity,
                compiler_evidence=compiler_state_evidence,
            )
    if compiler_state_projection is not None:
        if projection_equivalence is not None and (
            projection_equivalence.theorem is not None
            or projection_equivalence.proof is not None
            or projection_equivalence.clean_code_certificates
            or projection_equivalence.effective_code_certificates
            or projection_equivalence.clean_data_certificates
            or projection_equivalence.effective_data_certificates
        ):
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state code projection cannot compose with another "
                "runtime projection theorem"
            )
        clean_overlap = set(clean_certificates) & set(compiler_state_projection.clean_certificates)
        effective_overlap = set(effective_certificates) & set(
            compiler_state_projection.effective_certificates
        )
        if clean_overlap or effective_overlap:
            raise ClassicSemanticError(
                "MSVC 4.20 compiler-state code projection overlaps another code theorem"
            )
        clean_certificates.update(
            {
                section: _CodeProjectionCertificate(
                    certificate.theorem,
                    certificate.digest,
                    certificate.covers_relocations,
                )
                for section, certificate in compiler_state_projection.clean_certificates.items()
            }
        )
        effective_certificates.update(
            {
                section: _CodeProjectionCertificate(
                    certificate.theorem,
                    certificate.digest,
                    certificate.covers_relocations,
                )
                for section, certificate in compiler_state_projection.effective_certificates.items()
            }
        )
    clean_envelope = _coff_semantic_envelope(
        clean,
        certified_code_sections=clean_certificates,
        certified_data_sections=clean_data_certificates,
    )
    effective_envelope = _coff_semantic_envelope(
        effective,
        excluded_sections=excluded_effective_sections,
        excluded_undefineds=frozenset(typed_dependencies),
        certified_code_sections=effective_certificates,
        certified_data_sections=effective_data_certificates,
    )
    if clean_envelope["statement"] != effective_envelope["statement"]:
        clean_statement = clean_envelope["statement"]
        effective_statement = effective_envelope["statement"]
        assert isinstance(clean_statement, dict)
        assert isinstance(effective_statement, dict)
        changed = sorted(
            key for key in clean_statement if clean_statement[key] != effective_statement[key]
        )
        raise ClassicSemanticError(
            f"{effective.label} changes the closed COFF semantic envelope: {changed}"
        )
    clean_code = clean_envelope["code_bodies"]
    effective_code = effective_envelope["code_bodies"]
    assert isinstance(clean_code, tuple)
    assert isinstance(effective_code, tuple)
    changed_code_sections = sum(
        1
        for (clean_body, _), (effective_body, _) in zip(clean_code, effective_code, strict=False)
        if clean_body != effective_body
    ) + abs(len(clean_code) - len(effective_code))
    digest = clean_envelope["digest"]
    assert isinstance(digest, Digest)
    allowed_deltas = [
        "proven-direction-bit-register-code-encoding",
        "code-relocation-seat-preserving-offset",
        "runtime-section-seat-and-order",
        "typed-msvc-static-local-serial-alpha-renaming",
    ]
    certificate_theorems = {certificate.theorem for certificate in clean_certificates.values()}
    if _EQUALITY_CMP_PROJECTION_THEOREM in certificate_theorems:
        allowed_deltas.append("equality-only-cmp-operand-reversal-with-dead-flags")
    if _REGISTER_TRANSPOSITION_PROJECTION_THEOREM in certificate_theorems:
        allowed_deltas.append("two-register-transposition-over-one-dead-boundary-region")
    if (
        projection_equivalence is not None
        and projection_equivalence.theorem == _COMPILER_LOCAL_ALPHA_PROJECTION_THEOREM
    ):
        allowed_deltas.append("compiler-local-symbol-alpha-renaming")
    if (
        projection_equivalence is not None
        and projection_equivalence.theorem == _DATA_COMDAT_PERMUTATION_PROJECTION_THEOREM
    ):
        allowed_deltas.extend(
            [
                "independent-relocation-free-data-comdat-order",
                "compiler-local-symbol-alpha-renaming",
            ]
        )
    if data_projection_active:
        data_theorems = {certificate.theorem for certificate in clean_data_certificates.values()}
        if _DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM in data_theorems:
            allowed_deltas.append(
                "dead-internal-readonly-data-owner-permutation-and-alignment-repack"
            )
        else:
            allowed_deltas.append("dead-internal-readonly-data-prefix-and-clean-data-reseat")
    if crt_pull_dependencies:
        allowed_deltas.append("typed-unreachable-crt-linker-dependency")
    if ordered_archive_seed_dependencies:
        allowed_deltas.append("typed-ordered-archive-seed-dependency")
    if compiler_state_projection is not None:
        allowed_deltas.append("typed-msvc-4.20-compiler-state-code-image")
    preserved_dependencies = (
        "all-other-undefined-dependencies" if typed_dependencies else "undefined-dependency-set"
    )
    initialized_data_preservation = (
        "all-other-relocation-aware-initialized-data"
        if data_projection_active
        else "relocation-aware-initialized-data"
    )
    result: dict[str, object] = {
        "theorem": "closed-source-compiler-congruence-coff-envelope-v1",
        "semantic_envelope_digest": digest.model_dump(mode="json"),
        "changed_code_section_count": changed_code_sections,
        "allowed_deltas": allowed_deltas,
        "preserved": [
            "exports-and-linker-directives",
            "external-common-weak-and-absolute-linkage",
            preserved_dependencies,
            "comdat-selection-and-association",
            "relocation-target-type-addend-semantics",
            initialized_data_preservation,
            "uninitialized-data-size",
            "startup-crt-tls-and-runtime-root-sections",
        ],
    }
    if crt_pull_dependencies:
        result["crt_pull_linker_dependencies"] = [
            {
                "name": dependency.name,
                "type": dependency.symbol_type,
                "helper_sections": list(dependency.helper_sections),
                "relocation_sites": [
                    {
                        "section": section,
                        "offset": offset,
                        "type": relocation_type,
                        "addend": addend,
                    }
                    for section, offset, relocation_type, addend in dependency.relocation_sites
                ],
            }
            for dependency in crt_pull_dependencies
        ]
    if ordered_archive_seed_dependencies:
        result["ordered_archive_seed_dependencies"] = [
            {
                "theorem": "ordered-archive-seed-undefined-binding-v1",
                "helper_identifier": dependency.helper_identifier,
                "helper_symbol": dependency.helper_symbol,
                "helper_section": dependency.helper_section,
                "policy": dependency.policy,
                "binding_kind": dependency.binding_kind,
                "name": dependency.name,
                "type": dependency.symbol_type,
                "relocation_offset": dependency.relocation_offset,
                "relocation_type": dependency.relocation_type,
                "addend": dependency.addend,
                "first_use_ordinal": dependency.first_use_ordinal,
                "undefined_symbol_index": dependency.undefined_symbol_index,
                "undefined_row_ordinal": dependency.undefined_row_ordinal,
            }
            for dependency in ordered_archive_seed_dependencies
        ]
    if projection_equivalence is not None and projection_equivalence.proof is not None:
        result["relational_projection_proof"] = dict(projection_equivalence.proof)
    if compiler_state_projection is not None:
        result["compiler_state_projection_proof"] = dict(compiler_state_projection.proof)
    return result


__all__ = [
    "ClassicCoffLineNumberCorrespondence",
    "ClassicCoffLineNumberDelta",
    "ClassicLinkRelevantCoffProjection",
    "classic_link_relevant_coff_projection",
    "prove_classic_coff_line_number_correspondence",
]
