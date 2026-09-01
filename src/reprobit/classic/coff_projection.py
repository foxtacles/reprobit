"""Strict COFF projections and closed compiler-congruence proofs."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from reprobit.classic.coff_evidence import (
    _coff_directive_receipt,
    _CoffObject,
    _CoffSection,
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
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

from .coff_projection_envelope import _coff_semantic_envelope
from .coff_projection_runtime import (
    _COMPILER_LOCAL_ALPHA_PROJECTION_THEOREM,
    _DATA_COMDAT_PERMUTATION_PROJECTION_THEOREM,
    _DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM,
    _DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM,
    _DEAD_RDATA_REPACK_EQUALITY_COMPOSITION_THEOREM,
    _EQUALITY_CMP_PROJECTION_THEOREM,
    _REGISTER_TRANSPOSITION_PROJECTION_THEOREM,
    _CodeProjectionCertificate,
    _DataProjectionCertificate,
    _external_function_owner,
    _relational_external_entries,
    _retained_runtime_sections,
    _runtime_projection,
    _RuntimeProjectionEquivalence,
)
from .coff_projection_statements import (
    _CODE_SECTION_PREFIXES,
    _associated_debug_evidence_statement,
    _associated_eh_control_statement,
    _associated_fpo_evidence_statement,
    _coff_header_statement,
    _linkage_statement,
    _relocation_statement,
    _section_topology_statement,
    _symbols_by_section,
)


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
