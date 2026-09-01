"""Strict COFF projections: code projection proofs and runtime projection equivalence."""

from __future__ import annotations

from types import MappingProxyType

from reprobit.binary import ByteIdentityError
from reprobit.classic.coff_evidence import (
    _coff_directive_receipt,
    _CoffObject,
    _CoffSection,
)
from reprobit.classic.register_bijection import apply_register_bijection
from reprobit.classic.register_semantics import (
    IA32_GENERAL_REGISTER_NAMES,
    decode_ia32_bijection_body,
)
from reprobit.classic.relational_projection import (
    derive_equality_compare_reversals,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

from .coff_projection_data import (
    _compiler_local_permutation_alpha_proof,
    _data_comdat_permutation_proof,
    _dead_internal_rdata_prefix_projection,
    _dead_internal_rdata_repack_component,
    _section_permutation_identity,
)
from .coff_projection_envelope import _coff_semantic_envelope
from .coff_projection_runtime import (
    _COMPILER_LOCAL_ALPHA_PROJECTION_THEOREM,
    _DATA_COMDAT_PERMUTATION_PROJECTION_THEOREM,
    _DEAD_RDATA_REPACK_EQUALITY_COMPOSITION_THEOREM,
    _EQUALITY_CMP_PROJECTION_THEOREM,
    _REGISTER_TRANSPOSITION_PROJECTION_THEOREM,
    _alpha_normalized_runtime_projections,
    _CodeProjectionCertificate,
    _DataProjectionCertificate,
    _external_function_owner,
    _relational_external_entries,
    _retained_relocation_entries_into,
    _retained_runtime_sections,
    _runtime_projection,
    _RuntimeProjectionEquivalence,
)
from .coff_projection_statements import (
    _CODE_SECTION_PREFIXES,
    _RELOCATION_WIDTHS,
    _coff_header_statement,
    _linkage_statement,
    _symbols_by_section,
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
