"""Strict COFF projections: data COMDAT permutation and dead-.rdata projection proofs."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from types import MappingProxyType

from reprobit.classic.coff_evidence import (
    _coff_directive_receipt,
    _CoffObject,
    _CoffSection,
    _CoffSymbol,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

from .coff_projection_envelope import _coff_semantic_envelope
from .coff_projection_runtime import (
    _DATA_COMDAT_PERMUTATION_PROJECTION_THEOREM,
    _DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM,
    _DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM,
    _DataProjectionCertificate,
    _DataProjectionComponent,
    _has_retained_relocation_touching,
    _retained_runtime_sections,
    _runtime_projection_symbols,
    _runtime_symbols_outside_section,
    _RuntimeProjectionEquivalence,
    _StaticDataOwnerImage,
)
from .coff_projection_statements import (
    _compiler_local_definition_kind,
    _is_section_symbol,
    _linkage_statement,
    _msvc_static_serial_stem,
    _ordinary_readonly_rdata_section,
    _relocation_statement,
    _section_topology_statement,
    _symbols_by_section,
)


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
