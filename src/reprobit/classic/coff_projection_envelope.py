"""Strict COFF projections: the semantic envelope of a compiled object."""

from __future__ import annotations

from collections.abc import Mapping

from reprobit.classic.coff_evidence import (
    _coff_directive_receipt,
    _CoffObject,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest
from reprobit.strict_json import canonical_json

from .coff_projection_runtime import (
    _DEAD_INTERNAL_RDATA_PREFIX_PROJECTION_THEOREM,
    _DEAD_INTERNAL_RDATA_REPACK_PROJECTION_THEOREM,
    _FORBIDDEN_RUNTIME_SECTION_PREFIXES,
    _CodeProjectionCertificate,
    _DataProjectionCertificate,
)
from .coff_projection_statements import (
    _CODE_SECTION_PREFIXES,
    _COMPILER_CONTROL_SECTION_PREFIXES,
    _INITIALIZED_DATA_SECTION_PREFIXES,
    _RELOCATION_WIDTHS,
    _UNINITIALIZED_DATA_SECTION_PREFIXES,
    _canonical_multiset,
    _coff_header_statement,
    _linkage_statement,
    _ordinary_readonly_rdata_section,
    _relocation_statement,
    _section_definition_statement,
    _section_topology_statement,
    _semantic_code_stream,
    _SemanticCodePartitionError,
    _symbols_by_section,
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
