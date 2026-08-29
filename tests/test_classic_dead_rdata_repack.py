from __future__ import annotations

import struct
from dataclasses import replace

import pytest

from reprobit.classic.coff_evidence import (
    _CoffObject,
    _CoffRelocation,
    _CoffSection,
    _CoffSymbol,
    _parse_coff,
)
from reprobit.classic.coff_projection import (
    _CodeProjectionCertificate,
    _coff_compiler_congruence_trace,
    _coff_semantic_envelope,
    _CrtPullLinkerDependency,
    _runtime_projection_equivalence_proof,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest

_ROTATE_INDEX = bytes.fromhex("010000000200000000000000")
_PI = bytes.fromhex("182d4454fb210940")
_CLEAN_RDATA = _ROTATE_INDEX + bytes(4) + _PI
_EFFECTIVE_RDATA = _PI + _ROTATE_INDEX
_CLEAN_CODE = bytes.fromhex("390d000000007400390d000000007500c3")
_EFFECTIVE_CODE = bytes.fromhex("3b0d0000000074003b0d000000007500c3")
_RDATA_CHARACTERISTICS = 0x40400040
_COMPOSITE_THEOREM = "dead-rdata-repack-plus-equality-cmp-composition-v1"
_DATA_THEOREM = "dead-internal-rdata-static-owner-permutation-alignment-repack-v1"
_CODE_THEOREM = "ia32-equality-compare-operand-reversal-flags-dead-v1"


def _symbol(
    index: int,
    name: str,
    *,
    value: int,
    section: int,
    symbol_type: int = 0,
    storage: int = 3,
    auxiliary: bytes = b"",
) -> _CoffSymbol:
    return _CoffSymbol(
        index,
        name,
        value,
        section,
        symbol_type,
        storage,
        len(auxiliary) // 18,
        auxiliary,
    )


def _section(
    number: int,
    name: str,
    body: bytes,
    *,
    characteristics: int,
    relocations: tuple[_CoffRelocation, ...] = (),
    selection: int | None = 0,
) -> _CoffSection:
    return _CoffSection(
        number,
        name,
        body,
        characteristics,
        (),
        relocations,
        selection,
        0,
    )


def _code_relocations() -> tuple[_CoffRelocation, ...]:
    return (
        _CoffRelocation(2, 6, 6, "_Nil", 0, 0, 0, 2, bytes(4)),
        _CoffRelocation(10, 6, 6, "_Nil", 0, 0, 0, 2, bytes(4)),
    )


def _object(
    label: str,
    *,
    rdata: bytes,
    effective_owner_order: bool,
    code: bytes,
    local_name: str,
    directive: bytes = b"-defaultlib:LIBCMT ",
) -> _CoffObject:
    if effective_owner_order:
        owners = (
            _symbol(2, "_rotateIndex$S50167", value=8, section=2),
            _symbol(3, "_Pi$S34392", value=0, section=2),
        )
    else:
        owners = (
            _symbol(2, "_Pi$S42510", value=16, section=2),
            _symbol(3, "_rotateIndex$S34684", value=0, section=2),
        )
    sections = (
        _section(1, ".drectve", directive, characteristics=0x00100A00),
        _section(2, ".rdata", rdata, characteristics=_RDATA_CHARACTERISTICS),
        _section(
            3,
            ".text",
            code,
            characteristics=0x60000020,
            relocations=_code_relocations(),
        ),
    )
    symbols = (
        _symbol(
            0,
            ".rdata",
            value=0,
            section=2,
            auxiliary=len(rdata).to_bytes(4, "little") + bytes(14),
        ),
        *owners,
        _symbol(5, "_entry", value=0, section=3, symbol_type=0x20, storage=2),
        _symbol(6, "_Nil", value=0, section=0, storage=2),
        _symbol(7, local_name, value=16, section=3, storage=6),
    )
    digest_material = label.encode("ascii") + b"".join(section.body for section in sections)
    return _CoffObject(
        label,
        Digest.from_bytes(digest_material),
        0,
        sections,
        symbols,
    )


def _pair(
    *,
    clean_rdata: bytes = _CLEAN_RDATA,
    effective_rdata: bytes = _EFFECTIVE_RDATA,
    clean_code: bytes = _CLEAN_CODE,
    effective_code: bytes = _EFFECTIVE_CODE,
    directive: bytes = b"-defaultlib:LIBCMT ",
) -> tuple[_CoffObject, _CoffObject]:
    return (
        _object(
            "counterfactual.obj",
            rdata=clean_rdata,
            effective_owner_order=False,
            code=clean_code,
            local_name="$L100",
            directive=directive,
        ),
        _object(
            "effective.obj",
            rdata=effective_rdata,
            effective_owner_order=True,
            code=effective_code,
            local_name="$L900",
            directive=directive,
        ),
    )


def _with_text_definition(coff: _CoffObject, *, checksum: int = 0) -> _CoffObject:
    text = coff.sections[2]
    auxiliary = struct.pack(
        "<IHHIhBBH",
        len(text.body),
        len(text.relocations),
        len(text.line_numbers),
        checksum,
        0,
        0,
        0,
        0,
    )
    return replace(
        coff,
        symbols=(*coff.symbols, _symbol(8, ".text", value=0, section=3, auxiliary=auxiliary)),
    )


def _replace_section(coff: _CoffObject, number: int, **changes: object) -> _CoffObject:
    return replace(
        coff,
        sections=tuple(
            replace(section, **changes) if section.number == number else section
            for section in coff.sections
        ),
    )


def test_real_flc_layout_composes_dead_repack_with_two_relocated_equality_cmps() -> None:
    clean, effective = _pair()

    equivalence = _runtime_projection_equivalence_proof(clean, effective)

    assert equivalence.equivalent is True
    assert equivalence.byte_equal is False
    assert equivalence.theorem == _COMPOSITE_THEOREM
    assert set(equivalence.clean_data_certificates) == {2}
    assert set(equivalence.clean_code_certificates) == {3}
    assert equivalence.clean_data_certificates[2].theorem == _DATA_THEOREM
    assert equivalence.clean_code_certificates[3].theorem == _CODE_THEOREM
    assert equivalence.proof is not None
    data = equivalence.proof["data_component"]
    assert data["alignment"] == 8
    assert data["clean_size"] == 24
    assert data["effective_size"] == 20
    assert data["section_definition"] == {
        "clean_length": 24,
        "effective_length": 20,
        "shared_non_length_auxiliary": bytes(14).hex(),
    }
    assert data["clean_order"] == ["_rotateIndex", "_Pi"]
    assert data["effective_order"] == ["_Pi", "_rotateIndex"]
    owners = {item["stable_name"]: item for item in data["owners"]}
    assert owners["_Pi"]["core_size"] == 8
    assert owners["_rotateIndex"]["core_size"] == 12
    assert owners["_rotateIndex"]["clean"]["alignment_tail_size"] == 4
    assert owners["_rotateIndex"]["effective"]["alignment_tail_size"] == 0
    assert equivalence.proof["compiler_local_alpha_renames"] == [
        {
            "symbol_index": 7,
            "compiler_local_kind": "L",
            "clean_section": 3,
            "effective_section": 3,
            "value": 16,
        }
    ]
    code_proof = equivalence.proof["code_sections"][0]["proof"]
    assert [site["compare_offset"] for site in code_proof["sites"]] == [0, 8]
    assert code_proof["preserved_flags"] == ["zf"]

    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=frozenset(),
        projection_equivalence=equivalence,
        compiler_state_projection_required=True,
    )
    assert "equality-only-cmp-operand-reversal-with-dead-flags" in trace["allowed_deltas"]
    assert (
        "dead-internal-readonly-data-owner-permutation-and-alignment-repack"
        in trace["allowed_deltas"]
    )
    assert "compiler_state_projection_proof" not in trace


@pytest.mark.parametrize(
    ("clean_rdata", "effective_rdata"),
    (
        (_ROTATE_INDEX + b"\x01\0\0\0" + _PI, _EFFECTIVE_RDATA),
        (_CLEAN_RDATA, _PI + _ROTATE_INDEX[:-1] + b"\x01"),
        (_CLEAN_RDATA, _PI + _ROTATE_INDEX + bytes(8)),
    ),
    ids=("nonzero-alignment-tail", "mutated-owner-core", "unowned-effective-suffix"),
)
def test_repack_rejects_every_owner_image_widening(
    clean_rdata: bytes,
    effective_rdata: bytes,
) -> None:
    clean, effective = _pair(
        clean_rdata=clean_rdata,
        effective_rdata=effective_rdata,
    )

    equivalence = _runtime_projection_equivalence_proof(clean, effective)

    assert equivalence.equivalent is False
    assert equivalence.theorem is None


def test_repack_rejects_an_owner_stem_mismatch_or_external_owner() -> None:
    clean, effective = _pair()
    mismatched = replace(
        effective,
        symbols=tuple(
            replace(symbol, name="_Tau$S34392") if symbol.name == "_Pi$S34392" else symbol
            for symbol in effective.symbols
        ),
    )
    external = replace(
        effective,
        symbols=tuple(
            replace(symbol, storage=2) if symbol.name == "_Pi$S34392" else symbol
            for symbol in effective.symbols
        ),
    )

    assert not _runtime_projection_equivalence_proof(clean, mismatched).equivalent
    assert not _runtime_projection_equivalence_proof(clean, external).equivalent


def test_repack_rejects_non_length_rdata_section_auxiliary_drift() -> None:
    clean, effective = _pair()
    effective = replace(
        effective,
        symbols=tuple(
            replace(
                symbol,
                auxiliary=symbol.auxiliary[:8] + b"\x01" + symbol.auxiliary[9:],
            )
            if symbol.name == ".rdata"
            else symbol
            for symbol in effective.symbols
        ),
    )

    equivalence = _runtime_projection_equivalence_proof(clean, effective)

    assert equivalence.equivalent is False
    assert equivalence.theorem is None


def test_repack_requires_a_genuine_owner_permutation() -> None:
    clean, effective = _pair(effective_rdata=_CLEAN_RDATA)
    effective = replace(
        effective,
        symbols=tuple(
            replace(symbol, value=16, name="_Pi$S34392")
            if symbol.name == "_Pi$S34392"
            else replace(symbol, value=0, name="_rotateIndex$S50167")
            if symbol.name == "_rotateIndex$S50167"
            else symbol
            for symbol in effective.symbols
        ),
    )

    assert not _runtime_projection_equivalence_proof(clean, effective).equivalent


def test_repack_rejects_retained_inbound_or_outbound_relocations() -> None:
    clean, effective = _pair()
    inbound = _CoffRelocation(0, 6, 0, ".rdata", 2, 0, 0, 3, bytes(4))
    effective_inbound = _replace_section(
        effective,
        3,
        relocations=(*effective.sections[2].relocations, inbound),
    )
    outbound = _CoffRelocation(0, 6, 6, "_Nil", 0, 0, 0, 2, bytes(4))
    effective_outbound = _replace_section(effective, 2, relocations=(outbound,))

    assert not _runtime_projection_equivalence_proof(clean, effective_inbound).equivalent
    assert not _runtime_projection_equivalence_proof(clean, effective_outbound).equivalent


@pytest.mark.parametrize("case", ("writable", "comdat", "merged"))
def test_repack_rejects_nonordinary_or_merged_rdata(case: str) -> None:
    clean, effective = _pair(
        directive=(b"/merge:.rdata=.text " if case == "merged" else b"-defaultlib:LIBCMT ")
    )
    if case == "writable":
        clean = _replace_section(
            clean,
            2,
            characteristics=_RDATA_CHARACTERISTICS | 0x80000000,
        )
        effective = _replace_section(
            effective,
            2,
            characteristics=_RDATA_CHARACTERISTICS | 0x80000000,
        )
    elif case == "comdat":
        clean = _replace_section(
            clean,
            2,
            characteristics=_RDATA_CHARACTERISTICS | 0x1000,
            comdat_selection=2,
        )
        effective = _replace_section(
            effective,
            2,
            characteristics=_RDATA_CHARACTERISTICS | 0x1000,
            comdat_selection=2,
        )

    assert not _runtime_projection_equivalence_proof(clean, effective).equivalent


def test_repack_composes_only_with_equality_cmp_code() -> None:
    unsafe_clean = _CLEAN_CODE.replace(b"\x74\x00", b"\x72\x00", 1)
    unsafe_effective = _EFFECTIVE_CODE.replace(b"\x74\x00", b"\x72\x00", 1)
    clean, effective = _pair(
        clean_code=unsafe_clean,
        effective_code=unsafe_effective,
    )

    equivalence = _runtime_projection_equivalence_proof(clean, effective)

    assert equivalence.equivalent is False
    assert equivalence.theorem is None


@pytest.mark.parametrize("case", ("directive", "relocation-seat", "code-owner"))
def test_repack_composition_leaves_residual_coff_equality_authoritative(case: str) -> None:
    clean, effective = _pair()
    if case == "directive":
        effective = _replace_section(effective, 1, body=b"-defaultlib:OLDNAMES ")
    elif case == "relocation-seat":
        relocations = effective.sections[2].relocations
        effective = _replace_section(
            effective,
            3,
            relocations=(replace(relocations[0], offset=3), relocations[1]),
        )
    else:
        effective = replace(
            effective,
            symbols=tuple(
                replace(symbol, name="_other_entry") if symbol.name == "_entry" else symbol
                for symbol in effective.symbols
            ),
        )

    equivalence = _runtime_projection_equivalence_proof(clean, effective)

    assert equivalence.equivalent is False
    assert equivalence.theorem is None


def test_repack_composition_rejects_text_section_definition_checksum_drift() -> None:
    clean, effective = _pair()
    clean = _with_text_definition(clean)
    effective = _with_text_definition(effective, checksum=0x10203040)

    equivalence = _runtime_projection_equivalence_proof(clean, effective)

    assert equivalence.equivalent is False
    assert equivalence.theorem is None


def test_repack_composition_rejects_helper_exclusions_and_dependencies() -> None:
    clean, effective = _pair()
    helper = _section(4, ".text$helper", b"\xc3", characteristics=0x60000020)
    effective_with_helper = replace(effective, sections=(*effective.sections, helper))
    excluded = _runtime_projection_equivalence_proof(
        clean,
        effective_with_helper,
        excluded_effective_sections=frozenset({4}),
    )
    assert excluded.equivalent is False

    equivalence = _runtime_projection_equivalence_proof(clean, effective)
    with pytest.raises(ClassicSemanticError, match="no exact permitted composition"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=frozenset(),
            projection_equivalence=equivalence,
            crt_pull_dependencies=(_CrtPullLinkerDependency("_pull", 0, (4,), ()),),
        )


def test_repack_coordinator_rejects_non_equality_or_overlapping_code_certificate() -> None:
    clean, effective = _pair()
    equivalence = _runtime_projection_equivalence_proof(clean, effective)
    other = _CodeProjectionCertificate("other-code-theorem", "0" * 64)
    wrong_theorem = replace(
        equivalence,
        clean_code_certificates={3: other},
        effective_code_certificates={3: other},
    )
    overlap = replace(
        equivalence,
        clean_code_certificates={2: other},
        effective_code_certificates={2: other},
    )

    with pytest.raises(ClassicSemanticError, match="no exact permitted composition"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=frozenset(),
            projection_equivalence=wrong_theorem,
        )
    with pytest.raises(ClassicSemanticError, match="overlap sections"):
        _coff_compiler_congruence_trace(
            clean,
            effective,
            excluded_effective_sections=frozenset(),
            projection_equivalence=overlap,
        )


def _canonical_section_object(
    section_name: str,
    *,
    header_characteristics: int = 0,
    definition_type: int = 0,
    definition_length: int | None = None,
    definition_relocations: int = 0,
    definition_lines: int = 0,
    checksum: int = 0,
    duplicate_definition: bool = False,
) -> bytes:
    body = b"\xc3" if section_name == ".text" else bytes.fromhex("78563412")
    raw_offset = 60
    symbol_offset = raw_offset + len(body)
    characteristics = 0x60000020 if section_name == ".text" else _RDATA_CHARACTERISTICS
    owner = b"_entry\0\0" if section_name == ".text" else b"_value\0\0"
    definition = section_name.encode("ascii").ljust(8, b"\0") + struct.pack(
        "<IhHBB",
        0,
        1,
        definition_type,
        3,
        1,
    )
    auxiliary = struct.pack(
        "<IHHIhBBH",
        len(body) if definition_length is None else definition_length,
        definition_relocations,
        definition_lines,
        checksum,
        0,
        0,
        0,
        0,
    )
    owner_symbol = owner + struct.pack(
        "<IhHBB",
        0,
        1,
        0x20 if section_name == ".text" else 0,
        2 if section_name == ".text" else 3,
        0,
    )
    definitions = definition + auxiliary
    if duplicate_definition:
        definitions += definition + auxiliary
    symbol_table = definitions + owner_symbol
    symbol_count = 5 if duplicate_definition else 3
    header = struct.pack(
        "<HHIIIHH",
        0x14C,
        1,
        0,
        symbol_offset,
        symbol_count,
        0,
        header_characteristics,
    )
    section = section_name.encode("ascii").ljust(8, b"\0") + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        raw_offset,
        0,
        0,
        0,
        0,
        characteristics,
    )
    return header + section + body + symbol_table + struct.pack("<I", 4)


@pytest.mark.parametrize("section_name", (".text", ".rdata"))
def test_parser_rejects_a_typed_section_definition_candidate(
    section_name: str,
) -> None:
    payload = _canonical_section_object(section_name, definition_type=0x20)

    with pytest.raises(ClassicSemanticError, match="definition symbol is non-canonical"):
        _parse_coff(payload, f"typed-{section_name}.obj")


@pytest.mark.parametrize(
    "changes",
    (
        {"definition_length": 2},
        {"definition_relocations": 1},
        {"definition_lines": 1},
    ),
    ids=("length", "relocation-count", "line-count"),
)
def test_parser_rejects_text_definition_size_or_table_count_drift(
    changes: dict[str, int],
) -> None:
    payload = _canonical_section_object(".text", **changes)

    with pytest.raises(
        ClassicSemanticError,
        match="definition length or table counts differ",
    ):
        _parse_coff(payload, "drifted-text-definition.obj")


def test_parser_rejects_duplicate_section_definitions() -> None:
    payload = _canonical_section_object(".text", duplicate_definition=True)

    with pytest.raises(ClassicSemanticError, match="duplicate definition symbols"):
        _parse_coff(payload, "duplicate-text-definition.obj")


def test_parser_keeps_coff_header_flags_distinct_from_section_flags() -> None:
    baseline = _parse_coff(
        _canonical_section_object(".rdata"),
        "baseline-header.obj",
    )
    changed = _parse_coff(
        _canonical_section_object(".rdata", header_characteristics=0x0100),
        "changed-header.obj",
    )

    assert baseline.header_characteristics == 0
    assert changed.header_characteristics == 0x0100
    assert baseline.sections == changed.sections
    assert changed.sections[0].characteristics == _RDATA_CHARACTERISTICS


def test_runtime_projection_rejects_parsed_coff_header_only_flag_drift() -> None:
    baseline = _parse_coff(
        _canonical_section_object(".rdata"),
        "baseline-header.obj",
    )
    changed = _parse_coff(
        _canonical_section_object(".rdata", header_characteristics=0x0100),
        "changed-header.obj",
    )

    equivalence = _runtime_projection_equivalence_proof(baseline, changed)

    assert equivalence.equivalent is False
    assert equivalence.theorem is None


def test_runtime_projection_rejects_code_theorem_plus_coff_header_flag_drift() -> None:
    clean, _effective = _pair()
    changed = replace(
        _replace_section(clean, 3, body=_EFFECTIVE_CODE),
        label="code-plus-header.obj",
        header_characteristics=0x0100,
    )

    equivalence = _runtime_projection_equivalence_proof(clean, changed)

    assert equivalence.equivalent is False
    assert equivalence.theorem is None


def test_compiler_congruence_rejects_parsed_coff_header_only_flag_drift() -> None:
    baseline = _parse_coff(
        _canonical_section_object(".rdata"),
        "baseline-header.obj",
    )
    changed = _parse_coff(
        _canonical_section_object(".rdata", header_characteristics=0x0100),
        "changed-header.obj",
    )

    with pytest.raises(ClassicSemanticError, match="closed COFF semantic envelope"):
        _coff_compiler_congruence_trace(
            baseline,
            changed,
            excluded_effective_sections=frozenset(),
        )


def test_repack_rejects_coff_header_only_flag_drift() -> None:
    clean, effective = _pair()
    effective = replace(effective, header_characteristics=0x0100)

    equivalence = _runtime_projection_equivalence_proof(clean, effective)

    assert equivalence.equivalent is False
    assert equivalence.theorem is None


def test_ordinary_semantic_envelope_binds_section_definition_checksum() -> None:
    baseline = _parse_coff(_canonical_section_object(".text"), "baseline-text.obj")
    changed = _parse_coff(
        _canonical_section_object(".text", checksum=0x10203040),
        "changed-text.obj",
    )

    assert _coff_semantic_envelope(baseline) != _coff_semantic_envelope(changed)
