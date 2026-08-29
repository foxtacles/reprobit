from __future__ import annotations

from dataclasses import replace

import pytest

from reprobit.classic.coff_evidence import (
    _CoffObject,
    _CoffRelocation,
    _CoffSection,
    _CoffSymbol,
)
from reprobit.classic.coff_projection import (
    _CodeProjectionCertificate,
    _coff_compiler_congruence_trace,
    _coff_semantic_envelope,
    _runtime_projection_equivalence_proof,
)
from reprobit.classic.semantic_errors import ClassicSemanticError
from reprobit.model import Digest

_CLEAN_DATA = bytes.fromhex("010000000200000000000000")
_PREFIX = bytes.fromhex("182d4454fb210940")
_RDATA_CHARACTERISTICS = 0x40400040


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


def _section_symbol(index: int, size: int, *, name: str = ".rdata") -> _CoffSymbol:
    return _symbol(
        index,
        name,
        value=0,
        section=2,
        auxiliary=size.to_bytes(4, "little") + bytes(14),
    )


def _section(
    number: int,
    name: str,
    body: bytes,
    *,
    characteristics: int,
    relocations: tuple[_CoffRelocation, ...] = (),
    selection: int | None = 0,
    associated: int | None = 0,
) -> _CoffSection:
    return _CoffSection(
        number,
        name,
        body,
        characteristics,
        (),
        relocations,
        selection,
        associated,
    )


def _object(
    label: str,
    *,
    data: bytes,
    data_owners: tuple[_CoffSymbol, ...],
    directive: bytes = b"/DEFAULTLIB:LIBCMT ",
) -> _CoffObject:
    sections = (
        _section(1, ".drectve", directive, characteristics=0x00100A00),
        _section(2, ".rdata", data, characteristics=_RDATA_CHARACTERISTICS),
        _section(3, ".text", b"\xc3", characteristics=0x60000020),
    )
    symbols = (
        _section_symbol(0, len(data)),
        *data_owners,
        _symbol(
            max((owner.index for owner in data_owners), default=1) + 1,
            "_entry",
            value=0,
            section=3,
            symbol_type=0x20,
            storage=2,
        ),
    )
    digest_material = label.encode() + b"".join(section.body for section in sections)
    return _CoffObject(label, Digest.from_bytes(digest_material), 0, sections, symbols)


def _pair(
    *,
    clean_data: bytes = _CLEAN_DATA,
    prefix: bytes = _PREFIX,
    effective_data: bytes | None = None,
) -> tuple[_CoffObject, _CoffObject]:
    clean = _object(
        "clean.obj",
        data=clean_data,
        data_owners=(_symbol(2, "_rotateIndex$S1", value=0, section=2),),
    )
    effective = _object(
        "effective.obj",
        data=(prefix + clean_data if effective_data is None else effective_data),
        data_owners=(
            _symbol(2, "_rotateIndex$S2", value=len(prefix), section=2),
            _symbol(3, "_Pi$S3", value=0, section=2),
        ),
    )
    return clean, effective


def _replace_section(coff: _CoffObject, number: int, **changes: object) -> _CoffObject:
    return replace(
        coff,
        sections=tuple(
            replace(section, **changes) if section.number == number else section
            for section in coff.sections
        ),
    )


def _replace_rdata_body(coff: _CoffObject, body: bytes) -> _CoffObject:
    coff = _replace_section(coff, 2, body=body)
    return replace(
        coff,
        symbols=tuple(
            replace(symbol, auxiliary=len(body).to_bytes(4, "little") + bytes(14))
            if symbol.name == ".rdata"
            else symbol
            for symbol in coff.symbols
        ),
    )


def test_dead_static_prefix_reseats_clean_rdata_and_rejoins_envelope() -> None:
    clean, effective = _pair()

    equivalence = _runtime_projection_equivalence_proof(clean, effective)

    assert equivalence.equivalent is True
    assert equivalence.byte_equal is False
    assert equivalence.theorem == "dead-internal-rdata-prefix-carrier-reseat-v1"
    assert equivalence.proof is not None
    assert equivalence.proof["prefix_size"] == len(_PREFIX)
    assert equivalence.proof["added_owner"]["name"] == "_Pi$S3"
    assert (
        _coff_semantic_envelope(clean)["statement"]
        != _coff_semantic_envelope(effective)["statement"]
    )

    trace = _coff_compiler_congruence_trace(
        clean,
        effective,
        excluded_effective_sections=frozenset(),
        projection_equivalence=equivalence,
    )

    assert "dead-internal-readonly-data-prefix-and-clean-data-reseat" in trace["allowed_deltas"]
    assert (
        trace["relational_projection_proof"]["clean_data_digest"]
        == (equivalence.proof["clean_data_digest"])
    )


def _adversarial_pair(case: str) -> tuple[_CoffObject, _CoffObject]:
    if case == "ambiguous-clean-image":
        return _pair(clean_data=b"AB", prefix=b"AB")
    clean, effective = _pair()
    if case in {"external-carrier", "weak-carrier", "untyped-carrier"}:
        storage = {"external-carrier": 2, "weak-carrier": 105}.get(case, 3)
        effective = replace(
            effective,
            symbols=tuple(
                replace(
                    symbol,
                    storage=storage,
                    name=("_Pi" if case == "untyped-carrier" else symbol.name),
                )
                if symbol.name == "_Pi$S3"
                else symbol
                for symbol in effective.symbols
            ),
        )
    elif case == "inbound-section-addend":

        def add_inbound(coff: _CoffObject) -> _CoffObject:
            relocation = _CoffRelocation(1, 6, 0, ".rdata", 2, 0, 0, 3, (4).to_bytes(4, "little"))
            return _replace_section(
                coff,
                3,
                body=b"\xa1\0\0\0\0\xc3",
                relocations=(relocation,),
            )

        clean, effective = add_inbound(clean), add_inbound(effective)
    elif case == "outbound-relocation":

        def add_outbound(coff: _CoffObject) -> _CoffObject:
            target = next(symbol for symbol in coff.symbols if symbol.name == "_entry")
            relocation = _CoffRelocation(0, 6, target.index, target.name, 3, 0, 0x20, 2, bytes(4))
            return _replace_section(coff, 2, relocations=(relocation,))

        clean, effective = add_outbound(clean), add_outbound(effective)
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
    elif case == "associative":
        clean = _replace_section(clean, 2, comdat_associated=3)
        effective = _replace_section(effective, 2, comdat_associated=3)
    elif case == "runtime-root":
        clean = _replace_section(clean, 2, name=".CRT$XCU")
        effective = _replace_section(effective, 2, name=".CRT$XCU")
        clean = replace(
            clean,
            symbols=tuple(
                replace(symbol, name=".CRT$XCU") if symbol.name == ".rdata" else symbol
                for symbol in clean.symbols
            ),
        )
        effective = replace(
            effective,
            symbols=tuple(
                replace(symbol, name=".CRT$XCU") if symbol.name == ".rdata" else symbol
                for symbol in effective.symbols
            ),
        )
    elif case == "mutated-clean-span":
        effective = _replace_rdata_body(
            effective, _PREFIX + _CLEAN_DATA[:-1] + bytes([_CLEAN_DATA[-1] ^ 1])
        )
    elif case == "deleted-clean-span":
        effective = _replace_rdata_body(effective, _PREFIX + _CLEAN_DATA[:-1])
    elif case == "suffix":
        effective = _replace_rdata_body(effective, _PREFIX + _CLEAN_DATA + b"X")
    elif case == "second-carrier":
        effective = replace(
            effective,
            symbols=(*effective.symbols, _symbol(9, "_Other$S4", value=4, section=2)),
        )
    elif case == "wrong-retained-owner":
        effective = replace(
            effective,
            symbols=tuple(
                replace(symbol, name="_other$S2") if symbol.name == "_rotateIndex$S2" else symbol
                for symbol in effective.symbols
            ),
        )
    elif case == "code-delta":
        effective = _replace_section(effective, 3, body=b"\x90\xc3")
    elif case == "directive-delta":
        effective = _replace_section(effective, 1, body=b"/DEFAULTLIB:OLDNAMES ")
    elif case == "linkage-delta":
        effective = replace(
            effective,
            symbols=(
                *effective.symbols,
                _symbol(10, "_new_dependency", value=0, section=0, storage=2),
            ),
        )
    elif case == "uncomposed-local-alpha":
        clean = replace(
            clean,
            symbols=(*clean.symbols, _symbol(10, "$L1", value=0, section=3, storage=6)),
        )
        effective = replace(
            effective,
            symbols=(
                *effective.symbols,
                _symbol(10, "$L999", value=0, section=3, storage=6),
            ),
        )
    elif case == "merged-rdata":
        clean = _replace_section(clean, 1, body=b"/merge:.rdata=.text ")
        effective = _replace_section(effective, 1, body=b"/merge:.rdata=.text ")
    elif case == "writable-rdata":
        clean = _replace_section(clean, 2, characteristics=_RDATA_CHARACTERISTICS | 0x80000000)
        effective = _replace_section(
            effective, 2, characteristics=_RDATA_CHARACTERISTICS | 0x80000000
        )
    else:
        raise AssertionError(f"unknown test case {case}")
    return clean, effective


@pytest.mark.parametrize(
    "case",
    (
        "external-carrier",
        "weak-carrier",
        "untyped-carrier",
        "inbound-section-addend",
        "outbound-relocation",
        "comdat",
        "associative",
        "runtime-root",
        "mutated-clean-span",
        "deleted-clean-span",
        "suffix",
        "ambiguous-clean-image",
        "second-carrier",
        "wrong-retained-owner",
        "code-delta",
        "directive-delta",
        "linkage-delta",
        "uncomposed-local-alpha",
        "merged-rdata",
        "writable-rdata",
    ),
)
def test_dead_static_prefix_rejects_every_widening(case: str) -> None:
    clean, effective = _adversarial_pair(case)

    equivalence = _runtime_projection_equivalence_proof(clean, effective)

    assert equivalence.equivalent is False
    assert equivalence.theorem is None


def test_dead_static_prefix_rejects_excluded_helper_composition() -> None:
    clean, effective = _pair()
    effective = replace(
        effective,
        sections=(
            *effective.sections,
            _section(4, ".text$helper", b"\xc3", characteristics=0x60000020),
        ),
        symbols=(*effective.symbols, _symbol(10, "$L1", value=0, section=4, storage=6)),
    )

    equivalence = _runtime_projection_equivalence_proof(
        clean,
        effective,
        excluded_effective_sections=frozenset({4}),
    )

    assert equivalence.equivalent is False


def test_data_certificates_are_side_bound_consumed_and_nonoverlapping() -> None:
    clean, effective = _pair()
    equivalence = _runtime_projection_equivalence_proof(clean, effective)
    clean_certificate = equivalence.clean_data_certificates[2]
    effective_certificate = equivalence.effective_data_certificates[2]

    clean_envelope = _coff_semantic_envelope(clean, certified_data_sections={2: clean_certificate})
    effective_envelope = _coff_semantic_envelope(
        effective, certified_data_sections={2: effective_certificate}
    )
    assert clean_envelope["statement"] == effective_envelope["statement"]

    with pytest.raises(ClassicSemanticError, match="does not bind"):
        _coff_semantic_envelope(clean, certified_data_sections={2: effective_certificate})
    with pytest.raises(ClassicSemanticError, match="do not bind"):
        _coff_semantic_envelope(clean, certified_data_sections={99: clean_certificate})
    with pytest.raises(ClassicSemanticError, match="overlap"):
        _coff_semantic_envelope(
            clean,
            certified_code_sections={
                2: _CodeProjectionCertificate("unrelated-code-theorem", "0" * 64)
            },
            certified_data_sections={2: clean_certificate},
        )
