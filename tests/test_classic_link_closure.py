from __future__ import annotations

import struct

import pytest

from reprobit.classic_link_closure import (
    ClassicLinkClosureError,
    MissingDirectiveInputsError,
    audit_classic_link_directives,
    parse_classic_module_definition,
)
from reprobit.model import Digest


def _symbol(
    name: str,
    *,
    section: int,
    symbol_type: int,
    storage: int,
    auxiliary_count: int = 0,
    value: int = 0,
) -> bytes:
    encoded = name.encode("ascii")
    assert len(encoded) <= 8
    return encoded.ljust(8, b"\0") + struct.pack(
        "<IhHBB", value, section, symbol_type, storage, auxiliary_count
    )


def _coff_directives(body: bytes, *, machine: int = 0x14C) -> bytes:
    section_table_end = 60
    symbols = (
        _symbol(
            ".drectve",
            section=1,
            symbol_type=0,
            storage=3,
            auxiliary_count=1,
        )
        + struct.pack("<IHHIhBBH", len(body), 0, 0, 0, 0, 2, 0, 0)
        + _symbol("_fixture", section=1, symbol_type=32, storage=2)
    )
    symbol_offset = section_table_end + len(body)
    header = struct.pack("<HHIIIHH", machine, 1, 0xAABBCCDD, symbol_offset, 3, 0, 0)
    section = b".drectve" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        section_table_end,
        0,
        0,
        0,
        0,
        0x60501020,
    )
    return header + section + body + symbols + struct.pack("<I", 4)


def _import_object(symbol: str, dll: str) -> bytes:
    data = symbol.encode("ascii") + b"\0" + dll.encode("ascii") + b"\0"
    return struct.pack("<HHHHIIHH", 0, 0xFFFF, 0, 0x14C, 7, len(data), 0, 4) + data


def _archive_auxless_section_anchor(
    section_name: str,
    *,
    optional_size: int,
    section_characteristics: int,
    machine: int = 0x014C,
    header_characteristics: int = 0x0100,
    value: int = 0,
    symbol_type: int = 0,
    auxiliary_count: int = 0,
    extra_metadata: str | None = None,
    optional_version: tuple[int, int, int, int] = (3, 10, 4, 0),
    optional_mutation_offset: int | None = None,
) -> bytes:
    optional = bytearray(optional_size)
    if optional_size:
        assert optional_size == 0x00E0
        linker_major, linker_minor, os_major, os_minor = optional_version
        struct.pack_into("<HBB", optional, 0, 0x010B, linker_major, linker_minor)
        struct.pack_into("<HH", optional, 40, os_major, os_minor)
        for offset, byte in {
            33: 0x10,
            37: 0x02,
            74: 0x10,
            77: 0x10,
            82: 0x10,
            85: 0x10,
            92: 0x10,
        }.items():
            optional[offset] = byte
        if optional_mutation_offset is not None:
            optional[optional_mutation_offset] ^= 1
    section_table_end = 20 + optional_size + 40
    body = b"\0"
    auxless = _symbol(
        section_name,
        section=1,
        symbol_type=symbol_type,
        storage=3,
        value=value,
        auxiliary_count=auxiliary_count,
    ) + bytes(18 * auxiliary_count)
    canonical = _symbol(
        section_name,
        section=1,
        symbol_type=0,
        storage=3,
        auxiliary_count=1,
    ) + struct.pack("<IHHIhBBH", len(body), 0, 0, 0, 0, 0, 0, 0)
    if extra_metadata is None:
        symbols = auxless
    elif extra_metadata == "auxless":
        symbols = auxless + auxless
    elif extra_metadata == "canonical-after":
        symbols = auxless + canonical
    elif extra_metadata == "canonical-before":
        symbols = canonical + auxless
    elif extra_metadata == "canonical-only":
        symbols = canonical
    else:
        raise AssertionError(f"unknown fixture metadata shape: {extra_metadata}")
    header = struct.pack(
        "<HHIIIHH",
        machine,
        1,
        0,
        section_table_end + len(body),
        len(symbols) // 18,
        optional_size,
        header_characteristics,
    )
    section = section_name.encode("ascii") + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        section_table_end,
        0,
        0,
        0,
        0,
        section_characteristics,
    )
    return header + bytes(optional) + section + body + symbols + struct.pack("<I", 4)


def _archive(*members: tuple[str, bytes]) -> bytes:
    output = bytearray(b"!<arch>\n")
    for name, payload in members:
        header = (
            (name.encode("ascii") + b"/").ljust(16, b" ")
            + b"0".ljust(12, b" ")
            + b"0".ljust(6, b" ")
            + b"0".ljust(6, b" ")
            + b"100644".ljust(8, b" ")
            + str(len(payload)).encode("ascii").ljust(10, b" ")
            + b"`\n"
        )
        output.extend(header)
        output.extend(payload)
        if len(payload) & 1:
            output.extend(b"\n")
    return bytes(output)


def test_directive_closure_classifies_every_object_and_archive_member() -> None:
    direct = _coff_directives(
        b"/DEFAULTLIB:runtime /INCLUDE:_forced /EXPORT:_visible "
        b"/MERGE:.CRT=.data /DISALLOWLIB:debugcrt.lib\0"
    )
    archive_member = bytearray(_coff_directives(b"/DEFAULTLIB:runtime "))
    archive_member[:2] = b"\0\0"
    package = _archive(
        ("member.obj", bytes(archive_member)),
        ("import.obj", _import_object("_puts", "runtime.dll")),
    )

    closure = audit_classic_link_directives(
        object_inputs={"build/unit.obj": direct},
        archive_inputs={
            "build/package.lib": package,
            "system-library/runtime.lib": _archive(
                ("runtime.obj", _import_object("_runtime", "runtime.dll"))
            ),
        },
        declared_archive_refs=(
            "build/package.lib",
            "system-library/runtime.lib",
        ),
        linker_arguments=("/machine:i386",),
    )

    assert closure.include_symbols == ("_forced",)
    assert closure.export_symbols == ("_visible",)
    assert closure.default_libraries[0].name == "runtime.lib"
    assert closure.default_libraries[0].reference == "system-library/runtime.lib"
    assert closure.merge_sections == ((".CRT", ".data"),)
    assert closure.disallowed_libraries == ("debugcrt.lib",)
    assert closure.objects[0].digest == Digest.from_bytes(direct)
    package_receipt = next(
        item for item in closure.archives if item.reference == "build/package.lib"
    )
    assert package_receipt.content_member_count == 2
    assert len(package_receipt.ordinary_members) == 1
    assert package_receipt.import_members[0].symbol == "_puts"


@pytest.mark.parametrize(
    ("section_name", "optional_size", "section_characteristics"),
    (
        (".debug$S", 0, 0x42100040),
        (".idata$6", 0x00E0, 0xC0200040),
    ),
)
def test_directive_closure_accepts_vc42_import_library_section_anchors(
    section_name: str,
    optional_size: int,
    section_characteristics: int,
) -> None:
    member = _archive_auxless_section_anchor(
        section_name,
        optional_size=optional_size,
        section_characteristics=section_characteristics,
    )

    closure = audit_classic_link_directives(
        object_inputs={},
        archive_inputs={"system-library/runtime.lib": _archive(("runtime.dll", member))},
        declared_archive_refs=("system-library/runtime.lib",),
        linker_arguments=(),
    )

    assert len(closure.archives[0].ordinary_members) == 1
    assert closure.archives[0].ordinary_members[0].directives.tokens == ()


def test_directive_closure_accepts_a_vc5_long_import_optional_header() -> None:
    member = _archive_auxless_section_anchor(
        ".idata$6",
        optional_size=0x00E0,
        section_characteristics=0xC0200040,
        optional_version=(5, 10, 4, 0),
    )

    closure = audit_classic_link_directives(
        object_inputs={},
        archive_inputs={"system-library/runtime.lib": _archive(("runtime.dll", member))},
        declared_archive_refs=("system-library/runtime.lib",),
        linker_arguments=(),
    )

    assert len(closure.archives[0].ordinary_members) == 1


@pytest.mark.parametrize(
    ("optional_version", "optional_mutation_offset"),
    (
        ((5, 10, 2, 0), None),
        ((5, 10, 4, 1), None),
        ((5, 10, 4, 0), 32),
        ((5, 10, 4, 0), 96),
    ),
    ids=("os-major", "os-minor", "section-alignment", "data-directory"),
)
def test_directive_closure_rejects_noncanonical_long_import_optional_headers(
    optional_version: tuple[int, int, int, int],
    optional_mutation_offset: int | None,
) -> None:
    member = _archive_auxless_section_anchor(
        ".idata$6",
        optional_size=0x00E0,
        section_characteristics=0xC0200040,
        optional_version=optional_version,
        optional_mutation_offset=optional_mutation_offset,
    )

    with pytest.raises(ClassicLinkClosureError, match="classic import optional header"):
        audit_classic_link_directives(
            object_inputs={},
            archive_inputs={"system-library/runtime.lib": _archive(("runtime.dll", member))},
            declared_archive_refs=("system-library/runtime.lib",),
            linker_arguments=(),
        )


@pytest.mark.parametrize(
    "changes",
    (
        {"optional_mutation_offset": 96},
        {"machine": 0},
        {"header_characteristics": 0},
        {"header_characteristics": 0x0101},
    ),
    ids=("data-directory", "machine", "header-flags-zero", "header-flags-drift"),
)
def test_optional_header_gate_does_not_depend_on_an_auxless_anchor(
    changes: dict[str, int],
) -> None:
    member = _archive_auxless_section_anchor(
        ".idata$6",
        optional_size=0x00E0,
        section_characteristics=0xC0200040,
        extra_metadata="canonical-only",
        **changes,
    )

    with pytest.raises(ClassicLinkClosureError, match="classic import optional header"):
        audit_classic_link_directives(
            object_inputs={},
            archive_inputs={"system-library/runtime.lib": _archive(("runtime.dll", member))},
            declared_archive_refs=("system-library/runtime.lib",),
            linker_arguments=(),
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "value",
        "type",
        "auxiliary-count",
        "machine",
        "header-characteristics",
        "section-characteristics",
    ),
)
@pytest.mark.parametrize(
    ("section_name", "optional_size", "section_characteristics"),
    (
        (".debug$S", 0, 0x42100040),
        (".idata$6", 0x00E0, 0xC0200040),
    ),
)
def test_directive_closure_rejects_near_miss_auxless_section_anchors(
    mutation: str,
    section_name: str,
    optional_size: int,
    section_characteristics: int,
) -> None:
    changes = {
        "value": 0,
        "symbol_type": 0,
        "auxiliary_count": 0,
        "machine": 0x014C,
        "header_characteristics": 0x0100,
        "section_characteristics": section_characteristics,
    }
    if mutation == "value":
        changes["value"] = 1
    elif mutation == "type":
        changes["symbol_type"] = 0x20
    elif mutation == "auxiliary-count":
        changes["auxiliary_count"] = 2
    elif mutation == "machine":
        changes["machine"] = 0
    elif mutation == "header-characteristics":
        changes["header_characteristics"] = 0
    else:
        changes["section_characteristics"] ^= 0x1000
    member = _archive_auxless_section_anchor(
        section_name,
        optional_size=optional_size,
        **changes,
    )

    with pytest.raises(
        ClassicLinkClosureError,
        match=r"definition symbol is non-canonical|classic import optional header",
    ):
        audit_classic_link_directives(
            object_inputs={},
            archive_inputs={"system-library/runtime.lib": _archive(("runtime.dll", member))},
            declared_archive_refs=("system-library/runtime.lib",),
            linker_arguments=(),
        )


@pytest.mark.parametrize(
    "extra_metadata",
    ("auxless", "canonical-after", "canonical-before"),
)
@pytest.mark.parametrize(
    ("section_name", "optional_size", "section_characteristics"),
    (
        (".debug$S", 0, 0x42100040),
        (".idata$6", 0x00E0, 0xC0200040),
    ),
)
def test_directive_closure_rejects_duplicate_or_mixed_archive_section_metadata(
    extra_metadata: str,
    section_name: str,
    optional_size: int,
    section_characteristics: int,
) -> None:
    member = _archive_auxless_section_anchor(
        section_name,
        optional_size=optional_size,
        section_characteristics=section_characteristics,
        extra_metadata=extra_metadata,
    )

    with pytest.raises(ClassicLinkClosureError, match="duplicate section-metadata symbols"):
        audit_classic_link_directives(
            object_inputs={},
            archive_inputs={"system-library/runtime.lib": _archive(("runtime.dll", member))},
            declared_archive_refs=("system-library/runtime.lib",),
            linker_arguments=(),
        )


def test_default_library_requires_one_declared_archive_edge() -> None:
    with pytest.raises(MissingDirectiveInputsError) as caught:
        audit_classic_link_directives(
            object_inputs={"unit.obj": _coff_directives(b"/DEFAULTLIB:unsealed ")},
            archive_inputs={},
            declared_archive_refs=(),
            linker_arguments=(),
        )
    assert caught.value.libraries == ("unsealed.lib",)


def test_nodefaultlib_suppression_is_exact_and_malformed_values_fail() -> None:
    payload = _coff_directives(b"/DEFAULTLIB:runtime ")
    closure = audit_classic_link_directives(
        object_inputs={"unit.obj": payload},
        archive_inputs={},
        declared_archive_refs=(),
        linker_arguments=("/NODEFAULTLIB:runtime",),
    )
    assert closure.default_libraries == ()
    with pytest.raises(ClassicLinkClosureError, match="malformed NODEFAULTLIB"):
        audit_classic_link_directives(
            object_inputs={"unit.obj": payload},
            archive_inputs={},
            declared_archive_refs=(),
            linker_arguments=(r"/NODEFAULTLIB:C:\host\runtime.lib",),
        )


def test_disallowlib_conflict_and_ambiguous_merge_fail_closed() -> None:
    runtime_archive = _archive(("runtime.obj", _import_object("_runtime", "runtime.dll")))
    with pytest.raises(ClassicLinkClosureError, match="DISALLOWLIB conflicts"):
        audit_classic_link_directives(
            object_inputs={"unit.obj": _coff_directives(b"/DISALLOWLIB:runtime ")},
            archive_inputs={"system-library/runtime.lib": runtime_archive},
            declared_archive_refs=("system-library/runtime.lib",),
            linker_arguments=(),
        )
    with pytest.raises(ClassicLinkClosureError, match="conflicting destinations"):
        audit_classic_link_directives(
            object_inputs={
                "left.obj": _coff_directives(b"/MERGE:.CRT=.data "),
                "right.obj": _coff_directives(b"/MERGE:.CRT=.rdata "),
            },
            archive_inputs={},
            declared_archive_refs=(),
            linker_arguments=(),
        )


def test_module_definition_receipt_closes_exports_and_description() -> None:
    payload = b"""\
; fixture
LIBRARY Fixture.dll
DESCRIPTION 'fixture module'
EXPORTS
?Public@@YAXXZ=_Private@0 @7 NONAME
_Data DATA
"""

    receipt = parse_classic_module_definition(payload, label="fixture.def")

    assert receipt.digest == Digest.from_bytes(payload)
    assert receipt.module_name == "Fixture.dll"
    assert receipt.description == "fixture module"
    assert receipt.exports == ("_Private@0", "_Data")


@pytest.mark.parametrize(
    "payload",
    (
        b"LIBRARY safe\nSTUB host.exe\n",
        b"EXPORTS\n_ok\nSTUB host.exe\n",
        b"IMPORTS\nfoo=bar.baz\n",
        b"EXPORTS\n_bad ATTRIBUTE\n",
        b"DESCRIPTION 'unterminated\n",
    ),
)
def test_module_definition_rejects_stub_and_unmodeled_grammar(
    payload: bytes,
) -> None:
    with pytest.raises(ClassicLinkClosureError):
        parse_classic_module_definition(payload, label="unsafe.def")
