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


def _symbol(name: str, *, section: int, symbol_type: int, storage: int) -> bytes:
    encoded = name.encode("ascii")
    assert len(encoded) <= 8
    return encoded.ljust(8, b"\0") + struct.pack(
        "<IhHBB", 0, section, symbol_type, storage, 0
    )


def _coff_directives(body: bytes, *, machine: int = 0x14C) -> bytes:
    section_table_end = 60
    symbols = (
        _symbol(".drectve", section=1, symbol_type=0, storage=3)
        + struct.pack("<IHHIhBBH", len(body), 0, 0, 0, 0, 2, 0, 0)
        + _symbol("_fixture", section=1, symbol_type=32, storage=2)
    )
    symbol_offset = section_table_end + len(body)
    header = struct.pack(
        "<HHIIIHH", machine, 1, 0xAABBCCDD, symbol_offset, 3, 0, 0
    )
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


def test_default_library_requires_one_declared_archive_edge() -> None:
    with pytest.raises(MissingDirectiveInputsError) as caught:
        audit_classic_link_directives(
            object_inputs={
                "unit.obj": _coff_directives(b"/DEFAULTLIB:unsealed ")
            },
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
    runtime_archive = _archive(
        ("runtime.obj", _import_object("_runtime", "runtime.dll"))
    )
    with pytest.raises(ClassicLinkClosureError, match="DISALLOWLIB conflicts"):
        audit_classic_link_directives(
            object_inputs={
                "unit.obj": _coff_directives(b"/DISALLOWLIB:runtime ")
            },
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
