from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from reprobit.binary import ByteIdentityError
from reprobit.msvc42_pdb import (
    Msvc42PdbIdentity,
    canonicalize_msvc42_pdb,
    read_msvc42_pdb_identity,
)
from reprobit.msvc42_pe_debug import (
    MSVC42_DEBUG_COMPANION_POLICY,
    CanonicalizedMsvc42DebugCompanion,
    DebugCompanionCanonicalizationCategory,
    canonicalize_msvc42_debug_companion,
    read_msvc42_debug_companion_identity,
)

RAW_TIME = 0x11223344
LINK_TIME = 0x55667788
PDB_PATH = r"Z:\work\sample\build\SAMPLE.PDB"
IMAGE_PATH = r"Z:\work\sample\build\SAMPLE.EXE"
PE_OFFSET = 0x80
OPTIONAL_OFFSET = PE_OFFSET + 24
DEBUG_DIRECTORY_OFFSET = 0x200
OVERLAY_OFFSET = 0x400


def _misc_payload() -> bytes:
    data = bytearray(272)
    struct.pack_into("<IIB3s", data, 0, 1, len(data), 0, b"\0\0\0")
    encoded = IMAGE_PATH.encode("ascii") + b"\0"
    data[12 : 12 + len(encoded)] = encoded
    return bytes(data)


def _fpo_payload() -> bytes:
    return b"".join(
        (
            struct.pack("<IIIHH", 0x1000, 0x30, 2, 1, 5 | (2 << 8)),
            struct.pack("<IIIHH", 0x1040, 0x20, 0, 0, 3 | (1 << 8)),
        )
    )


def _nb10_payload(*, path: str = PDB_PATH, age: int = 0, tail: bytes = b"") -> bytes:
    return struct.pack("<4sIII", b"NB10", 0, RAW_TIME, age) + path.encode("ascii") + b"\0" + tail


def _synthetic_image(
    *,
    kinds: tuple[int, ...] = (4, 3, 2),
    nb10_age: int = 0,
    nb10_tail: bytes = b"",
) -> bytes:
    payload_for = {
        4: _misc_payload(),
        3: _fpo_payload(),
        2: _nb10_payload(age=nb10_age, tail=nb10_tail),
    }
    payloads = tuple((kind, payload_for[kind]) for kind in kinds)
    data = bytearray(OVERLAY_OFFSET + sum(len(payload) for _kind, payload in payloads))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, PE_OFFSET)
    data[PE_OFFSET : PE_OFFSET + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        data,
        PE_OFFSET + 4,
        0x014C,
        1,
        RAW_TIME,
        0,
        0,
        224,
        0x010F,
    )
    struct.pack_into("<H", data, OPTIONAL_OFFSET, 0x010B)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 28, 0x00400000)
    struct.pack_into("<II", data, OPTIONAL_OFFSET + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 56, 0x2000)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 60, 0x200)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 64, 0)
    struct.pack_into("<I", data, OPTIONAL_OFFSET + 92, 16)
    struct.pack_into(
        "<II",
        data,
        OPTIONAL_OFFSET + 96 + 6 * 8,
        0x1000,
        len(payloads) * 28,
    )
    section = OPTIONAL_OFFSET + 224
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x40000040)

    cursor = OVERLAY_OFFSET
    for index, (kind, payload) in enumerate(payloads):
        struct.pack_into(
            "<IIHHIIII",
            data,
            DEBUG_DIRECTORY_OFFSET + index * 28,
            0,
            RAW_TIME,
            0,
            0,
            kind,
            len(payload),
            0,
            cursor,
        )
        data[cursor : cursor + len(payload)] = payload
        cursor += len(payload)
    return bytes(data)


def _canonicalize(data: bytes, *, link_time: int = LINK_TIME) -> CanonicalizedMsvc42DebugCompanion:
    identity = read_msvc42_debug_companion_identity(data, expected_pdb_path=PDB_PATH)
    return canonicalize_msvc42_debug_companion(
        data,
        link_time=link_time,
        expected_pdb_path=PDB_PATH,
        expected_input_pdb_identity=identity.pdb_identity,
    )


def test_identity_is_strictly_coupled_to_the_planned_pdb() -> None:
    identity = read_msvc42_debug_companion_identity(
        _synthetic_image(),
        expected_pdb_path=PDB_PATH,
    )

    assert identity.signature == RAW_TIME
    assert identity.age == 0
    assert identity.pdb_path == PDB_PATH
    assert identity.pdb_identity == Msvc42PdbIdentity(19950814, RAW_TIME, 0)


def test_canonicalizer_changes_only_the_coupled_timestamp_fields() -> None:
    raw = _synthetic_image()
    result = _canonicalize(raw)
    changed = {
        offset
        for offset, (before, after) in enumerate(zip(raw, result.data, strict=True))
        if before != after
    }
    allowed = {
        byte
        for write in result.audit.writes
        for byte in range(write.file_offset, write.file_offset + 4)
    }

    assert changed == allowed
    assert result.audit.policy_version == MSVC42_DEBUG_COMPANION_POLICY
    assert result.audit.normalized_bytes == 20
    assert result.audit.changed_bytes == 20
    assert result.audit.raw_sha256 != result.audit.output_sha256
    assert len(result.audit.bytes_outside_policy_ranges_sha256) == 64
    assert result.audit.input_identity.signature == RAW_TIME
    assert result.audit.output_identity.signature == LINK_TIME
    assert result.audit.output_identity.pdb_identity == Msvc42PdbIdentity(
        19950814,
        LINK_TIME,
        0,
    )
    assert {write.category for write in result.audit.writes} == set(
        DebugCompanionCanonicalizationCategory
    )


def test_canonicalization_is_idempotent() -> None:
    first = _canonicalize(_synthetic_image())
    second = canonicalize_msvc42_debug_companion(
        first.data,
        link_time=LINK_TIME,
        expected_pdb_path=PDB_PATH,
        expected_input_pdb_identity=first.audit.output_identity.pdb_identity,
    )

    assert second.data == first.data
    assert second.audit.raw_sha256 == first.audit.output_sha256
    assert second.audit.output_sha256 == first.audit.output_sha256
    assert second.audit.changed_bytes == 0


def test_misc_and_fpo_entries_are_optional() -> None:
    raw = _synthetic_image(kinds=(2,))
    result = _canonicalize(raw)

    assert result.audit.normalized_bytes == 12
    assert result.audit.output_identity.signature == LINK_TIME


def test_rva_backed_debug_payload_must_match_its_file_pointer() -> None:
    raw = bytearray(_synthetic_image())
    section = OPTIONAL_OFFSET + 224
    struct.pack_into("<II", raw, section + 8, len(raw) - 0x200, 0x1000)
    struct.pack_into("<I", raw, section + 16, len(raw) - 0x200)
    nb10 = raw.index(b"NB10", OVERLAY_OFFSET)
    for index in range(3):
        entry = DEBUG_DIRECTORY_OFFSET + index * 28
        pointer = struct.unpack_from("<I", raw, entry + 24)[0]
        struct.pack_into("<I", raw, entry + 20, 0x1000 + pointer - 0x200)

    assert _canonicalize(bytes(raw)).audit.output_identity.signature == LINK_TIME

    codeview_entry = DEBUG_DIRECTORY_OFFSET + 2 * 28
    struct.pack_into("<I", raw, codeview_entry + 20, 0x1000 + nb10 - 0x200 - 1)
    with pytest.raises(ByteIdentityError, match="RVA and file pointer disagree"):
        read_msvc42_debug_companion_identity(bytes(raw), expected_pdb_path=PDB_PATH)


def test_canonicalizer_requires_the_raw_pdb_identity() -> None:
    raw = _synthetic_image()

    with pytest.raises(ByteIdentityError, match="raw PDB binding"):
        canonicalize_msvc42_debug_companion(
            raw,
            link_time=LINK_TIME,
            expected_pdb_path=PDB_PATH,
            expected_input_pdb_identity=Msvc42PdbIdentity(19950814, RAW_TIME + 1, 0),
        )


@pytest.mark.parametrize("link_time", [-1, 0x80000000, True, 1.5])
def test_link_time_must_be_a_classic_signed_time_t(link_time: object) -> None:
    raw = _synthetic_image()
    identity = read_msvc42_debug_companion_identity(raw, expected_pdb_path=PDB_PATH)

    with pytest.raises(ByteIdentityError, match="link_time"):
        canonicalize_msvc42_debug_companion(
            raw,
            link_time=link_time,  # type: ignore[arg-type]
            expected_pdb_path=PDB_PATH,
            expected_input_pdb_identity=identity.pdb_identity,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.__setitem__(slice(0, 2), b"NO"), "MZ"),
        (
            lambda data: struct.pack_into("<H", data, PE_OFFSET + 4, 0x8664),
            "not i386",
        ),
        (
            lambda data: struct.pack_into("<I", data, OPTIONAL_OFFSET + 64, 1),
            "checksum",
        ),
        (
            lambda data: struct.pack_into("<I", data, DEBUG_DIRECTORY_OFFSET + 4, RAW_TIME + 1),
            "timestamp differs",
        ),
        (
            lambda data: struct.pack_into("<I", data, DEBUG_DIRECTORY_OFFSET + 12, 99),
            "not admitted",
        ),
        (
            lambda data: struct.pack_into("<I", data, DEBUG_DIRECTORY_OFFSET + 28 + 12, 2),
            "exactly one CodeView",
        ),
        (
            lambda data: struct.pack_into("<I", data, DEBUG_DIRECTORY_OFFSET + 24, len(data)),
            "payload range",
        ),
        (
            lambda data: struct.pack_into("<I", data, DEBUG_DIRECTORY_OFFSET + 24, 0x300),
            "external overlay",
        ),
        (
            lambda data: struct.pack_into("<I", data, DEBUG_DIRECTORY_OFFSET + 28 + 24, 0x400),
            "payloads overlap",
        ),
    ],
)
def test_parser_rejects_unsupported_or_ambiguous_pe_layouts(
    mutation: object,
    message: str,
) -> None:
    malformed = bytearray(_synthetic_image())
    mutation(malformed)  # type: ignore[operator]

    with pytest.raises(ByteIdentityError, match=message):
        read_msvc42_debug_companion_identity(bytes(malformed), expected_pdb_path=PDB_PATH)


def test_nb10_requires_zero_offset_and_age_and_the_exact_terminal_path() -> None:
    raw = _synthetic_image()
    nb10 = raw.index(b"NB10", OVERLAY_OFFSET)

    for relative, value, message in (
        (4, 1, "offset is not zero"),
        (8, RAW_TIME + 1, "signature differs"),
        (12, 1, "age is not zero"),
    ):
        malformed = bytearray(raw)
        struct.pack_into("<I", malformed, nb10 + relative, value)
        with pytest.raises(ByteIdentityError, match=message):
            read_msvc42_debug_companion_identity(
                bytes(malformed),
                expected_pdb_path=PDB_PATH,
            )

    with pytest.raises(ByteIdentityError, match="exact planned logical path"):
        read_msvc42_debug_companion_identity(raw, expected_pdb_path=PDB_PATH.lower())
    with pytest.raises(ByteIdentityError, match="exact planned logical path"):
        read_msvc42_debug_companion_identity(
            _synthetic_image(nb10_tail=b"\0"),
            expected_pdb_path=PDB_PATH,
        )


def test_misc_exename_and_fpo_shapes_fail_closed() -> None:
    misc_type = bytearray(_synthetic_image())
    struct.pack_into("<I", misc_type, OVERLAY_OFFSET, 2)
    with pytest.raises(ByteIdentityError, match="not EXENAME"):
        read_msvc42_debug_companion_identity(bytes(misc_type), expected_pdb_path=PDB_PATH)

    fpo = OVERLAY_OFFSET + len(_misc_payload())
    reserved_fpo = bytearray(_synthetic_image())
    attributes = struct.unpack_from("<H", reserved_fpo, fpo + 14)[0]
    struct.pack_into("<H", reserved_fpo, fpo + 14, attributes | (1 << 13))
    with pytest.raises(ByteIdentityError, match="reserved bit"):
        read_msvc42_debug_companion_identity(bytes(reserved_fpo), expected_pdb_path=PDB_PATH)

    short_fpo = bytearray(_synthetic_image())
    struct.pack_into("<I", short_fpo, DEBUG_DIRECTORY_OFFSET + 28 + 16, 31)
    with pytest.raises(ByteIdentityError, match="FPO_DATA array"):
        read_msvc42_debug_companion_identity(bytes(short_fpo), expected_pdb_path=PDB_PATH)


_REAL_FIXTURES = ("A", "B", "C")


@pytest.mark.parametrize("name", _REAL_FIXTURES)
def test_captured_image_and_pdb_pairs_recouple(name: str) -> None:
    wine_root = os.environ.get("REPROBIT_MSVC42_PE_WINE_FIXTURES")
    windows_root = os.environ.get("REPROBIT_MSVC42_PE_WINDOWS_FIXTURES")
    image_name = os.environ.get(f"REPROBIT_MSVC42_PE_FIXTURE_{name}_IMAGE")
    pdb_name = os.environ.get(f"REPROBIT_MSVC42_PE_FIXTURE_{name}_PDB")
    logical_pdb = os.environ.get(f"REPROBIT_MSVC42_PE_FIXTURE_{name}_LOGICAL_PDB")
    if None in (wine_root, windows_root, image_name, pdb_name, logical_pdb):
        pytest.skip("set both ReproBit MSVC 4.2 PE/PDB fixture roots to run the corpus")

    for root in (wine_root, windows_root):
        assert root is not None and image_name is not None and pdb_name is not None
        assert logical_pdb is not None
        image = (Path(root) / image_name).read_bytes()
        pdb = (Path(root) / pdb_name).read_bytes()
        raw_pdb_identity = read_msvc42_pdb_identity(pdb)
        canonical_image = canonicalize_msvc42_debug_companion(
            image,
            link_time=LINK_TIME,
            expected_pdb_path=logical_pdb,
            expected_input_pdb_identity=raw_pdb_identity,
        )
        canonical_pdb = canonicalize_msvc42_pdb(
            pdb,
            link_time=LINK_TIME,
            expected_input_identity=raw_pdb_identity,
        )

        assert (
            canonical_image.audit.output_identity.pdb_identity
            == canonical_pdb.audit.output_identity
        )
        assert canonical_image.audit.changed_bytes <= canonical_image.audit.normalized_bytes
        assert canonical_image.audit.bytes_outside_policy_ranges_sha256
