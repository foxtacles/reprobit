from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from reprobit.binary import ByteIdentityError
from reprobit.msvc42_pdb import (
    MSVC42_PDB_CANONICALIZATION_POLICY,
    CanonicalizedMsvc42Pdb,
    Msvc42PdbIdentity,
    PdbCanonicalizationCategory,
    PdbCanonicalizationRange,
    canonicalize_msvc42_pdb,
    read_msvc42_pdb_identity,
)
from reprobit.small_msf import SMALL_MSF_MAGIC, SmallMsf

PAGE_SIZE = 1024
LINK_TIME = 0x341455A1


def _stream_table(
    streams: list[tuple[int, int, tuple[int, ...]] | None],
) -> bytes:
    data = bytearray(struct.pack("<HH", len(streams), 0))
    for stream in streams:
        if stream is None:
            data.extend(struct.pack("<II", 0xFFFFFFFF, 0xDEADBEEF))
        else:
            size, pointer, _pages = stream
            data.extend(struct.pack("<II", size, pointer))
    for stream in streams:
        if stream is not None:
            for page in stream[2]:
                data.extend(struct.pack("<H", page))
    return bytes(data)


def _sc40(*, seed: int) -> bytes:
    data = bytearray(20)
    struct.pack_into("<H", data, 0, 1)
    data[2:4] = bytes((seed, seed + 1))
    struct.pack_into("<IIIH", data, 4, 0x120, 0x44, 0x60000020, 3)
    data[18:20] = bytes((seed + 2, seed + 3))
    return bytes(data)


def _gproc_record() -> bytes:
    name = b"N" * 255
    tail = bytes(range(0x80, 0x8B))
    total_size = 38 + len(name) + len(tail)
    data = bytearray(total_size)
    struct.pack_into("<HH", data, 0, total_size - 2, 0x0205)
    struct.pack_into(
        "<IIIIIIIHHB",
        data,
        4,
        0,
        4 + total_size,
        0,
        0x40,
        2,
        0x3E,
        0x1234,
        1,
        0x1042,
        0,
    )
    data[37] = len(name)
    data[38 : 38 + len(name)] = name
    data[-len(tail) :] = tail
    return bytes(data)


def _synthetic_pdb(
    *,
    page_count: int = 32,
    active_fpm: int = 9,
    extra_free_pages: tuple[int, ...] = (),
) -> bytes:
    module = struct.pack("<I", 1) + _gproc_record() + struct.pack("<HH", 2, 0x0006)
    tpi_record = struct.pack("<HH", 2, 0x1001)
    tpi = struct.pack("<IHHIH2x", 19951122, 0x1000, 0x1001, len(tpi_record), 5)
    tpi += tpi_record
    tpi_hash = struct.pack("<H", 0x77) + struct.pack("<H2sI", 0x1000, b"\x22\x33", 0)
    pdb_info = struct.pack("<III", 19950814, 0x66778899, 7) + b"named-payload"

    fixed = bytearray(48)
    struct.pack_into("<I", fixed, 0, 0x11223344)
    fixed[4:24] = _sc40(seed=0x41)
    struct.pack_into("<HHIIIH", fixed, 24, 1, 4, len(module), 0, 0, 1)
    fixed[42:44] = b"\x51\x52"
    struct.pack_into("<I", fixed, 44, 0x55667788)
    names = b"module\0object.obj\0"
    name_padding = b"\x61" * ((-(len(fixed) + len(names))) % 4)
    modi = bytes(fixed) + names + name_padding
    dbi_header = bytearray(24)
    struct.pack_into("<HHH", dbi_header, 0, 0xFFFF, 0xFFFF, 0xFFFF)
    dbi_header[6:8] = b"\x71\x72"
    struct.pack_into("<IIII", dbi_header, 8, len(modi), 20, 0, 0)
    dbi = bytes(dbi_header) + modi + _sc40(seed=0x31)

    old_table = _stream_table(
        [
            (16, 0xA1000010, (17,)),
            (16, 0xA2000020, (18,)),
            (16, 0xA3000030, (19,)),
        ]
    )
    payloads = [old_table, pdb_info, tpi, dbi, module, tpi_hash]
    stream_pages = (20, 21, 22, 23, 24, 25)
    directory = _stream_table(
        [
            (len(payload), 0xB0000000 + index * 0x10101, (stream_pages[index],))
            for index, payload in enumerate(payloads)
        ]
    )

    data = bytearray(page_count * PAGE_SIZE)
    data[: len(SMALL_MSF_MAGIC)] = SMALL_MSF_MAGIC
    struct.pack_into(
        "<IHHII",
        data,
        44,
        PAGE_SIZE,
        active_fpm,
        page_count,
        len(directory),
        0xCAFEBABE,
    )
    struct.pack_into("<H", data, 60, 30)
    free_pages = (17, 18, 19, 20, 26, 27, 28, 29, 31, *range(32, page_count))
    for page in free_pages:
        data[active_fpm * PAGE_SIZE + page // 8] |= 1 << (page % 8)
    for page in (17, 18, 19, 26, 27, 28, 29, 31, *extra_free_pages):
        data[page * PAGE_SIZE : (page + 1) * PAGE_SIZE] = bytes((page & 0xFF,)) * PAGE_SIZE
    for page, payload in zip(stream_pages, payloads, strict=True):
        data[page * PAGE_SIZE : page * PAGE_SIZE + len(payload)] = payload
    data[30 * PAGE_SIZE : 30 * PAGE_SIZE + len(directory)] = directory
    return bytes(data)


def _positions(ranges: tuple[PdbCanonicalizationRange, ...]) -> set[int]:
    return {
        offset
        for item in ranges
        for offset in range(item.start, item.end)
    }


def _canonicalize(data: bytes, *, link_time: int = LINK_TIME) -> CanonicalizedMsvc42Pdb:
    return canonicalize_msvc42_pdb(
        data,
        link_time=link_time,
        expected_input_identity=read_msvc42_pdb_identity(data),
    )


def test_canonicalizer_changes_only_audited_bookkeeping() -> None:
    raw = _synthetic_pdb()
    result = _canonicalize(raw)
    parsed = SmallMsf(result.data)
    changed = {
        offset
        for offset, pair in enumerate(zip(raw, result.data, strict=True))
        if pair[0] != pair[1]
    }
    audited = {
        offset
        for stat in result.audit.stats
        for offset in _positions(stat.changed_ranges)
    }

    assert changed == audited
    assert result.audit.changed_bytes == len(changed)
    assert result.audit.raw_sha256 != result.audit.output_sha256
    assert len(result.audit.bytes_outside_policy_ranges_sha256) == 64
    assert result.audit.input_identity == read_msvc42_pdb_identity(raw)
    assert result.audit.input_identity.signature == 0x66778899
    assert result.audit.input_identity.age == 7
    assert result.audit.output_identity == Msvc42PdbIdentity(19950814, LINK_TIME, 7)
    assert result.audit.policy_version == MSVC42_PDB_CANONICALIZATION_POLICY
    assert struct.unpack_from("<I", parsed.read_stream(1, "test"), 4)[0] == LINK_TIME
    assert parsed.read_stream(1, "test")[12:] == b"named-payload"
    assert parsed.read_stream(5, "test")[4:6] == b"\0\0"
    assert parsed.read_stream(4, "test")[-15:-4] == b"\0" * 11
    assert result.data[17 * PAGE_SIZE : 18 * PAGE_SIZE] == b"\0" * PAGE_SIZE
    assert result.data[20 * PAGE_SIZE : 20 * PAGE_SIZE + 4] == struct.pack("<HH", 3, 0)

    categories = {stat.category for stat in result.audit.stats}
    assert categories == set(PdbCanonicalizationCategory)


def test_canonicalizer_requires_the_raw_nb10_identity_binding() -> None:
    raw = _synthetic_pdb()
    identity = read_msvc42_pdb_identity(raw)
    wrong = Msvc42PdbIdentity(identity.version, identity.signature + 1, identity.age)

    with pytest.raises(ByteIdentityError, match="raw NB10 binding"):
        canonicalize_msvc42_pdb(
            raw,
            link_time=LINK_TIME,
            expected_input_identity=wrong,
        )


@pytest.mark.parametrize("active_fpm", [1, 9])
def test_both_eight_page_fpm_banks_are_supported(active_fpm: int) -> None:
    result = _canonicalize(
        _synthetic_pdb(active_fpm=active_fpm),
    )

    assert SmallMsf(result.data).fpm_page == active_fpm


def test_fpm_covers_the_full_sixteen_bit_page_space() -> None:
    high_free_page = 8500
    result = _canonicalize(
        _synthetic_pdb(page_count=9000, extra_free_pages=(high_free_page,)),
    )

    assert result.data[
        high_free_page * PAGE_SIZE : (high_free_page + 1) * PAGE_SIZE
    ] == b"\0" * PAGE_SIZE


def test_canonicalization_is_idempotent() -> None:
    first = _canonicalize(_synthetic_pdb())
    second = _canonicalize(first.data)

    assert second.data == first.data
    assert second.audit.raw_sha256 == first.audit.output_sha256
    assert second.audit.output_sha256 == first.audit.output_sha256
    assert second.audit.changed_bytes == 0
    assert second.audit.normalized_bytes == first.audit.normalized_bytes


def test_semantic_procedure_fields_are_preserved() -> None:
    raw = _synthetic_pdb()
    parsed = SmallMsf(raw)
    absolute = parsed.stream_ranges(4, 4 + 16, 4, "procedure length")[0][0]
    changed = bytearray(raw)
    struct.pack_into("<I", changed, absolute, 0x55)

    baseline = _canonicalize(raw)
    modified = _canonicalize(bytes(changed))

    assert modified.data != baseline.data
    assert (
        modified.audit.bytes_outside_policy_ranges_sha256
        != baseline.audit.bytes_outside_policy_ranges_sha256
    )
    modified_stream = SmallMsf(modified.data).read_stream(4, "test")
    assert struct.unpack_from("<I", modified_stream, 4 + 16)[0] == 0x55


@pytest.mark.parametrize("link_time", [-1, 0x80000000, True, 1.5])
def test_link_time_must_be_a_classic_signed_time_t(link_time: object) -> None:
    with pytest.raises(ByteIdentityError, match="link_time"):
        raw = _synthetic_pdb()
        canonicalize_msvc42_pdb(
            raw,
            link_time=link_time,  # type: ignore[arg-type]
            expected_input_identity=read_msvc42_pdb_identity(raw),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda data: data.__setitem__(slice(0, 4), b"Nope"), "magic"),
        (
            lambda data: struct.pack_into("<I", data, 44, 2048),
            "1 KiB-page",
        ),
        (
            lambda data: struct.pack_into("<H", data, 30 * PAGE_SIZE + 2, 1),
            "not canonical",
        ),
        (
            lambda data: struct.pack_into("<H", data, 48, 2),
            "active FPM bank is invalid",
        ),
        (
            lambda data: struct.pack_into("<H", data, 30 * PAGE_SIZE + 54, 1),
            "aliases a structural page",
        ),
        (
            lambda data: struct.pack_into("<H", data, 30 * PAGE_SIZE + 56, 21),
            "belongs to multiple streams",
        ),
        (
            lambda data: data.__setitem__(
                9 * PAGE_SIZE + 21 // 8,
                data[9 * PAGE_SIZE + 21 // 8] | (1 << (21 % 8)),
            ),
            "live stream 1 page 21 is marked free",
        ),
        (
            lambda data: data.__setitem__(
                9 * PAGE_SIZE + 20 // 8,
                data[9 * PAGE_SIZE + 20 // 8] & ~(1 << (20 % 8)),
            ),
            "stream 0 container page is not free",
        ),
        (
            lambda data: data.__setitem__(
                9 * PAGE_SIZE + 26 // 8,
                data[9 * PAGE_SIZE + 26 // 8] & ~(1 << (26 % 8)),
            ),
            "data page 26 has no owner",
        ),
    ],
)
def test_small_msf_rejects_unsupported_or_ambiguous_layouts(
    mutation: object,
    message: str,
) -> None:
    malformed = bytearray(_synthetic_pdb())
    mutation(malformed)  # type: ignore[operator]
    with pytest.raises(ByteIdentityError, match=message):
        _canonicalize(bytes(malformed))


def test_tpi_rejects_semantically_invalid_ti_off_entry() -> None:
    malformed = bytearray(_synthetic_pdb())
    parsed = SmallMsf(bytes(malformed))
    offset = parsed.stream_ranges(5, 2, 2, "TI_OFF type")[0][0]
    struct.pack_into("<H", malformed, offset, 0x2000)

    with pytest.raises(ByteIdentityError, match="type index is out of range"):
        _canonicalize(bytes(malformed))


def test_tpi_rejects_ti_off_that_is_not_its_type_boundary() -> None:
    malformed = bytearray(_synthetic_pdb())
    parsed = SmallMsf(bytes(malformed))
    offset = parsed.stream_ranges(5, 6, 4, "TI_OFF offset")[0][0]
    struct.pack_into("<I", malformed, offset, 1)

    with pytest.raises(ByteIdentityError, match="type-record boundary"):
        _canonicalize(bytes(malformed))


def test_tpi_rejects_a_missing_initial_ti_off_entry() -> None:
    malformed = bytearray(_synthetic_pdb())
    directory_size = 4 + 5 * 8
    directory_page = 30 * PAGE_SIZE
    struct.pack_into("<I", malformed, directory_page + directory_size, 2)

    with pytest.raises(ByteIdentityError, match="no initial entry"):
        _canonicalize(bytes(malformed))


def test_stream_roles_cannot_alias_tpi_hash_and_module_symbols() -> None:
    malformed = bytearray(_synthetic_pdb())
    parsed = SmallMsf(bytes(malformed))
    module_number = parsed.stream_ranges(3, 24 + 26, 2, "module stream")[0][0]
    symbol_size = parsed.stream_ranges(3, 24 + 28, 4, "module symbols")[0][0]
    struct.pack_into("<H", malformed, module_number, 5)
    struct.pack_into("<I", malformed, symbol_size, 4)

    with pytest.raises(ByteIdentityError, match="stream roles alias"):
        _canonicalize(bytes(malformed))


def test_dbi_rejects_module_debug_range_overflow() -> None:
    malformed = bytearray(_synthetic_pdb())
    parsed = SmallMsf(bytes(malformed))
    offset = parsed.stream_ranges(3, 24 + 28, 4, "cbSyms")[0][0]
    struct.pack_into("<I", malformed, offset, 0xFFFFFFFF)

    with pytest.raises(ByteIdentityError, match="symbols exceed"):
        _canonicalize(bytes(malformed))


def test_codeview_rejects_unexplained_short_name_tail() -> None:
    malformed = bytearray(_synthetic_pdb())
    parsed = SmallMsf(bytes(malformed))
    offset = parsed.stream_ranges(4, 4 + 37, 1, "procedure name length")[0][0]
    malformed[offset] = 254

    with pytest.raises(ByteIdentityError, match="unexplained tail"):
        _canonicalize(bytes(malformed))


def test_codeview_rejects_an_unaligned_record() -> None:
    malformed = bytearray(_synthetic_pdb())
    parsed = SmallMsf(bytes(malformed))
    offset = parsed.stream_ranges(4, 4, 2, "procedure record length")[0][0]
    original = struct.unpack_from("<H", malformed, offset)[0]
    struct.pack_into("<H", malformed, offset, original - 1)

    with pytest.raises(ByteIdentityError, match="record is not aligned"):
        _canonicalize(bytes(malformed))


def test_gproc_end_must_name_a_real_s_end_record() -> None:
    malformed = bytearray(_synthetic_pdb())
    parsed = SmallMsf(bytes(malformed))
    offset = parsed.stream_ranges(4, 4 + 8, 4, "procedure end")[0][0]
    struct.pack_into("<I", malformed, offset, 12)

    with pytest.raises(ByteIdentityError, match="pEnd does not name"):
        _canonicalize(bytes(malformed))


def test_non_gproc_record_with_the_same_byte_shape_is_not_normalized() -> None:
    raw = bytearray(_synthetic_pdb())
    parsed = SmallMsf(bytes(raw))
    record_type = parsed.stream_ranges(4, 4 + 2, 2, "record type")[0][0]
    struct.pack_into("<H", raw, record_type, 0x0204)

    result = _canonicalize(bytes(raw))
    output_module = SmallMsf(result.data).read_stream(4, "module")

    assert output_module[-15:-4] == bytes(range(0x80, 0x8B))
    assert all(
        stat.category is not PdbCanonicalizationCategory.CODEVIEW_GPROC_TAIL
        for stat in result.audit.stats
    )


_REAL_FIXTURES = {
    "fixture_a": (
        "REPROBIT_MSVC42_PDB_FIXTURE_A_NAME",
        873747873,
        "718e5eaca03d40c46f8c4c814a37d7670529e87a2f48d0ad8a2a0d28eef4dda1",
        "808ebbb8dc0e26a40be7b8d7de254690aad19650d704938c385c6c5a502669d9",
        "0412b2badbe5ab1ff01c4675f98742c1d720a9811c3ea5eeea8cf3266d78ca80",
    ),
    "fixture_b": (
        "REPROBIT_MSVC42_PDB_FIXTURE_B_NAME",
        873748568,
        "1d17b10fe134ccc3adf7464ea6819a1887f6e3e66630267246061fa1db253636",
        "62c60ad3ca9dcb1de1c8aa7a532977f52d29fb4e15f0eac886c957a3ee66dbd1",
        "d7b6541a59b4969d0753216959b2742ba45590e11cd9654af5fdfa2dd692bf13",
    ),
    "fixture_c": (
        "REPROBIT_MSVC42_PDB_FIXTURE_C_NAME",
        873496219,
        "8dd5a9838c0d99cb7109253d0dc202b14aa314eda9cd35ca9a85ac42c43ed968",
        "3df72ade8d4eeef372d4e9c961a3ba7f54c6044ccb160725f593221f9670fdef",
        "8a148de12227a0469b3949391c1dbcdd59889c90e02b8c048a063ec2680da8c6",
    ),
}


@pytest.mark.parametrize("name", sorted(_REAL_FIXTURES))
def test_native_and_wine_real_fixtures_converge(name: str) -> None:
    wine_root = os.environ.get("REPROBIT_MSVC42_PDB_WINE_FIXTURES")
    windows_root = os.environ.get("REPROBIT_MSVC42_PDB_WINDOWS_FIXTURES")
    file_name_env = _REAL_FIXTURES[name][0]
    file_name = os.environ.get(file_name_env)
    if wine_root is None or windows_root is None or file_name is None:
        pytest.skip("set both ReproBit MSVC42 PDB fixture roots to run the captured corpus")
    _file_name_env, link_time, wine_hash, windows_hash, output_hash = _REAL_FIXTURES[name]

    wine = _canonicalize((Path(wine_root) / file_name).read_bytes(), link_time=link_time)
    windows = _canonicalize(
        (Path(windows_root) / file_name).read_bytes(),
        link_time=link_time,
    )

    assert wine.audit.raw_sha256 == wine_hash
    assert windows.audit.raw_sha256 == windows_hash
    assert wine.audit.output_sha256 == windows.audit.output_sha256 == output_hash
    assert (
        wine.audit.bytes_outside_policy_ranges_sha256
        == windows.audit.bytes_outside_policy_ranges_sha256
    )
    assert wine.data == windows.data
