from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import cast

from reprobit.classic_link_layout_repair import (
    ClassicLinkLayoutHint,
    derive_classic_link_layout_hint,
)
from reprobit.model import Digest
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole
from reprobit.schema import ProjectBundle
from reprobit.small_msf import SMALL_MSF_MAGIC

_PAGE_SIZE = 1024
_IMAGE_BASE = 0x10000000
_TEXT_RAW = 0x200
_RDATA_RAW = 0x400
_RELOC_RAW = 0x600
_CORE_OFFSET = 0x40
_DEBUG_CORE_OFFSET = 0x60
_ALPHA = struct.pack("<II", _IMAGE_BASE + 0x1180, _IMAGE_BASE + 0x1190)
_BETA = struct.pack("<II", _IMAGE_BASE + 0x11A0, _IMAGE_BASE + 0x11B0)


@dataclass(frozen=True)
class _Paths:
    build: str


@dataclass(frozen=True)
class _Target:
    id: str
    artifact: str


@dataclass(frozen=True)
class _Spec:
    paths: _Paths
    targets: tuple[_Target, ...]


@dataclass(frozen=True)
class _Bundle:
    spec: _Spec


def _graph() -> ProducerGraphDocument:
    compiler = ProducerNode(
        id="compiler.program.0000",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=(
            "/c",
            "${SOURCE}/unit.cpp",
            "/Fo${BUILD}/obj/unit.obj",
        ),
        inputs=("source/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )
    linker = ProducerNode(
        id="linker.program.0001",
        role=ProducerRole.LINKER,
        owner="program",
        target_id="program",
        arguments=(
            "${BUILD}/obj/unit.obj",
            "/out:${BUILD}/program.exe",
        ),
        inputs=("build/obj/unit.obj",),
        outputs=("build/program.exe",),
        depends_on=(compiler.id,),
    )
    return ProducerGraphDocument(
        schema_version=3,
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-makefiles-v1",
        nodes=(compiler, linker),
    )


def _bundle() -> ProjectBundle:
    return cast(
        ProjectBundle,
        _Bundle(
            _Spec(
                _Paths(r"Z:\fixture\build"),
                (_Target("program", "build/program.exe"),),
            )
        ),
    )


def _section_descriptor(
    name: bytes,
    *,
    virtual_size: int,
    virtual_address: int,
    raw_size: int,
    raw_offset: int,
    characteristics: int,
) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI",
        name.ljust(8, b"\0"),
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        characteristics,
    )


def _pe_image(
    *,
    core_offset: int,
    chunks: tuple[bytes, bytes],
    alpha_pointer: int,
    beta_pointer: int,
    duplicate_core: bool = False,
    pdb_path: str | None = None,
    pdb_signature: int = 0x12345678,
) -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x014C, 3, 0, 0, 0, 0xE0, 0x010F)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x010B)
    struct.pack_into("<I", data, optional + 28, _IMAGE_BASE)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x4000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 5 * 8, 0x3000, 28)
    if pdb_path is not None:
        struct.pack_into("<II", data, optional + 96 + 6 * 8, 0x2100, 28)
    section_table = optional + 0xE0
    descriptors = (
        _section_descriptor(
            b".text",
            virtual_size=0x200,
            virtual_address=0x1000,
            raw_size=0x200,
            raw_offset=_TEXT_RAW,
            characteristics=0x60000020,
        ),
        _section_descriptor(
            b".rdata",
            virtual_size=0x200,
            virtual_address=0x2000,
            raw_size=0x200,
            raw_offset=_RDATA_RAW,
            characteristics=0x40000040,
        ),
        _section_descriptor(
            b".reloc",
            virtual_size=28,
            virtual_address=0x3000,
            raw_size=0x200,
            raw_offset=_RELOC_RAW,
            characteristics=0x42000040,
        ),
    )
    data[section_table : section_table + 120] = b"".join(descriptors)

    struct.pack_into("<II", data, _TEXT_RAW + 0x20, alpha_pointer, beta_pointer)
    core = b"".join(chunks)
    data[_RDATA_RAW + core_offset : _RDATA_RAW + core_offset + len(core)] = core
    if duplicate_core:
        data[_RDATA_RAW + 0x80 : _RDATA_RAW + 0x80 + len(core)] = core

    text_entries = (0x3000 | 0x20, 0x3000 | 0x24)
    rdata_entries = tuple(0x3000 | (core_offset + index * 4) for index in range(4))
    reloc = struct.pack("<IIHH", 0x1000, 12, *text_entries)
    reloc += struct.pack("<IIHHHH", 0x2000, 16, *rdata_entries)
    data[_RELOC_RAW : _RELOC_RAW + len(reloc)] = reloc
    if pdb_path is not None:
        nb10 = struct.pack("<4sIII", b"NB10", 0, pdb_signature, 0)
        nb10 += pdb_path.encode("ascii") + b"\0"
        struct.pack_into(
            "<IIHHIIII",
            data,
            _RDATA_RAW + 0x100,
            0,
            0,
            0,
            0,
            2,
            len(nb10),
            0x2120,
            _RDATA_RAW + 0x120,
        )
        data[_RDATA_RAW + 0x120 : _RDATA_RAW + 0x120 + len(nb10)] = nb10
    return bytes(data)


def _images(*, duplicate_debug_core: bool = False) -> tuple[bytes, bytes, bytes]:
    alpha_candidate = _IMAGE_BASE + 0x2000 + _CORE_OFFSET
    beta_candidate = alpha_candidate + len(_ALPHA)
    candidate = _pe_image(
        core_offset=_CORE_OFFSET,
        chunks=(_ALPHA, _BETA),
        alpha_pointer=alpha_candidate,
        beta_pointer=beta_candidate,
    )
    oracle = _pe_image(
        core_offset=_CORE_OFFSET,
        chunks=(_BETA, _ALPHA),
        alpha_pointer=beta_candidate,
        beta_pointer=alpha_candidate,
    )
    debug = _pe_image(
        core_offset=_DEBUG_CORE_OFFSET,
        chunks=(_ALPHA, _BETA),
        alpha_pointer=_IMAGE_BASE + 0x2000 + _DEBUG_CORE_OFFSET,
        beta_pointer=_IMAGE_BASE + 0x2000 + _DEBUG_CORE_OFFSET + len(_ALPHA),
        duplicate_core=duplicate_debug_core,
        pdb_path=r"Z:\fixture\build\.reprobit-analysis\program\program.PDB",
    )
    return candidate, oracle, debug


def _stream_table(streams: tuple[tuple[bytes, tuple[int, ...]], ...]) -> bytes:
    data = bytearray(struct.pack("<HH", len(streams), 0))
    for payload, _pages in streams:
        data.extend(struct.pack("<II", len(payload), 0))
    for _payload, pages in streams:
        for page in pages:
            data.extend(struct.pack("<H", page))
    return bytes(data)


def _sc40(*, offset: int, module_index: int = 0) -> bytes:
    return struct.pack("<HHIIIHH", 2, 0, offset, 8, 0x40403040, module_index, 0)


def _public(*, offset: int, name: str) -> bytes:
    encoded = name.encode("latin-1")
    record = bytearray(struct.pack("<HHIHHB", 0, 0x0203, offset, 2, 0, len(encoded)))
    record.extend(encoded)
    record.extend(b"\0" * (-len(record) % 4))
    struct.pack_into("<H", record, 0, len(record) - 2)
    return bytes(record)


def _pdb(
    *,
    object_name: str = r"Z:\fixture\build/obj/unit.obj",
    signature: int = 0x12345678,
) -> bytes:
    module = struct.pack("<I", 1)
    fixed = bytearray(48)
    fixed[4:24] = _sc40(offset=_DEBUG_CORE_OFFSET)
    struct.pack_into("<HHIIIH", fixed, 24, 1, 4, len(module), 0, 0, 1)
    names = b"fixture\0" + object_name.encode("latin-1") + b"\0"
    modi = bytes(fixed) + names + b"\0" * ((-(len(fixed) + len(names))) % 4)
    contributions = _sc40(offset=_DEBUG_CORE_OFFSET) + _sc40(
        offset=_DEBUG_CORE_OFFSET + len(_ALPHA)
    )
    dbi_header = bytearray(24)
    struct.pack_into("<HHH", dbi_header, 0, 0xFFFF, 5, 6)
    struct.pack_into("<IIII", dbi_header, 8, len(modi), len(contributions), 0, 0)
    dbi = bytes(dbi_header) + modi + contributions

    alpha = _public(offset=_DEBUG_CORE_OFFSET, name="?alpha@@")
    beta = _public(offset=_DEBUG_CORE_OFFSET + len(_ALPHA), name="?beta@@")
    symbols = alpha + beta
    psi = struct.pack("<IIIIH2xII", 0, 8, 0, 0, 0, 0, 0)
    psi += struct.pack("<II", 0, len(alpha))
    pdb_info = struct.pack("<III", 19950814, signature, 0)

    stream_payloads = (b"", pdb_info, b"", dbi, module, psi, symbols)
    stream_pages = ((), (20,), (), (21,), (22,), (23,), (24,))
    streams = tuple(zip(stream_payloads, stream_pages, strict=True))
    directory = _stream_table(streams)
    data = bytearray(32 * _PAGE_SIZE)
    data[: len(SMALL_MSF_MAGIC)] = SMALL_MSF_MAGIC
    struct.pack_into("<IHHII", data, 44, _PAGE_SIZE, 9, 32, len(directory), 0)
    struct.pack_into("<H", data, 60, 30)
    live_pages = {20, 21, 22, 23, 24, 30}
    for page in range(17, 32):
        if page not in live_pages:
            data[9 * _PAGE_SIZE + page // 8] |= 1 << (page % 8)
    for payload, pages in streams:
        for index, page in enumerate(pages):
            chunk = payload[index * _PAGE_SIZE : (index + 1) * _PAGE_SIZE]
            data[page * _PAGE_SIZE : page * _PAGE_SIZE + len(chunk)] = chunk
    data[30 * _PAGE_SIZE : 30 * _PAGE_SIZE + len(directory)] = directory
    return bytes(data)


def _derive(
    *,
    candidate: bytes,
    oracle: bytes,
    debug: bytes,
    pdb: bytes,
    target_id: str = "program",
) -> ClassicLinkLayoutHint | None:
    return derive_classic_link_layout_hint(
        _bundle(),
        _graph(),
        target_id=target_id,
        candidate_image=candidate,
        oracle_image=oracle,
        debug_image=debug,
        pdb=pdb,
    )


def test_derives_provider_and_oracle_symbol_order() -> None:
    candidate, oracle, debug = _images()

    hint = _derive(candidate=candidate, oracle=oracle, debug=debug, pdb=_pdb())

    assert hint == ClassicLinkLayoutHint(
        compiler_node_id="compiler.program.0000",
        desired_symbol_order=("?beta@@", "?alpha@@"),
    )


def test_duplicate_debug_content_match_fails_closed() -> None:
    candidate, oracle, debug = _images(duplicate_debug_core=True)

    assert _derive(candidate=candidate, oracle=oracle, debug=debug, pdb=_pdb()) is None


def test_extra_non_relocation_difference_fails_closed() -> None:
    candidate, oracle, debug = _images()
    changed = bytearray(oracle)
    changed[_TEXT_RAW + 0x10] ^= 1

    assert _derive(candidate=candidate, oracle=bytes(changed), debug=debug, pdb=_pdb()) is None


def test_wrong_target_fails_closed() -> None:
    candidate, oracle, debug = _images()

    assert (
        _derive(
            candidate=candidate,
            oracle=oracle,
            debug=debug,
            pdb=_pdb(),
            target_id="other",
        )
        is None
    )


def test_module_object_outside_build_seat_fails_closed() -> None:
    candidate, oracle, debug = _images()

    assert (
        _derive(
            candidate=candidate,
            oracle=oracle,
            debug=debug,
            pdb=_pdb(object_name=r"Z:\fixture\source\obj\unit.obj"),
        )
        is None
    )


def test_stale_pdb_identity_fails_closed() -> None:
    candidate, oracle, debug = _images()

    assert (
        _derive(
            candidate=candidate,
            oracle=oracle,
            debug=debug,
            pdb=_pdb(signature=0x87654321),
        )
        is None
    )
