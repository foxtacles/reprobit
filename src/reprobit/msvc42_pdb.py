"""Fail-closed canonicalization for authenticity-irrelevant MSVC 4.2 PDB bytes.

VC 4.2 persists several process-local pointers, ABI padding holes, and one
truncated-symbol tail in otherwise semantic PDB streams.  This module parses
the exact old layouts before touching those bytes.  It deliberately does not
recognize newer PDB/MSF variants or perform heuristic address scrubbing.
"""

from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256

from reprobit.binary import require
from reprobit.small_msf import SmallMsf, parse_small_msf_stream_table

_PDB_STREAM_VERSION = 19950814
_TPI_STREAM_VERSION = 19951122
_TPI_HEADER_SIZE = 16
_DBI_HEADER_SIZE = 24
_MODI50_FIXED_SIZE = 48
_SC40_SIZE = 20
_S_GPROC32_16T = 0x0205
_MODULE_STREAM_SIGNATURE = 1
_NIL_STREAM = 0xFFFF
MSVC42_PDB_CANONICALIZATION_POLICY = "msvc42-pdb-v1"


class PdbCanonicalizationCategory(StrEnum):
    """Named, reviewable reasons why bytes are eligible for replacement."""

    MSF_HEADER_POINTER = "msf.header_pointer"
    MSF_DIRECTORY_POINTERS = "msf.directory_pointers"
    MSF_STREAM_ZERO_POINTERS = "msf.stream_zero_pointers"
    PDB_SIGNATURE = "pdb.signature"
    TPI_TI_OFF_PADDING = "tpi.ti_off_padding"
    DBI_TRANSIENT_POINTERS = "dbi.transient_pointers"
    DBI_SC40_PADDING = "dbi.sc40_padding"
    DBI_ABI_PADDING = "dbi.abi_padding"
    CODEVIEW_GPROC_TAIL = "codeview.gproc32_16t_tail"
    MSF_FREE_PAGES = "msf.free_pages"


@dataclass(frozen=True, order=True, slots=True)
class PdbCanonicalizationRange:
    """One non-empty half-open physical file range."""

    start: int
    end: int

    def __post_init__(self) -> None:
        require(self.start >= 0, "canonicalization range starts before the file")
        require(self.end > self.start, "canonicalization range is empty")

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class PdbCanonicalizationStat:
    """All eligible and actually changed ranges for one reason."""

    category: PdbCanonicalizationCategory
    normalized_ranges: tuple[PdbCanonicalizationRange, ...]
    changed_ranges: tuple[PdbCanonicalizationRange, ...]
    normalized_bytes: int
    changed_bytes: int


@dataclass(frozen=True, slots=True)
class Msvc42PdbIdentity:
    """The raw PDB side of an image/PDB NB10 identity binding."""

    version: int
    signature: int
    age: int


@dataclass(frozen=True, slots=True)
class PdbCanonicalizationAudit:
    """Content identity and exact byte-level explanation of one transform."""

    policy_version: str
    raw_sha256: str
    output_sha256: str
    bytes_outside_policy_ranges_sha256: str
    size: int
    link_time: int
    input_identity: Msvc42PdbIdentity
    output_identity: Msvc42PdbIdentity
    stats: tuple[PdbCanonicalizationStat, ...]

    @property
    def normalized_bytes(self) -> int:
        return sum(stat.normalized_bytes for stat in self.stats)

    @property
    def changed_bytes(self) -> int:
        return sum(stat.changed_bytes for stat in self.stats)


@dataclass(frozen=True, slots=True)
class CanonicalizedMsvc42Pdb:
    """Canonical PDB bytes paired with their complete audit."""

    data: bytes
    audit: PdbCanonicalizationAudit


@dataclass(frozen=True, slots=True)
class _ModuleStream:
    number: int
    symbol_size: int


@dataclass(frozen=True, slots=True)
class _DbiStreams:
    modules: tuple[_ModuleStream, ...]
    auxiliaries: tuple[int, ...]


def _coalesce(ranges: list[tuple[int, int]]) -> tuple[PdbCanonicalizationRange, ...]:
    if not ranges:
        return ()
    ordered = sorted(ranges)
    result: list[PdbCanonicalizationRange] = []
    start, end = ordered[0]
    for next_start, next_end in ordered[1:]:
        require(next_start >= end, "canonicalization ranges overlap")
        if next_start == end:
            end = next_end
        else:
            result.append(PdbCanonicalizationRange(start, end))
            start, end = next_start, next_end
    result.append(PdbCanonicalizationRange(start, end))
    return tuple(result)


class _Edits:
    def __init__(self, data: bytes) -> None:
        self.data = bytearray(data)
        self.normalized: dict[PdbCanonicalizationCategory, list[tuple[int, int]]] = defaultdict(
            list
        )
        self.changed: dict[PdbCanonicalizationCategory, list[tuple[int, int]]] = defaultdict(list)

    def replace(
        self,
        category: PdbCanonicalizationCategory,
        ranges: tuple[tuple[int, int], ...],
        replacement: bytes,
    ) -> None:
        require(
            sum(end - start for start, end in ranges) == len(replacement),
            f"{category} replacement length is inconsistent",
        )
        consumed = 0
        for start, end in ranges:
            require(0 <= start < end <= len(self.data), f"{category} range exceeds the PDB")
            size = end - start
            piece = replacement[consumed : consumed + size]
            before = self.data[start:end]
            self.normalized[category].append((start, end))
            change_start: int | None = None
            for relative, (old, new) in enumerate(zip(before, piece, strict=True)):
                absolute = start + relative
                if old != new and change_start is None:
                    change_start = absolute
                elif old == new and change_start is not None:
                    self.changed[category].append((change_start, absolute))
                    change_start = None
            if change_start is not None:
                self.changed[category].append((change_start, end))
            self.data[start:end] = piece
            consumed += size

    def zero(
        self,
        category: PdbCanonicalizationCategory,
        ranges: tuple[tuple[int, int], ...],
    ) -> None:
        self.replace(category, ranges, b"\0" * sum(end - start for start, end in ranges))

    def finish(
        self,
        raw: bytes,
        link_time: int,
        input_identity: Msvc42PdbIdentity,
    ) -> CanonicalizedMsvc42Pdb:
        all_ranges = sorted(
            (start, end, category)
            for category, ranges in self.normalized.items()
            for start, end in ranges
        )
        previous_end = 0
        for start, end, _category in all_ranges:
            require(start >= previous_end, "canonicalization categories overlap")
            previous_end = end

        output = bytes(self.data)
        preserved_raw = bytearray(raw)
        preserved_output = bytearray(output)
        for start, end, _category in all_ranges:
            preserved_raw[start:end] = b"\0" * (end - start)
            preserved_output[start:end] = b"\0" * (end - start)
        require(
            preserved_raw == preserved_output,
            "canonicalization changed a byte outside its audited ranges",
        )

        stats: list[PdbCanonicalizationStat] = []
        for category in PdbCanonicalizationCategory:
            normalized = _coalesce(self.normalized[category])
            if not normalized:
                continue
            changed = _coalesce(self.changed[category])
            stats.append(
                PdbCanonicalizationStat(
                    category=category,
                    normalized_ranges=normalized,
                    changed_ranges=changed,
                    normalized_bytes=sum(item.size for item in normalized),
                    changed_bytes=sum(item.size for item in changed),
                )
            )
        return CanonicalizedMsvc42Pdb(
            data=output,
            audit=PdbCanonicalizationAudit(
                policy_version=MSVC42_PDB_CANONICALIZATION_POLICY,
                raw_sha256=sha256(raw).hexdigest(),
                output_sha256=sha256(output).hexdigest(),
                bytes_outside_policy_ranges_sha256=sha256(preserved_raw).hexdigest(),
                size=len(raw),
                link_time=link_time,
                input_identity=input_identity,
                output_identity=Msvc42PdbIdentity(
                    input_identity.version,
                    link_time,
                    input_identity.age,
                ),
                stats=tuple(stats),
            ),
        )


def _stream_zero(msf: SmallMsf, edits: _Edits) -> None:
    stream = msf.read_stream(0, "SmallMSF stream 0")
    table = parse_small_msf_stream_table(
        stream,
        page_count=msf.page_count,
        context="SmallMSF stream 0 table",
    )
    for offset in table.pointer_offsets:
        edits.zero(
            PdbCanonicalizationCategory.MSF_STREAM_ZERO_POINTERS,
            msf.stream_ranges(0, offset, 4, "SmallMSF stream 0 pointer"),
        )


def _pdb_identity(msf: SmallMsf) -> Msvc42PdbIdentity:
    stream = msf.read_stream(1, "PDB info")
    require(len(stream) >= 12, "PDB info stream is truncated")
    version, signature, age = struct.unpack_from("<III", stream, 0)
    require(version == _PDB_STREAM_VERSION, "unsupported PDB info stream version")
    return Msvc42PdbIdentity(version, signature, age)


def _pdb_stream(msf: SmallMsf, edits: _Edits, link_time: int) -> Msvc42PdbIdentity:
    identity = _pdb_identity(msf)
    edits.replace(
        PdbCanonicalizationCategory.PDB_SIGNATURE,
        msf.stream_ranges(1, 4, 4, "PDB signature"),
        struct.pack("<I", link_time),
    )
    return identity


def _tpi_stream(msf: SmallMsf, edits: _Edits) -> int:
    stream = msf.read_stream(2, "TPI")
    require(len(stream) >= _TPI_HEADER_SIZE, "TPI stream is truncated")
    version, ti_min, ti_mac, record_bytes, hash_stream = struct.unpack_from(
        "<IHHIH", stream, 0
    )
    hash_stream = int(hash_stream)
    require(version == _TPI_STREAM_VERSION, "unsupported TPI stream version")
    require(stream[14:16] == b"\0\0", "TPI header ABI padding is not canonical")
    require(ti_min == 0x1000 and ti_mac >= ti_min, "TPI type-index range is invalid")
    require(
        len(stream) == _TPI_HEADER_SIZE + record_bytes,
        "TPI record byte count does not exhaust the stream",
    )

    cursor = _TPI_HEADER_SIZE
    record_offsets: list[int] = []
    while cursor < len(stream):
        record_offsets.append(cursor - _TPI_HEADER_SIZE)
        require(cursor <= len(stream) - 2, "TPI record length is truncated")
        length = struct.unpack_from("<H", stream, cursor)[0]
        require(length >= 2, "TPI record is too short")
        cursor += 2 + length
        require(cursor <= len(stream), "TPI record exceeds the stream")
        require(
            (2 + length) % 4 == 0,
            "TPI record size is not aligned",
        )
    record_count = len(record_offsets)
    require(record_count == ti_mac - ti_min, "TPI record count differs from its type range")

    require(hash_stream >= 4, "TPI hash aliases a reserved PDB stream")
    hashes = msf.read_stream(hash_stream, "TPI hash")
    hash_bytes = 2 * record_count
    require(hash_bytes <= len(hashes), "TPI hash values are truncated")
    require((len(hashes) - hash_bytes) % 8 == 0, "TPI TI_OFF_16t table is misaligned")
    require(
        record_count == 0 or len(hashes) > hash_bytes,
        "TPI TI_OFF_16t table has no initial entry",
    )
    previous_ti = ti_min - 1
    previous_offset = -1
    for entry_index, offset in enumerate(range(hash_bytes, len(hashes), 8)):
        ti = struct.unpack_from("<H", hashes, offset)[0]
        record_offset = struct.unpack_from("<I", hashes, offset + 4)[0]
        require(ti_min <= ti < ti_mac, "TPI TI_OFF_16t type index is out of range")
        require(record_offset < record_bytes, "TPI TI_OFF_16t record offset is out of range")
        require(
            ti > previous_ti and record_offset > previous_offset,
            "TPI TI_OFF_16t entries are not ordered",
        )
        require(
            record_offset == record_offsets[ti - ti_min],
            "TPI TI_OFF_16t entry does not name its type-record boundary",
        )
        if entry_index == 0:
            require(
                ti == ti_min and record_offset == 0,
                "TPI TI_OFF_16t table has no canonical initial entry",
            )
        edits.zero(
            PdbCanonicalizationCategory.TPI_TI_OFF_PADDING,
            msf.stream_ranges(hash_stream, offset + 2, 2, "TPI TI_OFF_16t padding"),
        )
        previous_ti = ti
        previous_offset = record_offset
    return hash_stream


def _find_nul(data: bytes, start: int, end: int, context: str) -> int:
    offset = data.find(b"\0", start, end)
    require(offset >= 0, f"{context} is not NUL-terminated")
    return offset


def _dbi_stream(msf: SmallMsf, edits: _Edits) -> _DbiStreams:
    stream = msf.read_stream(3, "DBI")
    require(len(stream) >= _DBI_HEADER_SIZE, "DBI stream is truncated")
    global_symbols, public_symbols, symbol_records = struct.unpack_from("<HHH", stream, 0)
    module_bytes, sc_bytes, section_map_bytes, file_info_bytes = struct.unpack_from(
        "<IIII", stream, 8
    )
    auxiliary_streams: list[int] = []
    for number, label in (
        (global_symbols, "DBI global-symbol"),
        (public_symbols, "DBI public-symbol"),
        (symbol_records, "DBI symbol-record"),
    ):
        if number != _NIL_STREAM:
            require(number >= 4, f"{label} aliases a reserved PDB stream")
            msf.require_stream(number, label)
            auxiliary_streams.append(number)
    require(
        len(set(auxiliary_streams)) == len(auxiliary_streams),
        "DBI auxiliary stream roles alias one another",
    )
    require(module_bytes % 4 == 0, "DBI MODI50 substream is not aligned")
    require(sc_bytes % _SC40_SIZE == 0, "DBI SC40 substream is not aligned")
    require(
        len(stream)
        == _DBI_HEADER_SIZE + module_bytes + sc_bytes + section_map_bytes + file_info_bytes,
        "DBI substream sizes do not exhaust the stream",
    )
    edits.zero(
        PdbCanonicalizationCategory.DBI_ABI_PADDING,
        msf.stream_ranges(3, 6, 2, "DBI header ABI padding"),
    )

    module_end = _DBI_HEADER_SIZE + module_bytes
    modules: list[_ModuleStream] = []
    live_streams: set[int] = set()
    cursor = _DBI_HEADER_SIZE
    while cursor < module_end:
        require(cursor <= module_end - _MODI50_FIXED_SIZE, "DBI MODI50 record is truncated")
        stream_number = struct.unpack_from("<H", stream, cursor + 26)[0]
        symbol_size, line_size, fpo_size = struct.unpack_from("<III", stream, cursor + 28)
        if stream_number == _NIL_STREAM:
            require(
                symbol_size == line_size == fpo_size == 0,
                "DBI nil module stream has debug data",
            )
        else:
            module_stream = msf.require_stream(stream_number, "DBI module")
            require(stream_number >= 4, "DBI module aliases a reserved PDB stream")
            require(stream_number not in live_streams, "DBI module stream is referenced twice")
            require(symbol_size >= 4, "DBI module symbol stream is truncated")
            require(symbol_size <= module_stream.size, "DBI module symbols exceed their stream")
            require(
                line_size <= module_stream.size - symbol_size,
                "DBI module lines exceed their stream",
            )
            require(
                fpo_size <= module_stream.size - symbol_size - line_size,
                "DBI module FPO data exceeds its stream",
            )
            modules.append(_ModuleStream(stream_number, symbol_size))
            live_streams.add(stream_number)

        first_nul = _find_nul(stream, cursor + _MODI50_FIXED_SIZE, module_end, "DBI module name")
        require(first_nul > cursor + _MODI50_FIXED_SIZE, "DBI module name is empty")
        second_nul = _find_nul(stream, first_nul + 1, module_end, "DBI object name")
        require(second_nul > first_nul + 1, "DBI object name is empty")
        record_end = (second_nul + 4) & ~3
        require(record_end <= module_end, "DBI MODI50 alignment exceeds its substream")

        edits.zero(
            PdbCanonicalizationCategory.DBI_TRANSIENT_POINTERS,
            msf.stream_ranges(3, cursor, 4, "DBI pmod pointer"),
        )
        edits.zero(
            PdbCanonicalizationCategory.DBI_SC40_PADDING,
            msf.stream_ranges(3, cursor + 6, 2, "DBI embedded SC40 leading padding"),
        )
        edits.zero(
            PdbCanonicalizationCategory.DBI_SC40_PADDING,
            msf.stream_ranges(3, cursor + 22, 2, "DBI embedded SC40 trailing padding"),
        )
        edits.zero(
            PdbCanonicalizationCategory.DBI_ABI_PADDING,
            msf.stream_ranges(3, cursor + 42, 2, "DBI MODI50 ABI padding"),
        )
        edits.zero(
            PdbCanonicalizationCategory.DBI_TRANSIENT_POINTERS,
            msf.stream_ranges(3, cursor + 44, 4, "DBI mpifileichFile pointer"),
        )
        if second_nul + 1 < record_end:
            edits.zero(
                PdbCanonicalizationCategory.DBI_ABI_PADDING,
                msf.stream_ranges(
                    3,
                    second_nul + 1,
                    record_end - second_nul - 1,
                    "DBI MODI50 string alignment",
                ),
            )
        cursor = record_end
    require(cursor == module_end, "DBI MODI50 records do not exhaust their substream")

    sc_end = module_end + sc_bytes
    for offset in range(module_end, sc_end, _SC40_SIZE):
        edits.zero(
            PdbCanonicalizationCategory.DBI_SC40_PADDING,
            msf.stream_ranges(3, offset + 2, 2, "DBI SC40 leading padding"),
        )
        edits.zero(
            PdbCanonicalizationCategory.DBI_SC40_PADDING,
            msf.stream_ranges(3, offset + 18, 2, "DBI SC40 trailing padding"),
        )
    return _DbiStreams(tuple(modules), tuple(auxiliary_streams))


def _validate_stream_roles(tpi_hash: int, dbi: _DbiStreams) -> None:
    roles = (tpi_hash, *dbi.auxiliaries, *(module.number for module in dbi.modules))
    require(len(set(roles)) == len(roles), "MSVC 4.2 PDB stream roles alias one another")


def _module_streams(msf: SmallMsf, edits: _Edits, modules: tuple[_ModuleStream, ...]) -> None:
    for module in modules:
        stream = msf.read_stream(module.number, "DBI module symbols")
        signature = struct.unpack_from("<I", stream, 0)[0]
        require(signature == _MODULE_STREAM_SIGNATURE, "unsupported module symbol signature")
        cursor = 4
        records: list[tuple[int, int, int]] = []
        while cursor < module.symbol_size:
            require(cursor <= module.symbol_size - 4, "CodeView symbol header is truncated")
            record_length, record_type = struct.unpack_from("<HH", stream, cursor)
            require(record_length >= 2, "CodeView symbol record is too short")
            record_end = cursor + 2 + record_length
            require(record_end <= module.symbol_size, "CodeView symbol exceeds cbSyms")
            require(record_end % 4 == 0, "CodeView symbol record is not aligned")
            records.append((cursor, record_end, record_type))
            cursor = record_end
        require(cursor == module.symbol_size, "CodeView symbols do not exhaust cbSyms")

        record_types = {start: record_type for start, _end, record_type in records}
        for cursor, record_end, record_type in records:
            if record_type == _S_GPROC32_16T:
                require(record_end >= cursor + 38, "S_GPROC32_16t fixed fields are truncated")
                parent, procedure_end, next_procedure = struct.unpack_from(
                    "<III", stream, cursor + 4
                )
                require(
                    procedure_end > cursor and record_types.get(procedure_end) == 0x0006,
                    "S_GPROC32_16t pEnd does not name an S_END record",
                )
                require(
                    parent == 0 or parent in record_types,
                    "S_GPROC32_16t pParent is not a record boundary",
                )
                require(
                    next_procedure == 0 or next_procedure in record_types,
                    "S_GPROC32_16t pNext is not a record boundary",
                )
                name_size = stream[cursor + 37]
                name_end = cursor + 38 + name_size
                require(name_end <= record_end, "S_GPROC32_16t name exceeds its record")
                tail_size = record_end - name_end
                expected_alignment = (-name_end) % 4
                if name_size < 255:
                    require(
                        tail_size == expected_alignment,
                        "S_GPROC32_16t has an unexplained tail",
                    )
                elif tail_size > expected_alignment:
                    require(
                        record_end % 4 == 0,
                        "truncated S_GPROC32_16t tail is not record-aligned",
                    )
                    edits.zero(
                        PdbCanonicalizationCategory.CODEVIEW_GPROC_TAIL,
                        msf.stream_ranges(
                            module.number,
                            name_end,
                            tail_size,
                            "S_GPROC32_16t unaddressable tail",
                        ),
                    )
                else:
                    require(
                        tail_size == expected_alignment,
                        "S_GPROC32_16t alignment is malformed",
                    )


def read_msvc42_pdb_identity(data: bytes) -> Msvc42PdbIdentity:
    """Read the raw signature and age that an NB10 image record must bind."""

    require(type(data) is bytes, "MSVC 4.2 PDB input must be bytes")
    return _pdb_identity(SmallMsf(data))


def _canonicalize_once(data: bytes, link_time: int) -> CanonicalizedMsvc42Pdb:
    msf = SmallMsf(data)
    require(len(msf.streams) >= 4, "MSVC 4.2 PDB is missing reserved streams")
    edits = _Edits(data)

    edits.zero(
        PdbCanonicalizationCategory.MSF_HEADER_POINTER,
        ((56, 60),),
    )
    for offset in msf.directory.pointer_offsets:
        edits.zero(
            PdbCanonicalizationCategory.MSF_DIRECTORY_POINTERS,
            msf.directory_ranges(offset, 4, "SmallMSF directory pointer"),
        )
    _stream_zero(msf, edits)
    input_identity = _pdb_stream(msf, edits, link_time)
    tpi_hash = _tpi_stream(msf, edits)
    dbi = _dbi_stream(msf, edits)
    _validate_stream_roles(tpi_hash, dbi)
    _module_streams(msf, edits, dbi.modules)
    for page in msf.unreferenced_free_pages:
        start = page * msf.page_size
        edits.zero(
            PdbCanonicalizationCategory.MSF_FREE_PAGES,
            ((start, start + msf.page_size),),
        )

    result = edits.finish(data, link_time, input_identity)
    SmallMsf(result.data)
    return result


def canonicalize_msvc42_pdb(
    data: bytes,
    *,
    link_time: int,
    expected_input_identity: Msvc42PdbIdentity,
) -> CanonicalizedMsvc42Pdb:
    """Canonicalize only parsed MSVC 4.2 PDB bookkeeping and padding.

    ``link_time`` is the declared authentic PE/PDB timestamp.
    ``expected_input_identity`` must come from the raw private image's NB10
    binding; the transform refuses to rebind a different PDB.
    Unsupported or ambiguous input raises
    :class:`reprobit.binary.ByteIdentityError` before a result is returned.
    """

    require(type(data) is bytes, "MSVC 4.2 PDB input must be bytes")
    require(type(link_time) is int, "MSVC 4.2 PDB link_time must be an integer")
    require(0 <= link_time <= 0x7FFFFFFF, "MSVC 4.2 PDB link_time is out of range")
    require(
        type(expected_input_identity) is Msvc42PdbIdentity,
        "MSVC 4.2 expected input identity is invalid",
    )
    observed_identity = read_msvc42_pdb_identity(data)
    require(
        observed_identity == expected_input_identity,
        "MSVC 4.2 PDB identity differs from the raw NB10 binding",
    )
    result = _canonicalize_once(data, link_time)
    reparsed = _canonicalize_once(result.data, link_time)
    require(
        reparsed.data == result.data and reparsed.audit.changed_bytes == 0,
        "canonical MSVC 4.2 PDB is not structurally idempotent",
    )
    return result


__all__ = [
    "MSVC42_PDB_CANONICALIZATION_POLICY",
    "CanonicalizedMsvc42Pdb",
    "Msvc42PdbIdentity",
    "PdbCanonicalizationAudit",
    "PdbCanonicalizationCategory",
    "PdbCanonicalizationRange",
    "PdbCanonicalizationStat",
    "canonicalize_msvc42_pdb",
    "read_msvc42_pdb_identity",
]
