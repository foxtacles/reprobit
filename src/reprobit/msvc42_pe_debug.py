"""Fail-closed identity policy for an MSVC 4.2 debug-companion image.

The VC 4.2 linker binds a PE image to its PDB with an ``NB10`` record.  A
private analysis relink may have a different wall-clock value even when every
semantic byte is stable.  This module recognizes the exact old PE/debug
layout and permits only the three copies of that value to be pinned:

* the PE COFF timestamp;
* every ``IMAGE_DEBUG_DIRECTORY`` timestamp; and
* the ``NB10`` signature.

It does not rewrite addresses, section layout, symbols, FPO data, paths, or
arbitrary overlay bytes.  Unknown and ambiguous layouts are rejected before a
result is returned.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from itertools import pairwise

from reprobit.binary import require
from reprobit.msvc42_pdb import Msvc42PdbIdentity

_IMAGE_FILE_MACHINE_I386 = 0x014C
_IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x010B
_IMAGE_DEBUG_TYPE_CODEVIEW = 2
_IMAGE_DEBUG_TYPE_FPO = 3
_IMAGE_DEBUG_TYPE_MISC = 4
_IMAGE_DEBUG_MISC_EXENAME = 1
_DEBUG_DIRECTORY_INDEX = 6
_DEBUG_DIRECTORY = struct.Struct("<IIHHIIII")
_NB10 = struct.Struct("<4sIII")
_DEBUG_MISC = struct.Struct("<IIB3s")
_FPO_DATA = struct.Struct("<IIIHH")
_MSVC42_PDB_VERSION = 19950814

MSVC42_DEBUG_COMPANION_POLICY = "msvc42-pe-debug-companion-v1"


class DebugCompanionCanonicalizationCategory(StrEnum):
    """The three named sources of the coupled link timestamp."""

    PE_COFF_TIMESTAMP = "pe.coff_timestamp"
    DEBUG_DIRECTORY_TIMESTAMP = "pe.debug_directory_timestamp"
    NB10_SIGNATURE = "codeview.nb10_signature"


@dataclass(frozen=True, slots=True)
class Msvc42DebugCompanionIdentity:
    """The identity shared by a VC 4.2 analysis image and its PDB."""

    signature: int
    age: int
    pdb_path: str

    @property
    def pdb_identity(self) -> Msvc42PdbIdentity:
        """Return the old-PDB identity represented by this ``NB10`` record."""

        return Msvc42PdbIdentity(_MSVC42_PDB_VERSION, self.signature, self.age)


@dataclass(frozen=True, slots=True)
class DebugCompanionCanonicalizationWrite:
    """One audited four-byte timestamp write."""

    category: DebugCompanionCanonicalizationCategory
    file_offset: int
    before: int
    after: int


@dataclass(frozen=True, slots=True)
class DebugCompanionCanonicalizationAudit:
    """Content identity and byte-preservation proof for one transform."""

    policy_version: str
    raw_sha256: str
    output_sha256: str
    bytes_outside_policy_ranges_sha256: str
    size: int
    link_time: int
    input_identity: Msvc42DebugCompanionIdentity
    output_identity: Msvc42DebugCompanionIdentity
    writes: tuple[DebugCompanionCanonicalizationWrite, ...]
    changed_bytes: int

    @property
    def normalized_bytes(self) -> int:
        return 4 * len(self.writes)


@dataclass(frozen=True, slots=True)
class CanonicalizedMsvc42DebugCompanion:
    """Canonical debug-companion image bytes paired with their audit."""

    data: bytes
    audit: DebugCompanionCanonicalizationAudit


@dataclass(frozen=True, slots=True)
class _Section:
    virtual_address: int
    raw_offset: int
    raw_size: int

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


@dataclass(frozen=True, slots=True)
class _ParsedDebugCompanion:
    identity: Msvc42DebugCompanionIdentity
    timestamp_fields: tuple[tuple[DebugCompanionCanonicalizationCategory, int], ...]


def _validate_windows_path_bytes(value: bytes, context: str) -> None:
    require(3 <= len(value) <= 259, f"{context} length is outside the VC 4.2 range")
    require(
        ((65 <= value[0] <= 90) or (97 <= value[0] <= 122)) and value[1:3] == b":\\",
        f"{context} is not an absolute drive path",
    )
    require(b"/" not in value, f"{context} uses a non-DOS path separator")
    require(
        all(0x20 <= byte <= 0x7E for byte in value),
        f"{context} is not a printable VC 4.2 path",
    )


def _expected_pdb_path_bytes(expected_pdb_path: str) -> bytes:
    require(type(expected_pdb_path) is str, "expected logical PDB path must be a string")
    require(expected_pdb_path.isascii(), "expected logical PDB path is not ASCII")
    encoded = expected_pdb_path.encode("ascii")
    _validate_windows_path_bytes(encoded, "expected logical PDB path")
    require(encoded[-4:].lower() == b".pdb", "expected logical PDB path is not a PDB")
    return encoded


class _Pe32DebugMap:
    """Validated PE32 geometry and the narrow VC 4.2 debug overlay."""

    def __init__(self, data: bytes, expected_pdb_path: str) -> None:
        require(len(data) >= 64 and data[:2] == b"MZ", "missing DOS MZ header")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        require(64 <= pe <= len(data) - 24, "PE header extends past EOF")
        require(data[pe : pe + 4] == b"PE\0\0", "missing PE signature")

        machine, section_count = struct.unpack_from("<HH", data, pe + 4)
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        require(machine == _IMAGE_FILE_MACHINE_I386, "debug companion is not i386")
        require(0 < section_count <= 96, "PE section count is invalid")
        optional = pe + 24
        require(
            optional_size >= 152 and optional <= len(data) - optional_size,
            "PE32 optional header lacks the debug data directory",
        )
        require(
            struct.unpack_from("<H", data, optional)[0] == _IMAGE_NT_OPTIONAL_HDR32_MAGIC,
            "debug companion is not PE32",
        )
        checksum = struct.unpack_from("<I", data, optional + 64)[0]
        size_of_headers = struct.unpack_from("<I", data, optional + 60)[0]
        directory_count = struct.unpack_from("<I", data, optional + 92)[0]
        require(checksum == 0, "MSVC 4.2 debug companion checksum is not zero")
        require(
            directory_count > _DEBUG_DIRECTORY_INDEX,
            "debug companion lacks the PE debug data directory",
        )

        table = optional + optional_size
        table_end = table + section_count * 40
        require(
            table_end <= size_of_headers <= len(data),
            "PE section table is outside SizeOfHeaders",
        )

        sections: list[_Section] = []
        for index in range(section_count):
            header = table + index * 40
            name = data[header : header + 8].rstrip(b"\0")
            _virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, header + 8
            )
            require(
                raw_size == 0
                or (raw_offset >= size_of_headers and raw_offset <= len(data) - raw_size),
                f"PE section {name!r} raw data is invalid",
            )
            sections.append(_Section(virtual_address, raw_offset, raw_size))

        raw_ranges = sorted(
            (section.raw_offset, section.raw_end) for section in sections if section.raw_size
        )
        require(
            all(left[1] <= right[0] for left, right in pairwise(raw_ranges)),
            "PE sections overlap in the file",
        )
        self.sections = tuple(sections)
        coff_timestamp_offset = pe + 8

        directory_at = optional + 96 + _DEBUG_DIRECTORY_INDEX * 8
        debug_rva, debug_size = struct.unpack_from("<II", data, directory_at)
        require(
            debug_rva != 0
            and debug_size >= _DEBUG_DIRECTORY.size
            and debug_size % _DEBUG_DIRECTORY.size == 0,
            "PE debug data directory is missing or malformed",
        )
        debug_offset = self.rva_to_offset(debug_rva, debug_size, "PE debug data directory")
        entry_count = debug_size // _DEBUG_DIRECTORY.size

        entries: list[tuple[int, int, int, int]] = []
        debug_timestamps: list[int] = []
        for index in range(entry_count):
            entry = debug_offset + index * _DEBUG_DIRECTORY.size
            (
                characteristics,
                timestamp,
                major,
                minor,
                kind,
                payload_size,
                payload_rva,
                payload_offset,
            ) = _DEBUG_DIRECTORY.unpack_from(data, entry)
            require(characteristics == 0, "PE debug entry characteristics are not zero")
            require(major == 0 and minor == 0, "PE debug entry version is not zero")
            require(
                kind
                in {
                    _IMAGE_DEBUG_TYPE_CODEVIEW,
                    _IMAGE_DEBUG_TYPE_FPO,
                    _IMAGE_DEBUG_TYPE_MISC,
                },
                f"PE debug entry type {kind} is not admitted",
            )
            require(payload_size > 0, "PE debug entry has an empty payload")
            require(
                payload_offset > 0 and payload_offset <= len(data) - payload_size,
                "PE debug payload range is invalid",
            )
            if payload_rva != 0:
                require(
                    self.rva_to_offset(payload_rva, payload_size, "PE debug payload")
                    == payload_offset,
                    "PE debug payload RVA and file pointer disagree",
                )
            else:
                payload_end = payload_offset + payload_size
                require(
                    payload_offset >= size_of_headers
                    and all(
                        payload_end <= section.raw_offset or payload_offset >= section.raw_end
                        for section in sections
                        if section.raw_size
                    ),
                    "zero-RVA PE debug payload is not in an external overlay",
                )
            entries.append((kind, payload_offset, payload_size, timestamp))
            debug_timestamps.append(entry + 4)

        kinds = tuple(entry[0] for entry in entries)
        require(
            kinds.count(_IMAGE_DEBUG_TYPE_MISC) <= 1 and kinds.count(_IMAGE_DEBUG_TYPE_FPO) <= 1,
            "PE debug data repeats a VC 4.2 MISC or FPO entry",
        )
        require(
            kinds.count(_IMAGE_DEBUG_TYPE_CODEVIEW) == 1,
            "PE debug data must contain exactly one CodeView entry",
        )

        payload_ranges = sorted(
            (payload_offset, payload_offset + payload_size)
            for _kind, payload_offset, payload_size, _timestamp in entries
        )
        require(
            all(left[1] <= right[0] for left, right in pairwise(payload_ranges)),
            "PE debug payloads overlap",
        )
        debug_end = debug_offset + debug_size
        for payload_offset, payload_end in payload_ranges:
            require(
                payload_end <= debug_offset or payload_offset >= debug_end,
                "PE debug payload overlaps its directory",
            )

        raw_timestamp = struct.unpack_from("<I", data, coff_timestamp_offset)[0]
        require(raw_timestamp <= 0x7FFFFFFF, "PE COFF timestamp is outside classic time_t")
        nb10_signature: int | None = None
        nb10_age: int | None = None
        nb10_signature_offset: int | None = None
        expected_path_bytes = _expected_pdb_path_bytes(expected_pdb_path)
        for kind, payload_offset, payload_size, timestamp in entries:
            require(
                timestamp == raw_timestamp,
                "PE debug-entry timestamp differs from its COFF timestamp",
            )
            payload = data[payload_offset : payload_offset + payload_size]
            if kind == _IMAGE_DEBUG_TYPE_MISC:
                self._validate_misc(payload)
            elif kind == _IMAGE_DEBUG_TYPE_FPO:
                self._validate_fpo(payload)
            else:
                signature, age = self._validate_nb10(payload, expected_path_bytes)
                nb10_signature = signature
                nb10_age = age
                nb10_signature_offset = payload_offset + 8

        require(
            nb10_signature == raw_timestamp,
            "NB10 signature differs from the PE/debug timestamp",
        )
        require(
            nb10_age is not None and nb10_signature_offset is not None,
            "PE debug data lacks a validated NB10 record",
        )
        assert nb10_signature is not None
        assert nb10_age is not None
        assert nb10_signature_offset is not None
        self.parsed = _ParsedDebugCompanion(
            identity=Msvc42DebugCompanionIdentity(
                signature=nb10_signature,
                age=nb10_age,
                pdb_path=expected_pdb_path,
            ),
            timestamp_fields=(
                (
                    DebugCompanionCanonicalizationCategory.PE_COFF_TIMESTAMP,
                    coff_timestamp_offset,
                ),
                *(
                    (
                        DebugCompanionCanonicalizationCategory.DEBUG_DIRECTORY_TIMESTAMP,
                        offset,
                    )
                    for offset in debug_timestamps
                ),
                (
                    DebugCompanionCanonicalizationCategory.NB10_SIGNATURE,
                    nb10_signature_offset,
                ),
            ),
        )

    def rva_to_offset(self, rva: int, size: int, context: str) -> int:
        require(size > 0, f"{context} is empty")
        require(0 < rva <= 0xFFFFFFFF - size, f"{context} RVA range overflows")
        matches = []
        for section in self.sections:
            delta = rva - section.virtual_address
            if delta >= 0 and delta <= section.raw_size - size:
                matches.append(section.raw_offset + delta)
        require(len(matches) == 1, f"{context} does not map uniquely to raw section data")
        return matches[0]

    @staticmethod
    def _validate_misc(payload: bytes) -> None:
        require(
            len(payload) == 272,
            "VC 4.2 MISC EXENAME payload does not have its fixed size",
        )
        data_type, length, unicode, reserved = _DEBUG_MISC.unpack_from(payload, 0)
        require(data_type == _IMAGE_DEBUG_MISC_EXENAME, "MISC debug payload is not EXENAME")
        require(length == len(payload), "MISC EXENAME length differs from its payload")
        require(unicode == 0 and reserved == b"\0\0\0", "MISC EXENAME flags are malformed")
        name, separator, padding = payload[_DEBUG_MISC.size :].partition(b"\0")
        require(separator == b"\0" and bool(name), "MISC EXENAME path is not terminated")
        require(not padding.strip(b"\0"), "MISC EXENAME has nonzero trailing bytes")
        _validate_windows_path_bytes(name, "MISC EXENAME path")

    @staticmethod
    def _validate_fpo(payload: bytes) -> None:
        require(
            len(payload) >= _FPO_DATA.size and len(payload) % _FPO_DATA.size == 0,
            "FPO debug payload is not a non-empty FPO_DATA array",
        )
        for offset in range(0, len(payload), _FPO_DATA.size):
            _start, _procedure_size, _locals, _params, attributes = _FPO_DATA.unpack_from(
                payload, offset
            )
            reserved = (attributes >> 13) & 0x1
            require(reserved == 0, "FPO record reserved bit is set")

    @staticmethod
    def _validate_nb10(payload: bytes, expected_path: bytes) -> tuple[int, int]:
        require(len(payload) >= _NB10.size + 1, "CodeView NB10 payload is truncated")
        magic, offset, signature, age = _NB10.unpack_from(payload, 0)
        require(magic == b"NB10", "CodeView debug payload is not NB10")
        require(offset == 0, "NB10 offset is not zero")
        require(age == 0, "NB10 age is not zero")
        require(
            payload[_NB10.size :] == expected_path + b"\0",
            "NB10 PDB path differs from the exact planned logical path",
        )
        return signature, age


def read_msvc42_debug_companion_identity(
    data: bytes,
    *,
    expected_pdb_path: str,
) -> Msvc42DebugCompanionIdentity:
    """Parse and return one fully coupled VC 4.2 image-side identity."""

    require(type(data) is bytes, "MSVC 4.2 debug-companion input must be bytes")
    return _Pe32DebugMap(data, expected_pdb_path).parsed.identity


def _canonicalize_once(
    data: bytes,
    *,
    link_time: int,
    expected_pdb_path: str,
    expected_input_pdb_identity: Msvc42PdbIdentity,
) -> CanonicalizedMsvc42DebugCompanion:
    parsed = _Pe32DebugMap(data, expected_pdb_path).parsed
    require(
        parsed.identity.pdb_identity == expected_input_pdb_identity,
        "MSVC 4.2 debug-companion identity differs from the raw PDB binding",
    )

    output = bytearray(data)
    writes: list[DebugCompanionCanonicalizationWrite] = []
    offsets: set[int] = set()
    for category, offset in parsed.timestamp_fields:
        require(offset not in offsets, "debug-companion timestamp fields overlap")
        offsets.add(offset)
        before = struct.unpack_from("<I", data, offset)[0]
        struct.pack_into("<I", output, offset, link_time)
        writes.append(DebugCompanionCanonicalizationWrite(category, offset, before, link_time))
    result = bytes(output)

    preserved_raw = bytearray(data)
    preserved_output = bytearray(result)
    for offset in offsets:
        preserved_raw[offset : offset + 4] = b"\0" * 4
        preserved_output[offset : offset + 4] = b"\0" * 4
    require(
        preserved_raw == preserved_output,
        "debug-companion canonicalization changed a byte outside its audited fields",
    )
    changed_bytes = sum(before != after for before, after in zip(data, result, strict=True))
    output_identity = Msvc42DebugCompanionIdentity(
        signature=link_time,
        age=parsed.identity.age,
        pdb_path=parsed.identity.pdb_path,
    )
    reparsed = _Pe32DebugMap(result, expected_pdb_path).parsed.identity
    require(reparsed == output_identity, "canonical debug companion did not recouple its identity")
    require(
        reparsed.pdb_identity
        == Msvc42PdbIdentity(_MSVC42_PDB_VERSION, link_time, parsed.identity.age),
        "canonical debug companion did not recouple to the canonical PDB identity",
    )
    return CanonicalizedMsvc42DebugCompanion(
        data=result,
        audit=DebugCompanionCanonicalizationAudit(
            policy_version=MSVC42_DEBUG_COMPANION_POLICY,
            raw_sha256=sha256(data).hexdigest(),
            output_sha256=sha256(result).hexdigest(),
            bytes_outside_policy_ranges_sha256=sha256(preserved_raw).hexdigest(),
            size=len(data),
            link_time=link_time,
            input_identity=parsed.identity,
            output_identity=output_identity,
            writes=tuple(writes),
            changed_bytes=changed_bytes,
        ),
    )


def canonicalize_msvc42_debug_companion(
    data: bytes,
    *,
    link_time: int,
    expected_pdb_path: str,
    expected_input_pdb_identity: Msvc42PdbIdentity,
) -> CanonicalizedMsvc42DebugCompanion:
    """Pin only the coupled timestamp fields of a validated VC 4.2 image.

    The mandatory PDB identity must be read from the raw private PDB, not
    synthesized from the image.  This prevents accidentally rebinding a PDB
    from another link.  The returned image is reparsed and canonicalized a
    second time to prove identity coupling and structural idempotence.
    """

    require(type(data) is bytes, "MSVC 4.2 debug-companion input must be bytes")
    require(type(link_time) is int, "MSVC 4.2 debug link_time must be an integer")
    require(0 <= link_time <= 0x7FFFFFFF, "MSVC 4.2 debug link_time is out of range")
    require(
        type(expected_input_pdb_identity) is Msvc42PdbIdentity,
        "MSVC 4.2 expected input PDB identity is invalid",
    )
    require(
        expected_input_pdb_identity.version == _MSVC42_PDB_VERSION,
        "MSVC 4.2 expected input PDB version is unsupported",
    )
    first = _canonicalize_once(
        data,
        link_time=link_time,
        expected_pdb_path=expected_pdb_path,
        expected_input_pdb_identity=expected_input_pdb_identity,
    )
    second = _canonicalize_once(
        first.data,
        link_time=link_time,
        expected_pdb_path=expected_pdb_path,
        expected_input_pdb_identity=first.audit.output_identity.pdb_identity,
    )
    require(
        second.data == first.data and second.audit.changed_bytes == 0,
        "canonical MSVC 4.2 debug companion is not structurally idempotent",
    )
    return first


__all__ = [
    "MSVC42_DEBUG_COMPANION_POLICY",
    "CanonicalizedMsvc42DebugCompanion",
    "DebugCompanionCanonicalizationAudit",
    "DebugCompanionCanonicalizationCategory",
    "DebugCompanionCanonicalizationWrite",
    "Msvc42DebugCompanionIdentity",
    "canonicalize_msvc42_debug_companion",
    "read_msvc42_debug_companion_identity",
]
