"""Fail-closed PE32 metadata normalization over candidate-owned bytes."""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from itertools import pairwise

from reprobit.binary import require

from .foundation import (
    exact_audit_keys,
    require_exact_int,
    require_payload_free_declaration,
    sha256_bytes,
)


@dataclass(frozen=True, slots=True)
class _Section:
    name: bytes
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int

    @property
    def raw_end(self) -> int:
        return self.raw_offset + self.raw_size


class _PE32MetadataMap:
    """Validated PE surface needed to locate timestamp fields exactly."""

    def __init__(self, data: bytes) -> None:
        require(len(data) >= 64 and data[:2] == b"MZ", "missing DOS MZ header")
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        require(pe <= len(data) - 24 and data[pe : pe + 4] == b"PE\0\0", "missing PE signature")
        machine, section_count = struct.unpack_from("<HH", data, pe + 4)
        optional_size = struct.unpack_from("<H", data, pe + 20)[0]
        require(machine == 0x14C, "only i386 PE images are supported")
        require(0 < section_count <= 96, "invalid PE section count")
        optional = pe + 24
        require(
            optional_size >= 120 and optional + optional_size <= len(data),
            "PE32 optional header lacks required data directories",
        )
        require(
            struct.unpack_from("<H", data, optional)[0] == 0x10B,
            "only PE32 images are supported",
        )
        directory_count = struct.unpack_from("<I", data, optional + 92)[0]
        require(directory_count >= 3, "PE image lacks export/resource directories")
        self.data = data
        self.coff_timestamp_offset = pe + 8
        self.export_rva, self.export_size = struct.unpack_from("<II", data, optional + 96)
        self.resource_rva, self.resource_size = struct.unpack_from("<II", data, optional + 112)

        table = optional + optional_size
        require(table + section_count * 40 <= len(data), "section table extends past EOF")
        sections: list[_Section] = []
        for index in range(section_count):
            header = table + index * 40
            name = data[header : header + 8].rstrip(b"\0")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, header + 8
            )
            require(
                raw_size == 0 or raw_offset <= len(data) - raw_size,
                f"section {name!r} raw data extends past EOF",
            )
            sections.append(
                _Section(name, virtual_address, virtual_size, raw_offset, raw_size)
            )
        occupied = sorted(
            (section.raw_offset, section.raw_end)
            for section in sections
            if section.raw_size
        )
        require(
            all(left[1] <= right[0] for left, right in pairwise(occupied)),
            "PE sections overlap in the file",
        )
        self.sections = tuple(sections)

    def rva_to_offset(self, rva: int, size: int, context: str) -> int:
        require(size >= 0, f"{context} has a negative size")
        matches = []
        for section in self.sections:
            delta = rva - section.virtual_address
            if delta >= 0 and delta <= section.raw_size - size:
                matches.append(section.raw_offset + delta)
        require(len(matches) == 1, f"{context} does not map uniquely to raw data")
        return matches[0]

    def export_timestamp_offset(self) -> int | None:
        if self.export_rva == 0 and self.export_size == 0:
            return None
        require(
            self.export_rva != 0 and self.export_size >= 8,
            "export data directory is malformed",
        )
        return self.rva_to_offset(self.export_rva, 8, "export directory") + 4

    def resource_timestamp_offsets(self) -> tuple[int, ...]:
        if self.resource_rva == 0 and self.resource_size == 0:
            return ()
        require(
            self.resource_rva != 0 and self.resource_size >= 16,
            "resource data directory is malformed",
        )
        root = self.rva_to_offset(
            self.resource_rva,
            self.resource_size,
            "resource data directory",
        )
        limit = root + self.resource_size
        pending = [0]
        visited: set[int] = set()
        offsets: list[int] = []
        while pending:
            relative = pending.pop()
            require(relative not in visited, "resource directory graph has a cycle")
            visited.add(relative)
            require(len(visited) <= 65536, "resource directory graph is unreasonably large")
            directory = root + relative
            require(
                root <= directory <= limit - 16,
                "resource directory record is outside its data directory",
            )
            named, identified = struct.unpack_from("<HH", self.data, directory + 12)
            count = named + identified
            require(
                count <= 65535 and directory + 16 + count * 8 <= limit,
                "resource directory entries extend outside their data directory",
            )
            offsets.append(directory + 4)
            for index in range(count):
                entry = directory + 16 + index * 8
                child = struct.unpack_from("<I", self.data, entry + 4)[0]
                if child & 0x80000000:
                    pending.append(child & 0x7FFFFFFF)
        return tuple(sorted(offsets))


def apply_pe_metadata_candidate(
    candidate: bytes,
    declaration: Mapping[str, object],
) -> tuple[bytes, dict[str, object]]:
    """Normalize declared link/resource timestamps without an image oracle."""

    require(isinstance(candidate, bytes), "PE candidate must be immutable bytes")
    require_payload_free_declaration(declaration, "PE metadata declaration")
    value = dict(declaration)
    exact_audit_keys(value, {"link_time", "resource_time"}, "PE metadata declaration")
    link_time = require_exact_int(
        value.get("link_time"),
        "PE metadata declaration.link_time",
        minimum=0,
        maximum=0xFFFFFFFF,
    )
    resource_time = require_exact_int(
        value.get("resource_time"),
        "PE metadata declaration.resource_time",
        minimum=0,
        maximum=0xFFFFFFFF,
    )
    image = _PE32MetadataMap(candidate)
    writes: dict[int, int] = {image.coff_timestamp_offset: link_time}
    export = image.export_timestamp_offset()
    if export is not None:
        writes[export] = link_time
    for offset in image.resource_timestamp_offsets():
        writes[offset] = resource_time
    require(len(writes) == len(set(writes)), "PE metadata writes overlap")

    output = bytearray(candidate)
    previous = []
    for offset, timestamp in sorted(writes.items()):
        old = struct.unpack_from("<I", candidate, offset)[0]
        struct.pack_into("<I", output, offset, timestamp)
        previous.append({"file_offset": offset, "before": old, "after": timestamp})
    result = bytes(output)
    changed = {
        index
        for index, (before, after) in enumerate(zip(candidate, result, strict=True))
        if before != after
    }
    allowed = {
        byte
        for offset in writes
        for byte in range(offset, offset + 4)
    }
    require(changed <= allowed, "PE metadata normalization changed an undeclared byte")
    return result, {
        "schema": "pe32_timestamp_normalization_v1",
        "link_time": link_time,
        "resource_time": resource_time,
        "writes": previous,
        "input_sha256": sha256_bytes(candidate),
        "output_sha256": sha256_bytes(result),
        "candidate_only": True,
        "oracle_payload_bytes_read": 0,
    }


__all__ = ["apply_pe_metadata_candidate"]
