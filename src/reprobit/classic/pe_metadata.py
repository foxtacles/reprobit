"""Fail-closed PE32 metadata normalization over candidate-owned bytes."""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass

from reprobit.binary import require
from reprobit.pe32 import Pe32Headers, parse_pe32_headers

from .foundation import (
    exact_audit_keys,
    require_exact_int,
    require_payload_free_declaration,
    sha256_bytes,
)


@dataclass(frozen=True, slots=True)
class PE32MetadataTimes:
    """The two declared clock values carried by a stabilized PE32 image."""

    link_time: int
    resource_time: int


class _PE32MetadataMap:
    """Validated PE surface needed to locate timestamp fields exactly."""

    def __init__(self, data: bytes) -> None:
        self._headers: Pe32Headers = parse_pe32_headers(data, minimum_optional_size=120)
        directories = "export/resource directories"
        self.data = data
        self.coff_timestamp_offset = self._headers.coff_timestamp_offset
        self.export_rva, self.export_size = self._headers.data_directory(0, directories)
        self.resource_rva, self.resource_size = self._headers.data_directory(2, directories)
        self.sections = self._headers.sections

    def rva_to_offset(self, rva: int, size: int, context: str) -> int:
        return self._headers.rva_to_offset(rva, size, context=context)

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


def read_pe32_metadata_times(candidate: bytes) -> PE32MetadataTimes:
    """Read one already-coherent PE32 image metadata policy.

    The certified image is the authority for the companion image's clock
    values.  Refuse an image whose link-generated fields disagree rather than
    guessing which timestamp should win.  Images without resources have no
    independent resource clock, so their link time is the harmless canonical
    value for the unused policy seat.
    """

    require(isinstance(candidate, bytes), "PE candidate must be immutable bytes")
    image = _PE32MetadataMap(candidate)
    link_time = struct.unpack_from("<I", candidate, image.coff_timestamp_offset)[0]
    export = image.export_timestamp_offset()
    if export is not None:
        require(
            struct.unpack_from("<I", candidate, export)[0] == link_time,
            "PE export timestamp differs from its COFF link time",
        )
    resource_values = {
        struct.unpack_from("<I", candidate, offset)[0]
        for offset in image.resource_timestamp_offsets()
    }
    require(
        len(resource_values) <= 1,
        "PE resource directories do not share one timestamp",
    )
    resource_time = next(iter(resource_values), link_time)
    return PE32MetadataTimes(link_time, resource_time)


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
    allowed = {byte for offset in writes for byte in range(offset, offset + 4)}
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


__all__ = [
    "PE32MetadataTimes",
    "apply_pe_metadata_candidate",
    "read_pe32_metadata_times",
]
