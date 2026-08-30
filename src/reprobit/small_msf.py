"""Strict reader for the 1 KiB-page SmallMSF container used by PDB 2.00.

The reader describes byte locations but never guesses or repairs them.  The
MSVC 4.2 policy lives in :mod:`reprobit.msvc42_pdb`; keeping the container
grammar separate makes the normalization boundary reviewable.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass

from reprobit.binary import require

SMALL_MSF_MAGIC = b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0"
SMALL_MSF_PAGE_SIZE = 1024
_DELETED_STREAM_SIZE = 0xFFFFFFFF
_FPM_BANK_PAGE_COUNT = 8
_FPM_BANK_STARTS = (1, 9)
_DATA_PAGE_MIN = 17
_MAX_PAGE_COUNT = 0xFFFF
_MAX_STREAM_COUNT = 0x1000


@dataclass(frozen=True, slots=True)
class SmallMsfStream:
    """One current stream and its physical page list."""

    size: int
    pages: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class SmallMsfStreamTable:
    """A fully consumed SmallMSF stream table."""

    streams: tuple[SmallMsfStream | None, ...]
    pointer_offsets: tuple[int, ...]


def _u16(data: bytes, offset: int, context: str) -> int:
    require(0 <= offset <= len(data) - 2, f"{context} is truncated")
    return int(struct.unpack_from("<H", data, offset)[0])


def _u32(data: bytes, offset: int, context: str) -> int:
    require(0 <= offset <= len(data) - 4, f"{context} is truncated")
    return int(struct.unpack_from("<I", data, offset)[0])


def parse_small_msf_stream_table(
    data: bytes,
    *,
    page_count: int,
    context: str,
) -> SmallMsfStreamTable:
    """Parse one old SmallMSF stream table and require exact consumption."""

    require(len(data) >= 4, f"{context} header is truncated")
    stream_count = _u16(data, 0, f"{context} stream count")
    require(_u16(data, 2, f"{context} reserved field") == 0, f"{context} is not canonical")
    require(0 < stream_count <= _MAX_STREAM_COUNT, f"{context} stream count is unsupported")
    descriptor_end = 4 + stream_count * 8
    require(descriptor_end <= len(data), f"{context} descriptors are truncated")

    streams: list[SmallMsfStream | None] = []
    pointer_offsets: list[int] = []
    cursor = descriptor_end
    for stream_number in range(stream_count):
        descriptor = 4 + stream_number * 8
        size = _u32(data, descriptor, f"{context} stream {stream_number} size")
        pointer_offsets.append(descriptor + 4)
        if size == _DELETED_STREAM_SIZE:
            streams.append(None)
            continue
        require(
            size <= page_count * SMALL_MSF_PAGE_SIZE,
            f"{context} stream {stream_number} is larger than the file",
        )
        count = math.ceil(size / SMALL_MSF_PAGE_SIZE)
        require(
            cursor <= len(data) - count * 2,
            f"{context} stream {stream_number} page list is truncated",
        )
        pages = tuple(
            _u16(data, cursor + index * 2, f"{context} stream {stream_number} page")
            for index in range(count)
        )
        require(
            all(page < page_count for page in pages),
            f"{context} stream {stream_number} references an invalid page",
        )
        require(
            len(set(pages)) == len(pages),
            f"{context} stream {stream_number} repeats a page",
        )
        streams.append(SmallMsfStream(size=size, pages=pages))
        cursor += count * 2

    require(cursor == len(data), f"{context} has trailing or missing page data")
    return SmallMsfStreamTable(tuple(streams), tuple(pointer_offsets))


class SmallMsf:
    """Fail-closed description of a complete PDB 2.00 SmallMSF file."""

    def __init__(self, data: bytes) -> None:
        require(data[: len(SMALL_MSF_MAGIC)] == SMALL_MSF_MAGIC, "unsupported PDB/MSF magic")
        require(len(data) >= SMALL_MSF_PAGE_SIZE, "SmallMSF header page is truncated")
        self.data = data
        self.page_size = _u32(data, 44, "SmallMSF page size")
        require(
            self.page_size == SMALL_MSF_PAGE_SIZE,
            "only 1 KiB-page PDB 2.00 SmallMSF files are supported",
        )
        self.fpm_page = _u16(data, 48, "SmallMSF active FPM page")
        self.page_count = _u16(data, 50, "SmallMSF page count")
        require(
            _DATA_PAGE_MIN < self.page_count <= _MAX_PAGE_COUNT,
            "SmallMSF page count is unsupported",
        )
        require(
            len(data) == self.page_count * self.page_size,
            "SmallMSF file size does not match its page count",
        )
        require(
            self.fpm_page in _FPM_BANK_STARTS,
            "SmallMSF active FPM bank is invalid",
        )
        self.fpm_pages = tuple(range(self.fpm_page, self.fpm_page + _FPM_BANK_PAGE_COUNT))
        self.reserved_pages = frozenset(range(_DATA_PAGE_MIN))

        self.directory_size = _u32(data, 52, "SmallMSF directory size")
        require(self.directory_size >= 4, "SmallMSF directory is truncated")
        directory_page_count = math.ceil(self.directory_size / self.page_size)
        directory_list_end = 60 + directory_page_count * 2
        require(
            directory_list_end <= self.page_size,
            "SmallMSF directory page list exceeds the header page",
        )
        self.directory_pages = tuple(
            _u16(data, 60 + index * 2, "SmallMSF directory page")
            for index in range(directory_page_count)
        )
        require(
            all(page < self.page_count for page in self.directory_pages),
            "SmallMSF directory references an invalid page",
        )
        require(
            len(set(self.directory_pages)) == len(self.directory_pages),
            "SmallMSF directory repeats a page",
        )
        require(
            not (self.reserved_pages & set(self.directory_pages)),
            "SmallMSF directory aliases a structural page",
        )

        directory = self._read_pages(self.directory_pages, self.directory_size)
        self.directory = parse_small_msf_stream_table(
            directory,
            page_count=self.page_count,
            context="SmallMSF directory",
        )
        self.streams = self.directory.streams
        self.free_pages = self._parse_free_pages()
        self._validate_current_page_ownership()

    def _read_pages(self, pages: tuple[int, ...], size: int) -> bytes:
        return b"".join(
            self.data[page * self.page_size : (page + 1) * self.page_size] for page in pages
        )[:size]

    def _parse_free_pages(self) -> frozenset[int]:
        fpm = self._read_pages(self.fpm_pages, _FPM_BANK_PAGE_COUNT * self.page_size)
        return frozenset(
            page for page in range(self.page_count) if fpm[page // 8] & (1 << (page % 8))
        )

    def _validate_current_page_ownership(self) -> None:
        structural = {*self.reserved_pages, *self.directory_pages}
        require(
            not (structural & self.free_pages),
            "SmallMSF marks a structural page free",
        )
        owner: dict[int, int] = {}
        for stream_number, stream in enumerate(self.streams):
            if stream is None:
                continue
            for page in stream.pages:
                require(
                    page not in structural,
                    f"SmallMSF stream {stream_number} aliases a structural page",
                )
                require(page not in owner, f"SmallMSF page {page} belongs to multiple streams")
                require(
                    page not in self.free_pages or stream_number == 0,
                    f"SmallMSF live stream {stream_number} page {page} is marked free",
                )
                owner[page] = stream_number
        require(self.streams[0] is not None, "SmallMSF stream 0 is deleted")
        stream_zero = self.streams[0]
        assert stream_zero is not None
        require(
            all(page in self.free_pages for page in stream_zero.pages),
            "SmallMSF stream 0 container page is not free",
        )
        for page in range(_DATA_PAGE_MIN, self.page_count):
            if page in self.directory_pages or page in owner:
                continue
            require(page in self.free_pages, f"SmallMSF data page {page} has no owner")
        self.current_page_owners = owner

    def require_stream(self, stream_number: int, context: str) -> SmallMsfStream:
        require(
            0 <= stream_number < len(self.streams),
            f"{context} references missing stream {stream_number}",
        )
        stream = self.streams[stream_number]
        require(stream is not None, f"{context} references deleted stream {stream_number}")
        assert stream is not None
        return stream

    def read_stream(self, stream_number: int, context: str) -> bytes:
        stream = self.require_stream(stream_number, context)
        return self._read_pages(stream.pages, stream.size)

    def stream_ranges(
        self,
        stream_number: int,
        offset: int,
        size: int,
        context: str,
    ) -> tuple[tuple[int, int], ...]:
        stream = self.require_stream(stream_number, context)
        return self._logical_ranges(stream.pages, stream.size, offset, size, context)

    def directory_ranges(
        self,
        offset: int,
        size: int,
        context: str,
    ) -> tuple[tuple[int, int], ...]:
        return self._logical_ranges(
            self.directory_pages,
            self.directory_size,
            offset,
            size,
            context,
        )

    def _logical_ranges(
        self,
        pages: tuple[int, ...],
        logical_size: int,
        offset: int,
        size: int,
        context: str,
    ) -> tuple[tuple[int, int], ...]:
        require(size > 0, f"{context} range is empty")
        require(
            0 <= offset <= logical_size - size,
            f"{context} range exceeds its stream",
        )
        ranges: list[tuple[int, int]] = []
        remaining = size
        cursor = offset
        while remaining:
            page_index, within_page = divmod(cursor, self.page_size)
            count = min(remaining, self.page_size - within_page)
            absolute = pages[page_index] * self.page_size + within_page
            ranges.append((absolute, absolute + count))
            cursor += count
            remaining -= count
        return tuple(ranges)

    @property
    def unreferenced_free_pages(self) -> tuple[int, ...]:
        """FPM-free pages not used by any current root or stream."""

        roots = {*self.reserved_pages, *self.directory_pages, *self.current_page_owners}
        return tuple(sorted(self.free_pages - roots))


__all__ = [
    "SMALL_MSF_MAGIC",
    "SMALL_MSF_PAGE_SIZE",
    "SmallMsf",
    "SmallMsfStream",
    "SmallMsfStreamTable",
    "parse_small_msf_stream_table",
]
