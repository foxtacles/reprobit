"""Isolated, opt-in quarantine for frozen oracle-byte installations.

This module exposes only the sealed PE32 read capability required by the two
explicitly allowlisted quarantine interventions. It cannot copy arbitrary file
ranges or authorize new actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

from reprobit.verify import SealedFileOracle, VerificationError


class LegacyInstallError(RuntimeError):
    """Raised when a quarantined installation is not exactly allowlisted."""


@dataclass(frozen=True, slots=True)
class _PE32Section:
    name: str
    virtual_address: int
    mapped_size: int
    raw_offset: int
    raw_size: int

    @property
    def virtual_end(self) -> int:
        return self.virtual_address + self.mapped_size


class PE32VirtualAddressReader:
    """Read only mapped PE32 bytes through an already sealed capability.

    The reader has no path, descriptor, or file-offset API.  It is created by
    :func:`bind_pe32_oracle` after the complete PE header and section map have
    passed strict bounds checks, then permits only one-section virtual-address
    reads.  Virtual zero-fill tails are intentionally unreadable because they
    have no file bytes to authenticate.
    """

    __slots__ = (
        "__image_base",
        "__oracle",
        "__sections",
        "__size_of_headers",
        "__size_of_image",
    )

    def __init__(
        self,
        oracle: SealedFileOracle,
        *,
        image_base: int,
        size_of_headers: int,
        size_of_image: int,
        sections: tuple[_PE32Section, ...],
    ) -> None:
        self.__oracle = oracle
        self.__image_base = image_base
        self.__size_of_headers = size_of_headers
        self.__size_of_image = size_of_image
        self.__sections = sections

    @property
    def image_base(self) -> int:
        return self.__image_base

    @property
    def size_of_image(self) -> int:
        return self.__size_of_image

    def read_virtual_address(self, address: int, length: int) -> bytes:
        if type(address) is not int or type(length) is not int:
            raise LegacyInstallError("PE32 virtual read bounds must be integers")
        if length < 1:
            raise LegacyInstallError("PE32 virtual read length must be positive")
        rva = address - self.__image_base
        end = rva + length
        if rva < 0 or end <= rva or end > self.__size_of_image:
            raise LegacyInstallError("PE32 virtual read is outside the image")
        if rva < self.__size_of_headers:
            if end > self.__size_of_headers:
                raise LegacyInstallError("PE32 virtual read crosses the header boundary")
            return _sealed_read(self.__oracle, rva, length)
        section = next(
            (
                item
                for item in self.__sections
                if item.virtual_address <= rva and end <= item.virtual_end
            ),
            None,
        )
        if section is None:
            raise LegacyInstallError("PE32 virtual read is not contained by one mapped section")
        relative = rva - section.virtual_address
        if relative + length > section.raw_size:
            raise LegacyInstallError(
                f"PE32 virtual read enters the zero-fill tail of section {section.name!r}"
            )
        return _sealed_read(self.__oracle, section.raw_offset + relative, length)

    def __repr__(self) -> str:
        return (
            f"<{type(self).__name__} image_base=0x{self.__image_base:08x} "
            f"size={self.__size_of_image}>"
        )

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("a PE32 oracle capability cannot be serialized")


def _sealed_read(oracle: SealedFileOracle, offset: int, length: int) -> bytes:
    try:
        return oracle._read_exact_at(offset, length)
    except VerificationError as error:
        raise LegacyInstallError(f"cannot read sealed PE32 oracle: {error}") from error


def _u16(value: bytes, offset: int) -> int:
    return int.from_bytes(value[offset : offset + 2], "little")


def _u32(value: bytes, offset: int) -> int:
    return int.from_bytes(value[offset : offset + 4], "little")


def bind_pe32_oracle(oracle: SealedFileOracle) -> PE32VirtualAddressReader:
    """Validate a sealed PE32 image and return its VA-only read capability."""

    if not isinstance(oracle, SealedFileOracle):
        raise LegacyInstallError("PE32 oracle binding requires a sealed file capability")
    if oracle.size < 64:
        raise LegacyInstallError("PE32 oracle is shorter than its DOS header")
    dos = _sealed_read(oracle, 0, 64)
    if dos[:2] != b"MZ":
        raise LegacyInstallError("PE32 oracle lacks an MZ signature")
    nt_offset = _u32(dos, 0x3C)
    if nt_offset < 64 or nt_offset > oracle.size - 24:
        raise LegacyInstallError("PE32 NT header offset is outside the sealed file")
    nt = _sealed_read(oracle, nt_offset, 24)
    if nt[:4] != b"PE\0\0":
        raise LegacyInstallError("PE32 oracle lacks a PE signature")
    if _u16(nt, 4) != 0x014C:
        raise LegacyInstallError("legacy oracle must be an i386 PE32 image")
    section_count = _u16(nt, 6)
    optional_size = _u16(nt, 20)
    if not 1 <= section_count <= 96:
        raise LegacyInstallError("PE32 oracle section count is invalid")
    if not 96 <= optional_size <= 4096:
        raise LegacyInstallError("PE32 optional-header size is invalid")
    optional_offset = nt_offset + 24
    section_table_offset = optional_offset + optional_size
    section_table_size = section_count * 40
    if section_table_offset + section_table_size > oracle.size:
        raise LegacyInstallError("PE32 section table leaves the sealed file")
    optional = _sealed_read(oracle, optional_offset, optional_size)
    if _u16(optional, 0) != 0x010B:
        raise LegacyInstallError("legacy oracle must use a PE32 optional header")
    image_base = _u32(optional, 28)
    section_alignment = _u32(optional, 32)
    file_alignment = _u32(optional, 36)
    size_of_image = _u32(optional, 56)
    size_of_headers = _u32(optional, 60)
    if image_base == 0 or image_base + size_of_image > 0x1_0000_0000:
        raise LegacyInstallError("PE32 image extent is outside the 32-bit address space")
    if section_alignment == 0 or file_alignment == 0:
        raise LegacyInstallError("PE32 image alignment is invalid")
    if size_of_image == 0:
        raise LegacyInstallError("PE32 SizeOfImage must be positive")
    if not section_table_offset + section_table_size <= size_of_headers <= oracle.size:
        raise LegacyInstallError("PE32 SizeOfHeaders does not contain its header tables")

    table = _sealed_read(oracle, section_table_offset, section_table_size)
    sections: list[_PE32Section] = []
    for index in range(section_count):
        row = table[index * 40 : (index + 1) * 40]
        raw_name = row[:8].split(b"\0", 1)[0]
        name = raw_name.decode("ascii", errors="backslashreplace") or f"section-{index}"
        virtual_size = _u32(row, 8)
        virtual_address = _u32(row, 12)
        raw_size = _u32(row, 16)
        raw_offset = _u32(row, 20)
        mapped_size = max(virtual_size, raw_size)
        if mapped_size == 0:
            continue
        if virtual_address < size_of_headers or virtual_address + mapped_size > size_of_image:
            raise LegacyInstallError(f"PE32 section {name!r} has an invalid virtual extent")
        if raw_size and (raw_offset < size_of_headers or raw_offset + raw_size > oracle.size):
            raise LegacyInstallError(f"PE32 section {name!r} has an invalid raw extent")
        sections.append(
            _PE32Section(
                name=name,
                virtual_address=virtual_address,
                mapped_size=mapped_size,
                raw_offset=raw_offset,
                raw_size=raw_size,
            )
        )
    sections.sort(key=lambda item: item.virtual_address)
    for left, right in pairwise(sections):
        if left.virtual_end > right.virtual_address:
            raise LegacyInstallError(
                f"PE32 sections {left.name!r} and {right.name!r} overlap virtually"
            )
    return PE32VirtualAddressReader(
        oracle,
        image_base=image_base,
        size_of_headers=size_of_headers,
        size_of_image=size_of_image,
        sections=tuple(sections),
    )
