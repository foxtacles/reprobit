"""Isolated, opt-in quarantine for frozen oracle-byte installations.

Normal intervention and semantic modules do not import this module.  The API
exists only to carry a finite historical allowlist through migration while
making its ancestry and authenticity failure impossible to hide.
"""

from __future__ import annotations

import json
import os
import re
import stat
import threading
from dataclasses import dataclass
from hashlib import sha256
from itertools import pairwise
from pathlib import Path
from typing import Protocol

from reprobit.artifacts import digest_bytes
from reprobit.model import ByteRange, Quarantine
from reprobit.verify import SealedFileOracle, VerificationError


class LegacyInstallError(RuntimeError):
    """Raised when a quarantined installation is not exactly allowlisted."""


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class LegacyCopyRange:
    output_offset: int
    oracle_offset: int
    length: int
    preimage_digest: str
    oracle_digest: str

    def __post_init__(self) -> None:
        if self.output_offset < 0 or self.oracle_offset < 0:
            raise LegacyInstallError("legacy range offsets cannot be negative")
        if self.length < 1:
            raise LegacyInstallError("legacy range length must be positive")
        for label, value in (
            ("preimage digest", self.preimage_digest),
            ("oracle digest", self.oracle_digest),
        ):
            if not _SHA256.fullmatch(value):
                raise LegacyInstallError(f"{label} must be lowercase SHA-256")

    @property
    def output_end(self) -> int:
        return self.output_offset + self.length


@dataclass(frozen=True, slots=True)
class LegacyOracleInstall:
    id: str
    ranges: tuple[LegacyCopyRange, ...]

    def __post_init__(self) -> None:
        if not _IDENTIFIER.fullmatch(self.id):
            raise LegacyInstallError(f"invalid legacy action id: {self.id!r}")
        if not self.ranges:
            raise LegacyInstallError("legacy action must contain at least one range")
        ordered = sorted(self.ranges, key=lambda item: item.output_offset)
        if tuple(ordered) != self.ranges:
            raise LegacyInstallError("legacy ranges must be in canonical output order")
        for left, right in pairwise(ordered):
            if left.output_end > right.output_offset:
                raise LegacyInstallError(f"legacy action {self.id!r} has overlapping ranges")

    @property
    def byte_count(self) -> int:
        return sum(item.length for item in self.ranges)

    @property
    def fingerprint(self) -> str:
        value = {
            "id": self.id,
            "ranges": [
                {
                    "output_offset": item.output_offset,
                    "oracle_offset": item.oracle_offset,
                    "length": item.length,
                    "preimage_digest": item.preimage_digest,
                    "oracle_digest": item.oracle_digest,
                }
                for item in self.ranges
            ],
        }
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        return sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class LegacyPolicy:
    """A frozen action-shape allowlist and non-increasing global ceilings."""

    enabled: bool
    allowed_fingerprints: tuple[tuple[str, str], ...]
    maximum_actions: int
    maximum_ranges: int
    maximum_bytes: int

    def __post_init__(self) -> None:
        ids = [action_id for action_id, _ in self.allowed_fingerprints]
        if len(ids) != len(set(ids)):
            raise LegacyInstallError("legacy policy contains duplicate action ids")
        if ids != sorted(ids):
            raise LegacyInstallError("legacy policy allowlist must be in canonical id order")
        if any(not _IDENTIFIER.fullmatch(action_id) for action_id in ids):
            raise LegacyInstallError("legacy policy contains an invalid action id")
        if any(not _SHA256.fullmatch(value) for _, value in self.allowed_fingerprints):
            raise LegacyInstallError("legacy policy contains an invalid action fingerprint")
        if min(self.maximum_actions, self.maximum_ranges, self.maximum_bytes) < 0:
            raise LegacyInstallError("legacy policy ceilings cannot be negative")
        if len(ids) > self.maximum_actions:
            raise LegacyInstallError("legacy allowlist exceeds its action ceiling")
        if not self.enabled and (
            self.allowed_fingerprints
            or self.maximum_actions
            or self.maximum_ranges
            or self.maximum_bytes
        ):
            raise LegacyInstallError("a disabled legacy policy must be empty")

    @classmethod
    def freeze(cls, actions: tuple[LegacyOracleInstall, ...]) -> LegacyPolicy:
        if len({action.id for action in actions}) != len(actions):
            raise LegacyInstallError("cannot freeze duplicate legacy action ids")
        return cls(
            enabled=True,
            allowed_fingerprints=tuple(
                sorted((action.id, action.fingerprint) for action in actions)
            ),
            maximum_actions=len(actions),
            maximum_ranges=sum(len(action.ranges) for action in actions),
            maximum_bytes=sum(action.byte_count for action in actions),
        )

    def authorize(self, actions: tuple[LegacyOracleInstall, ...]) -> None:
        if actions and not self.enabled:
            raise LegacyInstallError("legacy oracle installation is disabled")
        if len({action.id for action in actions}) != len(actions):
            raise LegacyInstallError("legacy action ids must be unique")
        if len(actions) > self.maximum_actions:
            raise LegacyInstallError("legacy action count exceeds its frozen ceiling")
        range_count = sum(len(action.ranges) for action in actions)
        byte_count = sum(action.byte_count for action in actions)
        if range_count > self.maximum_ranges:
            raise LegacyInstallError("legacy range count exceeds its frozen ceiling")
        if byte_count > self.maximum_bytes:
            raise LegacyInstallError("legacy byte count exceeds its frozen ceiling")
        allowed = dict(self.allowed_fingerprints)
        for action in actions:
            if allowed.get(action.id) != action.fingerprint:
                raise LegacyInstallError(
                    f"legacy action {action.id!r} is new or differs from its frozen shape"
                )


class LegacyOracleSource(Protocol):
    """Byte-reading capability available only inside this quarantine module."""

    def read_range(self, offset: int, length: int) -> bytes: ...


class LegacyFileOracle:
    """An opened oracle descriptor used only by the quarantine worker."""

    __slots__ = ("__descriptor", "__lock", "__size")

    def __init__(self, descriptor: int, size: int) -> None:
        self.__descriptor = descriptor
        self.__size = size
        self.__lock = threading.Lock()

    @classmethod
    def open(cls, path: Path) -> LegacyFileOracle:
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise LegacyInstallError(f"cannot open legacy oracle: {error}") from error
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            os.close(descriptor)
            raise LegacyInstallError("legacy oracle must be a regular file")
        return cls(descriptor, info.st_size)

    def read_range(self, offset: int, length: int) -> bytes:
        if self.__descriptor < 0:
            raise LegacyInstallError("legacy oracle capability is closed")
        if offset < 0 or length < 0 or offset + length > self.__size:
            raise LegacyInstallError("legacy oracle read is outside the frozen file")
        try:
            if hasattr(os, "pread"):
                value = os.pread(self.__descriptor, length, offset)
            else:
                with self.__lock:
                    os.lseek(self.__descriptor, offset, os.SEEK_SET)
                    value = os.read(self.__descriptor, length)
        except OSError as error:
            raise LegacyInstallError(f"legacy oracle read failed: {error}") from error
        if len(value) != length:
            raise LegacyInstallError("legacy oracle produced a short read")
        return value

    def close(self) -> None:
        if self.__descriptor >= 0:
            os.close(self.__descriptor)
            self.__descriptor = -1

    def __enter__(self) -> LegacyFileOracle:
        if self.__descriptor < 0:
            raise LegacyInstallError("legacy oracle capability is closed")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.__descriptor < 0 else f"quarantined size={self.__size}"
        return f"<{type(self).__name__} {state}>"

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("a legacy oracle capability cannot be serialized")


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


@dataclass(frozen=True, slots=True)
class LegacyInstallReceipt:
    action_ids: tuple[str, ...]
    ranges: tuple[ByteRange, ...]
    byte_count: int
    input_digest: str
    output_digest: str

    @property
    def toolchain_origin(self) -> bool:
        return False

    @property
    def clean(self) -> bool:
        return False

    def quarantine(self, *, artifact_id: str) -> Quarantine:
        return Quarantine(
            id="legacy.oracle_install",
            kind="legacy.oracle_install",
            artifact_id=artifact_id,
            ranges=self.ranges,
            byte_count=self.byte_count,
            reason=(
                "output ranges were installed from a reference oracle by frozen legacy actions: "
                + ", ".join(self.action_ids)
            ),
        )


@dataclass(frozen=True, slots=True)
class LegacyOracleInstallGate:
    policy: LegacyPolicy

    def apply(
        self,
        candidate: bytes,
        oracle: LegacyOracleSource,
        actions: tuple[LegacyOracleInstall, ...],
    ) -> tuple[bytes, LegacyInstallReceipt]:
        """Apply only byte ranges matching the frozen allowlist and preimages."""

        if not actions:
            raise LegacyInstallError("legacy install gate requires at least one action")
        self.policy.authorize(actions)
        all_ranges = [
            (item.output_offset, item.output_end, action.id)
            for action in actions
            for item in action.ranges
        ]
        all_ranges.sort()
        for left, right in pairwise(all_ranges):
            if left[1] > right[0]:
                raise LegacyInstallError(f"legacy actions {left[2]!r} and {right[2]!r} overlap")

        output = bytearray(candidate)
        disclosed: list[ByteRange] = []
        for action in actions:
            for item in action.ranges:
                if item.output_end > len(output):
                    raise LegacyInstallError(
                        f"legacy action {action.id!r} extends beyond the candidate"
                    )
                preimage = bytes(output[item.output_offset : item.output_end])
                if digest_bytes(preimage) != item.preimage_digest:
                    raise LegacyInstallError(f"legacy action {action.id!r} preimage does not match")
                payload = oracle.read_range(item.oracle_offset, item.length)
                if digest_bytes(payload) != item.oracle_digest:
                    raise LegacyInstallError(
                        f"legacy action {action.id!r} oracle range does not match"
                    )
                output[item.output_offset : item.output_end] = payload
                disclosed.append(ByteRange(offset=item.output_offset, length=item.length))

        result = bytes(output)
        disclosed.sort(key=lambda item: item.offset)
        receipt = LegacyInstallReceipt(
            action_ids=tuple(action.id for action in actions),
            ranges=tuple(disclosed),
            byte_count=sum(item.length for item in disclosed),
            input_digest=digest_bytes(candidate),
            output_digest=digest_bytes(result),
        )
        return result, receipt
