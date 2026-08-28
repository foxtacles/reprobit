"""Literal byte verification through a sealed oracle capability."""

from __future__ import annotations

import os
import stat
import threading
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Protocol, runtime_checkable


class VerificationError(RuntimeError):
    """Raised when literal verification cannot produce a trustworthy receipt."""


@dataclass(frozen=True, slots=True)
class ComparisonReceipt:
    candidate_digest: str
    oracle_digest: str
    candidate_size: int
    oracle_size: int
    byte_exact: bool
    first_difference_offset: int | None
    candidate_device: int
    candidate_inode: int


@runtime_checkable
class OracleCapability(Protocol):
    """Narrow capability accepted by verifiers.

    It intentionally has no path or byte-reading method.  Concrete capabilities
    expose comparison only to verifier implementations through the private
    protocol method.
    """

    @property
    def size(self) -> int: ...

    def _compare_candidate(self, candidate: Path, *, chunk_size: int) -> ComparisonReceipt: ...


class SealedFileOracle:
    """An already-open reference file with no public payload accessor."""

    __slots__ = ("__descriptor", "__identity", "__lock", "__size")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del kwargs
        raise TypeError("sealed oracle capabilities cannot be subclassed")

    def __init__(
        self,
        descriptor: int,
        size: int,
        identity: tuple[int, int, int, int],
    ) -> None:
        self.__descriptor = descriptor
        self.__size = size
        self.__identity = identity
        self.__lock = threading.Lock()

    @classmethod
    def _open(cls, path: Path) -> SealedFileOracle:
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
            raise VerificationError(f"cannot seal oracle: {error}") from error
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise VerificationError("oracle must be a regular file")
            identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            return cls(descriptor, info.st_size, identity)
        except Exception:
            os.close(descriptor)
            raise

    @property
    def size(self) -> int:
        self._ensure_open()
        return self.__size

    @property
    def closed(self) -> bool:
        return self.__descriptor < 0

    def close(self) -> None:
        if self.__descriptor >= 0:
            os.close(self.__descriptor)
            self.__descriptor = -1

    def __enter__(self) -> SealedFileOracle:
        self._ensure_open()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self.closed else f"sealed size={self.__size}"
        return f"<{type(self).__name__} {state}>"

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("an oracle capability cannot be serialized")

    def _ensure_open(self) -> None:
        if self.__descriptor < 0:
            raise VerificationError("oracle capability is closed")

    def _read_at(self, offset: int, length: int) -> bytes:
        if hasattr(os, "pread"):
            return os.pread(self.__descriptor, length, offset)
        # Native Windows has no pread.  Serialize seek/read on the otherwise
        # sealed descriptor so concurrent verifications cannot move its cursor.
        with self.__lock:
            os.lseek(self.__descriptor, offset, os.SEEK_SET)
            return os.read(self.__descriptor, length)

    def _read_exact_at(self, offset: int, length: int) -> bytes:
        """Read one bounded slice for the isolated legacy-oracle bridge.

        This deliberately remains a private method.  Normal verifiers only
        compare candidates and never obtain reference bytes; the quarantine
        module is the sole caller that turns this sealed descriptor into a
        more narrowly scoped PE virtual-address capability.
        """

        self._ensure_open()
        if type(offset) is not int or type(length) is not int:
            raise VerificationError("sealed oracle read bounds must be integers")
        if offset < 0 or length < 0 or offset + length > self.__size:
            raise VerificationError("sealed oracle read is outside the frozen file")
        try:
            before = os.fstat(self.__descriptor)
            identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            if identity != self.__identity:
                raise VerificationError("sealed oracle changed before quarantined read")
            value = self._read_at(offset, length)
            after = os.fstat(self.__descriptor)
        except OSError as error:
            raise VerificationError(f"sealed oracle read failed: {error}") from error
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if after_identity != self.__identity:
            raise VerificationError("sealed oracle changed during quarantined read")
        if len(value) != length:
            raise VerificationError("sealed oracle produced a short read")
        return value

    def _digest_receipt(self, *, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
        """Hash the held descriptor without revealing its path or payload."""

        self._ensure_open()
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        digest = sha256()
        offset = 0
        try:
            before = os.fstat(self.__descriptor)
            identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            if identity != self.__identity:
                raise VerificationError("sealed oracle changed before digest receipt")
            while offset < self.__size:
                block = self._read_at(offset, min(chunk_size, self.__size - offset))
                if not block:
                    raise VerificationError("sealed oracle produced a short digest read")
                digest.update(block)
                offset += len(block)
            after = os.fstat(self.__descriptor)
        except OSError as error:
            raise VerificationError(f"sealed oracle digest failed: {error}") from error
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        if after_identity != self.__identity:
            raise VerificationError("sealed oracle changed during digest receipt")
        return digest.hexdigest(), self.__size

    def _compare_candidate(self, candidate: Path, *, chunk_size: int) -> ComparisonReceipt:
        self._ensure_open()
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        candidate_digest = sha256()
        oracle_digest = sha256()
        candidate_size = 0
        oracle_size = 0
        first_difference: int | None = None
        offset = 0
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(candidate, flags)
            with os.fdopen(descriptor, "rb") as candidate_stream:
                candidate_before = os.fstat(candidate_stream.fileno())
                if not stat.S_ISREG(candidate_before.st_mode):
                    raise VerificationError("candidate must be a regular file")
                oracle_before = os.fstat(self.__descriptor)
                oracle_identity = (
                    oracle_before.st_dev,
                    oracle_before.st_ino,
                    oracle_before.st_size,
                    oracle_before.st_mtime_ns,
                )
                if oracle_identity != self.__identity:
                    raise VerificationError("sealed oracle changed before verification")
                if (
                    candidate_before.st_dev,
                    candidate_before.st_ino,
                ) == (oracle_before.st_dev, oracle_before.st_ino):
                    raise VerificationError("candidate aliases the sealed oracle")
                while True:
                    candidate_chunk = candidate_stream.read(chunk_size)
                    oracle_chunk = self._read_at(offset, chunk_size)
                    if not candidate_chunk and not oracle_chunk:
                        break
                    candidate_digest.update(candidate_chunk)
                    oracle_digest.update(oracle_chunk)
                    candidate_size += len(candidate_chunk)
                    oracle_size += len(oracle_chunk)
                    if first_difference is None and candidate_chunk != oracle_chunk:
                        shared = min(len(candidate_chunk), len(oracle_chunk))
                        relative = next(
                            (
                                index
                                for index in range(shared)
                                if candidate_chunk[index] != oracle_chunk[index]
                            ),
                            shared,
                        )
                        first_difference = offset + relative
                    offset += max(len(candidate_chunk), len(oracle_chunk))
                candidate_after = os.fstat(candidate_stream.fileno())
                oracle_after = os.fstat(self.__descriptor)
        except OSError as error:
            raise VerificationError(f"literal verification failed: {error}") from error
        before_identity = (
            candidate_before.st_dev,
            candidate_before.st_ino,
            candidate_before.st_size,
            candidate_before.st_mtime_ns,
        )
        after_identity = (
            candidate_after.st_dev,
            candidate_after.st_ino,
            candidate_after.st_size,
            candidate_after.st_mtime_ns,
        )
        if before_identity != after_identity:
            raise VerificationError("candidate changed during literal verification")
        oracle_after_identity = (
            oracle_after.st_dev,
            oracle_after.st_ino,
            oracle_after.st_size,
            oracle_after.st_mtime_ns,
        )
        if oracle_after_identity != self.__identity:
            raise VerificationError("sealed oracle changed during verification")
        exact = first_difference is None and candidate_size == oracle_size
        return ComparisonReceipt(
            candidate_digest=candidate_digest.hexdigest(),
            oracle_digest=oracle_digest.hexdigest(),
            candidate_size=candidate_size,
            oracle_size=oracle_size,
            byte_exact=exact,
            first_difference_offset=first_difference,
            candidate_device=candidate_after.st_dev,
            candidate_inode=candidate_after.st_ino,
        )


def seal_file_oracle(path: Path) -> SealedFileOracle:
    """Open a reference file and return only a comparison capability."""

    return SealedFileOracle._open(path)


@dataclass(frozen=True, slots=True)
class LiteralVerifier:
    chunk_size: int = 1024 * 1024

    def __post_init__(self) -> None:
        if self.chunk_size <= 0:
            raise ValueError("chunk_size must be positive")

    def verify(self, candidate: Path, oracle: OracleCapability) -> ComparisonReceipt:
        """Compare a candidate without obtaining oracle bytes or its path."""

        return oracle._compare_candidate(candidate, chunk_size=self.chunk_size)
