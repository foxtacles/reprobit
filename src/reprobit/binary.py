"""Small fail-closed primitives shared by binary format readers."""

from __future__ import annotations


class ByteIdentityError(RuntimeError):
    """A binary structure or byte-identity proof is malformed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ByteIdentityError(message)


__all__ = ["ByteIdentityError", "require"]
