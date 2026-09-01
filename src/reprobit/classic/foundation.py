from __future__ import annotations

import json
import re
from typing import Any

import reprobit.binary as binary
from reprobit.model import Digest

"""Classic compiler algorithms: foundation."""
SHA256_RE = re.compile("^[0-9a-f]{64}$")
ADDRESS_RE = re.compile("^0x[0-9a-f]{6,8}$")
SOURCE_OVERLAY_TOKEN_RE = re.compile(
    "//[^\\n]*|/\\*.*?\\*/|\"(?:\\\\.|[^\"\\\\])*\"|\\'(?:\\\\.|[^\\'\\\\])*\\'|[A-Za-z_]\\w*|0[xX][0-9A-Fa-f]+|\\d+(?:\\.\\d*)?(?:[eE][+-]?\\d+)?[A-Za-z]*|::|->\\*|->|\\.\\*|<<=|>>=|==|!=|<=|>=|\\+\\+|--|&&|\\|\\||<<|>>|\\+=|-=|\\*=|/=|%=|&=|\\|=|\\^=|##|\\.\\.\\.|[^\\s]",
    re.S,
)
FORBIDDEN_CONVENIENCE_OPTIONS = {"/e", "-e", "/ep", "-ep", "/p", "-p"}
FORBIDDEN_DECLARATION_PAYLOAD_KEYS = frozenset(
    {
        "body",
        "bytes",
        "oracle_body",
        "oracle_bytes",
        "oracle_payload",
        "payload",
        "reference_body",
        "reference_bytes",
        "reference_payload",
        "retail_body",
        "retail_bytes",
        "retail_payload",
        "target_body",
        "target_bytes",
        "target_payload",
    }
)


def local_symbol_kind(name: str) -> str | None:
    """Classify compiler-local COFF symbols while ignoring their serial number."""

    if len(name) > 2 and name[0] == "$" and (name[1] in "LT") and name[2:].isdigit():
        return name[1]
    if name.startswith("$done$") and name[6:].isdigit():
        return "done"
    return None


def require_payload_free_declaration(value: object, context: str) -> None:
    """Refuse embedded byte payloads anywhere in clean recipe metadata.

    Compiler artifacts are explicit byte-valued function arguments.  Recipe
    declarations are JSON-like geometry and digest commitments only, so a
    caller cannot smuggle a reference body into a nested, otherwise ignored
    field and later mistake it for producer provenance.
    """
    pending = [(value, context)]
    seen: set[int] = set()
    while pending:
        current, path = pending.pop()
        if isinstance(current, (bytes, bytearray, memoryview)):
            raise binary.ByteIdentityError(f"{path} embeds a byte payload")
        if isinstance(current, dict):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            for key, item in current.items():
                binary.require(isinstance(key, str), f"{path} has a non-string key")
                forbidden = (
                    key in FORBIDDEN_DECLARATION_PAYLOAD_KEYS
                    or key.endswith("_bytes")
                    or key.endswith("_payload")
                    or key.endswith("_body")
                )
                binary.require(not forbidden, f"{path}.{key} is an embedded payload field")
                pending.append((item, f"{path}.{key}"))
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend((item, f"{path}[{index}]") for index, item in enumerate(current))


def sha256_bytes(data: bytes) -> str:
    return Digest.from_bytes(data).value


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def exact_keys(value: dict[str, Any], allowed: set[str], context: str) -> None:
    unknown = set(value) - allowed
    binary.require(not unknown, f"{context} has unknown keys: {sorted(unknown)}")


def exact_audit_keys(
    value: dict[str, Any], expected: set[str], context: str, optional: set[str] | None = None
) -> None:
    unknown = set(value) - expected
    missing = expected - set(value) - (optional or set())
    binary.require(
        not unknown and (not missing),
        f"{context} schema differs; unknown={sorted(unknown)} missing={sorted(missing)}",
    )


def exact_json_equal(left: object, right: object) -> bool:
    """JSON equality that never treats bool/int/float as interchangeable."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            exact_json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            (exact_json_equal(a, b) for a, b in zip(left, right))
        )
    return left == right


def require_sha(value: object, context: str) -> str:
    binary.require(
        isinstance(value, str) and SHA256_RE.fullmatch(value) is not None,
        f"{context} must be a lowercase SHA-256",
    )
    return value


def require_exact_int(
    value: object, context: str, *, minimum: int | None = None, maximum: int | None = None
) -> int:
    binary.require(type(value) is int, f"{context} must be an exact JSON integer")
    if minimum is not None:
        binary.require(value >= minimum, f"{context} is below its minimum")
    if maximum is not None:
        binary.require(value <= maximum, f"{context} exceeds its maximum")
    return value
