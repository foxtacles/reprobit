"""The debug representation delta deriver is the exact inverse of its validator."""

from __future__ import annotations

from reprobit.classic import debug as subject


def _record(record_type: int, payload: bytes) -> bytes:
    return (len(payload) + 2).to_bytes(2, "little") + record_type.to_bytes(2, "little") + payload


def _name(text: str) -> bytes:
    return bytes([len(text)]) + text.encode("latin1")


def _procedure(length: int, start: int, end: int) -> bytes:
    payload = (
        b"\0" * 12
        + length.to_bytes(4, "little")
        + start.to_bytes(4, "little")
        + end.to_bytes(4, "little")
        + b"\x11\x22\x33\x44\x55\x66"
        + b"\0\0"
        + b"\0"
        + _name("Serialize")
    )
    return _record(517, payload)


def _label(serial: int) -> bytes:
    return _record(521, b"\x01\x02\x03\x04\x05\x06\x07" + _name(f"$L{serial}"))


def _bprel(offset: int, type_index: int, name: str) -> bytes:
    return _record(
        512,
        offset.to_bytes(4, "little", signed=True) + type_index.to_bytes(2, "little") + _name(name),
    )


def _register(type_index: int, register: int, name: str) -> bytes:
    return _record(
        2, type_index.to_bytes(2, "little") + register.to_bytes(2, "little") + _name(name)
    )


END = _record(6, b"")


def test_deriver_classifies_every_closed_difference_and_round_trips() -> None:
    seed = (
        _procedure(223, 11, 214)
        + _label(80106)
        + _bprel(-8, 0x102B, "this")
        + _bprel(4, 0x157B, "p_storage")
        + _register(0x74, 24, "j")
        + END
    )
    donor = (
        _procedure(229, 15, 220)
        + _label(80109)
        + _register(0x1031, 24, "this")
        + _bprel(4, 0x1581, "p_storage")
        + _register(0x74, 23, "j")
        + END
    )

    derived = subject.derive_debug_representation_delta(seed, donor, "test")

    assert derived == [
        {"kind": "procedure_extent", "record_index": 0},
        {"kind": "compiler_label_number", "record_index": 1},
        {
            "kind": "local_location",
            "record_index": 2,
            "name": "this",
            "seed_type": 0x102B,
            "donor_type": 0x1031,
            "seed_location": {"bp_offset": -8},
            "donor_location": {"register": 24},
        },
        {
            "kind": "local_location",
            "record_index": 3,
            "name": "p_storage",
            "seed_type": 0x157B,
            "donor_type": 0x1581,
            "seed_location": {"bp_offset": 4},
            "donor_location": {"bp_offset": 4},
        },
        {
            "kind": "local_location",
            "record_index": 4,
            "name": "j",
            "seed_type": 0x74,
            "donor_type": 0x74,
            "seed_location": {"register": 24},
            "donor_location": {"register": 23},
        },
    ]
    normalized = subject.validate_debug_representation_delta(derived, "test")
    detail = subject.require_debug_symbol_representation_delta(
        seed, donor, normalized, 223, 229, "test"
    )
    assert [item["kind"] for item in detail] == [
        "procedure_extent",
        "compiler_label_number",
        "local_location",
        "local_location",
        "local_location",
    ]
    assert subject.derive_debug_representation_delta(seed, seed, "test") == []


def test_deriver_refuses_differences_outside_the_closed_kinds() -> None:
    seed = _procedure(10, 1, 9) + _bprel(-8, 1, "this") + END
    renamed = _procedure(10, 1, 9) + _bprel(-8, 1, "that") + END
    assert subject.derive_debug_representation_delta(seed, renamed, "test") is None
    extra = _procedure(10, 1, 9) + _bprel(-8, 1, "this") + _bprel(-4, 1, "more") + END
    assert subject.derive_debug_representation_delta(seed, extra, "test") is None
    moved_parent = (
        _record(
            517,
            b"\1" * 12
            + (10).to_bytes(4, "little")
            + (1).to_bytes(4, "little")
            + (9).to_bytes(4, "little")
            + b"\x11\x22\x33\x44\x55\x66"
            + b"\0\0"
            + b"\0"
            + _name("Serialize"),
        )
        + _bprel(-8, 1, "this")
        + END
    )
    assert subject.derive_debug_representation_delta(seed, moved_parent, "test") is None
    assert subject.derive_debug_representation_delta(seed, b"\x01\x00", "test") is None
