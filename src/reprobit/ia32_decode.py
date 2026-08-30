"""Fail-closed IA-32 instruction-length decoding for compiler output analysis."""

from __future__ import annotations

from types import MappingProxyType

from reprobit.binary import ByteIdentityError, require

_PREFIXES = {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0xF0, 0xF2, 0xF3}


def _one_byte_table() -> dict[int, tuple[str, ...]]:
    table: dict[int, tuple[str, ...]] = {}
    for base in range(0, 64, 8):
        table[base] = ("M",)
        table[base + 1] = ("M",)
        table[base + 2] = ("M",)
        table[base + 3] = ("M",)
        table[base + 4] = ("Ib",)
        table[base + 5] = ("Iz",)
    for opcode in (6, 7, 14, 22, 23, 30, 31, 39, 47, 55, 63):
        table[opcode] = ()
    for opcode in range(64, 98):
        table[opcode] = ()
    table.update(
        {
            98: ("M",),
            99: ("M",),
            104: ("Iz",),
            105: ("M", "Iz"),
            106: ("Ib",),
            107: ("M", "Ib"),
        }
    )
    for opcode in range(108, 112):
        table[opcode] = ()
    for opcode in range(112, 128):
        table[opcode] = ("Jb",)
    table.update(
        {
            128: ("M", "Ib"),
            129: ("M", "Iz"),
            130: ("M", "Ib"),
            131: ("M", "Ib"),
        }
    )
    for opcode in range(132, 144):
        table[opcode] = ("M",)
    for opcode in range(144, 154):
        table[opcode] = ()
    table[154] = ("Ap",)
    for opcode in range(155, 160):
        table[opcode] = ()
    for opcode in range(160, 164):
        table[opcode] = ("Ov",)
    for opcode in range(164, 168):
        table[opcode] = ()
    table[168] = ("Ib",)
    table[169] = ("Iz",)
    for opcode in range(170, 176):
        table[opcode] = ()
    for opcode in range(176, 184):
        table[opcode] = ("Ib",)
    for opcode in range(184, 192):
        table[opcode] = ("Iz",)
    table.update(
        {
            192: ("M", "Ib"),
            193: ("M", "Ib"),
            194: ("Iw",),
            195: (),
            196: ("M",),
            197: ("M",),
            198: ("M", "Ib"),
            199: ("M", "Iz"),
            200: ("Iw", "Ib"),
            201: (),
            202: ("Iw",),
            203: (),
            204: (),
            205: ("Ib",),
            206: (),
            207: (),
        }
    )
    for opcode in range(208, 212):
        table[opcode] = ("M",)
    table[212] = ("Ib",)
    table[213] = ("Ib",)
    table[215] = ()
    for opcode in range(216, 224):
        table[opcode] = ("M",)
    for opcode in range(224, 228):
        table[opcode] = ("Jb",)
    for opcode in range(228, 232):
        table[opcode] = ("Ib",)
    table[232] = ("Jz",)
    table[233] = ("Jz",)
    table[234] = ("Ap",)
    table[235] = ("Jb",)
    for opcode in range(236, 240):
        table[opcode] = ()
    table[244] = ()
    table[245] = ()
    table[246] = ("M", "F6")
    table[247] = ("M", "F7")
    for opcode in range(248, 254):
        table[opcode] = ()
    table[254] = ("M",)
    table[255] = ("M",)
    return table


def _two_byte_table() -> dict[int, tuple[str, ...]]:
    table: dict[int, tuple[str, ...]] = {}
    for opcode in (0, 1, 2, 3, 13, 24, 31):
        table[opcode] = ("M",)
    for opcode in (6, 8, 9, 11, 48, 49, 50, 51, 119, 160, 161, 162, 168, 169, 170):
        table[opcode] = ()
    for opcode in range(16, 24):
        table[opcode] = ("M",)
    for opcode in range(32, 36):
        table[opcode] = ("M",)
    for opcode in range(40, 48):
        table[opcode] = ("M",)
    for opcode in range(64, 112):
        table[opcode] = ("M",)
    for opcode in range(112, 116):
        table[opcode] = ("M", "Ib")
    for opcode in range(116, 119):
        table[opcode] = ("M",)
    table[126] = ("M",)
    table[127] = ("M",)
    for opcode in range(128, 144):
        table[opcode] = ("Jz",)
    for opcode in range(144, 160):
        table[opcode] = ("M",)
    table.update(
        {
            163: ("M",),
            164: ("M", "Ib"),
            165: ("M",),
            171: ("M",),
            172: ("M", "Ib"),
            173: ("M",),
            174: ("M",),
            175: ("M",),
        }
    )
    for opcode in range(176, 184):
        table[opcode] = ("M",)
    table[185] = ("M",)
    table[186] = ("M", "Ib")
    for opcode in range(187, 194):
        table[opcode] = ("M",)
    table.update(
        {
            194: ("M", "Ib"),
            195: ("M",),
            196: ("M", "Ib"),
            197: ("M", "Ib"),
            198: ("M", "Ib"),
            199: ("M",),
        }
    )
    for opcode in range(200, 208):
        table[opcode] = ()
    for opcode in range(208, 256):
        table[opcode] = ("M",)
    return table


_ONE_BYTE = _one_byte_table()
_TWO_BYTE = _two_byte_table()
IA32_PREFIXES = frozenset(_PREFIXES)
IA32_ONE_BYTE_OPCODES = MappingProxyType(_ONE_BYTE)
IA32_TWO_BYTE_OPCODES = MappingProxyType(_TWO_BYTE)


def supported_ia32_instruction_length(encoded: bytes, context: str) -> int:
    """Decode one bounded flat 32-bit instruction, refusing unknown encodings."""

    require(bool(encoded), f"{context}: instruction encoding is missing")
    cursor = 0
    operand_size_16 = False
    seen_prefixes: set[int] = set()
    while cursor < len(encoded) and encoded[cursor] in _PREFIXES:
        prefix = encoded[cursor]
        require(
            prefix not in seen_prefixes,
            f"{context}: unsupported repeated instruction prefix",
        )
        seen_prefixes.add(prefix)
        if prefix == 0x66:
            operand_size_16 = True
        cursor += 1
    require(cursor < len(encoded), f"{context}: unsupported or truncated prefix")
    require(cursor <= 4, f"{context}: unsupported instruction prefix run")
    opcode = encoded[cursor]
    cursor += 1
    if opcode == 0x0F:
        require(cursor < len(encoded), f"{context}: truncated two-byte opcode")
        opcode = encoded[cursor]
        cursor += 1
        operands = _TWO_BYTE.get(opcode)
        require(operands is not None, f"{context}: unsupported two-byte opcode")
    else:
        operands = _ONE_BYTE.get(opcode)
        require(operands is not None, f"{context}: unsupported instruction opcode")
    assert operands is not None
    modrm = 0
    for token in operands:
        if token == "M":
            require(cursor < len(encoded), f"{context}: instruction lacks ModRM")
            modrm = encoded[cursor]
            cursor += 1
            mode = modrm >> 6
            rm = modrm & 7
            if mode != 3 and rm == 4:
                require(cursor < len(encoded), f"{context}: instruction lacks SIB")
                sib = encoded[cursor]
                cursor += 1
                if mode == 0 and sib & 7 == 5:
                    cursor += 4
            elif mode == 0 and rm == 5:
                cursor += 4
            if mode == 1:
                cursor += 1
            elif mode == 2:
                cursor += 4
        elif token in {"F6", "F7"}:
            if modrm >> 3 & 7 in {0, 1}:
                cursor += 1 if token == "F6" else 2 if operand_size_16 else 4
        elif token in {"Ib", "Jb"}:
            cursor += 1
        elif token == "Iw":
            cursor += 2
        elif token in {"Iz", "Jz"}:
            cursor += 2 if operand_size_16 else 4
        elif token == "Ov":
            cursor += 4
        elif token == "Ap":
            cursor += 6
        else:
            raise ByteIdentityError(f"{context}: decoder table error")
    require(cursor <= len(encoded), f"{context}: supported instruction is truncated")
    require(cursor <= 15, f"{context}: instruction exceeds 15 bytes")
    return cursor


__all__ = [
    "IA32_ONE_BYTE_OPCODES",
    "IA32_PREFIXES",
    "IA32_TWO_BYTE_OPCODES",
    "supported_ia32_instruction_length",
]
