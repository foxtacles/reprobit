"""Closed IA-32 register semantics, decoding, and liveness analysis."""

from __future__ import annotations

from reprobit.binary import ByteIdentityError, require
from reprobit.ia32_decode import IA32_PREFIXES, supported_ia32_instruction_length

IA32_GENERAL_REGISTER_NAMES = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
_IA32_REGISTER_NUMBERS = {name: number for number, name in enumerate(IA32_GENERAL_REGISTER_NAMES)}
_IA32_STRUCTURAL_REGISTERS = frozenset({"esp", "ebp"})
_IA32_CALL_CLOBBERED = frozenset({"eax", "ecx", "edx"})
_IA32_RETURN_LIVE = frozenset({"eax", "ebx", "esi", "edi", "ebp", "esp"})


def _bijection_form(
    *,
    modrm: bool = False,
    reg: str | None = None,
    reg_read: bool = False,
    reg_write: bool = False,
    rm_read: bool = False,
    rm_write: bool = False,
    ext_no_write: frozenset = frozenset(),
    ext_write: frozenset = frozenset(),
    ext_allowed: frozenset | None = None,
    ext_implicit: dict | None = None,
    ext_flow: dict | None = None,
    implicit_frozen: frozenset = frozenset(),
    opreg: str | None = None,
    reads: frozenset = frozenset(),
    writes: frozenset = frozenset(),
    flow: str = "fall",
    displacement: int = 0,
    width: int = 32,
    rm_width: int | None = None,
    x87: bool = False,
    size16_ok: bool = False,
    size16_ext: frozenset | None = None,
    string_memory: dict | None = None,
) -> dict:
    return {
        "modrm": modrm,
        "reg": reg,
        "reg_read": reg_read,
        "reg_write": reg_write,
        "rm_read": rm_read,
        "rm_write": rm_write,
        "ext_no_write": ext_no_write,
        "ext_write": ext_write,
        "ext_allowed": ext_allowed,
        "ext_implicit": ext_implicit or {},
        "ext_flow": ext_flow or {},
        "implicit_frozen": implicit_frozen,
        "opreg": opreg,
        "reads": reads,
        "writes": writes,
        "flow": flow,
        "displacement": displacement,
        "width": width,
        "rm_width": rm_width,
        "x87": x87,
        "size16_ok": size16_ok,
        "size16_ext": size16_ext,
        "string_memory": string_memory,
    }


def _ia32_bijection_table() -> dict:
    """The closed semantic table this class will rewrite.

    An opcode is admitted only when its register fields and its *complete*
    implicit-operand set are known exactly.  Everything outside the table --
    including every form with an implicit general-register operand, every
    unadmitted prefix and every indirect *jump* -- is refused rather than
    guessed.
    """
    table = {}
    stack = frozenset({"esp"})
    table[49] = _bijection_form(
        modrm=True, reg="gpr", reg_read=True, rm_read=True, rm_write=True, size16_ok=True
    )
    table[51] = _bijection_form(
        modrm=True, reg="gpr", reg_read=True, reg_write=True, rm_read=True, size16_ok=True
    )
    table[57] = _bijection_form(modrm=True, reg="gpr", reg_read=True, rm_read=True, size16_ok=True)
    table[59] = _bijection_form(modrm=True, reg="gpr", reg_read=True, rm_read=True, size16_ok=True)
    table[133] = _bijection_form(modrm=True, reg="gpr", reg_read=True, rm_read=True, size16_ok=True)
    for opcode in (3, 11, 27, 35, 43):
        table[opcode] = _bijection_form(
            modrm=True, reg="gpr", reg_read=True, reg_write=True, rm_read=True, size16_ok=True
        )
    table[137] = _bijection_form(
        modrm=True, reg="gpr", reg_read=True, rm_write=True, size16_ok=True
    )
    table[139] = _bijection_form(
        modrm=True, reg="gpr", reg_write=True, rm_read=True, size16_ok=True
    )
    table[141] = _bijection_form(modrm=True, reg="gpr", reg_write=True)
    table[131] = _bijection_form(
        modrm=True,
        reg="ext",
        rm_read=True,
        rm_write=True,
        ext_no_write=frozenset({7}),
        size16_ok=True,
    )
    table[129] = _bijection_form(
        modrm=True,
        reg="ext",
        rm_read=True,
        rm_write=True,
        ext_no_write=frozenset({7}),
        size16_ok=True,
    )
    table[199] = _bijection_form(
        modrm=True, reg="ext", ext_allowed=frozenset({0}), rm_write=True, size16_ok=True
    )
    table[56] = _bijection_form(modrm=True, reg="gpr", reg_read=True, rm_read=True, width=8)
    table[58] = _bijection_form(modrm=True, reg="gpr", reg_read=True, rm_read=True, width=8)
    table[132] = _bijection_form(modrm=True, reg="gpr", reg_read=True, rm_read=True, width=8)
    table[136] = _bijection_form(modrm=True, reg="gpr", reg_read=True, rm_write=True, width=8)
    table[138] = _bijection_form(modrm=True, reg="gpr", reg_write=True, rm_read=True, width=8)
    table[26] = _bijection_form(
        modrm=True, reg="gpr", reg_read=True, reg_write=True, rm_read=True, width=8
    )
    table[128] = _bijection_form(
        modrm=True, reg="ext", rm_read=True, rm_write=True, ext_no_write=frozenset({7}), width=8
    )
    table[198] = _bijection_form(
        modrm=True, reg="ext", ext_allowed=frozenset({0}), rm_write=True, width=8
    )
    table[246] = _bijection_form(
        modrm=True,
        reg="ext",
        rm_read=True,
        rm_write=True,
        ext_no_write=frozenset({0}),
        ext_allowed=frozenset({0, 2, 3}),
        width=8,
    )
    table[254] = _bijection_form(
        modrm=True, reg="ext", rm_read=True, rm_write=True, ext_allowed=frozenset({0, 1}), width=8
    )
    table[60] = _bijection_form(reads=frozenset({"eax"}), implicit_frozen=frozenset({"eax"}))
    table[153] = _bijection_form(
        reads=frozenset({"eax"}),
        writes=frozenset({"edx"}),
        implicit_frozen=frozenset({"eax", "edx"}),
    )
    _muldiv = (frozenset({"eax", "edx"}), frozenset({"eax", "edx"}), frozenset({"eax", "edx"}))
    table[247] = _bijection_form(
        modrm=True,
        reg="ext",
        rm_read=True,
        rm_write=True,
        ext_no_write=frozenset({0, 4, 5, 6, 7}),
        ext_allowed=frozenset({0, 2, 3, 4, 5, 6, 7}),
        ext_implicit={4: _muldiv, 5: _muldiv, 6: _muldiv, 7: _muldiv},
    )
    for index in range(8):
        table[64 + index] = _bijection_form(opreg="readwrite", size16_ok=True)
        table[72 + index] = _bijection_form(opreg="readwrite", size16_ok=True)
        table[80 + index] = _bijection_form(opreg="read", reads=stack, writes=stack)
        table[88 + index] = _bijection_form(opreg="write", reads=stack, writes=stack)
        table[184 + index] = _bijection_form(opreg="write", size16_ok=True)
    table[5] = _bijection_form(
        reads=frozenset({"eax"}), writes=frozenset({"eax"}), implicit_frozen=frozenset({"eax"})
    )
    table[161] = _bijection_form(writes=frozenset({"eax"}), implicit_frozen=frozenset({"eax"}))
    table[163] = _bijection_form(reads=frozenset({"eax"}), implicit_frozen=frozenset({"eax"}))
    table[104] = _bijection_form(reads=stack, writes=stack)
    table[106] = _bijection_form(reads=stack, writes=stack)
    for opcode in range(112, 128):
        table[opcode] = _bijection_form(flow="jcc", displacement=1)
    table[235] = _bijection_form(flow="jmp", displacement=1)
    table[233] = _bijection_form(flow="jmp", displacement=4)
    table[232] = _bijection_form(
        flow="call", displacement=4, reads=stack, writes=_IA32_CALL_CLOBBERED
    )
    table[255] = _bijection_form(
        modrm=True,
        reg="ext",
        ext_allowed=frozenset({0, 1, 2, 4}),
        rm_read=True,
        ext_write=frozenset({0, 1}),
        size16_ok=True,
        size16_ext=frozenset({0, 1}),
        flow="call",
        ext_flow={0: "fall", 1: "fall", 2: "call", 4: "exit"},
        ext_implicit={
            2: (stack, _IA32_CALL_CLOBBERED, frozenset()),
            4: (frozenset(IA32_GENERAL_REGISTER_NAMES), frozenset(), frozenset()),
        },
    )
    table[194] = _bijection_form(flow="ret", reads=_IA32_RETURN_LIVE)
    table[195] = _bijection_form(flow="ret", reads=_IA32_RETURN_LIVE)
    for opcode in range(216, 224):
        table[opcode] = _bijection_form(modrm=True, reg="ext", x87=True)
    return _ia32_bijection_table_widening(table)


_IA32_SHIFT_DIGITS = frozenset({0, 1, 4, 5, 7})


def _ia32_bijection_table_widening(table: dict) -> dict:
    """The forms this compiler emits that the first hundred did not name.

    Every entry here was measured before it was written: `$W/BF-probe`
    compiles each encoding with this project's own MSVC 4.2, runs it under
    Wine over a register file of distinct arena pointers, perturbs one
    liveness ATOM at a time, and refuses the entry unless

      * every atom the entry does not declare READ leaves the whole final
        state -- registers, flags and memory -- unchanged except for its own
        preserved copy, and
      * every atom the entry declares written and not read comes out
        independent of its input, and
      * every register the instruction is observed to touch is either named
        by a rewritable field of the encoding or declared FROZEN.

    The same three checks are re-run over the pre-existing entries as a
    control.  A form whose complete effect could not be stated is left out
    and named in the refusal tests instead.
    """
    table[144] = _bijection_form()
    for opcode in (8, 16, 24, 32, 40, 48):
        table[opcode] = _bijection_form(
            modrm=True, reg="gpr", reg_read=True, rm_read=True, rm_write=True, width=8
        )
    for opcode in (2, 10, 18, 34, 42, 50):
        table[opcode] = _bijection_form(
            modrm=True, reg="gpr", reg_read=True, reg_write=True, rm_read=True, width=8
        )
    for opcode in (1, 9, 17, 25, 33, 41):
        table[opcode] = _bijection_form(
            modrm=True, reg="gpr", reg_read=True, rm_read=True, rm_write=True, size16_ok=True
        )
    table[19] = _bijection_form(
        modrm=True, reg="gpr", reg_read=True, reg_write=True, rm_read=True, size16_ok=True
    )
    for opcode in (4, 12, 20, 28, 36, 44, 52, 168):
        table[opcode] = _bijection_form(
            reads=frozenset({"eax"}), implicit_frozen=frozenset({"eax"}), width=8
        )
    for opcode in (13, 21, 29, 37, 45, 53):
        table[opcode] = _bijection_form(
            reads=frozenset({"eax"}), writes=frozenset({"eax"}), implicit_frozen=frozenset({"eax"})
        )
    for opcode in (61, 169):
        table[opcode] = _bijection_form(
            reads=frozenset({"eax"}), implicit_frozen=frozenset({"eax"}), size16_ok=True
        )
    for index in range(8):
        table[176 + index] = _bijection_form(opreg="write", width=8)
    for opcode in (192, 208):
        table[opcode] = _bijection_form(
            modrm=True,
            reg="ext",
            rm_read=True,
            rm_write=True,
            width=8,
            ext_allowed=_IA32_SHIFT_DIGITS,
        )
    for opcode in (193, 209):
        table[opcode] = _bijection_form(
            modrm=True,
            reg="ext",
            rm_read=True,
            rm_write=True,
            size16_ok=True,
            ext_allowed=_IA32_SHIFT_DIGITS,
        )
    table[210] = _bijection_form(
        modrm=True,
        reg="ext",
        rm_read=True,
        rm_write=True,
        width=8,
        ext_allowed=_IA32_SHIFT_DIGITS,
        reads=frozenset({"ecx"}),
        implicit_frozen=frozenset({"ecx"}),
    )
    table[211] = _bijection_form(
        modrm=True,
        reg="ext",
        rm_read=True,
        rm_write=True,
        size16_ok=True,
        ext_allowed=_IA32_SHIFT_DIGITS,
        reads=frozenset({"ecx"}),
        implicit_frozen=frozenset({"ecx"}),
    )
    return table


def _ia32_bijection_two_byte_table() -> dict:
    """The admitted 0F forms: near Jcc, SETcc, MOVZX/MOVSX, and DWORD IMUL.

    `0F B7`/`0F BF` widen a 16-bit source into a 32-bit destination.  Both
    fields number the SAME eight registers (a mod == 3 r/m16 is AX..DI, not
    AL..BH), so sigma's permutation is the right rewriting for both, and the
    destination write is a full 32-bit definition that legitimately kills.
    The byte-source siblings `0F B6`/`0F BE` carry an ASYMMETRIC pair of
    fields: the destination is a full 32-bit register field sigma rewrites
    and legitimately kills, while the r/m8 source names AL..BH and is frozen
    exactly as every other width-8 field is -- `rm_width` records that
    split.  A memory-source encoding freezes nothing: its base and index
    are ordinary 32-bit address registers.  (Tickle's mirror region is the
    row that needs them.)  `0F AF /r` is admitted only at the native DWORD
    width: its destination is both read and written and its r/m source is
    read.  The 66-prefixed and immediate 69/6B siblings remain closed.
    """
    table = {}
    for opcode in range(128, 144):
        table[opcode] = _bijection_form(flow="jcc", displacement=4)
    for opcode in (183, 191):
        table[opcode] = _bijection_form(modrm=True, reg="gpr", reg_write=True, rm_read=True)
    for opcode in (182, 190):
        table[opcode] = _bijection_form(
            modrm=True, reg="gpr", reg_write=True, rm_read=True, rm_width=8
        )
    # IMUL r32,r/m32 reads and rewrites its explicit destination and reads its
    # explicit source.  The 16-bit prefix remains outside this exact row.
    table[175] = _bijection_form(modrm=True, reg="gpr", reg_read=True, reg_write=True, rm_read=True)
    for opcode in range(144, 160):
        table[opcode] = _bijection_form(
            modrm=True, reg="ext", ext_allowed=frozenset({0}), rm_write=True, width=8
        )
    return table


IA32_BIJECTION_FORMS = _ia32_bijection_table()
IA32_BIJECTION_TWO_BYTE_FORMS = _ia32_bijection_two_byte_table()
_IA32_INERT_SEGMENT_PREFIXES = frozenset({38, 46, 54, 62, 100, 101})
_IA32_OPERAND_SIZE_PREFIX = 102
_IA32_REPEAT_PREFIXES = frozenset({242, 243})


def _ia32_string_form(reads, writes, *, memory_read, memory_write) -> dict:
    """One repeated string operation, with its COMPLETE implicit operand set.

    Every general register such a form touches -- the count in ECX, the
    source pointer in ESI, the destination pointer in EDI, the value or
    comparand in EAX -- is named by NO field of the encoding, so all of them
    are FROZEN and a sigma whose support meets one is refused inside the
    region.  A register the form defines is also a register it reads (the
    pointers advance from their own value, and the count is read before it is
    zeroed), so the declared write can never under-approximate liveness: the
    read re-adds every atom the write would kill.

    The MEMORY it touches is a span whose extent is the runtime value of ECX.
    That extent is not a descriptor any disambiguation rule can compare, so
    the form declares its memory UNKNOWN and every consumer that reasons
    about memory refuses it outright rather than reading an address that was
    never derived.
    """
    return _bijection_form(
        reads=frozenset(reads),
        writes=frozenset(writes),
        implicit_frozen=frozenset(set(reads) | set(writes)),
        string_memory={"read": memory_read, "write": memory_write},
    )


IA32_BIJECTION_REPEATED_STRING_FORMS = {
    (prefix, opcode): _ia32_string_form(
        ("ecx", "esi", "edi"), ("ecx", "esi", "edi"), memory_read=True, memory_write=True
    )
    for prefix in (243,)
    for opcode in (164, 165)
}
IA32_BIJECTION_REPEATED_STRING_FORMS.update(
    {
        (243, opcode): _ia32_string_form(
            ("eax", "ecx", "edi"), ("ecx", "edi"), memory_read=False, memory_write=True
        )
        for opcode in (170, 171)
    }
)
IA32_BIJECTION_REPEATED_STRING_FORMS.update(
    {
        (prefix, opcode): _ia32_string_form(
            ("eax", "ecx", "edi"), ("ecx", "edi"), memory_read=True, memory_write=False
        )
        for prefix in (242, 243)
        for opcode in (174, 175)
    }
)
IA32_BIJECTION_REPEATED_STRING_FORMS.update(
    {
        (prefix, opcode): _ia32_string_form(
            ("ecx", "esi", "edi"), ("ecx", "esi", "edi"), memory_read=True, memory_write=False
        )
        for prefix in (242, 243)
        for opcode in (166, 167)
    }
)
_IA32_EXTERNAL_TRANSFER_LIVE = frozenset(IA32_GENERAL_REGISTER_NAMES)
_IA32_BYTE_ADDRESSABLE = ("eax", "ecx", "edx", "ebx")


def _ia32_register_atoms(name: str) -> tuple:
    """Every liveness atom of one general register."""
    if name in _IA32_BYTE_ADDRESSABLE:
        return (name + ".l", name + ".h", name + ".u")
    return (name + ".w",)


_IA32_ATOMS_OF = {
    name: frozenset(_ia32_register_atoms(name)) for name in IA32_GENERAL_REGISTER_NAMES
}


def ia32_register_atoms(names) -> frozenset:
    """The atom set of a collection of whole general registers."""
    return frozenset().union(*[_IA32_ATOMS_OF[name] for name in names]) if names else frozenset()


def _ia32_atom_registers(atoms) -> list:
    """The register names an atom set touches, for a refusal message."""
    return sorted({atom.split(".")[0] for atom in atoms})


def _bijection_form_for(opcode: int) -> dict | None:
    """Look one decoded opcode key up in the closed table."""
    if opcode & 65280 == 3840:
        return IA32_BIJECTION_TWO_BYTE_FORMS.get(opcode & 255)
    return IA32_BIJECTION_FORMS.get(opcode)


_MSVC_MEMBER_FUNCTION_CLASSES = frozenset("ABEFIJMNQRUV")
_MSVC_STATIC_FUNCTION_CLASSES = frozenset("CDKLST")
_MSVC_GLOBAL_FUNCTION_CLASSES = frozenset("YZ")
_MSVC_THUNK_FUNCTION_CLASSES = frozenset("GHOPWX")
_MSVC_CV_LETTERS = frozenset("ABCD")
_MSVC_CALL_ARGUMENT_REGISTERS = {
    "A": frozenset(),
    "B": frozenset(),
    "C": frozenset(),
    "D": frozenset(),
    "E": frozenset({"ecx"}),
    "F": frozenset({"ecx"}),
    "G": frozenset(),
    "H": frozenset(),
    "I": frozenset({"ecx", "edx"}),
    "J": frozenset({"ecx", "edx"}),
}


def msvc_call_argument_registers(symbol: object) -> frozenset | None:
    """Which general registers a callee reads as arguments, or None.

    Closed decode of an MSVC 4.2 decorated name.  Every `@@` in the name is
    tried as the scope terminator; a position is a *reading* only if the
    letters after it form a complete (function class, [CV], calling
    convention) triple.  The true scope terminator is always one such
    position, so requiring **exactly one distinct reading** means the answer
    agrees with the truth or is refused.  Adjustor thunks, undecorated names
    and anything else return None, which the caller must treat as "read the
    whole caller-saved set".
    """
    if not isinstance(symbol, str) or not symbol.startswith("?"):
        return None
    if not symbol.endswith("Z"):
        return None
    readings = set()
    for index in range(len(symbol) - 1):
        if symbol[index : index + 2] == "@@":
            cursor = index + 2
        elif symbol[index] == "@" and symbol[index + 1] in _MSVC_GLOBAL_FUNCTION_CLASSES:
            cursor = index + 1
        else:
            continue
        if cursor >= len(symbol):
            continue
        letter = symbol[cursor]
        cursor += 1
        if letter in _MSVC_THUNK_FUNCTION_CLASSES:
            if (
                cursor + 2 < len(symbol)
                and symbol[cursor].isdigit()
                and (symbol[cursor + 1] in _MSVC_CV_LETTERS)
                and (symbol[cursor + 2] in _MSVC_CALL_ARGUMENT_REGISTERS)
            ):
                return None
            continue
        if letter in _MSVC_MEMBER_FUNCTION_CLASSES:
            if cursor >= len(symbol) or symbol[cursor] not in _MSVC_CV_LETTERS:
                continue
            cursor += 1
        elif letter not in _MSVC_STATIC_FUNCTION_CLASSES | _MSVC_GLOBAL_FUNCTION_CLASSES:
            continue
        if cursor >= len(symbol):
            continue
        registers = _MSVC_CALL_ARGUMENT_REGISTERS.get(symbol[cursor])
        if registers is None:
            continue
        readings.add(registers)
    if len(readings) != 1:
        return None
    return next(iter(readings))


def decode_ia32_bijection_instruction(
    body: bytes, offset: int, context: str, relocations: dict | None = None
) -> dict:
    """Decode one instruction into register fields, operands and control flow.

    Returns the encoding's general-register fields as `(byte, shift)` pairs so
    a bijection can rewrite them in place, together with the exact set of
    general registers the instruction reads and writes -- explicit operands
    and the table's implicit ones alike.  `frozen` names the general registers
    an instruction touches through a field that cannot be rewritten (a
    sub-register encoding); `relocations`, when given, maps a relocation's
    offset to `{"width": int, "target": str}` and is what lets a direct call's
    callee be named.
    """
    require(0 <= offset < len(body), f"{context}: instruction offset is out of range")
    window = body[offset:]
    length = supported_ia32_instruction_length(window, context)
    encoded = body[offset : offset + length]
    require(len(encoded) == length, f"{context}: instruction is truncated")
    cursor = 0
    segment_prefix = False
    operand_size_16 = False
    repeat_prefix = None
    while encoded[cursor] in IA32_PREFIXES:
        prefix = encoded[cursor]
        if prefix in _IA32_INERT_SEGMENT_PREFIXES:
            require(not segment_prefix, f"{context}: repeated segment prefix")
            segment_prefix = True
        elif prefix == _IA32_OPERAND_SIZE_PREFIX:
            require(not operand_size_16, f"{context}: repeated operand-size prefix")
            operand_size_16 = True
        elif prefix in _IA32_REPEAT_PREFIXES:
            require(repeat_prefix is None, f"{context}: repeated repeat prefix")
            repeat_prefix = prefix
        else:
            raise ByteIdentityError(
                f"{context}: prefixed instructions are outside the register-bijection table"
            )
        cursor += 1
        require(cursor < length, f"{context}: instruction is only prefixes")
    opcode_at = offset + cursor
    opcode = encoded[cursor]
    cursor += 1
    if opcode == 15:
        require(cursor < length, f"{context}: truncated two-byte opcode")
        opcode = 3840 | encoded[cursor]
        cursor += 1
    if repeat_prefix is not None:
        form = IA32_BIJECTION_REPEATED_STRING_FORMS.get((repeat_prefix, opcode))
        require(
            form is not None,
            f"{context}: the repeat prefix 0x{repeat_prefix:02x} on opcode 0x{opcode:02x} is outside the register-bijection table",
        )
        require(
            not operand_size_16,
            f"{context}: an operand-size prefix on a repeated string operation is outside the register-bijection table",
        )
    else:
        form = _bijection_form_for(opcode)
    require(
        form is not None,
        f"{context}: opcode 0x{opcode:02x} is outside the register-bijection table",
    )
    width = form["width"]
    if operand_size_16:
        require(
            form["size16_ok"] and width == 32,
            f"{context}: the operand-size prefix is outside the register-bijection table for this opcode",
        )
        width = 16
    effective_width = width
    fields = []
    encoding = None
    flow_override = None
    frozen = set(form["implicit_frozen"])
    memory = None
    reads = set(form["reads"])
    writes = set(form["writes"])
    read_atoms = set(ia32_register_atoms(form["reads"]))
    write_atoms = set(ia32_register_atoms(form["writes"]))
    read_atoms |= ia32_register_atoms(form["implicit_frozen"])
    indirect = False
    names = IA32_GENERAL_REGISTER_NAMES

    def _touch(value: int, is_read: bool, is_write: bool, field_width: int | None = None) -> None:
        """Account for one register-operand field of the form's own width.

        32- and 16-bit fields number the same eight registers, so they are
        rewritable; an 8-bit field numbers AL..BH, whose 4..7 are the HIGH
        bytes of EAX..EBX, so it is frozen.  At REGISTER granularity a write
        narrower than 32 bits is reported as a read and never as a kill; at
        ATOM granularity it reads and kills exactly the atoms it touches.
        A form with an `rm_width` narrower than its register field passes
        that width here explicitly; every symmetric form passes None.
        """
        width = effective_width if field_width is None else field_width
        if width == 8:
            name = names[value & 3]
            frozen.add(name)
            atoms = frozenset({name + (".l" if value < 4 else ".h")})
        else:
            name = names[value]
            if width == 16 and name in _IA32_BYTE_ADDRESSABLE:
                atoms = frozenset({name + ".l", name + ".h"})
            elif width == 16:
                atoms = _IA32_ATOMS_OF[name]
            else:
                atoms = _IA32_ATOMS_OF[name]
        if is_read or (is_write and width != 32):
            reads.add(name)
        if is_write and width == 32:
            writes.add(name)
        if is_read:
            read_atoms.update(atoms)
        if is_write:
            if width == 32 or name in _IA32_BYTE_ADDRESSABLE:
                write_atoms.update(atoms)
            else:
                read_atoms.update(atoms)

    if form["opreg"] is not None:
        if width != 8:
            fields.append((opcode_at, 0))
        _touch(
            opcode & 7,
            form["opreg"] in ("read", "readwrite"),
            form["opreg"] in ("write", "readwrite"),
        )
    if form["modrm"]:
        require(cursor < length, f"{context}: instruction lacks ModRM")
        modrm_at = offset + cursor
        modrm = encoded[cursor]
        cursor += 1
        modrm_byte = modrm
        mode = modrm >> 6
        rm = modrm & 7
        register_field = modrm >> 3 & 7
        rm_write = form["rm_write"]
        sib_at = None
        displacement_at = None
        displacement_size = 0
        absolute_operand = False
        if form["reg"] == "gpr":
            if width != 8:
                fields.append((modrm_at, 3))
            _touch(register_field, form["reg_read"], form["reg_write"])
        else:
            require(form["reg"] == "ext", f"{context}: ModRM register field role is undeclared")
            allowed = form["ext_allowed"]
            require(
                allowed is None or register_field in allowed,
                f"{context}: ModRM extension /{register_field} of opcode 0x{opcode:02x} is outside the register-bijection table",
            )
            require(
                width != 16 or form["size16_ext"] is None or register_field in form["size16_ext"],
                f"{context}: the operand-size prefix on extension /{register_field} of opcode 0x{opcode:02x} is outside the register-bijection table",
            )
            if register_field in form["ext_no_write"]:
                rm_write = False
            if register_field in form["ext_write"]:
                rm_write = True
            implicit = form["ext_implicit"].get(register_field)
            if implicit is not None:
                extra_reads, extra_writes, extra_frozen = implicit
                reads |= extra_reads
                writes |= extra_writes
                frozen |= extra_frozen
                read_atoms |= ia32_register_atoms(extra_reads | extra_frozen)
                write_atoms |= ia32_register_atoms(extra_writes)
            member_flow = form["ext_flow"].get(register_field)
            if member_flow is not None:
                flow_override = member_flow
        if mode == 3:
            if form["x87"]:
                if opcode == 223 and modrm == 224:
                    write_atoms |= {"eax.l", "eax.h"}
                    frozen.add("eax")
            else:
                rm_field_width = form["rm_width"] or width
                if rm_field_width != 8:
                    fields.append((modrm_at, 0))
                _touch(rm, form["rm_read"], rm_write, rm_field_width)
        else:
            base_name = None
            index_name = None
            scale = 1
            absolute = False
            if rm == 4:
                require(cursor < length, f"{context}: instruction lacks SIB")
                sib_at = offset + cursor
                sib = encoded[cursor]
                cursor += 1
                base = sib & 7
                index = sib >> 3 & 7
                scale = 1 << (sib >> 6)
                if not (mode == 0 and base == 5):
                    fields.append((sib_at, 0))
                    reads.add(names[base])
                    read_atoms |= _IA32_ATOMS_OF[names[base]]
                    base_name = names[base]
                else:
                    absolute = True
                if index != 4:
                    fields.append((sib_at, 3))
                    reads.add(names[index])
                    read_atoms |= _IA32_ATOMS_OF[names[index]]
                    index_name = names[index]
            elif not (mode == 0 and rm == 5):
                fields.append((modrm_at, 0))
                reads.add(names[rm])
                read_atoms |= _IA32_ATOMS_OF[names[rm]]
                base_name = names[rm]
            else:
                absolute = True
            displacement = 0
            absolute_operand = absolute
            if mode == 1:
                require(cursor < length, f"{context}: instruction lacks its disp8")
                displacement_at = offset + cursor
                displacement_size = 1
                displacement = int.from_bytes(encoded[cursor : cursor + 1], "little", signed=True)
            elif mode == 2 or absolute:
                require(cursor + 4 <= length, f"{context}: instruction lacks its disp32")
                displacement_at = offset + cursor
                displacement_size = 4
                displacement = int.from_bytes(encoded[cursor : cursor + 4], "little", signed=True)
            if form["rm_read"] or rm_write or form["x87"]:
                memory = {
                    "base": base_name,
                    "index": index_name,
                    "scale": scale,
                    "displacement": displacement,
                    "absolute": absolute,
                    "width": max(width // 8, 1),
                    "read": bool(form["rm_read"]) or bool(form["x87"]),
                    "write": bool(rm_write),
                    "unknown": False,
                }
        require(
            form["reg"] != "gpr" or not (form["reg_write"] and form["rm_write"]),
            f"{context}: instruction form writes two operands",
        )
        encoding = {
            "modrm_at": modrm_at,
            "mode": mode,
            "rm": rm,
            "reg": register_field,
            "sib_at": sib_at,
            "displacement_at": displacement_at,
            "displacement_size": displacement_size,
            "absolute": absolute_operand,
        }
    target = None
    flow = form["flow"] if flow_override is None else flow_override
    if flow == "exit" and form["modrm"]:
        indirect = True
    if flow in ("jcc", "jmp", "call") and form["displacement"]:
        width_bytes = form["displacement"]
        displacement_at = offset + length - width_bytes
        row = (relocations or {}).get(displacement_at)
        external = row is not None and row.get("width") == width_bytes
        if external and flow == "jmp":
            flow = "exit"
            reads = set(_IA32_EXTERNAL_TRANSFER_LIVE)
            writes = set()
            read_atoms = set(ia32_register_atoms(_IA32_EXTERNAL_TRANSFER_LIVE))
            write_atoms = set()
        elif external and flow == "jcc":
            raise ByteIdentityError(
                f"{context}: a relocated conditional branch is outside the register-bijection table"
            )
        elif not external:
            relative = int.from_bytes(encoded[length - width_bytes :], "little", signed=True)
            target = offset + length + relative
        if flow == "call":
            symbol = row.get("target") if row is not None else None
            argument = msvc_call_argument_registers(symbol) if external else None
            extra = _IA32_CALL_CLOBBERED if argument is None else argument
            reads |= extra
            read_atoms |= ia32_register_atoms(extra)
            target = None
    elif flow == "call":
        reads |= _IA32_CALL_CLOBBERED
        read_atoms |= ia32_register_atoms(_IA32_CALL_CLOBBERED)
    if form["string_memory"] is not None:
        memory = {
            "base": None,
            "index": None,
            "scale": 1,
            "displacement": 0,
            "absolute": False,
            "width": 0,
            "read": form["string_memory"]["read"],
            "write": form["string_memory"]["write"],
            "unknown": True,
        }
    if opcode in (49, 51) and form["modrm"] and (width == 32):
        if modrm_byte >> 6 == 3 and modrm_byte & 7 == modrm_byte >> 3 & 7:
            zeroed = names[modrm_byte & 7]
            reads.discard(zeroed)
            writes.add(zeroed)
            read_atoms -= _IA32_ATOMS_OF[zeroed]
            write_atoms |= _IA32_ATOMS_OF[zeroed]
    return {
        "offset": offset,
        "length": length,
        "opcode": opcode,
        "fields": fields,
        "reads": frozenset(reads),
        "writes": frozenset(writes),
        "flow": flow,
        "target": target,
        "frozen": frozenset(frozen),
        "memory": memory,
        "encoding": encoding,
        "indirect": indirect,
        "read_atoms": frozenset(read_atoms),
        "write_atoms": frozenset(write_atoms),
    }


def decode_ia32_bijection_body(
    body: bytes, context: str, relocations: dict | None = None, code_length: int | None = None
) -> list[dict]:
    """Decode a COMDAT body to exhaustion with the closed table.

    `code_length`, when given, is the pinned extent of the body's CODE: a
    COMDAT that ends in a compiler-emitted switch table carries data after
    its last instruction, and decoding that data as instructions would be
    nonsense.  The tail is never decoded, never rewritten, and is proved
    unreachable from the decoded control flow: the code must decode to
    exactly `code_length` with no straddling instruction, and its last
    instruction may not fall through into the tail.
    """
    require(isinstance(body, (bytes, bytearray)) and body, f"{context}: body is empty")
    body = bytes(body)
    limit = len(body) if code_length is None else code_length
    require(
        isinstance(limit, int) and (not isinstance(limit, bool)) and (0 < limit <= len(body)),
        f"{context}: code length is out of range",
    )
    code = body[:limit]
    instructions = []
    offset = 0
    while offset < len(code):
        instruction = decode_ia32_bijection_instruction(
            code, offset, f"{context} at {offset}", relocations
        )
        instructions.append(instruction)
        offset += instruction["length"]
    require(offset == len(code), f"{context}: body does not decode to exhaustion")
    if limit < len(body):
        require(
            instructions[-1]["flow"] in ("ret", "jmp", "exit"),
            f"{context}: code falls through into the body's data tail",
        )
    starts = {item["offset"] for item in instructions}
    for item in instructions:
        if item["target"] is not None:
            require(
                item["target"] in starts,
                f"{context}: branch at {item['offset']} does not target an instruction boundary in this body",
            )
    return instructions


def _ia32_backward_liveness(
    instructions: list[dict], successors: list[list[int]], context: str, blind: dict | None = None
) -> list[frozenset]:
    """Backward atom liveness over a supplied control-flow graph.

    The lattice is the sub-register ATOM set, so a partial definition
    (`fnstsw ax`, `mov al, m`) kills exactly the bits it defines and no more.
    The fixpoint is monotone and bounded by the twenty atoms, so it
    terminates.  `blind`, when given, maps an instruction index to atoms
    subtracted from its READ set -- the way to ask "would this register still
    be live here if this particular consumer did not exist", which is how the
    web certificate proves a value has no consumer outside its own web.
    """
    blind = blind or {}
    live = [frozenset() for _ in instructions]
    for _ in range(len(instructions) * 20 + 20):
        changed = False
        for index in reversed(range(len(instructions))):
            item = instructions[index]
            out = (
                frozenset().union(*[live[edge] for edge in successors[index]])
                if successors[index]
                else frozenset()
            )
            reads = item["read_atoms"] - blind.get(index, frozenset())
            value = out - item["write_atoms"] | reads
            if value != live[index]:
                live[index] = value
                changed = True
        if not changed:
            break
    else:
        raise ByteIdentityError(f"{context}: liveness did not converge")
    return live


def _ia32_live_out(live: list[frozenset], successors: list[list[int]], index: int) -> frozenset:
    """The union of the live sets on an instruction's outgoing edges."""
    return (
        frozenset().union(*[live[edge] for edge in successors[index]])
        if successors[index]
        else frozenset()
    )


def _register_bijection_live_sets(instructions: list[dict], context: str) -> list[frozenset]:
    """Backward liveness over the body's own control-flow graph.

    Successors are the fall-through and the decoded branch target; `ret` has
    none and instead reads the ABI's live-out set, so the epilogue's `pop`s
    kill exactly the callee-saved registers they restore.
    """
    index_of = {item["offset"]: index for index, item in enumerate(instructions)}
    successors = []
    for index, item in enumerate(instructions):
        edges = []
        if item["flow"] in ("fall", "jcc", "call"):
            if index + 1 < len(instructions):
                edges.append(index + 1)
            else:
                require(item["flow"] != "fall", f"{context}: body falls off its end")
        if item["flow"] in ("jcc", "jmp"):
            edges.append(index_of[item["target"]])
        successors.append(edges)
    return (_ia32_backward_liveness(instructions, successors, context), successors)
