from __future__ import annotations

from reprobit.binary import ByteIdentityError, require
from reprobit.coff import CoffObject, coff_auxiliary, coff_body, coff_unpack, detailed_relocations, section_definitions
from reprobit.ia32 import IA32_PREFIXES, supported_ia32_instruction_length

from .coff import _coff_marker, _coff_section_symbol, _coff_table_bytes, _comdat_child, _comdat_child_closure, comdat_primary_identity_multiset, function_multiset, function_symbol
from .composition import compose_equal_body_comdat, compose_same_slot_resize, instruction_mosaic_metadata_sha256, require_instruction_mosaic_semantic_relocations
from .debug import CODEVIEW_SYMBOL_NAME_OFFSETS, FPO_RECORD_KEYS, _apply_replacements, local_symbol_kind, parse_codeview_symbol_stream, parse_fpo_data, shifted_pointer
from .foundation import exact_audit_keys, exact_keys, require_exact_int, require_payload_free_declaration, require_sha, sha256_bytes
from .ia32 import require_declared_relocation_semantics

"""Classic compiler algorithms: registers."""
REGISTER_BIJECTION_CLASS = 'retail_exact_register_bijection'
REGISTER_BIJECTION_KIND = 'callee_saved_register_bijection_v1'
REGISTER_BIJECTION_FPO_CLOSURE = ['.debug$F', '.debug$S']
REGISTER_BIJECTION_EH_CLOSURE = ['.debug$S', '.xdata$x']

def register_bijection_delegate(expected_closure: object, expected_code_renames: object, expected_relocation_moves: object=()) -> str:
    """Name the installation delegate from the PINS alone.

    Both inputs are manifest declarations, never measurements of the objects
    -- the composer requires the objects' own closure and rename set to equal
    these pins first, so a pin that disagrees refuses before this is reached.
    `equal_body_strict` is kept wherever the pins allow it (the FPO closure
    with no declared rename), which is exactly the shape every row landed on
    this class so far.  Otherwise the delegate is
    `equal_body_eh_structural_local`, the pre-existing class that admits both
    closure shapes, requires byte-identical xdata, and proves each declared
    object-local $L/$T rename structurally.

    A donor that reaches a different compiler state can also SCHEDULE its
    instructions differently, which moves the operands its relocations cover.
    That is the pre-existing `equal_body_eh_reloc_layout` class: it pairs the
    two tables by ordinal, requires identical types and addends and
    structurally identical targets, and gives the seed's own relocation
    RECORDS the donor's offsets.  A non-empty `expected_relocation_moves` pin
    names it; an empty one can never reach it.
    """
    if expected_relocation_moves:
        return 'equal_body_eh_reloc_layout'
    if list(expected_closure) == REGISTER_BIJECTION_FPO_CLOSURE and (not expected_code_renames):
        return 'equal_body_strict'
    return 'equal_body_eh_structural_local'
IA32_GENERAL_REGISTER_NAMES = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi')
_IA32_REGISTER_NUMBERS = {name: number for number, name in enumerate(IA32_GENERAL_REGISTER_NAMES)}
_IA32_STRUCTURAL_REGISTERS = frozenset({'esp', 'ebp'})
_IA32_CALL_CLOBBERED = frozenset({'eax', 'ecx', 'edx'})
_IA32_RETURN_LIVE = frozenset({'eax', 'ebx', 'esi', 'edi', 'ebp', 'esp'})
CODEVIEW_X86_REGISTER_NUMBERS = {'eax': 17, 'ecx': 18, 'edx': 19, 'ebx': 20, 'esp': 21, 'ebp': 22, 'esi': 23, 'edi': 24}
CODEVIEW_REGISTER_RECORD_TYPE = 2

def _bijection_form(*, modrm: bool=False, reg: str | None=None, reg_read: bool=False, reg_write: bool=False, rm_read: bool=False, rm_write: bool=False, ext_no_write: frozenset=frozenset(), ext_write: frozenset=frozenset(), ext_allowed: frozenset | None=None, ext_implicit: dict | None=None, ext_flow: dict | None=None, implicit_frozen: frozenset=frozenset(), opreg: str | None=None, reads: frozenset=frozenset(), writes: frozenset=frozenset(), flow: str='fall', displacement: int=0, width: int=32, rm_width: int | None=None, x87: bool=False, size16_ok: bool=False, size16_ext: frozenset | None=None, string_memory: dict | None=None) -> dict:
    return {'modrm': modrm, 'reg': reg, 'reg_read': reg_read, 'reg_write': reg_write, 'rm_read': rm_read, 'rm_write': rm_write, 'ext_no_write': ext_no_write, 'ext_write': ext_write, 'ext_allowed': ext_allowed, 'ext_implicit': ext_implicit or {}, 'ext_flow': ext_flow or {}, 'implicit_frozen': implicit_frozen, 'opreg': opreg, 'reads': reads, 'writes': writes, 'flow': flow, 'displacement': displacement, 'width': width, 'rm_width': rm_width, 'x87': x87, 'size16_ok': size16_ok, 'size16_ext': size16_ext, 'string_memory': string_memory}

def _ia32_bijection_table() -> dict:
    """The closed semantic table this class will rewrite.

    An opcode is admitted only when its register fields and its *complete*
    implicit-operand set are known exactly.  Everything outside the table --
    including every form with an implicit general-register operand, every
    unadmitted prefix and every indirect *jump* -- is refused rather than
    guessed.
    """
    table = {}
    stack = frozenset({'esp'})
    table[49] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_read=True, rm_write=True, size16_ok=True)
    table[51] = _bijection_form(modrm=True, reg='gpr', reg_read=True, reg_write=True, rm_read=True, size16_ok=True)
    table[57] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_read=True, size16_ok=True)
    table[59] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_read=True, size16_ok=True)
    table[133] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_read=True, size16_ok=True)
    for opcode in (3, 11, 27, 35, 43):
        table[opcode] = _bijection_form(modrm=True, reg='gpr', reg_read=True, reg_write=True, rm_read=True, size16_ok=True)
    table[137] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_write=True, size16_ok=True)
    table[139] = _bijection_form(modrm=True, reg='gpr', reg_write=True, rm_read=True, size16_ok=True)
    table[141] = _bijection_form(modrm=True, reg='gpr', reg_write=True)
    table[131] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, ext_no_write=frozenset({7}), size16_ok=True)
    table[129] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, ext_no_write=frozenset({7}), size16_ok=True)
    table[199] = _bijection_form(modrm=True, reg='ext', ext_allowed=frozenset({0}), rm_write=True, size16_ok=True)
    table[56] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_read=True, width=8)
    table[58] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_read=True, width=8)
    table[132] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_read=True, width=8)
    table[136] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_write=True, width=8)
    table[138] = _bijection_form(modrm=True, reg='gpr', reg_write=True, rm_read=True, width=8)
    table[26] = _bijection_form(modrm=True, reg='gpr', reg_read=True, reg_write=True, rm_read=True, width=8)
    table[128] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, ext_no_write=frozenset({7}), width=8)
    table[198] = _bijection_form(modrm=True, reg='ext', ext_allowed=frozenset({0}), rm_write=True, width=8)
    table[246] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, ext_no_write=frozenset({0}), ext_allowed=frozenset({0, 2, 3}), width=8)
    table[254] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, ext_allowed=frozenset({0, 1}), width=8)
    table[60] = _bijection_form(reads=frozenset({'eax'}), implicit_frozen=frozenset({'eax'}))
    table[153] = _bijection_form(reads=frozenset({'eax'}), writes=frozenset({'edx'}), implicit_frozen=frozenset({'eax', 'edx'}))
    _muldiv = (frozenset({'eax', 'edx'}), frozenset({'eax', 'edx'}), frozenset({'eax', 'edx'}))
    table[247] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, ext_no_write=frozenset({0, 4, 5, 6, 7}), ext_allowed=frozenset({0, 2, 3, 4, 5, 6, 7}), ext_implicit={4: _muldiv, 5: _muldiv, 6: _muldiv, 7: _muldiv})
    for index in range(8):
        table[64 + index] = _bijection_form(opreg='readwrite', size16_ok=True)
        table[72 + index] = _bijection_form(opreg='readwrite', size16_ok=True)
        table[80 + index] = _bijection_form(opreg='read', reads=stack, writes=stack)
        table[88 + index] = _bijection_form(opreg='write', reads=stack, writes=stack)
        table[184 + index] = _bijection_form(opreg='write', size16_ok=True)
    table[5] = _bijection_form(reads=frozenset({'eax'}), writes=frozenset({'eax'}), implicit_frozen=frozenset({'eax'}))
    table[161] = _bijection_form(writes=frozenset({'eax'}), implicit_frozen=frozenset({'eax'}))
    table[163] = _bijection_form(reads=frozenset({'eax'}), implicit_frozen=frozenset({'eax'}))
    table[104] = _bijection_form(reads=stack, writes=stack)
    table[106] = _bijection_form(reads=stack, writes=stack)
    for opcode in range(112, 128):
        table[opcode] = _bijection_form(flow='jcc', displacement=1)
    table[235] = _bijection_form(flow='jmp', displacement=1)
    table[233] = _bijection_form(flow='jmp', displacement=4)
    table[232] = _bijection_form(flow='call', displacement=4, reads=stack, writes=_IA32_CALL_CLOBBERED)
    table[255] = _bijection_form(modrm=True, reg='ext', ext_allowed=frozenset({0, 1, 2, 4}), rm_read=True, ext_write=frozenset({0, 1}), size16_ok=True, size16_ext=frozenset({0, 1}), flow='call', ext_flow={0: 'fall', 1: 'fall', 2: 'call', 4: 'exit'}, ext_implicit={2: (stack, _IA32_CALL_CLOBBERED, frozenset()), 4: (frozenset(IA32_GENERAL_REGISTER_NAMES), frozenset(), frozenset())})
    table[194] = _bijection_form(flow='ret', reads=_IA32_RETURN_LIVE)
    table[195] = _bijection_form(flow='ret', reads=_IA32_RETURN_LIVE)
    for opcode in range(216, 224):
        table[opcode] = _bijection_form(modrm=True, reg='ext', x87=True)
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
        table[opcode] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_read=True, rm_write=True, width=8)
    for opcode in (2, 10, 18, 34, 42, 50):
        table[opcode] = _bijection_form(modrm=True, reg='gpr', reg_read=True, reg_write=True, rm_read=True, width=8)
    for opcode in (1, 9, 17, 25, 33, 41):
        table[opcode] = _bijection_form(modrm=True, reg='gpr', reg_read=True, rm_read=True, rm_write=True, size16_ok=True)
    table[19] = _bijection_form(modrm=True, reg='gpr', reg_read=True, reg_write=True, rm_read=True, size16_ok=True)
    for opcode in (4, 12, 20, 28, 36, 44, 52, 168):
        table[opcode] = _bijection_form(reads=frozenset({'eax'}), implicit_frozen=frozenset({'eax'}), width=8)
    for opcode in (13, 21, 29, 37, 45, 53):
        table[opcode] = _bijection_form(reads=frozenset({'eax'}), writes=frozenset({'eax'}), implicit_frozen=frozenset({'eax'}))
    for opcode in (61, 169):
        table[opcode] = _bijection_form(reads=frozenset({'eax'}), implicit_frozen=frozenset({'eax'}), size16_ok=True)
    for index in range(8):
        table[176 + index] = _bijection_form(opreg='write', width=8)
    for opcode in (192, 208):
        table[opcode] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, width=8, ext_allowed=_IA32_SHIFT_DIGITS)
    for opcode in (193, 209):
        table[opcode] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, size16_ok=True, ext_allowed=_IA32_SHIFT_DIGITS)
    table[210] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, width=8, ext_allowed=_IA32_SHIFT_DIGITS, reads=frozenset({'ecx'}), implicit_frozen=frozenset({'ecx'}))
    table[211] = _bijection_form(modrm=True, reg='ext', rm_read=True, rm_write=True, size16_ok=True, ext_allowed=_IA32_SHIFT_DIGITS, reads=frozenset({'ecx'}), implicit_frozen=frozenset({'ecx'}))
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
        table[opcode] = _bijection_form(flow='jcc', displacement=4)
    for opcode in (183, 191):
        table[opcode] = _bijection_form(modrm=True, reg='gpr', reg_write=True, rm_read=True)
    for opcode in (182, 190):
        table[opcode] = _bijection_form(modrm=True, reg='gpr', reg_write=True, rm_read=True, rm_width=8)
    # IMUL r32,r/m32 reads and rewrites its explicit destination and reads its
    # explicit source.  The 16-bit prefix remains outside this exact row.
    table[175] = _bijection_form(modrm=True, reg='gpr', reg_read=True, reg_write=True, rm_read=True)
    for opcode in range(144, 160):
        table[opcode] = _bijection_form(modrm=True, reg='ext', ext_allowed=frozenset({0}), rm_write=True, width=8)
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
    return _bijection_form(reads=frozenset(reads), writes=frozenset(writes), implicit_frozen=frozenset(set(reads) | set(writes)), string_memory={'read': memory_read, 'write': memory_write})
IA32_BIJECTION_REPEATED_STRING_FORMS = {(prefix, opcode): _ia32_string_form(('ecx', 'esi', 'edi'), ('ecx', 'esi', 'edi'), memory_read=True, memory_write=True) for prefix in (243,) for opcode in (164, 165)}
IA32_BIJECTION_REPEATED_STRING_FORMS.update({(243, opcode): _ia32_string_form(('eax', 'ecx', 'edi'), ('ecx', 'edi'), memory_read=False, memory_write=True) for opcode in (170, 171)})
IA32_BIJECTION_REPEATED_STRING_FORMS.update({(prefix, opcode): _ia32_string_form(('eax', 'ecx', 'edi'), ('ecx', 'edi'), memory_read=True, memory_write=False) for prefix in (242, 243) for opcode in (174, 175)})
IA32_BIJECTION_REPEATED_STRING_FORMS.update({(prefix, opcode): _ia32_string_form(('ecx', 'esi', 'edi'), ('ecx', 'esi', 'edi'), memory_read=True, memory_write=False) for prefix in (242, 243) for opcode in (166, 167)})
_IA32_EXTERNAL_TRANSFER_LIVE = frozenset(IA32_GENERAL_REGISTER_NAMES)
_IA32_BYTE_ADDRESSABLE = ('eax', 'ecx', 'edx', 'ebx')

def _ia32_register_atoms(name: str) -> tuple:
    """Every liveness atom of one general register."""
    if name in _IA32_BYTE_ADDRESSABLE:
        return (name + '.l', name + '.h', name + '.u')
    return (name + '.w',)
_IA32_ATOMS_OF = {name: frozenset(_ia32_register_atoms(name)) for name in IA32_GENERAL_REGISTER_NAMES}

def ia32_register_atoms(names) -> frozenset:
    """The atom set of a collection of whole general registers."""
    return frozenset().union(*[_IA32_ATOMS_OF[name] for name in names]) if names else frozenset()

def _ia32_atom_registers(atoms) -> list:
    """The register names an atom set touches, for a refusal message."""
    return sorted({atom.split('.')[0] for atom in atoms})

def _bijection_form_for(opcode: int) -> dict | None:
    """Look one decoded opcode key up in the closed table."""
    if opcode & 65280 == 3840:
        return IA32_BIJECTION_TWO_BYTE_FORMS.get(opcode & 255)
    return IA32_BIJECTION_FORMS.get(opcode)
_MSVC_MEMBER_FUNCTION_CLASSES = frozenset('ABEFIJMNQRUV')
_MSVC_STATIC_FUNCTION_CLASSES = frozenset('CDKLST')
_MSVC_GLOBAL_FUNCTION_CLASSES = frozenset('YZ')
_MSVC_THUNK_FUNCTION_CLASSES = frozenset('GHOPWX')
_MSVC_CV_LETTERS = frozenset('ABCD')
_MSVC_CALL_ARGUMENT_REGISTERS = {'A': frozenset(), 'B': frozenset(), 'C': frozenset(), 'D': frozenset(), 'E': frozenset({'ecx'}), 'F': frozenset({'ecx'}), 'G': frozenset(), 'H': frozenset(), 'I': frozenset({'ecx', 'edx'}), 'J': frozenset({'ecx', 'edx'})}

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
    if not isinstance(symbol, str) or not symbol.startswith('?'):
        return None
    if not symbol.endswith('Z'):
        return None
    readings = set()
    for index in range(len(symbol) - 1):
        if symbol[index:index + 2] == '@@':
            cursor = index + 2
        elif symbol[index] == '@' and symbol[index + 1] in _MSVC_GLOBAL_FUNCTION_CLASSES:
            cursor = index + 1
        else:
            continue
        if cursor >= len(symbol):
            continue
        letter = symbol[cursor]
        cursor += 1
        if letter in _MSVC_THUNK_FUNCTION_CLASSES:
            if cursor + 2 < len(symbol) and symbol[cursor].isdigit() and (symbol[cursor + 1] in _MSVC_CV_LETTERS) and (symbol[cursor + 2] in _MSVC_CALL_ARGUMENT_REGISTERS):
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

def decode_ia32_bijection_instruction(body: bytes, offset: int, context: str, relocations: dict | None=None) -> dict:
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
    require(0 <= offset < len(body), f'{context}: instruction offset is out of range')
    window = body[offset:]
    length = supported_ia32_instruction_length(window, context)
    encoded = body[offset:offset + length]
    require(len(encoded) == length, f'{context}: instruction is truncated')
    cursor = 0
    segment_prefix = False
    operand_size_16 = False
    repeat_prefix = None
    while encoded[cursor] in IA32_PREFIXES:
        prefix = encoded[cursor]
        if prefix in _IA32_INERT_SEGMENT_PREFIXES:
            require(not segment_prefix, f'{context}: repeated segment prefix')
            segment_prefix = True
        elif prefix == _IA32_OPERAND_SIZE_PREFIX:
            require(not operand_size_16, f'{context}: repeated operand-size prefix')
            operand_size_16 = True
        elif prefix in _IA32_REPEAT_PREFIXES:
            require(repeat_prefix is None, f'{context}: repeated repeat prefix')
            repeat_prefix = prefix
        else:
            raise ByteIdentityError(f'{context}: prefixed instructions are outside the register-bijection table')
        cursor += 1
        require(cursor < length, f'{context}: instruction is only prefixes')
    opcode_at = offset + cursor
    opcode = encoded[cursor]
    cursor += 1
    if opcode == 15:
        require(cursor < length, f'{context}: truncated two-byte opcode')
        opcode = 3840 | encoded[cursor]
        cursor += 1
    if repeat_prefix is not None:
        form = IA32_BIJECTION_REPEATED_STRING_FORMS.get((repeat_prefix, opcode))
        require(form is not None, f'{context}: the repeat prefix 0x{repeat_prefix:02x} on opcode 0x{opcode:02x} is outside the register-bijection table')
        require(not operand_size_16, f'{context}: an operand-size prefix on a repeated string operation is outside the register-bijection table')
    else:
        form = _bijection_form_for(opcode)
    require(form is not None, f'{context}: opcode 0x{opcode:02x} is outside the register-bijection table')
    width = form['width']
    if operand_size_16:
        require(form['size16_ok'] and width == 32, f'{context}: the operand-size prefix is outside the register-bijection table for this opcode')
        width = 16
    effective_width = width
    fields = []
    encoding = None
    flow_override = None
    frozen = set(form['implicit_frozen'])
    memory = None
    reads = set(form['reads'])
    writes = set(form['writes'])
    read_atoms = set(ia32_register_atoms(form['reads']))
    write_atoms = set(ia32_register_atoms(form['writes']))
    read_atoms |= ia32_register_atoms(form['implicit_frozen'])
    indirect = False
    names = IA32_GENERAL_REGISTER_NAMES

    def _touch(value: int, is_read: bool, is_write: bool, field_width: int | None=None) -> None:
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
            atoms = frozenset({name + ('.l' if value < 4 else '.h')})
        else:
            name = names[value]
            if width == 16 and name in _IA32_BYTE_ADDRESSABLE:
                atoms = frozenset({name + '.l', name + '.h'})
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
    if form['opreg'] is not None:
        if width != 8:
            fields.append((opcode_at, 0))
        _touch(opcode & 7, form['opreg'] in ('read', 'readwrite'), form['opreg'] in ('write', 'readwrite'))
    if form['modrm']:
        require(cursor < length, f'{context}: instruction lacks ModRM')
        modrm_at = offset + cursor
        modrm = encoded[cursor]
        cursor += 1
        modrm_byte = modrm
        mode = modrm >> 6
        rm = modrm & 7
        register_field = modrm >> 3 & 7
        rm_write = form['rm_write']
        sib_at = None
        displacement_at = None
        displacement_size = 0
        absolute_operand = False
        if form['reg'] == 'gpr':
            if width != 8:
                fields.append((modrm_at, 3))
            _touch(register_field, form['reg_read'], form['reg_write'])
        else:
            require(form['reg'] == 'ext', f'{context}: ModRM register field role is undeclared')
            allowed = form['ext_allowed']
            require(allowed is None or register_field in allowed, f'{context}: ModRM extension /{register_field} of opcode 0x{opcode:02x} is outside the register-bijection table')
            require(width != 16 or form['size16_ext'] is None or register_field in form['size16_ext'], f'{context}: the operand-size prefix on extension /{register_field} of opcode 0x{opcode:02x} is outside the register-bijection table')
            if register_field in form['ext_no_write']:
                rm_write = False
            if register_field in form['ext_write']:
                rm_write = True
            implicit = form['ext_implicit'].get(register_field)
            if implicit is not None:
                extra_reads, extra_writes, extra_frozen = implicit
                reads |= extra_reads
                writes |= extra_writes
                frozen |= extra_frozen
                read_atoms |= ia32_register_atoms(extra_reads | extra_frozen)
                write_atoms |= ia32_register_atoms(extra_writes)
            member_flow = form['ext_flow'].get(register_field)
            if member_flow is not None:
                flow_override = member_flow
        if mode == 3:
            if form['x87']:
                if opcode == 223 and modrm == 224:
                    write_atoms |= {'eax.l', 'eax.h'}
                    frozen.add('eax')
            else:
                rm_field_width = form['rm_width'] or width
                if rm_field_width != 8:
                    fields.append((modrm_at, 0))
                _touch(rm, form['rm_read'], rm_write, rm_field_width)
        else:
            base_name = None
            index_name = None
            scale = 1
            absolute = False
            if rm == 4:
                require(cursor < length, f'{context}: instruction lacks SIB')
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
                require(cursor < length, f'{context}: instruction lacks its disp8')
                displacement_at = offset + cursor
                displacement_size = 1
                displacement = int.from_bytes(encoded[cursor:cursor + 1], 'little', signed=True)
            elif mode == 2 or absolute:
                require(cursor + 4 <= length, f'{context}: instruction lacks its disp32')
                displacement_at = offset + cursor
                displacement_size = 4
                displacement = int.from_bytes(encoded[cursor:cursor + 4], 'little', signed=True)
            if form['rm_read'] or rm_write or form['x87']:
                memory = {'base': base_name, 'index': index_name, 'scale': scale, 'displacement': displacement, 'absolute': absolute, 'width': max(width // 8, 1), 'read': bool(form['rm_read']) or bool(form['x87']), 'write': bool(rm_write), 'unknown': False}
        require(form['reg'] != 'gpr' or not (form['reg_write'] and form['rm_write']), f'{context}: instruction form writes two operands')
        encoding = {'modrm_at': modrm_at, 'mode': mode, 'rm': rm, 'reg': register_field, 'sib_at': sib_at, 'displacement_at': displacement_at, 'displacement_size': displacement_size, 'absolute': absolute_operand}
    target = None
    flow = form['flow'] if flow_override is None else flow_override
    if flow == 'exit' and form['modrm']:
        indirect = True
    if flow in ('jcc', 'jmp', 'call') and form['displacement']:
        width_bytes = form['displacement']
        displacement_at = offset + length - width_bytes
        row = (relocations or {}).get(displacement_at)
        external = row is not None and row.get('width') == width_bytes
        if external and flow == 'jmp':
            flow = 'exit'
            reads = set(_IA32_EXTERNAL_TRANSFER_LIVE)
            writes = set()
            read_atoms = set(ia32_register_atoms(_IA32_EXTERNAL_TRANSFER_LIVE))
            write_atoms = set()
        elif external and flow == 'jcc':
            raise ByteIdentityError(f'{context}: a relocated conditional branch is outside the register-bijection table')
        elif not external:
            relative = int.from_bytes(encoded[length - width_bytes:], 'little', signed=True)
            target = offset + length + relative
        if flow == 'call':
            symbol = row.get('target') if row is not None else None
            argument = msvc_call_argument_registers(symbol) if external else None
            extra = _IA32_CALL_CLOBBERED if argument is None else argument
            reads |= extra
            read_atoms |= ia32_register_atoms(extra)
            target = None
    elif flow == 'call':
        reads |= _IA32_CALL_CLOBBERED
        read_atoms |= ia32_register_atoms(_IA32_CALL_CLOBBERED)
    if form['string_memory'] is not None:
        memory = {'base': None, 'index': None, 'scale': 1, 'displacement': 0, 'absolute': False, 'width': 0, 'read': form['string_memory']['read'], 'write': form['string_memory']['write'], 'unknown': True}
    if opcode in (49, 51) and form['modrm'] and (width == 32):
        if modrm_byte >> 6 == 3 and modrm_byte & 7 == modrm_byte >> 3 & 7:
            zeroed = names[modrm_byte & 7]
            reads.discard(zeroed)
            writes.add(zeroed)
            read_atoms -= _IA32_ATOMS_OF[zeroed]
            write_atoms |= _IA32_ATOMS_OF[zeroed]
    return {'offset': offset, 'length': length, 'opcode': opcode, 'fields': fields, 'reads': frozenset(reads), 'writes': frozenset(writes), 'flow': flow, 'target': target, 'frozen': frozenset(frozen), 'memory': memory, 'encoding': encoding, 'indirect': indirect, 'read_atoms': frozenset(read_atoms), 'write_atoms': frozenset(write_atoms)}

def decode_ia32_bijection_body(body: bytes, context: str, relocations: dict | None=None, code_length: int | None=None) -> list[dict]:
    """Decode a COMDAT body to exhaustion with the closed table.

    `code_length`, when given, is the pinned extent of the body's CODE: a
    COMDAT that ends in a compiler-emitted switch table carries data after
    its last instruction, and decoding that data as instructions would be
    nonsense.  The tail is never decoded, never rewritten, and is proved
    unreachable from the decoded control flow: the code must decode to
    exactly `code_length` with no straddling instruction, and its last
    instruction may not fall through into the tail.
    """
    require(isinstance(body, (bytes, bytearray)) and body, f'{context}: body is empty')
    body = bytes(body)
    limit = len(body) if code_length is None else code_length
    require(isinstance(limit, int) and (not isinstance(limit, bool)) and (0 < limit <= len(body)), f'{context}: code length is out of range')
    code = body[:limit]
    instructions = []
    offset = 0
    while offset < len(code):
        instruction = decode_ia32_bijection_instruction(code, offset, f'{context} at {offset}', relocations)
        instructions.append(instruction)
        offset += instruction['length']
    require(offset == len(code), f'{context}: body does not decode to exhaustion')
    if limit < len(body):
        require(instructions[-1]['flow'] in ('ret', 'jmp', 'exit'), f"{context}: code falls through into the body's data tail")
    starts = {item['offset'] for item in instructions}
    for item in instructions:
        if item['target'] is not None:
            require(item['target'] in starts, f"{context}: branch at {item['offset']} does not target an instruction boundary in this body")
    return instructions

def _ia32_backward_liveness(instructions: list[dict], successors: list[list[int]], context: str, blind: dict | None=None) -> list[frozenset]:
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
            out = frozenset().union(*[live[edge] for edge in successors[index]]) if successors[index] else frozenset()
            reads = item['read_atoms'] - blind.get(index, frozenset())
            value = out - item['write_atoms'] | reads
            if value != live[index]:
                live[index] = value
                changed = True
        if not changed:
            break
    else:
        raise ByteIdentityError(f'{context}: liveness did not converge')
    return live

def _ia32_live_out(live: list[frozenset], successors: list[list[int]], index: int) -> frozenset:
    """The union of the live sets on an instruction's outgoing edges."""
    return frozenset().union(*[live[edge] for edge in successors[index]]) if successors[index] else frozenset()

def _register_bijection_live_sets(instructions: list[dict], context: str) -> list[frozenset]:
    """Backward liveness over the body's own control-flow graph.

    Successors are the fall-through and the decoded branch target; `ret` has
    none and instead reads the ABI's live-out set, so the epilogue's `pop`s
    kill exactly the callee-saved registers they restore.
    """
    index_of = {item['offset']: index for index, item in enumerate(instructions)}
    successors = []
    for index, item in enumerate(instructions):
        edges = []
        if item['flow'] in ('fall', 'jcc', 'call'):
            if index + 1 < len(instructions):
                edges.append(index + 1)
            else:
                require(item['flow'] != 'fall', f'{context}: body falls off its end')
        if item['flow'] in ('jcc', 'jmp'):
            edges.append(index_of[item['target']])
        successors.append(edges)
    return (_ia32_backward_liveness(instructions, successors, context), successors)

def apply_register_bijection(body: bytes, mapping: dict, region: tuple[int, int], relocation_offsets: frozenset, context: str, relocations: dict | None=None, code_length: int | None=None, internal_targets: frozenset | None=None) -> tuple[bytes, dict]:
    """Rewrite one region's general-register fields under a proved bijection.

    Every obligation this class rests on is checked here: total decode, closed
    forms, structural-register exclusion, relocation disjointness, the
    liveness proof for the region's boundary, and length preservation verified
    by re-decoding the image.
    """
    require_payload_free_declaration(mapping, f'{context} register mapping')
    body = bytes(body)
    start, end = region
    instructions = decode_ia32_bijection_body(body, context, relocations, code_length)
    limit = len(body) if code_length is None else code_length
    boundaries = {item['offset'] for item in instructions}
    boundaries.add(limit)
    require(end <= limit, f"{context}: region reaches past the body's code")
    if any((item['indirect'] for item in instructions)):
        require(internal_targets is not None, f'{context}: a computed jump requires the relocated in-body target set')
        entered = sorted((target for target in internal_targets if start < target < end))
        require(not entered, f'{context}: a relocated in-body target at {entered[:1]} enters the region other than at its first instruction')
    require(start in boundaries and end in boundaries and (start < end), f'{context}: region does not span whole instructions')
    numbers = {}
    for source, destination in mapping.items():
        require(source in _IA32_REGISTER_NUMBERS and destination in _IA32_REGISTER_NUMBERS, f'{context}: mapping names an unknown register')
        numbers[_IA32_REGISTER_NUMBERS[source]] = _IA32_REGISTER_NUMBERS[destination]
    support = set(mapping) | set(mapping.values())
    require(len(set(mapping.values())) == len(mapping) and set(mapping.values()) == set(mapping), f'{context}: mapping is not a bijection of one register set')
    require(all((source != destination for source, destination in mapping.items())), f'{context}: mapping fixes a register it names')
    require('esp' not in support, f'{context}: mapping touches ESP, whose encodings carry ModRM/SIB structure')
    live, successors = _register_bijection_live_sets(instructions, context)
    inside = [item for item in instructions if start <= item['offset'] < end]
    require(inside, f'{context}: region contains no instruction')
    require(inside[-1]['offset'] + inside[-1]['length'] == end, f'{context}: region does not end on an instruction boundary')
    entry = instructions.index(inside[0])
    for item in inside:
        blocked = support & set(item.get('frozen', frozenset()))
        require(not blocked, f"{context}: {sorted(blocked)} is named by a sub-register field at {item['offset']} that sigma cannot rewrite")
    for index, item in enumerate(instructions):
        for edge in successors[index]:
            crosses_in = not start <= item['offset'] < end and start <= instructions[edge]['offset'] < end
            if crosses_in:
                require(edge == entry, f'{context}: control enters the region other than at its first instruction')
    support_atoms = ia32_register_atoms(support)
    dead_in = support_atoms & set(live[entry])
    require(not dead_in, f'{context}: {_ia32_atom_registers(dead_in)} is live on entry to the region')
    affected = {index for index, item in enumerate(instructions) if start <= item['offset'] < end and item['flow'] not in ('ret', 'exit') and support_atoms & (set(item['read_atoms']) | set(item['write_atoms']))}
    sigma_reachable = set(affected)
    frontier = list(affected)
    while frontier:
        node = frontier.pop()
        for edge in successors[node]:
            if edge not in sigma_reachable:
                sigma_reachable.add(edge)
                frontier.append(edge)
    for index, item in enumerate(instructions):
        if not start <= item['offset'] < end:
            continue
        for edge in successors[index]:
            if start <= instructions[edge]['offset'] < end:
                continue
            leaking = support_atoms & set(live[edge])
            require(not leaking, f"{context}: {_ia32_atom_registers(leaking)} is live on an edge leaving the region at {item['offset']}")
        if item['flow'] in ('ret', 'exit'):
            leaking = support_atoms & set(item['read_atoms'])
            require(not leaking or index not in sigma_reachable, f"{context}: {_ia32_atom_registers(leaking)} is live at the region's return")
    image = bytearray(body)
    rewritten = []
    for item in inside:
        for byte_index, shift in item['fields']:
            value = image[byte_index] >> shift & 7
            if value not in numbers:
                continue
            require(byte_index not in relocation_offsets, f'{context}: a rewritten byte overlaps a relocation')
            image[byte_index] = (image[byte_index] & ~(7 << shift) | numbers[value] << shift) & 255
            rewritten.append(byte_index)
    require(rewritten, f'{context}: the bijection rewrites nothing')
    image = bytes(image)
    require(len(image) == len(body), f'{context}: the image changed the body length')
    image_instructions = decode_ia32_bijection_body(image, f'{context} image', relocations, code_length)
    require([(item['offset'], item['length']) for item in image_instructions] == [(item['offset'], item['length']) for item in instructions], f'{context}: the image changed an instruction boundary')
    for left, right in zip(image_instructions, instructions):
        form = _bijection_form_for(right['opcode'])
        opreg = form is not None and form['opreg'] is not None
        mask = 248 if opreg else 65535
        require(left['opcode'] & mask == right['opcode'] & mask and left['flow'] == right['flow'] and (left['target'] == right['target']), f'{context}: the image changed an opcode or a branch')
    for left, right in zip(image_instructions, instructions):
        expected_reads = frozenset((mapping.get(name, name) if start <= right['offset'] < end else name for name in right['reads']))
        expected_writes = frozenset((mapping.get(name, name) if start <= right['offset'] < end else name for name in right['writes']))
        require(left['reads'] == expected_reads and left['writes'] == expected_writes, f"{context}: the image's operand set at {right['offset']} is not the bijection's image")
    changed = sorted({index for index in range(len(body)) if body[index] != image[index]})
    require(changed == sorted(set(rewritten)), f'{context}: the image changed a byte the bijection did not name')
    return (image, {'rewritten_offsets': changed, 'region_instruction_count': len(inside), 'instruction_count': len(instructions), 'code_length': limit})

def _codeview_register_field(record: dict, context: str) -> int:
    """The offset of one S_REGISTER record's two-byte register field."""
    field_at = record['offset'] + 4 + 2
    require(field_at + 2 <= record['offset'] + record['size'], f'{context}: S_REGISTER record has no register field')
    return field_at

def _codeview_register_name(stream: bytes, field_at: int, context: str) -> str:
    number = int.from_bytes(stream[field_at:field_at + 2], 'little')
    name = next((key for key, value in CODEVIEW_X86_REGISTER_NUMBERS.items() if value == number), None)
    require(name is not None, f'{context}: S_REGISTER names a non-general register')
    return name

def apply_codeview_register_bijection(stream: bytes, mapping: dict, declared: list[dict], context: str, donor_stream: bytes | None=None) -> bytes:
    """Map the S_REGISTER records that name a bijected register.

    Obligation 9.  The stream is parsed to exhaustion before and after with
    the module's closed record table, only the two-byte register field of a
    declared record changes, and the resulting record identity/size list must
    be unchanged -- so debug information continues to name the register the
    installed code actually uses.

    `donor_stream`, when given, is the DONOR's own `.debug$S`.  It is needed
    whenever the donor reaches a different compiler state, because then the
    installed code is the donor's OUTSIDE the region too and the seed's
    debug information would name the seed's register allocation for locals
    the composition never installs.  In that mode the two streams are first
    proved to describe the same debug structure -- identical record list, and
    byte differences confined to S_REGISTER register fields and to the name
    bytes of object-local `$L`/`$T` symbols, whose seed names the composition
    keeps because it keeps the seed's symbol table -- and then every
    S_REGISTER record takes the DONOR's register, with sigma applied to
    exactly the declared records.  Declaring a record is the statement that
    the local it names lives inside the region; a local outside it keeps the
    register the installed code actually uses, which is the donor's.
    """
    require_payload_free_declaration(mapping, f'{context} register mapping')
    require_payload_free_declaration(declared, f'{context} CodeView declaration')
    records = parse_codeview_symbol_stream(stream, context)
    image = bytearray(stream)
    if donor_stream is None:
        seen = []
        for record in records:
            if record['type'] != CODEVIEW_REGISTER_RECORD_TYPE:
                continue
            field_at = _codeview_register_field(record, context)
            try:
                name = _codeview_register_name(image, field_at, context)
            except ByteIdentityError:
                continue
            if name not in mapping:
                continue
            seen.append({'name': record['name'], 'record_offset': record['offset'], 'donor_register': name, 'image_register': mapping[name]})
            image[field_at:field_at + 2] = CODEVIEW_X86_REGISTER_NUMBERS[mapping[name]].to_bytes(2, 'little')
        require(seen == declared, f'{context}: the S_REGISTER map differs from its declaration')
    else:
        donor_records = parse_codeview_symbol_stream(donor_stream, f'{context} donor')
        require([(item['offset'], item['size'], item['type']) for item in donor_records] == [(item['offset'], item['size'], item['type']) for item in records], f"{context}: the donor's debug$S record list differs from the seed's")
        movable = set()
        for seed_record, donor_record in zip(records, donor_records):
            if seed_record['type'] == CODEVIEW_REGISTER_RECORD_TYPE:
                field_at = _codeview_register_field(seed_record, context)
                movable.update((field_at, field_at + 1))
                continue
            if seed_record['name'] == donor_record['name']:
                continue
            kind = local_symbol_kind(seed_record['name'])
            require(kind is not None and kind == local_symbol_kind(donor_record['name']) and (len(seed_record['name']) == len(donor_record['name'])), f"{context}: the donor's debug$S renames a non-local symbol")
            name_at = seed_record['offset'] + 4 + CODEVIEW_SYMBOL_NAME_OFFSETS[seed_record['type']] + 1
            movable.update(range(name_at, name_at + len(seed_record['name'])))
        differing = {index for index in range(len(stream)) if stream[index] != donor_stream[index]}
        require(differing <= movable, f"{context}: the donor's debug$S differs outside its S_REGISTER fields and object-local names")
        for seed_record in records:
            if seed_record['type'] != CODEVIEW_REGISTER_RECORD_TYPE:
                continue
            field_at = _codeview_register_field(seed_record, context)
            name = _codeview_register_name(donor_stream, field_at, context)
            image[field_at:field_at + 2] = CODEVIEW_X86_REGISTER_NUMBERS[name].to_bytes(2, 'little')
        offsets = [item['record_offset'] for item in declared]
        require(len(set(offsets)) == len(offsets), f'{context}: the S_REGISTER map declares a record twice')
        by_offset = {item['offset']: item for item in records}
        for item in declared:
            record = by_offset.get(item['record_offset'])
            require(record is not None and record['type'] == CODEVIEW_REGISTER_RECORD_TYPE and (record['name'] == item['name']), f'{context}: the S_REGISTER map names no such record')
            field_at = _codeview_register_field(record, context)
            name = _codeview_register_name(donor_stream, field_at, context)
            require(name == item['donor_register'] and mapping.get(name) == item['image_register'], f'{context}: the S_REGISTER map differs from its declaration')
            image[field_at:field_at + 2] = CODEVIEW_X86_REGISTER_NUMBERS[item['image_register']].to_bytes(2, 'little')
    image = bytes(image)
    require([(item['offset'], item['size'], item['type'], item['name']) for item in parse_codeview_symbol_stream(image, f'{context} image')] == [(item['offset'], item['size'], item['type'], item['name']) for item in records], f'{context}: the mapped stream is not the same record list')
    return image

def validate_register_bijection_reencoding(value: object, context: str, preimage_length: int, image_length: int) -> dict:
    """Validate one re-encoding register-bijection declaration.

    Every quantity the composer will MEASURE is declared here first, so a
    manifest that disagrees with the objects refuses before anything is
    installed.  The regions are the only free parameters; growth, branch
    repairs, reseats and the boundary-derived debug ranges are consequences,
    and pinning them is what makes a silent change to the primitive visible.
    """
    require(isinstance(value, dict), f'{context} must be an object')
    exact_audit_keys(value, {'kind', 'regions', 'expected_fpo_record', 'expected_growth', 'expected_branch_repairs', 'expected_relocation_reseat', 'expected_rewritten_field_offsets', 'expected_region_instruction_counts', 'expected_instruction_count', 'expected_image_code_length', 'expected_procedure_range', 'expected_carried_code_symbols', 'authenticity_rationale', 'expected_code_length', 'expected_internal_relocation_targets'}, context, optional={'expected_code_length', 'expected_internal_relocation_targets'})
    require(value.get('kind') == REGISTER_BIJECTION_REENCODING_KIND, f'{context}.kind differs')
    regions = value.get('regions')
    require(isinstance(regions, list) and 1 <= len(regions) <= 8, f'{context}.regions is invalid')
    normalized = []
    previous_end = 0
    names_ebp = False
    for index, item in enumerate(regions):
        item_context = f'{context}.regions[{index}]'
        require(isinstance(item, dict), f'{item_context} must be an object')
        exact_keys(item, {'start', 'end', 'mapping'}, item_context)
        start = require_exact_int(item.get('start'), f'{item_context}.start', minimum=1, maximum=preimage_length - 1)
        end = require_exact_int(item.get('end'), f'{item_context}.end', minimum=2, maximum=preimage_length - 1)
        require(start >= previous_end and start < end, f'{item_context}: regions are unsorted, empty or overlapping')
        previous_end = end
        mapping = item.get('mapping')
        require(isinstance(mapping, dict) and 2 <= len(mapping) <= 8 and all((isinstance(key, str) and isinstance(entry, str) and (key in _IA32_REGISTER_NUMBERS) and (entry in _IA32_REGISTER_NUMBERS) for key, entry in mapping.items())), f'{item_context}.mapping is invalid')
        require(set(mapping) == set(mapping.values()) and len(set(mapping.values())) == len(mapping) and all((key != entry for key, entry in mapping.items())), f'{item_context}.mapping is not a fixed-point-free bijection')
        require('esp' not in set(mapping) | set(mapping.values()), f'{item_context}.mapping touches ESP')
        if 'ebp' in set(mapping) | set(mapping.values()):
            names_ebp = True
        normalized.append({'start': start, 'end': end, 'mapping': dict(sorted(mapping.items()))})
    require(names_ebp, f'{context}: no region names EBP, so this is an ordinary {REGISTER_BIJECTION_CLASS} and must be declared as one')
    record = value.get('expected_fpo_record')
    require(isinstance(record, dict) and set(record) == FPO_RECORD_KEYS - {'raw_sha256'}, f'{context}.expected_fpo_record is invalid')
    require(record.get('cbFrame') == FPO_FRAME_KIND_FPO and record.get('fHasSEH') == 0, f'{context}.expected_fpo_record does not declare a frame-pointer-free, SEH-free frame')
    growth = value.get('expected_growth')
    require(isinstance(growth, list) and growth and (len(growth) <= 64) and all((isinstance(row, list) and len(row) == 4 and all((type(entry) is int for entry in row)) and (0 <= row[0] < preimage_length) and (0 <= row[1] < image_length) and (1 <= row[2] <= 15) and (1 <= row[3] <= 15) and (abs(row[3] - row[2]) == 1) for row in growth)) and ([row[0] for row in growth] == sorted({row[0] for row in growth})), f'{context}.expected_growth is invalid')
    require(image_length - preimage_length == sum((row[3] - row[2] for row in growth)), f"{context}.expected_growth does not account for the image's length change")
    repairs = value.get('expected_branch_repairs')
    require(isinstance(repairs, list) and len(repairs) <= 256 and (repairs == sorted(set(repairs))) and all((type(entry) is int and 0 <= entry < image_length for entry in repairs)), f'{context}.expected_branch_repairs is invalid')
    reseat = value.get('expected_relocation_reseat')
    require(isinstance(reseat, list) and len(reseat) <= 256 and all((isinstance(pair, list) and len(pair) == 2 and all((type(entry) is int for entry in pair)) and (0 <= pair[0] < preimage_length) and (0 <= pair[1] < image_length) and (pair[0] != pair[1]) for pair in reseat)) and ([pair[0] for pair in reseat] == sorted({pair[0] for pair in reseat})) and (len({pair[1] for pair in reseat}) == len(reseat)), f'{context}.expected_relocation_reseat is invalid')
    fields = value.get('expected_rewritten_field_offsets')
    require(isinstance(fields, list) and fields and (fields == sorted(set(fields))) and all((type(entry) is int and any((item['start'] <= entry < item['end'] for item in normalized)) for entry in fields)), f'{context}.expected_rewritten_field_offsets is invalid')
    counts = value.get('expected_region_instruction_counts')
    total = require_exact_int(value.get('expected_instruction_count'), f'{context}.expected_instruction_count', minimum=2)
    require(isinstance(counts, list) and len(counts) == len(normalized) and all((type(entry) is int and entry >= 1 for entry in counts)) and (sum(counts) <= total), f'{context}.expected_region_instruction_counts is invalid')
    require(require_exact_int(value.get('expected_image_code_length'), f'{context}.expected_image_code_length', minimum=1) <= image_length, f'{context}.expected_image_code_length exceeds the image')
    procedure = value.get('expected_procedure_range')
    require(isinstance(procedure, list) and len(procedure) == 3 and all((type(entry) is int for entry in procedure)) and (procedure[0] == image_length) and (0 <= procedure[1] <= procedure[2] < image_length), f'{context}.expected_procedure_range is invalid')
    carried = value.get('expected_carried_code_symbols')
    require(isinstance(carried, list) and len(carried) <= 64 and all((isinstance(row, list) and len(row) == 3 and isinstance(row[0], str) and row[0] and (type(row[1]) is int) and (type(row[2]) is int) and (0 <= row[1] < preimage_length) and (0 <= row[2] < image_length) for row in carried)), f'{context}.expected_carried_code_symbols is invalid')
    targets = value.get('expected_internal_relocation_targets')
    if targets is not None:
        require(isinstance(targets, list) and targets == sorted(set(targets)) and all((type(entry) is int and 0 <= entry < preimage_length for entry in targets)), f'{context}.expected_internal_relocation_targets is invalid')
    code_length = value.get('expected_code_length')
    if code_length is not None:
        require_exact_int(code_length, f'{context}.expected_code_length', minimum=1, maximum=preimage_length)
    normalized_value = {**value, 'regions': normalized, 'expected_fpo_record': dict(sorted(record.items()))}
    return normalized_value

def validate_register_bijection(value: object, context: str, body_length: int) -> dict:
    """Validate one register-bijection certificate declaration."""
    require(isinstance(value, dict), f'{context} must be an object')
    exact_audit_keys(value, {'kind', 'mapping', 'region_start', 'region_end', 'expected_region_instruction_count', 'expected_instruction_count', 'expected_rewritten_offsets', 'debug_s_register_map', 'expected_seed_debug_s_sha256', 'expected_image_debug_s_sha256', 'authenticity_rationale', 'expected_code_length', 'expected_internal_relocation_targets', 'expected_rewritten_offsets_restoring_seed'}, context, optional={'expected_code_length', 'expected_internal_relocation_targets', 'expected_rewritten_offsets_restoring_seed'})
    require(value.get('kind') == REGISTER_BIJECTION_KIND, f'{context}.kind differs')
    mapping = value.get('mapping')
    require(isinstance(mapping, dict) and 2 <= len(mapping) <= 8 and all((isinstance(key, str) and isinstance(item, str) and (key in _IA32_REGISTER_NUMBERS) and (item in _IA32_REGISTER_NUMBERS) for key, item in mapping.items())), f'{context}.mapping is invalid')
    require(set(mapping) == set(mapping.values()) and len(set(mapping.values())) == len(mapping) and all((key != item for key, item in mapping.items())), f'{context}.mapping is not a fixed-point-free bijection')
    require(not set(mapping) & _IA32_STRUCTURAL_REGISTERS, f'{context}.mapping touches ESP or EBP')
    start = require_exact_int(value.get('region_start'), f'{context}.region_start', minimum=1, maximum=body_length - 1)
    end = require_exact_int(value.get('region_end'), f'{context}.region_end', minimum=2, maximum=body_length - 1)
    require(start < end, f'{context}: region is empty')
    require(require_exact_int(value.get('expected_region_instruction_count'), f'{context}.expected_region_instruction_count', minimum=1) <= require_exact_int(value.get('expected_instruction_count'), f'{context}.expected_instruction_count', minimum=2), f"{context}: region instruction count exceeds the body's")
    offsets = value.get('expected_rewritten_offsets')
    require(isinstance(offsets, list) and offsets and (offsets == sorted(set(offsets))) and all((type(offset) is int and start <= offset < end for offset in offsets)), f'{context}.expected_rewritten_offsets is invalid')
    declared = value.get('debug_s_register_map')
    require(isinstance(declared, list) and len(declared) <= 8, f'{context}.debug_s_register_map is invalid')
    normalized_map = []
    for index, item in enumerate(declared):
        item_context = f'{context}.debug_s_register_map[{index}]'
        require(isinstance(item, dict), f'{item_context} must be an object')
        exact_audit_keys(item, {'name', 'record_offset', 'donor_register', 'image_register'}, item_context)
        require(isinstance(item.get('name'), str) and item['name'], f'{item_context}.name is invalid')
        require(item.get('donor_register') in mapping and mapping[item['donor_register']] == item.get('image_register'), f'{item_context} is not the declared mapping')
        normalized_map.append({'name': item['name'], 'record_offset': require_exact_int(item.get('record_offset'), f'{item_context}.record_offset', minimum=0), 'donor_register': item['donor_register'], 'image_register': item['image_register']})
    rationale = value.get('authenticity_rationale')
    require(isinstance(rationale, str) and len(rationale) >= 40, f'{context}.authenticity_rationale is missing')
    code_length = value.get('expected_code_length')
    if code_length is not None:
        code_length = require_exact_int(code_length, f'{context}.expected_code_length', minimum=2, maximum=body_length)
        require(end <= code_length, f'{context}: region reaches past the declared code length')
    restoring = value.get('expected_rewritten_offsets_restoring_seed')
    if restoring is not None:
        require(isinstance(restoring, list) and restoring == sorted(set(restoring)) and (set(restoring) <= set(offsets)), f'{context}.expected_rewritten_offsets_restoring_seed is invalid')
    targets = value.get('expected_internal_relocation_targets')
    if targets is not None:
        require(isinstance(targets, list) and targets == sorted(set(targets)) and all((type(item) is int and 0 <= item < body_length for item in targets)), f'{context}.expected_internal_relocation_targets is invalid')
        require(not any((start < item < end for item in targets)), f'{context}: a relocated in-body target enters the region')
    normalized = {'kind': REGISTER_BIJECTION_KIND, 'mapping': dict(sorted(mapping.items())), 'region_start': start, 'region_end': end, 'expected_region_instruction_count': value['expected_region_instruction_count'], 'expected_instruction_count': value['expected_instruction_count'], 'expected_rewritten_offsets': list(offsets), 'debug_s_register_map': normalized_map, 'expected_seed_debug_s_sha256': require_sha(value.get('expected_seed_debug_s_sha256'), f'{context}.expected_seed_debug_s_sha256'), 'expected_image_debug_s_sha256': require_sha(value.get('expected_image_debug_s_sha256'), f'{context}.expected_image_debug_s_sha256'), 'authenticity_rationale': rationale}
    if code_length is not None:
        normalized['expected_code_length'] = code_length
    if targets is not None:
        normalized['expected_internal_relocation_targets'] = list(targets)
    if restoring is not None:
        normalized['expected_rewritten_offsets_restoring_seed'] = list(restoring)
    return normalized

def produce_register_bijection_candidate(seed_bytes: bytes, donor_bytes: bytes, function: dict) -> tuple[bytes, dict]:
    """Produce sigma(donor body) from a fresh compiler artifact.

    See the class comment above: this is a certificate.  The donor is an
    ordinary, census-pinned carrier compile of the same translation unit; the
    bijection is proved sound against the body's own control flow; and the
    result is constrained by declarative relocation semantics.  Body
    installation itself is delegated, unchanged, to the
    equal-body primitive, so output conservation is proved by the same code
    every other equal-body class uses.
    """
    require_payload_free_declaration(function, 'register-bijection declaration')
    require(function.get('splice_class') == REGISTER_BIJECTION_CLASS, 'splice class is not retail_exact_register_bijection')
    require('target_source_refactor' not in function, 'register-bijection functions carry no source refactor')
    spec = function['register_bijection']
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function['mangled']
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    donor_seat = function.get('expected_donor_section_number')
    if donor_seat is None:
        require(sp['number'] == dp['number'] == function['expected_section_number'], 'register-bijection target section seat changed')
    else:
        require(sp['number'] == function['expected_section_number'] and dp['number'] == donor_seat, 'register-bijection target section seat changed')
    require(len(seed.sections) == len(donor.sections) == function['expected_section_count'], 'register-bijection global section count changed')
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    require(seed_functions == donor_functions and sum(seed_functions.values()) == function['expected_function_count'], 'register-bijection donor function set differs')
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    require(seed_comdats == donor_comdats and sum(seed_comdats.values()) == function['expected_comdat_count'], 'register-bijection donor COMDAT identity set differs')
    require(sp['raw_size'] == dp['raw_size'] == function['expected_body_length'] and sp['relocation_count'] == dp['relocation_count'] == function['expected_relocation_count'] and (sp['line_count'] == function['expected_seed_line_count']) and (dp['line_count'] == function['expected_donor_line_count']) and (sp['name'] == dp['name']) and (sp['characteristics'] == dp['characteristics'] == function['expected_characteristics']), 'register-bijection target header/count pins changed')
    require(section_definitions(seed)[sp['number']]['selection'] == section_definitions(donor)[dp['number']]['selection'] == function['expected_selection'], 'register-bijection COMDAT selection changed')
    expected_closure = tuple(function['expected_closure'])
    require(_comdat_child_closure(seed, sp) == _comdat_child_closure(donor, dp) == (len(expected_closure), expected_closure), 'register-bijection target closure changed')
    require(list(expected_closure) in (REGISTER_BIJECTION_FPO_CLOSURE, REGISTER_BIJECTION_EH_CLOSURE), 'register-bijection closure pin names no installation delegate')
    delegate = register_bijection_delegate(function['expected_closure'], function['expected_code_renames'], function.get('expected_relocation_moves'))
    require(instruction_mosaic_metadata_sha256(seed, sp) == function['expected_seed_metadata_sha256'] and instruction_mosaic_metadata_sha256(donor, dp) == function['expected_donor_metadata_sha256'], 'register-bijection metadata differs from its pin')
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(sha256_bytes(seed_body) == function['expected_seed_body_sha256'] and sha256_bytes(donor_body) == function['expected_donor_body_sha256'], 'register-bijection seed/donor body differs from its pin')
    seed_rows = detailed_relocations(seed, sp)
    donor_rows = detailed_relocations(donor, dp)
    if register_bijection_delegate(function['expected_closure'], function['expected_code_renames'], function.get('expected_relocation_moves')) == 'equal_body_eh_reloc_layout':
        require(len(seed_rows) == len(donor_rows), 'register-bijection donor relocation count differs')
        code_renames = []
        for left, right in zip(seed_rows, donor_rows):
            if left['target'] == right['target']:
                continue
            kind = local_symbol_kind(left['target'])
            require(kind is not None and kind == local_symbol_kind(right['target']) and all((left['target_' + field] == right['target_' + field] for field in ('section', 'value', 'type', 'storage'))), 'register-bijection donor renames a non-local relocation')
            code_renames.append((right['offset'], kind))
    else:
        code_renames = require_instruction_mosaic_semantic_relocations(seed, sp, donor, dp, 'register-bijection code')
    require([[offset, kind] for offset, kind in code_renames] == function['expected_code_renames'], 'register-bijection code rename set changed')
    seed_targets = {right['offset']: left['target'] for left, right in zip(seed_rows, donor_rows)}
    donor_targets = {row['offset']: row['target'] for row in donor_rows}
    require([[offset, seed_targets.get(offset), donor_targets.get(offset)] for offset, _ in code_renames] == function.get('expected_code_rename_symbols', []), 'register-bijection code rename symbol pair changed')
    require(len(seed_rows) == len(donor_rows) and [(row['type'], row['addend']) for row in seed_rows] == [(row['type'], row['addend']) for row in donor_rows], 'register-bijection donor relocation layout differs from the seed')
    moves = [[left['offset'], right['offset']] for left, right in zip(seed_rows, donor_rows) if left['offset'] != right['offset']]
    require(moves == (function.get('expected_relocation_moves') or []), 'register-bijection relocation move set changed')
    require([row['target'] for row in seed_rows if row['type'] == 20] == [row['target'] for row in donor_rows if row['type'] == 20], 'register-bijection donor call/branch relocation targets differ from the seed')
    installed_rows = [{**left, 'offset': right['offset']} for left, right in zip(seed_rows, donor_rows)]
    relocation_offsets = frozenset((row['offset'] + byte for row in installed_rows for byte in range(row['width'])))
    relocation_symbols = {row['offset']: {'width': row['width'], 'target': row['target']} for row in installed_rows}
    internal_targets = frozenset((row['target_value'] for row in donor_rows if row['target_section'] == dp['number']))
    declared_targets = spec.get('expected_internal_relocation_targets')
    if declared_targets is not None:
        require(sorted(internal_targets) == declared_targets, 'register-bijection in-body relocated target set changed')
    image, proof = apply_register_bijection(donor_body, spec['mapping'], (spec['region_start'], spec['region_end']), relocation_offsets, 'register-bijection image', relocation_symbols, spec.get('expected_code_length'), internal_targets)
    require(proof['code_length'] == (spec.get('expected_code_length') or len(donor_body)), 'register-bijection code length differs from its pin')
    require(proof['rewritten_offsets'] == spec['expected_rewritten_offsets'] and proof['region_instruction_count'] == spec['expected_region_instruction_count'] and (proof['instruction_count'] == spec['expected_instruction_count']), 'register-bijection image differs from its declaration')
    require(donor_body[:spec['region_start']] == image[:spec['region_start']] and donor_body[spec['region_end']:] == image[spec['region_end']:], 'register-bijection changed the prologue or epilogue')
    require(sorted((offset for offset in proof['rewritten_offsets'] if seed_body[offset] == image[offset])) == (spec.get('expected_rewritten_offsets_restoring_seed') or []), 'register-bijection seed-restoring rewrite set changed')
    require(sha256_bytes(image) == function['expected_body_sha256'], 'register-bijection image differs from its pin')
    require(image != donor_body, 'register-bijection image does not move the donor body')
    pinned_length = function['retail_oracle']['length']
    require(pinned_length == len(image), 'register-bijection linked length changed')
    semantic_detail = require_declared_relocation_semantics(
        installed_rows,
        function['retail_relocations'],
        'register-bijection candidate relocation semantics',
    )
    derived = bytearray(donor_bytes)
    derived[dp['raw_offset']:dp['raw_offset'] + dp['raw_size']] = image
    derived = bytes(derived)
    effective = {'mangled': mangled, 'splice_class': delegate, 'expected_body_length': function['expected_body_length'], 'expected_body_sha256': function['expected_body_sha256'], 'expected_changed_offsets': function['expected_changed_offsets']}
    if delegate == 'equal_body_eh_structural_local':
        effective['expected_code_renames'] = function['expected_code_renames']
        effective['expected_xdata_rename_offsets'] = function['expected_xdata_rename_offsets']
    elif delegate == 'equal_body_eh_reloc_layout':
        effective['expected_relocation_moves'] = function['expected_relocation_moves']
        effective['expected_xdata_rename_offsets'] = function['expected_xdata_rename_offsets']
    composed, detail = compose_equal_body_comdat(seed_bytes, derived, effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, 'register-bijection composed body differs from the image')
    composed_rows = detailed_relocations(checked, cp)
    require(composed_rows == installed_rows and [row['symbol_index'] for row in composed_rows] == [row['symbol_index'] for row in seed_rows] and (_coff_table_bytes(checked, cp, 'lines') == _coff_table_bytes(seed, sp, 'lines')), 'register-bijection output changed seed relocation/line bytes')
    debug_child = _comdat_child(checked, cp, '.debug$S')
    debug_stream = coff_body(checked, debug_child)
    require(sha256_bytes(debug_stream) == spec['expected_seed_debug_s_sha256'], 'register-bijection debug$S differs from its pin')
    donor_debug = None
    if delegate == 'equal_body_eh_reloc_layout':
        donor_debug = bytes(coff_body(donor, _comdat_child(donor, dp, '.debug$S')))
    debug_image = apply_codeview_register_bijection(debug_stream, spec['mapping'], spec['debug_s_register_map'], 'register-bijection debug$S', donor_debug)
    require(sha256_bytes(debug_image) == spec['expected_image_debug_s_sha256'], 'register-bijection mapped debug$S differs from its pin')
    composed = bytearray(composed)
    composed[debug_child['raw_offset']:debug_child['raw_offset'] + debug_child['raw_size']] = debug_image
    composed = bytes(composed)
    final = CoffObject(composed)
    fp = final.function_section(mangled)
    require(coff_body(final, fp) == image, 'register-bijection output changed the installed body')
    for child_name in expected_closure:
        if child_name == '.debug$S':
            continue
        require(coff_body(final, _comdat_child(final, fp, child_name)) == coff_body(seed, _comdat_child(seed, sp, child_name)), f'register-bijection output changed its {child_name} child')
    allowed = set(range(sp['raw_offset'], sp['raw_offset'] + sp['raw_size']))
    allowed |= set(range(debug_child['raw_offset'], debug_child['raw_offset'] + debug_child['raw_size']))
    if delegate == 'equal_body_eh_reloc_layout':
        moving = [ordinal for ordinal, (left, right) in enumerate(zip(seed_rows, donor_rows)) if left['offset'] != right['offset']]
        allowed |= {sp['relocation_offset'] + ordinal * 10 + byte for ordinal in moving for byte in range(4)}
    require({index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]} <= allowed, 'register-bijection changed bytes outside its own COMDAT')
    return (composed, {**detail, 'splice_class': REGISTER_BIJECTION_CLASS, 'register_bijection': dict(sorted(spec['mapping'].items())), 'region': [spec['region_start'], spec['region_end']], 'rewritten_offsets': proof['rewritten_offsets'], 'region_instruction_count': proof['region_instruction_count'], 'instruction_count': proof['instruction_count'], 'debug_s_register_map': spec['debug_s_register_map'], 'candidate_only': True, **semantic_detail})
REGISTER_BIJECTION_REENCODING_CLASS = 'retail_exact_register_bijection_reencoding'
REGISTER_BIJECTION_REENCODING_KIND = 'frame_pointer_free_register_bijection_v1'
FPO_FRAME_KIND_FPO = 0

def require_no_ebp_frame_derivation(body: bytes, instructions, context: str) -> None:
    """Prove that decoded instructions never establish EBP from ESP."""
    for item in instructions:
        if 'ebp' not in item['writes']:
            continue
        encoding = item['encoding']
        direct = set()
        for byte_index, shift in item['fields']:
            name = IA32_GENERAL_REGISTER_NAMES[body[byte_index] >> shift & 7]
            if encoding is None:
                direct.add(name)
                continue
            memory_base = byte_index == (encoding['sib_at'] if encoding['sib_at'] is not None else encoding['modrm_at']) and shift == 0 and (encoding['mode'] != 3)
            memory_index = encoding['sib_at'] is not None and byte_index == encoding['sib_at'] and (shift == 3) and (encoding['mode'] != 3)
            if memory_base or memory_index:
                if item['opcode'] == 141:
                    direct.add(name)
                continue
            direct.add(name)
        require('esp' not in direct, f"{context}: the instruction at {item['offset']} derives EBP from ESP, which establishes a frame pointer")

def require_frame_pointer_free_frame(coff: 'CoffObject', section: dict, body: bytes, instructions: list[dict], context: str) -> dict:
    """Obligation 11: prove EBP is not this body's frame pointer.

    Two independent facts are required, and BOTH come from the object itself:
    the compiler's own FPO record for this COMDAT declares FRAME_FPO with no
    structured exception handling, and no instruction in the decoded body
    derives EBP from ESP.  The first is the compiler's statement that the
    function has no EBP frame; the second is a structural check on the code
    that no `mov ebp, esp` / `lea ebp, [esp+d]` establishes one anyway.
    """
    closure = _comdat_child_closure(coff, section)
    require(closure == (2, ('.debug$F', '.debug$S')), f'{context}: a frame-pointer-free proof needs the FPO closure')
    record = parse_fpo_data(bytes(coff_body(coff, _comdat_child(coff, section, '.debug$F'))), expected_proc_size=section['raw_size'])
    require(record['cbFrame'] == FPO_FRAME_KIND_FPO, f"{context}: the FPO record does not declare FRAME_FPO, so EBP may be this body's frame pointer")
    require(record['fHasSEH'] == 0, f'{context}: the FPO record declares structured exception handling, whose unwind may read EBP')
    require_no_ebp_frame_derivation(body, instructions, context)
    return record

def _reencoding_region_for(regions: list[dict], offset: int) -> dict | None:
    """The declared region covering one instruction, or None."""
    for region in regions:
        if region['start'] <= offset < region['end']:
            return region
    return None

def _reencoded_instruction(body: bytes, item: dict, mapping: dict, numbers: dict, relocation_offsets: frozenset, context: str) -> tuple[bytes, str, list[int]]:
    """Rewrite ONE instruction's register fields, re-encoding if EBP forces it.

    Obligation 12.  Returns the new encoding, the class of change and the
    pre-image byte offsets whose value the rewrite changed:
    `"field"` when only register fields moved, `"reencode"` when the ModRM
    `mod` field additionally had to change because the memory BASE crossed
    EBP.  The re-encoding is derived from the decoder's own layout
    description, never by re-disassembling this function's own output.
    """
    start, length = (item['offset'], item['length'])
    raw = bytearray(body[start:start + length])
    encoding = item['encoding']
    base_field = None
    if encoding is not None and encoding['mode'] != 3 and (not encoding['absolute']):
        base_field = encoding['sib_at'] if encoding['sib_at'] is not None else encoding['modrm_at']
    base_before = None
    base_after = None
    touched = []
    for byte_index, shift in item['fields']:
        value = raw[byte_index - start] >> shift & 7
        if byte_index == base_field and shift == 0:
            base_before = value
        if value not in numbers:
            if byte_index == base_field and shift == 0:
                base_after = value
            continue
        require(byte_index not in relocation_offsets, f'{context}: a rewritten byte at {byte_index} overlaps a relocation')
        raw[byte_index - start] = (raw[byte_index - start] & ~(7 << shift) | numbers[value] << shift) & 255
        if raw[byte_index - start] != body[byte_index]:
            touched.append(byte_index)
        if byte_index == base_field and shift == 0:
            base_after = numbers[value]
    touched = sorted(set(touched))
    if base_field is None or base_before is None or base_before == base_after:
        return (bytes(raw), 'field', touched)
    ebp = _IA32_REGISTER_NUMBERS['ebp']
    modrm_local = encoding['modrm_at'] - start
    mode = encoding['mode']
    if base_after == ebp:
        require(mode in (0, 1, 2), f'{context}: unexpected ModRM mode at {start}')
        if mode != 0:
            return (bytes(raw), 'field', touched)
        insert_at = encoding['sib_at'] - start + 1 if encoding['sib_at'] is not None else modrm_local + 1
        require(encoding['displacement_size'] == 0, f'{context}: a mod-00 operand at {start} already carries a displacement')
        raw[modrm_local] = raw[modrm_local] & 63 | 64
        raw = raw[:insert_at] + bytearray(b'\x00') + raw[insert_at:]
        return (bytes(raw), 'reencode', touched)
    if base_before == ebp:
        if mode != 1:
            return (bytes(raw), 'field', touched)
        require(encoding['displacement_size'] == 1 and encoding['displacement_at'] is not None, f'{context}: a mod-01 operand at {start} has no disp8')
        displacement_local = encoding['displacement_at'] - start
        if raw[displacement_local] != 0:
            return (bytes(raw), 'field', touched)
        raw[modrm_local] = raw[modrm_local] & 63
        del raw[displacement_local]
        return (bytes(raw), 'reencode', touched)
    return (bytes(raw), 'field', touched)
IA32_REPAIRABLE_BRANCH_WIDTHS = (1, 4)
REGISTER_BIJECTION_REENCODING_FIXPOINT_ROUNDS = 64

def apply_slot_bijection(body: bytes, mapping: dict, relocation_offsets: frozenset, context: str, relocations: dict | None=None, code_length: int | None=None) -> tuple[bytes, dict]:
    """Exchange two (or more) EBP frame slots' displacements body-wide.

    Renaming same-width private stack slots consistently everywhere is an
    isomorphism of the machine function: every read, write and address
    formation moves with its slot, so no execution can tell the difference.
    The soundness rests on TOTALITY and NON-OVERLAP, and both are checked
    here: every instruction whose EBP-based operand touches a mapped slot
    must reference it exactly (same displacement, dword width or an address
    formation), any partial overlap refuses, any ESP-based operand in the
    body refuses (it could alias a mapped slot at a distance this check
    cannot bound), and a displacement byte under a relocation refuses.
    Length preservation is structural: only displacement BYTES change, and
    each rewritten value must fit the encoded displacement size.
    """
    require_payload_free_declaration(list(mapping.items()) if isinstance(mapping, dict) else mapping, f'{context} slot mapping')
    require(isinstance(mapping, dict) and len(mapping) >= 2, f'{context}: the slot mapping is empty')
    slots = {int(key): int(value) for key, value in mapping.items()}
    require(set(slots) == set(slots.values()) and len(set(slots.values())) == len(slots) and all((key != value for key, value in slots.items())), f'{context}: the slot mapping is not a fixed-point-free bijection')
    require(all((key < 0 and value < 0 for key, value in slots.items())), f'{context}: the slot mapping leaves the local frame')
    ordered = sorted(slots)
    for left, right in zip(ordered, ordered[1:]):
        require(right - left >= 4, f'{context}: mapped slots overlap')
    instructions = decode_ia32_bijection_body(body, context, relocations, code_length)
    image = bytearray(body)
    rewritten = []
    for item in instructions:
        memory = item.get('memory')
        if not memory or memory.get('absolute'):
            continue
        base = memory.get('base')
        require(base != 'esp', f"{context}: an ESP-based operand at {item['offset']} could alias a mapped slot")
        if base != 'ebp':
            continue
        displacement = memory.get('displacement')
        width = memory.get('width') or 4
        if displacement in slots:
            is_lea = item['opcode'] == 141
            require(is_lea or width == 4, f"{context}: the access at {item['offset']} reads a mapped slot at a different width")
            encoding = item.get('encoding') or {}
            at = encoding.get('displacement_at')
            size = encoding.get('displacement_size')
            require(at is not None and size in (1, 4), f"{context}: the instruction at {item['offset']} has no rewritable displacement field")
            require(not any((at + k in relocation_offsets for k in range(size))), f"{context}: the displacement at {item['offset']} is relocated")
            value = slots[displacement]
            limit = 1 << 8 * size - 1
            require(-limit <= value < limit, f"{context}: the exchanged displacement at {item['offset']} does not fit its field")
            image[at:at + size] = value.to_bytes(size, 'little', signed=True)
            rewritten.extend(range(at, at + size))
        else:
            for slot in slots:
                require(displacement + width <= slot or slot + 4 <= displacement, f"{context}: the access at {item['offset']} partially overlaps a mapped slot")
    require(rewritten, f'{context}: the slot bijection rewrites nothing')
    reencoded = decode_ia32_bijection_body(bytes(image), f'{context} image', relocations, code_length)
    require(len(reencoded) == len(instructions) and all((left['offset'] == right['offset'] and left['length'] == right['length'] for left, right in zip(instructions, reencoded))), f'{context}: the exchange changed the instruction grid')
    changed = [offset for offset in rewritten if image[offset] != body[offset]]
    return (bytes(image), {'rewritten_offsets': sorted(changed)})

def apply_register_bijection_reencoding(body: bytes, regions: list[dict], relocation_offsets: frozenset, context: str, relocations: dict | None=None, code_length: int | None=None, internal_targets: frozenset | None=None, frame_pointer_free: bool=False) -> tuple[bytes, dict]:
    """Rewrite several regions under proved bijections, re-encoding for EBP.

    This is `apply_register_bijection` generalised on two axes: sigma may name
    EBP when the caller has discharged obligation 11, and an instruction may
    change length when -- and only when -- the ModRM `mod` field forces it.
    Every obligation of the parent still holds, and obligations 12 to 14 are
    checked here.  The result is re-decoded to exhaustion so that every claim
    about the image is measured ON the image.
    """
    require_payload_free_declaration(regions, f'{context} register re-encoding declaration')
    body = bytes(body)
    instructions = decode_ia32_bijection_body(body, context, relocations, code_length)
    limit = len(body) if code_length is None else code_length
    boundaries = {item['offset'] for item in instructions}
    boundaries.add(limit)
    index_of = {item['offset']: index for index, item in enumerate(instructions)}
    require(regions, f'{context}: no region is declared')
    previous_end = 0
    for position, region in enumerate(regions):
        region_context = f'{context} region {position}'
        start, end = (region['start'], region['end'])
        require(start >= previous_end and start < end, f'{region_context}: regions are unsorted, empty or overlapping')
        previous_end = end
        require(end <= limit, f"{region_context}: region reaches past the body's code")
        require(start in boundaries and end in boundaries, f'{region_context}: region does not span whole instructions')
        mapping = region['mapping']
        require(set(mapping.values()) == set(mapping) and all((source != destination for source, destination in mapping.items())), f'{region_context}: mapping is not a bijection of one register set')
        for name in set(mapping) | set(mapping.values()):
            require(name in _IA32_REGISTER_NUMBERS, f'{region_context}: mapping names an unknown register')
        support = set(mapping) | set(mapping.values())
        require('esp' not in support, f'{region_context}: ESP cannot be a ModRM base or a SIB index, so a rename to or from it is not an encoding change')
        require(frame_pointer_free or 'ebp' not in support, f'{region_context}: EBP is refused without a frame-pointer-free proof for this body')
    if any((item['indirect'] for item in instructions)):
        require(internal_targets is not None, f'{context}: a computed jump requires the relocated in-body target set')
        for position, region in enumerate(regions):
            entered = sorted((target for target in internal_targets if region['start'] < target < region['end']))
            require(not entered, f'{context} region {position}: a relocated in-body target at {entered[:1]} enters the region other than at its first instruction')
    live, successors = _register_bijection_live_sets(instructions, context)
    for position, region in enumerate(regions):
        region_context = f'{context} region {position}'
        start, end = (region['start'], region['end'])
        mapping = region['mapping']
        support = set(mapping) | set(mapping.values())
        inside = [item for item in instructions if start <= item['offset'] < end]
        require(inside, f'{region_context}: region contains no instruction')
        require(inside[-1]['offset'] + inside[-1]['length'] == end, f'{region_context}: region does not end on an instruction boundary')
        entry = index_of[inside[0]['offset']]
        for item in inside:
            blocked = support & set(item.get('frozen', frozenset()))
            require(not blocked, f"{region_context}: {sorted(blocked)} is named by a sub-register field at {item['offset']} that sigma cannot rewrite")
        for index, item in enumerate(instructions):
            for edge in successors[index]:
                if not start <= item['offset'] < end and start <= instructions[edge]['offset'] < end:
                    require(edge == entry, f'{region_context}: control enters the region other than at its first instruction')
        support_atoms = ia32_register_atoms(support)
        dead_in = support_atoms & set(live[entry])
        require(not dead_in, f'{region_context}: {_ia32_atom_registers(dead_in)} is live on entry to the region')
        for index, item in enumerate(instructions):
            if not start <= item['offset'] < end:
                continue
            for edge in successors[index]:
                if start <= instructions[edge]['offset'] < end:
                    continue
                leaking = support_atoms & set(live[edge])
                require(not leaking, f"{region_context}: {_ia32_atom_registers(leaking)} is live on an edge leaving the region at {item['offset']}")
            if item['flow'] in ('ret', 'exit'):
                leaking = support_atoms & set(item['read_atoms'])
                require(not leaking, f"{region_context}: {_ia32_atom_registers(leaking)} is live at the region's return")
    pieces = []
    classes = []
    rewritten_fields = []
    for item in instructions:
        region = _reencoding_region_for(regions, item['offset'])
        if region is None:
            pieces.append(body[item['offset']:item['offset'] + item['length']])
            classes.append('unchanged')
            continue
        numbers = {_IA32_REGISTER_NUMBERS[source]: _IA32_REGISTER_NUMBERS[destination] for source, destination in region['mapping'].items()}
        raw, kind, touched = _reencoded_instruction(body, item, region['mapping'], numbers, relocation_offsets, context)
        rewritten_fields.extend(touched)
        require(len(raw) - item['length'] in (-1, 0, 1), f"{context}: the re-encoding at {item['offset']} changed the length by more than the one byte a mod field forces")
        require(kind == 'reencode' or len(raw) == item['length'], f"{context}: the instruction at {item['offset']} changed length without a mod re-encoding")
        pieces.append(raw)
        classes.append(kind)
    tail = body[limit:]

    def _starts(current: list[bytes]) -> list[int]:
        cursor, out = (0, [])
        for raw in current:
            out.append(cursor)
            cursor += len(raw)
        return out
    repaired = set()
    for _round in range(REGISTER_BIJECTION_REENCODING_FIXPOINT_ROUNDS):
        starts = _starts(pieces)
        changed = False
        for index, item in enumerate(instructions):
            if item['flow'] not in ('jcc', 'jmp') or item['target'] is None:
                continue
            raw = bytearray(pieces[index])
            width = _reencoding_branch_width(item, raw, context)
            destination = starts[index_of[item['target']]]
            delta = destination - (starts[index] + len(raw))
            require(-(1 << 8 * width - 1) <= delta < 1 << 8 * width - 1, f"{context}: the branch at {item['offset']} no longer reaches its target in {width} displacement byte(s); widening it would be a code change, not a renaming")
            encoded = delta.to_bytes(width, 'little', signed=True)
            if bytes(raw[len(raw) - width:]) != encoded:
                raw[len(raw) - width:] = encoded
                pieces[index] = bytes(raw)
                repaired.add(item['offset'])
                changed = True
        if not changed:
            break
    else:
        raise ByteIdentityError(f'{context}: the branch-displacement fixpoint did not converge')
    starts = _starts(pieces)
    image = b''.join(pieces) + tail
    offset_map = {item['offset']: starts[index] for index, item in enumerate(instructions)}
    image_limit = starts[-1] + len(pieces[-1]) if pieces else 0
    offset_map[limit] = image_limit
    require(len(image) == image_limit + len(tail), f'{context}: the image is not the concatenation of its pieces')
    for index, item in enumerate(instructions):
        original = body[item['offset']:item['offset'] + item['length']]
        if pieces[index] == original:
            continue
        require(classes[index] in ('field', 'reencode') or item['offset'] in repaired, f"{context}: the instruction at {item['offset']} changed outside a declared region and is not a branch repair")
    reseat = []
    for offset in sorted(relocations or {}):
        record = (relocations or {})[offset]
        width = record['width']
        owner = None
        for index, item in enumerate(instructions):
            if item['offset'] <= offset and offset + width <= item['offset'] + item['length']:
                owner = index
                break
        require(owner is not None, f'{context}: the relocation at {offset} does not lie wholly inside one decoded instruction')
        item = instructions[owner]
        growth = len(pieces[owner]) - item['length']
        from_end = item['offset'] + item['length'] - offset
        new_offset = starts[owner] + len(pieces[owner]) - from_end
        if growth:
            encoding = item['encoding']
            require(encoding is not None, f"{context}: a re-encoded instruction at {item['offset']} has no ModRM layout")
            fixed_end = (encoding['sib_at'] if encoding['sib_at'] is not None else encoding['modrm_at']) + 1
            require(offset >= fixed_end, f'{context}: the relocation at {offset} overlaps the ModRM/SIB bytes the re-encoding changed')
            require(new_offset == offset + (starts[owner] - item['offset']) + growth, f'{context}: the reseat of {offset} is inconsistent')
        require(starts[owner] <= new_offset and new_offset + width <= starts[owner] + len(pieces[owner]), f'{context}: the reseat of {offset} leaves its instruction')
        reseat.append([offset, new_offset])
    require(len({pair[1] for pair in reseat}) == len(reseat), f'{context}: the reseat collides two relocation records')
    image_relocations = None
    if relocations is not None:
        moved = dict(reseat)
        image_relocations = {moved[offset]: record for offset, record in relocations.items()}
    image_internal = None
    if internal_targets is not None:
        for target in internal_targets:
            require(target in offset_map, f'{context}: a relocated in-body target at {target} is not an instruction boundary')
        image_internal = frozenset((offset_map[target] for target in internal_targets))
    image_instructions = decode_ia32_bijection_body(image, f'{context} image', image_relocations, None if code_length is None else image_limit)
    require(len(image_instructions) == len(instructions), f'{context}: the image has a different instruction count')
    for left, right, raw in zip(image_instructions, instructions, pieces):
        require(left['offset'] == offset_map[right['offset']] and left['length'] == len(raw), f"{context}: the image's instruction at {right['offset']} did not land where the layout says")
        form = _bijection_form_for(right['opcode'])
        opreg = form is not None and form['opreg'] is not None
        mask = 248 if opreg else 65535
        require(left['opcode'] & mask == right['opcode'] & mask and left['flow'] == right['flow'], f"{context}: the image changed an opcode or a control flow at {right['offset']}")
        require(left['target'] == (None if right['target'] is None else offset_map[right['target']]), f"{context}: the image changed a branch target at {right['offset']}")
        region = _reencoding_region_for(regions, right['offset'])
        mapping = {} if region is None else region['mapping']
        require(left['reads'] == frozenset((mapping.get(name, name) for name in right['reads'])) and left['writes'] == frozenset((mapping.get(name, name) for name in right['writes'])), f"{context}: the image's operand set at {right['offset']} is not the bijection's image")
    require(image[image_limit:] == tail, f"{context}: the image changed the body's data tail")
    growth_detail = [[item['offset'], starts[index], item['length'], len(pieces[index])] for index, item in enumerate(instructions) if len(pieces[index]) != item['length']]
    rewritten = sorted(set(rewritten_fields))
    require(rewritten, f'{context}: the bijection rewrites no register field')
    require(image != body or growth_detail, f'{context}: the bijection moves nothing')
    return (image, {'offset_map': {str(key): value for key, value in sorted(offset_map.items())}, 'growth': growth_detail, 'branch_repairs': sorted((offset_map[offset] for offset in repaired)), 'relocation_reseat': [pair for pair in reseat if pair[0] != pair[1]], 'region_instruction_counts': [sum((1 for item in instructions if region['start'] <= item['offset'] < region['end'])) for region in regions], 'rewritten_field_offsets': rewritten, 'instruction_count': len(instructions), 'code_length': limit, 'image_code_length': image_limit})

def _reencoding_branch_width(item: dict, raw: bytes, context: str) -> int:
    """The displacement width of one repairable relative branch.

    Read off the module's own closed form table, never guessed, and refused
    for any encoding whose displacement this class will not repair.
    """
    form = _bijection_form_for(item['opcode'])
    require(form is not None and form['displacement'] in IA32_REPAIRABLE_BRANCH_WIDTHS, f"{context}: the branch at {item['offset']} has no repairable displacement field")
    require(len(raw) == item['length'], f"{context}: the branch at {item['offset']} changed its own encoding length")
    return form['displacement']

def _reencoded_donor_object(donor_bytes: bytes, mangled: str, image: bytes, proof: dict, context: str, fpo_required: bool=True) -> bytes:
    """Re-seat one COMDAT's dependent COFF records around a resized body.

    Obligations 14 to 16.  The donor is an authentic compiler object; this
    produces the same object with the proved image in place of the target
    body and every record that states a code offset carried through the
    bijection's own boundary map.  Nothing outside the target COMDAT's own
    data, tables and closure children is touched, and the result is re-parsed
    and re-checked before it is handed to the installation primitive.
    """
    donor = CoffObject(donor_bytes)
    primary = donor.function_section(mangled)
    offset_map = {int(key): value for key, value in proof['offset_map'].items()}
    body_length = len(image)
    require(offset_map[primary['raw_size']] == body_length if primary['raw_size'] in offset_map else True, f'{context}: the boundary map does not end at the image length')
    line_bytes = _coff_table_bytes(donor, primary, 'lines')
    require(len(line_bytes) == primary['line_count'] * 6 and primary['line_count'] >= 1, f'{context}: the donor line table is missing')
    rebuilt_lines = bytearray(line_bytes[:6])
    require(coff_unpack('<IH', line_bytes, 0, f'{context} line sentinel')[1] == 0, f'{context}: the donor line sentinel is invalid')
    for position in range(1, primary['line_count']):
        offset, line = coff_unpack('<IH', line_bytes, position * 6, f'{context} line row {position}')
        require(line != 0, f'{context}: line row {position} has no line number')
        require(offset in offset_map, f'{context}: line row {position} at {offset} is not an instruction boundary of the pre-image')
        rebuilt_lines += offset_map[offset].to_bytes(4, 'little')
        rebuilt_lines += line.to_bytes(2, 'little')
    require(len(rebuilt_lines) == len(line_bytes), f'{context}: the rebuilt line table changed size')
    relocation_bytes = _coff_table_bytes(donor, primary, 'relocations')
    moved = dict(proof['relocation_reseat'])
    rebuilt_relocations = bytearray(relocation_bytes)
    for ordinal in range(primary['relocation_count']):
        at = ordinal * 10
        offset = int.from_bytes(relocation_bytes[at:at + 4], 'little')
        rebuilt_relocations[at:at + 4] = moved.get(offset, offset).to_bytes(4, 'little')
    require(len(rebuilt_relocations) == len(relocation_bytes), f'{context}: the rebuilt relocation table changed size')
    debug_child = _comdat_child(donor, primary, '.debug$S')
    debug_raw = bytes(coff_body(donor, debug_child))
    require(len(debug_raw) >= 28 and debug_raw[2:4] in (b'\x04\x02', b'\x05\x02'), f'{context}: the donor debug$S is not a procedure record')
    code_length, debug_start, debug_end = coff_unpack('<III', debug_raw, 16, f'{context} debug range')
    require(code_length == primary['raw_size'] and 0 <= debug_start <= debug_end < code_length, f'{context}: the donor debug procedure range is stale')
    require(debug_start in offset_map and debug_end in offset_map, f'{context}: the debug range is not on instruction boundaries')
    rebuilt_debug = bytearray(debug_raw)
    rebuilt_debug[16:28] = body_length.to_bytes(4, 'little') + offset_map[debug_start].to_bytes(4, 'little') + offset_map[debug_end].to_bytes(4, 'little')
    fpo_child = None
    if fpo_required:
        fpo_child = _comdat_child(donor, primary, '.debug$F')
    else:
        try:
            fpo_child = _comdat_child(donor, primary, '.debug$F')
        except ByteIdentityError:
            fpo_child = None
    if fpo_child is not None:
        fpo_raw = bytes(coff_body(donor, fpo_child))
        parse_fpo_data(fpo_raw, expected_proc_size=primary['raw_size'])
        rebuilt_fpo = bytearray(fpo_raw)
        rebuilt_fpo[4:8] = body_length.to_bytes(4, 'little')
        parse_fpo_data(bytes(rebuilt_fpo), expected_proc_size=body_length)
        require(rebuilt_fpo[:4] == fpo_raw[:4] and rebuilt_fpo[8:] == fpo_raw[8:], f'{context}: the rebuilt FPO record changed a field other than cbProcSize')
    replacements = [(primary['raw_offset'], primary['raw_offset'] + primary['raw_size'], bytes(image)), (primary['line_offset'], primary['line_offset'] + primary['line_count'] * 6, bytes(rebuilt_lines)), (primary['relocation_offset'], primary['relocation_offset'] + primary['relocation_count'] * 10, bytes(rebuilt_relocations)), (debug_child['raw_offset'], debug_child['raw_offset'] + debug_child['raw_size'], bytes(rebuilt_debug))]
    if fpo_child is not None:
        replacements.append((fpo_child['raw_offset'], fpo_child['raw_offset'] + fpo_child['raw_size'], bytes(rebuilt_fpo)))
        replacements.sort()
    output = bytearray(_apply_replacements(donor_bytes, replacements))

    def shifted(pointer: int) -> int:
        return shifted_pointer(pointer, replacements)
    new_symbol_offset = shifted(donor.symbol_offset)
    output[8:12] = new_symbol_offset.to_bytes(4, 'little')
    for section in donor.sections:
        header = 20 + (section['number'] - 1) * 40
        if section['number'] == primary['number']:
            output[header + 16:header + 20] = body_length.to_bytes(4, 'little')
        for field, relative in (('raw_offset', 20), ('relocation_offset', 24), ('line_offset', 28)):
            pointer = shifted(section[field])
            if pointer != section[field]:
                output[header + relative:header + relative + 4] = pointer.to_bytes(4, 'little')
    for symbol_index, item in donor.symbols.items():
        if item['type'] == 32 and item['aux_count'] >= 1:
            auxiliary = coff_auxiliary(donor, symbol_index, item)
            line_pointer = int.from_bytes(auxiliary[8:12], 'little')
            mapped = shifted(line_pointer) if line_pointer else line_pointer
            if mapped != line_pointer:
                at = new_symbol_offset + (symbol_index + 1) * 18
                output[at + 8:at + 12] = mapped.to_bytes(4, 'little')
    function_index, function_symbol_record = function_symbol(donor, mangled, primary['number'])
    function_aux = coff_auxiliary(donor, function_index, function_symbol_record)
    require(int.from_bytes(function_aux[4:8], 'little') == primary['raw_size'], f'{context}: the donor Function Definition TotalSize is stale')
    at = new_symbol_offset + (function_index + 1) * 18
    output[at + 4:at + 8] = body_length.to_bytes(4, 'little')
    section_index, section_symbol_record = _coff_section_symbol(donor, primary)
    aux_at = new_symbol_offset + (section_index + 1) * 18
    require(int.from_bytes(coff_auxiliary(donor, section_index, section_symbol_record)[0:4], 'little') == primary['raw_size'], f'{context}: the donor COMDAT auxiliary Length is stale')
    output[aux_at:aux_at + 4] = body_length.to_bytes(4, 'little')
    end_index, end_symbol = _coff_marker(donor, '.ef', primary['number'])
    require(end_symbol['value'] == primary['raw_size'], f'{context}: the donor .ef marker is stale')
    output[new_symbol_offset + end_index * 18 + 8:new_symbol_offset + end_index * 18 + 12] = body_length.to_bytes(4, 'little')
    carried = []
    for symbol_index, item in donor.symbols.items():
        if item['section'] != primary['number']:
            continue
        if symbol_index in (function_index, section_index, end_index):
            continue
        if item['name'] in ('.bf', '.lf'):
            continue
        require(item['value'] in offset_map, f"{context}: the symbol {item['name']} at {item['value']} is not an instruction boundary of the pre-image")
        mapped = offset_map[item['value']]
        if mapped != item['value']:
            at = new_symbol_offset + symbol_index * 18
            output[at + 8:at + 12] = mapped.to_bytes(4, 'little')
            carried.append([item['name'], item['value'], mapped])
    derived = bytes(output)
    checked = CoffObject(derived)
    checked_primary = checked.function_section(mangled)
    require(coff_body(checked, checked_primary) == bytes(image), f'{context}: the derived donor body is not the image')
    require(checked_primary['raw_size'] == body_length and checked_primary['line_count'] == primary['line_count'] and (checked_primary['relocation_count'] == primary['relocation_count']) and (checked_primary['number'] == primary['number']) and (checked_primary['characteristics'] == primary['characteristics']), f'{context}: the derived donor target header is inconsistent')
    require(function_multiset(checked) == function_multiset(donor) and comdat_primary_identity_multiset(checked) == comdat_primary_identity_multiset(donor) and (len(checked.sections) == len(donor.sections)), f"{context}: the derived donor changed the object's topology")
    require(_comdat_child_closure(checked, checked_primary) == _comdat_child_closure(donor, primary), f'{context}: the derived donor changed the target closure')
    require([row['target'] for row in detailed_relocations(checked, checked_primary)] == [row['target'] for row in detailed_relocations(donor, primary)], f'{context}: the derived donor changed a relocation target')
    require([row['offset'] for row in detailed_relocations(checked, checked_primary)] == [moved.get(row['offset'], row['offset']) for row in detailed_relocations(donor, primary)], f'{context}: the derived donor relocation offsets are not the proved reseat')
    return (derived, {'carried_code_symbols': carried, 'line_rows': primary['line_count'], 'procedure_range': [body_length, offset_map[debug_start], offset_map[debug_end]]})

def produce_register_bijection_reencoding_candidate(seed_bytes: bytes, donor_bytes: bytes, function: dict) -> tuple[bytes, dict]:
    """Produce a resized sigma(donor body) from compiler output.

    The parent class with EBP admitted: see the class comment above for the
    seven obligations that admission costs.  The pre-image is an ordinary,
    census-pinned carrier compile of the same translation unit; the renaming
    is proved sound against the body's own control flow AND against the
    compiler's own frame declaration; the resized image is re-seated through
    the bijection's own boundary map. Installation is delegated, unchanged, to `compose_same_slot_resize`
    in the mode a dozen landed rows already use.
    """
    require_payload_free_declaration(function, 'register-bijection re-encoding declaration')
    require(function.get('splice_class') == REGISTER_BIJECTION_REENCODING_CLASS, 'splice class is not retail_exact_register_bijection_reencoding')
    require('target_source_refactor' not in function, 'register-bijection functions carry no source refactor')
    spec = function['register_bijection_reencoding']
    require(spec['kind'] == REGISTER_BIJECTION_REENCODING_KIND, 're-encoding bijection kind differs')
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function['mangled']
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(sp['number'] == dp['number'] == function['expected_section_number'], 're-encoding target section seat changed')
    require(len(seed.sections) == len(donor.sections) == function['expected_section_count'], 're-encoding global section count changed')
    seed_functions = function_multiset(seed)
    require(seed_functions == function_multiset(donor) and sum(seed_functions.values()) == function['expected_function_count'], 're-encoding donor function set differs')
    seed_comdats = comdat_primary_identity_multiset(seed)
    require(seed_comdats == comdat_primary_identity_multiset(donor) and sum(seed_comdats.values()) == function['expected_comdat_count'], 're-encoding donor COMDAT identity set differs')
    require(sp['raw_size'] == function['expected_seed_length'] and dp['raw_size'] == function['expected_preimage_length'] and (sp['relocation_count'] == dp['relocation_count'] == function['expected_relocation_count']) and (sp['line_count'] == function['expected_seed_line_count']) and (dp['line_count'] == function['expected_donor_line_count']) and (sp['name'] == dp['name']) and (sp['characteristics'] == dp['characteristics'] == function['expected_characteristics']), 're-encoding target header/count pins changed')
    require(section_definitions(seed)[sp['number']]['selection'] == section_definitions(donor)[dp['number']]['selection'] == function['expected_selection'], 're-encoding COMDAT selection changed')
    expected_closure = tuple(function['expected_closure'])
    require(_comdat_child_closure(seed, sp) == _comdat_child_closure(donor, dp) == (len(expected_closure), expected_closure) and list(expected_closure) == REGISTER_BIJECTION_FPO_CLOSURE, 're-encoding target closure is not the FPO debug pair')
    require(instruction_mosaic_metadata_sha256(seed, sp) == function['expected_seed_metadata_sha256'] and instruction_mosaic_metadata_sha256(donor, dp) == function['expected_donor_metadata_sha256'], 're-encoding metadata differs from its pin')
    seed_body = coff_body(seed, sp)
    donor_body = bytes(coff_body(donor, dp))
    require(sha256_bytes(seed_body) == function['expected_seed_body_sha256'] and sha256_bytes(donor_body) == function['expected_donor_body_sha256'], 're-encoding seed/donor body differs from its pin')
    donor_rows = detailed_relocations(donor, dp)
    require([row['target'] for row in donor_rows] == [row['target'] for row in detailed_relocations(seed, sp)], 're-encoding donor relocation targets differ from the seed')
    relocation_offsets = frozenset((row['offset'] + byte for row in donor_rows for byte in range(row['width'])))
    relocation_symbols = {row['offset']: {'width': row['width'], 'target': row['target']} for row in donor_rows}
    internal_targets = frozenset((row['target_value'] for row in donor_rows if row['target_section'] == dp['number']))
    declared_targets = spec.get('expected_internal_relocation_targets')
    if declared_targets is not None:
        require(sorted(internal_targets) == declared_targets, 're-encoding in-body relocated target set changed')
    instructions = decode_ia32_bijection_body(donor_body, 're-encoding frame proof', relocation_symbols, spec.get('expected_code_length'))
    fpo_record = require_frame_pointer_free_frame(donor, dp, donor_body, instructions, 're-encoding frame proof')
    measured_fpo = {key: value for key, value in fpo_record.items() if key != 'raw_sha256'}
    require(measured_fpo == spec['expected_fpo_record'], 're-encoding FPO record differs from its declaration')
    regions = [{'start': item['start'], 'end': item['end'], 'mapping': dict(item['mapping'])} for item in spec['regions']]
    image, proof = apply_register_bijection_reencoding(donor_body, regions, relocation_offsets, 're-encoding image', relocation_symbols, spec.get('expected_code_length'), internal_targets or None, True)
    require(proof['code_length'] == (spec.get('expected_code_length') or len(donor_body)), 're-encoding code length differs from its pin')
    require(proof['growth'] == spec['expected_growth'] and proof['branch_repairs'] == spec['expected_branch_repairs'] and (proof['relocation_reseat'] == spec['expected_relocation_reseat']) and (proof['rewritten_field_offsets'] == spec['expected_rewritten_field_offsets']) and (proof['region_instruction_counts'] == spec['expected_region_instruction_counts']) and (proof['instruction_count'] == spec['expected_instruction_count']) and (proof['image_code_length'] == spec['expected_image_code_length']), 're-encoding image differs from its declaration')
    require(sha256_bytes(image) == function['expected_body_sha256'], 're-encoding image differs from its pin')
    require(len(image) == function['expected_body_length'] == function['expected_donor_length'], 're-encoding image length differs from its pin')
    require(image != donor_body, 're-encoding image does not move the donor body')
    pinned_length = function['retail_oracle']['length']
    require(pinned_length == len(image), 're-encoding linked length changed')
    moved = dict(proof['relocation_reseat'])
    installed_rows = [{**row, 'offset': moved.get(row['offset'], row['offset'])} for row in donor_rows]
    semantic_detail = require_declared_relocation_semantics(
        installed_rows,
        function['retail_relocations'],
        're-encoding candidate relocation semantics',
    )
    derived, derived_detail = _reencoded_donor_object(donor_bytes, mangled, image, proof, 're-encoding derived donor')
    require(derived_detail['procedure_range'] == spec['expected_procedure_range'] and derived_detail['carried_code_symbols'] == spec['expected_carried_code_symbols'], 're-encoding derived donor differs from its declaration')
    effective = {'mangled': mangled, 'splice_class': 'retail_exact_reloc_divergent', 'expected_seed_length': function['expected_seed_length'], 'expected_donor_length': function['expected_donor_length'], 'expected_linked_span': function['expected_linked_span'], 'expected_body_sha256': function['expected_body_sha256'], 'expected_seed_line_count': function['expected_seed_line_count'], 'expected_donor_line_count': function['expected_donor_line_count'], 'retail_oracle': function['retail_oracle'], 'retail_relocations': function['retail_relocations']}
    composed, detail = compose_same_slot_resize(seed_bytes, derived, effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, 're-encoding composed body differs from the image')
    require([row['offset'] for row in detailed_relocations(checked, cp)] == [row['offset'] for row in installed_rows] and [row['target'] for row in detailed_relocations(checked, cp)] == [row['target'] for row in installed_rows], 're-encoding composed relocation table is not the proved reseat')
    return (composed, {**detail, 'splice_class': REGISTER_BIJECTION_REENCODING_CLASS, 'register_bijection_reencoding': [{'start': item['start'], 'end': item['end'], 'mapping': dict(sorted(item['mapping'].items()))} for item in regions], 'fpo_record': measured_fpo, 'growth': proof['growth'], 'branch_repairs': proof['branch_repairs'], 'relocation_reseat': proof['relocation_reseat'], 'rewritten_field_offsets': proof['rewritten_field_offsets'], 'instruction_count': proof['instruction_count'], 'carried_code_symbols': derived_detail['carried_code_symbols'], 'procedure_range': derived_detail['procedure_range'], 'candidate_only': True, **semantic_detail})
