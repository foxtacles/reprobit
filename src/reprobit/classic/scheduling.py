from __future__ import annotations

from .coff import CoffObject, _coff_table_bytes, _comdat_child, _comdat_child_closure, coff_body, coff_unpack, comdat_primary_identity_multiset, detailed_relocations, function_multiset, function_symbol, section_definitions
from .composition import compose_equal_body_comdat, instruction_mosaic_metadata_sha256, require_instruction_mosaic_semantic_relocations
from .debug import CODEVIEW_PROCEDURE_RECORD_TYPES, FPO_RECORD_KEYS, parse_codeview_symbol_stream
from .foundation import exact_audit_keys, require, require_exact_int, require_payload_free_declaration, sha256_bytes
from .ia32 import require_declared_relocation_semantics, supported_ia32_instruction_length
from .registers import CODEVIEW_REGISTER_RECORD_TYPE, CODEVIEW_X86_REGISTER_NUMBERS, FPO_FRAME_KIND_FPO, IA32_GENERAL_REGISTER_NAMES, _IA32_INERT_SEGMENT_PREFIXES, _IA32_OPERAND_SIZE_PREFIX, _IA32_REGISTER_NUMBERS, _IA32_STRUCTURAL_REGISTERS, _bijection_form_for, _codeview_register_field, _codeview_register_name, _ia32_atom_registers, _ia32_backward_liveness, _ia32_live_out, decode_ia32_bijection_body, decode_ia32_bijection_instruction, ia32_register_atoms, require_frame_pointer_free_frame
from .relational import relational_form_external_entries

"""Classic compiler algorithms: scheduling."""
INSTRUCTION_SCHEDULE_CLASS = 'retail_exact_instruction_schedule'
INSTRUCTION_SCHEDULE_KIND = 'topological_window_reordering_v1'
INSTRUCTION_SCHEDULE_FPO_CLOSURE = ['.debug$F', '.debug$S']
INSTRUCTION_SCHEDULE_EH_CLOSURE = ['.debug$S', '.xdata$x']

def instruction_schedule_delegate(expected_closure: object, expected_code_renames: object, relocation_reseat: bool=False) -> str:
    """Name the installation delegate from the PINS alone.

    Identical policy to the register-bijection certificate: the composer
    requires the objects' own closure and rename set to equal these pins
    first, so a pin that disagrees refuses before this is reached.

    A window that moves a relocated operand needs the one primitive that can
    install a moved relocation record -- `equal_body_eh_reloc_layout`, which
    already pairs the two tables by ordinal, proves type/addend/target
    identity, and rewrites nothing but the four offset bytes.  The other two
    delegates retain the seed table verbatim and so cannot express a reseat.
    """
    if relocation_reseat:
        return 'equal_body_eh_reloc_layout'
    if list(expected_closure) == INSTRUCTION_SCHEDULE_FPO_CLOSURE and (not expected_code_renames):
        return 'equal_body_strict'
    return 'equal_body_eh_structural_local'

def _ia32_schedule_flag_table() -> dict:
    table = {}
    for opcode in (136, 137, 138, 139, 141, 198, 199):
        table[opcode] = (False, False)
    for index in range(8):
        table[184 + index] = (False, False)
    for opcode in (3, 11, 35, 43, 49, 51, 56, 57, 58, 59, 128, 129, 131, 132, 133):
        table[opcode] = (False, True)
    for index in range(8):
        table[64 + index] = (False, True)
        table[72 + index] = (False, True)
    for opcode in (26, 27):
        table[opcode] = (True, True)
    table[246] = (False, True)
    for index in range(8):
        table[80 + index] = (False, False)
    return table
_IA32_SCHEDULE_STACK_PUSH_OPCODES = frozenset(range(80, 88))
IA32_SCHEDULE_FLAG_EFFECTS = _ia32_schedule_flag_table()
IA32_STACK_SLOT_BYTES = 4

def ia32_esp_relative_displacement(body: bytes, item: dict) -> tuple | None:
    """(byte offset, size, signed value) of an ESP-relative displacement.

    ESP can only be a memory base through a SIB whose base field is 4, so this
    reads the SIB rather than guessing from the r/m field.  It deliberately
    covers `lea` as well as loads and stores: `lea edx, [esp+0x14]` carries an
    ESP displacement that a moved push shifts exactly as it shifts a load's,
    and `lea` has no memory OPERAND for the decoder to report.

    Returns None when the instruction has no ESP displacement, and also when
    it has an ESP base with NO displacement byte (mod 0), which cannot absorb
    an adjustment without growing an encoding -- the caller refuses that.
    """
    encoding = item['encoding']
    if encoding is None or encoding['mode'] == 3 or encoding['absolute']:
        return None
    if encoding['sib_at'] is None:
        return None
    sib = body[encoding['sib_at']]
    base = sib & 7
    if base != _IA32_REGISTER_NUMBERS['esp']:
        return None
    if encoding['mode'] == 0:
        return ('no_displacement', 0, 0)
    at, size = (encoding['displacement_at'], encoding['displacement_size'])
    if at is None or size == 0:
        return ('no_displacement', 0, 0)
    return (at, size, int.from_bytes(body[at:at + size], 'little', signed=True))

def ia32_esp_used_only_as_a_base(body: bytes, item: dict) -> bool:
    """Does this instruction touch ESP ONLY through an adjusted address?

    True when the instruction has a real ESP-relative displacement AND ESP
    appears in no register-direct field.  For such an instruction the stack
    adjustment restores the exact address it names, so a moved push changes
    nothing it observes -- which is what lets the ESP dependence between the
    two be discharged.  `lea edx, [esp+0x14]` qualifies: its displacement is
    adjusted too, so the ADDRESS it computes is preserved.
    """
    found = ia32_esp_relative_displacement(body, item)
    if found is None or found[0] == 'no_displacement':
        return False
    encoding = item['encoding']
    for byte_index, shift in item['fields']:
        name = IA32_GENERAL_REGISTER_NAMES[body[byte_index] >> shift & 7]
        if name != 'esp':
            continue
        is_base = encoding is not None and encoding['sib_at'] is not None and (byte_index == encoding['sib_at']) and (shift == 0)
        if not is_base:
            return False
    return True

def ia32_schedule_stack_adjustments(body: bytes, inside: list[dict], order: list[int], context: str) -> list[list]:
    """Obligation 6c: what a moved PUSH does to every ESP displacement.

    A `push` lowers ESP by four, so an ESP-relative operand that the
    permutation moves from one side of a push to the other must have its
    displacement changed by four in order to name the SAME address.  The
    adjustment is DERIVED here from the declared permutation -- it is never a
    free parameter -- as

        delta(i) = 4 * (pushes before i in the TARGET order
                        - pushes before i in the SOURCE order)

    and it is required to be absorbable without changing the instruction's
    encoded length, so a `disp8` that would overflow, or an ESP base with no
    displacement byte at all, REFUSES rather than growing an encoding.

    Returns `[[source index, byte offset, old value, new value], ...]`, sorted.
    """
    pushes = [index for index, item in enumerate(inside) if item['opcode'] in _IA32_SCHEDULE_STACK_PUSH_OPCODES]
    if not pushes:
        return []
    position = {source: index for index, source in enumerate(order)}
    adjustments = []
    for index, item in enumerate(inside):
        found = ia32_esp_relative_displacement(body, item)
        if found is None:
            continue
        before_source = sum((1 for push in pushes if push < index))
        before_target = sum((1 for push in pushes if position[push] < position[index]))
        delta = IA32_STACK_SLOT_BYTES * (before_target - before_source)
        if not delta:
            continue
        at, size, value = found
        require(at != 'no_displacement', f"{context}: the instruction at {item['offset']} has an ESP base with no displacement byte, so it cannot absorb the {delta:+d} a moved push forces without growing its encoding")
        updated = value + delta
        low, high = (-(1 << 8 * size - 1), (1 << 8 * size - 1) - 1)
        require(low <= updated <= high, f"{context}: adjusting the ESP displacement at {item['offset']} by {delta:+d} would overflow its {size}-byte field, which would change the encoding's length")
        adjustments.append([index, at, value, updated])
    return sorted(adjustments)

def ia32_schedule_instruction_facts(instruction: dict, context: str) -> dict:
    """Flag effect and memory operand of one window instruction, or refuse."""
    opcode = instruction['opcode']
    effect = IA32_SCHEDULE_FLAG_EFFECTS.get(opcode)
    require(effect is not None, f'{context}: opcode 0x{opcode:02x} is outside the instruction-schedule table')
    require(instruction['flow'] == 'fall', f'{context}: a control-transfer instruction is outside the instruction-schedule table')
    memory = instruction['memory']
    if memory is not None:
        require(not memory.get('unknown'), f"{context}: a repeated string operation's memory span is an unknown extent and cannot be disambiguated")
        require(not memory['absolute'], f'{context}: an absolute memory operand cannot be disambiguated')
        require(memory['index'] is None, f'{context}: an indexed memory operand cannot be disambiguated')
        require(memory['base'] is not None, f'{context}: a memory operand without a base register cannot be disambiguated')
    return {'offset': instruction['offset'], 'length': instruction['length'], 'opcode': opcode, 'reads': instruction['reads'], 'writes': instruction['writes'], 'reads_flags': effect[0], 'writes_flags': effect[1], 'memory': memory}

def ia32_memory_provably_disjoint(left: dict, right: dict) -> bool:
    """Two memory cells that provably cannot alias.

    The ONLY admitted proof: the same base register, no index on either side,
    neither absolute, and non-overlapping [displacement, displacement+width)
    spans.  Two different base registers are NOT a proof of anything and this
    returns False for them, which makes the pair a dependence edge.
    """
    if left['absolute'] or right['absolute']:
        return False
    if left['index'] is not None or right['index'] is not None:
        return False
    if left['base'] is None or left['base'] != right['base']:
        return False
    return left['displacement'] + left['width'] <= right['displacement'] or right['displacement'] + right['width'] <= left['displacement']

def ia32_schedule_dependence_edges(instructions: list[dict], context: str, body: bytes | None=None, stack_adjusted: bool=False) -> tuple[list[dict], list[list]]:
    """The window's dependence DAG (obligation 4).

    Every ordered pair carries an edge unless it is proved independent on
    registers, on flags AND on memory.  The memory proof is the conservative
    one above, and a base register written anywhere inside the window
    invalidates every displacement comparison against it, so that is refused
    outright rather than reasoned around.

    `stack_adjusted` says the caller has DECLARED the ESP-displacement
    adjustments a moved push forces (obligation 6c).  Without it a push in the
    window is refused exactly as before, so every landed entry is unaffected.
    """
    facts = [ia32_schedule_instruction_facts(item, f"{context} at {item['offset']}") for item in instructions]
    if any((item['opcode'] in _IA32_SCHEDULE_STACK_PUSH_OPCODES for item in facts)):
        offending = sorted((item['offset'] for item in facts if item['memory'] is not None and item['memory']['base'] == 'esp'))
        require(not offending or stack_adjusted, f"{context}: a push shares the window with the esp-relative memory operand at {offending[:1]}, whose address the push's own esp delta would move")
        if stack_adjusted:
            require(body is not None, f'{context}: a stack-adjusted window needs its body')
            for item in instructions:
                found = ia32_esp_relative_displacement(body, item)
                if found is None or found[0] == 'no_displacement':
                    continue
                require(found[2] >= 0, f"{context}: the ESP displacement {found[2]} at {item['offset']} is below ESP, where a push in this window writes, so disjointness does not hold")
    written = set()
    for item in facts:
        written |= set(item['writes'])
    esp_compensated = [stack_adjusted and body is not None and ia32_esp_used_only_as_a_base(body, item) for item in instructions]
    is_stack_operation = [item['opcode'] in _IA32_SCHEDULE_STACK_PUSH_OPCODES for item in facts]
    edges = []
    for left in range(len(facts)):
        for right in range(left + 1, len(facts)):
            first, second = (facts[left], facts[right])
            reasons = []
            discharged = frozenset({'esp'}) if is_stack_operation[left] and esp_compensated[right] or (is_stack_operation[right] and esp_compensated[left]) else frozenset()
            first_reads = first['reads'] - discharged
            first_writes = first['writes'] - discharged
            second_reads = second['reads'] - discharged
            second_writes = second['writes'] - discharged
            if first_writes & second_reads:
                reasons.append('register_raw')
            if first_reads & second_writes:
                reasons.append('register_war')
            if first_writes & second_writes:
                reasons.append('register_waw')
            if first['writes_flags'] and second['reads_flags']:
                reasons.append('flags_raw')
            if first['reads_flags'] and second['writes_flags']:
                reasons.append('flags_war')
            if first['writes_flags'] and second['writes_flags']:
                reasons.append('flags_waw')
            one, two = (first['memory'], second['memory'])
            if one is not None and two is not None and (one['write'] or two['write']):
                base_is_written = one['base'] in written or two['base'] in written
                canonical_disjoint = False
                if stack_adjusted and body is not None and (one['base'] == 'esp' == two['base']) and all((is_stack_operation[k] or 'esp' not in facts[k]['writes'] for k in range(len(facts)))):

                    def _canonical(mem, index):
                        depth = sum((1 for k in range(index) if is_stack_operation[k]))
                        adjusted = dict(mem)
                        adjusted['displacement'] = mem['displacement'] - 4 * depth
                        return adjusted
                    canonical_disjoint = ia32_memory_provably_disjoint(_canonical(one, left), _canonical(two, right))
                if not canonical_disjoint and (base_is_written or not ia32_memory_provably_disjoint(one, two)):
                    reasons.append('memory')
            if reasons:
                edges.append([left, right, sorted(reasons)])
    return (facts, edges)

def require_topological_instruction_order(count: int, edges: list[list], order: list[int], context: str) -> None:
    """The declared order must respect every edge of the DAG."""
    require(sorted(order) == list(range(count)), f'{context}: the target order is not a permutation of the window')
    position = {source: index for index, source in enumerate(order)}
    for left, right, reasons in edges:
        require(position[left] < position[right], f"{context}: the target order moves instruction {right} before {left}, which the dependence DAG forbids ({', '.join(reasons)})")
    require(order != list(range(count)), f'{context}: the declared order does not reorder the window')
_IA32_SCHEDULE_INTERIOR_PREFIXES = _IA32_INERT_SEGMENT_PREFIXES | frozenset({_IA32_OPERAND_SIZE_PREFIX})
_IA32_SCHEDULE_TERMINAL_OPCODES = frozenset({194, 195, 202, 203, 233, 235})

def ia32_schedule_body_walk(body: bytes, relocations: dict | None, context: str, code_length: int | None=None, internal_targets: frozenset | None=None) -> tuple[list[tuple[int, int]], set]:
    """Boundaries and interior branch targets of a whole COMDAT body."""
    require(isinstance(body, (bytes, bytearray)) and body, f'{context}: body is empty')
    body = bytes(body)
    relocations = relocations or {}
    limit = len(body) if code_length is None else code_length
    require(isinstance(limit, int) and (not isinstance(limit, bool)) and (0 < limit <= len(body)), f'{context}: code length is out of range')
    code = body[:limit]
    spans = []
    targets = set()
    computed = []
    offset = 0
    while offset < len(code):
        length = supported_ia32_instruction_length(code[offset:], f'{context} at {offset}')
        spans.append((offset, length))
        cursor = offset
        while code[cursor] in _IA32_SCHEDULE_INTERIOR_PREFIXES:
            cursor += 1
            require(cursor < offset + length, f'{context}: instruction at {offset} is only prefixes')
        opcode = code[cursor]
        width = 0
        if opcode in range(112, 128) or opcode in (235, 224, 225, 226, 227):
            width = 1
        elif opcode in (233, 232):
            width = 4
        elif opcode == 15 and cursor + 1 < offset + length and (128 <= code[cursor + 1] <= 143):
            width = 4
        elif opcode == 255:
            require(cursor + 1 < offset + length, f'{context}: FF form at {offset} lacks its ModRM')
            extension = code[cursor + 1] >> 3 & 7
            require(extension not in (3, 5), f"{context}: a far jump at {offset} makes the window's entry set unknowable")
            if extension == 4:
                computed.append(offset)
        if width:
            displacement_at = offset + length - width
            row = relocations.get(displacement_at)
            if row is None or row.get('width') != width:
                relative = int.from_bytes(code[displacement_at:offset + length], 'little', signed=True)
                targets.add(offset + length + relative)
        offset += length
    require(offset == len(code), f'{context}: body does not decode to exhaustion')
    starts = {start for start, _ in spans}
    for target in sorted(targets):
        require(target in starts, f'{context}: a branch targets {target}, which is not an instruction boundary of this body')
    if limit < len(body):
        last_at, last_length = spans[-1]
        cursor = last_at
        while code[cursor] in _IA32_SCHEDULE_INTERIOR_PREFIXES:
            cursor += 1
        opcode = code[cursor]
        terminal = opcode in _IA32_SCHEDULE_TERMINAL_OPCODES
        if opcode == 255:
            terminal = code[cursor + 1] >> 3 & 7 == 4
        require(terminal, f"{context}: code falls through into the body's data tail")
    if computed:
        require(internal_targets is not None, f"{context}: a computed jump at {computed[0]} makes the window's entry set unknowable without the relocated in-body target set")
        stray = sorted((target for target in internal_targets if target < limit and target not in starts))
        require(not stray, f'{context}: the relocated in-body target {stray[:1]} is not an instruction boundary of this body')
        targets |= set(internal_targets)
    return (spans, targets)

def apply_instruction_schedule(body: bytes, windows: list[dict], relocation_offsets: frozenset, context: str, relocations: dict | None=None, code_length: int | None=None, internal_targets: frozenset | None=None) -> tuple[bytes, dict]:
    """Reorder each declared window under a proved dependence DAG.

    Obligations 2 through 6 are checked here, and the result is re-decoded to
    exhaustion so that every claim about the image is measured on the image.

    `code_length` pins where a switch-table body's code ends; the tail is
    never decoded, never inside a window and never rewritten.
    """
    require_payload_free_declaration(windows, f'{context} instruction schedule declaration')
    body = bytes(body)
    limit = len(body) if code_length is None else code_length
    spans, targets = ia32_schedule_body_walk(body, relocations, context, code_length, internal_targets)
    instructions = [{'offset': start, 'length': length} for start, length in spans]
    boundaries = {start for start, _ in spans}
    boundaries.add(limit)
    image = bytearray(body)
    detail = []
    previous_end = 0
    for index, window in enumerate(windows):
        window_context = f'{context} window {index}'
        start, end = (window['start'], window['end'])
        require(start >= previous_end, f'{window_context}: windows are unsorted or overlapping')
        previous_end = end
        require(end <= limit, f"{window_context}: the window reaches into the body's data tail")
        require(start in boundaries and end in boundaries and (start < end), f'{window_context}: the window does not span whole instructions')
        inside = [item for item in instructions if start <= item['offset'] < end]
        require(inside and inside[-1]['offset'] + inside[-1]['length'] == end, f'{window_context}: the window does not end on an instruction boundary')
        require(len(inside) >= 2, f'{window_context}: a window needs at least two instructions')
        inside = [decode_ia32_bijection_instruction(body, item['offset'], f"{window_context} at {item['offset']}", relocations) for item in inside]
        require([item['offset'] + item['length'] for item in inside][-1] == end, f'{window_context}: the decoded window does not end on the window boundary')
        crossing = sorted((target for target in targets if start < target < end))
        require(not crossing, f'{window_context}: a branch targets the window interior at {crossing}')
        overlapping = sorted((offset for offset in range(start, end) if offset in relocation_offsets))
        declared_reseat = window.get('relocation_reseat')
        window_reseat = []
        if declared_reseat is None:
            require(not overlapping, f'{window_context}: a relocation operand lies inside the window at {overlapping[:4]}; this class refuses to move a relocation rather than reseat it approximately')
        else:
            require(overlapping, f'{window_context}: a relocation reseat is declared but no relocation operand lies inside the window')
            require(relocations, f'{window_context}: a relocation reseat needs the relocation records')
            lengths_in = [item['length'] for item in inside]
            starts_in = [item['offset'] for item in inside]
            seated = {}
            cursor = start
            for position in window['target_order']:
                seated[position] = cursor
                cursor += lengths_in[position]
            for offset in sorted(relocations):
                record = relocations[offset]
                width = record['width']
                if offset + width <= start or offset >= end:
                    require(not (start < offset + width and offset < end), f'{window_context}: a relocation straddles the window boundary at {offset}')
                    continue
                require(start <= offset and offset + width <= end, f'{window_context}: a relocation straddles the window boundary at {offset}')
                position = next((index for index in range(len(inside)) if starts_in[index] <= offset and offset + width <= starts_in[index] + lengths_in[index]), None)
                require(position is not None, f'{window_context}: the relocation at {offset} straddles an instruction boundary')
                window_reseat.append([offset, seated[position] + (offset - starts_in[position])])
            require(window_reseat == declared_reseat, f'{window_context}: the measured relocation reseat {window_reseat} differs from its declaration')
        declared_stack = window.get('stack_adjustments')
        facts, edges = ia32_schedule_dependence_edges(inside, window_context, body, declared_stack is not None)
        require(edges == window['expected_dependence_edges'], f'{window_context}: the measured dependence DAG differs from its declaration')
        order = list(window['target_order'])
        require_topological_instruction_order(len(inside), edges, order, window_context)
        original = [bytes(body[item['offset']:item['offset'] + item['length']]) for item in inside]
        require([len(piece) for piece in original] == list(window['source_instruction_lengths']), f"{window_context}: the window's instruction partition differs from its declaration")
        window_stack = ia32_schedule_stack_adjustments(body, inside, order, window_context)
        if declared_stack is None:
            require(not window_stack, f'{window_context}: the permutation moves a push past an ESP-relative operand but declares no stack adjustment')
        else:
            require(window_stack == declared_stack, f'{window_context}: the measured stack adjustment {window_stack} differs from its declaration')
        pieces = [bytearray(piece) for piece in original]
        adjusted_spans = {}
        for index, at, _old_value, new_value in window_stack:
            found = ia32_esp_relative_displacement(body, inside[index])
            local = at - inside[index]['offset']
            size = found[1]
            pieces[index][local:local + size] = new_value.to_bytes(size, 'little', signed=True)
            adjusted_spans[index] = list(range(local, local + size))
        pieces = [bytes(piece) for piece in pieces]
        for index, (before_piece, after_piece) in enumerate(zip(original, pieces)):
            changed_bytes = [position for position in range(len(before_piece)) if before_piece[position] != after_piece[position]]
            require(changed_bytes == adjusted_spans.get(index, []), f"{window_context}: the instruction at {inside[index]['offset']} changed outside its declared ESP displacement")
        reordered = b''.join((pieces[source] for source in order))
        require(sorted(pieces) == sorted((reordered[offset:offset + length] for offset, length in _instruction_spans(order, pieces))), f"{window_context}: the reordering is not a permutation of the window's own instructions")
        require(len(reordered) == end - start, f'{window_context}: the reordering changed the window length')
        image[start:end] = reordered
        detail.append({'start': start, 'end': end, 'relocation_reseat': window_reseat, 'stack_adjustments': window_stack, 'adjusted_instructions': sorted(pieces), 'instruction_count': len(inside), 'source_instruction_lengths': [len(piece) for piece in pieces], 'target_order': order, 'dependence_edges': edges, 'memory_disambiguation': [{'instruction': position, 'base': item['memory']['base'], 'displacement': item['memory']['displacement'], 'width': item['memory']['width'], 'read': item['memory']['read'], 'write': item['memory']['write']} for position, item in enumerate(facts) if item['memory'] is not None]})
    image = bytes(image)
    require(len(image) == len(body), f'{context}: the reordering changed the body length')
    require(image != body, f'{context}: the reordering moves nothing')
    reseat = [pair for item in detail for pair in item['relocation_reseat']]
    image_relocations = relocations
    if reseat:
        moved = dict(reseat)
        image_relocations = {moved.get(offset, offset): record for offset, record in (relocations or {}).items()}
        require(len(image_relocations) == len(relocations or {}), f'{context}: the reseat collides two relocation records')
    image_spans, _ = ia32_schedule_body_walk(image, image_relocations, f'{context} image', code_length, internal_targets)
    image_instructions = [{'offset': start, 'length': length} for start, length in image_spans]
    window_spans = [(item['start'], item['end']) for item in windows]

    def _in_window(offset):
        return any((start <= offset < end for start, end in window_spans))
    require([(item['offset'], item['length']) for item in image_instructions if not _in_window(item['offset'])] == [(item['offset'], item['length']) for item in instructions if not _in_window(item['offset'])], f'{context}: the image moved an instruction boundary outside a declared window')
    for (start, end), item in zip(window_spans, detail):
        before = item['adjusted_instructions']
        after = sorted((image[position['offset']:position['offset'] + position['length']] for position in image_instructions if start <= position['offset'] < end))
        require(before == after, f'{context}: window {start:#x} is not the same instruction multiset in the image')
    changed = sorted((index for index in range(len(body)) if body[index] != image[index]))
    require(all((_in_window(offset) for offset in changed)), f'{context}: the image changed a byte outside a declared window')
    for item in detail:
        item.pop('adjusted_instructions', None)
    return (image, {'windows': detail, 'instruction_count': len(instructions), 'changed_offsets': changed, 'relocation_reseat': reseat, 'stack_adjustments': [pair for item in detail for pair in item['stack_adjustments']], 'code_length': limit})

def _instruction_spans(order: list[int], pieces: list[bytes]):
    """The (offset, length) spans the reordered pieces occupy."""
    cursor = 0
    for source in order:
        yield (cursor, len(pieces[source]))
        cursor += len(pieces[source])

def require_instruction_schedule_debug_fidelity(coff: 'CoffObject', section: dict, image: bytes, windows: list[dict], spec: dict, mangled: str, context: str, relocations: dict | None=None, code_length: int | None=None, internal_targets: frozenset | None=None) -> dict:
    """Obligation 7: re-derive the line rows and the debug ranges.

    Every COFF line row is checked against the IMAGE's own instruction
    boundaries, the rows inside each window are pinned together with the
    source instruction that now begins at them, the CodeView procedure
    record's code length and debug range are pinned and required to stay
    clear of every window interior, and no closure-child relocation may name
    a code symbol whose value falls inside one.
    """
    spans, _ = ia32_schedule_body_walk(image, relocations, f'{context} image', code_length, internal_targets)
    boundaries = {start for start, _ in spans}
    boundaries.add(len(image) if code_length is None else code_length)
    index_of = {start: position for position, (start, _) in enumerate(spans)}
    line_bytes = _coff_table_bytes(coff, section, 'lines')
    require(len(line_bytes) == section['line_count'] * 6 and len(line_bytes) >= 12, f'{context}: the compiler line table is missing')
    marker_index, marker_line = coff_unpack('<IH', line_bytes, 0, f'{context} line sentinel')
    function_index, _ = function_symbol(coff, mangled, section['number'])
    require(marker_line == 0 and marker_index == function_index, f'{context}: the compiler line sentinel differs')
    rows = []
    for position in range(1, section['line_count']):
        offset, line = coff_unpack('<IH', line_bytes, position * 6, f'{context} line row {position}')
        require(line != 0 and 0 <= offset < len(image), f'{context}: line row {position} is invalid')
        require(offset in boundaries, f'{context}: line row {position} at {offset:#x} is not an instruction boundary of the image')
        rows.append([offset, line])
    interior = []
    declared_windows = list(spec.get('windows') or []) + list(spec.get('trailing_windows') or [])
    require(len(windows) == len(declared_windows), f'{context}: the window list differs from its declaration')
    for window, declared in zip(windows, declared_windows):
        start, end = (window['start'], window['end'])
        order = list(window['target_order'])
        attribution = [[offset, line, order[index_of[offset] - index_of[start]]] for offset, line in rows if start <= offset < end]
        require(attribution == declared['expected_line_rows'], f'{context}: the line rows inside window {start:#x} differ from their declaration')
        interior.extend(attribution)
    child = _comdat_child(coff, section, '.debug$S')
    stream = coff_body(coff, child)
    records = parse_codeview_symbol_stream(stream, f'{context} debug$S')
    procedures = [record for record in records if record['type'] in CODEVIEW_PROCEDURE_RECORD_TYPES]
    require(len(procedures) == 1, f'{context}: the .debug$S stream does not carry exactly one procedure record')
    record = procedures[0]
    code_length, debug_start, debug_end = coff_unpack('<III', stream, record['offset'] + 16, f'{context} procedure record')
    require([code_length, debug_start, debug_end] == spec['expected_procedure_range'], f"{context}: the procedure record's code range differs from its declaration")
    require(code_length == len(image), f"{context}: the procedure record's code length is not the body")
    for name, value in (('debug_start', debug_start), ('debug_end', debug_end)):
        require(value in boundaries, f"{context}: the procedure record's {name} is not an instruction boundary of the image")
        require(not any((start < value < end for start, end in [(item['start'], item['end']) for item in windows])), f"{context}: the procedure record's {name} falls inside a reordered window")
    values = {}
    for symbol in coff.symbols.values():
        if symbol['section'] == section['number']:
            values[symbol['name']] = symbol['value']
    referenced = []
    for child_name in _comdat_child_closure(coff, section)[1]:
        sibling = _comdat_child(coff, section, child_name)
        for row in detailed_relocations(coff, sibling):
            if row['target'] in values:
                value = values[row['target']]
                require(not any((start < value < end for start, end in [(item['start'], item['end']) for item in windows])), f"{context}: {child_name} names the code symbol {row['target']} at {value:#x}, inside a reordered window")
                referenced.append([child_name, row['target'], value])
    require(sorted(referenced) == sorted(spec['expected_code_symbol_references']), f"{context}: the closure's code-symbol references differ from their declaration")
    return {'line_rows': len(rows), 'window_line_rows': interior, 'procedure_range': [code_length, debug_start, debug_end], 'code_symbol_references': referenced}

def _validate_schedule_windows(windows: list, context: str, body_length: int, code_length: int | None=None, targets: list | None=None) -> list[dict]:
    """Normalise a list of reordering windows.

    Shared by the instruction-schedule certificate and the web-recolour
    certificate, which applies the same reordering primitive before its own
    proof.
    """
    normalized_windows = []
    previous_end = 0
    for index, window in enumerate(windows):
        window_context = f'{context}.windows[{index}]'
        require(isinstance(window, dict), f'{window_context} must be an object')
        exact_audit_keys(window, {'start', 'end', 'source_instruction_lengths', 'target_order', 'expected_dependence_edges', 'expected_line_rows', 'relocation_reseat', 'stack_adjustments'}, window_context, optional={'relocation_reseat', 'stack_adjustments'})
        start = require_exact_int(window.get('start'), f'{window_context}.start', minimum=0, maximum=body_length - 1)
        end = require_exact_int(window.get('end'), f'{window_context}.end', minimum=1, maximum=body_length)
        require(start >= previous_end and start < end, f'{window_context}: windows are unsorted, empty or overlapping')
        require(code_length is None or end <= code_length, f'{window_context}: the window reaches past the declared code length')
        require(targets is None or not any((start < item < end for item in targets)), f"{window_context}: a relocated in-body target enters the window's interior")
        previous_end = end
        lengths = window.get('source_instruction_lengths')
        require(isinstance(lengths, list) and 2 <= len(lengths) <= 64 and all((type(item) is int and 1 <= item <= 15 for item in lengths)) and (sum(lengths) == end - start), f'{window_context}.source_instruction_lengths differs')
        order = window.get('target_order')
        require(isinstance(order, list) and sorted(order) == list(range(len(lengths))) and (order != list(range(len(lengths)))), f'{window_context}.target_order is not a non-identity permutation')
        edges = window.get('expected_dependence_edges')
        require(isinstance(edges, list) and all((isinstance(edge, list) and len(edge) == 3 and (type(edge[0]) is int) and (type(edge[1]) is int) and (0 <= edge[0] < edge[1] < len(lengths)) and isinstance(edge[2], list) and edge[2] and (edge[2] == sorted(set(edge[2]))) and all((reason in INSTRUCTION_SCHEDULE_EDGE_REASONS for reason in edge[2])) for edge in edges)) and ([edge[:2] for edge in edges] == sorted((edge[:2] for edge in edges))), f'{window_context}.expected_dependence_edges is invalid')
        line_rows = window.get('expected_line_rows')
        require(isinstance(line_rows, list) and all((isinstance(row, list) and len(row) == 3 and all((type(item) is int for item in row)) and (start <= row[0] < end) and (0 <= row[2] < len(lengths)) for row in line_rows)) and ([row[0] for row in line_rows] == sorted({row[0] for row in line_rows})), f'{window_context}.expected_line_rows is invalid')
        stack = window.get('stack_adjustments')
        normalized_stack = None
        if stack is not None:
            require(isinstance(stack, list) and 1 <= len(stack) <= 64 and all((isinstance(row, list) and len(row) == 4 and all((type(value) is int for value in row)) and (0 <= row[0] < len(lengths)) and (start <= row[1] < end) and (row[2] != row[3]) and (abs(row[3] - row[2]) % 4 == 0) for row in stack)) and (stack == sorted(stack)) and (len({row[1] for row in stack}) == len(stack)), f'{window_context}.stack_adjustments is invalid')
            normalized_stack = [list(row) for row in stack]
        reseat = window.get('relocation_reseat')
        normalized_reseat = None
        if reseat is not None:
            require(isinstance(reseat, list) and 1 <= len(reseat) <= 64 and all((isinstance(pair, list) and len(pair) == 2 and all((type(item) is int for item in pair)) and (start <= pair[0] < end) and (start <= pair[1] < end) for pair in reseat)) and ([pair[0] for pair in reseat] == sorted({pair[0] for pair in reseat})) and (len({pair[1] for pair in reseat}) == len(reseat)) and any((pair[0] != pair[1] for pair in reseat)), f'{window_context}.relocation_reseat is invalid')
            normalized_reseat = [list(pair) for pair in reseat]
        normalized_window = {'start': start, 'end': end, 'source_instruction_lengths': list(lengths), 'target_order': list(order), 'expected_dependence_edges': [[edge[0], edge[1], list(edge[2])] for edge in edges], 'expected_line_rows': [list(row) for row in line_rows]}
        if normalized_reseat is not None:
            normalized_window['relocation_reseat'] = normalized_reseat
        if normalized_stack is not None:
            normalized_window['stack_adjustments'] = normalized_stack
        normalized_windows.append(normalized_window)
    return normalized_windows

def validate_web_recolour(value: object, context: str, body_length: int) -> dict:
    """Validate one web-recolour certificate declaration."""
    require(isinstance(value, dict), f'{context} must be an object')
    exact_audit_keys(value, {'kind', 'windows', 'webs', 'expected_instruction_count', 'expected_changed_offsets', 'expected_procedure_range', 'expected_code_symbol_references', 'expected_debug_s_registers', 'expected_code_length', 'expected_internal_relocation_targets', 'expected_fpo_record', 'trailing_windows', 'authenticity_rationale'}, context, optional={'windows', 'trailing_windows', 'expected_code_length', 'expected_internal_relocation_targets', 'expected_fpo_record'})
    require(value.get('kind') == WEB_RECOLOUR_KIND, f'{context}.kind differs')
    code_length = value.get('expected_code_length')
    if code_length is not None:
        code_length = require_exact_int(code_length, f'{context}.expected_code_length', minimum=2, maximum=body_length)
    targets = value.get('expected_internal_relocation_targets')
    if targets is not None:
        require(isinstance(targets, list) and targets == sorted(set(targets)) and all((type(item) is int and 0 <= item < body_length for item in targets)), f'{context}.expected_internal_relocation_targets is invalid')

    def _windows(key):
        if value.get(key) is None:
            return []
        windows = value[key]
        require(isinstance(windows, list) and 1 <= len(windows) <= 32, f'{context}.{key} must contain 1..32 windows')
        return _validate_schedule_windows(windows, f'{context}.{key}' if key != 'windows' else context, body_length, code_length, targets)
    normalized_windows = _windows('windows')
    normalized_trailing = _windows('trailing_windows')
    for leading in normalized_windows:
        for trailing in normalized_trailing:
            require(leading['end'] <= trailing['start'] or trailing['end'] <= leading['start'], f'{context}: a trailing window overlaps a leading one')
    fpo_record = value.get('expected_fpo_record')
    if fpo_record is not None:
        require(isinstance(fpo_record, dict) and set(fpo_record) == FPO_RECORD_KEYS - {'raw_sha256'}, f'{context}.expected_fpo_record is invalid')
        require(fpo_record.get('cbFrame') == FPO_FRAME_KIND_FPO and fpo_record.get('fHasSEH') == 0, f'{context}.expected_fpo_record does not declare a frame-pointer-free, SEH-free frame')
    structural = {'esp'} if fpo_record is not None else _IA32_STRUCTURAL_REGISTERS
    webs = value.get('webs')
    require(isinstance(webs, list) and 1 <= len(webs) <= 32, f'{context}.webs must contain 1..32 webs')
    normalized_webs = []
    rewritten = []
    for index, web in enumerate(webs):
        web_context = f'{context}.webs[{index}]'
        require(isinstance(web, dict), f'{web_context} must be an object')
        exact_audit_keys(web, {'source_register', 'image_register', 'definitions', 'uses', 'expected_rewritten_offsets'}, web_context)
        source = web.get('source_register')
        image_register = web.get('image_register')
        require(source in _IA32_REGISTER_NUMBERS and image_register in _IA32_REGISTER_NUMBERS and (source != image_register), f'{web_context} does not name two distinct general registers')
        require(not {source, image_register} & structural, f'{web_context} touches ' + ('ESP' if fpo_record is not None else 'ESP or EBP'))
        role_offsets = {}
        field_scopes = {}
        for role in ('definitions', 'uses'):
            offsets, scopes = _ia32_web_membership(web, role, web_context)
            require(offsets == sorted(set(offsets)) and all((0 <= offset < (code_length or body_length) for offset in offsets)), f'{web_context}.{role} is invalid')
            for offset, ordinal in scopes.items():
                require(offset not in field_scopes, f'{web_context} scopes {offset} twice')
                field_scopes[offset] = ordinal
            role_offsets[role] = offsets
        for offset in set(role_offsets['definitions']) & set(role_offsets['uses']):
            require(offset not in field_scopes, f'{web_context}: {offset} is a read-modify-write node and cannot also be field-scoped')
        offsets = web.get('expected_rewritten_offsets')
        require(isinstance(offsets, list) and offsets and (offsets == sorted(set(offsets))) and (len(offsets) == len(role_offsets['definitions']) + len(role_offsets['uses'])) and all((type(item) is int and 0 <= item < (code_length or body_length) for item in offsets)), f'{web_context}.expected_rewritten_offsets is invalid')
        rewritten.extend(offsets)
        normalized_webs.append({'source_register': source, 'image_register': image_register, 'definitions': list(role_offsets['definitions']), 'uses': list(role_offsets['uses']), 'field_scopes': dict(field_scopes), 'expected_rewritten_offsets': list(offsets)})
    changed = value.get('expected_changed_offsets')
    require(isinstance(changed, list) and changed and (changed == sorted(set(changed))) and all((type(offset) is int and (offset in rewritten or any((item['start'] <= offset < item['end'] for item in normalized_windows + normalized_trailing))) for offset in changed)), f'{context}.expected_changed_offsets is invalid')
    require(set(rewritten) <= set(changed), f'{context}.expected_changed_offsets omits a recoloured byte')
    procedure = value.get('expected_procedure_range')
    require(isinstance(procedure, list) and len(procedure) == 3 and all((type(item) is int and item >= 0 for item in procedure)) and (procedure[0] == body_length) and (procedure[1] <= procedure[2] <= body_length), f'{context}.expected_procedure_range is invalid')
    references = value.get('expected_code_symbol_references')
    require(isinstance(references, list) and all((isinstance(item, list) and len(item) == 3 and isinstance(item[0], str) and isinstance(item[1], str) and (type(item[2]) is int) and (0 <= item[2] <= body_length) for item in references)), f'{context}.expected_code_symbol_references is invalid')
    registers = value.get('expected_debug_s_registers')
    require(isinstance(registers, list) and all((isinstance(item, list) and len(item) == 3 and isinstance(item[0], str) and (type(item[1]) is int) and (item[1] >= 0) and (item[2] in CODEVIEW_X86_REGISTER_NUMBERS) for item in registers)), f'{context}.expected_debug_s_registers is invalid')
    rationale = value.get('authenticity_rationale')
    require(isinstance(rationale, str) and len(rationale) >= 40, f'{context}.authenticity_rationale is missing')
    normalized = {'kind': WEB_RECOLOUR_KIND, 'webs': normalized_webs, 'expected_instruction_count': require_exact_int(value.get('expected_instruction_count'), f'{context}.expected_instruction_count', minimum=2), 'expected_changed_offsets': list(changed), 'expected_procedure_range': list(procedure), 'expected_code_symbol_references': [list(item) for item in references], 'expected_debug_s_registers': [list(item) for item in registers], 'authenticity_rationale': rationale}
    if normalized_windows:
        normalized['windows'] = normalized_windows
    if normalized_trailing:
        normalized['trailing_windows'] = normalized_trailing
    if code_length is not None:
        normalized['expected_code_length'] = code_length
    if targets is not None:
        normalized['expected_internal_relocation_targets'] = list(targets)
    return normalized

def produce_web_recolour_candidate(seed_bytes: bytes, donor_bytes: bytes, function: dict) -> tuple[bytes, dict]:
    """Produce a recoloured def-use web from compiler output.

    See the class comment above.  The pre-image is the SEED's own
    compiler-produced body -- no donor bytes are installed, and the donor the
    manifest names is required to reproduce that body exactly, which is what
    makes it a provenance witness rather than decoration.  A declared
    reordering is applied first through the unchanged
    `apply_instruction_schedule` primitive; every web obligation is then
    measured on the reordered body. Installation is delegated, unchanged, to
    the equal-body primitive; literal comparison remains verifier-only.
    """
    require_payload_free_declaration(function, 'web-recolour declaration')
    require(function.get('splice_class') == WEB_RECOLOUR_CLASS, 'splice class is not retail_exact_web_recolour')
    require('target_source_refactor' not in function, 'web-recolour functions carry no source refactor')
    spec = function['web_recolour']
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function['mangled']
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(sp['number'] == dp['number'] == function['expected_section_number'], 'web-recolour target section seat changed')
    require(len(seed.sections) == len(donor.sections) == function['expected_section_count'], 'web-recolour global section count changed')
    seed_functions = function_multiset(seed)
    require(seed_functions == function_multiset(donor) and sum(seed_functions.values()) == function['expected_function_count'], 'web-recolour donor function set differs')
    seed_comdats = comdat_primary_identity_multiset(seed)
    require(seed_comdats == comdat_primary_identity_multiset(donor) and sum(seed_comdats.values()) == function['expected_comdat_count'], 'web-recolour donor COMDAT identity set differs')
    require(sp['raw_size'] == dp['raw_size'] == function['expected_body_length'] and sp['relocation_count'] == dp['relocation_count'] == function['expected_relocation_count'] and (sp['line_count'] == function['expected_seed_line_count']) and (dp['line_count'] == function['expected_donor_line_count']) and (sp['name'] == dp['name']) and (sp['characteristics'] == dp['characteristics'] == function['expected_characteristics']), 'web-recolour target header/count pins changed')
    require(section_definitions(seed)[sp['number']]['selection'] == section_definitions(donor)[dp['number']]['selection'] == function['expected_selection'], 'web-recolour COMDAT selection changed')
    expected_closure = tuple(function['expected_closure'])
    require(_comdat_child_closure(seed, sp) == _comdat_child_closure(donor, dp) == (len(expected_closure), expected_closure), 'web-recolour target closure changed')
    require(list(expected_closure) == INSTRUCTION_SCHEDULE_FPO_CLOSURE or list(expected_closure) == ['.debug$S', '.xdata$x'], 'web-recolour closure pin names no installation delegate')
    installation_delegate = 'equal_body_strict' if list(expected_closure) == INSTRUCTION_SCHEDULE_FPO_CLOSURE else 'equal_body_eh_structural_local'
    require(instruction_mosaic_metadata_sha256(seed, sp) == function['expected_seed_metadata_sha256'] and instruction_mosaic_metadata_sha256(donor, dp) == function['expected_donor_metadata_sha256'], 'web-recolour metadata differs from its pin')
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(sha256_bytes(seed_body) == function['expected_seed_body_sha256'] and sha256_bytes(donor_body) == function['expected_donor_body_sha256'], 'web-recolour seed/donor body differs from its pin')
    require(donor_body == seed_body, "web-recolour donor does not reproduce the seed's body")
    seed_rows = detailed_relocations(seed, sp)
    relocation_offsets = frozenset((row['offset'] + byte for row in seed_rows for byte in range(row['width'])))
    relocation_symbols = {row['offset']: {'width': row['width'], 'target': row['target']} for row in seed_rows}
    internal_targets = frozenset((row['target_value'] for row in seed_rows if row['target_section'] == sp['number']))
    declared_targets = spec.get('expected_internal_relocation_targets')
    if declared_targets is not None:
        require(sorted(internal_targets) == declared_targets, 'web-recolour in-body relocated target set changed')
    code_length = spec.get('expected_code_length')

    def _schedule(windows, phase):
        nonlocal image
        if not windows:
            return []
        image, schedule_proof = apply_instruction_schedule(image, windows, relocation_offsets, f'web-recolour {phase}', relocation_symbols, code_length, internal_targets)
        require(not schedule_proof['relocation_reseat'], 'web-recolour refuses to move a relocation')
        return schedule_proof['windows']
    image = seed_body
    schedule_detail = _schedule(spec.get('windows') or [], 'schedule')
    declared_fpo = spec.get('expected_fpo_record')
    names_ebp = any(('ebp' in {web.get('source_register'), web.get('image_register')} for web in spec['webs']))
    require(declared_fpo is not None or not names_ebp, 'web-recolour names EBP without a frame-pointer-free record')
    if declared_fpo is not None:
        measured = require_frame_pointer_free_frame(seed, sp, seed_body, decode_ia32_bijection_body(seed_body, 'web-recolour frame proof', relocation_symbols, code_length), 'web-recolour frame proof')
        require({key: value for key, value in measured.items() if key != 'raw_sha256'} == declared_fpo, 'web-recolour FPO record differs from its declaration')
    image, proof = apply_web_recolour(image, spec['webs'], relocation_offsets, 'web-recolour image', relocation_symbols, code_length, internal_targets, declared_fpo is not None, frozenset(relational_form_external_entries(seed, sp, 'web-recolour funclet entries')))
    require(proof['code_length'] == (code_length or len(seed_body)), 'web-recolour code length differs from its pin')
    require(proof['instruction_count'] == spec['expected_instruction_count'], 'web-recolour instruction count differs from its declaration')
    schedule_detail = schedule_detail + _schedule(spec.get('trailing_windows') or [], 'trailing schedule')
    changed = sorted((index for index in range(len(seed_body)) if seed_body[index] != image[index]))
    require(changed == spec['expected_changed_offsets'], 'web-recolour image differs from its declaration')
    require(sha256_bytes(image) == function['expected_body_sha256'], 'web-recolour image differs from its pin')
    require(changed == function['expected_changed_offsets'], 'web-recolour changed offsets differ from their pin')
    debug_detail = require_instruction_schedule_debug_fidelity(seed, sp, image, (spec.get('windows') or []) + (spec.get('trailing_windows') or []), spec, mangled, 'web-recolour debug fidelity', relocation_symbols, code_length, internal_targets)
    debug_registers = require_web_recolour_debug_registers(coff_body(seed, _comdat_child(seed, sp, '.debug$S')), spec['expected_debug_s_registers'], 'web-recolour debug registers')
    pinned_length = function['retail_oracle']['length']
    require(pinned_length == len(image), 'web-recolour linked length changed')
    semantic_detail = require_declared_relocation_semantics(
        seed_rows,
        function['retail_relocations'],
        'web-recolour candidate relocation semantics',
    )
    derived = bytearray(seed_bytes)
    derived[sp['raw_offset']:sp['raw_offset'] + sp['raw_size']] = image
    effective = {'mangled': mangled, 'splice_class': installation_delegate, 'expected_body_length': function['expected_body_length'], 'expected_body_sha256': function['expected_body_sha256'], 'expected_changed_offsets': function['expected_changed_offsets']}
    if installation_delegate == 'equal_body_eh_structural_local':
        effective['expected_code_renames'] = []
        effective['expected_xdata_rename_offsets'] = []
    composed, detail = compose_equal_body_comdat(seed_bytes, bytes(derived), effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, 'web-recolour composed body differs from the image')
    require(detailed_relocations(checked, cp) == seed_rows and _coff_table_bytes(checked, cp, 'relocations') == _coff_table_bytes(seed, sp, 'relocations') and (_coff_table_bytes(checked, cp, 'lines') == _coff_table_bytes(seed, sp, 'lines')), 'web-recolour output changed seed relocation/line bytes')
    for child_name in expected_closure:
        require(coff_body(checked, _comdat_child(checked, cp, child_name)) == coff_body(seed, _comdat_child(seed, sp, child_name)), f'web-recolour output changed its {child_name} child')
    allowed = set(range(sp['raw_offset'], sp['raw_offset'] + sp['raw_size']))
    require({index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]} <= allowed, 'web-recolour changed bytes outside its own COMDAT')
    return (composed, {**detail, 'splice_class': WEB_RECOLOUR_CLASS, 'instruction_schedule': schedule_detail, 'web_recolour': proof['webs'], 'instruction_count': proof['instruction_count'], 'changed_offsets': changed, 'debug_fidelity': debug_detail, 'debug_s_registers': debug_registers, 'candidate_only': True, **semantic_detail})

def validate_instruction_schedule(value: object, context: str, body_length: int) -> dict:
    """Validate one instruction-schedule certificate declaration."""
    require(isinstance(value, dict), f'{context} must be an object')
    exact_audit_keys(value, {'kind', 'windows', 'expected_instruction_count', 'expected_changed_offsets', 'expected_procedure_range', 'expected_code_symbol_references', 'authenticity_rationale', 'expected_code_length', 'expected_internal_relocation_targets'}, context, optional={'expected_code_length', 'expected_internal_relocation_targets'})
    require(value.get('kind') == INSTRUCTION_SCHEDULE_KIND, f'{context}.kind differs')
    code_length = value.get('expected_code_length')
    if code_length is not None:
        code_length = require_exact_int(code_length, f'{context}.expected_code_length', minimum=2, maximum=body_length)
    targets = value.get('expected_internal_relocation_targets')
    if targets is not None:
        require(isinstance(targets, list) and targets == sorted(set(targets)) and all((type(item) is int and 0 <= item < body_length for item in targets)), f'{context}.expected_internal_relocation_targets is invalid')
    windows = value.get('windows')
    require(isinstance(windows, list) and 1 <= len(windows) <= 32, f'{context}.windows must contain 1..32 windows')
    normalized_windows = _validate_schedule_windows(windows, context, body_length, code_length, targets)
    changed = value.get('expected_changed_offsets')
    require(isinstance(changed, list) and changed and (changed == sorted(set(changed))) and all((type(offset) is int and any((item['start'] <= offset < item['end'] for item in normalized_windows)) for offset in changed)), f'{context}.expected_changed_offsets is invalid')
    procedure = value.get('expected_procedure_range')
    require(isinstance(procedure, list) and len(procedure) == 3 and all((type(item) is int and item >= 0 for item in procedure)) and (procedure[0] == body_length) and (procedure[1] <= procedure[2] <= body_length), f'{context}.expected_procedure_range is invalid')
    references = value.get('expected_code_symbol_references')
    require(isinstance(references, list) and all((isinstance(item, list) and len(item) == 3 and isinstance(item[0], str) and isinstance(item[1], str) and (type(item[2]) is int) and (0 <= item[2] <= body_length) for item in references)), f'{context}.expected_code_symbol_references is invalid')
    rationale = value.get('authenticity_rationale')
    require(isinstance(rationale, str) and len(rationale) >= 40, f'{context}.authenticity_rationale is missing')
    normalized = {'kind': INSTRUCTION_SCHEDULE_KIND, 'windows': normalized_windows, 'expected_instruction_count': require_exact_int(value.get('expected_instruction_count'), f'{context}.expected_instruction_count', minimum=2), 'expected_changed_offsets': list(changed), 'expected_procedure_range': list(procedure), 'expected_code_symbol_references': [list(item) for item in references], 'authenticity_rationale': rationale}
    if code_length is not None:
        normalized['expected_code_length'] = code_length
    if targets is not None:
        normalized['expected_internal_relocation_targets'] = list(targets)
    return normalized
WEB_RECOLOUR_CLASS = 'retail_exact_web_recolour'
WEB_RECOLOUR_KIND = 'web_recolour_v1'

def ia32_web_control_flow(instructions: list[dict], context: str, internal_targets: frozenset | None=None, entry_offsets: frozenset | None=None) -> list[list[int]]:
    """The body's complete control-flow graph, or a refusal.

    Successors are the fall-through and the decoded branch target.  A computed
    jump has no decodable successors, so it is admitted only against the
    relocated in-body target set, whose in-code members become its successors.
    `ret` and a relocated tail-jump out of the COMDAT have none.  Every
    instruction must then be reachable from an entry: an unreachable block
    would make every reaching-definition statement about it vacuous.  The
    entries are the function head plus `entry_offsets` -- on a C++ EH function
    the unwind funclet heads the `.xdata$x` table hands to the runtime, a
    DERIVED set (`relational_form_external_entries`), never an author's claim.
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
        if item['flow'] in ('jcc', 'jmp') and item['target'] is not None:
            edges.append(index_of[item['target']])
        if item['indirect']:
            require(internal_targets is not None, f"{context}: a computed jump at {item['offset']} requires the relocated in-body target set")
            edges.extend((index_of[target] for target in sorted(internal_targets) if target in index_of))
        successors.append(sorted(set(edges)))
    seen = set()
    stack = [0]
    if entry_offsets:
        stack.extend((index_of[offset] for offset in sorted(entry_offsets) if offset in index_of))
    while stack:
        index = stack.pop()
        if index in seen:
            continue
        seen.add(index)
        stack.extend(successors[index])
    unreachable = sorted((instructions[index]['offset'] for index in range(len(instructions)) if index not in seen))
    require(not unreachable, f'{context}: the instruction at {unreachable[:1]} is unreachable from the entry, so the control-flow graph is incomplete')
    return successors

def _ia32_web_predecessors(successors: list[list[int]]) -> list[list[int]]:
    predecessors = [[] for _ in successors]
    for index, edges in enumerate(successors):
        for edge in edges:
            predecessors[edge].append(index)
    return predecessors

def _ia32_web_reached_uses(instructions: list[dict], successors: list[list[int]], definitions: list[int], atoms: frozenset, context: str) -> tuple[set, set]:
    """Every reader of `atoms` a definition reaches, and the range between.

    Traversal stops at a full redefinition.  A PARTIAL redefinition inside the
    range refuses: the value would be half the web's and half something else,
    which no rename can express.
    """
    reached = set()
    interior = set()
    stack = [edge for index in definitions for edge in successors[index]]
    while stack:
        index = stack.pop()
        if index in interior:
            continue
        interior.add(index)
        item = instructions[index]
        if atoms & item['read_atoms']:
            reached.add(index)
        overlap = atoms & item['write_atoms']
        if overlap:
            require(atoms <= item['write_atoms'], f"{context}: the instruction at {item['offset']} partially redefines the web's register inside its range")
            continue
        stack.extend(successors[index])
    return (reached, interior)

def _ia32_web_reaching_definitions(instructions: list[dict], predecessors: list[list[int]], uses: list[int], atoms: frozenset, context: str) -> tuple[set, set]:
    """Every definition of `atoms` that reaches one of `uses`.

    Also returns the backward cone -- every instruction that can reach a use
    without passing a redefinition.  Intersected with the forward cone that
    is the web's LIVE RANGE, and nothing outside it is the coalesce's concern.
    """
    reaching = set()
    seen = set()
    stack = list(uses)
    while stack:
        index = stack.pop()
        if index in seen:
            continue
        seen.add(index)
        require(index != 0 or index in uses, f"{context}: the function's entry reaches a declared use, so the web's value is not defined on every path")
        for previous in predecessors[index]:
            item = instructions[previous]
            if atoms & item['write_atoms']:
                require(atoms <= item['write_atoms'], f"{context}: the instruction at {item['offset']} partially defines the web's register")
                reaching.add(previous)
            else:
                stack.append(previous)
        require(predecessors[index] or index in uses, f"{context}: the instruction at {instructions[index]['offset']} has no predecessor, so a use is reached by no definition")
    return (reaching, seen)

def _ia32_web_membership(web: dict, role: str, context: str) -> tuple:
    """Split a web's membership list into offsets and their field scopes.

    An entry is an instruction offset, or a two-element `[offset, ordinal]`
    pair naming WHICH register field of that instruction belongs to the web.
    Both the manifest schema and the composer read membership through here,
    so a declaration means the same thing on both sides -- the composer is
    handed the RAW manifest dict, and a normalizer that lived only in the
    schema would be silently bypassed.
    """
    entries = web.get(role)
    require(isinstance(entries, list) and entries, f'{context}.{role} is invalid')
    offsets = []
    scopes = {}
    for item in entries:
        if type(item) is int:
            offsets.append(item)
            continue
        require(isinstance(item, list) and len(item) == 2 and (type(item[0]) is int) and (type(item[1]) is int) and (item[1] >= 0), f'{context}.{role} entry is invalid')
        require(item[0] not in scopes, f'{context}.{role} scopes {item[0]} twice')
        scopes[item[0]] = item[1]
        offsets.append(item[0])
    declared = web.get('field_scopes') or {}
    for offset, ordinal in declared.items():
        offset = int(offset)
        require(offset not in scopes or scopes[offset] == ordinal, f'{context}.{role} scopes {offset} twice')
        if offset in offsets:
            scopes[offset] = ordinal
    return (offsets, scopes)

def apply_web_recolour(body: bytes, webs: list[dict], relocation_offsets: frozenset, context: str, relocations: dict | None=None, code_length: int | None=None, internal_targets: frozenset | None=None, frame_pointer_free: bool=False, entry_offsets: frozenset | None=None) -> tuple[bytes, dict]:
    """Recolour each declared web, proving W1..W7 on the body it is given.

    Webs are applied in order and each one's proof is measured on the body the
    previous ones produced, so a certificate that declares several is a
    composition of individually proved steps.
    """
    require_payload_free_declaration(webs, f'{context} web-recolour declaration')
    body = bytes(body)
    image = bytes(body)
    detail = []
    rewritten_all = []
    instruction_count = None
    for position, web in enumerate(webs):
        web_context = f'{context} web {position}'
        instructions = decode_ia32_bijection_body(image, web_context, relocations, code_length)
        instruction_count = len(instructions)
        successors = ia32_web_control_flow(instructions, web_context, internal_targets, entry_offsets)
        predecessors = _ia32_web_predecessors(successors)
        index_of = {item['offset']: index for index, item in enumerate(instructions)}
        source = web['source_register']
        target = web['image_register']
        require(source in _IA32_REGISTER_NUMBERS and target in _IA32_REGISTER_NUMBERS and (source != target), f'{web_context}: the recolour names an unknown register')
        structural = {'esp'} if frame_pointer_free else _IA32_STRUCTURAL_REGISTERS
        require(not {source, target} & structural, f'{web_context}: the recolour touches ' + ('ESP' if frame_pointer_free else 'ESP or EBP') + ', whose encodings carry ModRM/SIB structure')
        source_atoms = ia32_register_atoms({source})
        target_atoms = ia32_register_atoms({target})
        source_number = _IA32_REGISTER_NUMBERS[source]
        target_number = _IA32_REGISTER_NUMBERS[target]
        definition_offsets, field_scopes = _ia32_web_membership(web, 'definitions', web_context)
        use_offsets, use_scopes = _ia32_web_membership(web, 'uses', web_context)
        for offset, ordinal in use_scopes.items():
            require(offset not in field_scopes, f'{web_context} scopes {offset} twice')
            field_scopes[offset] = ordinal
        for role, offsets in (('definitions', definition_offsets), ('uses', use_offsets)):
            for offset in offsets:
                require(offset in index_of, f'{web_context}: {role} names {offset}, which is not an instruction boundary of this body')
        definitions = [index_of[offset] for offset in definition_offsets]
        uses = [index_of[offset] for offset in use_offsets]
        through = set(definitions) & set(uses)
        for index in sorted(through):
            item = instructions[index]
            require(source_atoms <= item['read_atoms'] and source_atoms <= item['write_atoms'], f"{web_context}: the instruction at {item['offset']} is declared as both a definition and a use but does not read and write the whole register")
            require(item['offset'] not in field_scopes, f"{web_context}: the read-modify-write node at {item['offset']} carries the whole web, so it cannot also be field-scoped")
        for index in definitions:
            item = instructions[index]
            require(source_atoms <= item['write_atoms'], f"{web_context}: the declared definition at {item['offset']} does not define the whole register")
            require(not source_atoms & item['read_atoms'] or item['offset'] in field_scopes or index in through, f"{web_context}: the declared definition at {item['offset']} also reads the source register")
            require(target not in item['writes'], f"{web_context}: the declared definition at {item['offset']} already writes the image register")
        for index in uses:
            item = instructions[index]
            require(source_atoms <= item['read_atoms'] and (not source_atoms & item['write_atoms'] or item['offset'] in field_scopes or index in through), f"{web_context}: the declared use at {item['offset']} does not read the whole register without defining it")
            require(target not in item['reads'] and target not in item['writes'], f"{web_context}: the declared use at {item['offset']} already names the image register")
        reached, forward = _ia32_web_reached_uses(instructions, successors, definitions, source_atoms, web_context)
        require(reached == set(uses), f"{web_context}: the definitions reach the uses at {sorted((instructions[index]['offset'] for index in reached))}, which is not the declared use set")
        reaching, backward = _ia32_web_reaching_definitions(instructions, predecessors, uses, source_atoms, web_context)
        require(reaching == set(definitions), f"{web_context}: the uses are reached by the definitions at {sorted((instructions[index]['offset'] for index in reaching))}, which is not the declared definition set")
        interior = forward & backward | set(uses)
        live = _ia32_backward_liveness(instructions, successors, web_context)
        for index in definitions:
            leaking = target_atoms & _ia32_live_out(live, successors, index)
            require(not leaking, f"{web_context}: {_ia32_atom_registers(leaking)} is live on an out-edge of the definition at {instructions[index]['offset']}, so the two live ranges overlap and cannot be coalesced")
        for index in sorted(interior):
            item = instructions[index]
            if index in uses:
                require(not target_atoms & item['write_atoms'], f"{web_context}: the use at {item['offset']} defines the image register")
                continue
            touching = target_atoms & (item['read_atoms'] | item['write_atoms'])
            require(not touching, f"{web_context}: the instruction at {item['offset']} names {_ia32_atom_registers(touching)} inside the web's live range")
            leaking = target_atoms & live[index]
            require(not leaking, f"{web_context}: {_ia32_atom_registers(leaking)} is live at {item['offset']}, inside the web's live range")
        blind = _ia32_backward_liveness(instructions, successors, web_context, {index: source_atoms for index in uses})
        for index in definitions:
            leaking = source_atoms & _ia32_live_out(blind, successors, index)
            require(not leaking, f"{web_context}: {_ia32_atom_registers(leaking)} still has a consumer outside the web at {instructions[index]['offset']}")
        buffer = bytearray(image)
        rewritten = []
        for index in sorted(set(definitions) | set(uses)):
            item = instructions[index]
            blocked = {source, target} & set(item.get('frozen', frozenset()))
            require(not blocked, f"{web_context}: {sorted(blocked)} is named by a sub-register field at {item['offset']} that the recolour cannot rewrite")
            ordinal = field_scopes.get(item['offset'])
            if ordinal is None:
                hits = [(byte_index, shift) for byte_index, shift in item['fields'] if buffer[byte_index] >> shift & 7 == source_number]
                require(len(hits) == 1 or (len(hits) > 1 and (not item['writes'])), f"{web_context}: the instruction at {item['offset']} names {source} in {len(hits)} register fields, so which occurrence belongs to the web is not decidable")
                if len(hits) > 1:
                    for byte_index, shift in hits[1:]:
                        buffer[byte_index] = buffer[byte_index] & ~(7 << shift) | target_number << shift
                        rewritten.append(byte_index)
                byte_index, shift = hits[0]
            else:
                require(ordinal < len(item['fields']), f"{web_context}: the instruction at {item['offset']} has no register field {ordinal}")
                byte_index, shift = item['fields'][ordinal]
                require(buffer[byte_index] >> shift & 7 == source_number, f"{web_context}: register field {ordinal} at {item['offset']} does not name {source}")
            require(byte_index not in relocation_offsets, f'{web_context}: a rewritten byte overlaps a relocation')
            buffer[byte_index] = (buffer[byte_index] & ~(7 << shift) | target_number << shift) & 255
            rewritten.append(byte_index)
        require(rewritten, f'{web_context}: the recolour rewrites nothing')
        candidate = bytes(buffer)
        require(len(candidate) == len(image), f'{web_context}: the recolour changed the body length')
        image_instructions = decode_ia32_bijection_body(candidate, f'{web_context} image', relocations, code_length)
        require([(item['offset'], item['length']) for item in image_instructions] == [(item['offset'], item['length']) for item in instructions], f'{web_context}: the image changed an instruction boundary')
        mapping = {source: target}
        for left, right in zip(image_instructions, instructions):
            form = _bijection_form_for(right['opcode'])
            opreg = form is not None and form['opreg'] is not None
            mask = 248 if opreg else 65535
            require(left['opcode'] & mask == right['opcode'] & mask and left['flow'] == right['flow'] and (left['target'] == right['target']), f'{web_context}: the image changed an opcode or a branch')
            offset = right['offset']
            is_definition = offset in definition_offsets
            recoloured = is_definition or offset in use_offsets
            scoped = recoloured and offset in field_scopes
            rename_reads = recoloured and (not (scoped and is_definition))
            rename_writes = recoloured and (not (scoped and (not is_definition)))
            expected_reads = frozenset((mapping.get(name, name) if rename_reads else name for name in right['reads']))
            expected_writes = frozenset((mapping.get(name, name) if rename_writes else name for name in right['writes']))
            require(left['reads'] == expected_reads and left['writes'] == expected_writes, f"{web_context}: the image's operand set at {right['offset']} is not the recolour's image")
        changed = sorted({index for index in range(len(image)) if image[index] != candidate[index]})
        require(changed == sorted(set(rewritten)), f'{web_context}: the image changed a byte the recolour did not name')
        require(changed == list(web['expected_rewritten_offsets']), f'{web_context}: the rewritten offset set {changed} differs from its declaration')
        entry = {'source_register': source, 'image_register': target, 'definitions': list(definition_offsets), 'uses': list(use_offsets), 'live_range': sorted((instructions[index]['offset'] for index in interior)), 'rewritten_offsets': changed}
        if field_scopes:
            entry['field_scopes'] = {str(offset): ordinal for offset, ordinal in sorted(field_scopes.items())}
        detail.append(entry)
        rewritten_all.extend(changed)
        image = candidate
    require(image != body, f'{context}: the recolour moves nothing')
    return (image, {'webs': detail, 'instruction_count': instruction_count, 'rewritten_offsets': sorted(set(rewritten_all)), 'code_length': len(body) if code_length is None else code_length})

def require_web_recolour_debug_registers(stream: bytes, declared: list, context: str) -> list:
    """W8.  Pin the `.debug$S` S_REGISTER record list.

    The recolour leaves the stream alone.  That is sound rather than
    optimistic because of W4 and W5: no value of the image register is live
    anywhere in the web's range, and no value of the source register survives
    a definition, so no named register local can BE the web and none can span
    it.  What is pinned here is that the record list has not changed -- a
    different allocation would produce a different one and must be re-proved.
    """
    records = parse_codeview_symbol_stream(stream, context)
    measured = []
    for record in records:
        if record['type'] != CODEVIEW_REGISTER_RECORD_TYPE:
            continue
        field_at = _codeview_register_field(record, context)
        measured.append([record['name'], record['offset'], _codeview_register_name(stream, field_at, context)])
    require(measured == [list(item) for item in declared], f'{context}: the S_REGISTER record list {measured} differs from its declaration')
    return measured
INSTRUCTION_SCHEDULE_EDGE_REASONS = frozenset({'register_raw', 'register_war', 'register_waw', 'flags_raw', 'flags_war', 'flags_waw', 'memory'})

def produce_instruction_schedule_candidate(seed_bytes: bytes, donor_bytes: bytes, function: dict) -> tuple[bytes, dict]:
    """Produce a topological reordering from compiler output.

    See the class comment above: this is a certificate.  The pre-image is an
    ordinary, census-pinned compile of the same translation unit; the
    reordering is proved to respect the window's own dependence DAG. Body
    installation itself is delegated, unchanged, to the
    equal-body primitive.
    """
    require_payload_free_declaration(function, 'instruction-schedule declaration')
    require(function.get('splice_class') == INSTRUCTION_SCHEDULE_CLASS, 'splice class is not retail_exact_instruction_schedule')
    require('target_source_refactor' not in function, 'instruction-schedule functions carry no source refactor')
    spec = function['instruction_schedule']
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function['mangled']
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(sp['number'] == function['expected_section_number'] and dp['number'] == function['expected_donor_section_number'], 'instruction-schedule target section seat changed')
    require(len(seed.sections) == len(donor.sections) == function['expected_section_count'], 'instruction-schedule global section count changed')
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    require(seed_functions == donor_functions and sum(seed_functions.values()) == function['expected_function_count'], 'instruction-schedule donor function set differs')
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    require(seed_comdats == donor_comdats and sum(seed_comdats.values()) == function['expected_comdat_count'], 'instruction-schedule donor COMDAT identity set differs')
    require(sp['raw_size'] == dp['raw_size'] == function['expected_body_length'] and sp['relocation_count'] == dp['relocation_count'] == function['expected_relocation_count'] and (sp['line_count'] == function['expected_seed_line_count']) and (dp['line_count'] == function['expected_donor_line_count']) and (sp['name'] == dp['name']) and (sp['characteristics'] == dp['characteristics'] == function['expected_characteristics']), 'instruction-schedule target header/count pins changed')
    require(section_definitions(seed)[sp['number']]['selection'] == section_definitions(donor)[dp['number']]['selection'] == function['expected_selection'], 'instruction-schedule COMDAT selection changed')
    expected_closure = tuple(function['expected_closure'])
    require(_comdat_child_closure(seed, sp) == _comdat_child_closure(donor, dp) == (len(expected_closure), expected_closure), 'instruction-schedule target closure changed')
    require(list(expected_closure) in (INSTRUCTION_SCHEDULE_FPO_CLOSURE, INSTRUCTION_SCHEDULE_EH_CLOSURE), 'instruction-schedule closure pin names no installation delegate')
    reseat_declared = any((window.get('relocation_reseat') for window in spec['windows']))
    delegate = instruction_schedule_delegate(function['expected_closure'], function['expected_code_renames'], reseat_declared)
    require(instruction_mosaic_metadata_sha256(seed, sp) == function['expected_seed_metadata_sha256'] and instruction_mosaic_metadata_sha256(donor, dp) == function['expected_donor_metadata_sha256'], 'instruction-schedule metadata differs from its pin')
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(sha256_bytes(seed_body) == function['expected_seed_body_sha256'] and sha256_bytes(donor_body) == function['expected_donor_body_sha256'], 'instruction-schedule seed/donor body differs from its pin')
    code_renames = require_instruction_mosaic_semantic_relocations(seed, sp, donor, dp, 'instruction-schedule code')
    require([[offset, kind] for offset, kind in code_renames] == function['expected_code_renames'], 'instruction-schedule code rename set changed')
    seed_rows = detailed_relocations(seed, sp)
    donor_rows = detailed_relocations(donor, dp)
    seed_targets = {row['offset']: row['target'] for row in seed_rows}
    donor_targets = {row['offset']: row['target'] for row in donor_rows}
    require([[offset, seed_targets.get(offset), donor_targets.get(offset)] for offset, _ in code_renames] == function.get('expected_code_rename_symbols', []), 'instruction-schedule code rename symbol pair changed')
    require([(row['offset'], row['type'], row['addend']) for row in seed_rows] == [(row['offset'], row['type'], row['addend']) for row in donor_rows], 'instruction-schedule donor relocation layout differs from the seed')
    require([(row['offset'], row['target']) for row in seed_rows if row['type'] == 20] == [(row['offset'], row['target']) for row in donor_rows if row['type'] == 20], 'instruction-schedule donor call/branch relocation targets differ from the seed')
    relocation_offsets = frozenset((row['offset'] + byte for row in seed_rows for byte in range(row['width'])))
    relocation_symbols = {row['offset']: {'width': row['width'], 'target': row['target']} for row in seed_rows}
    internal_targets = frozenset((row['target_value'] for row in donor_rows if row['target_section'] == dp['number']))
    declared_targets = spec.get('expected_internal_relocation_targets')
    if declared_targets is not None:
        require(sorted(internal_targets) == declared_targets, 'instruction-schedule in-body relocated target set changed')
    image, proof = apply_instruction_schedule(donor_body, spec['windows'], relocation_offsets, 'instruction-schedule image', relocation_symbols, spec.get('expected_code_length'), internal_targets)
    require(proof['code_length'] == (spec.get('expected_code_length') or len(donor_body)), 'instruction-schedule code length differs from its pin')
    require(proof['changed_offsets'] == spec['expected_changed_offsets'] and proof['instruction_count'] == spec['expected_instruction_count'], 'instruction-schedule image differs from its declaration')
    require(sha256_bytes(image) == function['expected_body_sha256'], 'instruction-schedule image differs from its pin')
    require(image != donor_body, 'instruction-schedule image does not move the donor body')
    moved = {old_offset: new_offset for old_offset, new_offset in proof['relocation_reseat']}
    require(bool(moved) == reseat_declared, 'instruction-schedule reseat declaration and measurement differ')
    if moved:
        require(function.get('expected_relocation_moves') == [[old_offset, new_offset] for old_offset, new_offset in proof['relocation_reseat'] if old_offset != new_offset], 'instruction-schedule relocation move set differs from its pin')
    image_rows = []
    for row in seed_rows:
        if row['offset'] in moved:
            row = dict(row)
            row['offset'] = moved[row['offset']]
        image_rows.append(row)
    require([row['offset'] for row in image_rows] == sorted((row['offset'] for row in image_rows)), "instruction-schedule reseat breaks the relocation table's ascending offset order")
    image_relocation_symbols = {row['offset']: {'width': row['width'], 'target': row['target']} for row in image_rows}
    require(len(image_relocation_symbols) == len(image_rows), 'instruction-schedule reseat collides two relocation records')
    debug_detail = require_instruction_schedule_debug_fidelity(seed, sp, image, spec['windows'], spec, mangled, 'instruction-schedule debug fidelity', image_relocation_symbols, spec.get('expected_code_length'), internal_targets)
    pinned_length = function['retail_oracle']['length']
    require(pinned_length == len(image), 'instruction-schedule linked length changed')
    semantic_detail = require_declared_relocation_semantics(
        image_rows,
        function['retail_relocations'],
        'instruction-schedule candidate relocation semantics',
    )
    derived = bytearray(donor_bytes)
    derived[dp['raw_offset']:dp['raw_offset'] + dp['raw_size']] = image
    if moved:
        for ordinal, row in enumerate(donor_rows):
            if row['offset'] not in moved:
                continue
            record_at = dp['relocation_offset'] + ordinal * 10
            derived[record_at:record_at + 4] = moved[row['offset']].to_bytes(4, 'little')
    derived = bytes(derived)
    effective = {'mangled': mangled, 'splice_class': delegate, 'expected_body_length': function['expected_body_length'], 'expected_body_sha256': function['expected_body_sha256'], 'expected_changed_offsets': function['expected_changed_offsets']}
    if delegate == 'equal_body_eh_structural_local':
        effective['expected_code_renames'] = function['expected_code_renames']
        effective['expected_xdata_rename_offsets'] = function['expected_xdata_rename_offsets']
    if delegate == 'equal_body_eh_reloc_layout':
        effective['expected_relocation_moves'] = function['expected_relocation_moves']
        effective['expected_xdata_rename_offsets'] = function['expected_xdata_rename_offsets']
    composed, detail = compose_equal_body_comdat(seed_bytes, derived, effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, 'instruction-schedule composed body differs from the image')
    expected_relocation_table = bytearray(_coff_table_bytes(seed, sp, 'relocations'))
    for ordinal, row in enumerate(seed_rows):
        if row['offset'] in moved:
            record_at = ordinal * 10
            expected_relocation_table[record_at:record_at + 4] = moved[row['offset']].to_bytes(4, 'little')
    require(detailed_relocations(checked, cp) == image_rows and _coff_table_bytes(checked, cp, 'relocations') == bytes(expected_relocation_table) and (_coff_table_bytes(checked, cp, 'lines') == _coff_table_bytes(seed, sp, 'lines')), 'instruction-schedule output changed seed relocation/line bytes')
    for child_name in expected_closure:
        require(coff_body(checked, _comdat_child(checked, cp, child_name)) == coff_body(seed, _comdat_child(seed, sp, child_name)), f'instruction-schedule output changed its {child_name} child')
    allowed = set(range(sp['raw_offset'], sp['raw_offset'] + sp['raw_size']))
    if moved:
        allowed |= {sp['relocation_offset'] + ordinal * 10 + byte for ordinal, row in enumerate(seed_rows) if row['offset'] in moved for byte in range(4)}
    require({index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]} <= allowed, 'instruction-schedule changed bytes outside its own COMDAT')
    return (composed, {**detail, 'splice_class': INSTRUCTION_SCHEDULE_CLASS, 'instruction_schedule': proof['windows'], 'instruction_count': proof['instruction_count'], 'changed_offsets': proof['changed_offsets'], 'debug_fidelity': debug_detail, 'relocation_reseat': proof['relocation_reseat'], 'candidate_only': True, **semantic_detail})
