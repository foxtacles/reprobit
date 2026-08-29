from __future__ import annotations

from reprobit.binary import require
from reprobit.ia32 import supported_ia32_instruction_length

from .foundation import require_payload_free_declaration
from .relational import ia32_relational_flow_walk

"""Classic compiler algorithms: floating."""
FP_SUM_REASSOCIATION_KIND = 'fp_sum_reassociation_v1'

def _fp_sum_parse_chain(body: bytes, start: int, end: int, context: str) -> list[dict]:
    """Parse [start, end) into PAIR / FADDP slots, or refuse."""
    slots = []
    offset = start
    pending_fld = None
    while offset < end:
        length = supported_ia32_instruction_length(body[offset:], context)
        require(offset + length <= end, f'{context}: an instruction straddles the chain boundary at {offset}')
        encoded = body[offset:offset + length]
        opcode = encoded[0]
        if opcode == 221 and length >= 2 and (encoded[1] >> 6 != 3) and (encoded[1] >> 3 & 7 == 0):
            require(pending_fld is None, f'{context}: two fld in a row at {offset} -- not a product pair')
            pending_fld = (offset, length)
        elif opcode == 220 and length >= 2 and (encoded[1] >> 6 != 3) and (encoded[1] >> 3 & 7 == 1):
            require(pending_fld is not None, f'{context}: fmul without its fld at {offset}')
            slots.append({'kind': 'pair', 'offset': pending_fld[0], 'length': pending_fld[1] + length})
            pending_fld = None
        elif encoded == b'\xde\xc1':
            require(pending_fld is None, f'{context}: faddp splits a product pair at {offset}')
            slots.append({'kind': 'faddp', 'offset': offset, 'length': 2})
        else:
            require(False, f'{context}: the instruction at {offset} is not an fld m64, fmul m64 or faddp st(1)')
        offset += length
    require(offset == end, f'{context}: the chain does not end on an instruction boundary')
    require(pending_fld is None, f'{context}: the chain ends inside a product pair')
    require(sum((1 for slot in slots if slot['kind'] == 'pair')) >= 2 and any((slot['kind'] == 'faddp' for slot in slots)), f'{context}: a chain is at least two product pairs and one faddp')
    return slots

def apply_x87_squared_addend_exchange(body: bytes, chains: list, relocation_offsets: frozenset, context: str, relocations: dict | None=None, code_length: int | None=None, external_entries: frozenset | None=None, internal_targets: frozenset | None=None) -> tuple[bytes, dict]:
    """Permute `fld m32 / fsub m32` addend units whose values provably enter
    the result only as SQUARES inside one commutative x87 sum, or refuse.

    x87_squared_addend_exchange_v1 obligations, all discharged here:
      X1  the window parses as N >= 2 contiguous units, each EXACTLY
          `fld m32` (D9 /0) then `fsub m32` (D8 /4), no relocation byte
          anywhere inside the window;
      X2  no branch target, external entry or relocated target lies inside
          the window (same flow walk the fp-sum primitive performs);
      X3  from the window end, the consumption region consists ONLY of
          `fxch st(k)`, `fmul st(0), st(0)` and `faddp st(1)` instructions,
          each pushed unit value is multiplied by itself exactly once
          before any faddp consumes it, and the region ends with all N unit
          values folded into a single stack slot: every unit therefore
          contributes only its square to one commutative, associative sum,
          so any unit permutation preserves the computed value exactly;
      X4  the declared order is a true permutation, only whole units move,
          the length is unchanged, and the rewritten byte set equals the
          declared `expected_rewritten_offsets`.
    """
    require_payload_free_declaration(chains, f'{context} x87 exchange declaration')
    require(isinstance(body, (bytes, bytearray)) and body, f'{context}: body is empty')
    body = bytes(body)
    require(isinstance(chains, list) and chains, f'{context}: no chain is declared')
    items, successors, entries = ia32_relational_flow_walk(body, relocations, context, code_length, external_entries)
    branch_targets = {item['target'] for item in items if item.get('target') is not None}
    image = bytearray(body)
    proved = []
    previous_end = 0
    for ordinal, chain in enumerate(chains):
        chain_context = f'{context} x87 chain {ordinal}'
        start = chain['chain_start']
        end = chain['chain_end']
        require(type(start) is int and type(end) is int and (0 < start < end <= len(body)), f'{chain_context}: bounds are out of range')
        require(previous_end <= start, f'{chain_context}: chains are unsorted or overlapping')
        previous_end = end
        inside = lambda target: start < target < end
        require(not any((inside(target) for target in branch_targets)), f'{chain_context}: a branch targets the chain interior')
        require(not any((inside(items[entry]['offset']) for entry in entries[1:])), f'{chain_context}: an external entry lies inside the chain')
        require(not any((inside(target) for target in internal_targets or frozenset())), f'{chain_context}: a relocated target lies inside the chain')
        require(not (start - 1 in relocation_offsets and start in relocation_offsets) and (not (end - 1 in relocation_offsets and end in relocation_offsets)), f'{chain_context}: a relocated record crosses the chain edge')
        carried_runs = []
        run_start = None
        for offset in range(start, end + 1):
            if offset < end and offset in relocation_offsets:
                if run_start is None:
                    run_start = offset
            elif run_start is not None:
                carried_runs.append((run_start, offset))
                run_start = None
        for run_lo, run_hi in carried_runs:
            require(run_hi - run_lo <= 4 and run_lo - 1 not in relocation_offsets and (run_hi not in relocation_offsets), f'{chain_context}: a relocated run inside the chain is not one whole record')
        units = []
        cursor = start
        while cursor < end:
            require(cursor + 2 <= end and body[cursor] == 217 and (body[cursor + 1] >> 3 & 7 == 0) and (body[cursor + 1] >> 6 != 3), f'{chain_context}: the instruction at {cursor} is not an fld m32')
            fld_len = _x87_m32_length(body, cursor, chain_context)
            sub_at = cursor + fld_len
            require(sub_at + 2 <= end and body[sub_at] == 216 and (body[sub_at + 1] >> 3 & 7 in (0, 4)) and (body[sub_at + 1] >> 6 != 3), f'{chain_context}: the instruction at {sub_at} is not an fsub/fadd m32')
            sub_len = _x87_m32_length(body, sub_at, chain_context)
            units.append((cursor, fld_len + sub_len, fld_len))
            cursor = sub_at + sub_len
        require(cursor == end and len(units) >= 2, f'{chain_context}: the window is not a whole number of fld/fsub units')
        require(all((any((offset <= run_lo and run_hi <= offset + length for offset, length, _ in units)) for run_lo, run_hi in carried_runs)), f'{chain_context}: a relocated record straddles a unit boundary')
        squared = [False] * len(units)
        stack = list(range(len(units) - 1, -1, -1))
        scan = end
        walk_at = {item['offset']: item for item in items}
        while True:
            require(scan + 2 <= len(body), f'{chain_context}: the consumption region runs off the body')
            op, modrm = (body[scan], body[scan + 1])
            if not 216 <= op <= 223 and op != 155:
                item = walk_at.get(scan)
                require(item is not None and item['flow'] == 'fall', f'{chain_context}: a non-x87 instruction at {scan} in the consumption region is not straight-line')
                scan += item['length']
                continue
            if op == 217 and 200 <= modrm <= 207:
                k = modrm - 200
                require(k < len(stack), f'{chain_context}: fxch exchanges below the unit stack')
                stack[0], stack[k] = (stack[k], stack[0])
                scan += 2
            elif op in (216, 220) and modrm == 200:
                unit = stack[0]
                require(isinstance(unit, int) and (not squared[unit]), f'{chain_context}: a unit is multiplied twice or a folded slot is squared')
                squared[unit] = True
                scan += 2
            elif op == 222 and modrm == 193:
                require(len(stack) >= 2, f'{chain_context}: faddp folds below the unit stack')
                top, nxt = (stack[0], stack[1])
                for slot in (top, nxt):
                    if isinstance(slot, int):
                        require(squared[slot], f'{chain_context}: a unit is summed before it is squared')
                stack = [(nxt, top)] + stack[2:]
                scan += 2
            else:
                break
            if len(stack) == 1 and (not isinstance(stack[0], int)):
                break
        require(len(stack) == 1 and (not isinstance(stack[0], int)) and all(squared), f'{chain_context}: the consumption region does not fold every squared unit into one commutative sum')
        fold_tree = stack[0]
        order = chain['order']
        require(isinstance(order, list) and sorted(order) == list(range(len(units))), f'{chain_context}: the order is not a permutation of the {len(units)} units')
        require(order != list(range(len(units))), f'{chain_context}: the order is the identity')

        def canonical(node, labels):
            if isinstance(node, int):
                return ('L', labels[node])
            left = canonical(node[0], labels)
            right = canonical(node[1], labels)
            return ('N',) + (left + right if left <= right else right + left)
        identity = list(range(len(units)))
        require(canonical(fold_tree, order) == canonical(fold_tree, identity), f'{chain_context}: the order is not commutativity-exact for the fold tree')
        blocks = [body[offset:offset + length] for offset, length, _ in units]
        rebuilt = b''.join((blocks[index] for index in order))
        require(len(rebuilt) == end - start, f'{chain_context}: the permutation changed the length')
        image[start:end] = rebuilt
        chain_reseat = []
        instruction_moves = []
        cursor = start
        for source_index in order:
            source_offset, length, fld_len = units[source_index]
            if cursor != source_offset:
                instruction_moves.append([source_offset, cursor])
                instruction_moves.append([source_offset + fld_len, cursor + fld_len])
                for run_lo, run_hi in carried_runs:
                    if source_offset <= run_lo and run_hi <= source_offset + length:
                        chain_reseat.append([run_lo, cursor + (run_lo - source_offset)])
            cursor += length
        rewritten = [index for index in range(start, end) if image[index] != body[index]]
        require(rewritten == chain['expected_rewritten_offsets'], f'{chain_context}: rewrote a different byte set from its declaration')
        require(sorted(map(list, chain_reseat)) == sorted(map(list, chain.get('relocation_reseat') or [])), f'{chain_context}: reseated a different relocation set from its declaration')
        proved.append({'chain_start': start, 'chain_end': end, 'order': list(order), 'unit_count': len(units), 'relocation_reseat': sorted(chain_reseat), 'instruction_moves': sorted(instruction_moves), 'rewritten_offsets': rewritten})
    return (bytes(image), {'chains': proved})

def _x87_m32_length(body: bytes, offset: int, context: str) -> int:
    """Length of a D9/D8 m32 instruction (mod!=3), refusing exotic forms."""
    modrm = body[offset + 1]
    mod, rm = (modrm >> 6, modrm & 7)
    require(mod != 3, f'{context}: not a memory operand at {offset}')
    length = 2
    if rm == 4:
        length += 1
        rm = body[offset + 2] & 7
    if mod == 1:
        length += 1
    elif mod == 2 or (mod == 0 and rm == 5):
        length += 4
    return length

def apply_fp_sum_reassociation(body: bytes, chains: list, relocation_offsets: frozenset, context: str, relocations: dict | None=None, code_length: int | None=None, external_entries: frozenset | None=None, internal_targets: frozenset | None=None) -> tuple[bytes, dict]:
    """Permute product pairs within declared faddp chains, or refuse."""
    require_payload_free_declaration(chains, f'{context} FP reassociation declaration')
    require(isinstance(body, (bytes, bytearray)) and body, f'{context}: body is empty')
    body = bytes(body)
    require(isinstance(chains, list) and chains, f'{context}: no chain is declared')
    items, successors, entries = ia32_relational_flow_walk(body, relocations, context, code_length, external_entries)
    branch_targets = {item['target'] for item in items if item.get('target') is not None}
    image = bytearray(body)
    proved = []
    previous_end = 0
    for ordinal, chain in enumerate(chains):
        chain_context = f'{context} chain {ordinal}'
        start = chain['chain_start']
        end = chain['chain_end']
        require(type(start) is int and type(end) is int and (0 < start < end <= len(body)), f'{chain_context}: bounds are out of range')
        require(previous_end <= start, f'{chain_context}: chains are unsorted or overlapping')
        previous_end = end
        require(not any((start <= offset < end for offset in relocation_offsets)), f'{chain_context}: a relocation lies inside the chain')
        inside = lambda target: start < target < end
        require(not any((inside(target) for target in branch_targets)), f'{chain_context}: a branch targets the chain interior')
        require(not any((inside(items[entry]['offset']) for entry in entries[1:])), f'{chain_context}: an external entry lies inside the chain')
        require(not any((inside(target) for target in internal_targets or frozenset())), f'{chain_context}: a relocated target lies inside the chain')
        slots = _fp_sum_parse_chain(body, start, end, chain_context)
        pair_slots = [slot for slot in slots if slot['kind'] == 'pair']
        order = chain['order']
        require(isinstance(order, list) and sorted(order) == list(range(len(pair_slots))), f'{chain_context}: the order is not a permutation of the {len(pair_slots)} product pairs')
        pairs = [body[slot['offset']:slot['offset'] + slot['length']] for slot in pair_slots]
        rebuilt = []
        pair_cursor = 0
        for slot in slots:
            if slot['kind'] == 'pair':
                rebuilt.append(pairs[order[pair_cursor]])
                pair_cursor += 1
            else:
                rebuilt.append(body[slot['offset']:slot['offset'] + slot['length']])
        rebuilt = b''.join(rebuilt)
        require(len(rebuilt) == end - start, f'{chain_context}: the permuted chain changed length')
        image[start:end] = rebuilt
        image_slots = _fp_sum_parse_chain(bytes(image), start, end, f'{chain_context} image')
        require([slot['kind'] for slot in image_slots] == [slot['kind'] for slot in slots], f'{chain_context}: the image slot skeleton differs')
        image_pairs = sorted((bytes(image[slot['offset']:slot['offset'] + slot['length']]) for slot in image_slots if slot['kind'] == 'pair'))
        require(image_pairs == sorted(pairs), f'{chain_context}: the image pair multiset differs')
        proved.append({'chain_start': start, 'chain_end': end, 'order': list(order), 'pair_count': len(pair_slots), 'faddp_count': sum((1 for slot in slots if slot['kind'] == 'faddp')), 'rewritten_offsets': sorted((offset for offset in range(start, end) if body[offset] != image[offset]))})
    image = bytes(image)
    require(image != body, f'{context}: the image does not move the body')
    changed = {offset for offset in range(len(body)) if body[offset] != image[offset]}
    declared = {offset for chain in proved for offset in chain['rewritten_offsets']}
    require(changed <= declared, f'{context}: the image changed a byte outside the declared chains')
    image_items, image_successors, image_entries = ia32_relational_flow_walk(image, relocations, f'{context} image', code_length, external_entries)
    require({item['target'] for item in image_items if item.get('target') is not None} == branch_targets and image_entries == entries, f'{context}: the image changed a branch target or an entry')
    return (image, {'kind': FP_SUM_REASSOCIATION_KIND, 'chains': proved, 'instruction_count': len(image_items)})
