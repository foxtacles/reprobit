from __future__ import annotations

from collections import Counter
import struct

from reprobit.binary import require
from reprobit.coff import CoffObject, RELOCATION_WIDTHS, coff_body, coff_table, detailed_relocations

from .coff import function_multiset
from .foundation import exact_audit_keys, require_exact_int, require_sha, sha256_bytes
from .ia32 import ORDINARY_FPO_MOSAIC_IDENTITY_KIND, SOURCE_FPO_MOSAIC_IDENTITY_KIND

"""Classic compiler algorithms: debug."""
LOCAL_SET_DELTA_REFACTOR_KINDS = frozenset({'constructor_allocation_lift_v1'})
CODEVIEW_SYMBOL_NAME_OFFSETS = {2: 4, 6: None, 512: 6, 513: 8, 516: 33, 517: 33, 521: 7}
CODEVIEW_END_RECORD_TYPE = 6

def parse_codeview_symbol_stream(data: bytes, context: str) -> list[dict]:
    """Parse one object-file `.debug$S` symbol-record stream to exhaustion.

    Every record is `reclen:u16, rectyp:u16, payload[reclen-2]`, and every
    record type must be one this module knows how to name.  A stream that does
    not parse exactly, or that carries a record type outside the table, is
    refused rather than approximated.
    """
    records = []
    offset = 0
    while offset < len(data):
        require(offset + 4 <= len(data), f'{context}: symbol record header is truncated')
        length = int.from_bytes(data[offset:offset + 2], 'little')
        total = length + 2
        require(length >= 2 and offset + total <= len(data), f'{context}: symbol record length is out of range')
        record_type = int.from_bytes(data[offset + 2:offset + 4], 'little')
        require(record_type in CODEVIEW_SYMBOL_NAME_OFFSETS, f'{context}: symbol record type 0x{record_type:04x} is outside the closed table')
        payload = data[offset + 4:offset + total]
        name_offset = CODEVIEW_SYMBOL_NAME_OFFSETS[record_type]
        if name_offset is None:
            require(not payload, f'{context}: terminator record carries a payload')
            name = ''
        else:
            require(len(payload) > name_offset, f'{context}: symbol record has no name field')
            count = payload[name_offset]
            require(len(payload) == name_offset + 1 + count, f'{context}: symbol record name length is inconsistent')
            name = payload[name_offset + 1:].decode('latin1')
        records.append({'offset': offset, 'size': total, 'type': record_type, 'name': name})
        offset += total
    require(offset == len(data), f'{context}: symbol stream does not parse to exhaustion')
    return records

def codeview_symbol_identity(record: dict) -> tuple[int, str]:
    """A record's (type, name) with compiler-local serials collapsed.

    `$L`/`$T` serials are per-compile counters, exactly as they are for
    relocation targets -- `local_symbol_kind` is the same classifier the
    divergent relocation comparison already uses.  Collapsing them is what
    makes the two streams comparable at all; every other name is compared
    literally.
    """
    kind = local_symbol_kind(record['name'])
    return (record['type'], '$' + kind if kind is not None else record['name'])
DEBUG_REPRESENTATION_DELTA_KINDS = frozenset({'procedure_extent', 'compiler_label_number', 'local_location', 'inserted_donor_local'})
CODEVIEW_LOCAL_LOCATION_RECORD_TYPES = frozenset({2, 512})

def _codeview_local_location(record_type: int, payload: bytes, context: str) -> tuple[int, dict]:
    """One admitted local record's (type index, location encoding)."""
    if record_type == 2:
        return (int.from_bytes(payload[0:2], 'little'), {'register': int.from_bytes(payload[2:4], 'little')})
    require(record_type == 512, f'{context}: record is not a local-location record')
    return (int.from_bytes(payload[4:6], 'little'), {'bp_offset': int.from_bytes(payload[0:4], 'little', signed=True)})

def validate_debug_representation_delta(value: object, context: str) -> list[dict]:
    """Validate one pinned seed<->donor `.debug$S` representation delta."""
    require(isinstance(value, list) and 1 <= len(value) <= 32, f'{context} must name one to thirty-two records')
    normalized = []
    previous = -1
    for index, item in enumerate(value):
        item_context = f'{context}[{index}]'
        require(isinstance(item, dict), f'{item_context} must be an object')
        kind = item.get('kind')
        require(kind in DEBUG_REPRESENTATION_DELTA_KINDS, f'{item_context}.kind is outside the closed delta kinds')
        keys = {'kind', 'record_index'}
        if kind == 'local_location':
            keys |= {'name', 'seed_location', 'donor_location'}
            if 'seed_type' in item or 'donor_type' in item:
                keys |= {'seed_type', 'donor_type'}
            else:
                keys |= {'type'}
        elif kind == 'inserted_donor_local':
            keys |= {'name', 'type', 'location'}
        exact_audit_keys(item, keys, item_context)
        record_index = require_exact_int(item.get('record_index'), item_context + '.record_index', minimum=0, maximum=1 << 12)
        require(record_index > previous, f'{item_context}.record_index is unsorted or repeated')
        previous = record_index
        normalized_item = {'kind': kind, 'record_index': record_index}
        if kind == 'local_location':
            name = item.get('name')
            require(isinstance(name, str) and name and (local_symbol_kind(name) is None), f'{item_context}.name is not a source-named local')
            normalized_item['name'] = name
            if 'seed_type' in item or 'donor_type' in item:
                for type_key in ('seed_type', 'donor_type'):
                    normalized_item[type_key] = require_exact_int(item.get(type_key), item_context + '.' + type_key, minimum=0, maximum=65535)
            else:
                normalized_item['type'] = require_exact_int(item.get('type'), item_context + '.type', minimum=0, maximum=65535)
            for side in ('seed_location', 'donor_location'):
                location = item.get(side)
                require(isinstance(location, dict) and len(location) == 1 and (next(iter(location)) in ('register', 'bp_offset')), f'{item_context}.{side} is invalid')
                key = next(iter(location))
                if key == 'register':
                    bound = require_exact_int(location[key], f'{item_context}.{side}.register', minimum=1, maximum=65535)
                else:
                    bound = location[key]
                    require(type(bound) is int and bound != 0 and (-(1 << 31) <= bound < 1 << 31), f'{item_context}.{side}.bp_offset is invalid')
                normalized_item[side] = {key: bound}
            moves_type = 'seed_type' in normalized_item and normalized_item['seed_type'] != normalized_item['donor_type']
            require(normalized_item['seed_location'] != normalized_item['donor_location'] or moves_type, f"{item_context} does not move the local's location")
        elif kind == 'inserted_donor_local':
            name = item.get('name')
            require(isinstance(name, str) and name and (local_symbol_kind(name) is None), f'{item_context}.name is not a source-named local')
            normalized_item['name'] = name
            normalized_item['type'] = require_exact_int(item.get('type'), item_context + '.type', minimum=0, maximum=65535)
            location = item.get('location')
            require(isinstance(location, dict) and len(location) == 1 and (next(iter(location)) in ('register', 'bp_offset')), f'{item_context}.location is invalid')
            key = next(iter(location))
            if key == 'register':
                bound = require_exact_int(location[key], f'{item_context}.location.register', minimum=1, maximum=65535)
            else:
                bound = location[key]
                require(type(bound) is int and bound != 0 and (-(1 << 31) <= bound < 1 << 31), f'{item_context}.location.bp_offset is invalid')
            normalized_item['location'] = {key: bound}
        normalized.append(normalized_item)
    return normalized

def require_debug_symbol_representation_delta(seed_stream: bytes, donor_stream: bytes, declared: list[dict], expected_seed_length: int, expected_donor_length: int, context: str) -> list[dict]:
    """Prove the seed and donor `.debug$S` streams describe the SAME function.

    This replaces the raw-size equality proxy of D1 with something strictly
    stronger: both streams must parse to exhaustion within the closed record
    table, hold the same record sequence, and differ ONLY at the declared
    indices, each inside its closed kind:

      * `procedure_extent` -- the S_*PROC32 record's len/DbgEnd fields carry
        the two bodies' own lengths, pinned to the row's length pins and
        moving in lockstep; every other payload byte is equal.
      * `compiler_label_number` -- an S_LABEL32 record differs only in its
        `$L<serial>` per-compile serial, exactly the collapse the divergent
        relocation identity already performs for these names.
      * `local_location` -- one named local's location moved between the
        closed S_REGISTER/S_BPREL32 encodings (or recolored within
        S_REGISTER); its name and type index are pinned and must hold on
        BOTH sides, and both measured locations must equal the declaration.

    No donor `.debug$S` byte ever reaches the composed output (the install
    keeps the seed's stream); this proof exists purely so the same-function
    identity guarantee the raw-size proxy carried is preserved -- record by
    record, which the proxy never was.
    """
    seed_records = parse_codeview_symbol_stream(seed_stream, f'{context} (seed)')
    donor_records = parse_codeview_symbol_stream(donor_stream, f'{context} (donor)')
    declared_by_index = {item['record_index']: item for item in declared}
    require(max(declared_by_index, default=-1) < len(donor_records), f'{context}: a declared record index is out of range')
    inserted = sum((1 for item in declared if item['kind'] == 'inserted_donor_local'))
    require(len(donor_records) == len(seed_records) + inserted, f'{context}: record counts differ from the declared insertions')
    detail = []
    seed_cursor = 0
    for index, donor_record in enumerate(donor_records):
        item = declared_by_index.get(index)
        if item is not None and item['kind'] == 'inserted_donor_local':
            donor_payload = donor_stream[donor_record['offset'] + 4:donor_record['offset'] + donor_record['size']]
            require(donor_record['type'] in CODEVIEW_LOCAL_LOCATION_RECORD_TYPES, f'{context}: inserted record {index} is outside the closed local-location forms')
            require(donor_record['name'] == item['name'], f'{context}: inserted record {index} name differs from its pin')
            donor_type, donor_location = _codeview_local_location(donor_record['type'], donor_payload, f'{context} (donor)')
            require(donor_type == item['type'] and donor_location == item['location'], f'{context}: inserted record {index} differs from its declaration')
            detail.append({'record_index': index, 'kind': 'inserted_donor_local', 'name': donor_record['name']})
            continue
        require(seed_cursor < len(seed_records), f'{context}: the seed stream ran out of records')
        seed_record = seed_records[seed_cursor]
        seed_cursor += 1
        seed_payload = seed_stream[seed_record['offset'] + 4:seed_record['offset'] + seed_record['size']]
        donor_payload = donor_stream[donor_record['offset'] + 4:donor_record['offset'] + donor_record['size']]
        differs = seed_record['type'] != donor_record['type'] or seed_payload != donor_payload
        item = declared_by_index.get(index)
        if item is None:
            require(not differs, f'{context}: record {index} differs without a declaration')
            continue
        require(differs, f'{context}: declared record {index} does not differ')
        kind = item['kind']
        if kind == 'procedure_extent':
            require(seed_record['type'] == donor_record['type'] and seed_record['type'] in CODEVIEW_PROCEDURE_RECORD_TYPES and (len(seed_payload) == len(donor_payload)) and (len(seed_payload) >= 24), f'{context}: record {index} is not a procedure pair')
            require(seed_payload[:12] == donor_payload[:12] and seed_payload[24:30] == donor_payload[24:30] and (seed_payload[32:] == donor_payload[32:]), f'{context}: record {index} moves more than the procedure extent')
            seed_length = int.from_bytes(seed_payload[12:16], 'little')
            donor_length = int.from_bytes(donor_payload[12:16], 'little')
            seed_start = int.from_bytes(seed_payload[16:20], 'little')
            donor_start = int.from_bytes(donor_payload[16:20], 'little')
            seed_end = int.from_bytes(seed_payload[20:24], 'little')
            donor_end = int.from_bytes(donor_payload[20:24], 'little')
            require(seed_length == expected_seed_length and donor_length == expected_donor_length, f"{context}: record {index} extent differs from the row's length pins")
            require(seed_start <= seed_end <= seed_length and donor_start <= donor_end <= donor_length, f'{context}: record {index} debug range does not sit inside its own extent')
        elif kind == 'compiler_label_number':
            require(seed_record['type'] == donor_record['type'] == 521 and seed_payload[:7] == donor_payload[:7], f'{context}: record {index} is not a label pair')
            require(local_symbol_kind(seed_record['name']) == 'L' and local_symbol_kind(donor_record['name']) == 'L', f'{context}: record {index} is not a compiler-numbered label')
        else:
            require(seed_record['type'] in CODEVIEW_LOCAL_LOCATION_RECORD_TYPES and donor_record['type'] in CODEVIEW_LOCAL_LOCATION_RECORD_TYPES, f'{context}: record {index} is outside the closed local-location forms')
            require(seed_record['name'] == donor_record['name'] == item['name'], f'{context}: record {index} name differs from its pin')
            seed_type, seed_location = _codeview_local_location(seed_record['type'], seed_payload, f'{context} (seed)')
            donor_type, donor_location = _codeview_local_location(donor_record['type'], donor_payload, f'{context} (donor)')
            if 'type' in item:
                require(seed_type == donor_type == item['type'], f'{context}: record {index} type index differs from its pin')
            else:
                require(seed_type == item['seed_type'] and donor_type == item['donor_type'], f'{context}: record {index} type index differs from its pin')
            require(seed_location == item['seed_location'] and donor_location == item['donor_location'], f'{context}: record {index} location differs from its declaration')
        detail.append({'record_index': index, 'kind': kind, 'name': seed_record['name']})
    require(seed_cursor == len(seed_records), f'{context}: the seed stream has records the walk never paired')
    return detail

def require_removed_caller_locals_delta(seed_stream: bytes, donor_stream: bytes, relocation_offsets: list[int], delta: dict, context: str) -> tuple[dict, bytes]:
    """D1: prove a `.debug$S` size change is exactly a pinned local removal.

    The equality this replaces was a same-function sanity proxy, not an
    output-integrity check -- no donor `.debug$S` byte has ever reached the
    output.  What stands in its place is strictly more: the removal is pinned
    record by record, it is proved to be a removal and never an addition, it
    may not touch any relocated span, the surviving record sequence must equal
    the donor's, and the composed output DROPS the removed records instead of
    keeping a stale local the installed body does not have.
    """
    seed_records = parse_codeview_symbol_stream(seed_stream, context + ' seed')
    donor_records = parse_codeview_symbol_stream(donor_stream, context + ' donor')
    for records, role in ((seed_records, 'seed'), (donor_records, 'donor')):
        require(records and records[0]['type'] in CODEVIEW_PROCEDURE_RECORD_TYPES and (records[-1]['type'] == CODEVIEW_END_RECORD_TYPE), f'{context}: {role} symbol stream is not one bounded procedure record')
    removed = delta['removed_records']
    require(len(seed_stream) == delta['expected_seed_debug_size'] and len(donor_stream) == delta['expected_donor_debug_size'], f'{context}: debug$S sizes differ from their local-set pins')
    require(len(seed_stream) - len(donor_stream) == sum((item['size'] for item in removed)), f'{context}: the pinned local-set delta does not account for the whole debug$S size change')
    guard = max(relocation_offsets, default=-4) + 4
    by_offset = {record['offset']: record for record in seed_records}
    for item in removed:
        record = by_offset.get(item['seed_offset'])
        require(record is not None and record['size'] == item['size'] and (record['type'] == item['record_type']) and (record['name'] == item['identifier']), f"{context}: pinned removed record at {item['seed_offset']} is not the seed's {item['identifier']!r}")
        require(item['seed_offset'] >= guard, f'{context}: a removed record overlaps a relocated span, so debug$S relocation offsets would move')
    removed_offsets = {item['seed_offset'] for item in removed}
    surviving = [record for record in seed_records if record['offset'] not in removed_offsets]
    require([codeview_symbol_identity(item) for item in surviving] == [codeview_symbol_identity(item) for item in donor_records], f"{context}: the seed symbol stream minus its pinned removals is not the donor's symbol sequence")
    removed_identifiers = {item['identifier'] for item in removed}
    require(not removed_identifiers.intersection((record['name'] for record in donor_records)), f"{context}: a pinned removed local still exists in the donor's symbol stream")
    reduced = b''.join((seed_stream[record['offset']:record['offset'] + record['size']] for record in surviving))
    require(len(reduced) == len(donor_stream), f'{context}: the reduced seed symbol stream has the wrong size')
    return ({'local_set_removed_records': len(removed), 'local_set_removed_identifiers': sorted(removed_identifiers), 'local_set_debug_size_delta': len(reduced) - len(seed_stream)}, reduced)

def local_symbol_kind(name: str) -> str | None:
    if len(name) > 2 and name[0] == '$' and (name[1] in 'LT') and name[2:].isdigit():
        return name[1]
    if name.startswith('$done$') and name[6:].isdigit():
        return 'done'
    return None

def relocation_compatibility(seed_rows: list[dict], donor_rows: list[dict], seed_primary: int, donor_primary: int) -> dict | None:
    """Pair primary relocations by semantic target/type/addend, not file offset."""
    if len(seed_rows) != len(donor_rows):
        return None
    local_updates = {}
    pairs = []
    for seed, donor in zip(seed_rows, donor_rows):
        if not (seed['type'] == donor['type'] and seed['width'] == donor['width'] and (seed['addend'] == donor['addend']) and (seed['target_type'] == donor['target_type']) and (seed['target_storage'] == donor['target_storage'])):
            return None
        seed_internal = seed['target_section'] == seed_primary
        donor_internal = donor['target_section'] == donor_primary
        if seed_internal != donor_internal:
            return None
        seed_kind = local_symbol_kind(seed['target'])
        donor_kind = local_symbol_kind(donor['target'])
        if seed_kind or donor_kind:
            if not (seed_internal and donor_internal and (seed_kind == donor_kind)):
                return None
            previous = local_updates.setdefault(seed['symbol_index'], donor['target_value'])
            if previous != donor['target_value']:
                return None
        elif not (seed['target'] == donor['target'] and (seed_internal and seed['target_value'] == donor['target_value'] or (not seed_internal and seed['target_section'] == donor['target_section'] and (seed['target_value'] == donor['target_value'])))):
            return None
        pairs.append({'ordinal': seed['ordinal'], 'seed_offset': seed['offset'], 'donor_offset': donor['offset'], 'type': donor['type'], 'addend': donor['addend'], 'seed_target': seed['target'], 'donor_target': donor['target']})
    return {'pairs': pairs, 'local_updates': local_updates}

def linker_payload_multiset(coff: CoffObject) -> Counter:
    """Fingerprint every non-code, non-CodeView linker contribution.

    This intentionally includes `.drectve`, `.xdata`, import/CRT/tls families,
    and unknown section names.  A declaration shape is not allowed to create
    or perturb any such payload even though the final composition retains the
    seed copy. Raw relocation-table bytes are deliberately excluded because
    their symbol-index field is object bookkeeping; the ordered resolved tuple
    below retains offset, type, addend, target identity, section, value, type,
    and storage while the section-body digest retains the relocated operands.
    """
    result = Counter()
    for section in coff.sections:
        if section['name'].startswith('.text') or section['name'].startswith('.debug'):
            continue
        relocations = tuple(((item['offset'], item['type'], item['addend'], local_symbol_kind(item['target']) or item['target'], item['target_section'], item['target_value'], item['target_type'], item['target_storage']) for item in detailed_relocations(coff, section)))
        result[section['name'], section['raw_size'], section['characteristics'], sha256_bytes(coff_body(coff, section)), relocations] += 1
    return result

def verify_non_emitting_donor(seed: CoffObject, donor: CoffObject, identifiers: set[str]) -> dict:
    require(function_multiset(seed) == function_multiset(donor), 'declaration shape changed the complete function multiset')
    require(len(seed.sections) == len(donor.sections), 'declaration shape changed the section count')
    require(all((left['name'] == right['name'] and left['characteristics'] == right['characteristics'] for left, right in zip(seed.sections, donor.sections))), 'declaration shape changed section order or characteristics')
    leaked_symbols = sorted((symbol['name'] for symbol in donor.symbols.values() if any((identifier in symbol['name'] for identifier in identifiers))))
    require(not leaked_symbols, f'declaration shape emitted COFF symbols: {leaked_symbols[:5]}')
    require(linker_payload_multiset(seed) == linker_payload_multiset(donor), 'declaration shape added or altered non-code/directive/import/CRT linker payload')
    debug_type_ranges = [(section['raw_offset'], section['raw_offset'] + section['raw_size']) for section in donor.sections if section['name'] in ('.debug$S', '.debug$T') and section['raw_size']]
    for identifier in identifiers:
        needle = identifier.encode('ascii')
        start = 0
        while True:
            occurrence = donor.data.find(needle, start)
            if occurrence < 0:
                break
            require(any((left <= occurrence < right for left, right in debug_type_ranges)), f'declaration identifier escaped CodeView types: {identifier}')
            start = occurrence + 1
    return {'function_count': sum(function_multiset(seed).values()), 'section_count': len(seed.sections), 'defined_or_undefined_shape_symbols': [], 'noncode_directive_import_crt_payload_identical': True}

def normalized_donor_lines(seed: CoffObject, donor: CoffObject, seed_section: dict, donor_section: dict, seed_function_index: int, donor_function_index: int) -> bytes:
    require(seed_section['line_count'] > 0 and donor_section['line_count'] > 0, 'FPO composer requires COFF line tables')
    seed_lines = coff_table(seed, seed_section, 'lines')
    donor_lines = bytearray(coff_table(donor, donor_section, 'lines'))
    require(struct.unpack_from('<IH', seed_lines, 0) == (seed_function_index, 0), 'seed COFF line sentinel is invalid')
    require(struct.unpack_from('<IH', donor_lines, 0) == (donor_function_index, 0), 'donor COFF line sentinel is invalid')
    struct.pack_into('<I', donor_lines, 0, seed_function_index)
    previous = -1
    for index in range(1, donor_section['line_count']):
        offset, line = struct.unpack_from('<IH', donor_lines, index * 6)
        require(line != 0 and previous <= offset < donor_section['raw_size'], f'donor COFF line row {index} is outside or nonmonotonic')
        previous = offset
    return bytes(donor_lines)

def _apply_replacements(data: bytes, replacements: list[tuple[int, int, bytes]]) -> bytes:
    ordered = sorted(replacements, key=lambda item: item[0])
    cursor = 0
    chunks = []
    for start, end, replacement in ordered:
        require(cursor <= start <= end <= len(data), 'COFF replacement ranges overlap')
        chunks.extend((data[cursor:start], replacement))
        cursor = end
    chunks.append(data[cursor:])
    return b''.join(chunks)

def shifted_pointer(pointer: int, replacements: list[tuple[int, int, bytes]]) -> int:
    if pointer == 0:
        return 0
    delta = 0
    for start, end, replacement in sorted(replacements, key=lambda item: item[0]):
        if pointer < start:
            break
        if pointer == start:
            return start + delta
        require(pointer >= end, 'COFF pointer falls inside a replaced range')
        delta += len(replacement) - (end - start)
    return pointer + delta
FPO_RECORD_KEYS = {'ulOffStart', 'cbProcSize', 'cdwLocals', 'cdwParams', 'cbProlog', 'cbRegs', 'fHasSEH', 'fUseBP', 'reserved', 'cbFrame', 'raw_sha256'}

def parse_fpo_data(raw: bytes, *, expected_proc_size: int | None=None) -> dict:
    """Decode and structurally validate one classic 16-byte FPO_DATA row."""
    require(isinstance(raw, bytes) and len(raw) == 16, 'associated FPO record is not exactly 16 bytes')
    ul_off_start, cb_proc_size, cdw_locals, cdw_params = struct.unpack_from('<IIIH', raw, 0)
    cb_prolog = raw[14]
    packed = raw[15]
    result = {'ulOffStart': ul_off_start, 'cbProcSize': cb_proc_size, 'cdwLocals': cdw_locals, 'cdwParams': cdw_params, 'cbProlog': cb_prolog, 'cbRegs': packed & 7, 'fHasSEH': packed >> 3 & 1, 'fUseBP': packed >> 4 & 1, 'reserved': packed >> 5 & 1, 'cbFrame': packed >> 6 & 3, 'raw_sha256': sha256_bytes(raw)}
    require(result['ulOffStart'] == 0, 'associative function FPO ulOffStart must be zero')
    require(result['cbProcSize'] > 0, 'FPO cbProcSize must be positive')
    if expected_proc_size is not None:
        require(type(expected_proc_size) is int and expected_proc_size > 0 and (result['cbProcSize'] == expected_proc_size), 'FPO cbProcSize differs from its function section')
    require(result['cbProlog'] <= result['cbProcSize'], 'FPO cbProlog exceeds cbProcSize')
    require(result['reserved'] == 0, 'FPO reserved bit must remain zero')
    require(result['cdwLocals'] <= 1073741823, 'FPO local DWORD count overflows its byte range')
    require(result['cdwParams'] <= 32767, 'FPO parameter WORD count overflows its byte range')
    return result

def validate_manifest_fpo_record(value: object, context: str) -> dict:
    require(isinstance(value, dict), f'{context} must be an object')
    exact_audit_keys(value, FPO_RECORD_KEYS, context)
    integer_ranges = {'ulOffStart': (0, 4294967295), 'cbProcSize': (1, 4294967295), 'cdwLocals': (0, 1073741823), 'cdwParams': (0, 32767), 'cbProlog': (0, 255), 'cbRegs': (0, 7), 'fHasSEH': (0, 1), 'fUseBP': (0, 1), 'reserved': (0, 0), 'cbFrame': (0, 3)}
    normalized = {}
    for name, (minimum, maximum) in integer_ranges.items():
        item = value.get(name)
        require(type(item) is int and minimum <= item <= maximum, f'{context}.{name} is invalid')
        normalized[name] = item
    normalized['raw_sha256'] = require_sha(value.get('raw_sha256'), f'{context}.raw_sha256')
    require(normalized['ulOffStart'] == 0 and normalized['cbProlog'] <= normalized['cbProcSize'], f'{context} is structurally invalid')
    return normalized
ORDINARY_FPO_CHILD_IDENTITY_KEYS = {'section_number', 'raw_size', 'relocation_count', 'line_count', 'characteristics', 'selection', 'associated', 'expected_seed_body_sha256', 'expected_donor_body_sha256', 'expected_seed_relocation_sha256', 'expected_donor_relocation_sha256'}

def validate_ordinary_fpo_mosaic_identity(value: object, context: str, primary_section: int, body_length: int) -> dict:
    """Validate the narrow seed-authoritative FPO mosaic identity schema."""
    require(isinstance(value, dict), f'{context} must be an object')
    exact_audit_keys(value, {'kind', 'expected_primary_characteristics', 'expected_primary_selection', 'expected_function_count', 'expected_comdat_count', 'expected_seed_line_sha256', 'expected_donor_line_sha256', 'debug_f', 'debug_s'}, context)
    require(value.get('kind') == ORDINARY_FPO_MOSAIC_IDENTITY_KIND, f'{context}.kind differs')
    normalized = {'kind': value['kind']}
    for name, minimum, maximum in (('expected_primary_characteristics', 1, 4294967295), ('expected_primary_selection', 1, 7), ('expected_function_count', 1, 2147483647), ('expected_comdat_count', 1, 2147483647)):
        normalized[name] = require_exact_int(value.get(name), f'{context}.{name}', minimum=minimum, maximum=maximum)
    for name in ('expected_seed_line_sha256', 'expected_donor_line_sha256'):
        normalized[name] = require_sha(value.get(name), f'{context}.{name}')
    children = {}
    for key, section_name in (('debug_f', '.debug$F'), ('debug_s', '.debug$S')):
        child_context = f'{context}.{key}'
        child = value.get(key)
        require(isinstance(child, dict), f'{child_context} must be an object')
        extra_keys = {'expected_record'} if key == 'debug_f' else {'expected_common_prefix_sha256', 'expected_record_kind', 'expected_cb_proc', 'expected_dbg_start', 'expected_dbg_end'}
        exact_audit_keys(child, ORDINARY_FPO_CHILD_IDENTITY_KEYS | extra_keys, child_context)
        normalized_child = {}
        for name, minimum, maximum in (('section_number', 1, 32767), ('raw_size', 1, 4294967295), ('relocation_count', 0, 65535), ('line_count', 0, 65535), ('characteristics', 1, 4294967295), ('selection', 1, 7), ('associated', 1, 32767)):
            normalized_child[name] = require_exact_int(child.get(name), f'{child_context}.{name}', minimum=minimum, maximum=maximum)
        require(normalized_child['associated'] == primary_section and normalized_child['selection'] == 5 and (normalized_child['line_count'] == 0), f'{child_context} is not an associative debug child')
        for name in ('expected_seed_body_sha256', 'expected_donor_body_sha256', 'expected_seed_relocation_sha256', 'expected_donor_relocation_sha256'):
            normalized_child[name] = require_sha(child.get(name), f'{child_context}.{name}')
        if key == 'debug_f':
            require(normalized_child['raw_size'] == 16 and normalized_child['relocation_count'] == 1, f'{child_context} is not one classic FPO record')
            record = validate_manifest_fpo_record(child.get('expected_record'), f'{child_context}.expected_record')
            require(record['cbProcSize'] == body_length, f'{child_context} FPO size differs from the function')
            normalized_child['expected_record'] = record
        else:
            require(normalized_child['raw_size'] >= 28 and normalized_child['relocation_count'] == 2, f'{child_context} is not one CodeView procedure record')
            normalized_child['expected_common_prefix_sha256'] = require_sha(child.get('expected_common_prefix_sha256'), f'{child_context}.expected_common_prefix_sha256')
            require(child.get('expected_record_kind') == '0502', f'{child_context}.expected_record_kind differs')
            normalized_child['expected_record_kind'] = '0502'
            for name in ('expected_cb_proc', 'expected_dbg_start', 'expected_dbg_end'):
                normalized_child[name] = require_exact_int(child.get(name), f'{child_context}.{name}', minimum=0, maximum=body_length)
            require(normalized_child['expected_cb_proc'] == body_length and 0 <= normalized_child['expected_dbg_start'] <= normalized_child['expected_dbg_end'] < body_length, f'{child_context} CodeView procedure range differs')
        children[key] = normalized_child
    normalized.update(children)
    require(children['debug_f']['section_number'] != children['debug_s']['section_number'], f'{context} child seats are not distinct')
    return normalized
SOURCE_FPO_CHILD_IDENTITY_KEYS = {'section_number', 'expected_seed_raw_size', 'expected_donor_raw_size', 'relocation_count', 'line_count', 'characteristics', 'selection', 'associated', 'expected_seed_body_sha256', 'expected_donor_body_sha256', 'expected_seed_relocation_sha256', 'expected_donor_relocation_sha256'}
SOURCE_FPO_EXTRA_RELOCATION_KEYS = {'offset', 'width', 'type', 'addend', 'target', 'target_section', 'target_value', 'target_type', 'target_storage'}

def validate_source_fpo_mosaic_identity(value: object, context: str, primary_section: int, body_length: int) -> dict:
    """Validate the isolated source-refactor FPO/CodeView identity."""
    require(isinstance(value, dict), f'{context} must be an object')
    exact_audit_keys(value, {'kind', 'expected_primary_characteristics', 'expected_primary_selection', 'expected_function_count', 'expected_comdat_count', 'expected_seed_line_sha256', 'expected_donor_line_sha256', 'debug_f', 'debug_s'}, context)
    require(value.get('kind') == SOURCE_FPO_MOSAIC_IDENTITY_KIND, f'{context}.kind differs')
    normalized = {'kind': value['kind']}
    for name, minimum, maximum in (('expected_primary_characteristics', 1, 4294967295), ('expected_primary_selection', 1, 7), ('expected_function_count', 1, 2147483647), ('expected_comdat_count', 1, 2147483647)):
        normalized[name] = require_exact_int(value.get(name), f'{context}.{name}', minimum=minimum, maximum=maximum)
    for name in ('expected_seed_line_sha256', 'expected_donor_line_sha256'):
        normalized[name] = require_sha(value.get(name), f'{context}.{name}')
    children = {}
    for key in ('debug_f', 'debug_s'):
        child_context = f'{context}.{key}'
        child = value.get(key)
        require(isinstance(child, dict), f'{child_context} must be an object')
        extras = {'expected_record'} if key == 'debug_f' else {'expected_common_prefix_sha256', 'expected_record_kind', 'expected_cb_proc', 'expected_dbg_start', 'expected_dbg_end', 'expected_seed_tail_sha256', 'expected_donor_tail_sha256'}
        optional = {'expected_extra_relocations'} if key == 'debug_s' else set()
        exact_audit_keys(child, SOURCE_FPO_CHILD_IDENTITY_KEYS | extras | optional, child_context, optional=optional)
        normalized_child = {}
        for name, minimum, maximum in (('section_number', 1, 32767), ('expected_seed_raw_size', 1, 4294967295), ('expected_donor_raw_size', 1, 4294967295), ('relocation_count', 0, 65535), ('line_count', 0, 65535), ('characteristics', 1, 4294967295), ('selection', 1, 7), ('associated', 1, 32767)):
            normalized_child[name] = require_exact_int(child.get(name), f'{child_context}.{name}', minimum=minimum, maximum=maximum)
        require(normalized_child['associated'] == primary_section and normalized_child['selection'] == 5 and (normalized_child['line_count'] == 0), f'{child_context} is not an associative debug child')
        for name in ('expected_seed_body_sha256', 'expected_donor_body_sha256', 'expected_seed_relocation_sha256', 'expected_donor_relocation_sha256'):
            normalized_child[name] = require_sha(child.get(name), f'{child_context}.{name}')
        if key == 'debug_f':
            require(normalized_child['expected_seed_raw_size'] == 16 and normalized_child['expected_donor_raw_size'] == 16 and (normalized_child['relocation_count'] == 1), f'{child_context} is not one classic FPO record')
            record = validate_manifest_fpo_record(child.get('expected_record'), f'{child_context}.expected_record')
            require(record['cbProcSize'] == body_length, f'{child_context} FPO size differs from the function')
            normalized_child['expected_record'] = record
        else:
            extra_relocations = child.get('expected_extra_relocations', [])
            require(isinstance(extra_relocations, list), f'{child_context}.expected_extra_relocations must be an array')
            normalized_extra_relocations = []
            for index, relocation in enumerate(extra_relocations):
                relocation_context = f'{child_context}.expected_extra_relocations[{index}]'
                require(isinstance(relocation, dict), f'{relocation_context} must be an object')
                exact_audit_keys(relocation, SOURCE_FPO_EXTRA_RELOCATION_KEYS, relocation_context)
                normalized_relocation = {}
                for name, minimum, maximum in (('offset', 34, 4294967295), ('width', 1, 4), ('type', 0, 65535), ('addend', 0, 4294967295), ('target_section', 1, 32767), ('target_value', 0, body_length - 1), ('target_type', 0, 65535), ('target_storage', 0, 255)):
                    normalized_relocation[name] = require_exact_int(relocation.get(name), f'{relocation_context}.{name}', minimum=minimum, maximum=maximum)
                target = relocation.get('target')
                require(isinstance(target, str) and target, f'{relocation_context}.target is invalid')
                normalized_relocation['target'] = target
                require(RELOCATION_WIDTHS.get(normalized_relocation['type']) == normalized_relocation['width'] and normalized_relocation['target_section'] == primary_section and (normalized_relocation['offset'] + normalized_relocation['width'] <= min(normalized_child['expected_seed_raw_size'], normalized_child['expected_donor_raw_size'])), f'{relocation_context} shape or target seat differs')
                normalized_extra_relocations.append(normalized_relocation)
            require(all((left['offset'] + left['width'] <= right['offset'] for left, right in zip(normalized_extra_relocations, normalized_extra_relocations[1:]))), f'{child_context}.expected_extra_relocations overlap or are not ordered')
            require(normalized_child['expected_seed_raw_size'] >= 28 and normalized_child['expected_donor_raw_size'] >= 28 and (normalized_child['relocation_count'] == 2 + len(normalized_extra_relocations)), f'{child_context} is not a CodeView procedure record')
            if 'expected_extra_relocations' in child:
                require(normalized_extra_relocations, f'{child_context}.expected_extra_relocations is empty')
                normalized_child['expected_extra_relocations'] = normalized_extra_relocations
            for name in ('expected_common_prefix_sha256', 'expected_seed_tail_sha256', 'expected_donor_tail_sha256'):
                normalized_child[name] = require_sha(child.get(name), f'{child_context}.{name}')
            require(child.get('expected_record_kind') == '0502', f'{child_context}.expected_record_kind differs')
            normalized_child['expected_record_kind'] = '0502'
            for name in ('expected_cb_proc', 'expected_dbg_start', 'expected_dbg_end'):
                normalized_child[name] = require_exact_int(child.get(name), f'{child_context}.{name}', minimum=0, maximum=body_length)
            require(normalized_child['expected_cb_proc'] == body_length and 0 <= normalized_child['expected_dbg_start'] <= normalized_child['expected_dbg_end'] < body_length, f'{child_context} CodeView procedure range differs')
        children[key] = normalized_child
    normalized.update(children)
    require(children['debug_f']['section_number'] != children['debug_s']['section_number'], f'{context} child seats are not distinct')
    return normalized
CODEVIEW_PROCEDURE_RECORD_TYPES = (517, 516)
