from __future__ import annotations

from collections import Counter
import struct
from .foundation import ByteIdentityError, canonical_json_bytes, require, sha256_bytes

"""Classic compiler algorithms: coff."""

def coff_unpack(format_string: str, data: bytes, offset: int, context: str) -> tuple:
    size = struct.calcsize(format_string)
    require(0 <= offset <= len(data) - size, f'{context} is outside the COFF file')
    return struct.unpack_from(format_string, data, offset)

class CoffObject:
    """Strict reader for the classic i386 COFF emitted by VC4.2."""

    def __init__(self, data: bytes):
        self.data = data
        require(len(data) >= 20, 'COFF header is truncated')
        self.machine, self.section_count, self.timestamp, self.symbol_offset, self.symbol_count, optional_size, self.characteristics = coff_unpack('<HHIIIHH', data, 0, 'COFF header')
        require(self.machine == 332, 'only i386 COFF objects are supported')
        require(optional_size == 0, 'COFF optional headers are unsupported')
        require(0 < self.section_count < 65536, 'COFF section count is invalid')
        require(self.symbol_count > 0, 'COFF object has no symbol table')
        self.string_offset = self.symbol_offset + self.symbol_count * 18
        string_size, = coff_unpack('<I', data, self.string_offset, 'COFF string table')
        require(string_size >= 4 and self.string_offset <= len(data) - string_size, 'COFF string table is invalid')
        self.string_end = self.string_offset + string_size
        require(self.string_end == len(data), 'bytes after the COFF string table are unsupported')
        table_end = 20 + self.section_count * 40
        require(table_end <= len(data), 'COFF section table is truncated')
        self.sections = []
        for index in range(self.section_count):
            header_offset = 20 + index * 40
            raw_name = data[header_offset:header_offset + 8]
            name = self._section_name(raw_name)
            _, _, raw_size, raw_offset, relocation_offset, line_offset, relocation_count, line_count, characteristics = coff_unpack('<IIIIIIHHI', data, header_offset + 8, f'section {index + 1} header')
            if raw_size and (not characteristics & 128):
                require(raw_offset >= table_end and raw_offset <= len(data) - raw_size, f'section {index + 1} raw data is invalid')
            elif raw_size:
                require(raw_offset == 0, f'section {index + 1} uninitialized raw pointer is invalid')
            else:
                require(raw_offset == 0 or raw_offset >= table_end, f'section {index + 1} empty raw pointer is invalid')
            if relocation_count:
                require(relocation_offset >= table_end and relocation_offset <= len(data) - relocation_count * 10, f'section {index + 1} relocation table is invalid')
            if line_count:
                require(line_offset >= table_end and line_offset <= len(data) - line_count * 6, f'section {index + 1} line table is invalid')
            self.sections.append({'number': index + 1, 'header_offset': header_offset, 'name': name, 'raw_size': raw_size, 'raw_offset': raw_offset, 'relocation_offset': relocation_offset, 'relocation_count': relocation_count, 'line_offset': line_offset, 'line_count': line_count, 'characteristics': characteristics})
        require(self.symbol_offset >= table_end and self.symbol_offset <= len(data) - self.symbol_count * 18, 'COFF symbol table is invalid')
        self.symbols = {}
        symbol_index = 0
        while symbol_index < self.symbol_count:
            offset = self.symbol_offset + symbol_index * 18
            name = self._symbol_name(data[offset:offset + 8])
            value, section, symbol_type, storage, auxiliary_count = coff_unpack('<IhHBB', data, offset + 8, f'symbol {symbol_index}')
            require(symbol_index + auxiliary_count < self.symbol_count, f'symbol {symbol_index} auxiliary records are truncated')
            self.symbols[symbol_index] = {'index': symbol_index, 'name': name, 'value': value, 'section': section, 'type': symbol_type, 'storage': storage, 'aux_count': auxiliary_count}
            symbol_index += 1 + auxiliary_count

    def _string(self, relative: int, context: str) -> str:
        require(4 <= relative < self.string_end - self.string_offset, f'{context} string offset is invalid')
        absolute = self.string_offset + relative
        end = self.data.find(b'\x00', absolute, self.string_end)
        require(end >= 0, f'{context} is not NUL-terminated')
        return self.data[absolute:end].decode('ascii', 'strict')

    def _section_name(self, raw: bytes) -> str:
        if raw.startswith(b'/'):
            digits = raw[1:].rstrip(b'\x00')
            require(digits.isdigit(), 'long COFF section name is invalid')
            return self._string(int(digits), 'section name')
        return raw.rstrip(b'\x00').decode('ascii', 'strict')

    def _symbol_name(self, raw: bytes) -> str:
        if raw[:4] == b'\x00\x00\x00\x00':
            relative, = coff_unpack('<I', raw, 4, 'long symbol name')
            return self._string(relative, 'symbol name')
        return raw.rstrip(b'\x00').decode('ascii', 'strict')

    def function_section(self, mangled: str) -> dict:
        matches = [symbol for symbol in self.symbols.values() if symbol['name'] == mangled and symbol['section'] > 0 and (symbol['value'] == 0) and (symbol['type'] == 32) and (symbol['storage'] in (2, 3))]
        require(len(matches) == 1, f'expected one definition of {mangled!r}, found {len(matches)}')
        section = self.sections[matches[0]['section'] - 1]
        require(section['name'].startswith('.text'), f'{mangled!r} is not in a text section')
        require(section['characteristics'] & 4096, f'{mangled!r} is not in a COMDAT section')
        return section

def comdat_primary_section(coff: CoffObject, name: str) -> dict:
    """Return the unique COMDAT primary section defined by symbol ``name``.

    Unlike :meth:`CoffObject.function_section` this accepts any section kind
    (``.text`` functions, ``.rdata`` vftables and literals, ``.data``); the
    symbol must be an external or static definition at offset 0 of a COMDAT
    section that is not an associated (selection 5) child.
    """
    matches = [symbol for symbol in coff.symbols.values() if symbol['name'] == name and symbol['section'] > 0 and (symbol['value'] == 0) and (symbol['storage'] in (2, 3))]
    require(len(matches) == 1, f'expected one definition of {name!r}, found {len(matches)}')
    section = coff.sections[matches[0]['section'] - 1]
    require(section['characteristics'] & 4096, f'{name!r} is not in a COMDAT section')
    definition = section_definitions(coff).get(section['number'])
    require(definition is not None and definition.get('selection') != 5, f'{name!r} is not a COMDAT primary')
    return section

def coff_body(coff: CoffObject, section: dict) -> bytes:
    if not section['raw_size']:
        return b''
    if section['characteristics'] & 128:
        return b''
    start = section['raw_offset']
    return coff.data[start:start + section['raw_size']]

def coff_table(coff: CoffObject, section: dict, kind: str) -> bytes:
    if kind == 'relocations':
        start = section['relocation_offset']
        size = section['relocation_count'] * 10
    elif kind == 'lines':
        start = section['line_offset']
        size = section['line_count'] * 6
    else:
        raise ByteIdentityError(f'unknown COFF table kind: {kind}')
    return coff.data[start:start + size] if size else b''

def coff_auxiliary(coff: CoffObject, symbol_index: int, symbol: dict) -> bytes:
    require(symbol['aux_count'] >= 1, f"symbol {symbol['name']!r} has no auxiliary record")
    offset = coff.symbol_offset + (symbol_index + 1) * 18
    return coff.data[offset:offset + 18]

def unique_symbol(coff: CoffObject, predicate, description: str) -> tuple[int, dict]:
    matches = [(index, symbol) for index, symbol in coff.symbols.items() if predicate(symbol)]
    require(len(matches) == 1, f'expected one {description}, found {len(matches)}')
    return matches[0]

def function_symbol(coff: CoffObject, mangled: str, section_number: int) -> tuple[int, dict]:
    return unique_symbol(coff, lambda symbol: symbol['name'] == mangled and symbol['section'] == section_number and (symbol['value'] == 0) and (symbol['type'] == 32) and (symbol['storage'] in (2, 3)), f'function symbol {mangled!r}')

def section_symbol(coff: CoffObject, section: dict) -> tuple[int, dict]:
    return unique_symbol(coff, lambda symbol: symbol['name'] == section['name'] and symbol['section'] == section['number'] and (symbol['storage'] == 3) and (symbol['aux_count'] >= 1), f"section-definition symbol for section {section['number']}")

def marker_symbol(coff: CoffObject, name: str, section_number: int) -> tuple[int, dict]:
    return unique_symbol(coff, lambda symbol: symbol['name'] == name and symbol['section'] == section_number and (symbol['storage'] == 101) and (symbol['aux_count'] >= 1), f'{name} symbol for section {section_number}')

def section_definitions(coff: CoffObject) -> dict[int, dict]:
    result = {}
    for index, symbol in coff.symbols.items():
        if not (0 < symbol['section'] <= len(coff.sections) and symbol['storage'] == 3 and (symbol['aux_count'] >= 1)):
            continue
        section = coff.sections[symbol['section'] - 1]
        if symbol['name'] != section['name']:
            continue
        auxiliary = coff_auxiliary(coff, index, symbol)
        associated = int.from_bytes(auxiliary[12:14], 'little') | int.from_bytes(auxiliary[16:18], 'little') << 16
        result[section['number']] = {'symbol_index': index, 'raw': auxiliary, 'length': int.from_bytes(auxiliary[0:4], 'little'), 'relocations': int.from_bytes(auxiliary[4:6], 'little'), 'lines': int.from_bytes(auxiliary[6:8], 'little'), 'checksum': int.from_bytes(auxiliary[8:12], 'little'), 'associated': associated, 'selection': auxiliary[14]}
    return result

def associated_sections(coff: CoffObject, definitions: dict[int, dict], parent: int) -> tuple[tuple[int, str], ...]:
    return tuple(((section['number'], section['name']) for section in coff.sections if definitions.get(section['number'], {}).get('selection') == 5 and definitions[section['number']]['associated'] == parent))

def function_multiset(coff: CoffObject) -> Counter:
    return Counter((symbol['name'] for symbol in coff.symbols.values() if symbol['type'] == 32 and symbol['section'] > 0 and (symbol['value'] == 0) and (symbol['storage'] in (2, 3)) and coff.sections[symbol['section'] - 1]['name'].startswith('.text') and (coff.sections[symbol['section'] - 1]['raw_size'] > 0)))

def comdat_primary_identity(coff: CoffObject, section: dict) -> tuple:
    """Return one non-associative COMDAT group's structural identity."""
    definitions = section_definitions(coff)
    definition = definitions.get(section['number'])
    require(definition is not None and definition['selection'] not in (0, 5), f"section {section['number']} is not a primary COMDAT")
    owners = [symbol for symbol in coff.symbols.values() if symbol['section'] == section['number'] and symbol['value'] == 0 and (symbol['name'] != section['name']) and (symbol['storage'] in (2, 3))]
    external = [symbol for symbol in owners if symbol['storage'] == 2]
    owners = external or owners
    require(len(owners) == 1, f"COMDAT section {section['number']} has no unique owner")
    owner = owners[0]
    return (owner['name'], owner['type'], owner['storage'], section['name'], definition['selection'], tuple(sorted((name for _, name in associated_sections(coff, definitions, section['number'])))))

def comdat_primary_identity_multiset(coff: CoffObject) -> Counter:
    """Name every non-associative COMDAT group by its defining symbol.

    Raw sizes are intentionally absent: the target function is allowed to
    resize.  Symbol identity, selection policy, section kind, and complete
    associative-child shape still prevent a donor from adding or exchanging
    a code/data group under cover of an omitted function.
    """
    definitions = section_definitions(coff)
    identities = [comdat_primary_identity(coff, section) for section in coff.sections if definitions.get(section['number'], {}).get('selection') not in (None, 0, 5)]
    return Counter(identities)

def canonical_identity_receipt_sha256(value: object) -> str:
    """Hash a structural identity using the manifest's canonical JSON form."""

    def json_value(item):
        if isinstance(item, (tuple, list)):
            return [json_value(child) for child in item]
        if isinstance(item, dict):
            return {key: json_value(child) for key, child in item.items()}
        return item
    return sha256_bytes(canonical_json_bytes(json_value(value)))

def canonical_counter_receipt_sha256(value: Counter) -> str:
    """Hash every repeated Counter identity in deterministic repr order."""
    require(isinstance(value, Counter), 'canonical identity receipt requires a Counter')
    return canonical_identity_receipt_sha256(sorted(value.elements(), key=repr))

def section_shape_receipt_sha256(coff: CoffObject) -> str:
    """Hash the ordered section name/characteristics sequence."""
    return canonical_identity_receipt_sha256([(section['name'], section['characteristics']) for section in coff.sections])

def require_target_closure_extraction_topology(seed: CoffObject, donor: CoffObject, function: dict, context: str) -> dict:
    """Replace whole-object equality with a pinned strict-subset proof.

    The donor is allowed to omit only the explicitly named definitions that
    the seed object continues to carry.  It may add none.  The final composer
    still proves that every non-target seed section and the seed function set
    survive unchanged.
    """
    require(len(seed.sections) == function['expected_seed_section_count'], f'{context} seed section count changed')
    require(len(donor.sections) == function['expected_donor_section_count'], f'{context} donor section count changed')
    require(len(seed.sections) > len(donor.sections), f'{context} donor is not a strict section subset')
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    donor_only = donor_functions - seed_functions
    require(not donor_only, f'{context} donor adds functions absent from the seed')
    seed_only = sorted((seed_functions - donor_functions).elements())
    require(seed_only == function['expected_seed_only_functions'], f'{context} seed-only function set differs')
    require(seed_only, f'{context} target-closure extraction declares no omitted function')
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    require(not donor_comdats - seed_comdats, f'{context} donor adds or exchanges a COMDAT group')
    omitted_comdats = list((seed_comdats - donor_comdats).elements())
    require(sorted((identity[0] for identity in omitted_comdats)) == seed_only, f'{context} omitted COMDAT groups differ from the declared seed-only functions')
    return {'seed_section_count': len(seed.sections), 'donor_section_count': len(donor.sections), 'seed_only_functions': seed_only, 'seed_comdat_count': sum(seed_comdats.values()), 'donor_comdat_count': sum(donor_comdats.values())}

def require_source_target_closure_topology(seed: CoffObject, donor: CoffObject, function: dict, context: str) -> dict:
    """Pin one same-name target closure while ignoring donor-only COMDATs."""
    require(len(seed.sections) == function['expected_seed_section_count'] and len(donor.sections) == function['expected_donor_section_count'], f'{context} section census changed')
    mangled = function['mangled']
    sp, dp = (seed.function_section(mangled), donor.function_section(mangled))
    require(sp['number'] == dp['number'] == function['expected_section_number'], f'{context} target section seat changed')
    seed_id = [item for item in comdat_primary_identity_multiset(seed).elements() if item[0] == mangled]
    donor_id = [item for item in comdat_primary_identity_multiset(donor).elements() if item[0] == mangled]
    require(len(seed_id) == len(donor_id) == 1 and seed_id == donor_id, f'{context} target is not the same mangled COMDAT')
    require(sha256_bytes(coff_body(seed, sp)) == function['expected_seed_body_sha256'], f'{context} seed target body changed')
    expected = {'.xdata$x': ('expected_xdata_section_number', 'expected_seed_xdata_sha256', 'expected_donor_xdata_sha256'), '.debug$S': ('expected_debug_section_number', 'expected_seed_debug_sha256', 'expected_donor_debug_sha256')}
    for name, (seat_key, seed_sha_key, donor_sha_key) in expected.items():
        left, right = (_comdat_child(seed, sp, name), _comdat_child(donor, dp, name))
        require(left['number'] == right['number'] == function[seat_key] and sha256_bytes(coff_body(seed, left)) == function[seed_sha_key] and (sha256_bytes(coff_body(donor, right)) == function[donor_sha_key]), f'{context} pinned {name} closure changed')
    require(sp['relocation_count'] == dp['relocation_count'] == function['expected_relocation_count'] and sp['line_count'] == dp['line_count'] == function['expected_line_count'], f'{context} target relocation/line census changed')
    return {'seed_section_count': len(seed.sections), 'donor_section_count': len(donor.sections), 'donor_only_function_count': sum((function_multiset(donor) - function_multiset(seed)).values())}
RELOCATION_WIDTHS = {6: 4, 7: 4, 10: 2, 11: 4, 20: 4}

def detailed_relocations(coff: CoffObject, section: dict) -> list[dict]:
    result = []
    for ordinal in range(section['relocation_count']):
        offset = section['relocation_offset'] + ordinal * 10
        virtual_address, symbol_index, relocation_type = coff_unpack('<IIH', coff.data, offset, f"section {section['number']} relocation {ordinal}")
        require(symbol_index in coff.symbols, f"section {section['number']} relocation {ordinal} references an auxiliary symbol")
        width = RELOCATION_WIDTHS.get(relocation_type)
        require(width is not None, f'unsupported i386 relocation type 0x{relocation_type:04x}')
        require(virtual_address <= section['raw_size'] - width, f"section {section['number']} relocation {ordinal} operand is outside raw data")
        addend = int.from_bytes(coff.data[section['raw_offset'] + virtual_address:section['raw_offset'] + virtual_address + width], 'little')
        target = coff.symbols[symbol_index]
        result.append({'ordinal': ordinal, 'offset': virtual_address, 'symbol_index': symbol_index, 'type': relocation_type, 'width': width, 'addend': addend, 'target': target['name'], 'target_section': target['section'], 'target_value': target['value'], 'target_type': target['type'], 'target_storage': target['storage']})
    return result

def _comdat_child_closure(coff: CoffObject, primary: dict) -> tuple:
    """Return (count, sorted child section names) of a COMDAT's selection-5
    associates."""
    definitions = section_definitions(coff)
    children = tuple(sorted((section['name'] for section in coff.sections if definitions.get(section['number'], {}).get('selection') == 5 and definitions[section['number']]['associated'] == primary['number'])))
    return (len(children), children)

def _comdat_child(coff: CoffObject, primary: dict, name: str) -> dict:
    definitions = section_definitions(coff)
    matches = [section for section in coff.sections if section['name'] == name and definitions.get(section['number'], {}).get('selection') == 5 and (definitions[section['number']]['associated'] == primary['number'])]
    require(len(matches) == 1, f'expected one {name} child, found {len(matches)}')
    return matches[0]

def _coff_table_bytes(coff: CoffObject, section: dict, kind: str) -> bytes:
    if kind == 'relocations':
        start = section['relocation_offset']
        size = section['relocation_count'] * 10
    else:
        start = section['line_offset']
        size = section['line_count'] * 6
    return coff.data[start:start + size] if size else b''

def _coff_marker(coff: CoffObject, name: str, section_number: int):
    matches = [(index, symbol) for index, symbol in coff.symbols.items() if symbol['name'] == name and symbol['section'] == section_number and (symbol['storage'] == 101) and (symbol['aux_count'] >= 1)]
    require(len(matches) == 1, f'expected one {name} marker in section {section_number}')
    return matches[0]

def _coff_section_symbol(coff: CoffObject, section: dict):
    matches = [(index, symbol) for index, symbol in coff.symbols.items() if symbol['name'] == section['name'] and symbol['section'] == section['number'] and (symbol['storage'] == 3) and (symbol['aux_count'] >= 1)]
    require(len(matches) == 1, 'expected one section definition symbol')
    return matches[0]
