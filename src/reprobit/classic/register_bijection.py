"""Fixed-width register-bijection declarations and transformations."""

from __future__ import annotations

from reprobit.binary import ByteIdentityError, require

from .debug import CODEVIEW_SYMBOL_NAME_OFFSETS, local_symbol_kind, parse_codeview_symbol_stream
from .foundation import (
    exact_audit_keys,
    require_exact_int,
    require_payload_free_declaration,
    require_sha,
)
from .register_semantics import (
    _IA32_REGISTER_NUMBERS,
    _IA32_STRUCTURAL_REGISTERS,
    _bijection_form_for,
    _ia32_atom_registers,
    _register_bijection_live_sets,
    decode_ia32_bijection_body,
    ia32_register_atoms,
)

REGISTER_BIJECTION_CLASS = "retail_exact_register_bijection"
REGISTER_BIJECTION_KIND = "callee_saved_register_bijection_v1"
REGISTER_BIJECTION_FPO_CLOSURE = [".debug$F", ".debug$S"]
REGISTER_BIJECTION_EH_CLOSURE = [".debug$S", ".xdata$x"]


def register_bijection_delegate(
    expected_closure: object, expected_code_renames: object, expected_relocation_moves: object = ()
) -> str:
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
        return "equal_body_eh_reloc_layout"
    if list(expected_closure) == REGISTER_BIJECTION_FPO_CLOSURE and (not expected_code_renames):
        return "equal_body_strict"
    return "equal_body_eh_structural_local"


CODEVIEW_X86_REGISTER_NUMBERS = {
    "eax": 17,
    "ecx": 18,
    "edx": 19,
    "ebx": 20,
    "esp": 21,
    "ebp": 22,
    "esi": 23,
    "edi": 24,
}
CODEVIEW_REGISTER_RECORD_TYPE = 2


def apply_register_bijection(
    body: bytes,
    mapping: dict,
    region: tuple[int, int],
    relocation_offsets: frozenset,
    context: str,
    relocations: dict | None = None,
    code_length: int | None = None,
    internal_targets: frozenset | None = None,
) -> tuple[bytes, dict]:
    """Rewrite one region's general-register fields under a proved bijection.

    Every obligation this class rests on is checked here: total decode, closed
    forms, structural-register exclusion, relocation disjointness, the
    liveness proof for the region's boundary, and length preservation verified
    by re-decoding the image.
    """
    require_payload_free_declaration(mapping, f"{context} register mapping")
    body = bytes(body)
    start, end = region
    instructions = decode_ia32_bijection_body(body, context, relocations, code_length)
    limit = len(body) if code_length is None else code_length
    boundaries = {item["offset"] for item in instructions}
    boundaries.add(limit)
    require(end <= limit, f"{context}: region reaches past the body's code")
    if any((item["indirect"] for item in instructions)):
        require(
            internal_targets is not None,
            f"{context}: a computed jump requires the relocated in-body target set",
        )
        entered = sorted((target for target in internal_targets if start < target < end))
        require(
            not entered,
            f"{context}: a relocated in-body target at {entered[:1]} enters the region other than at its first instruction",
        )
    require(
        start in boundaries and end in boundaries and (start < end),
        f"{context}: region does not span whole instructions",
    )
    numbers = {}
    for source, destination in mapping.items():
        require(
            source in _IA32_REGISTER_NUMBERS and destination in _IA32_REGISTER_NUMBERS,
            f"{context}: mapping names an unknown register",
        )
        numbers[_IA32_REGISTER_NUMBERS[source]] = _IA32_REGISTER_NUMBERS[destination]
    support = set(mapping) | set(mapping.values())
    require(
        len(set(mapping.values())) == len(mapping) and set(mapping.values()) == set(mapping),
        f"{context}: mapping is not a bijection of one register set",
    )
    require(
        all((source != destination for source, destination in mapping.items())),
        f"{context}: mapping fixes a register it names",
    )
    require(
        "esp" not in support,
        f"{context}: mapping touches ESP, whose encodings carry ModRM/SIB structure",
    )
    live, successors = _register_bijection_live_sets(instructions, context)
    inside = [item for item in instructions if start <= item["offset"] < end]
    require(inside, f"{context}: region contains no instruction")
    require(
        inside[-1]["offset"] + inside[-1]["length"] == end,
        f"{context}: region does not end on an instruction boundary",
    )
    entry = instructions.index(inside[0])
    for item in inside:
        blocked = support & set(item.get("frozen", frozenset()))
        require(
            not blocked,
            f"{context}: {sorted(blocked)} is named by a sub-register field at {item['offset']} that sigma cannot rewrite",
        )
    for index, item in enumerate(instructions):
        for edge in successors[index]:
            crosses_in = (
                not start <= item["offset"] < end and start <= instructions[edge]["offset"] < end
            )
            if crosses_in:
                require(
                    edge == entry,
                    f"{context}: control enters the region other than at its first instruction",
                )
    support_atoms = ia32_register_atoms(support)
    dead_in = support_atoms & set(live[entry])
    require(
        not dead_in, f"{context}: {_ia32_atom_registers(dead_in)} is live on entry to the region"
    )
    affected = {
        index
        for index, item in enumerate(instructions)
        if start <= item["offset"] < end
        and item["flow"] not in ("ret", "exit")
        and support_atoms & (set(item["read_atoms"]) | set(item["write_atoms"]))
    }
    sigma_reachable = set(affected)
    frontier = list(affected)
    while frontier:
        node = frontier.pop()
        for edge in successors[node]:
            if edge not in sigma_reachable:
                sigma_reachable.add(edge)
                frontier.append(edge)
    for index, item in enumerate(instructions):
        if not start <= item["offset"] < end:
            continue
        for edge in successors[index]:
            if start <= instructions[edge]["offset"] < end:
                continue
            leaking = support_atoms & set(live[edge])
            require(
                not leaking,
                f"{context}: {_ia32_atom_registers(leaking)} is live on an edge leaving the region at {item['offset']}",
            )
        if item["flow"] in ("ret", "exit"):
            leaking = support_atoms & set(item["read_atoms"])
            require(
                not leaking or index not in sigma_reachable,
                f"{context}: {_ia32_atom_registers(leaking)} is live at the region's return",
            )
    image = bytearray(body)
    rewritten = []
    for item in inside:
        for byte_index, shift in item["fields"]:
            value = image[byte_index] >> shift & 7
            if value not in numbers:
                continue
            require(
                byte_index not in relocation_offsets,
                f"{context}: a rewritten byte overlaps a relocation",
            )
            image[byte_index] = (image[byte_index] & ~(7 << shift) | numbers[value] << shift) & 255
            rewritten.append(byte_index)
    require(rewritten, f"{context}: the bijection rewrites nothing")
    image = bytes(image)
    require(len(image) == len(body), f"{context}: the image changed the body length")
    image_instructions = decode_ia32_bijection_body(
        image, f"{context} image", relocations, code_length
    )
    require(
        [(item["offset"], item["length"]) for item in image_instructions]
        == [(item["offset"], item["length"]) for item in instructions],
        f"{context}: the image changed an instruction boundary",
    )
    for left, right in zip(image_instructions, instructions):
        form = _bijection_form_for(right["opcode"])
        opreg = form is not None and form["opreg"] is not None
        mask = 248 if opreg else 65535
        require(
            left["opcode"] & mask == right["opcode"] & mask
            and left["flow"] == right["flow"]
            and (left["target"] == right["target"]),
            f"{context}: the image changed an opcode or a branch",
        )
    for left, right in zip(image_instructions, instructions):
        expected_reads = frozenset(
            (
                mapping.get(name, name) if start <= right["offset"] < end else name
                for name in right["reads"]
            )
        )
        expected_writes = frozenset(
            (
                mapping.get(name, name) if start <= right["offset"] < end else name
                for name in right["writes"]
            )
        )
        require(
            left["reads"] == expected_reads and left["writes"] == expected_writes,
            f"{context}: the image's operand set at {right['offset']} is not the bijection's image",
        )
    changed = sorted({index for index in range(len(body)) if body[index] != image[index]})
    require(
        changed == sorted(set(rewritten)),
        f"{context}: the image changed a byte the bijection did not name",
    )
    return (
        image,
        {
            "rewritten_offsets": changed,
            "region_instruction_count": len(inside),
            "instruction_count": len(instructions),
            "code_length": limit,
        },
    )


def _codeview_register_field(record: dict, context: str) -> int:
    """The offset of one S_REGISTER record's two-byte register field."""
    field_at = record["offset"] + 4 + 2
    require(
        field_at + 2 <= record["offset"] + record["size"],
        f"{context}: S_REGISTER record has no register field",
    )
    return field_at


def _codeview_register_name(stream: bytes, field_at: int, context: str) -> str:
    number = int.from_bytes(stream[field_at : field_at + 2], "little")
    name = next(
        (key for key, value in CODEVIEW_X86_REGISTER_NUMBERS.items() if value == number), None
    )
    require(name is not None, f"{context}: S_REGISTER names a non-general register")
    return name


def apply_codeview_register_bijection(
    stream: bytes,
    mapping: dict,
    declared: list[dict],
    context: str,
    donor_stream: bytes | None = None,
) -> bytes:
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
    require_payload_free_declaration(mapping, f"{context} register mapping")
    require_payload_free_declaration(declared, f"{context} CodeView declaration")
    records = parse_codeview_symbol_stream(stream, context)
    image = bytearray(stream)
    if donor_stream is None:
        seen = []
        for record in records:
            if record["type"] != CODEVIEW_REGISTER_RECORD_TYPE:
                continue
            field_at = _codeview_register_field(record, context)
            try:
                name = _codeview_register_name(image, field_at, context)
            except ByteIdentityError:
                continue
            if name not in mapping:
                continue
            seen.append(
                {
                    "name": record["name"],
                    "record_offset": record["offset"],
                    "donor_register": name,
                    "image_register": mapping[name],
                }
            )
            image[field_at : field_at + 2] = CODEVIEW_X86_REGISTER_NUMBERS[mapping[name]].to_bytes(
                2, "little"
            )
        require(seen == declared, f"{context}: the S_REGISTER map differs from its declaration")
    else:
        donor_records = parse_codeview_symbol_stream(donor_stream, f"{context} donor")
        require(
            [(item["offset"], item["size"], item["type"]) for item in donor_records]
            == [(item["offset"], item["size"], item["type"]) for item in records],
            f"{context}: the donor's debug$S record list differs from the seed's",
        )
        movable = set()
        for seed_record, donor_record in zip(records, donor_records):
            if seed_record["type"] == CODEVIEW_REGISTER_RECORD_TYPE:
                field_at = _codeview_register_field(seed_record, context)
                movable.update((field_at, field_at + 1))
                continue
            if seed_record["name"] == donor_record["name"]:
                continue
            kind = local_symbol_kind(seed_record["name"])
            require(
                kind is not None
                and kind == local_symbol_kind(donor_record["name"])
                and (len(seed_record["name"]) == len(donor_record["name"])),
                f"{context}: the donor's debug$S renames a non-local symbol",
            )
            name_at = (
                seed_record["offset"] + 4 + CODEVIEW_SYMBOL_NAME_OFFSETS[seed_record["type"]] + 1
            )
            movable.update(range(name_at, name_at + len(seed_record["name"])))
        differing = {index for index in range(len(stream)) if stream[index] != donor_stream[index]}
        require(
            differing <= movable,
            f"{context}: the donor's debug$S differs outside its S_REGISTER fields and object-local names",
        )
        for seed_record in records:
            if seed_record["type"] != CODEVIEW_REGISTER_RECORD_TYPE:
                continue
            field_at = _codeview_register_field(seed_record, context)
            name = _codeview_register_name(donor_stream, field_at, context)
            image[field_at : field_at + 2] = CODEVIEW_X86_REGISTER_NUMBERS[name].to_bytes(
                2, "little"
            )
        offsets = [item["record_offset"] for item in declared]
        require(
            len(set(offsets)) == len(offsets),
            f"{context}: the S_REGISTER map declares a record twice",
        )
        by_offset = {item["offset"]: item for item in records}
        for item in declared:
            record = by_offset.get(item["record_offset"])
            require(
                record is not None
                and record["type"] == CODEVIEW_REGISTER_RECORD_TYPE
                and (record["name"] == item["name"]),
                f"{context}: the S_REGISTER map names no such record",
            )
            field_at = _codeview_register_field(record, context)
            name = _codeview_register_name(donor_stream, field_at, context)
            require(
                name == item["donor_register"] and mapping.get(name) == item["image_register"],
                f"{context}: the S_REGISTER map differs from its declaration",
            )
            image[field_at : field_at + 2] = CODEVIEW_X86_REGISTER_NUMBERS[
                item["image_register"]
            ].to_bytes(2, "little")
    image = bytes(image)
    require(
        [
            (item["offset"], item["size"], item["type"], item["name"])
            for item in parse_codeview_symbol_stream(image, f"{context} image")
        ]
        == [(item["offset"], item["size"], item["type"], item["name"]) for item in records],
        f"{context}: the mapped stream is not the same record list",
    )
    return image


def validate_register_bijection(value: object, context: str, body_length: int) -> dict:
    """Validate one register-bijection certificate declaration."""
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(
        value,
        {
            "kind",
            "mapping",
            "region_start",
            "region_end",
            "expected_region_instruction_count",
            "expected_instruction_count",
            "expected_rewritten_offsets",
            "debug_s_register_map",
            "expected_seed_debug_s_sha256",
            "expected_image_debug_s_sha256",
            "authenticity_rationale",
            "expected_code_length",
            "expected_internal_relocation_targets",
            "expected_rewritten_offsets_restoring_seed",
        },
        context,
        optional={
            "expected_code_length",
            "expected_internal_relocation_targets",
            "expected_rewritten_offsets_restoring_seed",
        },
    )
    require(value.get("kind") == REGISTER_BIJECTION_KIND, f"{context}.kind differs")
    mapping = value.get("mapping")
    require(
        isinstance(mapping, dict)
        and 2 <= len(mapping) <= 8
        and all(
            (
                isinstance(key, str)
                and isinstance(item, str)
                and (key in _IA32_REGISTER_NUMBERS)
                and (item in _IA32_REGISTER_NUMBERS)
                for key, item in mapping.items()
            )
        ),
        f"{context}.mapping is invalid",
    )
    require(
        set(mapping) == set(mapping.values())
        and len(set(mapping.values())) == len(mapping)
        and all((key != item for key, item in mapping.items())),
        f"{context}.mapping is not a fixed-point-free bijection",
    )
    require(not set(mapping) & _IA32_STRUCTURAL_REGISTERS, f"{context}.mapping touches ESP or EBP")
    start = require_exact_int(
        value.get("region_start"), f"{context}.region_start", minimum=1, maximum=body_length - 1
    )
    end = require_exact_int(
        value.get("region_end"), f"{context}.region_end", minimum=2, maximum=body_length - 1
    )
    require(start < end, f"{context}: region is empty")
    require(
        require_exact_int(
            value.get("expected_region_instruction_count"),
            f"{context}.expected_region_instruction_count",
            minimum=1,
        )
        <= require_exact_int(
            value.get("expected_instruction_count"),
            f"{context}.expected_instruction_count",
            minimum=2,
        ),
        f"{context}: region instruction count exceeds the body's",
    )
    offsets = value.get("expected_rewritten_offsets")
    require(
        isinstance(offsets, list)
        and offsets
        and (offsets == sorted(set(offsets)))
        and all((type(offset) is int and start <= offset < end for offset in offsets)),
        f"{context}.expected_rewritten_offsets is invalid",
    )
    declared = value.get("debug_s_register_map")
    require(
        isinstance(declared, list) and len(declared) <= 8,
        f"{context}.debug_s_register_map is invalid",
    )
    normalized_map = []
    for index, item in enumerate(declared):
        item_context = f"{context}.debug_s_register_map[{index}]"
        require(isinstance(item, dict), f"{item_context} must be an object")
        exact_audit_keys(
            item, {"name", "record_offset", "donor_register", "image_register"}, item_context
        )
        require(
            isinstance(item.get("name"), str) and item["name"], f"{item_context}.name is invalid"
        )
        require(
            item.get("donor_register") in mapping
            and mapping[item["donor_register"]] == item.get("image_register"),
            f"{item_context} is not the declared mapping",
        )
        normalized_map.append(
            {
                "name": item["name"],
                "record_offset": require_exact_int(
                    item.get("record_offset"), f"{item_context}.record_offset", minimum=0
                ),
                "donor_register": item["donor_register"],
                "image_register": item["image_register"],
            }
        )
    rationale = value.get("authenticity_rationale")
    require(
        isinstance(rationale, str) and len(rationale) >= 40,
        f"{context}.authenticity_rationale is missing",
    )
    code_length = value.get("expected_code_length")
    if code_length is not None:
        code_length = require_exact_int(
            code_length, f"{context}.expected_code_length", minimum=2, maximum=body_length
        )
        require(end <= code_length, f"{context}: region reaches past the declared code length")
    restoring = value.get("expected_rewritten_offsets_restoring_seed")
    if restoring is not None:
        require(
            isinstance(restoring, list)
            and restoring == sorted(set(restoring))
            and (set(restoring) <= set(offsets)),
            f"{context}.expected_rewritten_offsets_restoring_seed is invalid",
        )
    targets = value.get("expected_internal_relocation_targets")
    if targets is not None:
        require(
            isinstance(targets, list)
            and targets == sorted(set(targets))
            and all((type(item) is int and 0 <= item < body_length for item in targets)),
            f"{context}.expected_internal_relocation_targets is invalid",
        )
        require(
            not any((start < item < end for item in targets)),
            f"{context}: a relocated in-body target enters the region",
        )
    normalized = {
        "kind": REGISTER_BIJECTION_KIND,
        "mapping": dict(sorted(mapping.items())),
        "region_start": start,
        "region_end": end,
        "expected_region_instruction_count": value["expected_region_instruction_count"],
        "expected_instruction_count": value["expected_instruction_count"],
        "expected_rewritten_offsets": list(offsets),
        "debug_s_register_map": normalized_map,
        "expected_seed_debug_s_sha256": require_sha(
            value.get("expected_seed_debug_s_sha256"), f"{context}.expected_seed_debug_s_sha256"
        ),
        "expected_image_debug_s_sha256": require_sha(
            value.get("expected_image_debug_s_sha256"), f"{context}.expected_image_debug_s_sha256"
        ),
        "authenticity_rationale": rationale,
    }
    if code_length is not None:
        normalized["expected_code_length"] = code_length
    if targets is not None:
        normalized["expected_internal_relocation_targets"] = list(targets)
    if restoring is not None:
        normalized["expected_rewritten_offsets_restoring_seed"] = list(restoring)
    return normalized
