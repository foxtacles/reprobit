from __future__ import annotations

import struct

from reprobit.binary import require
from reprobit.coff import (
    CoffObject,
    coff_body,
    coff_table,
    detailed_relocations,
    section_definitions,
)
from reprobit.ia32 import supported_ia32_instruction_length

from .coff import (
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    comdat_primary_identity_multiset,
    function_multiset,
)
from .composition import (
    compose_equal_body_comdat,
    instruction_mosaic_metadata_sha256,
    require_instruction_mosaic_semantic_relocations,
)
from .foundation import (
    exact_audit_keys,
    require_exact_int,
    require_payload_free_declaration,
    require_sha,
    sha256_bytes,
)
from .ia32 import require_declared_relocation_semantics
from .register_semantics import _ia32_backward_liveness, decode_ia32_bijection_instruction

"""Classic compiler algorithms: relational."""
RELATIONAL_FORM_CLASS = "retail_exact_relational_form"
RELATIONAL_FORM_KIND = "mirrored_relational_form_v1"
RELATIONAL_FORM_FPO_CLOSURE = [".debug$F", ".debug$S"]
RELATIONAL_FORM_EH_CLOSURE = [".debug$S", ".xdata$x"]
IA32_ARITHMETIC_FLAGS = frozenset({"cf", "pf", "af", "zf", "sf", "of"})
IA32_RELATIONAL_PRESERVED_FLAGS = frozenset({"zf"})
IA32_RELATIONAL_CHANGED_FLAGS = IA32_ARITHMETIC_FLAGS - IA32_RELATIONAL_PRESERVED_FLAGS
IA32_CONDITION_FLAGS = {
    0: frozenset({"of"}),
    1: frozenset({"of"}),
    2: frozenset({"cf"}),
    3: frozenset({"cf"}),
    4: frozenset({"zf"}),
    5: frozenset({"zf"}),
    6: frozenset({"cf", "zf"}),
    7: frozenset({"cf", "zf"}),
    8: frozenset({"sf"}),
    9: frozenset({"sf"}),
    10: frozenset({"pf"}),
    11: frozenset({"pf"}),
    12: frozenset({"sf", "of"}),
    13: frozenset({"sf", "of"}),
    14: frozenset({"zf", "sf", "of"}),
    15: frozenset({"zf", "sf", "of"}),
}
IA32_CONDITION_NAMES = {
    0: "o",
    1: "no",
    2: "b",
    3: "ae",
    4: "e",
    5: "ne",
    6: "be",
    7: "a",
    8: "s",
    9: "ns",
    10: "p",
    11: "np",
    12: "l",
    13: "ge",
    14: "le",
    15: "g",
}
IA32_CONDITION_CODES = {name: code for code, name in IA32_CONDITION_NAMES.items()}
IA32_RELATIONAL_MIRROR = {
    "b": "a",
    "a": "b",
    "ae": "be",
    "be": "ae",
    "e": "e",
    "ne": "ne",
    "l": "g",
    "g": "l",
    "ge": "le",
    "le": "ge",
}
IA32_RELATIONAL_COMPARE_PAIRS = {56: 58, 58: 56, 57: 59, 59: 57}
_IA32_RELATIONAL_PREFIXES = frozenset({38, 46, 54, 62, 100, 101, 102})
_IA32_RELATIONAL_REPEAT_PREFIXES = frozenset({242, 243})
_IA32_RELATIONAL_STRING_QUIET = frozenset({108, 109, 110, 111, 164, 165, 170, 171, 172, 173})
_IA32_RELATIONAL_STRING_COMPARE = frozenset({166, 167, 174, 175})
_IA32_RELATIONAL_REFUSED_OPCODES = frozenset({154, 234, 204, 205, 206, 207, 240, 241, 244})


def _ia32_relational_flag_table() -> dict:
    """Flag effect by opcode for the forms whose effect is opcode-determined.

    Everything absent falls back to the fail-closed default (reads every
    flag, writes none), which can only cause a refusal.
    """
    quiet = (frozenset(), frozenset())
    table = {}
    for opcode in (
        136,
        137,
        138,
        139,
        140,
        141,
        142,
        160,
        161,
        162,
        163,
        198,
        199,
        134,
        135,
        152,
        153,
        200,
        201,
        96,
        97,
        104,
        106,
        6,
        14,
        22,
        30,
        7,
        23,
        31,
        252,
        253,
    ):
        table[opcode] = quiet
    for opcode in range(176, 192):
        table[opcode] = quiet
    for opcode in range(80, 96):
        table[opcode] = quiet
    for opcode in range(144, 152):
        table[opcode] = quiet
    for opcode in range(216, 224):
        table[opcode] = quiet
    for opcode in _IA32_RELATIONAL_STRING_QUIET:
        table[opcode] = quiet
    for base in (0, 8, 32, 40, 48, 56):
        for step in range(6):
            table[base + step] = (frozenset(), IA32_ARITHMETIC_FLAGS)
    for base in (16, 24):
        for step in range(6):
            table[base + step] = (frozenset({"cf"}), IA32_ARITHMETIC_FLAGS)
    for opcode in (132, 133, 168, 169):
        table[opcode] = (frozenset(), IA32_ARITHMETIC_FLAGS)
    for opcode in _IA32_RELATIONAL_STRING_COMPARE:
        table[opcode] = (frozenset(), IA32_ARITHMETIC_FLAGS)
    for opcode in range(64, 80):
        table[opcode] = (frozenset(), IA32_ARITHMETIC_FLAGS - {"cf"})
    for opcode in (105, 107, 4015):
        table[opcode] = (frozenset(), frozenset({"cf", "of"}))
    for opcode in (4022, 4023, 4030, 4031):
        table[opcode] = quiet
    for opcode in (4003, 4011, 4019, 4027):
        table[opcode] = (frozenset(), frozenset({"cf"}))
    for opcode in (4028, 4029):
        table[opcode] = (frozenset(), frozenset({"zf"}))
    for code in range(16):
        table[3984 | code] = (IA32_CONDITION_FLAGS[code], frozenset())
        table[3904 | code] = (IA32_CONDITION_FLAGS[code], frozenset())
    table[156] = (IA32_ARITHMETIC_FLAGS, frozenset())
    table[157] = (frozenset(), IA32_ARITHMETIC_FLAGS)
    table[158] = (frozenset(), IA32_ARITHMETIC_FLAGS - {"of"})
    table[159] = (IA32_ARITHMETIC_FLAGS - {"of"}, frozenset())
    table[245] = (frozenset({"cf"}), frozenset({"cf"}))
    table[248] = (frozenset(), frozenset({"cf"}))
    table[249] = (frozenset(), frozenset({"cf"}))
    return table


IA32_RELATIONAL_FLAG_EFFECTS = _ia32_relational_flag_table()


def _ia32_relational_group_table() -> dict:
    """Flag effect by (opcode, ModRM extension digit).

    Reading the digit off the encoding makes these forms EXACT.  An
    opcode-granular table would have to take the union of the members' reads
    and the intersection of their writes -- sound, but it leaves CF live
    across every `cmp m, imm` in the body because ADC and SBB share the
    opcode, and that alone turned a provable site into a refusal.
    """
    group1 = {
        digit: (frozenset({"cf"}) if digit in (2, 3) else frozenset(), IA32_ARITHMETIC_FLAGS)
        for digit in range(8)
    }
    group3 = {
        0: (frozenset(), IA32_ARITHMETIC_FLAGS),
        1: (frozenset(), IA32_ARITHMETIC_FLAGS),
        2: (frozenset(), frozenset()),
        3: (frozenset(), IA32_ARITHMETIC_FLAGS),
        4: (frozenset(), frozenset({"cf", "of"})),
        5: (frozenset(), frozenset({"cf", "of"})),
        6: (frozenset(), frozenset()),
        7: (frozenset(), frozenset()),
    }
    group5 = {
        digit: (frozenset(), IA32_ARITHMETIC_FLAGS - {"cf"} if digit in (0, 1) else frozenset())
        for digit in range(8)
    }
    shift_one = {
        digit: (frozenset({"cf"}) if digit in (2, 3) else frozenset(), frozenset({"cf", "of"}))
        for digit in range(8)
    }
    shift_var = {
        digit: (frozenset({"cf"}) if digit in (2, 3) else frozenset(), frozenset())
        for digit in range(8)
    }
    return {
        128: group1,
        129: group1,
        131: group1,
        246: group3,
        247: group3,
        254: group5,
        255: group5,
        208: shift_one,
        209: shift_one,
        192: shift_var,
        193: shift_var,
        210: shift_var,
        211: shift_var,
    }


IA32_RELATIONAL_GROUP_FLAG_EFFECTS = _ia32_relational_group_table()


def relational_form_delegate(expected_closure: object, expected_code_renames: object) -> str:
    """Name the installation delegate from the PINS alone.

    Identical in spirit to `register_bijection_delegate`, minus its relocation
    branch: this class can never move a relocation, so
    `equal_body_eh_reloc_layout` is unreachable and is not offered.
    """
    if list(expected_closure) == RELATIONAL_FORM_FPO_CLOSURE and (not expected_code_renames):
        return "equal_body_strict"
    return "equal_body_eh_structural_local"


def ia32_relational_flow_walk(
    body: bytes,
    relocations: dict | None,
    context: str,
    code_length: int | None = None,
    external_entries: frozenset | None = None,
) -> tuple[list[dict], list[list[int]], list[int]]:
    """Tier A: boundaries, closed flow classification, CFG and flag facts.

    Obligation 2.  Returns `(items, successors, entry_indices)`.  Every item
    carries `reads_flags` / `writes_flags`; an opcode outside the table reads
    every flag and writes none, so an unmodelled instruction can only make a
    flag look MORE live.
    """
    require(isinstance(body, (bytes, bytearray)) and body, f"{context}: body is empty")
    body = bytes(body)
    relocations = relocations or {}
    limit = len(body) if code_length is None else code_length
    require(
        isinstance(limit, int) and (not isinstance(limit, bool)) and (0 < limit <= len(body)),
        f"{context}: code length is out of range",
    )
    code = body[:limit]
    items = []
    offset = 0
    while offset < len(code):
        length = supported_ia32_instruction_length(code[offset:], f"{context} at {offset}")
        cursor = offset
        repeated = False
        while (
            code[cursor] in _IA32_RELATIONAL_PREFIXES
            or code[cursor] in _IA32_RELATIONAL_REPEAT_PREFIXES
        ):
            if code[cursor] in _IA32_RELATIONAL_REPEAT_PREFIXES:
                require(
                    cursor + 1 < offset + length
                    and (
                        code[cursor + 1] in _IA32_RELATIONAL_STRING_QUIET
                        or code[cursor + 1] in _IA32_RELATIONAL_STRING_COMPARE
                    ),
                    f"{context}: the repeat prefix at {offset} does not prefix a string opcode",
                )
                repeated = True
            cursor += 1
            require(
                cursor < offset + length, f"{context}: instruction at {offset} is only prefixes"
            )
        opcode = code[cursor]
        require(
            opcode not in _IA32_RELATIONAL_REFUSED_OPCODES,
            f"{context}: opcode 0x{opcode:02x} at {offset} is outside the relational-form flow table",
        )
        if opcode == 15:
            require(
                cursor + 1 < offset + length, f"{context}: truncated two-byte opcode at {offset}"
            )
            opcode = 3840 | code[cursor + 1]
        flow, target, condition = ("fall", None, None)
        if 112 <= opcode <= 127:
            flow, condition = ("jcc", opcode & 15)
            target = (
                offset
                + length
                + int.from_bytes(code[offset + length - 1 : offset + length], "little", signed=True)
            )
        elif 3968 <= opcode <= 3983:
            flow, condition = ("jcc", opcode & 15)
            target = (
                offset
                + length
                + int.from_bytes(code[offset + length - 4 : offset + length], "little", signed=True)
            )
        elif opcode in (235, 233):
            flow = "jmp"
            width = 1 if opcode == 235 else 4
            target = (
                offset
                + length
                + int.from_bytes(
                    code[offset + length - width : offset + length], "little", signed=True
                )
            )
        elif opcode == 232:
            flow = "call"
        elif opcode in (194, 195):
            flow = "ret"
        elif opcode in (224, 225, 226, 227):
            flow = "jcc"
            target = (
                offset
                + length
                + int.from_bytes(code[offset + length - 1 : offset + length], "little", signed=True)
            )
        elif opcode == 255:
            require(cursor + 1 < offset + length, f"{context}: FF form at {offset} lacks its ModRM")
            extension = code[cursor + 1] >> 3 & 7
            require(
                extension not in (3, 5),
                f"{context}: a far transfer at {offset} makes the control-flow graph unknowable",
            )
            if extension == 2:
                flow = "call"
            elif extension == 4:
                require(
                    external_entries,
                    f"{context}: a computed jump at {offset} makes the control-flow graph unknowable",
                )
                flow = "computed"
                target = None
        if (
            flow in ("jmp", "jcc")
            and (opcode == 233 or 3968 <= opcode <= 3983)
            and (relocations.get(offset + length - 4, {}).get("width") == 4)
        ):
            flow, target, condition = ("exit", None, None)
        if flow == "jcc" and condition is not None:
            reads = IA32_CONDITION_FLAGS[condition]
            writes = frozenset()
        elif flow in ("jcc", "jmp", "call", "ret", "exit"):
            reads = frozenset({"zf"}) if opcode in (224, 225) else frozenset()
            writes = frozenset()
        elif opcode in IA32_RELATIONAL_GROUP_FLAG_EFFECTS:
            digit = code[cursor + 1] >> 3 & 7
            reads, writes = IA32_RELATIONAL_GROUP_FLAG_EFFECTS[opcode][digit]
        else:
            reads, writes = IA32_RELATIONAL_FLAG_EFFECTS.get(
                opcode, (IA32_ARITHMETIC_FLAGS, frozenset())
            )
            if repeated and opcode in _IA32_RELATIONAL_STRING_COMPARE:
                reads = reads | {"zf"}
        items.append(
            {
                "offset": offset,
                "length": length,
                "opcode": opcode,
                "opcode_at": cursor,
                "flow": flow,
                "target": target,
                "condition": condition,
                "reads_flags": frozenset(reads),
                "writes_flags": frozenset(writes),
            }
        )
        offset += length
    require(offset == len(code), f"{context}: body does not decode to exhaustion")
    starts = {item["offset"] for item in items}
    for item in items:
        require(
            item["target"] is None or item["target"] in starts,
            f"{context}: the branch at {item['offset']} does not target an instruction boundary of this body",
        )
    index_of = {item["offset"]: index for index, item in enumerate(items)}
    successors = []
    for index, item in enumerate(items):
        edges = []
        if item["flow"] in ("fall", "jcc", "call"):
            if index + 1 < len(items):
                edges.append(index + 1)
            else:
                require(item["flow"] != "fall", f"{context}: body falls off its end")
        if item["flow"] in ("jcc", "jmp") and item["target"] is not None:
            edges.append(index_of[item["target"]])
        if item["flow"] == "computed":
            edges.extend(
                (
                    index_of[target]
                    for target in sorted(external_entries or ())
                    if target in index_of
                )
            )
        successors.append(sorted(set(edges)))
    code_end = items[-1]["offset"] + items[-1]["length"] if items else 0
    external = sorted((target for target in external_entries or () if target < code_end))
    for target in external:
        require(
            target in index_of,
            f"{context}: the external entry {target} is not an instruction boundary of this body",
        )
    entries = [0] + [index_of[target] for target in external if target != 0]
    seen, stack = (set(), list(entries))
    while stack:
        index = stack.pop()
        if index in seen:
            continue
        seen.add(index)
        stack.extend(successors[index])
    unreachable = sorted(
        (items[index]["offset"] for index in range(len(items)) if index not in seen)
    )
    require(
        not unreachable,
        f"{context}: the instruction at {unreachable[:1]} is reachable neither from the entry nor from a declared external entry, so the control-flow graph is incomplete",
    )
    return (items, successors, entries)


def ia32_relational_flag_liveness(
    items: list[dict], successors: list[list[int]], context: str
) -> list[frozenset]:
    """Backward per-flag liveness, on the SAME fixpoint the register and web
    certificates use -- the flags are simply its atoms."""
    shim = [
        {"read_atoms": item["reads_flags"], "write_atoms": item["writes_flags"]} for item in items
    ]
    return _ia32_backward_liveness(shim, successors, context)


def apply_relational_form(
    body: bytes,
    sites: list,
    relocation_offsets: frozenset,
    context: str,
    relocations: dict | None = None,
    code_length: int | None = None,
    external_entries: frozenset | None = None,
) -> tuple[bytes, dict]:
    """Reverse each declared compare and mirror its branch, or refuse.

    Obligations 2 through 7 are discharged here; the composer adds
    provenance, retail equality and debug fidelity around it.
    """
    require_payload_free_declaration(sites, f"{context} relational-form declaration")
    require(isinstance(body, (bytes, bytearray)) and body, f"{context}: body is empty")
    body = bytes(body)
    require(isinstance(sites, list) and sites, f"{context}: no site is declared")
    items, successors, entries = ia32_relational_flow_walk(
        body, relocations, context, code_length, external_entries
    )
    index_of = {item["offset"]: index for index, item in enumerate(items)}
    predecessors = [[] for _ in items]
    for index, edges in enumerate(successors):
        for edge in edges:
            predecessors[edge].append(index)
    live = ia32_relational_flag_liveness(items, successors, context)
    image = bytearray(body)
    rewritten = []
    proved = []
    for ordinal, site in enumerate(sites):
        site_context = f"{context} site {ordinal}"
        compare_at = site["compare_offset"]
        branch_at = site["branch_offset"]
        require(
            compare_at in index_of and branch_at in index_of,
            f"{site_context}: an offset is not an instruction boundary",
        )
        compare_index = index_of[compare_at]
        branch_index = index_of[branch_at]
        compare = items[compare_index]
        branch = items[branch_index]
        require(
            branch_index == compare_index + 1,
            f"{site_context}: the branch does not immediately follow the compare",
        )
        require(
            compare["opcode"] in IA32_RELATIONAL_COMPARE_PAIRS,
            f"{site_context}: the instruction at {compare_at} is not a two-operand cmp with a reversible encoding",
        )
        require(compare["flow"] == "fall", f"{site_context}: the compare is a control transfer")
        require(
            branch["flow"] == "jcc" and branch["condition"] is not None,
            f"{site_context}: the instruction at {branch_at} is not a conditional branch this table can mirror",
        )
        require(
            predecessors[branch_index] == [compare_index],
            f"{site_context}: the branch has a predecessor other than its compare, so another path would consume flags this compare did not produce",
        )
        decoded = decode_ia32_bijection_instruction(
            body, compare_at, f"{site_context} compare", relocations
        )
        require(
            decoded["opcode"] == compare["opcode"] and decoded["length"] == compare["length"],
            f"{site_context}: the two decoders disagree about the compare",
        )
        decode_ia32_bijection_instruction(body, branch_at, f"{site_context} branch", relocations)
        seed_name = IA32_CONDITION_NAMES[branch["condition"]]
        require(
            seed_name in IA32_RELATIONAL_MIRROR,
            f"{site_context}: condition 'j{seed_name}' has no mirror -- it reads a flag whose value under the reversal is not a function of the original flags",
        )
        image_name = IA32_RELATIONAL_MIRROR[seed_name]
        require(
            site["seed_condition"] == seed_name and site["image_condition"] == image_name,
            f"{site_context}: the declared condition pair is not the closed table's mirror",
        )
        out = (
            frozenset().union(*[live[edge] for edge in successors[branch_index]])
            if successors[branch_index]
            else frozenset()
        )
        offending = sorted(out & IA32_RELATIONAL_CHANGED_FLAGS)
        require(
            not offending,
            f"{site_context}: the reversal changes {offending} and a successor of the branch reads it",
        )
        compare_byte = compare["opcode_at"]
        branch_byte = branch["opcode_at"] + (1 if branch["opcode"] >= 3840 else 0)
        require(
            compare_byte not in relocation_offsets and branch_byte not in relocation_offsets,
            f"{site_context}: a rewritten byte overlaps a relocation",
        )
        if site.get("reencode"):
            modrm_at = compare_byte + 1
            modrm = image[modrm_at]
            require(modrm >> 6 == 3, f"{site_context}: reencode requires a register-direct compare")
            require(
                modrm_at not in relocation_offsets,
                f"{site_context}: a rewritten byte overlaps a relocation",
            )
            image[modrm_at] = modrm & 192 | (modrm & 7) << 3 | modrm >> 3 & 7
            image[branch_byte] = image[branch_byte] & 240 | IA32_CONDITION_CODES[image_name]
            rewritten.extend([modrm_at, branch_byte])
        else:
            image[compare_byte] = IA32_RELATIONAL_COMPARE_PAIRS[compare["opcode"]]
            image[branch_byte] = image[branch_byte] & 240 | IA32_CONDITION_CODES[image_name]
            rewritten.extend([compare_byte, branch_byte])
        image_compare_opcode = (
            compare["opcode"]
            if site.get("reencode")
            else IA32_RELATIONAL_COMPARE_PAIRS[compare["opcode"]]
        )
        proved.append(
            {
                "compare_offset": compare_at,
                "branch_offset": branch_at,
                "seed_condition": seed_name,
                "image_condition": image_name,
                "seed_compare_opcode": compare["opcode"],
                "image_compare_opcode": image_compare_opcode,
                "changed_flags": sorted(IA32_RELATIONAL_CHANGED_FLAGS),
                "flags_live_out": sorted(out),
            }
        )
    for entry in entries[1:]:
        offending = sorted(live[entry] & IA32_RELATIONAL_CHANGED_FLAGS)
        require(
            not offending,
            f"{context}: the external entry at {items[entry]['offset']} has {offending} live, and the reversal changes it",
        )
    image = bytes(image)
    require(image != body, f"{context}: the image does not move the body")
    rewritten = sorted(set(rewritten))
    require(len(rewritten) == 2 * len(sites), f"{context}: two sites rewrite the same byte")
    require(
        {index for index in range(len(body)) if body[index] != image[index]} <= set(rewritten),
        f"{context}: the image changed a byte no site declares",
    )
    image_items, image_successors, image_entries = ia32_relational_flow_walk(
        image, relocations, f"{context} image", code_length, external_entries
    )
    require(
        len(image_items) == len(items)
        and all(
            (
                left["offset"] == right["offset"]
                and left["length"] == right["length"]
                and (left["flow"] == right["flow"])
                and (left["target"] == right["target"])
                for left, right in zip(items, image_items)
            )
        )
        and (image_successors == successors)
        and (image_entries == entries),
        f"{context}: the image does not re-decode to the same boundaries, flow and branch targets",
    )
    for site in proved:
        compare_item = image_items[index_of[site["compare_offset"]]]
        require(
            compare_item["opcode"] == site["image_compare_opcode"],
            f"{context}: the image compare opcode differs from its certificate",
        )
        branch_item = image_items[index_of[site["branch_offset"]]]
        require(
            IA32_CONDITION_NAMES[branch_item["condition"]] == site["image_condition"],
            f"{context}: the image branch is not the mirrored condition",
        )
    image_live = ia32_relational_flag_liveness(image_items, image_successors, f"{context} image")
    for site in proved:
        branch_index = index_of[site["branch_offset"]]
        edges = image_successors[branch_index]
        out = frozenset().union(*[image_live[edge] for edge in edges]) if edges else frozenset()
        offending = sorted(out & IA32_RELATIONAL_CHANGED_FLAGS)
        require(
            not offending,
            f"{context}: after the rewrite a successor of the branch at {site['branch_offset']} reads {offending}",
        )
        site["image_flags_live_out"] = sorted(out)
    for entry in image_entries[1:]:
        offending = sorted(image_live[entry] & IA32_RELATIONAL_CHANGED_FLAGS)
        require(
            not offending,
            f"{context}: after the rewrite the external entry at {image_items[entry]['offset']} has {offending} live",
        )
    return (
        image,
        {
            "kind": RELATIONAL_FORM_KIND,
            "sites": proved,
            "instruction_count": len(items),
            "rewritten_offsets": rewritten,
            "external_entries": [items[index]["offset"] for index in entries[1:]],
            "preserved_flags": sorted(IA32_RELATIONAL_PRESERVED_FLAGS),
            "changed_flags": sorted(IA32_RELATIONAL_CHANGED_FLAGS),
        },
    )


def relational_form_external_entries(obj: "CoffObject", section: dict, context: str) -> frozenset:
    """Every in-body offset a relocation of this COMDAT or of its closure
    children names.

    On a C++ EH function these are exactly the unwind funclet heads the
    `.xdata$x` table hands to the runtime -- code no decoded edge reaches.
    Deriving them (rather than letting an author declare them) is what makes
    obligation 2's reachability requirement closable without weakening it.
    """
    number = section["number"]
    entries = {
        row["target_value"]
        for row in detailed_relocations(obj, section)
        if row.get("target_section") == number
    }
    count, names = _comdat_child_closure(obj, section)
    require(count == len(names), f"{context}: malformed COMDAT closure")
    for child_name in names:
        child = _comdat_child(obj, section, child_name)
        entries |= {
            row["target_value"]
            for row in detailed_relocations(obj, child)
            if row.get("target_section") == number
        }
    entries.discard(0)
    return frozenset(entries)


def validate_relational_form(value: object, context: str, body_length: int) -> dict:
    """Validate one relational-form certificate declaration."""
    require(isinstance(value, dict), f"{context} must be an object")
    exact_audit_keys(
        value,
        {
            "kind",
            "sites",
            "expected_instruction_count",
            "expected_rewritten_offsets",
            "expected_external_entries",
            "expected_seed_debug_s_sha256",
            "authenticity_rationale",
            "expected_code_length",
        },
        context,
        optional={"expected_code_length"},
    )
    require(value.get("kind") == RELATIONAL_FORM_KIND, f"{context}.kind differs")
    sites = value.get("sites")
    require(isinstance(sites, list) and 1 <= len(sites) <= 64, f"{context}.sites is invalid")
    normalized_sites = []
    previous = -1
    for index, site in enumerate(sites):
        site_context = f"{context}.sites[{index}]"
        require(isinstance(site, dict), f"{site_context} must be an object")
        exact_audit_keys(
            site,
            {"compare_offset", "branch_offset", "seed_condition", "image_condition"},
            site_context,
        )
        compare_at = require_exact_int(
            site.get("compare_offset"),
            f"{site_context}.compare_offset",
            minimum=0,
            maximum=body_length - 2,
        )
        branch_at = require_exact_int(
            site.get("branch_offset"),
            f"{site_context}.branch_offset",
            minimum=1,
            maximum=body_length - 1,
        )
        require(compare_at > previous, f"{site_context}: sites are unsorted or overlapping")
        require(compare_at < branch_at, f"{site_context}: the branch does not follow the compare")
        previous = branch_at
        seed_condition = site.get("seed_condition")
        require(
            seed_condition in IA32_RELATIONAL_MIRROR,
            f"{site_context}.seed_condition has no mirror in the closed table",
        )
        require(
            site.get("image_condition") == IA32_RELATIONAL_MIRROR[seed_condition],
            f"{site_context}.image_condition is not the closed table's mirror",
        )
        normalized_sites.append(
            {
                "compare_offset": compare_at,
                "branch_offset": branch_at,
                "seed_condition": seed_condition,
                "image_condition": IA32_RELATIONAL_MIRROR[seed_condition],
            }
        )
    offsets = value.get("expected_rewritten_offsets")
    require(
        isinstance(offsets, list)
        and len(offsets) == 2 * len(normalized_sites)
        and (offsets == sorted(set(offsets)))
        and all((type(offset) is int and 0 <= offset < body_length for offset in offsets)),
        f"{context}.expected_rewritten_offsets is invalid",
    )
    external = value.get("expected_external_entries")
    require(
        isinstance(external, list)
        and external == sorted(set(external))
        and all((type(item) is int and 0 < item < body_length for item in external)),
        f"{context}.expected_external_entries is invalid",
    )
    rationale = value.get("authenticity_rationale")
    require(
        isinstance(rationale, str) and len(rationale) >= 40,
        f"{context}.authenticity_rationale is missing",
    )
    normalized = {
        "kind": RELATIONAL_FORM_KIND,
        "sites": normalized_sites,
        "expected_instruction_count": require_exact_int(
            value.get("expected_instruction_count"),
            f"{context}.expected_instruction_count",
            minimum=2,
        ),
        "expected_rewritten_offsets": list(offsets),
        "expected_external_entries": list(external),
        "expected_seed_debug_s_sha256": require_sha(
            value.get("expected_seed_debug_s_sha256"), f"{context}.expected_seed_debug_s_sha256"
        ),
        "authenticity_rationale": rationale,
    }
    code_length = value.get("expected_code_length")
    if code_length is not None:
        normalized["expected_code_length"] = require_exact_int(
            code_length, f"{context}.expected_code_length", minimum=2, maximum=body_length
        )
    return normalized


def produce_relational_form_candidate(
    seed_bytes: bytes, donor_bytes: bytes, function: dict
) -> tuple[bytes, dict]:
    """Produce reversed compares from a fresh compiler artifact.

    See the class comment: this is a certificate.  The pre-image is an
    ordinary census-pinned compile of the same translation unit; the reversal
    is proved sound against the body's own control flow with a per-flag
    liveness fixpoint. Body installation delegates,
    unchanged, to the equal-body primitive.
    """
    require_payload_free_declaration(function, "relational-form declaration")
    require(
        function.get("splice_class") == RELATIONAL_FORM_CLASS,
        "splice class is not retail_exact_relational_form",
    )
    require(
        "target_source_refactor" not in function,
        "relational-form functions carry no source refactor",
    )
    spec = function["relational_form"]
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["number"] == dp["number"] == function["expected_section_number"],
        "relational-form target section seat changed",
    )
    require(
        len(seed.sections) == len(donor.sections) == function["expected_section_count"],
        "relational-form global section count changed",
    )
    seed_functions = function_multiset(seed)
    donor_functions = function_multiset(donor)
    require(
        seed_functions == donor_functions
        and sum(seed_functions.values()) == function["expected_function_count"],
        "relational-form donor function set differs",
    )
    seed_comdats = comdat_primary_identity_multiset(seed)
    donor_comdats = comdat_primary_identity_multiset(donor)
    require(
        seed_comdats == donor_comdats
        and sum(seed_comdats.values()) == function["expected_comdat_count"],
        "relational-form donor COMDAT identity set differs",
    )
    require(
        sp["raw_size"] == dp["raw_size"] == function["expected_body_length"]
        and sp["relocation_count"]
        == dp["relocation_count"]
        == function["expected_relocation_count"]
        and (sp["line_count"] == function["expected_seed_line_count"])
        and (dp["line_count"] == function["expected_donor_line_count"])
        and (sp["name"] == dp["name"])
        and (
            sp["characteristics"] == dp["characteristics"] == function["expected_characteristics"]
        ),
        "relational-form target header/count pins changed",
    )
    require(
        section_definitions(seed)[sp["number"]]["selection"]
        == section_definitions(donor)[dp["number"]]["selection"]
        == function["expected_selection"],
        "relational-form COMDAT selection changed",
    )
    expected_closure = tuple(function["expected_closure"])
    require(
        _comdat_child_closure(seed, sp)
        == _comdat_child_closure(donor, dp)
        == (len(expected_closure), expected_closure),
        "relational-form target closure changed",
    )
    require(
        list(expected_closure) in (RELATIONAL_FORM_FPO_CLOSURE, RELATIONAL_FORM_EH_CLOSURE),
        "relational-form closure pin names no installation delegate",
    )
    delegate = relational_form_delegate(
        function["expected_closure"], function["expected_code_renames"]
    )
    require(
        instruction_mosaic_metadata_sha256(seed, sp) == function["expected_seed_metadata_sha256"]
        and instruction_mosaic_metadata_sha256(donor, dp)
        == function["expected_donor_metadata_sha256"],
        "relational-form metadata differs from its pin",
    )
    seed_body = coff_body(seed, sp)
    donor_body = coff_body(donor, dp)
    require(
        sha256_bytes(seed_body) == function["expected_seed_body_sha256"]
        and sha256_bytes(donor_body) == function["expected_donor_body_sha256"],
        "relational-form seed/donor body differs from its pin",
    )
    seed_rows = detailed_relocations(seed, sp)
    donor_rows = detailed_relocations(donor, dp)
    code_renames = require_instruction_mosaic_semantic_relocations(
        seed, sp, donor, dp, "relational-form code"
    )
    require(
        [[offset, kind] for offset, kind in code_renames] == function["expected_code_renames"],
        "relational-form code rename set changed",
    )
    require(
        len(seed_rows) == len(donor_rows)
        and [(row["offset"], row["type"], row["addend"]) for row in seed_rows]
        == [(row["offset"], row["type"], row["addend"]) for row in donor_rows],
        "relational-form donor relocation layout differs from the seed",
    )
    require(
        [row["target"] for row in seed_rows if row["type"] == 20]
        == [row["target"] for row in donor_rows if row["type"] == 20],
        "relational-form donor call/branch relocation targets differ from the seed",
    )
    installed_rows = [
        {**left, "offset": right["offset"]} for left, right in zip(seed_rows, donor_rows)
    ]
    relocation_offsets = frozenset(
        (row["offset"] + byte for row in installed_rows for byte in range(row["width"]))
    )
    relocation_symbols = {
        row["offset"]: {"width": row["width"], "target": row["target"]} for row in installed_rows
    }
    external = relational_form_external_entries(seed, sp, "relational-form seed")
    require(
        external == relational_form_external_entries(donor, dp, "relational-form donor"),
        "relational-form donor external entry set differs from the seed",
    )
    require(
        sorted(external) == spec["expected_external_entries"],
        "relational-form external entry set changed",
    )
    image, proof = apply_relational_form(
        donor_body,
        spec["sites"],
        relocation_offsets,
        "relational-form image",
        relocation_symbols,
        spec.get("expected_code_length"),
        external,
    )
    require(
        proof["rewritten_offsets"] == spec["expected_rewritten_offsets"]
        and proof["instruction_count"] == spec["expected_instruction_count"],
        "relational-form image differs from its declaration",
    )
    require(
        sha256_bytes(image) == function["expected_body_sha256"],
        "relational-form image differs from its pin",
    )
    pinned_length = function["retail_oracle"]["length"]
    require(pinned_length == len(image), "relational-form linked length changed")
    semantic_detail = require_declared_relocation_semantics(
        installed_rows,
        function["retail_relocations"],
        "relational-form candidate relocation semantics",
    )
    derived = bytearray(donor_bytes)
    derived[dp["raw_offset"] : dp["raw_offset"] + dp["raw_size"]] = image
    derived = bytes(derived)
    effective = {
        "mangled": mangled,
        "splice_class": delegate,
        "expected_body_length": function["expected_body_length"],
        "expected_body_sha256": function["expected_body_sha256"],
        "expected_changed_offsets": function["expected_changed_offsets"],
    }
    if delegate == "equal_body_eh_structural_local":
        effective["expected_code_renames"] = function["expected_code_renames"]
        effective["expected_xdata_rename_offsets"] = function["expected_xdata_rename_offsets"]
    composed, detail = compose_equal_body_comdat(seed_bytes, derived, effective)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(coff_body(checked, cp) == image, "relational-form composed body differs from the image")
    composed_rows = detailed_relocations(checked, cp)
    require(
        composed_rows == installed_rows
        and [row["symbol_index"] for row in composed_rows]
        == [row["symbol_index"] for row in seed_rows]
        and (
            _coff_table_bytes(checked, cp, "relocations")
            == _coff_table_bytes(seed, sp, "relocations")
        )
        and (_coff_table_bytes(checked, cp, "lines") == _coff_table_bytes(seed, sp, "lines")),
        "relational-form output changed seed relocation/line bytes",
    )
    debug_child = _comdat_child(checked, cp, ".debug$S")
    require(
        sha256_bytes(coff_body(checked, debug_child)) == spec["expected_seed_debug_s_sha256"],
        "relational-form debug$S differs from its pin",
    )
    for child_name in expected_closure:
        require(
            coff_body(checked, _comdat_child(checked, cp, child_name))
            == coff_body(seed, _comdat_child(seed, sp, child_name)),
            f"relational-form output changed its {child_name} child",
        )
    boundaries = {
        item["offset"]
        for item in ia32_relational_flow_walk(
            image,
            relocation_symbols,
            "relational-form image lines",
            spec.get("expected_code_length"),
            external,
        )[0]
    }
    if cp["line_count"] > 1:
        line_table = coff_table(checked, cp, "lines")
        for index in range(1, cp["line_count"]):
            row_offset, row_line = struct.unpack_from("<IH", line_table, index * 6)
            require(
                row_line != 0 and row_offset in boundaries,
                f"relational-form line row at {row_offset} does not land on an image instruction boundary",
            )
    allowed = set(range(sp["raw_offset"], sp["raw_offset"] + sp["raw_size"]))
    require(
        {index for index in range(len(seed_bytes)) if seed_bytes[index] != composed[index]}
        <= allowed,
        "relational-form changed bytes outside its own COMDAT",
    )
    return (
        composed,
        {
            **detail,
            "splice_class": RELATIONAL_FORM_CLASS,
            "relational_form": proof["sites"],
            "instruction_count": proof["instruction_count"],
            "rewritten_offsets": proof["rewritten_offsets"],
            "external_entries": proof["external_entries"],
            "preserved_flags": proof["preserved_flags"],
            "changed_flags": proof["changed_flags"],
            "candidate_only": True,
            **semantic_detail,
        },
    )
