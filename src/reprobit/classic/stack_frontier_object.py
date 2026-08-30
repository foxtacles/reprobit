"""FPO private-stack versus paired-debug ``this`` separation proof."""

from __future__ import annotations

from typing import Any, cast

from reprobit.binary import require
from reprobit.model import Digest

from .debug import (
    CODEVIEW_END_RECORD_TYPE,
    CODEVIEW_PROCEDURE_RECORD_TYPES,
    parse_codeview_symbol_stream,
    parse_fpo_data,
)
from .registers import (
    CODEVIEW_REGISTER_RECORD_TYPE,
    _codeview_register_field,
    _codeview_register_name,
)
from .stack_frontier_balance import derive_stack_depths
from .stack_frontier_foundation import (
    MAX_INSTRUCTIONS,
    address_form,
    ancestors,
    predecessors,
    stack_change,
)

_REGISTER_PUSHES = frozenset(range(0x50, 0x58))
_STACK_PUSHES = _REGISTER_PUSHES | frozenset({0x6A})
_MSVC420_MEMBER_CLASSES = frozenset("ABEFIJMNQRUV")
_MSVC420_MEMBER_CV = frozenset("ABCD")


def _evidence_digest(value: str | None, label: str, context: str) -> str:
    require(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value),
        f"{context}: paired {label} receipt digest is malformed",
    )
    assert isinstance(value, str)
    return value


def _thiscall_owner(owner: str | None, debug_procedure: object, context: str) -> dict[str, object]:
    """Bind the entry ECX value to one ordinary VC 4.20 member owner.

    The first three bytes after an MSVC member scope encode member class,
    cv-qualification, and calling convention.  This proof deliberately
    accepts only simple named scopes and the ``E`` (``__thiscall``) calling
    convention; operators and template spellings can gain their own closed
    parser if a real compiler product needs them later.
    """

    require(
        isinstance(owner, str)
        and owner.startswith("?")
        and owner.endswith("Z")
        and isinstance(debug_procedure, str),
        f"{context}: private-stack/object proof lacks an MSVC function owner",
    )
    assert isinstance(owner, str) and isinstance(debug_procedure, str)
    readings: list[dict[str, object]] = []
    for scope_end in range(1, len(owner) - 4):
        if owner[scope_end : scope_end + 2] != "@@":
            continue
        cursor = scope_end + 2
        if (
            owner[cursor] not in _MSVC420_MEMBER_CLASSES
            or owner[cursor + 1] not in _MSVC420_MEMBER_CV
            or owner[cursor + 2] != "E"
        ):
            continue
        components = owner[1:scope_end].split("@")
        if not components or any(
            not component
            or any(not (character.isalnum() or character in "_$") for character in component)
            for component in components
        ):
            continue
        procedure = "::".join(reversed(components))
        if procedure != debug_procedure:
            continue
        readings.append(
            {
                "kind": "msvc-4.20-win32-thiscall-owner-v1",
                "owner": owner,
                "procedure": procedure,
                "member_class": owner[cursor],
                "cv_encoding": owner[cursor + 1],
                "calling_convention_encoding": "E",
                "entry_this_register": "ecx",
            }
        )
    require(
        len(readings) == 1,
        f"{context}: function owner is not one unambiguous VC 4.20 __thiscall procedure",
    )
    return readings[0]


def _fpo_frame_floor(
    body: bytes,
    instructions: list[dict[str, Any]],
    fpo_body: bytes,
    context: str,
) -> tuple[int, int, dict[str, object]]:
    record = parse_fpo_data(fpo_body, expected_proc_size=len(body))
    require(
        record["cbFrame"] == 0 and record["fHasSEH"] == 0 and record["fUseBP"] == 0,
        f"{context}: paired FPO does not describe a frame-pointer-free non-EH function",
    )
    prolog_end = int(record["cbProlog"])
    boundary = next(
        (index for index, item in enumerate(instructions) if int(item["offset"]) == prolog_end),
        None,
    )
    require(
        boundary is not None and boundary > 0,
        f"{context}: paired FPO prologue does not end on an instruction boundary",
    )
    assert boundary is not None
    prologue = instructions[:boundary]
    require(
        int(prologue[-1]["offset"]) + int(prologue[-1]["length"]) == prolog_end,
        f"{context}: paired FPO prologue has a boundary gap",
    )
    locals_bytes = int(record["cdwLocals"]) * 4
    first = prologue[0]
    first_raw = body[int(first["offset"]) : int(first["offset"]) + int(first["length"])]
    allocation = (
        len(first_raw) == 3 and first_raw[:2] == b"\x83\xec" and first_raw[2] == locals_bytes
    ) or (
        len(first_raw) == 6
        and first_raw[:2] == b"\x81\xec"
        and int.from_bytes(first_raw[2:], "little") == locals_bytes
    )
    require(
        0 < locals_bytes <= 0x7FFFFFFF and allocation,
        f"{context}: paired FPO locals do not match one canonical fixed allocation",
    )
    saved: list[int] = []
    floor = 0
    for index, item in enumerate(prologue):
        require(item["flow"] == "fall", f"{context}: control flow enters the FPO prologue")
        change = stack_change(body, item)
        require(change is not None, f"{context}: FPO prologue has an unknown ESP update")
        assert change is not None
        if index > 0 and change < 0:
            start = int(item["offset"])
            opcode = int(item["opcode"])
            require(
                int(item["length"]) == 1
                and opcode in _REGISTER_PUSHES
                and opcode in (0x53, 0x55, 0x56, 0x57)
                and body[start] == opcode
                and opcode not in saved,
                f"{context}: FPO prologue has a non-canonical saved-register PUSH",
            )
            saved.append(opcode)
        elif index > 0:
            require(change == 0, f"{context}: FPO prologue changes its fixed frame twice")
        floor += change
    require(
        len(saved) == int(record["cbRegs"]) and floor == -(locals_bytes + len(saved) * 4),
        f"{context}: paired FPO register/local counts differ from the code prologue",
    )
    return floor, boundary, record


def _paired_debug_this(
    debug_body: bytes, body_length: int, context: str
) -> tuple[str, dict[str, object]]:
    records = parse_codeview_symbol_stream(debug_body, f"{context} paired debug$S")
    require(
        bool(records)
        and records[0]["type"] in CODEVIEW_PROCEDURE_RECORD_TYPES
        and records[-1]["type"] == CODEVIEW_END_RECORD_TYPE
        and sum(item["type"] in CODEVIEW_PROCEDURE_RECORD_TYPES for item in records) == 1
        and sum(item["type"] == CODEVIEW_END_RECORD_TYPE for item in records) == 1,
        f"{context}: paired debug$S is not one closed procedure scope",
    )
    procedure = records[0]
    extent_at = int(procedure["offset"]) + 16
    require(
        extent_at + 12 <= int(procedure["offset"]) + int(procedure["size"]),
        f"{context}: paired debug procedure lacks its extent",
    )
    code_length, debug_start, debug_end = (
        int.from_bytes(debug_body[extent_at + offset : extent_at + offset + 4], "little")
        for offset in (0, 4, 8)
    )
    require(
        code_length == body_length and 0 <= debug_start <= debug_end <= body_length,
        f"{context}: paired debug procedure extent differs from its code",
    )
    this_records = [
        item
        for item in records
        if item["type"] == CODEVIEW_REGISTER_RECORD_TYPE and item["name"] == "this"
    ]
    require(
        len(this_records) == 1,
        f"{context}: paired debug$S has no unique register-resident 'this'",
    )
    this_record = this_records[0]
    field = _codeview_register_field(this_record, context)
    register = _codeview_register_name(debug_body, field, context)
    return register, {
        "procedure": procedure["name"],
        "code_length": code_length,
        "debug_range": [debug_start, debug_end],
        "this_register": register,
        "this_record_offset": int(this_record["offset"]),
        "stream_digest": Digest.from_bytes(debug_body).value,
    }


def _unique_reaching_definition(
    instructions: list[dict[str, Any]],
    predecessor_rows: list[list[int]],
    sink: int,
    register: str,
    context: str,
) -> int:
    definitions: set[int] = set()
    reaches_entry = False
    seen: set[int] = set()
    work = list(predecessor_rows[sink])
    while work:
        current = work.pop()
        if current in seen:
            continue
        seen.add(current)
        if register in instructions[current]["writes"]:
            definitions.add(current)
            continue
        incoming = predecessor_rows[current]
        if not incoming:
            reaches_entry = True
        work.extend(incoming)
        require(
            len(seen) <= MAX_INSTRUCTIONS,
            f"{context}: reaching-definition analysis exceeds its bound",
        )
    require(
        not reaches_entry and len(definitions) == 1,
        f"{context}: object base has no unique reaching definition",
    )
    return next(iter(definitions))


def _require_entry_this_copy(
    body: bytes,
    instructions: list[dict[str, Any]],
    predecessor_rows: list[list[int]],
    definition: int,
    this_register: str,
    prolog_end: int,
    context: str,
) -> dict[str, object]:
    item = instructions[definition]
    start = int(item["offset"])
    raw = body[start : start + int(item["length"])]
    require(
        start < prolog_end
        and item["flow"] == "fall"
        and item["memory"] is None
        and item["reads"] == frozenset({"ecx"})
        and item["writes"] == frozenset({this_register})
        and raw in (b"\x8b\xf1", b"\x89\xce"),
        f"{context}: paired-debug 'this' is not the canonical entry ECX copy",
    )
    seen: set[int] = set()
    work = list(predecessor_rows[definition])
    while work:
        current = work.pop()
        if current in seen:
            continue
        seen.add(current)
        require(
            "ecx" not in instructions[current]["writes"],
            f"{context}: entry ECX changes before the paired-debug 'this' copy",
        )
        work.extend(predecessor_rows[current])
    return {
        "kind": "paired-debug-entry-this-copy-v1",
        "entry_register": "ecx",
        "this_register": this_register,
        "definition_offset": start,
        "encoding": raw.hex(),
    }


def _adjusted_body(
    body: bytes,
    instructions: list[dict[str, Any]],
    window: list[int],
    adjustments: list[list[int]],
    context: str,
) -> bytes:
    adjusted = bytearray(body)
    for local, at, old, new in adjustments:
        encoding = instructions[window[local]]["encoding"]
        require(isinstance(encoding, dict), f"{context}: adjusted instruction has no encoding")
        size = int(encoding["displacement_size"])
        require(
            int.from_bytes(body[at : at + size], "little", signed=True) == old,
            f"{context}: adjusted stack displacement changed before proof",
        )
        adjusted[at : at + size] = new.to_bytes(size, "little", signed=True)
    return bytes(adjusted)


def derive_private_stack_object_boundary(
    body: bytes,
    instructions: list[dict[str, Any]],
    successors: list[list[int]],
    relocations: dict[int, dict[str, object]],
    external_entries: frozenset[int],
    start: int,
    end: int,
    target_order: list[int],
    stack_adjustments: list[list[int]],
    discharged: list[dict[str, Any]],
    fpo_body: bytes | None,
    debug_body: bytes | None,
    fpo_receipt_digest: str | None,
    debug_receipt_digest: str | None,
    function_owner: str | None,
    context: str,
) -> dict[str, object]:
    """Prove every projected memory pair separates private stack from ``this``."""

    require(
        1 <= len(instructions) <= MAX_INSTRUCTIONS,
        f"{context}: body exceeds the bounded private-stack analysis",
    )
    require(
        isinstance(fpo_body, bytes) and isinstance(debug_body, bytes),
        f"{context}: private-stack/object proof lacks paired FPO and debug evidence",
    )
    assert isinstance(fpo_body, bytes) and isinstance(debug_body, bytes)
    fpo_receipt = _evidence_digest(fpo_receipt_digest, "FPO", context)
    debug_receipt = _evidence_digest(debug_receipt_digest, "debug$S", context)
    floor, prolog_boundary, fpo = _fpo_frame_floor(body, instructions, fpo_body, context)
    this_register, debug = _paired_debug_this(debug_body, len(body), context)
    require(
        this_register == "esi",
        f"{context}: private-stack/object theorem only admits the reviewed "
        "ESI-resident 'this' form",
    )
    owner = _thiscall_owner(function_owner, debug["procedure"], context)
    index_of = {int(item["offset"]): index for index, item in enumerate(instructions)}
    window = [
        index for index, item in enumerate(instructions) if start <= int(item["offset"]) < end
    ]
    require(
        bool(window)
        and int(instructions[window[-1]]["offset"]) + int(instructions[window[-1]]["length"]) == end
        and all(instructions[index]["flow"] == "fall" for index in window),
        f"{context}: private-stack window boundaries or control flow changed",
    )
    predecessor_rows = predecessors(successors)
    ancestor_set = ancestors(predecessor_rows, set(window))
    unresolved = sorted(
        entry for entry in external_entries if entry in index_of and index_of[entry] in ancestor_set
    )
    require(
        not unresolved,
        f"{context}: an external entry reaches the private-stack window at {unresolved[:1]}",
    )
    depths, call_balance = derive_stack_depths(
        body,
        instructions,
        successors,
        ancestor_set,
        floor,
        prolog_boundary,
        relocations,
        context,
    )
    entry_depth = depths[window[0]]
    require(
        entry_depth is not None and entry_depth <= floor,
        f"{context}: private-stack window is above its fixed FPO floor",
    )
    assert entry_depth is not None
    adjusted = _adjusted_body(body, instructions, window, stack_adjustments, context)
    target_depths: dict[int, int] = {}
    target_depth = entry_depth
    for local in target_order:
        target_depths[local] = target_depth
        require(
            target_depth <= floor,
            f"{context}: target order raises ESP above the fixed FPO floor",
        )
        change = stack_change(body, instructions[window[local]])
        require(change is not None, f"{context}: target order has an unknown ESP update")
        assert change is not None
        target_depth += change
    require(
        target_depth <= floor,
        f"{context}: target order exits above the fixed FPO floor",
    )
    source_depth = entry_depth
    for index in window:
        require(
            depths[index] == source_depth and source_depth <= floor,
            f"{context}: source stack depth differs inside the schedule window",
        )
        change = stack_change(body, instructions[index])
        require(change is not None, f"{context}: source window has an unknown ESP update")
        assert change is not None
        source_depth += change
    require(
        source_depth == target_depth,
        f"{context}: schedule changes the stack depth at its rejoin",
    )

    separations: list[dict[str, object]] = []
    this_copy: dict[str, object] | None = None
    this_definition: int | None = None
    target_position = {local: position for position, local in enumerate(target_order)}
    for pair in discharged:
        stack_local = int(pair["stack_instruction"])
        object_local = int(pair["object_instruction"])
        stack_index = window[stack_local]
        object_index = window[object_local]
        stack_item = instructions[stack_index]
        object_item = instructions[object_index]
        object_memory = object_item.get("memory")
        object_address = address_form(body, object_item)
        require(
            isinstance(object_memory, dict)
            and object_memory["base"] == this_register
            and object_memory["index"] is None
            and not object_memory["absolute"]
            and int(object_memory["displacement"]) >= 0
            and int(object_memory["width"]) > 0,
            f"{context}: projected object memory is not based on paired-debug 'this'",
        )
        assert isinstance(object_memory, dict)
        require(
            object_address
            == (
                this_register,
                None,
                1,
                int(object_memory["displacement"]),
            ),
            f"{context}: projected object memory has a segment, index, or noncanonical address",
        )
        definition = _unique_reaching_definition(
            instructions, predecessor_rows, object_index, this_register, context
        )
        if this_definition is None:
            this_definition = definition
            this_copy = _require_entry_this_copy(
                body,
                instructions,
                predecessor_rows,
                definition,
                this_register,
                cast(int, fpo["cbProlog"]),
                context,
            )
        require(
            definition == this_definition,
            f"{context}: projected object operands do not share one entry 'this' definition",
        )
        require(
            all(
                this_register not in instructions[window[local]]["writes"]
                for local in target_order[: target_position[object_local]]
            ),
            f"{context}: target order clobbers paired-debug 'this' before its object access",
        )

        opcode = int(stack_item["opcode"])
        if opcode in _STACK_PUSHES:
            require(
                stack_item["memory"] is None,
                f"{context}: projected PUSH unexpectedly has explicit memory",
            )
            source_before = depths[stack_index]
            require(source_before is not None, f"{context}: PUSH has no source stack depth")
            assert source_before is not None
            source_span = [source_before - 4, source_before]
            target_before = target_depths[stack_local]
            target_span = [target_before - 4, target_before]
            stack_kind = "implicit-push-seat"
        else:
            memory = stack_item.get("memory")
            require(
                isinstance(memory, dict)
                and memory["base"] == "esp"
                and memory["index"] is None
                and not memory["absolute"]
                and int(memory["width"]) > 0,
                f"{context}: projected private-stack operand is not direct ESP memory",
            )
            assert isinstance(memory, dict)
            require(
                address_form(body, stack_item) == ("esp", None, 1, int(memory["displacement"])),
                f"{context}: projected stack memory has a segment, index, or noncanonical address",
            )
            source_before = depths[stack_index]
            require(source_before is not None, f"{context}: stack operand has no source depth")
            assert source_before is not None
            source_left = source_before + int(memory["displacement"])
            source_span = [source_left, source_left + int(memory["width"])]
            encoding = stack_item.get("encoding")
            require(isinstance(encoding, dict), f"{context}: stack operand has no encoding")
            assert isinstance(encoding, dict)
            displacement_at = encoding["displacement_at"]
            displacement_size = int(encoding["displacement_size"])
            require(
                displacement_at is not None and displacement_size > 0,
                f"{context}: stack operand has no direct displacement field",
            )
            target_displacement = int.from_bytes(
                adjusted[int(displacement_at) : int(displacement_at) + displacement_size],
                "little",
                signed=True,
            )
            target_left = target_depths[stack_local] + target_displacement
            target_span = [target_left, target_left + int(memory["width"])]
            stack_kind = "explicit-private-stack-cell"
        if stack_kind == "implicit-push-seat":
            require(
                source_span == target_span
                and source_span == [source_before - 4, source_before]
                and target_span == [target_depths[stack_local] - 4, target_depths[stack_local]]
                and source_before <= floor
                and target_depths[stack_local] <= floor,
                f"{context}: projected PUSH is not the same fresh seat below ESP in both orders",
            )
        else:
            locals_floor = -4 * cast(int, fpo["cdwLocals"])
            require(
                source_span == target_span
                and source_before <= source_span[0] < source_span[1]
                and target_depths[stack_local] <= target_span[0] < target_span[1]
                and locals_floor <= source_span[0]
                and source_span[1] <= 0,
                f"{context}: projected ESP operand is outside the exact FPO local interval",
            )
        separations.append(
            {
                "source_pair": list(pair["source_pair"]),
                "stack_instruction": stack_local,
                "stack_offset": int(stack_item["offset"]),
                "stack_kind": stack_kind,
                "source_span_from_entry_esp": source_span,
                "target_span_from_entry_esp": target_span,
                "object_instruction": object_local,
                "object_offset": int(object_item["offset"]),
                "object_base": this_register,
                "object_displacement": int(object_memory["displacement"]),
                "object_width": int(object_memory["width"]),
                "abi_separation": "caller-object-excludes-active-callee-stack",
            }
        )
    require(this_copy is not None, f"{context}: no paired-debug object separation was proved")
    return {
        "kind": "fpo-private-stack-object-frontier-v1",
        "frame_floor_from_entry_esp": floor,
        "window_entry_esp_from_entry": entry_depth,
        "window_exit_esp_from_entry": source_depth,
        "fpo": fpo,
        "fpo_receipt_digest": fpo_receipt,
        "debug": debug,
        "debug_receipt_digest": debug_receipt,
        "owner": owner,
        "this_copy": this_copy,
        "call_balance": call_balance,
        "memory_separations": separations,
    }


__all__ = ["derive_private_stack_object_boundary"]
