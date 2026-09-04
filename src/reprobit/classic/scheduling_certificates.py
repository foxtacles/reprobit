"""Classic compiler algorithms: instruction-schedule and web-recolour certificate validators."""

from __future__ import annotations

from typing import Any, cast

from reprobit.binary import require
from reprobit.coff_format import (
    CoffObject,
    coff_body,
    coff_unpack,
    detailed_relocations,
)

from .coff import (
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    function_symbol,
)
from .debug import CODEVIEW_PROCEDURE_RECORD_TYPES, FPO_RECORD_KEYS, parse_codeview_symbol_stream
from .foundation import (
    RelocationView,
    exact_audit_keys,
    require_exact_int,
)
from .register_bijection import (
    CODEVIEW_X86_REGISTER_NUMBERS,
)
from .register_reencoding import FPO_FRAME_KIND_FPO
from .register_semantics import (
    _IA32_REGISTER_NUMBERS,
    _IA32_STRUCTURAL_REGISTERS,
)
from .scheduling_apply import ia32_schedule_body_walk
from .scheduling_dependence import _IA32_SCHEDULE_STACK_FRONTIER_THEOREMS
from .scheduling_webs import _ia32_web_membership

INSTRUCTION_SCHEDULE_KIND = "topological_window_reordering_v1"


def measure_instruction_schedule_debug_envelope(
    coff: CoffObject,
    section: dict[str, Any],
    context: str,
) -> dict[str, Any]:
    """Measure the procedure range and closure references used by rewriting proofs."""

    child = _comdat_child(coff, section, ".debug$S")
    stream = coff_body(coff, child)
    records = parse_codeview_symbol_stream(stream, f"{context} debug$S")
    procedures = [record for record in records if record["type"] in CODEVIEW_PROCEDURE_RECORD_TYPES]
    require(
        len(procedures) == 1,
        f"{context}: the .debug$S stream does not carry exactly one procedure record",
    )
    record = procedures[0]
    procedure_range = list(
        coff_unpack("<III", stream, record["offset"] + 16, f"{context} procedure record")
    )
    values = {
        symbol["name"]: symbol["value"]
        for symbol in coff.symbols.values()
        if symbol["section"] == section["number"]
    }
    referenced = []
    for child_name in _comdat_child_closure(coff, section)[1]:
        sibling = _comdat_child(coff, section, child_name)
        for row in detailed_relocations(coff, sibling):
            if row["target"] in values:
                referenced.append([child_name, row["target"], values[row["target"]]])
    return {
        "procedure_range": procedure_range,
        "code_symbol_references": referenced,
    }


def require_instruction_schedule_debug_fidelity(
    coff: CoffObject,
    section: dict[str, Any],
    image: bytes,
    windows: list[dict[str, Any]],
    spec: dict[str, Any],
    mangled: str,
    context: str,
    *,
    view: RelocationView | None = None,
) -> dict[str, Any]:
    """Obligation 7: re-derive the line rows and the debug ranges.

    Every COFF line row is checked against the IMAGE's own instruction
    boundaries, the rows inside each window are pinned together with the
    source instruction that now begins at them, the CodeView procedure
    record's code length and debug range are pinned and required to stay
    clear of every window interior, and no closure-child relocation may name
    a code symbol whose value falls inside one.
    """
    if view is None:
        view = RelocationView()
    relocations = view.relocations
    code_length = view.code_length
    internal_targets = view.internal_targets
    spans, _ = ia32_schedule_body_walk(
        image, relocations, f"{context} image", code_length, internal_targets
    )
    boundaries = {start for start, _ in spans}
    boundaries.add(len(image) if code_length is None else code_length)
    index_of = {start: position for position, (start, _) in enumerate(spans)}
    line_bytes = _coff_table_bytes(coff, section, "lines")
    require(
        len(line_bytes) == section["line_count"] * 6 and len(line_bytes) >= 12,
        f"{context}: the compiler line table is missing",
    )
    marker_index, marker_line = coff_unpack("<IH", line_bytes, 0, f"{context} line sentinel")
    function_index, _ = function_symbol(coff, mangled, section["number"])
    require(
        marker_line == 0 and marker_index == function_index,
        f"{context}: the compiler line sentinel differs",
    )
    rows = []
    for position in range(1, section["line_count"]):
        offset, line = coff_unpack(
            "<IH", line_bytes, position * 6, f"{context} line row {position}"
        )
        require(
            line != 0 and 0 <= offset < len(image), f"{context}: line row {position} is invalid"
        )
        require(
            offset in boundaries,
            f"{context}: line row {position} at {offset:#x} is not an instruction boundary of the image",
        )
        rows.append([offset, line])
    interior = []
    declared_windows = list(spec.get("windows") or []) + list(spec.get("trailing_windows") or [])
    require(
        len(windows) == len(declared_windows),
        f"{context}: the window list differs from its declaration",
    )
    for window, declared in zip(windows, declared_windows, strict=True):
        start, end = (window["start"], window["end"])
        order = list(window["target_order"])
        attribution = [
            [offset, line, order[index_of[offset] - index_of[start]]]
            for offset, line in rows
            if start <= offset < end
        ]
        require(
            attribution == declared["expected_line_rows"],
            f"{context}: the line rows inside window {start:#x} differ from their declaration",
        )
        interior.extend(attribution)
    envelope = measure_instruction_schedule_debug_envelope(coff, section, context)
    code_length, debug_start, debug_end = envelope["procedure_range"]
    require(
        [code_length, debug_start, debug_end] == spec["expected_procedure_range"],
        f"{context}: the procedure record's code range differs from its declaration",
    )
    require(
        code_length == len(image), f"{context}: the procedure record's code length is not the body"
    )
    for name, value in (("debug_start", debug_start), ("debug_end", debug_end)):
        require(
            value in boundaries,
            f"{context}: the procedure record's {name} is not an instruction boundary of the image",
        )
        require(
            not any(
                (
                    start < value < end
                    for start, end in [(item["start"], item["end"]) for item in windows]
                )
            ),
            f"{context}: the procedure record's {name} falls inside a reordered window",
        )
    referenced = envelope["code_symbol_references"]
    for child_name, target, value in referenced:
        require(
            not any(
                start < value < end
                for start, end in [(item["start"], item["end"]) for item in windows]
            ),
            f"{context}: {child_name} names the code symbol {target} at {value:#x}, inside a reordered window",
        )
    require(
        sorted(referenced) == sorted(spec["expected_code_symbol_references"]),
        f"{context}: the closure's code-symbol references differ from their declaration",
    )
    return {
        "line_rows": len(rows),
        "window_line_rows": interior,
        "procedure_range": [code_length, debug_start, debug_end],
        "code_symbol_references": referenced,
    }


def _validate_schedule_windows(
    windows: list[Any],
    context: str,
    body_length: int,
    code_length: int | None = None,
    targets: list[Any] | None = None,
) -> list[dict[str, Any]]:
    """Normalise a list of reordering windows.

    Shared by the instruction-schedule certificate and the web-recolour
    certificate, which applies the same reordering primitive before its own
    proof.
    """
    normalized_windows = []
    previous_end = 0
    for index, window in enumerate(windows):
        window_context = f"{context}.windows[{index}]"
        require(isinstance(window, dict), f"{window_context} must be an object")
        exact_audit_keys(
            window,
            {
                "start",
                "end",
                "source_instruction_lengths",
                "target_order",
                "expected_dependence_edges",
                "expected_line_rows",
                "relocation_reseat",
                "stack_adjustments",
                "stack_frontier_theorem",
            },
            window_context,
            optional={"relocation_reseat", "stack_adjustments", "stack_frontier_theorem"},
        )
        start = require_exact_int(
            window.get("start"), f"{window_context}.start", minimum=0, maximum=body_length - 1
        )
        end = require_exact_int(
            window.get("end"), f"{window_context}.end", minimum=1, maximum=body_length
        )
        require(
            start >= previous_end and start < end,
            f"{window_context}: windows are unsorted, empty or overlapping",
        )
        require(
            code_length is None or end <= code_length,
            f"{window_context}: the window reaches past the declared code length",
        )
        require(
            targets is None or not any(start < item < end for item in targets),
            f"{window_context}: a relocated in-body target enters the window's interior",
        )
        previous_end = end
        lengths = window.get("source_instruction_lengths")
        require(
            isinstance(lengths, list)
            and 2 <= len(lengths) <= 64
            and all(type(item) is int and 1 <= item <= 15 for item in lengths)
            and (sum(lengths) == end - start),
            f"{window_context}.source_instruction_lengths differs",
        )
        order = window.get("target_order")
        require(
            isinstance(order, list)
            and sorted(order) == list(range(len(lengths)))
            and (order != list(range(len(lengths)))),
            f"{window_context}.target_order is not a non-identity permutation",
        )
        edges = window.get("expected_dependence_edges")
        require(
            isinstance(edges, list)
            and all(
                isinstance(edge, list)
                and len(edge) == 3
                and (type(edge[0]) is int)
                and (type(edge[1]) is int)
                and (0 <= edge[0] < edge[1] < len(lengths))
                and isinstance(edge[2], list)
                and edge[2]
                and (edge[2] == sorted(set(edge[2])))
                and all(reason in INSTRUCTION_SCHEDULE_EDGE_REASONS for reason in edge[2])
                for edge in edges
            )
            and ([edge[:2] for edge in edges] == sorted(edge[:2] for edge in edges)),
            f"{window_context}.expected_dependence_edges is invalid",
        )
        line_rows = window.get("expected_line_rows")
        require(
            isinstance(line_rows, list)
            and all(
                isinstance(row, list)
                and len(row) == 3
                and all(type(item) is int for item in row)
                and (start <= row[0] < end)
                and (0 <= row[2] < len(lengths))
                for row in line_rows
            )
            and ([row[0] for row in line_rows] == sorted({row[0] for row in line_rows})),
            f"{window_context}.expected_line_rows is invalid",
        )
        stack = window.get("stack_adjustments")
        normalized_stack = None
        if stack is not None:
            require(
                isinstance(stack, list)
                and 1 <= len(stack) <= 64
                and all(
                    isinstance(row, list)
                    and len(row) == 4
                    and all(type(value) is int for value in row)
                    and (0 <= row[0] < len(lengths))
                    and (start <= row[1] < end)
                    and (row[2] != row[3])
                    and (abs(row[3] - row[2]) % 4 == 0)
                    for row in stack
                )
                and (stack == sorted(stack))
                and (len({row[1] for row in stack}) == len(stack)),
                f"{window_context}.stack_adjustments is invalid",
            )
            normalized_stack = [list(row) for row in stack]
        stack_frontier_theorem = window.get("stack_frontier_theorem")
        if stack_frontier_theorem is not None:
            require(
                type(stack_frontier_theorem) is str
                and stack_frontier_theorem in _IA32_SCHEDULE_STACK_FRONTIER_THEOREMS,
                f"{window_context}.stack_frontier_theorem differs",
            )
        reseat = window.get("relocation_reseat")
        normalized_reseat = None
        if reseat is not None:
            require(
                isinstance(reseat, list)
                and 1 <= len(reseat) <= 64
                and all(
                    isinstance(pair, list)
                    and len(pair) == 2
                    and all(type(item) is int for item in pair)
                    and (start <= pair[0] < end)
                    and (start <= pair[1] < end)
                    for pair in reseat
                )
                and ([pair[0] for pair in reseat] == sorted({pair[0] for pair in reseat}))
                and (len({pair[1] for pair in reseat}) == len(reseat))
                and any(pair[0] != pair[1] for pair in reseat),
                f"{window_context}.relocation_reseat is invalid",
            )
            normalized_reseat = [list(pair) for pair in reseat]
        normalized_window = {
            "start": start,
            "end": end,
            "source_instruction_lengths": list(lengths),
            "target_order": list(order),
            "expected_dependence_edges": [[edge[0], edge[1], list(edge[2])] for edge in edges],
            "expected_line_rows": [list(row) for row in line_rows],
        }
        if normalized_reseat is not None:
            normalized_window["relocation_reseat"] = normalized_reseat
        if normalized_stack is not None:
            normalized_window["stack_adjustments"] = normalized_stack
        if stack_frontier_theorem is not None:
            normalized_window["stack_frontier_theorem"] = stack_frontier_theorem
        normalized_windows.append(normalized_window)
    return normalized_windows


def validate_web_recolour(value: object, context: str, body_length: int) -> dict[str, Any]:
    """Validate one web-recolour certificate declaration."""
    require(isinstance(value, dict), f"{context} must be an object")
    document = cast(dict[str, Any], value)
    exact_audit_keys(
        document,
        {
            "kind",
            "windows",
            "webs",
            "expected_instruction_count",
            "expected_changed_offsets",
            "expected_procedure_range",
            "expected_code_symbol_references",
            "expected_debug_s_registers",
            "expected_code_length",
            "expected_internal_relocation_targets",
            "expected_fpo_record",
            "trailing_windows",
            "authenticity_rationale",
        },
        context,
        optional={
            "windows",
            "trailing_windows",
            "expected_code_length",
            "expected_internal_relocation_targets",
            "expected_fpo_record",
        },
    )
    require(document.get("kind") == WEB_RECOLOUR_KIND, f"{context}.kind differs")
    code_length = document.get("expected_code_length")
    if code_length is not None:
        code_length = require_exact_int(
            code_length, f"{context}.expected_code_length", minimum=2, maximum=body_length
        )
    targets = document.get("expected_internal_relocation_targets")
    if targets is not None:
        require(
            isinstance(targets, list)
            and targets == sorted(set(targets))
            and all(type(item) is int and 0 <= item < body_length for item in targets),
            f"{context}.expected_internal_relocation_targets is invalid",
        )

    def _windows(key: str) -> list[dict[str, Any]]:
        if document.get(key) is None:
            return []
        windows = document[key]
        require(
            isinstance(windows, list) and 1 <= len(windows) <= 32,
            f"{context}.{key} must contain 1..32 windows",
        )
        return _validate_schedule_windows(
            windows,
            f"{context}.{key}" if key != "windows" else context,
            body_length,
            code_length,
            targets,
        )

    normalized_windows = _windows("windows")
    normalized_trailing = _windows("trailing_windows")
    for leading in normalized_windows:
        for trailing in normalized_trailing:
            require(
                leading["end"] <= trailing["start"] or trailing["end"] <= leading["start"],
                f"{context}: a trailing window overlaps a leading one",
            )
    fpo_record = document.get("expected_fpo_record")
    if fpo_record is not None:
        require(
            isinstance(fpo_record, dict) and set(fpo_record) == FPO_RECORD_KEYS - {"raw_sha256"},
            f"{context}.expected_fpo_record is invalid",
        )
        require(
            fpo_record.get("cbFrame") == FPO_FRAME_KIND_FPO and fpo_record.get("fHasSEH") == 0,
            f"{context}.expected_fpo_record does not declare a frame-pointer-free, SEH-free frame",
        )
    structural = {"esp"} if fpo_record is not None else _IA32_STRUCTURAL_REGISTERS
    webs = document.get("webs")
    require(
        isinstance(webs, list) and 1 <= len(webs) <= 32, f"{context}.webs must contain 1..32 webs"
    )
    normalized_webs = []
    rewritten = []
    for index, web in enumerate(cast(list[Any], webs)):
        web_context = f"{context}.webs[{index}]"
        require(isinstance(web, dict), f"{web_context} must be an object")
        exact_audit_keys(
            web,
            {
                "source_register",
                "image_register",
                "definitions",
                "uses",
                "expected_rewritten_offsets",
            },
            web_context,
        )
        source = web.get("source_register")
        image_register = web.get("image_register")
        require(
            source in _IA32_REGISTER_NUMBERS
            and image_register in _IA32_REGISTER_NUMBERS
            and (source != image_register),
            f"{web_context} does not name two distinct general registers",
        )
        require(
            not {source, image_register} & structural,
            f"{web_context} touches " + ("ESP" if fpo_record is not None else "ESP or EBP"),
        )
        role_offsets = {}
        field_scopes = {}
        for role in ("definitions", "uses"):
            offsets, scopes = _ia32_web_membership(web, role, web_context)
            require(
                offsets == sorted(set(offsets))
                and all(0 <= offset < (code_length or body_length) for offset in offsets),
                f"{web_context}.{role} is invalid",
            )
            for offset, ordinal in scopes.items():
                require(offset not in field_scopes, f"{web_context} scopes {offset} twice")
                field_scopes[offset] = ordinal
            role_offsets[role] = offsets
        for offset in set(role_offsets["definitions"]) & set(role_offsets["uses"]):
            require(
                offset not in field_scopes,
                f"{web_context}: {offset} is a read-modify-write node and cannot also be field-scoped",
            )
        offsets = web.get("expected_rewritten_offsets")
        require(
            isinstance(offsets, list)
            and bool(offsets)
            and (offsets == sorted(set(offsets)))
            and (len(offsets) == len(role_offsets["definitions"]) + len(role_offsets["uses"]))
            and all(
                type(item) is int and 0 <= item < (code_length or body_length) for item in offsets
            ),
            f"{web_context}.expected_rewritten_offsets is invalid",
        )
        rewritten.extend(offsets)
        normalized_webs.append(
            {
                "source_register": source,
                "image_register": image_register,
                "definitions": list(role_offsets["definitions"]),
                "uses": list(role_offsets["uses"]),
                "field_scopes": dict(field_scopes),
                "expected_rewritten_offsets": list(offsets),
            }
        )
    changed = document.get("expected_changed_offsets")
    require(
        isinstance(changed, list)
        and bool(changed)
        and (changed == sorted(set(changed)))
        and all(
            type(offset) is int
            and (
                offset in rewritten
                or any(
                    item["start"] <= offset < item["end"]
                    for item in normalized_windows + normalized_trailing
                )
            )
            for offset in changed
        ),
        f"{context}.expected_changed_offsets is invalid",
    )
    require(
        set(rewritten) <= set(cast(list[Any], changed)),
        f"{context}.expected_changed_offsets omits a recoloured byte",
    )
    procedure = document.get("expected_procedure_range")
    require(
        isinstance(procedure, list)
        and len(procedure) == 3
        and all(type(item) is int and item >= 0 for item in procedure)
        and (procedure[0] == body_length)
        and (procedure[1] <= procedure[2] <= body_length),
        f"{context}.expected_procedure_range is invalid",
    )
    references = document.get("expected_code_symbol_references")
    require(
        isinstance(references, list)
        and all(
            isinstance(item, list)
            and len(item) == 3
            and isinstance(item[0], str)
            and isinstance(item[1], str)
            and (type(item[2]) is int)
            and (0 <= item[2] <= body_length)
            for item in references
        ),
        f"{context}.expected_code_symbol_references is invalid",
    )
    registers = document.get("expected_debug_s_registers")
    require(
        isinstance(registers, list)
        and all(
            isinstance(item, list)
            and len(item) == 3
            and isinstance(item[0], str)
            and (type(item[1]) is int)
            and (item[1] >= 0)
            and (item[2] in CODEVIEW_X86_REGISTER_NUMBERS)
            for item in registers
        ),
        f"{context}.expected_debug_s_registers is invalid",
    )
    rationale = document.get("authenticity_rationale")
    require(
        isinstance(rationale, str) and len(rationale) >= 40,
        f"{context}.authenticity_rationale is missing",
    )
    normalized = {
        "kind": WEB_RECOLOUR_KIND,
        "webs": normalized_webs,
        "expected_instruction_count": require_exact_int(
            document.get("expected_instruction_count"),
            f"{context}.expected_instruction_count",
            minimum=2,
        ),
        "expected_changed_offsets": list(cast(list[Any], changed)),
        "expected_procedure_range": list(cast(list[Any], procedure)),
        "expected_code_symbol_references": [list(item) for item in cast(list[Any], references)],
        "expected_debug_s_registers": [list(item) for item in cast(list[Any], registers)],
        "authenticity_rationale": rationale,
    }
    if normalized_windows:
        normalized["windows"] = normalized_windows
    if normalized_trailing:
        normalized["trailing_windows"] = normalized_trailing
    if code_length is not None:
        normalized["expected_code_length"] = code_length
    if targets is not None:
        normalized["expected_internal_relocation_targets"] = list(targets)
    return normalized


def validate_instruction_schedule(value: object, context: str, body_length: int) -> dict[str, Any]:
    """Validate one instruction-schedule certificate declaration."""
    require(isinstance(value, dict), f"{context} must be an object")
    document = cast(dict[str, Any], value)
    exact_audit_keys(
        document,
        {
            "kind",
            "windows",
            "expected_instruction_count",
            "expected_changed_offsets",
            "expected_procedure_range",
            "expected_code_symbol_references",
            "authenticity_rationale",
            "expected_code_length",
            "expected_internal_relocation_targets",
        },
        context,
        optional={"expected_code_length", "expected_internal_relocation_targets"},
    )
    require(document.get("kind") == INSTRUCTION_SCHEDULE_KIND, f"{context}.kind differs")
    code_length = document.get("expected_code_length")
    if code_length is not None:
        code_length = require_exact_int(
            code_length, f"{context}.expected_code_length", minimum=2, maximum=body_length
        )
    targets = document.get("expected_internal_relocation_targets")
    if targets is not None:
        require(
            isinstance(targets, list)
            and targets == sorted(set(targets))
            and all(type(item) is int and 0 <= item < body_length for item in targets),
            f"{context}.expected_internal_relocation_targets is invalid",
        )
    windows = document.get("windows")
    require(
        isinstance(windows, list) and 1 <= len(windows) <= 32,
        f"{context}.windows must contain 1..32 windows",
    )
    normalized_windows = _validate_schedule_windows(
        cast(list[Any], windows), context, body_length, code_length, targets
    )
    changed = document.get("expected_changed_offsets")
    require(
        isinstance(changed, list)
        and bool(changed)
        and (changed == sorted(set(changed)))
        and all(
            type(offset) is int
            and any(item["start"] <= offset < item["end"] for item in normalized_windows)
            for offset in changed
        ),
        f"{context}.expected_changed_offsets is invalid",
    )
    procedure = document.get("expected_procedure_range")
    require(
        isinstance(procedure, list)
        and len(procedure) == 3
        and all(type(item) is int and item >= 0 for item in procedure)
        and (procedure[0] == body_length)
        and (procedure[1] <= procedure[2] <= body_length),
        f"{context}.expected_procedure_range is invalid",
    )
    references = document.get("expected_code_symbol_references")
    require(
        isinstance(references, list)
        and all(
            isinstance(item, list)
            and len(item) == 3
            and isinstance(item[0], str)
            and isinstance(item[1], str)
            and (type(item[2]) is int)
            and (0 <= item[2] <= body_length)
            for item in references
        ),
        f"{context}.expected_code_symbol_references is invalid",
    )
    rationale = document.get("authenticity_rationale")
    require(
        isinstance(rationale, str) and len(rationale) >= 40,
        f"{context}.authenticity_rationale is missing",
    )
    normalized = {
        "kind": INSTRUCTION_SCHEDULE_KIND,
        "windows": normalized_windows,
        "expected_instruction_count": require_exact_int(
            document.get("expected_instruction_count"),
            f"{context}.expected_instruction_count",
            minimum=2,
        ),
        "expected_changed_offsets": list(cast(list[Any], changed)),
        "expected_procedure_range": list(cast(list[Any], procedure)),
        "expected_code_symbol_references": [list(item) for item in cast(list[Any], references)],
        "authenticity_rationale": rationale,
    }
    if code_length is not None:
        normalized["expected_code_length"] = code_length
    if targets is not None:
        normalized["expected_internal_relocation_targets"] = list(targets)
    return normalized


WEB_RECOLOUR_KIND = "web_recolour_v1"


INSTRUCTION_SCHEDULE_EDGE_REASONS = frozenset(
    {
        "register_raw",
        "register_war",
        "register_waw",
        "flags_raw",
        "flags_war",
        "flags_waw",
        "memory",
    }
)
