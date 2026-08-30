"""Candidate-only classic COFF constant-pool repacking."""

from __future__ import annotations

import re
import struct
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any

from reprobit.binary import require
from reprobit.coff_format import CoffObject

from .foundation import (
    exact_audit_keys,
    require_exact_int,
    require_payload_free_declaration,
    require_sha,
    sha256_bytes,
)

JsonDict = dict[str, Any]

RDATA_POOL_REPACK_SCHEMA = "rdata_pool_repack_v1"
RDATA_POOL_REPACK_SECTION_NAMES = (".rdata",)
RDATA_POOL_REPACK_LITERAL_SIZES = (4, 8)
RDATA_POOL_REPACK_PAD_FILLS = ("00",)
RDATA_POOL_REPACK_LITERAL_RE = re.compile(r"^\$T[0-9]{1,10}$")
RDATA_POOL_REPACK_STATIC_RE = re.compile(r"^_[A-Za-z_][A-Za-z0-9_]*\$S[0-9]{1,10}$")
COFF_CHARACTERISTICS_RE = re.compile(r"^0x[0-9a-f]{8}$")
COFF_SCN_CNT_INITIALIZED_DATA = 0x00000040
COFF_SCN_LNK_COMDAT = 0x00001000
COFF_SCN_ALIGN_MASK = 0x00F00000
COFF_SCN_MEM_READ = 0x40000000
COFF_SCN_MEM_WRITE = 0x80000000
COFF_RELOCATION_SIZE = 10
COFF_LINE_NUMBER_SIZE = 6
COFF_SYMBOL_SIZE = 18
COFF_REL_I386_DIR32 = 0x0006
COFF_SYM_CLASS_STATIC = 3


def coff_section_alignment(characteristics: int, context: str) -> int:
    """Decode a COFF section alignment field, refusing an unset one."""

    encoded = (characteristics & COFF_SCN_ALIGN_MASK) >> 20
    require(1 <= encoded <= 14, f"{context} declares no COFF section alignment")
    return 1 << (encoded - 1)


def rdata_pool_repack_seats(entries: list[JsonDict], key: str, start: int, context: str) -> int:
    """Re-derive seats implied by an ordered run of literal widths."""

    cursor = start
    for index, entry in enumerate(entries):
        size = int(entry["size"])
        seat = (cursor + size - 1) & ~(size - 1)
        require(
            entry[key] == seat,
            f"{context}[{index}].{key} seats {entry['symbol']} at {entry[key]}, "
            f"but its widths seat it at {seat}",
        )
        cursor = seat + size
    return cursor


def rdata_pool_repack_image(declaration: JsonDict, pool: bytes, context: str) -> bytes:
    """Rebuild a pool solely from its candidate pre-image bytes."""

    pre: JsonDict = declaration["pre_image"]
    prefix: JsonDict = pre["fixed_prefix"]
    post: JsonDict = declaration["post_image"]
    fill = bytes.fromhex(declaration["pad_fill"])
    require(len(pool) == pre["size"], f"{context} pre-image size differs")
    require(sha256_bytes(pool) == pre["sha256"], f"{context} pre-image digest differs")
    prefix_size = int(prefix["size"])
    require(
        sha256_bytes(pool[:prefix_size]) == prefix["sha256"],
        f"{context} fixed prefix differs",
    )
    entries: list[JsonDict] = declaration["permutation"]
    ordered = sorted(entries, key=lambda entry: int(entry["old_offset"]))
    cursor = prefix_size
    for entry in ordered:
        old = int(entry["old_offset"])
        gap = pool[cursor:old]
        require(gap == fill * len(gap), f"{context} pre-image pad before {entry['symbol']} differs")
        cursor = old + int(entry["size"])
    require(cursor == pre["size"], f"{context} pre-image literals do not reach its end")

    packed = bytearray(fill * int(post["size"]))
    packed[:prefix_size] = pool[:prefix_size]
    for entry in entries:
        old, new, size = int(entry["old_offset"]), int(entry["new_offset"]), int(entry["size"])
        require(
            old + size <= len(pool) and new + size <= len(packed),
            f"{context} seats {entry['symbol']} outside its pool",
        )
        packed[new : new + size] = pool[old : old + size]
    result = bytes(packed)
    require(sha256_bytes(result) == post["sha256"], f"{context} post-image digest differs")
    return result


def validate_rdata_pool_repack_declaration(
    value: object, context: str, *, pool_bytes: bytes | None = None
) -> JsonDict:
    """Validate a payload-free, candidate-owned constant-pool permutation."""

    require(isinstance(value, dict), f"{context} must be an object")
    assert isinstance(value, dict)
    exact_audit_keys(
        value,
        {
            "schema",
            "rationale",
            "object",
            "translation_unit",
            "section",
            "pad_fill",
            "pre_image",
            "permutation",
            "post_image",
        },
        context,
    )
    require(value.get("schema") == RDATA_POOL_REPACK_SCHEMA, f"{context}.schema is unsupported")
    rationale = value.get("rationale")
    require(isinstance(rationale, str) and bool(rationale), f"{context}.rationale must be stated")
    assert isinstance(rationale, str)
    require(
        "synthetic" in rationale.lower(),
        f"{context}.rationale must identify this as a synthetic construct",
    )
    for key, suffix in (("object", ".obj"), ("translation_unit", ".cpp")):
        declared = value.get(key)
        require(isinstance(declared, str) and bool(declared), f"{context}.{key} is invalid")
        assert isinstance(declared, str)
        pure = PurePosixPath(declared)
        require(
            "\\" not in declared
            and "\0" not in declared
            and not pure.is_absolute()
            and pure.as_posix() == declared
            and all(part not in ("", ".", "..") for part in pure.parts)
            and declared.endswith(suffix),
            f"{context}.{key} must be one canonical relative {suffix} path",
        )
    require(
        value.get("pad_fill") in RDATA_POOL_REPACK_PAD_FILLS, f"{context}.pad_fill is unsupported"
    )

    section = value.get("section")
    require(isinstance(section, dict), f"{context}.section must be an object")
    assert isinstance(section, dict)
    section_context = f"{context}.section"
    exact_audit_keys(
        section,
        {"index", "name", "characteristics", "relocation_count", "line_number_count"},
        section_context,
    )
    require_exact_int(section.get("index"), f"{section_context}.index", minimum=1, maximum=0xFFFF)
    require(
        section.get("name") in RDATA_POOL_REPACK_SECTION_NAMES,
        f"{section_context}.name is unsupported",
    )
    characteristics = section.get("characteristics")
    require(
        isinstance(characteristics, str)
        and COFF_CHARACTERISTICS_RE.fullmatch(characteristics) is not None,
        f"{section_context}.characteristics is invalid",
    )
    assert isinstance(characteristics, str)
    flags = int(characteristics, 16)
    require(
        bool(flags & COFF_SCN_CNT_INITIALIZED_DATA)
        and bool(flags & COFF_SCN_MEM_READ)
        and not flags & COFF_SCN_MEM_WRITE
        and not flags & COFF_SCN_LNK_COMDAT,
        f"{section_context}.characteristics must describe read-only initialized non-COMDAT data",
    )
    alignment = coff_section_alignment(flags, f"{section_context}.characteristics")
    require(
        type(section.get("relocation_count")) is int
        and section.get("relocation_count") == 0
        and type(section.get("line_number_count")) is int
        and section.get("line_number_count") == 0,
        f"{section_context} must carry no relocations or line numbers",
    )

    pre = value.get("pre_image")
    require(isinstance(pre, dict), f"{context}.pre_image must be an object")
    assert isinstance(pre, dict)
    exact_audit_keys(pre, {"size", "sha256", "fixed_prefix"}, f"{context}.pre_image")
    pre_size = require_exact_int(
        pre.get("size"), f"{context}.pre_image.size", minimum=1, maximum=1 << 24
    )
    require_sha(pre.get("sha256"), f"{context}.pre_image.sha256")
    prefix = pre.get("fixed_prefix")
    require(isinstance(prefix, dict), f"{context}.pre_image.fixed_prefix must be an object")
    assert isinstance(prefix, dict)
    prefix_context = f"{context}.pre_image.fixed_prefix"
    exact_audit_keys(prefix, {"size", "sha256", "symbols"}, prefix_context)
    prefix_size = require_exact_int(
        prefix.get("size"), f"{prefix_context}.size", minimum=0, maximum=pre_size
    )
    require_sha(prefix.get("sha256"), f"{prefix_context}.sha256")
    statics = prefix.get("symbols")
    require(
        isinstance(statics, list) and 1 <= len(statics) <= 256,
        f"{prefix_context}.symbols is invalid",
    )
    assert isinstance(statics, list)
    fixed_names: list[str] = []
    cursor = 0
    for position, static in enumerate(statics):
        static_context = f"{prefix_context}.symbols[{position}]"
        require(isinstance(static, dict), f"{static_context} must be an object")
        assert isinstance(static, dict)
        exact_audit_keys(static, {"symbol", "offset", "size"}, static_context)
        name = static.get("symbol")
        require(
            isinstance(name, str) and RDATA_POOL_REPACK_STATIC_RE.fullmatch(name) is not None,
            f"{static_context}.symbol is invalid",
        )
        assert isinstance(name, str)
        require(name not in fixed_names, f"{static_context}.symbol is duplicated")
        offset = require_exact_int(static.get("offset"), f"{static_context}.offset", minimum=0)
        size = require_exact_int(static.get("size"), f"{static_context}.size", minimum=1)
        require(offset == cursor, f"{static_context} does not tile the fixed prefix")
        fixed_names.append(name)
        cursor = offset + size
    require(cursor == prefix_size, f"{prefix_context}.symbols do not tile the prefix")

    entries = value.get("permutation")
    require(
        isinstance(entries, list) and 2 <= len(entries) <= 256, f"{context}.permutation is invalid"
    )
    assert isinstance(entries, list)
    symbols: list[str] = []
    old_offsets: list[int] = []
    new_offsets: list[int] = []
    typed_entries: list[JsonDict] = []
    for position, entry in enumerate(entries):
        entry_context = f"{context}.permutation[{position}]"
        require(isinstance(entry, dict), f"{entry_context} must be an object")
        assert isinstance(entry, dict)
        exact_audit_keys(
            entry,
            {"symbol", "old_offset", "new_offset", "size", "references"},
            entry_context,
        )
        name = entry.get("symbol")
        require(
            isinstance(name, str) and RDATA_POOL_REPACK_LITERAL_RE.fullmatch(name) is not None,
            f"{entry_context}.symbol is invalid",
        )
        assert isinstance(name, str)
        require(name not in fixed_names, f"{entry_context} names a fixed static")
        size_value = entry.get("size")
        require(
            type(size_value) is int and size_value in RDATA_POOL_REPACK_LITERAL_SIZES,
            f"{entry_context}.size is invalid",
        )
        assert isinstance(size_value, int)
        require(size_value <= alignment, f"{entry_context}.size exceeds section alignment")
        old = require_exact_int(
            entry.get("old_offset"),
            f"{entry_context}.old_offset",
            minimum=0,
            maximum=pre_size - size_value,
        )
        new = require_exact_int(
            entry.get("new_offset"),
            f"{entry_context}.new_offset",
            minimum=0,
            maximum=pre_size - size_value,
        )
        require(
            old >= prefix_size and new >= prefix_size, f"{entry_context} enters the fixed prefix"
        )
        require_exact_int(entry.get("references"), f"{entry_context}.references", minimum=0)
        symbols.append(name)
        old_offsets.append(old)
        new_offsets.append(new)
        typed_entries.append(entry)
    require(len(set(symbols)) == len(symbols), f"{context}.permutation names a symbol twice")
    require(len(set(old_offsets)) == len(old_offsets), f"{context}.permutation reuses an old seat")
    require(len(set(new_offsets)) == len(new_offsets), f"{context}.permutation reuses a new seat")
    require(new_offsets == sorted(new_offsets), f"{context}.permutation is not in post-image order")
    pre_end = rdata_pool_repack_seats(
        sorted(typed_entries, key=lambda entry: int(entry["old_offset"])),
        "old_offset",
        prefix_size,
        f"{context}.permutation",
    )
    require(pre_end == pre_size, f"{context}.permutation does not account for the pre-image")
    post_end = rdata_pool_repack_seats(
        typed_entries, "new_offset", prefix_size, f"{context}.permutation"
    )
    post = value.get("post_image")
    require(isinstance(post, dict), f"{context}.post_image must be an object")
    assert isinstance(post, dict)
    exact_audit_keys(post, {"size", "sha256"}, f"{context}.post_image")
    post_size = require_exact_int(
        post.get("size"), f"{context}.post_image.size", minimum=1, maximum=pre_size
    )
    require_sha(post.get("sha256"), f"{context}.post_image.sha256")
    require(post_end == post_size, f"{context}.permutation does not account for the post-image")
    require(
        post.get("sha256") != pre.get("sha256"), f"{context} declares an identical pre/post image"
    )
    normalized: JsonDict = dict(value)
    if pool_bytes is not None:
        rdata_pool_repack_image(normalized, pool_bytes, context)
    return normalized


def _pool_section(coff: CoffObject, declaration: JsonDict) -> JsonDict:
    declared: JsonDict = declaration["section"]
    candidates = [
        section
        for section in coff.sections
        if section["name"] == declared["name"]
        and not section["characteristics"] & COFF_SCN_LNK_COMDAT
    ]
    require(len(candidates) == 1, "object must contain exactly one declared non-COMDAT pool")
    section: JsonDict = candidates[0]
    require(section["number"] == declared["index"], "pool section seat differs")
    require(
        section["characteristics"] == int(declared["characteristics"], 16),
        "pool characteristics differ",
    )
    require(
        section["relocation_count"] == declared["relocation_count"]
        and section["line_count"] == declared["line_number_count"],
        "pool table counts differ",
    )
    require(section["raw_offset"] > 0 and section["raw_size"] > 0, "pool section has no raw data")
    return section


def _section_symbol(coff: CoffObject, section: JsonDict) -> tuple[int, int]:
    defining = [
        symbol
        for symbol in coff.symbols.values()
        if symbol["section"] == section["number"] and symbol["aux_count"]
    ]
    require(
        len(defining) == 1
        and defining[0]["name"] == section["name"]
        and defining[0]["value"] == 0
        and defining[0]["storage"] == COFF_SYM_CLASS_STATIC
        and defining[0]["aux_count"] == 1,
        "pool section symbol is not unique and well formed",
    )
    index = int(defining[0]["index"])
    auxiliary = coff.symbol_offset + (index + 1) * COFF_SYMBOL_SIZE
    length = int(struct.unpack_from("<I", coff.data, auxiliary)[0])
    require(length == section["raw_size"], "pool section auxiliary length differs")
    return index, auxiliary


def _pool_symbols(coff: CoffObject, section: JsonDict, defining_index: int) -> dict[str, JsonDict]:
    symbols: dict[str, JsonDict] = {}
    for symbol in coff.symbols.values():
        if symbol["section"] != section["number"] or symbol["index"] == defining_index:
            continue
        require(symbol["aux_count"] == 0, f"pool symbol {symbol['name']} carries auxiliary records")
        require(symbol["name"] not in symbols, f"pool symbol {symbol['name']} is duplicated")
        symbols[str(symbol["name"])] = symbol
    return symbols


def _symbol_references(coff: CoffObject, moved: set[str]) -> dict[str, int]:
    counts = dict.fromkeys(moved, 0)
    for section in coff.sections:
        count = int(section["relocation_count"])
        if not count:
            continue
        require(count < 0xFFFF, "COFF relocation overflow convention is unsupported")
        for slot in range(count):
            at = int(section["relocation_offset"]) + slot * COFF_RELOCATION_SIZE
            offset, symbol_index, kind = struct.unpack_from("<IIH", coff.data, at)
            symbol = coff.symbols.get(symbol_index)
            require(symbol is not None, "relocation names a non-symbol slot")
            assert symbol is not None
            name = str(symbol["name"])
            if name not in counts:
                continue
            require(kind == COFF_REL_I386_DIR32, f"relocation to {name} is not DIR32")
            require(
                section["raw_offset"] > 0 and offset + 4 <= section["raw_size"],
                f"relocation to {name} lies outside its section",
            )
            addend = int(
                struct.unpack_from("<I", coff.data, int(section["raw_offset"]) + offset)[0]
            )
            require(addend == 0, f"relocation to {name} carries a nonzero addend")
            counts[name] += 1
    return counts


def _shifted(field: int, cut_start: int, cut_end: int, delta: int, what: str) -> int:
    if field == 0 or field <= cut_start:
        return field
    require(field >= cut_end, f"{what} points inside the removed pool tail")
    return field - delta


def _verify_repacked_object(
    before: CoffObject,
    result: bytes,
    declaration: JsonDict,
    target_section: JsonDict,
    packed: bytes,
    reseated: dict[int, int],
    auxiliary_index: int,
) -> None:
    after = CoffObject(result)
    require(
        after.section_count == before.section_count
        and after.symbol_count == before.symbol_count
        and after.machine == before.machine
        and after.timestamp == before.timestamp
        and after.characteristics == before.characteristics,
        "repacked COFF header identity changed",
    )
    for old, new in zip(before.sections, after.sections, strict=True):
        target = old["number"] == target_section["number"]
        require(
            old["name"] == new["name"]
            and old["characteristics"] == new["characteristics"]
            and old["relocation_count"] == new["relocation_count"]
            and old["line_count"] == new["line_count"]
            and new["raw_size"]
            == (declaration["post_image"]["size"] if target else old["raw_size"]),
            f"section {old['number']} identity changed",
        )
        for kind, unit, offset_key, count_key in (
            ("raw", 1, "raw_offset", "raw_size"),
            ("relocation", COFF_RELOCATION_SIZE, "relocation_offset", "relocation_count"),
            ("line", COFF_LINE_NUMBER_SIZE, "line_offset", "line_count"),
        ):
            size = int(old[count_key]) * unit
            if not size or not old[offset_key]:
                continue
            was = before.data[int(old[offset_key]) : int(old[offset_key]) + size]
            now_size = int(new[count_key]) * unit
            now = result[int(new[offset_key]) : int(new[offset_key]) + now_size]
            if target and kind == "raw":
                require(now == packed, "repacked pool differs from the derived image")
            else:
                require(was == now, f"section {old['number']} {kind} bytes changed")
    for index in range(before.symbol_count):
        was = before.data[
            before.symbol_offset + index * COFF_SYMBOL_SIZE : before.symbol_offset
            + (index + 1) * COFF_SYMBOL_SIZE
        ]
        now = result[
            after.symbol_offset + index * COFF_SYMBOL_SIZE : after.symbol_offset
            + (index + 1) * COFF_SYMBOL_SIZE
        ]
        if index in reseated:
            require(
                now[:8] == was[:8]
                and now[12:] == was[12:]
                and struct.unpack_from("<I", now, 8)[0] == reseated[index],
                f"symbol record {index} was not re-seated as declared",
            )
        elif index == auxiliary_index:
            require(
                now[4:] == was[4:]
                and struct.unpack_from("<I", now, 0)[0] == declaration["post_image"]["size"],
                "pool section auxiliary record was not resized",
            )
        else:
            require(was == now, f"symbol record {index} changed")
    require(
        before.data[before.string_offset :] == result[after.string_offset :],
        "COFF string table changed",
    )


def apply_rdata_pool_repack_candidate(
    candidate: bytes, declaration: Mapping[str, object]
) -> tuple[bytes, dict[str, object]]:
    """Shrink and permute one non-COMDAT pool from candidate-owned bytes."""

    require(isinstance(candidate, bytes), "COFF candidate must be immutable bytes")
    require_payload_free_declaration(declaration, "rdata-pool declaration")
    plan = validate_rdata_pool_repack_declaration(dict(declaration), "rdata-pool declaration")
    coff = CoffObject(candidate)
    section = _pool_section(coff, plan)
    pre: JsonDict = plan["pre_image"]
    post: JsonDict = plan["post_image"]
    require(section["raw_size"] == pre["size"], "pool section size differs from its pre-image pin")
    pool_start = int(section["raw_offset"])
    pool = candidate[pool_start : pool_start + int(pre["size"])]
    validate_rdata_pool_repack_declaration(plan, "rdata-pool declaration", pool_bytes=pool)
    packed = rdata_pool_repack_image(plan, pool, "rdata-pool declaration")

    defining_index, auxiliary = _section_symbol(coff, section)
    present = _pool_symbols(coff, section, defining_index)
    prefix: JsonDict = pre["fixed_prefix"]
    fixed = {item["symbol"]: item for item in prefix["symbols"]}
    entries: list[JsonDict] = plan["permutation"]
    moved = {entry["symbol"]: entry for entry in entries}
    require(set(present) == set(fixed) | set(moved), "pool symbol universe differs")
    for name, item in fixed.items():
        require(present[name]["value"] == item["offset"], f"fixed static {name} moved")
    for name, entry in moved.items():
        require(
            present[name]["value"] == entry["old_offset"], f"pool literal {name} old seat differs"
        )
    counts = _symbol_references(coff, set(moved))
    for name, entry in moved.items():
        require(counts[name] == entry["references"], f"pool literal {name} reference count differs")

    cut_start = pool_start + int(post["size"])
    cut_end = pool_start + int(pre["size"])
    delta = int(pre["size"]) - int(post["size"])
    require(delta > 0, "rdata pool repack removes no bytes")
    output = bytearray(candidate[:pool_start] + packed + candidate[cut_end:])
    struct.pack_into("<I", output, int(section["header_offset"]) + 16, int(post["size"]))
    for other in coff.sections:
        header = int(other["header_offset"])
        if other["number"] != section["number"]:
            struct.pack_into(
                "<I",
                output,
                header + 20,
                _shifted(int(other["raw_offset"]), cut_start, cut_end, delta, "section raw data"),
            )
        struct.pack_into(
            "<I",
            output,
            header + 24,
            _shifted(
                int(other["relocation_offset"]), cut_start, cut_end, delta, "section relocations"
            ),
        )
        struct.pack_into(
            "<I",
            output,
            header + 28,
            _shifted(int(other["line_offset"]), cut_start, cut_end, delta, "section line numbers"),
        )
    new_symbol_offset = _shifted(coff.symbol_offset, cut_start, cut_end, delta, "symbol table")
    struct.pack_into("<I", output, 8, new_symbol_offset)
    struct.pack_into("<I", output, auxiliary - delta, int(post["size"]))
    reseated: dict[int, int] = {}
    for name, entry in moved.items():
        symbol_index = int(present[name]["index"])
        new_value = int(entry["new_offset"])
        record = new_symbol_offset + symbol_index * COFF_SYMBOL_SIZE
        struct.pack_into("<I", output, record + 8, new_value)
        reseated[symbol_index] = new_value

    result = bytes(output)
    _verify_repacked_object(coff, result, plan, section, packed, reseated, defining_index + 1)
    require(len(result) == len(candidate) - delta, "repacked object length differs")
    return result, {
        "schema": RDATA_POOL_REPACK_SCHEMA,
        "candidate_only": True,
        "oracle_payload_bytes_read": 0,
        "literal_count": len(entries),
        "removed_padding_bytes": delta,
        "input_sha256": sha256_bytes(candidate),
        "output_sha256": sha256_bytes(result),
        "pool_input_sha256": sha256_bytes(pool),
        "pool_output_sha256": sha256_bytes(packed),
    }


__all__ = [
    "RDATA_POOL_REPACK_SCHEMA",
    "apply_rdata_pool_repack_candidate",
    "coff_section_alignment",
    "rdata_pool_repack_image",
    "rdata_pool_repack_seats",
    "validate_rdata_pool_repack_declaration",
]
