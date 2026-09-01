"""Classic compiler algorithms: same-slot resize composition and the candidates built on it."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from reprobit.binary import require
from reprobit.coff_format import (
    CoffObject,
    coff_auxiliary,
    coff_body,
    coff_unpack,
    detailed_relocations,
    section_definitions,
)

from .coff import (
    _coff_marker,
    _coff_section_symbol,
    _coff_table_bytes,
    _comdat_child,
    _comdat_child_closure,
    function_multiset,
    function_symbol,
    require_source_target_closure_topology,
    require_target_closure_extraction_topology,
)
from .debug import (
    LOCAL_SET_DELTA_REFACTOR_KINDS,
    _apply_replacements,
    parse_fpo_data,
    require_debug_symbol_representation_delta,
    require_removed_caller_locals_delta,
    shifted_pointer,
)
from .foundation import (
    local_symbol_kind,
    require_payload_free_declaration,
    sha256_bytes,
)
from .ia32 import (
    require_declared_relocation_semantics,
)
from .source_proofs import (
    require_target_source_range_identity,
    require_target_source_refactor_identity,
)


def _pair_same_slot_relocations(
    seed_rows, donor_rows, seed_primary, donor_primary, seed_xdata, donor_xdata, mapping, context
):
    """Pair ordinal relocation semantics allowing offset movement and
    consistently mapped object-local symbols inside the target closure."""
    require(len(seed_rows) == len(donor_rows), f"{context}: relocation counts differ")
    reverse = {right: left for left, right in mapping.items()}

    def role(section_number, primary, xdata):
        if section_number == primary:
            return "primary"
        if section_number == xdata:
            return "xdata"
        return "external"

    pairs = []
    for left, right in zip(seed_rows, donor_rows, strict=True):
        require(
            left["type"] == right["type"] and left["addend"] == right["addend"],
            f"{context}: relocation type/addend differs",
        )
        require(
            role(left["target_section"], seed_primary, seed_xdata)
            == role(right["target_section"], donor_primary, donor_xdata),
            f"{context}: relocation target role differs",
        )
        left_local = local_symbol_kind(left["target"]) is not None
        right_local = local_symbol_kind(right["target"]) is not None
        if left_local or right_local:
            require(
                left_local
                and right_local
                and (left["target"][1] == right["target"][1])
                and (left["target_type"] == right["target_type"])
                and (left["target_storage"] == right["target_storage"]),
                f"{context}: local relocation target class differs",
            )
            if role(left["target_section"], seed_primary, seed_xdata) in ("primary", "xdata"):
                require(
                    mapping.setdefault(left["symbol_index"], right["symbol_index"])
                    == right["symbol_index"]
                    and reverse.setdefault(right["symbol_index"], left["symbol_index"])
                    == left["symbol_index"],
                    f"{context}: local symbol mapping is inconsistent",
                )
            else:
                require(
                    left["target_section"] == right["target_section"]
                    and left["target_value"] == right["target_value"],
                    f"{context}: external local relocation target differs",
                )
        else:
            require(
                left["target"] == right["target"]
                and left["target_type"] == right["target_type"]
                and (left["target_storage"] == right["target_storage"]),
                f"{context}: relocation target differs",
            )
        pairs.append((left, right))
    return pairs


def _resolve_substituted_seed_symbol(
    seed: CoffObject, donor_record: dict[str, Any], context: str
) -> int:
    """B5/B6: map a donor relocation's EXTERNAL target onto the seed's own
    symbol table, by name, unambiguously, with matching class.

    Compiler-local `$L`/`$T`/`$S` serials are deliberately NOT routed here --
    they are assigned per compile, are never present in the seed, and stay
    with the existing rename machinery (spec amendment 2).
    """
    name = donor_record["target"]
    require(
        local_symbol_kind(name) is None,
        f"{context}: compiler-local target {name!r} must not be remapped",
    )
    matches = [(index, symbol) for index, symbol in seed.symbols.items() if symbol["name"] == name]
    require(
        matches,
        f"{context}: donor relocation target {name!r} is not declared or defined by the seed object",
    )
    require(
        len(matches) == 1,
        f"{context}: ambiguous symbol remap for {name!r} -- {len(matches)} seed symbols share the name",
    )
    index, symbol = matches[0]
    require(
        symbol["type"] == donor_record["target_type"]
        and symbol["storage"] == donor_record["target_storage"],
        f"{context}: seed symbol {name!r} differs in type or storage class (seed type=0x{symbol['type']:02x} storage={symbol['storage']}, donor type=0x{donor_record['target_type']:02x} storage={donor_record['target_storage']})",
    )
    return index


def _source_target_relocation_substitutions(
    seed: CoffObject,
    donor_rows: list[dict[str, Any]],
    mapping: dict[int, int],
    expected_imports: list[str],
    section_map: dict[int, int],
    context: str,
) -> tuple[dict[int, int], list[tuple[str, int, int]]]:
    """Resolve a whole donor target table into seed locals/externals."""
    reverse = {donor_index: seed_index for seed_index, donor_index in mapping.items()}
    imports = {}
    substitutions = {}
    for ordinal, record in enumerate(donor_rows):
        if local_symbol_kind(record["target"]) is not None:
            if record["symbol_index"] not in reverse:
                candidates = [
                    index
                    for index, symbol in seed.symbols.items()
                    if local_symbol_kind(symbol["name"]) == local_symbol_kind(record["target"])
                    and symbol["section"] == section_map.get(record["target_section"])
                    and (symbol["value"] == record["target_value"])
                    and (symbol["type"] == record["target_type"])
                    and (symbol["storage"] == record["target_storage"])
                ]
                require(
                    len(candidates) == 1, f"{context}: target local has no unique seed structure"
                )
                mapping[candidates[0]] = record["symbol_index"]
                reverse[record["symbol_index"]] = candidates[0]
            substitutions[ordinal] = reverse[record["symbol_index"]]
            continue
        matches = [
            index for index, symbol in seed.symbols.items() if symbol["name"] == record["target"]
        ]
        if matches:
            substitutions[ordinal] = _resolve_substituted_seed_symbol(seed, record, context)
            continue
        name = record["target"]
        require(
            name in expected_imports
            and record["target_value"] == 0
            and (record["target_type"] == 32)
            and (record["target_storage"] == 2),
            f"{context}: donor target {name!r} is absent from the seed",
        )
        imports.setdefault(name, (name, record["target_type"], record["target_storage"]))
        substitutions[ordinal] = seed.symbol_count + expected_imports.index(name)
    require(
        sorted(imports) == expected_imports, f"{context}: imported undefined symbol set differs"
    )
    return (substitutions, [imports[name] for name in expected_imports])


def _append_undefined_external_symbols(data: bytes, symbols: list[tuple[str, int, int]]) -> bytes:
    if not symbols:
        return data
    coff = CoffObject(data)
    strings = bytearray(data[coff.string_offset : coff.string_end])
    records = bytearray()
    for name, symbol_type, storage in symbols:
        encoded = name.encode("ascii")
        if len(encoded) <= 8:
            name_field = encoded.ljust(8, b"\x00")
        else:
            name_field = b"\x00\x00\x00\x00" + len(strings).to_bytes(4, "little")
            strings.extend(encoded + b"\x00")
        records.extend(name_field + struct.pack("<IhHBB", 0, 0, symbol_type, storage, 0))
    strings[:4] = len(strings).to_bytes(4, "little")
    output = bytearray(data[: coff.string_offset] + records + strings)
    output[12:16] = (coff.symbol_count + len(symbols)).to_bytes(4, "little")
    return bytes(output)


@dataclass(frozen=True, slots=True, kw_only=True)
class RelocSide:
    """One object's primary relocation rows and the sections that classify them.

    ``coff`` is the object the rows come from, ``rows`` its detailed
    primary-section relocations, and ``primary`` and ``xdata`` the numbers
    of its primary and xdata sections, which decide whether a row's target
    is primary, xdata or external.
    """

    coff: CoffObject
    rows: list[dict[str, Any]]
    primary: int
    xdata: int


def _pair_reloc_divergent(
    seed_side: RelocSide, donor_side: RelocSide, mapping: dict[int, int], context: str
):
    """Pair the primary table allowing a divergent EXTERNAL target set.

    Identical to `_pair_same_slot_relocations` except that where both sides
    name ordinary (non-local) symbols and those names DIFFER, the ordinal is
    recorded as a substitution and the donor's target is resolved into the
    seed's symbol table under B5/B6.  Returns (pairs, substitutions) where
    substitutions maps the ordinal index to the seed symbol index to write.
    """
    seed = seed_side.coff
    donor = donor_side.coff
    seed_rows = seed_side.rows
    donor_rows = donor_side.rows
    seed_primary = seed_side.primary
    donor_primary = donor_side.primary
    seed_xdata = seed_side.xdata
    donor_xdata = donor_side.xdata
    require(
        len(donor_rows) >= len(seed_rows),
        f"{context}: the donor carries FEWER relocations than the seed; the shrinking path is not implemented",
    )
    appended_rows = donor_rows[len(seed_rows) :]
    donor_rows = donor_rows[: len(seed_rows)]
    reverse = {right: left for left, right in mapping.items()}

    def role(section_number, primary, xdata):
        if section_number == primary:
            return "primary"
        if section_number == xdata:
            return "xdata"
        return "external"

    pairs = []
    substitutions: dict[int, int] = {}
    for ordinal, (left, right) in enumerate(zip(seed_rows, donor_rows, strict=True)):
        require(left["type"] == right["type"], f"{context}: relocation type differs")
        left_local = local_symbol_kind(left["target"]) is not None
        right_local = local_symbol_kind(right["target"]) is not None
        if left_local or right_local:
            require(left["addend"] == right["addend"], f"{context}: relocation addend differs")
            require(
                role(left["target_section"], seed_primary, seed_xdata)
                == role(right["target_section"], donor_primary, donor_xdata),
                f"{context}: relocation target role differs",
            )
            require(
                left_local
                and right_local
                and (left["target"][1] == right["target"][1])
                and (left["target_type"] == right["target_type"])
                and (left["target_storage"] == right["target_storage"]),
                f"{context}: local relocation target class differs",
            )
            if role(left["target_section"], seed_primary, seed_xdata) in ("primary", "xdata"):
                require(
                    mapping.setdefault(left["symbol_index"], right["symbol_index"])
                    == right["symbol_index"]
                    and reverse.setdefault(right["symbol_index"], left["symbol_index"])
                    == left["symbol_index"],
                    f"{context}: local symbol mapping is inconsistent",
                )
            else:
                left_section_number = left["target_section"]
                right_section_number = right["target_section"]
                require(
                    0 < left_section_number <= len(seed.sections)
                    and right_section_number <= len(donor.sections)
                    and (left_section_number == right_section_number)
                    and (left["target_value"] == right["target_value"]),
                    f"{context}: external local relocation target differs",
                )
                left_section = seed.sections[left_section_number - 1]
                right_section = donor.sections[right_section_number - 1]
                left_definition = section_definitions(seed).get(left_section_number)
                right_definition = section_definitions(donor).get(right_section_number)
                require(
                    all(
                        left_section[key] == right_section[key]
                        for key in (
                            "name",
                            "raw_size",
                            "relocation_count",
                            "line_count",
                            "characteristics",
                        )
                    )
                    and coff_body(seed, left_section) == coff_body(donor, right_section)
                    and (
                        _coff_table_bytes(seed, left_section, "relocations")
                        == _coff_table_bytes(donor, right_section, "relocations")
                    )
                    and (
                        _coff_table_bytes(seed, left_section, "lines")
                        == _coff_table_bytes(donor, right_section, "lines")
                    )
                    and (left_definition is not None)
                    and (right_definition is not None)
                    and (left_definition["raw"] == right_definition["raw"]),
                    f"{context}: external local target section differs",
                )
        elif left["target"] == right["target"]:
            require(left["addend"] == right["addend"], f"{context}: relocation addend differs")
            require(
                left["target_type"] == right["target_type"]
                and left["target_storage"] == right["target_storage"],
                f"{context}: relocation target class differs",
            )
            require(
                _resolve_substituted_seed_symbol(seed, right, context) == left["symbol_index"],
                f"{context}: same-name relocation target is ambiguous or does not name the paired seed symbol",
            )
        else:
            left_base, left_sep, left_serial = left["target"].rpartition("$S")
            right_base, right_sep, right_serial = right["target"].rpartition("$S")
            if (
                left_sep
                and right_sep
                and left_base
                and (left_base == right_base)
                and left_serial.isdigit()
                and right_serial.isdigit()
            ):
                require(
                    left["addend"] == right["addend"]
                    and left["target_type"] == right["target_type"]
                    and (left["target_storage"] == right["target_storage"])
                    and (left["target_value"] == right["target_value"]),
                    f"{context}: renamed $S relocation target class differs",
                )
                left_section_number = left["target_section"]
                right_section_number = right["target_section"]
                require(
                    0 < left_section_number <= len(seed.sections)
                    and 0 < right_section_number <= len(donor.sections),
                    f"{context}: renamed $S relocation names no section",
                )
                left_section = seed.sections[left_section_number - 1]
                right_section = donor.sections[right_section_number - 1]
                require(
                    all(
                        left_section[key] == right_section[key]
                        for key in (
                            "name",
                            "raw_size",
                            "relocation_count",
                            "line_count",
                            "characteristics",
                        )
                    )
                    and coff_body(seed, left_section) == coff_body(donor, right_section)
                    and (
                        _coff_table_bytes(seed, left_section, "relocations")
                        == _coff_table_bytes(donor, right_section, "relocations")
                    ),
                    f"{context}: renamed $S target section differs",
                )
                matches = [
                    index
                    for index, symbol in seed.symbols.items()
                    if symbol["name"] == left["target"]
                ]
                require(
                    len(matches) == 1,
                    f"{context}: renamed $S seed symbol {left['target']!r} is not unique",
                )
                substitutions[ordinal] = matches[0]
            else:
                substitutions[ordinal] = _resolve_substituted_seed_symbol(seed, right, context)
        pairs.append((left, right))
    appended: list[tuple[dict[str, Any], int]] = []
    for extra_index, record in enumerate(appended_rows):
        where = f"{context} appended relocation {extra_index}"
        require(
            local_symbol_kind(record["target"]) is None,
            f"{where}: appended compiler-local target {record['target']!r} has no seed symbol to name it",
        )
        appended.append((record, _resolve_substituted_seed_symbol(seed, record, where)))
    return (pairs, substitutions, appended)


def compose_same_slot_resize(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    *,
    target_closure_extract: bool = False,
    source_target_extract: bool = False,
    declared_donor_extras: list[Any] | None = None,
    declared_seed_only: list[Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Install a donor code body of a different size that occupies the same
    16-byte linked contribution slot, repairing every dependent COFF record.

    The seed supplies the object, symbol table, CodeView types/names, xdata
    raw bytes/relocations, and every non-target section.  The donor supplies
    the compiler-generated target code, COFF line offsets, and procedure
    debug range.  Mapped object-local symbol values move to the donor's.

    A declared divergent class may use a different EXTERNAL relocation target
    set.  The producer proves that set against declarative symbol semantics;
    it never receives reference bytes.  Final linked-byte equality belongs to
    the sealed verifier.  ``target_closure_extract`` replaces only the two
    whole-donor topology guards with a pinned strict-subset proof; every
    target-closure and output-conservation guard remains shared.
    """
    require_payload_free_declaration(function, "same-slot resize declaration")
    splice_class = function.get("splice_class")
    require(
        splice_class
        in (
            "same_slot_resize",
            "retail_exact_reloc_divergent",
            "retail_exact_target_closure",
            "retail_exact_source_target_closure",
        ),
        "same-slot composer received an unsupported splice class",
    )
    expected_divergent = splice_class != "same_slot_resize"
    expected_extract = splice_class == "retail_exact_target_closure"
    expected_source_extract = splice_class == "retail_exact_source_target_closure"
    require(
        target_closure_extract == expected_extract,
        "target-closure topology mode differs from the splice class",
    )
    require(
        source_target_extract == expected_source_extract,
        "source-target topology mode differs from the splice class",
    )
    divergent = expected_divergent
    seed = CoffObject(seed_bytes)
    donor = CoffObject(donor_bytes)
    mangled = function["mangled"]
    sp = seed.function_section(mangled)
    dp = donor.function_section(mangled)
    require(
        sp["raw_size"] == function["expected_seed_length"]
        and dp["raw_size"] == function["expected_donor_length"],
        "target body lengths changed",
    )
    require(
        (dp["raw_size"] + 15) // 16 * 16 == function["expected_linked_span"],
        "donor 16-byte linked contribution span changed",
    )
    declared_donor_seat = function.get("expected_donor_section_number")
    if declared_donor_seat is None:
        require(sp["number"] == dp["number"], "target section seat changed")
    else:
        require(dp["number"] == declared_donor_seat, "declared cross-lane donor seat changed")
    topology_detail = {}
    if source_target_extract:
        topology_detail = require_source_target_closure_topology(
            seed, donor, function, "source-target closure extraction"
        )
    elif target_closure_extract:
        topology_detail = require_target_closure_extraction_topology(
            seed, donor, function, "target-closure extraction"
        )
    elif declared_donor_extras or declared_seed_only:
        seed_fns = function_multiset(seed)
        donor_fns = function_multiset(donor)
        measured_extra = []
        measured_only = []
        for name in set(seed_fns) | set(donor_fns):
            left, right = (seed_fns.get(name, 0), donor_fns.get(name, 0))
            if right == left:
                continue
            if right == left + 1:
                measured_extra.append(name)
                continue
            require(left == right + 1, f"donor function census diverges at {name}")
            measured_only.append(name)
        require(
            sorted(measured_extra) == sorted(declared_donor_extras or []),
            "donor function set differs from its declared extras",
        )
        require(
            sorted(measured_only) == sorted(declared_seed_only or []),
            "donor function set differs from its declared seed-only names",
        )
        require(
            mangled not in (declared_seed_only or []),
            "the target itself cannot be a seed-only name",
        )
    else:
        require(len(seed.sections) == len(donor.sections), "global section count differs")
        require(function_multiset(seed) == function_multiset(donor), "donor function set differs")
    require(
        all(sp[key] == dp[key] for key in ("name", "characteristics")),
        "target header shape changed",
    )
    require(
        divergent or sp["relocation_count"] == dp["relocation_count"], "target header shape changed"
    )
    if "expected_seed_line_count" in function or "expected_donor_line_count" in function:
        require(
            sp["line_count"] == function["expected_seed_line_count"]
            and dp["line_count"] == function["expected_donor_line_count"],
            "target COFF line counts differ from their split pins",
        )
    else:
        require(sp["line_count"] == dp["line_count"], "target header shape changed")
    seed_defs = section_definitions(seed)
    donor_defs = section_definitions(donor)
    require(
        seed_defs[sp["number"]]["selection"] == donor_defs[dp["number"]]["selection"],
        "target COMDAT selection changed",
    )
    closure = _comdat_child_closure(seed, sp)
    require(
        closure == _comdat_child_closure(donor, dp)
        and closure in ((2, (".debug$S", ".xdata$x")), (2, (".debug$F", ".debug$S"))),
        "target closure is not an EH or FPO debug pair",
    )
    fpo_closure = closure == (2, (".debug$F", ".debug$S"))
    if fpo_closure:
        sx = _comdat_child(seed, sp, ".debug$F")
        dx = _comdat_child(donor, dp, ".debug$F")
    else:
        sx = _comdat_child(seed, sp, ".xdata$x")
        dx = _comdat_child(donor, dp, ".xdata$x")
    sd = _comdat_child(seed, sp, ".debug$S")
    dd = _comdat_child(donor, dp, ".debug$S")
    if declared_donor_seat is None:
        require(
            sx["number"] == dx["number"] and sd["number"] == dd["number"],
            "closure section seats changed",
        )
    local_set_delta = function.get("local_set_delta")
    representation_delta = function.get("debug_representation_delta")
    local_set_detail = {}
    reduced_debug_raw = None
    debug_shape_keys = ("name", "raw_size", "relocation_count", "line_count", "characteristics")
    if local_set_delta is not None:
        require(
            "target_source_refactor" in function
            and function["target_source_refactor"]["kind"] in LOCAL_SET_DELTA_REFACTOR_KINDS,
            "local-set delta is outside its closed source-refactor kinds",
        )
        debug_shape_keys = ("name", "relocation_count", "line_count", "characteristics")
    if representation_delta is not None:
        require(
            local_set_delta is None,
            "debug representation delta cannot combine with a local-set delta",
        )
        debug_shape_keys = ("name", "relocation_count", "line_count", "characteristics")
    for left, right, name, keys in (
        (
            sx,
            dx,
            "xdata",
            ("name", "raw_size", "relocation_count", "line_count", "characteristics"),
        ),
        (sd, dd, "debug$S", debug_shape_keys),
    ):
        require(all(left[key] == right[key] for key in keys), f"{name} section shape changed")
    if local_set_delta is not None:
        local_set_detail, reduced_debug_raw = require_removed_caller_locals_delta(
            coff_body(seed, sd),
            coff_body(donor, dd),
            [item["offset"] for item in detailed_relocations(seed, sd)],
            local_set_delta,
            "debug$S local-set delta",
        )
    representation_detail = []
    if representation_delta is not None:
        representation_detail = require_debug_symbol_representation_delta(
            bytes(coff_body(seed, sd)),
            bytes(coff_body(donor, dd)),
            representation_delta,
            function["expected_seed_length"],
            function["expected_donor_length"],
            "debug$S representation delta",
        )
    if fpo_closure:
        parse_fpo_data(coff_body(seed, sx), expected_proc_size=sp["raw_size"])
        donor_fpo = coff_body(donor, dx)
        parse_fpo_data(donor_fpo, expected_proc_size=dp["raw_size"])
    else:
        require(coff_body(seed, sx) == coff_body(donor, dx), "runtime xdata bytes differ")
    donor_code = coff_body(donor, dp)
    require(
        sha256_bytes(donor_code) == function["expected_body_sha256"],
        "donor body differs from its pinned compiler output",
    )
    spr = detailed_relocations(seed, sp)
    dpr = detailed_relocations(donor, dp)
    sxr = detailed_relocations(seed, sx)
    dxr = detailed_relocations(donor, dx)
    sdr = detailed_relocations(seed, sd)
    ddr = detailed_relocations(donor, dd)
    mapping: dict[int, int] = {}
    substitutions: dict[int, int] = {}
    appended_relocations: list[tuple[dict[str, Any], int]] = []
    imported_symbols: list[tuple[str, int, int]] = []
    xdata_pairs = _pair_same_slot_relocations(
        sxr, dxr, sp["number"], dp["number"], sx["number"], dx["number"], mapping, "xdata"
    )
    debug_pairs = _pair_same_slot_relocations(
        sdr, ddr, sp["number"], dp["number"], sx["number"], dx["number"], mapping, "debug$S"
    )
    if divergent:
        pinned_length = function["retail_oracle"]["length"]
        require(
            len(donor_code) == pinned_length,
            "candidate body differs from its declared linked length",
        )
        semantic_detail = require_declared_relocation_semantics(
            dpr, function["retail_relocations"], "candidate relocation semantics"
        )
        if source_target_extract:
            require(len(spr) == len(dpr), "source-target relocation table count changed")
            substitutions, imported_symbols = _source_target_relocation_substitutions(
                seed,
                dpr,
                mapping,
                function["expected_imported_undefined_symbols"],
                {dp["number"]: sp["number"], dx["number"]: sx["number"]},
                "source-target primary",
            )
        else:
            _, substitutions, appended_relocations = _pair_reloc_divergent(
                RelocSide(coff=seed, rows=spr, primary=sp["number"], xdata=sx["number"]),
                RelocSide(coff=donor, rows=dpr, primary=dp["number"], xdata=dx["number"]),
                mapping,
                "primary",
            )
    else:
        semantic_detail = {}
        _pair_same_slot_relocations(
            spr, dpr, sp["number"], dp["number"], sx["number"], dx["number"], mapping, "primary"
        )
    require(
        all((a["offset"] == b["offset"] for a, b in xdata_pairs)), "xdata relocation offsets moved"
    )
    require(
        all((a["offset"] == b["offset"] for a, b in debug_pairs)),
        "debug$S relocation offsets moved",
    )
    allowed_sections = {sp["number"], sx["number"], sd["number"]}
    for section in seed.sections:
        for record in (
            detailed_relocations(seed, section)
            if section["relocation_count"] and section["number"] not in allowed_sections
            else []
        ):
            require(
                record["symbol_index"] not in mapping,
                "mapped local is consumed outside the target closure",
            )
    for seed_index, donor_index in mapping.items():
        left = seed.symbols[seed_index]
        right = donor.symbols[donor_index]
        if declared_donor_seat is None:
            require(
                (left["section"], left["type"], left["storage"])
                == (right["section"], right["type"], right["storage"]),
                "mapped local symbol class changed",
            )
        else:
            require(
                (left["section"] - sp["number"], left["type"], left["storage"])
                == (right["section"] - dp["number"], right["type"], right["storage"]),
                "mapped local symbol class changed",
            )
    seed_function_index, _seed_function = function_symbol(seed, mangled, sp["number"])
    donor_function_index, donor_function = function_symbol(donor, mangled, dp["number"])
    require(sp["line_count"] > 0 and dp["line_count"] > 0, "target COFF line count changed")
    seed_lines = _coff_table_bytes(seed, sp, "lines")
    donor_lines = bytearray(_coff_table_bytes(donor, dp, "lines"))
    require(
        coff_unpack("<IH", seed_lines, 0, "seed line sentinel") == (seed_function_index, 0)
        and coff_unpack("<IH", donor_lines, 0, "donor line sentinel") == (donor_function_index, 0),
        "COFF line sentinel is invalid",
    )
    donor_lines[0:4] = seed_function_index.to_bytes(4, "little")
    previous = -1
    for index in range(1, dp["line_count"]):
        offset, line = coff_unpack("<IH", bytes(donor_lines), index * 6, "donor line row")
        require(
            line != 0 and previous <= offset < dp["raw_size"],
            "donor COFF line row is outside/nonmonotonic",
        )
        previous = offset
    donor_lines = bytes(donor_lines)
    seed_debug_raw = coff_body(seed, sd)
    donor_debug_raw = coff_body(donor, dd)
    require(
        len(seed_debug_raw) >= 28
        and seed_debug_raw[2:4] == b"\x05\x02"
        and (donor_debug_raw[2:4] == b"\x05\x02"),
        "debug$S is not an S_*PROC32 record",
    )
    donor_cbproc, donor_dbgstart, donor_dbgend = coff_unpack(
        "<III", donor_debug_raw, 16, "donor debug range"
    )
    require(
        donor_cbproc == dp["raw_size"] and 0 <= donor_dbgstart <= donor_dbgend < donor_cbproc,
        "donor debug procedure range is stale",
    )
    expected_debug_raw = bytearray(
        seed_debug_raw if reduced_debug_raw is None else reduced_debug_raw
    )
    expected_debug_raw[16:28] = donor_debug_raw[16:28]
    old_end = sp["raw_offset"] + sp["raw_size"]
    replacements = [
        (sp["raw_offset"], old_end, donor_code),
        (sp["line_offset"], sp["line_offset"] + sp["line_count"] * 6, donor_lines),
    ]
    if reduced_debug_raw is not None:
        replacements.append(
            (sd["raw_offset"], sd["raw_offset"] + sd["raw_size"], bytes(expected_debug_raw))
        )
    if appended_relocations:
        grown = bytearray()
        # dpr carries the appended rows beyond the seed's count; they are written below.
        for index, (left, right) in enumerate(zip(spr, dpr, strict=False)):
            grown += right["offset"].to_bytes(4, "little")
            grown += substitutions.get(index, left["symbol_index"]).to_bytes(4, "little")
            grown += right["type"].to_bytes(2, "little")
        for record, seed_symbol_index in appended_relocations:
            grown += record["offset"].to_bytes(4, "little")
            grown += seed_symbol_index.to_bytes(4, "little")
            grown += record["type"].to_bytes(2, "little")
        require(
            len(grown) == dp["relocation_count"] * 10,
            "rebuilt relocation table size does not match the donor count",
        )
        replacements.append(
            (
                sp["relocation_offset"],
                sp["relocation_offset"] + sp["relocation_count"] * 10,
                bytes(grown),
            )
        )
    total_delta = sum(
        (len(replacement) - (end - start) for start, end, replacement in replacements)
    )

    def shifted(pointer: int) -> int:
        return shifted_pointer(pointer, replacements)

    output = bytearray(_apply_replacements(seed_bytes, replacements))
    new_symbol_offset = shifted(seed.symbol_offset)
    output[8:12] = new_symbol_offset.to_bytes(4, "little")
    for section in seed.sections:
        header = 20 + (section["number"] - 1) * 40
        if section["number"] == sp["number"]:
            output[header + 16 : header + 20] = dp["raw_size"].to_bytes(4, "little")
            output[header + 34 : header + 36] = dp["line_count"].to_bytes(2, "little")
            if appended_relocations:
                output[header + 32 : header + 34] = dp["relocation_count"].to_bytes(2, "little")
        if reduced_debug_raw is not None and section["number"] == sd["number"]:
            output[header + 16 : header + 20] = len(expected_debug_raw).to_bytes(4, "little")
        for field, relative in (("raw_offset", 20), ("relocation_offset", 24), ("line_offset", 28)):
            pointer = shifted(section[field])
            if pointer != section[field]:
                output[header + relative : header + relative + 4] = pointer.to_bytes(4, "little")
    primary_relocation_output = shifted(sp["relocation_offset"])
    for index, (left, right) in enumerate(
        [] if appended_relocations else zip(spr, dpr, strict=True)
    ):
        at = primary_relocation_output + index * 10
        symbol_index = substitutions.get(index, left["symbol_index"])
        output[at : at + 4] = right["offset"].to_bytes(4, "little")
        output[at + 4 : at + 8] = symbol_index.to_bytes(4, "little")
        output[at + 8 : at + 10] = right["type"].to_bytes(2, "little")
    for symbol_index, item in seed.symbols.items():
        if item["type"] != 32 or item["aux_count"] < 1:
            continue
        auxiliary = coff_auxiliary(seed, symbol_index, item)
        line_pointer = int.from_bytes(auxiliary[8:12], "little")
        mapped = shifted(line_pointer) if line_pointer else line_pointer
        if mapped != line_pointer:
            at = new_symbol_offset + (symbol_index + 1) * 18
            output[at + 8 : at + 12] = mapped.to_bytes(4, "little")
    local_value_updates = 0
    for seed_index, donor_index in sorted(mapping.items()):
        value = donor.symbols[donor_index]["value"]
        if value != seed.symbols[seed_index]["value"]:
            local_value_updates += 1
        at = new_symbol_offset + seed_index * 18
        output[at + 8 : at + 12] = value.to_bytes(4, "little")
    donor_function_aux = coff_auxiliary(donor, donor_function_index, donor_function)
    require(
        int.from_bytes(donor_function_aux[4:8], "little") == dp["raw_size"],
        "donor Function Definition TotalSize is stale",
    )
    at = new_symbol_offset + (seed_function_index + 1) * 18
    output[at + 4 : at + 8] = dp["raw_size"].to_bytes(4, "little")
    seed_begin_index, seed_begin = _coff_marker(seed, ".bf", sp["number"])
    donor_begin_index, donor_begin = _coff_marker(donor, ".bf", dp["number"])
    seed_begin_aux = coff_auxiliary(seed, seed_begin_index, seed_begin)
    donor_begin_aux = coff_auxiliary(donor, donor_begin_index, donor_begin)
    require(
        seed_begin_aux[:4] == donor_begin_aux[:4]
        and seed_begin_aux[6:12] == donor_begin_aux[6:12]
        and (seed_begin_aux[16:] == donor_begin_aux[16:]),
        ".bf non-line metadata changed",
    )
    seed_end_index, seed_end = _coff_marker(seed, ".ef", sp["number"])
    donor_end_index, donor_end = _coff_marker(donor, ".ef", dp["number"])
    require(donor_end["value"] == dp["raw_size"], "donor .ef value is stale")
    seed_end_aux = coff_auxiliary(seed, seed_end_index, seed_end)
    donor_end_aux = coff_auxiliary(donor, donor_end_index, donor_end)
    require(
        seed_end_aux[:4] == donor_end_aux[:4] and seed_end_aux[6:] == donor_end_aux[6:],
        ".ef non-line metadata changed",
    )
    at = new_symbol_offset + seed_end_index * 18
    output[at + 8 : at + 12] = donor_end["value"].to_bytes(4, "little")
    seed_lf = [
        (index, symbol)
        for index, symbol in seed.symbols.items()
        if symbol["name"] == ".lf"
        and symbol["section"] == sp["number"]
        and (symbol["storage"] == 101)
    ]
    donor_lf = [
        (index, symbol)
        for index, symbol in donor.symbols.items()
        if symbol["name"] == ".lf"
        and symbol["section"] == dp["number"]
        and (symbol["storage"] == 101)
    ]
    require(len(seed_lf) == len(donor_lf) <= 1, "target .lf line-count markers differ in presence")
    if seed_lf:
        seed_lf_index, seed_lf_symbol = seed_lf[0]
        _, donor_lf_symbol = donor_lf[0]
        require(
            seed_lf_symbol["value"] == sp["line_count"]
            and donor_lf_symbol["value"] == dp["line_count"],
            ".lf line-count marker is stale",
        )
        at = new_symbol_offset + seed_lf_index * 18
        output[at + 8 : at + 12] = donor_lf_symbol["value"].to_bytes(4, "little")
    seed_section_index, _seed_section_sym = _coff_section_symbol(seed, sp)
    donor_section_index, donor_section_sym = _coff_section_symbol(donor, dp)
    at = new_symbol_offset + (seed_section_index + 1) * 18
    output[at : at + 18] = coff_auxiliary(donor, donor_section_index, donor_section_sym)
    if reduced_debug_raw is not None:
        debug_section_index, _ = _coff_section_symbol(seed, sd)
        aux_at = new_symbol_offset + (debug_section_index + 1) * 18
        output[aux_at : aux_at + 4] = len(expected_debug_raw).to_bytes(4, "little")
    debug_output = shifted(sd["raw_offset"])
    output[debug_output : debug_output + len(expected_debug_raw)] = expected_debug_raw
    if fpo_closure:
        fpo_output = shifted(sx["raw_offset"])
        output[fpo_output : fpo_output + len(donor_fpo)] = donor_fpo
    composed = _append_undefined_external_symbols(bytes(output), imported_symbols)
    total_delta += len(composed) - len(output)
    checked = CoffObject(composed)
    cp = checked.function_section(mangled)
    require(len(composed) == len(seed_bytes) + total_delta, "output file-size delta is wrong")
    require(coff_body(checked, cp) == donor_code, "output target body differs from donor")
    cx = _comdat_child(checked, cp, ".debug$F" if fpo_closure else ".xdata$x")
    cd = _comdat_child(checked, cp, ".debug$S")
    require(
        coff_body(checked, cx) == (donor_fpo if fpo_closure else coff_body(seed, sx)),
        "output xdata/FPO record differs from its policy source",
    )
    require(coff_body(checked, cd) == bytes(expected_debug_raw), "output debug$S policy differs")
    if reduced_debug_raw is not None:
        checked_debug_index, checked_debug_symbol = _coff_section_symbol(checked, cd)
        require(
            int.from_bytes(
                coff_auxiliary(checked, checked_debug_index, checked_debug_symbol)[:4], "little"
            )
            == cd["raw_size"]
            == len(expected_debug_raw),
            "output debug$S section symbol still claims the removed locals",
        )
    require(function_multiset(checked) == function_multiset(seed), "output function set changed")
    require(
        checked.symbol_count == seed.symbol_count + len(imported_symbols)
        and all(
            (
                checked.symbols[seed.symbol_count + index]["name"] == item[0]
                and checked.symbols[seed.symbol_count + index]["section"] == 0
                and (checked.symbols[seed.symbol_count + index]["value"] == 0)
                and (checked.symbols[seed.symbol_count + index]["type"] == item[1])
                and (checked.symbols[seed.symbol_count + index]["storage"] == item[2])
                for index, item in enumerate(imported_symbols)
            )
        ),
        "output imported undefined symbol set changed",
    )
    require(
        _coff_table_bytes(checked, cp, "lines") == donor_lines,
        "output line table differs from the normalized donor",
    )
    require(
        _coff_table_bytes(checked, cx, "relocations") == _coff_table_bytes(seed, sx, "relocations"),
        "output xdata relocation records changed",
    )
    require(
        _coff_table_bytes(checked, cd, "relocations") == _coff_table_bytes(seed, sd, "relocations"),
        "output debug$S relocation records changed",
    )
    for before, after in zip(seed.sections, checked.sections, strict=True):
        if before["number"] in allowed_sections:
            continue
        require(
            coff_body(seed, before) == coff_body(checked, after),
            f"non-target raw section changed: {before['number']}",
        )
        require(
            _coff_table_bytes(seed, before, "relocations")
            == _coff_table_bytes(checked, after, "relocations"),
            f"non-target relocation table changed: {before['number']}",
        )
        require(
            _coff_table_bytes(seed, before, "lines") == _coff_table_bytes(checked, after, "lines"),
            f"non-target line table changed: {before['number']}",
        )
    if divergent:
        composed_rows = detailed_relocations(checked, cp)
        require(
            len(composed_rows) == len(dpr), "composed relocation count differs from the donor's"
        )
        for left, right in zip(composed_rows, dpr, strict=True):
            if local_symbol_kind(right["target"]) is not None:
                require(
                    local_symbol_kind(left["target"]) == local_symbol_kind(right["target"]),
                    f"composed local relocation class changed at offset {left['offset']}",
                )
                continue
            left_base, left_sep, left_serial = left["target"].rpartition("$S")
            right_base, right_sep, right_serial = right["target"].rpartition("$S")
            if (
                left["target"] != right["target"]
                and left_sep
                and right_sep
                and left_base
                and (left_base == right_base)
                and left_serial.isdigit()
                and right_serial.isdigit()
            ):
                continue
            require(
                left["target"] == right["target"],
                f"composed relocation target {left['target']!r} is not the donor's {right['target']!r}",
            )
    return (
        composed,
        {
            "mangled": mangled,
            "splice_class": function["splice_class"] if divergent else "same_slot_resize",
            "section_number": cp["number"],
            "seed_length": sp["raw_size"],
            "donor_length": dp["raw_size"],
            "file_size_delta": total_delta,
            "linked_span": function["expected_linked_span"],
            "mapped_locals": len(mapping),
            "changed_local_values": local_value_updates,
            "substituted_relocations": len(substitutions),
            "imported_undefined_symbols": [item[0] for item in imported_symbols],
            "candidate_only": bool(divergent),
            **(
                {"debug_representation_delta": representation_detail}
                if representation_detail
                else {}
            ),
            **local_set_detail,
            **topology_detail,
            **semantic_detail,
        },
    )


def produce_reloc_divergent_candidate(
    seed_bytes: bytes, donor_bytes: bytes, function: dict[str, Any]
) -> tuple[bytes, dict[str, Any]]:
    """Splice a donor body whose EXTERNAL relocation target set diverges.

    Every `same_slot_resize` check applies except relocation-target equality.
    In its place stands a closed declarative relocation contract.  The final
    image still has to pass the sealed literal verifier before byte identity
    can be claimed.
    """
    require_payload_free_declaration(function, "relocation-divergent declaration")
    require(
        function.get("splice_class") == "retail_exact_reloc_divergent",
        "splice class is not retail_exact_reloc_divergent",
    )
    require(
        "target_source_refactor" not in function,
        "source-refactor function requires its source-proof composer",
    )
    return compose_same_slot_resize(
        seed_bytes,
        donor_bytes,
        function,
        declared_donor_extras=function.get("expected_donor_extra_functions") or None,
        declared_seed_only=function.get("expected_seed_only_functions") or None,
    )


def produce_source_refactor_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    seed_source: bytes,
    donor_source: bytes,
) -> tuple[bytes, dict[str, Any]]:
    """Install one relocation-divergent body from a proved source refactor.

    The source proof is deliberately inseparable from this entry point.  The
    ordinary relocation-divergent producer continues to reject these
    declarations, while this wrapper authenticates the complete source
    permutation before delegating to the same candidate-only COFF composer.
    """
    require_payload_free_declaration(function, "source-refactor declaration")
    require(
        function.get("splice_class") == "retail_exact_reloc_divergent"
        and "target_source_refactor" in function,
        "retail-exact source-refactor contract is missing",
    )
    source_detail = require_target_source_refactor_identity(
        seed_source,
        donor_source,
        function["target_source_refactor"],
        "retail-exact source-refactor proof",
    )
    composed, detail = compose_same_slot_resize(
        seed_bytes,
        donor_bytes,
        function,
        declared_donor_extras=function.get("expected_donor_extra_functions") or None,
        declared_seed_only=function.get("expected_seed_only_functions") or None,
    )
    return (composed, {**detail, **source_detail})


def produce_source_target_closure_candidate(
    seed_bytes: bytes,
    donor_bytes: bytes,
    function: dict[str, Any],
    seed_source: bytes,
    donor_source: bytes,
) -> tuple[bytes, dict[str, Any]]:
    """Extract one compiler-produced target from a source-closed donor.

    The producer receives no reference-image body.  The donor body is pinned
    as a fresh compiler product, the source window is proved byte-identical,
    and the source-target COFF topology contract accounts for every omitted
    or imported contribution.  Literal image equality remains solely the
    sealed verifier's responsibility.
    """
    require_payload_free_declaration(function, "source-target closure declaration")
    require(
        function.get("splice_class") == "retail_exact_source_target_closure",
        "splice class is not retail_exact_source_target_closure",
    )
    require(
        isinstance(function.get("target_source_range"), dict),
        "source-target closure source proof is missing",
    )
    source_detail = require_target_source_range_identity(
        seed_source,
        donor_source,
        function["target_source_range"],
        "source-target closure source proof",
    )
    composed, detail = compose_same_slot_resize(
        seed_bytes,
        donor_bytes,
        function,
        source_target_extract=True,
    )
    return composed, {**detail, **source_detail}
