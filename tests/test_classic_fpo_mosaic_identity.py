"""Fixture tests for the two FPO-mosaic identity requirements.

`require_ordinary_fpo_mosaic_identity` authenticates the `.debug$F`/`.debug$S`
closure of an instruction mosaic whose seed and donor are the same
translation unit in two declaration-carrier states: the two CodeView payloads
must be the same size and the FPO row identical.  `require_source_fpo_mosaic_identity`
admits a source refactor, whose seed and donor may carry separately pinned
CodeView payload sizes, tails and extra child relocations, while still
describing one procedure with one FPO row.

Both are exercised on a miniature classic-i386 COFF: one COMDAT `.text`
primary with the ordinary FPO closure, a `.drectve` linker payload, and the
child relocations a real compiler emits (`DIR32NB` naming the function from
the FPO row; `SECREL` and `SECTION` naming it from the S_LPROC32 record).
Every refusal message of both functions is pinned here so that the two can be
folded into one implementation without changing what a record is told.
"""

from __future__ import annotations

import copy
import struct
import unittest

import reprobit.classic.coff as coff_algorithms
import reprobit.classic.composition_fpo_identity as fpo_identity
import reprobit.classic.debug as debug_algorithms
import reprobit.classic.foundation as foundation
import reprobit.coff_format as coff_format
from reprobit.binary import ByteIdentityError

TARGET_SYMBOL = "?Read@Fixture@@QAEJPAVStorage@@@Z"
OTHER_SYMBOL = "?Other@@YAXXZ"
DIRECTIVE = b"-defaultlib:LIBCMT -defaultlib:OLDNAMES "
#    push ebx / push esi / xor esi,esi / mov eax,[esp+12] / mov [esp+24],esi /
#    lea ebx,[ebx+8] / mov [esp+28],esi / test eax,eax / je / xor eax,eax /
#    pop esi / pop ebx / ret
SEED_BODY = bytes.fromhex("535633f68b44240c897424188d5b088974241c85c0740233c05e5bc3")
# The donor state moves the load past the first store: same length, same FPO row.
DONOR_BODY = bytes.fromhex("535633f6897424188b44240c8d5b088974241c85c0740233c05e5bc3")
SIZE = len(SEED_BODY)
LINE_ROWS = ((0, 11), (8, 12))
ORDINARY_CONTEXT = "ordinary FPO instruction mosaic"
SOURCE_CONTEXT = "source FPO instruction mosaic"
EXTRA_RELOCATION_FIELDS = (
    "offset",
    "width",
    "type",
    "addend",
    "target",
    "target_section",
    "target_value",
    "target_type",
    "target_storage",
)


def _section_aux(length, relocations, lines, selection, associated=0, checksum=0):
    raw = bytearray(18)
    struct.pack_into("<IHHI", raw, 0, length, relocations, lines, checksum)
    struct.pack_into("<H", raw, 12, associated & 0xFFFF)
    raw[14] = selection
    struct.pack_into("<H", raw, 16, associated >> 16)
    return bytes(raw)


def _function_aux(total_size, line_pointer):
    return struct.pack("<IIII", 0, total_size, line_pointer, 0) + b"\0\0"


# One S_BPREL32 record: the local a refactored source may add or drop, which
# changes the CodeView tail and size without touching the procedure record.
LOCAL_RECORD = struct.pack("<HHiH", 2 + 4 + 2 + 1 + 1, 0x0200, -4, 0x0074) + b"\x01i"


def codeview_stream(size=SIZE, debug_start=2, debug_end=SIZE - 3, extra=b""):
    """One S_LPROC32 record (code length and debug range at +12), then
    `extra` records, then S_END."""
    proc = bytearray(33)
    struct.pack_into("<III", proc, 12, size, debug_start, debug_end)
    name = b"Fixture::Read"
    payload = bytes(proc) + bytes([len(name)]) + name
    return (
        struct.pack("<HH", len(payload) + 2, 0x0205)
        + payload
        + extra
        + struct.pack("<HH", 2, 0x0006)
    )


def make_coff(
    *,
    body=SEED_BODY,
    debug_stream=None,
    directive=DIRECTIVE,
    fpo_locals=2,
    debug_f_relocation_type=7,
    code_relocations=(),
    line_rows=LINE_ROWS,
    extra_debug_s_relocation=False,
    omit_debug_f=False,
):
    """One classic-i386 COFF whose target COMDAT carries the FPO closure.

    Relocations are `(offset, symbol name, type)`; the FPO row names the
    function with DIR32NB at 0, the S_LPROC32 record with SECREL at 28 and
    SECTION at 32.  `extra_debug_s_relocation` appends a SECTION relocation
    naming an external, the shape a source refactor may pin as an extra child
    relocation.  `omit_debug_f` drops the FPO child so the closure is not the
    exact pair.
    """
    stream = codeview_stream(len(body)) if debug_stream is None else debug_stream
    fpo = struct.pack("<IIIHBB", 0, len(body), fpo_locals, 1, 2, 0x10)
    debug_s_relocations = [(28, TARGET_SYMBOL, 11), (32, TARGET_SYMBOL, 10)]
    if extra_debug_s_relocation:
        debug_s_relocations.append((34, OTHER_SYMBOL, 10))
    sections = [
        {
            "name": ".text",
            "raw": bytes(body),
            "relocations": list(code_relocations),
            "line_rows": line_rows,
            "characteristics": 0x60501020,
        },
        {
            "name": ".debug$F",
            "raw": fpo,
            "relocations": [(0, TARGET_SYMBOL, debug_f_relocation_type)],
            "line_rows": (),
            "characteristics": 0x42101040,
        },
        {
            "name": ".debug$S",
            "raw": stream,
            "relocations": debug_s_relocations,
            "line_rows": (),
            "characteristics": 0x42101048,
        },
        {
            "name": ".drectve",
            "raw": directive,
            "relocations": [],
            "line_rows": (),
            "characteristics": 0x00100A00,
        },
    ]
    if omit_debug_f:
        del sections[1]
    numbers = {item["name"]: index + 1 for index, item in enumerate(sections)}
    # (name, value, section, type, storage, aux builder or None), in symbol order.
    symbol_plan = [
        (".text", 0, numbers[".text"], 0, 3, "text"),
        (TARGET_SYMBOL, 0, numbers[".text"], 0x20, 2, "function"),
    ]
    for name in (".debug$F", ".debug$S"):
        if name in numbers:
            symbol_plan.append((name, 0, numbers[name], 0, 3, "child"))
    symbol_plan.append((".drectve", 0, numbers[".drectve"], 0, 3, "directive"))
    symbol_plan.append((OTHER_SYMBOL, 0, 0, 0x20, 2, None))
    indices = {}
    cursor_index = 0
    for name, _, _, _, _, aux in symbol_plan:
        indices[name] = cursor_index
        cursor_index += 2 if aux is not None else 1
    cursor = 20 + len(sections) * 40
    payload = bytearray()
    laid_out = []
    for item in sections:
        raw_offset = cursor
        payload.extend(item["raw"])
        cursor += len(item["raw"])
        rows = [(offset, indices[name], kind) for offset, name, kind in item["relocations"]]
        table = b"".join(struct.pack("<IIH", *row) for row in rows)
        relocation_offset = cursor if table else 0
        payload.extend(table)
        cursor += len(table)
        lines = b""
        if item["line_rows"]:
            lines = struct.pack("<IH", indices[TARGET_SYMBOL], 0) + b"".join(
                struct.pack("<IH", offset, line) for offset, line in item["line_rows"]
            )
        line_offset = cursor if lines else 0
        payload.extend(lines)
        cursor += len(lines)
        laid_out.append(
            {
                **item,
                "rows": rows,
                "raw_offset": raw_offset,
                "relocation_offset": relocation_offset,
                "line_offset": line_offset,
                "line_count": len(lines) // 6,
            }
        )
    by_name = {item["name"]: item for item in laid_out}
    table = bytearray()
    count = 0
    strings = bytearray(b"\0\0\0\0")
    string_offsets = {}

    def encoded(name):
        raw = name.encode("ascii")
        if len(raw) <= 8:
            return raw.ljust(8, b"\0")
        if name not in string_offsets:
            string_offsets[name] = len(strings)
            strings.extend(raw + b"\0")
        return b"\0\0\0\0" + struct.pack("<I", string_offsets[name])

    for name, value, section, symbol_type, storage, aux_kind in symbol_plan:
        if aux_kind == "text":
            item = by_name[".text"]
            aux = _section_aux(len(item["raw"]), len(item["rows"]), item["line_count"], 2)
        elif aux_kind == "function":
            aux = _function_aux(len(by_name[".text"]["raw"]), by_name[".text"]["line_offset"])
        elif aux_kind == "child":
            item = by_name[name]
            aux = _section_aux(
                len(item["raw"]), len(item["rows"]), 0, 5, associated=numbers[".text"]
            )
        elif aux_kind == "directive":
            aux = _section_aux(len(by_name[".drectve"]["raw"]), 0, 0, 0)
        else:
            aux = None
        table.extend(
            encoded(name)
            + struct.pack("<IhHBB", value, section, symbol_type, storage, 0 if aux is None else 1)
        )
        count += 1
        if aux is not None:
            table.extend(aux)
            count += 1
    struct.pack_into("<I", strings, 0, len(strings))
    headers = bytearray()
    for item in laid_out:
        headers.extend(item["name"].encode("ascii").ljust(8, b"\0"))
        headers.extend(
            struct.pack(
                "<IIIIIIHHI",
                0,
                0,
                len(item["raw"]),
                item["raw_offset"],
                item["relocation_offset"],
                item["line_offset"],
                len(item["rows"]),
                item["line_count"],
                item["characteristics"],
            )
        )
    header = struct.pack("<HHIIIHH", 0x14C, len(laid_out), 0x1234, cursor, count, 0, 0)
    return bytes(header + headers + payload + table + strings)


def _child_pin(seed, sp, donor, dp, name, *, source):
    sha = foundation.sha256_bytes
    left = coff_algorithms._comdat_child(seed, sp, name)
    right = coff_algorithms._comdat_child(donor, dp, name)
    pin = {
        "section_number": left["number"],
        "relocation_count": left["relocation_count"],
        "line_count": left["line_count"],
        "characteristics": left["characteristics"],
        "selection": 5,
        "associated": sp["number"],
        "expected_seed_body_sha256": sha(coff_format.coff_body(seed, left)),
        "expected_donor_body_sha256": sha(coff_format.coff_body(donor, right)),
        "expected_seed_relocation_sha256": sha(
            coff_algorithms._coff_table_bytes(seed, left, "relocations")
        ),
        "expected_donor_relocation_sha256": sha(
            coff_algorithms._coff_table_bytes(donor, right, "relocations")
        ),
    }
    if source:
        pin["expected_seed_raw_size"] = left["raw_size"]
        pin["expected_donor_raw_size"] = right["raw_size"]
    else:
        pin["raw_size"] = left["raw_size"]
    return pin, left, right


def identity(seed, donor, *, source):
    """The identity pin the caller derives from an authenticated pair."""
    sha = foundation.sha256_bytes
    sp = seed.function_section(TARGET_SYMBOL)
    dp = donor.function_section(TARGET_SYMBOL)
    debug_f, seed_f, _ = _child_pin(seed, sp, donor, dp, ".debug$F", source=source)
    debug_s, seed_s, donor_s = _child_pin(seed, sp, donor, dp, ".debug$S", source=source)
    fpo = coff_format.coff_body(seed, seed_f)
    debug_f["expected_record"] = debug_algorithms.parse_fpo_data(
        fpo, expected_proc_size=sp["raw_size"]
    )
    stream = coff_format.coff_body(seed, seed_s)
    donor_stream = coff_format.coff_body(donor, donor_s)
    cb_proc, dbg_start, dbg_end = struct.unpack_from("<III", stream, 16)
    debug_s.update(
        {
            "expected_common_prefix_sha256": sha(stream[:28]),
            "expected_record_kind": stream[2:4].hex(),
            "expected_cb_proc": cb_proc,
            "expected_dbg_start": dbg_start,
            "expected_dbg_end": dbg_end,
        }
    )
    if source:
        debug_s["expected_seed_tail_sha256"] = sha(stream[28:])
        debug_s["expected_donor_tail_sha256"] = sha(donor_stream[28:])
        extra = coff_format.detailed_relocations(seed, seed_s)[2:]
        if extra:
            debug_s["expected_extra_relocations"] = [
                {field: row[field] for field in EXTRA_RELOCATION_FIELDS} for row in extra
            ]
    return {
        "expected_primary_characteristics": sp["characteristics"],
        "expected_primary_selection": coff_format.section_definitions(seed)[sp["number"]][
            "selection"
        ],
        "expected_function_count": sum(coff_algorithms.function_multiset(seed).values()),
        "expected_comdat_count": sum(
            coff_algorithms.comdat_primary_identity_multiset(seed).values()
        ),
        "expected_seed_line_sha256": sha(coff_algorithms._coff_table_bytes(seed, sp, "lines")),
        "expected_donor_line_sha256": sha(coff_algorithms._coff_table_bytes(donor, dp, "lines")),
        "debug_f": debug_f,
        "debug_s": debug_s,
    }


def require_ordinary(seed_bytes, donor_bytes, identity_donor=None, mutate=None):
    """Run the ordinary flavour; the pin is derived from `identity_donor`
    (default: the donor itself) so a structurally broken donor can be tried
    against the pin an intact one would have earned."""
    seed = coff_format.CoffObject(seed_bytes)
    donor = coff_format.CoffObject(donor_bytes)
    pinned = donor if identity_donor is None else coff_format.CoffObject(identity_donor)
    value = identity(seed, pinned, source=False)
    if mutate is not None:
        value = copy.deepcopy(value)
        mutate(value)
    return fpo_identity.require_ordinary_fpo_mosaic_identity(
        seed,
        seed.function_section(TARGET_SYMBOL),
        donor,
        donor.function_section(TARGET_SYMBOL),
        {"mangled": TARGET_SYMBOL},
        value,
        ORDINARY_CONTEXT,
    )


def require_source(seed_bytes, donor_bytes, identity_donor=None, mutate=None):
    seed = coff_format.CoffObject(seed_bytes)
    donor = coff_format.CoffObject(donor_bytes)
    pinned = donor if identity_donor is None else coff_format.CoffObject(identity_donor)
    value = identity(seed, pinned, source=True)
    if mutate is not None:
        value = copy.deepcopy(value)
        mutate(value)
    return fpo_identity.require_source_fpo_mosaic_identity(
        seed,
        seed.function_section(TARGET_SYMBOL),
        donor,
        donor.function_section(TARGET_SYMBOL),
        {"mangled": TARGET_SYMBOL},
        value,
        SOURCE_CONTEXT,
    )


def _set(*path, value):
    def mutate(identity_value):
        target = identity_value
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return mutate


def _bump(*path):
    def mutate(identity_value):
        target = identity_value
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] += 1

    return mutate


# (label, seed options, donor options, identity mutation, message after the context)
# Each row is refused by both functions with the same wording, save for the
# two rows whose messages name the flavour.
COMMON_REFUSALS = [
    ("primary characteristics", {}, {}, _bump("expected_primary_characteristics"),
     ": primary characteristics differ"),
    ("primary selection", {}, {}, _set("expected_primary_selection", value=1),
     ": primary COMDAT selection differs"),
    ("function census", {}, {}, _bump("expected_function_count"),
     ": seed function census differs"),
    ("COMDAT census", {}, {}, _bump("expected_comdat_count"),
     ": seed COMDAT census differs"),
    ("line-table pin", {}, {}, _set("expected_donor_line_sha256", value="00" * 32),
     ": target line-table pin differs"),
    ("closure", {}, {"omit_debug_f": True}, None,
     ": closure is not the exact FPO pair"),
    ("child geometry", {}, {}, _bump("debug_f", "section_number"),
     ": seed .debug$F geometry differs"),
    ("child body pin", {}, {}, _set("debug_s", "expected_donor_body_sha256", value="00" * 32),
     ": donor .debug$S body pin differs"),
    ("child relocation-table pin", {}, {},
     _set("debug_f", "expected_seed_relocation_sha256", value="00" * 32),
     ": seed .debug$F relocation-table pin differs"),
    ("child relocation semantics", {"debug_f_relocation_type": 6},
     {"debug_f_relocation_type": 6}, None,
     ": seed .debug$F semantic relocations differ"),
    ("parsed FPO record", {}, {}, _bump("debug_f", "expected_record", "cdwLocals"),
     ": parsed FPO record differs"),
    ("CodeView record kind", {}, {}, _set("debug_s", "expected_record_kind", value="0602"),
     ": CodeView procedure identity differs"),
    ("CodeView procedure range", {}, {}, _bump("debug_s", "expected_dbg_end"),
     ": seed CodeView procedure range differs"),
]  # fmt: skip


class SharedRefusalTests(unittest.TestCase):
    """Refusals both flavours state in the same words."""

    def test_the_ordinary_flavour_refuses_each_row(self):
        for label, seed_options, donor_options, mutate, message in COMMON_REFUSALS:
            with self.subTest(label):
                seed = make_coff(**seed_options)
                donor = make_coff(body=DONOR_BODY, **donor_options)
                intact = make_coff(body=DONOR_BODY, **{**donor_options, "omit_debug_f": False})
                with self.assertRaises(ByteIdentityError) as raised:
                    require_ordinary(seed, donor, identity_donor=intact, mutate=mutate)
                self.assertEqual(str(raised.exception), ORDINARY_CONTEXT + message)

    def test_the_source_flavour_refuses_each_row(self):
        for label, seed_options, donor_options, mutate, message in COMMON_REFUSALS:
            with self.subTest(label):
                seed = make_coff(**seed_options)
                donor = make_coff(body=DONOR_BODY, **donor_options)
                intact = make_coff(body=DONOR_BODY, **{**donor_options, "omit_debug_f": False})
                with self.assertRaises(ByteIdentityError) as raised:
                    require_source(seed, donor, identity_donor=intact, mutate=mutate)
                self.assertEqual(str(raised.exception), SOURCE_CONTEXT + message)

    def test_a_changed_linker_payload_is_named_by_its_flavour(self):
        seed = make_coff()
        donor = make_coff(body=DONOR_BODY, directive=DIRECTIVE + b"-defaultlib:USER32 ")
        with self.assertRaises(ByteIdentityError) as raised:
            require_ordinary(seed, donor)
        self.assertEqual(
            str(raised.exception),
            ORDINARY_CONTEXT + ": declaration carrier changed linker payload",
        )
        with self.assertRaises(ByteIdentityError) as raised:
            require_source(seed, donor)
        self.assertEqual(
            str(raised.exception), SOURCE_CONTEXT + ": source refactor changed linker payload"
        )

    def test_a_different_fpo_row_is_named_by_its_flavour(self):
        seed = make_coff()
        donor = make_coff(body=DONOR_BODY, fpo_locals=3)
        with self.assertRaises(ByteIdentityError) as raised:
            require_ordinary(seed, donor)
        self.assertEqual(
            str(raised.exception),
            ORDINARY_CONTEXT + ": FPO raw bytes differ between compiler states",
        )
        with self.assertRaises(ByteIdentityError) as raised:
            require_source(seed, donor)
        self.assertEqual(str(raised.exception), SOURCE_CONTEXT + ": FPO raw bytes differ")


class OrdinaryIdentityTests(unittest.TestCase):
    def test_a_declaration_carrier_pair_is_accepted(self):
        pairs = require_ordinary(make_coff(), make_coff(body=DONOR_BODY))
        self.assertEqual(
            [(left["number"], right["number"]) for left, right in pairs], [(2, 2), (3, 3)]
        )
        self.assertEqual([left["name"] for left, _ in pairs], [".debug$F", ".debug$S"])

    def test_the_seed_pin_governs_the_donor_geometry(self):
        """The pair shares one CodeView payload size; a donor tail of another
        length is a geometry refusal, not a separately pinned payload."""
        seed = make_coff()
        donor = make_coff(body=DONOR_BODY, debug_stream=codeview_stream(extra=LOCAL_RECORD))
        with self.assertRaises(ByteIdentityError) as raised:
            require_ordinary(seed, donor)
        self.assertEqual(
            str(raised.exception), ORDINARY_CONTEXT + ": donor .debug$S geometry differs"
        )

    def test_an_extra_child_relocation_is_refused(self):
        seed = make_coff(extra_debug_s_relocation=True)
        donor = make_coff(body=DONOR_BODY, extra_debug_s_relocation=True)
        with self.assertRaises(ByteIdentityError) as raised:
            require_ordinary(seed, donor)
        self.assertEqual(
            str(raised.exception), ORDINARY_CONTEXT + ": seed .debug$S semantic relocations differ"
        )


class SourceIdentityTests(unittest.TestCase):
    def test_separately_pinned_codeview_payloads_are_accepted(self):
        seed = make_coff(extra_debug_s_relocation=True)
        donor = make_coff(
            body=DONOR_BODY,
            debug_stream=codeview_stream(extra=LOCAL_RECORD),
            extra_debug_s_relocation=True,
        )
        pairs = require_source(seed, donor)
        self.assertEqual(
            [(left["number"], right["number"]) for left, right in pairs], [(2, 2), (3, 3)]
        )
        self.assertNotEqual(pairs[1][0]["raw_size"], pairs[1][1]["raw_size"])

    def test_the_extra_relocation_must_be_pinned(self):
        seed = make_coff(extra_debug_s_relocation=True)
        donor = make_coff(body=DONOR_BODY, extra_debug_s_relocation=True)
        with self.assertRaises(ByteIdentityError) as raised:
            require_source(
                seed, donor, mutate=lambda v: v["debug_s"].pop("expected_extra_relocations")
            )
        self.assertEqual(
            str(raised.exception), SOURCE_CONTEXT + ": seed .debug$S semantic relocations differ"
        )

    def test_the_extra_relocation_pin_is_checked_field_by_field(self):
        seed = make_coff(extra_debug_s_relocation=True)
        donor = make_coff(body=DONOR_BODY, extra_debug_s_relocation=True)
        for field in EXTRA_RELOCATION_FIELDS:
            with self.subTest(field), self.assertRaises(ByteIdentityError) as raised:
                require_source(
                    seed,
                    donor,
                    mutate=lambda v, field=field: v["debug_s"]["expected_extra_relocations"][
                        0
                    ].__setitem__(field, "changed"),
                )
            self.assertEqual(
                str(raised.exception),
                SOURCE_CONTEXT + ": seed .debug$S extra semantic relocations differ",
            )

    def test_each_codeview_tail_is_pinned(self):
        seed = make_coff()
        donor = make_coff(body=DONOR_BODY, debug_stream=codeview_stream(extra=LOCAL_RECORD))
        for key in ("expected_seed_tail_sha256", "expected_donor_tail_sha256"):
            with self.subTest(key), self.assertRaises(ByteIdentityError) as raised:
                require_source(seed, donor, mutate=_set("debug_s", key, value="00" * 32))
            self.assertEqual(
                str(raised.exception), SOURCE_CONTEXT + ": CodeView procedure identity differs"
            )

    def test_the_fpo_row_is_pinned_by_digest(self):
        seed = make_coff()
        donor = make_coff(body=DONOR_BODY)
        with self.assertRaises(ByteIdentityError) as raised:
            require_source(
                seed,
                donor,
                mutate=_set("debug_f", "expected_record", "raw_sha256", value="00" * 32),
            )
        self.assertEqual(str(raised.exception), SOURCE_CONTEXT + ": FPO raw bytes differ")

    def test_each_child_size_is_pinned_per_role(self):
        seed = make_coff()
        donor = make_coff(body=DONOR_BODY, debug_stream=codeview_stream(extra=LOCAL_RECORD))
        with self.assertRaises(ByteIdentityError) as raised:
            require_source(seed, donor, mutate=_bump("debug_s", "expected_donor_raw_size"))
        self.assertEqual(
            str(raised.exception), SOURCE_CONTEXT + ": donor .debug$S geometry differs"
        )


if __name__ == "__main__":
    unittest.main()
