"""End-to-end fixture for the self-permuting instruction mosaic producer.

`produce_instruction_mosaic_candidate` had no fixture that declared an
`instruction_self_permutation`; the branch was only ever exercised by the
downstream cold verify.  This module builds the ordinary-FPO mosaic class
from the FPO-identity fixture: one same-offset sequence range imports the
donor's exchanged pair of stores and loads, and one closed self-permutation
(`xor edi, edi` / `mov edx, [esp+14h]`) reverses two of the seed's own
instructions with the donor as witness.  The composed object and the proof
are pinned so the branch stays golden for later refactors.
"""

from __future__ import annotations

import copy
import unittest

from test_classic_fpo_mosaic_identity import TARGET_SYMBOL, identity, make_coff

import reprobit.classic.coff as coff_algorithms
import reprobit.classic.composition_mosaic as composition_mosaic
import reprobit.classic.debug as debug_algorithms
import reprobit.classic.foundation as foundation_algorithms
import reprobit.coff_format as coff_format
import reprobit.declaration_shapes as declaration_shapes
from reprobit.binary import ByteIdentityError
from reprobit.strict_json import canonical_json

sha = foundation_algorithms.sha256_bytes

PROLOGUE = bytes.fromhex("535633f6")  # push ebx / push esi / xor esi, esi
SEED_RANGE = bytes.fromhex("8b44240c89742418")  # mov eax, [esp+0c] / mov [esp+18], esi
DONOR_RANGE = bytes.fromhex("897424188b44240c")  # the same two, exchanged
XOR_ZERO = bytes.fromhex("33ff")  # xor edi, edi
STACK_LOAD = bytes.fromhex("8b542414")  # mov edx, [esp+14]
PAIR = XOR_ZERO + STACK_LOAD
EPILOGUE = bytes.fromhex("8d5b088974241c85c0740233c05e5bc3")
SEED_BODY = PROLOGUE + SEED_RANGE + PAIR + EPILOGUE
DONOR_BODY = PROLOGUE + DONOR_RANGE + PAIR + EPILOGUE
RANGE = (len(PROLOGUE), len(PROLOGUE) + len(SEED_RANGE))
WINDOW = (RANGE[1], RANGE[1] + len(PAIR))
MOSAIC = PROLOGUE + DONOR_RANGE + STACK_LOAD + XOR_ZERO + EPILOGUE
OVERLAP_MESSAGE = "instruction mosaic same-offset ranges overlap the self-permutation window"

GOLDEN_OBJECT_SHA256 = "963475b2034e8c1b996344e7291811c3d5da915ce9f4e13c7bed0840568235a0"
GOLDEN_PROOF_SHA256 = "691a24a0d09b40a30caa5ee5367a6e7d6e9a068d6b42b7c7054f36d29f3db748"
GOLDEN_PROOF = {
    "mangled": "?Read@Fixture@@QAEJPAVStorage@@@Z",
    "splice_class": "retail_exact_instruction_mosaic",
    "section_number": 1,
    "body_length": 34,
    "instruction_ranges": [
        {
            "start": 4,
            "end": 12,
            "donor": "d_primary",
            "seed_sha256": "4915ed61fed8122a54da71e438a7daa8372f6857d32253c41b775ce11791c911",
            "donor_sha256": "68879374b5728fea263e446c2fb57e2b08da1103861ca4d17a7b0323a836ef08",
        }
    ],
    "instruction_self_permutation": [
        {
            "target_start": 12,
            "target_end": 16,
            "donor_start": 14,
            "donor_end": 18,
            "sha256": "4690bb8b6070c1fb441cb3af8bbe43cb115df332762391a7968036816403aa09",
        },
        {
            "target_start": 16,
            "target_end": 18,
            "donor_start": 12,
            "donor_end": 14,
            "sha256": "1770ae2694dfffb5381d1db167ea14ea806e849f7c886fc876528fc8e197f9ce",
        },
    ],
    "body_changed_offsets": [4, 5, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17],
    "relocations": 0,
    "relocation_reseats": [],
    "line_count": 3,
    "closure": [".debug$F", ".debug$S"],
    "ordinary_fpo_identity": True,
    "source_fpo_identity": False,
    "code_relocation_renames": [],
    "closure_relocation_renames": {".debug$F": [], ".debug$S": []},
    "relocation_order": "ordinal",
    "candidate_only": True,
    "semantic_relocation_count": 0,
    "oracle_payload_bytes_read": 0,
}


def carrier():
    """A two-seat extern-run carrier whose identifiers the fixture never emits."""
    header = declaration_shapes.generate_extern_run("g_h", 2, 2).encode("ascii")
    seat = declaration_shapes.generate_extern_run("g_p", 2, 2).encode("ascii")
    return {
        "kind": "extern_run_pair_v1",
        "placement": "after_includes_and_eof_v1",
        "width": 2,
        "header_prefix": "g_h",
        "header_count": 2,
        "seat_prefix": "g_p",
        "seat_count": 2,
        "generated_declarations_sha256": sha(header + seat),
    }


def object_receipts(seed):
    functions = coff_algorithms.function_multiset(seed)
    comdats = coff_algorithms.comdat_primary_identity_multiset(seed)
    linker = debug_algorithms.linker_payload_multiset(seed)
    return {
        "expected_function_multiset_sha256": coff_algorithms.canonical_counter_receipt_sha256(
            functions
        ),
        "expected_comdat_multiset_sha256": coff_algorithms.canonical_counter_receipt_sha256(
            comdats
        ),
        "expected_section_shape_sha256": coff_algorithms.section_shape_receipt_sha256(seed),
        "expected_linker_payload_count": sum(linker.values()),
        "expected_linker_payload_sha256": coff_algorithms.canonical_counter_receipt_sha256(linker),
    }


def self_permutation(seed, *, seed_body=SEED_BODY, mosaic=MOSAIC):
    start, end = WINDOW
    return {
        "kind": "commuting_xor_zero_stack_load_v1",
        "source_start": start,
        "source_end": end,
        "target_start": start,
        "target_end": end,
        "source_instruction_lengths": [len(XOR_ZERO), len(STACK_LOAD)],
        "target_instruction_lengths": [len(STACK_LOAD), len(XOR_ZERO)],
        "moves": [
            {
                "target_start": start,
                "target_end": start + len(STACK_LOAD),
                "target_sha256": sha(STACK_LOAD),
                "donor_start": start + len(XOR_ZERO),
                "donor_end": end,
                "donor_sha256": sha(STACK_LOAD),
            },
            {
                "target_start": start + len(STACK_LOAD),
                "target_end": end,
                "target_sha256": sha(XOR_ZERO),
                "donor_start": start,
                "donor_end": start + len(XOR_ZERO),
                "donor_sha256": sha(XOR_ZERO),
            },
        ],
        "expected_changed_offsets": [
            index for index in range(len(seed_body)) if seed_body[index] != mosaic[index]
        ],
        **object_receipts(seed),
    }


def sequence_range(start, end, seed_body, donor_body, lengths):
    return {
        "kind": "same_offset_complete_x86_instruction_sequence_v1",
        "start": start,
        "end": end,
        "seed_sha256": sha(seed_body[start:end]),
        "donor_sha256": sha(donor_body[start:end]),
        "seed_instruction_lengths": list(lengths),
        "donor_instruction_lengths": list(lengths),
    }


def function_record(seed_bytes, donor_bytes):
    seed = coff_format.CoffObject(seed_bytes)
    donor = coff_format.CoffObject(donor_bytes)
    sp = seed.function_section(TARGET_SYMBOL)
    dp = donor.function_section(TARGET_SYMBOL)
    return {
        "mangled": TARGET_SYMBOL,
        "splice_class": "retail_exact_instruction_mosaic",
        "expected_section_number": sp["number"],
        "expected_section_count": len(seed.sections),
        "expected_body_length": sp["raw_size"],
        "expected_relocation_count": sp["relocation_count"],
        "expected_line_count": sp["line_count"],
        "expected_seed_body_sha256": sha(SEED_BODY),
        "expected_donor_body_sha256": sha(DONOR_BODY),
        "expected_body_sha256": sha(MOSAIC),
        "expected_seed_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
            seed, sp
        ),
        "expected_donor_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
            donor, dp
        ),
        "retail_oracle": {
            "image": "SAMPLE.DLL",
            "address": "0x100aa510",
            "verdict": "MATCH",
            "length": len(MOSAIC),
        },
        "retail_relocations": [],
        "instruction_ranges": [sequence_range(*RANGE, SEED_BODY, DONOR_BODY, (4, 4))],
        "ordinary_fpo_identity": identity(seed, donor, source=False),
        "instruction_self_permutation": self_permutation(seed),
        "same_function_source_identity": {"carrier": carrier()},
    }


def fixture():
    seed = make_coff(body=SEED_BODY)
    donor = make_coff(body=DONOR_BODY)
    return seed, donor, function_record(seed, donor)


def compose(seed, donor, record):
    return composition_mosaic.produce_instruction_mosaic_candidate(
        seed, donor, record, primary_donor_id="d_primary"
    )


class SelfPermutingMosaicTest(unittest.TestCase):
    """The producer end to end on a declaration that carries a self-permutation."""

    def setUp(self):
        self.seed, self.donor, self.record = fixture()

    def test_the_range_imports_the_donor_and_the_window_is_reversed(self):
        composed, detail = compose(self.seed, self.donor, self.record)
        checked = coff_format.CoffObject(composed)
        body = coff_format.coff_body(checked, checked.function_section(TARGET_SYMBOL))
        self.assertEqual(body, MOSAIC)
        self.assertEqual(len(composed), len(self.seed))
        self.assertEqual(
            detail["instruction_self_permutation"],
            [
                {
                    "target_start": WINDOW[0],
                    "target_end": WINDOW[0] + len(STACK_LOAD),
                    "donor_start": WINDOW[0] + len(XOR_ZERO),
                    "donor_end": WINDOW[1],
                    "sha256": sha(STACK_LOAD),
                },
                {
                    "target_start": WINDOW[0] + len(STACK_LOAD),
                    "target_end": WINDOW[1],
                    "donor_start": WINDOW[0],
                    "donor_end": WINDOW[0] + len(XOR_ZERO),
                    "sha256": sha(XOR_ZERO),
                },
            ],
        )
        self.assertEqual(
            detail["body_changed_offsets"],
            self.record["instruction_self_permutation"]["expected_changed_offsets"],
        )

    def test_the_composed_object_keeps_every_other_byte(self):
        composed, _detail = compose(self.seed, self.donor, self.record)
        seed = coff_format.CoffObject(self.seed)
        raw_offset = seed.function_section(TARGET_SYMBOL)["raw_offset"]
        changed = {index for index in range(len(composed)) if composed[index] != self.seed[index]}
        allowed = {raw_offset + offset for offset in range(*RANGE)} | {
            raw_offset + offset for offset in range(*WINDOW)
        }
        self.assertTrue(changed)
        self.assertLessEqual(changed, allowed)

    def test_the_golden_object_and_proof_are_unchanged(self):
        composed, detail = compose(self.seed, self.donor, self.record)
        self.assertEqual(sha(composed), GOLDEN_OBJECT_SHA256)
        self.assertEqual(detail, GOLDEN_PROOF)
        self.assertEqual(sha(canonical_json(detail)), GOLDEN_PROOF_SHA256)

    def test_the_producer_is_deterministic(self):
        first = compose(self.seed, self.donor, self.record)
        second = compose(*fixture())
        self.assertEqual(first, second)

    def test_a_range_inside_the_permutation_window_is_refused(self):
        # A range that ends past the window's start is admissible on its own
        # (its seed and donor bytes differ) and is refused only by the window
        # overlap check, which reads the validated permutation.
        record = copy.deepcopy(self.record)
        start, end = (RANGE[0] + 4, WINDOW[0] + len(XOR_ZERO))
        record["instruction_ranges"] = [
            sequence_range(start, end, SEED_BODY, DONOR_BODY, (4, len(XOR_ZERO)))
        ]
        with self.assertRaises(ByteIdentityError) as caught:
            compose(self.seed, self.donor, record)
        self.assertEqual(str(caught.exception), OVERLAP_MESSAGE)

    def test_a_changed_offset_set_that_omits_the_window_is_refused(self):
        record = copy.deepcopy(self.record)
        record["instruction_self_permutation"]["expected_changed_offsets"] = [
            offset
            for offset in record["instruction_self_permutation"]["expected_changed_offsets"]
            if offset < WINDOW[0]
        ]
        with self.assertRaises(ByteIdentityError) as caught:
            compose(self.seed, self.donor, record)
        self.assertEqual(
            str(caught.exception), "instruction self-permutation changed-offset set differs"
        )

    def test_a_witness_whose_window_differs_from_the_seed_is_refused(self):
        # The donor is a witness: its window must carry the seed's own pair.
        donor_body = DONOR_BODY[: WINDOW[0]] + STACK_LOAD + XOR_ZERO + DONOR_BODY[WINDOW[1] :]
        donor = make_coff(body=donor_body)
        record = copy.deepcopy(self.record)
        record["expected_donor_body_sha256"] = sha(donor_body)
        with self.assertRaises(ByteIdentityError) as caught:
            compose(self.seed, donor, record)
        self.assertEqual(
            str(caught.exception),
            "instruction self-permutation.moves[0] differs from the fresh donor artifact",
        )


if __name__ == "__main__":
    unittest.main()
