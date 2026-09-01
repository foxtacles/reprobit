"""End-to-end fixture for the donor-rewriting PRODUCER.

`retail_exact_donor_rewriting` is the composed-rewriting seam turned around:
the pre-image is the DONOR's body (a different compile of the same function,
possibly of a different length) and the seed contributes only the object the
rewritten body is installed into.  The producer applies the same three
primitives the composed fixture uses -- one topological window reordering,
one regional `{ecx <-> edx}` bijection and one mirrored comparison -- to the
donor's body, re-seats the donor's COFF line rows through the window's own
boundary map, proves debug fidelity on the re-lined donor, and installs the
result through the same-slot resize.

The fixture reuses the composed-rewriting body as the DONOR (38 bytes) and
the instruction-schedule body as the SEED (28 bytes), so the installation is
a real resize: the seed's 32-byte linked span becomes the donor's 48-byte
span.  The line row the donor carries at offset 8 sits inside the window; the
schedule moves that instruction to offset 4, so the installed line table --
and the window attribution the debug-fidelity obligation pins -- read
`[4, 12, 1]` where the composed certificate (which never moves the seed's
rows) reads `[8, 12, 3]`.

Every byte of the composed object and every field of the proof are pinned
below.  Those pins are the golden reference for the later candidate-recipe
consolidation: a refactor that changes any emitted byte or any proof field
must explain itself here first.
"""

from __future__ import annotations

import copy
import unittest

import test_classic_composed_rewriting_full as composed
import test_classic_instruction_schedule_full as schedule

import reprobit.classic.coff as coff_algorithms
import reprobit.classic.composition_mosaic as composition_mosaic
import reprobit.classic.foundation as foundation_algorithms
import reprobit.classic.register_semantics as register_semantics
import reprobit.classic.rewriting as rewriting_algorithms
import reprobit.classic.rewriting_certificates as rewriting_certificates
import reprobit.coff_format as coff_format
from reprobit.binary import ByteIdentityError
from reprobit.strict_json import canonical_json

TARGET_SYMBOL = composed.TARGET_SYMBOL
OTHER_SYMBOL = schedule.OTHER_SYMBOL
DONOR_BODY = composed.BODY
IMAGE = composed.IMAGE
SEED_BODY = schedule.BODY
WINDOW_LINE_ROWS = [[4, 12, 1]]

# Captured from the producer at the time this fixture was written.
GOLDEN_OBJECT_SHA256 = "8730196a002b54dcb52691f3ac90dfa612ce6f57436d3e6de8478559d8f5383b"
GOLDEN_PROOF_SHA256 = "d077f9ca8c4704d69d6e33054c5be3416130f786db8e01a522ecfd47e55d2460"
GOLDEN_CHANGED_OFFSETS = [4, 5, 7, 11, 12, 13, 14, 15, 16, 17, 18, 20, 22, 29, 31]
GOLDEN_PROOF = {
    "candidate_only": True,
    "changed_local_values": 0,
    "changed_offsets": GOLDEN_CHANGED_OFFSETS,
    "commutative_operand_forms": [],
    "debug_fidelity": {
        "code_symbol_references": [],
        "line_rows": 2,
        "procedure_range": [38, 2, 35],
        "window_line_rows": WINDOW_LINE_ROWS,
    },
    "donor_length": 38,
    "external_entries": [],
    "file_size_delta": 10,
    "fp_pointer_exchanges": [],
    "fp_sum_reassociation": [],
    "imported_undefined_symbols": [],
    "instruction_count": 18,
    "instruction_schedule": [
        {
            "dependence_edges": [],
            "end": 19,
            "instruction_count": 4,
            "memory_disambiguation": [
                {
                    "base": "esp",
                    "displacement": 12,
                    "instruction": 0,
                    "read": True,
                    "width": 4,
                    "write": False,
                },
                {
                    "base": "esp",
                    "displacement": 24,
                    "instruction": 1,
                    "read": False,
                    "width": 4,
                    "write": True,
                },
                {
                    "base": "esp",
                    "displacement": 28,
                    "instruction": 3,
                    "read": False,
                    "width": 4,
                    "write": True,
                },
            ],
            "relocation_reseat": [],
            "source_instruction_lengths": [4, 4, 3, 4],
            "stack_adjustments": [],
            "start": 4,
            "target_order": [1, 3, 0, 2],
        }
    ],
    "linked_span": 48,
    "mangled": TARGET_SYMBOL,
    "mapped_locals": 0,
    "oracle_payload_bytes_read": 0,
    "register_bijections": [
        {
            "mapping": {"ecx": "edx", "edx": "ecx"},
            "region": [19, 23],
            "region_instruction_count": 2,
            "rewritten_offsets": [20, 22],
        }
    ],
    "relational_form": [
        {
            "branch_offset": 31,
            "changed_flags": ["af", "cf", "of", "pf", "sf"],
            "compare_offset": 29,
            "flags_live_out": [],
            "image_compare_opcode": 57,
            "image_condition": "a",
            "image_flags_live_out": [],
            "seed_compare_opcode": 59,
            "seed_condition": "b",
        }
    ],
    "section_number": 1,
    "seed_length": 28,
    "semantic_relocation_count": 0,
    "simulated_region_rewrites": [],
    "slot_bijections": [],
    "splice_class": rewriting_algorithms.DONOR_REWRITING_CLASS,
    "substituted_relocations": 0,
    "x87_squared_addend_exchanges": [],
}


def make_seed(**overrides):
    """The seed: the schedule fixture's 28-byte compile of the same function."""
    options = {
        "body": SEED_BODY,
        "debug_stream": schedule.codeview_stream(
            size=len(SEED_BODY), debug_start=2, debug_end=len(SEED_BODY) - 5
        ),
    }
    options.update(overrides)
    return schedule.make_coff(**options)


def make_donor(**overrides):
    """The donor: the composed fixture's 38-byte compile, the pre-image."""
    return composed.make_coff(**overrides)


def bijection_declaration(**overrides):
    """The composed bijection without its composed-only debug$S claim."""
    item = {
        key: value
        for key, value in composed.bijection_declaration().items()
        if key != "debug_s_register_map"
    }
    item.update(overrides)
    return item


def donor_spec(**overrides):
    spec = {
        "kind": rewriting_certificates.DONOR_REWRITING_KIND,
        "windows": [composed.window_declaration(expected_line_rows=WINDOW_LINE_ROWS)],
        "register_bijections": [bijection_declaration()],
        "relational_sites": [composed.site_declaration()],
        "expected_instruction_count": len(
            register_semantics.decode_ia32_bijection_body(IMAGE, "fixture", {})
        ),
        "expected_changed_offsets": sorted(
            index for index in range(len(IMAGE)) if DONOR_BODY[index] != IMAGE[index]
        ),
        "expected_procedure_range": list(composed.PROCEDURE_RANGE),
        "expected_code_symbol_references": [],
        "expected_external_entries": [],
        "authenticity_rationale": "One topological window reordering, one regional register "
        "bijection and one mirrored comparison applied to a donor compile of the same "
        "function, whose line rows follow the reordered window.",
    }
    spec.update(overrides)
    return spec


def function_record(seed_bytes, donor_bytes, image, **overrides):
    seed = coff_format.CoffObject(seed_bytes)
    donor = coff_format.CoffObject(donor_bytes)
    sp = seed.function_section(TARGET_SYMBOL)
    dp = donor.function_section(TARGET_SYMBOL)
    record = {
        "mangled": TARGET_SYMBOL,
        "donor": "d_0123456789ab",
        "splice_class": rewriting_algorithms.DONOR_REWRITING_CLASS,
        "expected_section_number": sp["number"],
        "expected_section_count": len(seed.sections),
        "expected_donor_section_count": len(donor.sections),
        "expected_function_count": sum(coff_algorithms.function_multiset(seed).values()),
        "expected_comdat_count": sum(
            coff_algorithms.comdat_primary_identity_multiset(seed).values()
        ),
        "expected_seed_length": sp["raw_size"],
        "expected_donor_length": dp["raw_size"],
        "expected_linked_span": (dp["raw_size"] + 15) // 16 * 16,
        "expected_relocation_count": sp["relocation_count"],
        "expected_seed_line_count": sp["line_count"],
        "expected_donor_line_count": dp["line_count"],
        "expected_characteristics": sp["characteristics"],
        "expected_selection": coff_format.section_definitions(seed)[sp["number"]]["selection"],
        "expected_closure": [".debug$F", ".debug$S"],
        "expected_seed_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
            seed, sp
        ),
        "expected_donor_metadata_sha256": composition_mosaic.instruction_mosaic_metadata_sha256(
            donor, dp
        ),
        "expected_seed_body_sha256": foundation_algorithms.sha256_bytes(
            coff_format.coff_body(seed, sp)
        ),
        "expected_donor_body_sha256": foundation_algorithms.sha256_bytes(
            coff_format.coff_body(donor, dp)
        ),
        "expected_body_sha256": foundation_algorithms.sha256_bytes(image),
        "retail_oracle": {
            "image": "SAMPLE.DLL",
            "address": f"0x{schedule.RETAIL_ADDRESS:08x}",
            "verdict": "MATCH",
            "length": len(image),
        },
        "retail_relocations": [],
        "donor_rewriting": donor_spec(),
    }
    record.update(overrides)
    return record


class DeclarationTests(unittest.TestCase):
    """The fixture's declaration is a valid donor-rewriting certificate."""

    def test_the_reference_declaration_validates(self):
        normalized = rewriting_certificates.validate_donor_rewriting(
            donor_spec(), "test", len(DONOR_BODY)
        )
        self.assertEqual(len(normalized["windows"]), 1)
        self.assertEqual(len(normalized["register_bijections"]), 1)
        self.assertEqual(len(normalized["relational_sites"]), 1)
        self.assertEqual(normalized["expected_changed_offsets"], GOLDEN_CHANGED_OFFSETS)

    def test_a_composed_only_debug_claim_is_refused(self):
        """The donor class re-derives no S_REGISTER claim; the key is not its schema."""
        spec = donor_spec(register_bijections=[composed.bijection_declaration()])
        with self.assertRaises(ByteIdentityError) as raised:
            rewriting_certificates.validate_donor_rewriting(spec, "test", len(DONOR_BODY))
        self.assertIn("register_bijections[0] schema differs", str(raised.exception))
        self.assertIn("debug_s_register_map", str(raised.exception))


class ProducerEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.seed = make_seed()
        self.donor = make_donor()
        self.record = function_record(self.seed, self.donor, IMAGE)

    def produce(self, record=None, seed=None, donor=None):
        return rewriting_algorithms.produce_donor_rewriting_candidate(
            seed or self.seed, donor or self.donor, record or self.record
        )

    def test_the_certificate_produces_the_declared_candidate(self):
        composed_bytes, detail = self.produce()
        checked = coff_format.CoffObject(composed_bytes)
        section = checked.function_section(TARGET_SYMBOL)
        self.assertEqual(bytes(coff_format.coff_body(checked, section)), IMAGE)
        self.assertEqual(detail["splice_class"], rewriting_algorithms.DONOR_REWRITING_CLASS)
        self.assertTrue(detail["candidate_only"])
        self.assertEqual((detail["seed_length"], detail["donor_length"]), (28, 38))
        self.assertEqual(detail["linked_span"], 48)
        self.assertEqual(detail["file_size_delta"], 10)
        self.assertEqual(len(detail["instruction_schedule"]), 1)
        self.assertEqual(len(detail["register_bijections"]), 1)
        self.assertEqual(len(detail["relational_form"]), 1)

    def test_the_installed_line_rows_follow_the_reordered_window(self):
        composed_bytes, detail = self.produce()
        checked = coff_format.CoffObject(composed_bytes)
        section = checked.function_section(TARGET_SYMBOL)
        lines = coff_algorithms._coff_table_bytes(checked, section, "lines")
        rows = [
            (
                int.from_bytes(lines[at : at + 4], "little"),
                int.from_bytes(lines[at + 4 : at + 6], "little"),
            )
            for at in range(6, len(lines), 6)
        ]
        self.assertEqual(rows, [(0, 11), (4, 12)])
        self.assertEqual(detail["debug_fidelity"]["window_line_rows"], WINDOW_LINE_ROWS)
        self.assertEqual(detail["debug_fidelity"]["procedure_range"], [38, 2, 35])

    def test_the_composed_object_keeps_every_other_comdat(self):
        composed_bytes, _detail = self.produce()
        checked = coff_format.CoffObject(composed_bytes)
        seed = coff_format.CoffObject(self.seed)
        self.assertEqual(
            coff_algorithms.function_multiset(checked), coff_algorithms.function_multiset(seed)
        )
        self.assertEqual(len(checked.sections), len(seed.sections))
        other = checked.function_section(OTHER_SYMBOL)
        self.assertEqual(bytes(coff_format.coff_body(checked, other)), b"OTHER-FN")

    def test_the_golden_object_and_proof_are_unchanged(self):
        composed_bytes, detail = self.produce()
        self.assertEqual(foundation_algorithms.sha256_bytes(composed_bytes), GOLDEN_OBJECT_SHA256)
        self.assertEqual(detail, GOLDEN_PROOF)
        self.assertEqual(
            foundation_algorithms.sha256_bytes(canonical_json(detail)), GOLDEN_PROOF_SHA256
        )

    def test_the_producer_is_deterministic(self):
        first = self.produce()
        second = self.produce(record=function_record(make_seed(), make_donor(), IMAGE))
        self.assertEqual(first, second)

    def test_candidate_api_refuses_a_literal_oracle_argument(self):
        other = bytearray(IMAGE)
        other[-2] ^= 0x01
        with self.assertRaises(TypeError):
            rewriting_algorithms.produce_donor_rewriting_candidate(
                self.seed, self.donor, self.record, bytes(other)
            )

    def test_a_declaration_that_moves_nothing_is_refused(self):
        record = copy.deepcopy(self.record)
        record["donor_rewriting"].update(windows=[], register_bijections=[], relational_sites=[])
        with self.assertRaises(ByteIdentityError) as raised:
            self.produce(record=record)
        self.assertEqual(
            str(raised.exception), "donor-rewriting image does not move the donor body"
        )

    def test_a_bijection_whose_rewrite_set_differs_is_refused(self):
        record = copy.deepcopy(self.record)
        record["donor_rewriting"]["register_bijections"][0]["expected_rewritten_offsets"] = [20]
        with self.assertRaises(ByteIdentityError) as raised:
            self.produce(record=record)
        self.assertEqual(
            str(raised.exception),
            "donor-rewriting bijection 0 rewrote a different byte set from its declaration",
        )

    def test_the_composed_line_attribution_is_refused_here(self):
        """The donor's rows move with the window; the seed-anchored attribution does not fit."""
        record = copy.deepcopy(self.record)
        record["donor_rewriting"]["windows"][0]["expected_line_rows"] = [[8, 12, 3]]
        with self.assertRaises(ByteIdentityError) as raised:
            self.produce(record=record)
        self.assertEqual(
            str(raised.exception),
            "donor-rewriting debug fidelity: the line rows inside window 0x4 differ "
            "from their declaration",
        )

    def test_a_wrong_image_pin_is_refused(self):
        record = copy.deepcopy(self.record)
        record["expected_body_sha256"] = "0" * 64
        with self.assertRaises(ByteIdentityError) as raised:
            self.produce(record=record)
        self.assertEqual(str(raised.exception), "donor-rewriting image differs from its pin")

    def test_a_changed_donor_length_pin_is_refused(self):
        record = copy.deepcopy(self.record)
        record["expected_donor_length"] = len(IMAGE) + 1
        with self.assertRaises(ByteIdentityError) as raised:
            self.produce(record=record)
        self.assertEqual(str(raised.exception), "donor-rewriting target header/count pins changed")

    def test_a_donor_that_differs_from_its_pin_is_refused(self):
        other = bytearray(DONOR_BODY)
        other[-2] ^= 0x01
        with self.assertRaises(ByteIdentityError) as raised:
            self.produce(donor=make_donor(body=bytes(other)))
        self.assertEqual(
            str(raised.exception), "donor-rewriting seed/donor body differs from its pin"
        )

    def test_a_declared_extra_donor_function_that_is_absent_is_refused(self):
        record = copy.deepcopy(self.record)
        record["expected_donor_extra_functions"] = ["?Extra@@YAXXZ"]
        with self.assertRaises(ByteIdentityError) as raised:
            self.produce(record=record)
        self.assertEqual(
            str(raised.exception),
            "donor-rewriting donor function set differs from its declared extras",
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
