"""End-to-end fixture for the quarantined simulated-elision PRODUCER.

`compose_retail_exact_simulated_elision` is the one classic producer allowed
to read reference-image bytes: each declared region of the seed's body is
replaced by the retail oracle's own bytes, but only after `_srr_simulate`
has executed both versions and found their exit states equal, and only if
the rebuilt body then equals the retail oracle under the relocation mask.
Its provenance is permanently ineligible for a clean verdict; a downstream
project's cold verify exercises it through its `legacy.oracle_install`
quarantines, and until this fixture existed that was its only guard.

The fixture is the smallest honest instance of the class.  The seed compiles
`mov eax, ecx` in the `8b /r` form; retail carries the same move in the
`89 /r` form.  Both encodings leave identical machine state, so the
simulator admits the exchange, the rebuilt body is retail's byte for byte,
and no branch, relocation or line row has to move:

    0:  53              push ebx
    1:  56              push esi
    2:  33 f6           xor  esi, esi
    4:  8b c1           mov  eax, ecx        <- region: retail writes 89 c8
    6:  8b 44 24 0c     mov  eax, [esp+12]
   10:  89 74 24 18     mov  [esp+24], esi
   14:  8d 5b 08        lea  ebx, [ebx+8]
   17:  89 74 24 1c     mov  [esp+28], esi
   21:  85 c0           test eax, eax
   23:  74 02           je   27
   25:  33 c0           xor  eax, eax
   27:  5e              pop  esi
   28:  5b              pop  ebx
   29:  c3              ret

The donor is the witness required to reproduce the seed's body.  Every byte
of the composed object and every field of the proof are pinned below as the
golden reference for the later candidate-recipe consolidation.
"""

from __future__ import annotations

import copy
import unittest

import test_classic_instruction_schedule_full as schedule

import reprobit.classic.coff as coff_algorithms
import reprobit.classic.composition_mosaic as composition_mosaic
import reprobit.classic.foundation as foundation_algorithms
import reprobit.classic.legacy_elision as legacy_elision
import reprobit.classic.register_semantics as register_semantics
import reprobit.coff_format as coff_format
from reprobit.binary import ByteIdentityError
from reprobit.strict_json import canonical_json

TARGET_SYMBOL = schedule.TARGET_SYMBOL
OTHER_SYMBOL = schedule.OTHER_SYMBOL
REGION = (4, 6)
SEED_MOVE = bytes.fromhex("8bc1")
RETAIL_MOVE = bytes.fromhex("89c8")
BODY = schedule.PROLOGUE + SEED_MOVE + schedule.WINDOW_SOURCE + schedule.EPILOGUE
IMAGE = schedule.PROLOGUE + RETAIL_MOVE + schedule.WINDOW_SOURCE + schedule.EPILOGUE
SIZE = len(BODY)
LINE_ROWS = ((0, 11), (6, 12))
PROCEDURE_RANGE = [SIZE, 2, SIZE - 5]

# Captured from the producer at the time this fixture was written.
GOLDEN_OBJECT_SHA256 = "7f42df5f09ea5726aaafd90d6049381f9d5160e6dd4b5bb41f0fcf395cdca298"
GOLDEN_PROOF_SHA256 = "3bd5c136b02efea7447ed18ba420b60800e1c584c8b7ad41977f501a923088c6"
GOLDEN_PROOF = {
    "branch_repairs": [],
    "branch_widenings": [],
    "candidate_only": True,
    "carried_code_symbols": [],
    "changed_local_values": 0,
    "donor_length": SIZE,
    "file_size_delta": 0,
    "imported_undefined_symbols": [],
    "linked_span": 32,
    "mangled": TARGET_SYMBOL,
    "mapped_locals": 0,
    "oracle_payload_bytes_read": 0,
    "procedure_range": PROCEDURE_RANGE,
    "relocation_reseat": [],
    "retail_exact": True,
    "section_number": 1,
    "seed_length": SIZE,
    "semantic_relocation_count": 0,
    "simulated_elision": [
        {
            "dead_registers": [],
            "dead_slots": [],
            "image_length": 2,
            "image_start": REGION[0],
            "region_end": REGION[1],
            "region_start": REGION[0],
        }
    ],
    "splice_class": legacy_elision.SIMULATED_ELISION_CLASS,
    "substituted_relocations": 0,
}


def make_coff(**overrides):
    options = {
        "body": BODY,
        "line_rows": LINE_ROWS,
        "debug_stream": schedule.codeview_stream(
            size=SIZE, debug_start=PROCEDURE_RANGE[1], debug_end=PROCEDURE_RANGE[2]
        ),
    }
    options.update(overrides)
    return schedule.make_coff(**options)


def region_declaration(**overrides):
    item = {
        "region_start": REGION[0],
        "region_end": REGION[1],
        "image_start": REGION[0],
        "image_length": REGION[1] - REGION[0],
    }
    item.update(overrides)
    return item


def elision_spec(**overrides):
    spec = {
        "kind": legacy_elision.SIMULATED_ELISION_KIND,
        "regions": [region_declaration()],
        "expected_external_entries": [],
        "expected_branch_repairs": [],
        "expected_branch_widenings": [],
        "expected_relocation_reseat": [],
        "expected_instruction_count": len(
            register_semantics.decode_ia32_bijection_body(BODY, "fixture", {})
        ),
        "expected_image_code_length": SIZE,
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
        "splice_class": legacy_elision.SIMULATED_ELISION_CLASS,
        "expected_section_number": sp["number"],
        "expected_donor_section_number": dp["number"],
        "expected_section_count": len(seed.sections),
        "expected_donor_section_count": len(donor.sections),
        "expected_function_count": sum(coff_algorithms.function_multiset(seed).values()),
        "expected_comdat_count": sum(
            coff_algorithms.comdat_primary_identity_multiset(seed).values()
        ),
        "expected_seed_length": sp["raw_size"],
        "expected_donor_length": len(image),
        "expected_linked_span": (len(image) + 15) // 16 * 16,
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
        "simulated_elision": elision_spec(),
    }
    record.update(overrides)
    return record


class ProducerEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.seed = make_coff()
        self.donor = make_coff()
        self.record = function_record(self.seed, self.donor, IMAGE)

    def compose(self, record=None, seed=None, donor=None, retail_body=IMAGE, oracles=None):
        return legacy_elision.compose_retail_exact_simulated_elision(
            seed or self.seed,
            donor or self.donor,
            record or self.record,
            retail_body,
            {} if oracles is None else oracles,
        )

    def test_the_elision_installs_retails_own_encoding(self):
        composed, detail = self.compose()
        checked = coff_format.CoffObject(composed)
        section = checked.function_section(TARGET_SYMBOL)
        self.assertEqual(bytes(coff_format.coff_body(checked, section)), IMAGE)
        self.assertIs(detail["retail_exact"], True)
        self.assertTrue(detail["candidate_only"])
        self.assertEqual(detail["splice_class"], legacy_elision.SIMULATED_ELISION_CLASS)
        self.assertEqual(detail["simulated_elision"], GOLDEN_PROOF["simulated_elision"])
        self.assertEqual(detail["procedure_range"], PROCEDURE_RANGE)
        self.assertEqual(detail["branch_repairs"], [])
        self.assertEqual(detail["relocation_reseat"], [])

    def test_the_composed_object_keeps_every_other_comdat(self):
        composed, _detail = self.compose()
        checked = coff_format.CoffObject(composed)
        seed = coff_format.CoffObject(self.seed)
        self.assertEqual(
            coff_algorithms.function_multiset(checked), coff_algorithms.function_multiset(seed)
        )
        self.assertEqual(len(checked.sections), len(seed.sections))
        self.assertEqual(len(composed), len(self.seed))
        other = checked.function_section(OTHER_SYMBOL)
        self.assertEqual(bytes(coff_format.coff_body(checked, other)), b"OTHER-FN")

    def test_the_golden_object_and_proof_are_unchanged(self):
        composed, detail = self.compose()
        self.assertEqual(foundation_algorithms.sha256_bytes(composed), GOLDEN_OBJECT_SHA256)
        self.assertEqual(detail, GOLDEN_PROOF)
        self.assertEqual(
            foundation_algorithms.sha256_bytes(canonical_json(detail)), GOLDEN_PROOF_SHA256
        )

    def test_the_producer_is_deterministic(self):
        first = self.compose()
        second = self.compose(record=function_record(make_coff(), make_coff(), IMAGE))
        self.assertEqual(first, second)

    def test_a_region_whose_versions_compute_different_state_is_refused(self):
        """The oracle never decides: `mov eax, edx` is refused whatever retail says."""
        other = (
            schedule.PROLOGUE + bytes.fromhex("8bc2") + schedule.WINDOW_SOURCE + schedule.EPILOGUE
        )
        record = function_record(self.seed, self.donor, other)
        with self.assertRaises(ByteIdentityError) as raised:
            self.compose(record=record, retail_body=other)
        self.assertEqual(
            str(raised.exception),
            "simulated-elision image region 0: the registers left differing ['eax'] "
            "are not the declared dead set []",
        )

    def test_a_differing_register_composes_when_it_is_declared_and_proved_dead(self):
        """`mov eax, edx` composes once EAX is declared dead: the next instruction
        overwrites it, so the bijection liveness proves the declaration."""
        other = (
            schedule.PROLOGUE + bytes.fromhex("8bc2") + schedule.WINDOW_SOURCE + schedule.EPILOGUE
        )
        record = function_record(self.seed, self.donor, other)
        record["simulated_elision"]["regions"][0]["dead_registers"] = ["eax"]
        composed, detail = self.compose(record=record, retail_body=other)
        checked = coff_format.CoffObject(composed)
        section = checked.function_section(TARGET_SYMBOL)
        self.assertEqual(bytes(coff_format.coff_body(checked, section)), other)
        self.assertEqual(detail["simulated_elision"][0]["dead_registers"], ["eax"])

    def test_a_declared_dead_register_that_is_live_at_the_exit_is_refused(self):
        """`mov ebx, ecx` leaves EBX differing, and `lea ebx, [ebx+8]` reads it."""
        other = (
            schedule.PROLOGUE + bytes.fromhex("8bd9") + schedule.WINDOW_SOURCE + schedule.EPILOGUE
        )
        record = function_record(self.seed, self.donor, other)
        record["simulated_elision"]["regions"][0]["dead_registers"] = ["eax", "ebx"]
        with self.assertRaises(ByteIdentityError) as raised:
            self.compose(record=record, retail_body=other)
        self.assertEqual(
            str(raised.exception),
            "simulated-elision image region 0: ebx is live on the region's exit edge "
            "(['ebx.h', 'ebx.l', 'ebx.u'])",
        )

    def test_a_retail_body_that_differs_outside_the_region_is_refused(self):
        retail = bytearray(IMAGE)
        retail[-2] ^= 0x01
        with self.assertRaises(ByteIdentityError) as raised:
            self.compose(retail_body=bytes(retail))
        self.assertEqual(
            str(raised.exception),
            "simulated-elision output is not retail-exact: 1 byte(s) differ under the "
            "relocation mask",
        )

    def test_a_witness_that_does_not_reproduce_the_seed_is_refused(self):
        donor = make_coff(body=IMAGE)
        record = function_record(self.seed, donor, IMAGE)
        with self.assertRaises(ByteIdentityError) as raised:
            self.compose(record=record, donor=donor)
        self.assertEqual(
            str(raised.exception),
            "simulated-elision witness does not reproduce the seed's body",
        )

    def test_a_wrong_image_pin_is_refused(self):
        record = copy.deepcopy(self.record)
        record["expected_body_sha256"] = "0" * 64
        with self.assertRaises(ByteIdentityError) as raised:
            self.compose(record=record)
        self.assertEqual(str(raised.exception), "simulated-elision image differs from its pin")

    def test_a_declaration_without_a_region_is_refused(self):
        record = copy.deepcopy(self.record)
        record["simulated_elision"]["regions"] = []
        with self.assertRaises(ByteIdentityError) as raised:
            self.compose(record=record)
        self.assertEqual(str(raised.exception), "simulated-elision image: no region is declared")

    def test_a_missing_retail_body_is_refused_before_anything_is_read(self):
        with self.assertRaises(ByteIdentityError) as raised:
            self.compose(retail_body=b"")
        self.assertEqual(str(raised.exception), "retail oracle body is missing")

    def test_another_splice_class_is_refused(self):
        record = copy.deepcopy(self.record)
        record["splice_class"] = "retail_exact_donor_rewriting"
        with self.assertRaises(ByteIdentityError) as raised:
            self.compose(record=record)
        self.assertEqual(
            str(raised.exception), "splice class is not retail_exact_simulated_elision"
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
