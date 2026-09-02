"""Tests for the mirrored equality-load exchange primitive.

`mov r, [ebp+A]; cmp [ebp+B], r; je/jne` tests A == B by way of r.  Loading
B and comparing A tests the same equality; the rewrite exchanges the two
displacement fields and proves that r and every flag but ZF are dead after
the branch.  The fixture is an EBP-framed body with one such test:

    0:  55              push ebp
    1:  8b ec           mov  ebp, esp
    3:  83 ec 08        sub  esp, 8
    6:  8b 4d f8        mov  ecx, [ebp-8]      <- THE LOAD
    9:  39 4d fc        cmp  [ebp-4], ecx      <- THE COMPARE
    12: 74 02           je   16                <- THE BRANCH
    14: 33 c0           xor  eax, eax
    16: 8b e5           mov  esp, ebp
    18: 5d              pop  ebp
    19: c3              ret
"""

from __future__ import annotations

import unittest

import reprobit.classic.register_semantics as register_semantics
import reprobit.classic.relational as relational_algorithms
import reprobit.classic.rewriting_certificates as rewriting_certificates
from reprobit.binary import ByteIdentityError

LOAD_AT, COMPARE_AT, BRANCH_AT = 6, 9, 12

BODY = bytes.fromhex(
    "55"  # push ebp
    "8bec"  # mov ebp, esp
    "83ec08"  # sub esp, 8
    "8b4df8"  # mov ecx, [ebp-8]        <- 6
    "394dfc"  # cmp [ebp-4], ecx        <- 9
    "7402"  # je 16                    <- 12
    "33c0"  # xor eax, eax             <- 14
    "8be5"  # mov esp, ebp             <- 16
    "5d"  # pop ebp
    "c3"  # ret
)

IMAGE = bytes.fromhex("558bec83ec088b4dfc394df8740233c08be55dc3")

EXCHANGES = [{"load_offset": LOAD_AT, "compare_offset": COMPARE_AT, "branch_offset": BRANCH_AT}]


def exchanged(body=BODY, exchanges=None, relocation_offsets=frozenset(), external=frozenset()):
    return relational_algorithms.apply_equality_load_exchange(
        body,
        exchanges if exchanges is not None else EXCHANGES,
        relocation_offsets,
        "fixture",
        {},
        None,
        external,
    )


class ExchangeTests(unittest.TestCase):
    def test_the_exchange_swaps_exactly_the_two_displacement_bytes(self):
        image, proof = exchanged()
        self.assertEqual(image, IMAGE)
        self.assertEqual(proof["kind"], relational_algorithms.EQUALITY_LOAD_EXCHANGE_KIND)
        self.assertEqual(proof["rewritten_offsets"], [8, 11])
        (site,) = proof["exchanges"]
        self.assertEqual(site["register"], "ecx")
        self.assertEqual(site["condition"], "e")
        self.assertEqual(site["displacement_size"], 1)
        self.assertEqual(site["seed_load_displacement"], -8)
        self.assertEqual(site["seed_compare_displacement"], -4)
        self.assertEqual(site["flags_live_out"], [])
        self.assertEqual(site["image_flags_live_out"], [])

    def test_the_exchange_is_an_involution(self):
        image, _ = exchanged()
        back, _ = exchanged(image)
        self.assertEqual(back, BODY)

    def test_a_disp32_pair_exchanges_all_eight_bytes(self):
        body = bytes.fromhex(
            "55"
            "8bec"
            "81ec00010000"
            "8b8d00ffffff"  # mov ecx, [ebp-256]      <- 9
            "398dfcfeffff"  # cmp [ebp-260], ecx      <- 15
            "7502"  # jne +2                  <- 21
            "33c0"
            "8be5"
            "5d"
            "c3"
        )
        image, proof = exchanged(
            body, [{"load_offset": 9, "compare_offset": 15, "branch_offset": 21}]
        )
        self.assertEqual(proof["rewritten_offsets"], [11, 12, 13, 14, 17, 18, 19, 20])
        self.assertEqual(image[11:15], body[17:21])
        self.assertEqual(image[17:21], body[11:15])
        self.assertEqual(proof["exchanges"][0]["condition"], "ne")

    def assertRefused(self, message, body=BODY, exchanges=None, **kwargs):
        with self.assertRaisesRegex(ByteIdentityError, message):
            exchanged(body, exchanges, **kwargs)

    def test_a_register_read_after_the_branch_is_refused(self):
        body = bytearray(BODY)
        body[14:16] = bytes.fromhex("8bc1")  # mov eax, ecx on the fall-through path
        self.assertRefused("ecx is live after the branch", bytes(body))

    def test_a_condition_that_reads_a_changed_flag_is_refused(self):
        body = bytearray(BODY)
        body[12] = 0x7C  # jl
        self.assertRefused("reads a flag the exchange changes", bytes(body))

    def test_a_flag_consumer_after_the_branch_is_refused(self):
        body = bytearray(BODY)
        body[14:16] = bytes.fromhex("1bc0")  # sbb eax, eax reads CF
        self.assertRefused("a successor of the branch reads", bytes(body))

    def test_mismatched_displacement_widths_are_refused(self):
        body = bytes.fromhex(
            "55"
            "8bec"
            "83ec08"
            "8b8df8ffffff"  # mov ecx, [ebp-8]  disp32   <- 6
            "394dfc"  # cmp [ebp-4], ecx  disp8    <- 12
            "7402"
            "33c0"
            "8be5"
            "5d"
            "c3"
        )
        self.assertRefused(
            "different encoded widths",
            body,
            [{"load_offset": 6, "compare_offset": 12, "branch_offset": 15}],
        )

    def test_the_same_slot_on_both_sides_is_refused(self):
        body = bytearray(BODY)
        body[11] = 0xF8
        self.assertRefused("the same slot", bytes(body))

    def test_a_relocation_on_an_exchanged_byte_is_refused(self):
        self.assertRefused("overlaps a relocation", relocation_offsets=frozenset({11}))

    def test_a_branch_into_the_compare_is_refused(self):
        body = bytes.fromhex(
            "55"
            "8bec"
            "83ec08"
            "7403"  # je 11   -> the compare, skipping the load   <- 6
            "8b4df8"  # mov ecx, [ebp-8]                            <- 8
            "394dfc"  # cmp [ebp-4], ecx                            <- 11
            "7402"
            "33c0"
            "8be5"
            "5d"
            "c3"
        )
        self.assertRefused(
            "the compare has a predecessor other than its load",
            body,
            [{"load_offset": 8, "compare_offset": 11, "branch_offset": 14}],
        )

    def test_a_non_frame_base_is_refused(self):
        body = bytearray(BODY)
        body[6:9] = bytes.fromhex("8b4e08")  # mov ecx, [esi+8]
        self.assertRefused("frame slot through EBP", bytes(body))

    def test_a_different_register_in_the_compare_is_refused(self):
        body = bytearray(BODY)
        body[9:12] = bytes.fromhex("3955fc")  # cmp [ebp-4], edx
        self.assertRefused("does not read the register the load defines", bytes(body))

    def test_non_consecutive_offsets_are_refused(self):
        self.assertRefused(
            "not consecutive",
            exchanges=[
                {"load_offset": 3, "compare_offset": COMPARE_AT, "branch_offset": BRANCH_AT}
            ],
        )


def donor_spec(**overrides):
    spec = {
        "kind": rewriting_certificates.DONOR_REWRITING_KIND,
        "equality_load_exchanges": [
            {
                "load_offset": LOAD_AT,
                "compare_offset": COMPARE_AT,
                "branch_offset": BRANCH_AT,
                "expected_rewritten_offsets": [8, 11],
            }
        ],
        "expected_instruction_count": len(
            register_semantics.decode_ia32_bijection_body(IMAGE, "fixture", {})
        ),
        "expected_changed_offsets": [8, 11],
        "expected_procedure_range": [len(BODY), 6, 16],
        "expected_code_symbol_references": [],
        "expected_external_entries": [],
        "authenticity_rationale": "One mirrored equality-load exchange applied to a donor "
        "compile of the same function; the register and the arithmetic flags are dead.",
    }
    spec.update(overrides)
    return spec


class DeclarationTests(unittest.TestCase):
    def test_the_reference_declaration_validates(self):
        normalized = rewriting_certificates.validate_donor_rewriting(
            donor_spec(), "test", len(BODY)
        )
        self.assertEqual(
            normalized["equality_load_exchanges"],
            [
                {
                    "load_offset": LOAD_AT,
                    "compare_offset": COMPARE_AT,
                    "branch_offset": BRANCH_AT,
                    "expected_rewritten_offsets": [8, 11],
                }
            ],
        )
        self.assertEqual(normalized["expected_changed_offsets"], [8, 11])

    def test_the_composed_declaration_accepts_the_key(self):
        spec = donor_spec(
            kind=rewriting_certificates.COMPOSED_REWRITING_KIND,
            expected_seed_debug_s_sha256="0" * 64,
            expected_image_debug_s_sha256="0" * 64,
        )
        normalized = rewriting_certificates.validate_composed_rewriting(
            spec, "test", len(BODY), lone_statement_ok=True
        )
        self.assertEqual(len(normalized["equality_load_exchanges"]), 1)

    def test_a_rewritten_byte_outside_the_exchange_is_refused(self):
        spec = donor_spec()
        spec["equality_load_exchanges"][0]["expected_rewritten_offsets"] = [8, 14]
        with self.assertRaisesRegex(ByteIdentityError, "expected_rewritten_offsets is invalid"):
            rewriting_certificates.validate_donor_rewriting(spec, "test", len(BODY))

    def test_an_omitted_changed_offset_is_refused(self):
        with self.assertRaisesRegex(ByteIdentityError, "omits a rewritten byte"):
            rewriting_certificates.validate_donor_rewriting(
                donor_spec(expected_changed_offsets=[8]), "test", len(BODY)
            )

    def test_an_unknown_key_is_refused(self):
        spec = donor_spec()
        spec["equality_load_exchanges"][0]["register"] = "ecx"
        with self.assertRaises(ByteIdentityError):
            rewriting_certificates.validate_donor_rewriting(spec, "test", len(BODY))

    def test_unordered_exchanges_are_refused(self):
        spec = donor_spec()
        spec["equality_load_exchanges"].append(dict(spec["equality_load_exchanges"][0]))
        with self.assertRaisesRegex(ByteIdentityError, "unsorted or overlapping"):
            rewriting_certificates.validate_donor_rewriting(spec, "test", len(BODY))


if __name__ == "__main__":
    unittest.main()
