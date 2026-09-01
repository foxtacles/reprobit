"""A body carrying a repeated string operation must be PROVED or REFUSED.

The closed semantic decoder admits `rep movs`, `rep stos`, `rep(n)e scas` and
`rep(n)e cmps` through their own prefixed table, deliberately leaving the
BARE string opcodes outside the one-byte table so that a string operation
without its repeat prefix stays refused.

Both byte-rewriting classes re-decode their image and compare each
instruction's opcode against the pre-image's, taking a looser mask for the
`+r` forms that encode a register in the opcode's low three bits.  That
lookup consulted the one-byte table alone, so on a body containing `f3 a5`
it indexed a missing entry and `apply_register_bijection` and
`apply_web_recolour` raised `TypeError` -- neither a proof nor a refusal --
before either could reach its retail-equality check.

Six of the fourteen open sample rows carry a repeated string operation, so
admitting these forms into the decoder did not by itself let the classes run
on those bodies.  These tests pin that a string-carrying body reaches a
verdict, and that the verdict is the STRICTER one: a string form has no `+r`
field, so its opcode must match in full.
"""

from __future__ import annotations

import unittest

import reprobit.classic.register_bijection as register_algorithms
import reprobit.classic.register_semantics as register_semantics
import reprobit.classic.scheduling_web_recolour as scheduling_web_recolour
from reprobit.binary import ByteIdentityError

# 0: mov ebx, eax   2: xor ebx, ebx   4: rep movsd   6: ret
#
# EBX is redefined at 2 and EDX is never used, so sigma = {ebx <-> edx} is
# dead on entry to the region [0, 2) and on the single edge leaving it.  The
# `rep movsd` sits OUTSIDE the region and only has to survive the image's
# opcode comparison -- which is exactly the step that used to crash.
STRING_BODY = bytes([0x8B, 0xD8, 0x33, 0xDB, 0xF3, 0xA5, 0xC3])
PLAIN_BODY = bytes([0x8B, 0xD8, 0x33, 0xDB, 0x90, 0xC3])
SIGMA = {"ebx": "edx", "edx": "ebx"}


class RepeatedStringBodyTests(unittest.TestCase):
    def test_a_bijection_proves_a_body_that_carries_rep_movsd(self):
        image, detail = register_algorithms.apply_register_bijection(
            STRING_BODY, SIGMA, (0, 2), frozenset(), "probe", {}
        )
        self.assertEqual(detail["rewritten_offsets"], [1])
        self.assertEqual(image, bytes([0x8B, 0xD0, 0x33, 0xDB, 0xF3, 0xA5, 0xC3]))
        self.assertEqual(image[4:6], STRING_BODY[4:6])

    def test_the_string_operation_does_not_change_the_verdict(self):
        string_image, _ = register_algorithms.apply_register_bijection(
            STRING_BODY, SIGMA, (0, 2), frozenset(), "probe", {}
        )
        plain_image, _ = register_algorithms.apply_register_bijection(
            PLAIN_BODY, SIGMA, (0, 2), frozenset(), "probe", {}
        )
        self.assertEqual(string_image[:4], plain_image[:4])

    def test_a_web_recolour_reaches_a_verdict_on_a_string_body(self):
        """Not an accept -- a refusal carrying a message, which is a verdict."""
        with self.assertRaises(ByteIdentityError) as raised:
            scheduling_web_recolour.apply_web_recolour(
                STRING_BODY,
                [
                    {
                        "source_register": "ebx",
                        "image_register": "edx",
                        "definitions": [0],
                        "uses": [],
                    }
                ],
                frozenset(),
                "probe",
                {},
            )
        self.assertIn("probe", str(raised.exception))

    def test_a_sigma_meeting_a_string_register_is_still_refused(self):
        """The forms' frozen implicit registers keep their guarantee."""
        with self.assertRaises(ByteIdentityError) as raised:
            register_algorithms.apply_register_bijection(
                STRING_BODY, {"ecx": "edx", "edx": "ecx"}, (4, 6), frozenset(), "probe", {}
            )
        message = str(raised.exception)
        self.assertTrue("sigma cannot rewrite" in message or "live" in message, message)

    def test_the_bare_string_opcode_is_still_outside_the_one_byte_table(self):
        """The fix must not have widened the table it looks into."""
        self.assertIsNone(register_semantics._bijection_form_for(0xA5))
        self.assertIsNone(register_semantics._bijection_form_for(0xA4))
        self.assertIn((0xF3, 0xA5), register_semantics.IA32_BIJECTION_REPEATED_STRING_FORMS)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
