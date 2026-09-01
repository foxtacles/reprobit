"""Focused tests for IA-32 PUSH scheduling and ESP displacement reseating."""

from __future__ import annotations

import unittest

import reprobit.classic.register_semantics as register_algorithms
import reprobit.classic.scheduling_apply as scheduling_apply
import reprobit.classic.scheduling_dependence as scheduling_dependence
from reprobit.binary import ByteIdentityError


def decode(body: bytes):
    instructions, offset = [], 0
    while offset < len(body):
        item = register_algorithms.decode_ia32_bijection_instruction(body, offset, "decode")
        instructions.append(item)
        offset += item["length"]
    return instructions


LOAD = bytes.fromhex("8b442418")
LEA = bytes.fromhex("8d542414")
PLAIN = bytes.fromhex("8b0a")
PUSH = bytes.fromhex("52")


class DerivationTest(unittest.TestCase):
    def test_a_push_moved_before_a_load_raises_its_displacement(self):
        body = LOAD + PUSH
        found = scheduling_dependence.ia32_schedule_stack_adjustments(
            body, decode(body), [1, 0], "w"
        )
        self.assertEqual(found, [[0, 3, 0x18, 0x1C]])

    def test_a_push_moved_after_a_load_lowers_its_displacement(self):
        body = PUSH + LOAD
        found = scheduling_dependence.ia32_schedule_stack_adjustments(
            body, decode(body), [1, 0], "w"
        )
        self.assertEqual(found, [[1, 4, 0x18, 0x14]])

    def test_a_lea_of_an_esp_address_is_adjusted_too(self):
        body = LEA + PUSH
        found = scheduling_dependence.ia32_schedule_stack_adjustments(
            body, decode(body), [1, 0], "w"
        )
        self.assertEqual(found, [[0, 3, 0x14, 0x18]])

    def test_no_push_means_no_adjustment(self):
        body = LOAD + PLAIN
        self.assertEqual(
            scheduling_dependence.ia32_schedule_stack_adjustments(body, decode(body), [1, 0], "w"),
            [],
        )

    def test_an_operand_that_does_not_cross_the_push_is_untouched(self):
        body = LOAD + PLAIN + PUSH
        self.assertEqual(
            scheduling_dependence.ia32_schedule_stack_adjustments(
                body, decode(body), [1, 0, 2], "w"
            ),
            [],
        )

    def test_a_displacement_that_would_overflow_its_field_refuses(self):
        body = bytes.fromhex("8b44247f") + PUSH
        with self.assertRaises(ByteIdentityError) as caught:
            scheduling_dependence.ia32_schedule_stack_adjustments(body, decode(body), [1, 0], "w")
        self.assertIn("would overflow", str(caught.exception))

    def test_an_esp_base_with_no_displacement_byte_refuses(self):
        body = bytes.fromhex("8b0424") + PUSH
        with self.assertRaises(ByteIdentityError) as caught:
            scheduling_dependence.ia32_schedule_stack_adjustments(body, decode(body), [1, 0], "w")
        self.assertIn("no displacement byte", str(caught.exception))


class ObligationTest(unittest.TestCase):
    def test_a_push_is_still_refused_without_a_declaration(self):
        body = LOAD + PUSH
        with self.assertRaises(ByteIdentityError) as caught:
            scheduling_dependence.ia32_schedule_dependence_edges(decode(body), "w")
        self.assertIn("a push shares the window", str(caught.exception))

    def test_a_negative_esp_displacement_refuses(self):
        body = bytes.fromhex("8b4424f8") + PUSH
        with self.assertRaises(ByteIdentityError) as caught:
            scheduling_dependence.ia32_schedule_dependence_edges(decode(body), "w", body, True)
        self.assertIn("below ESP", str(caught.exception))

    def test_the_esp_edge_is_discharged_for_an_adjusted_address(self):
        body = LOAD + PUSH
        _facts, edges = scheduling_dependence.ia32_schedule_dependence_edges(
            decode(body), "w", body, True
        )
        self.assertEqual(edges, [])

    def test_the_esp_edge_SURVIVES_when_esp_is_read_as_a_value(self):
        body = bytes.fromhex("8bc4") + PUSH
        _facts, edges = scheduling_dependence.ia32_schedule_dependence_edges(
            decode(body), "w", body, True
        )
        self.assertTrue(any("register_war" in edge[2] for edge in edges))

    def test_two_pushes_still_cannot_be_reordered(self):
        body = PUSH + PUSH
        _facts, edges = scheduling_dependence.ia32_schedule_dependence_edges(
            decode(body), "w", body, True
        )
        self.assertEqual([edge[:2] for edge in edges], [[0, 1]])


class ApplicationTest(unittest.TestCase):
    def test_the_image_carries_the_adjusted_displacement(self):
        body = LOAD + PUSH
        order = [1, 0]
        instructions = decode(body)
        stack = scheduling_dependence.ia32_schedule_stack_adjustments(
            body, instructions, order, "w"
        )
        _facts, edges = scheduling_dependence.ia32_schedule_dependence_edges(
            instructions, "w", body, True
        )
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [4, 1],
            "target_order": order,
            "expected_dependence_edges": edges,
            "expected_line_rows": [],
            "stack_adjustments": stack,
        }
        image, proof = scheduling_apply.apply_instruction_schedule(body, [window], frozenset(), "s")
        self.assertEqual(image, PUSH + bytes.fromhex("8b44241c"))
        self.assertEqual(proof["stack_adjustments"], [[0, 3, 0x18, 0x1C]])

    def test_a_declaration_that_disagrees_is_refused(self):
        body = LOAD + PUSH
        instructions = decode(body)
        _facts, edges = scheduling_dependence.ia32_schedule_dependence_edges(
            instructions, "w", body, True
        )
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [4, 1],
            "target_order": [1, 0],
            "expected_dependence_edges": edges,
            "expected_line_rows": [],
            "stack_adjustments": [[0, 3, 0x18, 0x20]],
        }
        with self.assertRaises(ByteIdentityError) as caught:
            scheduling_apply.apply_instruction_schedule(body, [window], frozenset(), "s")
        self.assertIn("differs from its declaration", str(caught.exception))
