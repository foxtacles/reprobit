"""Authenticity and integration tests for the IA-32 stack-frontier theorem.

The theorem may discharge only a crossed register-PUSH/explicit-memory edge,
after proving its exact compiler scope, local taint, rebase, and dependence DAG.
It is a compiler-output theorem, not a whole-body numeric pointer proof.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

import reprobit.classic.register_semantics as register_algorithms
import reprobit.classic.scheduling as schedule_algorithms
import reprobit.classic.stack_frontier_balance as frontier_balance
from reprobit.binary import ByteIdentityError
from reprobit.classic.compiler_identity import (
    Msvc420CompilerIdentity,
    issue_msvc420_compiler_identity,
)
from reprobit.classic.stack_frontier_foundation import (
    AffineState,
    address_form,
    ancestors,
    frame_floor,
    msvc420_direct_cdecl_call,
    predecessors,
    stack_change,
)
from reprobit.classic.stack_frontier_fpo import transfer_affines
from reprobit.model import Digest
from reprobit.schema import LockedTool, MsvcRelease, ToolchainLock, ToolchainProfileSource


def decode(body: bytes):
    instructions, offset = [], 0
    while offset < len(body):
        item = register_algorithms.decode_ia32_bijection_instruction(body, offset, "decode")
        instructions.append(item)
        offset += item["length"]
    return instructions


# mov eax,[esp+0x18] / lea edx,[esp+0x14] / mov ecx,[edx] / push edx
LOAD = bytes.fromhex("8b442418")
LEA = bytes.fromhex("8d542414")
PLAIN = bytes.fromhex("8b0a")
PUSH = bytes.fromhex("52")
FRAME_LOAD = bytes.fromhex("8b45ec")  # mov eax,[ebp-0x14]
STACK_FRONTIER = schedule_algorithms.IA32_SCHEDULE_STACK_FRONTIER_THEOREM


def canonical_compiler_identity() -> Msvc420CompilerIdentity:
    tools = (
        (
            "bin/CL.EXE",
            37_888,
            "c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f",
            ("compiler",),
        ),
        (
            "bin/C1XX.EXE",
            793_088,
            "9e0782ec157b30a387ca855374bc4c1b8a605dfb12364425497ba431541a5bf9",
            ("runtime",),
        ),
        (
            "bin/C2.EXE",
            549_888,
            "2aa1fcace0779531b3ec80b730663acd98f181aed3cdff51366440c602b724b5",
            ("runtime",),
        ),
    )
    lock = ToolchainLock(
        schema_version=3,
        adapter="classic-msvc",
        profile="msvc_4_2",
        release=MsvcRelease.V4_2,
        profile_sources=(
            ToolchainProfileSource(
                repository="https://github.com/archaic-msvc/msvc420.git",
                revision="b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50",
                paths=("bin/C1XX.EXE", "bin/C2.EXE", "bin/CL.EXE"),
            ),
        ),
        tools=tuple(
            LockedTool(
                id=f"compiler-{index}",
                path=path,
                size=size,
                digest=Digest(value=digest),
                roles=roles,
            )
            for index, (path, size, digest, roles) in enumerate(tools)
        ),
    )
    identity = issue_msvc420_compiler_identity(lock)
    assert identity is not None
    return identity


COMPILER_IDENTITY = canonical_compiler_identity()
EXTERNAL_CALL = {4: {"width": 4, "target": "?Probe@@YAXXZ"}}
EXTERNAL_CALL_BYTES = frozenset(range(4, 8))


def stack_frontier_window(body: bytes, order: list[int], *, theorem: str = STACK_FRONTIER):
    instructions = decode(body)
    facts, strict = schedule_algorithms.ia32_schedule_dependence_edges(
        instructions, "w", body, False
    )
    edges, _receipt = schedule_algorithms._ia32_schedule_stack_frontier_projection(
        instructions,
        facts,
        strict,
        order,
        theorem,
        body,
        False,
        COMPILER_IDENTITY,
        "w",
    )
    return {
        "start": 0,
        "end": len(body),
        "source_instruction_lengths": [item["length"] for item in instructions],
        "target_order": order,
        "expected_dependence_edges": edges,
        "expected_line_rows": [],
        "stack_frontier_theorem": theorem,
    }


def full_stack_frontier_window(body: bytes, start: int, end: int, order: list[int]):
    inside = [item for item in decode(body) if start <= item["offset"] < end]
    facts, strict = schedule_algorithms.ia32_schedule_dependence_edges(inside, "w", body, False)
    edges, _receipt = schedule_algorithms._ia32_schedule_stack_frontier_projection(
        inside,
        facts,
        strict,
        order,
        STACK_FRONTIER,
        body,
        False,
        COMPILER_IDENTITY,
        "w",
    )
    return {
        "start": start,
        "end": end,
        "source_instruction_lengths": [item["length"] for item in inside],
        "target_order": order,
        "expected_dependence_edges": edges,
        "expected_line_rows": [],
        "stack_frontier_theorem": STACK_FRONTIER,
    }


class StackFrontierProjectionTest(unittest.TestCase):
    def test_a_register_push_implicitly_conflicts_with_unknown_explicit_memory(self):
        body = PUSH + FRAME_LOAD
        _facts, edges = schedule_algorithms.ia32_schedule_dependence_edges(decode(body), "w", body)
        self.assertEqual(edges, [[0, 1, ["memory"]]])
        with self.assertRaises(ByteIdentityError) as caught:
            schedule_algorithms.require_topological_instruction_order(2, edges, [1, 0], "w")
        self.assertIn("dependence DAG forbids", str(caught.exception))

    def test_stack_frontier_keeps_register_reasons(self):
        # The load writes EDX, whose old value PUSH consumes.  The compiler
        # stack theorem removes only the implicit-store alias edge.
        body = PUSH + bytes.fromhex("8b55ec")
        instructions = decode(body)
        facts, strict = schedule_algorithms.ia32_schedule_dependence_edges(instructions, "w", body)
        edges, _receipt = schedule_algorithms._ia32_schedule_stack_frontier_projection(
            instructions,
            facts,
            strict,
            [1, 0],
            STACK_FRONTIER,
            body,
            False,
            COMPILER_IDENTITY,
            "w",
        )
        self.assertEqual(edges, [[0, 1, ["register_war"]]])

    def test_stack_frontier_keeps_explicit_memory_edges(self):
        body = PUSH + bytes.fromhex("8945ec") + bytes.fromhex("8b0e")
        instructions = decode(body)
        facts, strict = schedule_algorithms.ia32_schedule_dependence_edges(instructions, "w", body)
        edges, _receipt = schedule_algorithms._ia32_schedule_stack_frontier_projection(
            instructions,
            facts,
            strict,
            [1, 0, 2],
            STACK_FRONTIER,
            body,
            False,
            COMPILER_IDENTITY,
            "w",
        )
        self.assertIn([1, 2, ["memory"]], edges)

    def test_stack_frontier_never_projects_an_explicit_esp_alias(self):
        body = PUSH + bytes.fromhex("8b0424")  # push edx / mov eax,[esp]
        facts, strict = schedule_algorithms.ia32_schedule_dependence_edges(
            decode(body), "w", body, True
        )
        self.assertEqual(strict, [[0, 1, ["memory", "register_raw"]]])
        self.assertIsNone(schedule_algorithms._ia32_schedule_stack_frontier_pair(0, 1, facts))


class BoundaryAuthenticityTest(unittest.TestCase):
    def test_pop_esp_and_negative_sign_extended_adjustments_are_unresolved(self):
        for body in (bytes.fromhex("5c"), bytes.fromhex("83ecfc"), bytes.fromhex("83c4fc")):
            with self.subTest(body=body.hex()):
                self.assertIsNone(stack_change(body, decode(body)[0]))

    def test_fs_and_gs_memory_are_not_numeric_stack_addresses(self):
        for body in (bytes.fromhex("648b00"), bytes.fromhex("658b00")):
            with self.subTest(body=body.hex()):
                self.assertIsNone(address_form(body, decode(body)[0]))

    def test_push_seat_and_unresolved_write_kill_private_slot_facts(self):
        pointer = {40: frozenset({7})}
        state = AffineState({}, {-4: pointer, 12: pointer})
        push = bytes.fromhex("52")
        after_push = transfer_affines(push, decode(push)[0], state, 0, "w")
        self.assertNotIn(-4, after_push.slots)
        unknown_store = bytes.fromhex("8910")  # mov [eax],edx; EAX is unresolved
        after_store = transfer_affines(unknown_store, decode(unknown_store)[0], after_push, 0, "w")
        self.assertEqual(after_store.slots, {})

    def test_materializing_a_private_slot_address_invalidates_its_fact(self):
        body = bytes.fromhex("8d442410")
        state = AffineState({}, {16: {40: frozenset({7})}})
        self.assertNotIn(
            16,
            transfer_affines(body, decode(body)[0], state, 0, "w").slots,
        )

    def test_unrelated_function_pointer_and_ecx_write_are_not_a_member_call(self):
        body = bytes.fromhex("8bc88b1a56ff5304c3")
        instructions = decode(body)
        flow = schedule_algorithms.ia32_web_control_flow(instructions, "w")
        self.assertIsNone(
            frontier_balance._one_word_vcall_shape(body, instructions, predecessors(flow), {}, 3)
        )

    def test_sub_esp_is_not_a_callee_clean_argument_push(self):
        body = bytes.fromhex("83ec048bc8ff5304c3")
        instructions = decode(body)
        flow = schedule_algorithms.ia32_web_control_flow(instructions, "w")
        self.assertIsNone(
            frontier_balance._one_word_vcall_shape(body, instructions, predecessors(flow), {}, 2)
        )

    def test_an_indirect_tail_jump_is_not_a_vcall_candidate(self) -> None:
        body = bytes.fromhex("8bce8b0652ff20")
        instructions = decode(body)
        self.assertIsNone(
            frontier_balance._one_word_vcall_shape(body, instructions, [[], [0], [1], [2]], {}, 3)
        )

    def test_strong_vcall_binds_the_exact_receiver_vtable_lea_push_chain(self) -> None:
        body = bytes.fromhex("8bce8b2e8d471050ff5528c3")
        instructions = decode(body)
        flow = schedule_algorithms.ia32_web_control_flow(instructions, "w")
        shape = frontier_balance._one_word_vcall_shape(
            body, instructions, predecessors(flow), {}, 4
        )
        self.assertIsNotNone(shape)
        assert shape is not None
        self.assertEqual(shape["argument_register"], "eax")
        self.assertEqual(shape["argument_definition_offset"], 4)

    def test_strong_vcall_refuses_receiver_or_vtable_clobber(self) -> None:
        cases = (
            "8bce8b068d471050ff10c3",  # LEA EAX destroys the vtable call base.
            "8bce8b0e8d471050ff11c3",  # Vtable load destroys thiscall ECX.
        )
        for body_hex in cases:
            with self.subTest(body=body_hex):
                body = bytes.fromhex(body_hex)
                instructions = decode(body)
                flow = schedule_algorithms.ia32_web_control_flow(instructions, "w")
                self.assertIsNone(
                    frontier_balance._one_word_vcall_shape(
                        body, instructions, predecessors(flow), {}, 4
                    )
                )

    def test_strong_vcall_refuses_an_extra_cfg_entry_into_its_chain(self) -> None:
        body = bytes.fromhex("8bce8b2e8d471050ff5528c3")
        instructions = decode(body)
        flow = schedule_algorithms.ia32_web_control_flow(instructions, "w")
        predecessor_rows = predecessors(flow)
        predecessor_rows[2].append(0)
        self.assertIsNone(
            frontier_balance._one_word_vcall_shape(body, instructions, predecessor_rows, {}, 4)
        )

    def test_strong_vcall_refuses_non_vftable_slots(self) -> None:
        cases = (
            ("8bce8b2e8d471050ff55fcc3", {}),  # negative slot
            ("8bce8b2e8d471050ff5502c3", {}),  # unaligned slot
            ("8bce8b2e8d47105064ff5528c3", {}),  # segment override
        )
        for body_hex, relocations in cases:
            with self.subTest(body=body_hex):
                body = bytes.fromhex(body_hex)
                instructions = decode(body)
                flow = schedule_algorithms.ia32_web_control_flow(instructions, "w")
                self.assertIsNone(
                    frontier_balance._one_word_vcall_shape(
                        body, instructions, predecessors(flow), relocations, 4
                    )
                )

    def test_strong_vcall_refuses_a_relocated_call_operand(self) -> None:
        body = bytes.fromhex("8bce8b2e8d471050ff9528000000c3")
        instructions = decode(body)
        flow = schedule_algorithms.ia32_web_control_flow(instructions, "w")
        for width in (4, 0, "4"):
            with self.subTest(width=width):
                relocations = {10: {"width": width, "target": "?slot@@3HA"}}
                self.assertIsNone(
                    frontier_balance._one_word_vcall_shape(
                        body, instructions, predecessors(flow), relocations, 4
                    )
                )

    def test_only_a_relocation_bound_global_call_is_direct_cdecl(self) -> None:
        body = bytes.fromhex("e80000000083c404c3")
        instructions = decode(body)
        relocations = {1: {"width": 4, "target": "?Probe@@YAXXZ"}}
        self.assertIsNotNone(msvc420_direct_cdecl_call(body, instructions, relocations, 0))
        member = {1: {"width": 4, "target": "?foo@@QAEJH@Z"}}
        self.assertIsNone(msvc420_direct_cdecl_call(body, instructions, member, 0))


class StackFrontierApplicationTest(unittest.TestCase):
    def test_standard_frontier_uses_the_compiler_canonical_stack_dag(self) -> None:
        # Direct ESP operands that remain on the same side of PUSH carry no
        # actionable ESP edge in the compiler theorem.  The one operand that
        # crosses is still derived and rebased exactly from 28 to 24.
        body = bytes.fromhex("8d542414528968348b44241c8b4908894838")
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [4, 1, 3, 4, 3, 3],
            "target_order": [2, 4, 3, 0, 1, 5],
            "expected_dependence_edges": [
                [0, 1, ["register_raw"]],
                [1, 5, ["memory"]],
                [2, 3, ["memory", "register_war"]],
                [2, 4, ["memory"]],
                [2, 5, ["memory"]],
                [3, 5, ["memory", "register_raw"]],
                [4, 5, ["memory", "register_raw"]],
            ],
            "expected_line_rows": [],
            "stack_adjustments": [[3, 11, 28, 24]],
            "stack_frontier_theorem": STACK_FRONTIER,
        }
        image, proof = schedule_algorithms.apply_instruction_schedule(
            body,
            [window],
            frozenset(),
            "s",
            compiler_identity=COMPILER_IDENTITY,
        )
        self.assertEqual(image, bytes.fromhex("8968348b49088b4424188d54241452894838"))
        self.assertEqual(
            proof["windows"][0]["dependence_edges"],
            window["expected_dependence_edges"],
        )

    def test_standard_frontier_omits_only_noncrossed_esp_reasons(self) -> None:
        # Two direct ESP operands stay before PUSH while the third crosses it.
        # Only the crossed operand needs (and receives) a displacement rebase.
        body = bytes.fromhex("8b69048b4424188968348d5424148b4424188b490852")
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [3, 4, 3, 4, 4, 3, 1],
            "target_order": [1, 0, 3, 6, 2, 4, 5],
            "expected_dependence_edges": [
                [0, 2, ["memory", "register_raw"]],
                [0, 5, ["register_war"]],
                [0, 6, ["memory"]],
                [1, 2, ["memory", "register_raw"]],
                [1, 4, ["register_waw"]],
                [2, 4, ["memory", "register_war"]],
                [2, 5, ["memory"]],
                [3, 6, ["register_raw"]],
            ],
            "expected_line_rows": [],
            "stack_adjustments": [[4, 17, 24, 28]],
            "stack_frontier_theorem": STACK_FRONTIER,
        }
        image, proof = schedule_algorithms.apply_instruction_schedule(
            body,
            [window],
            frozenset(),
            "s",
            compiler_identity=COMPILER_IDENTITY,
        )
        self.assertEqual(image, bytes.fromhex("8b4424188b69048d542414528968348b44241c8b4908"))
        self.assertEqual(
            proof["windows"][0]["dependence_edges"],
            window["expected_dependence_edges"],
        )

    def test_stack_frontier_allows_a_compiler_scoped_pointer_loaded_from_a_local(
        self,
    ) -> None:
        # The standard v1 marker mirrors the compiler's local scheduling
        # theorem.  It deliberately does not attempt to reconstruct the
        # source-level provenance of a pointer loaded before the window.
        body = bytes.fromhex("83ec20e8000000008b4424185289480483c424c3")
        window = full_stack_frontier_window(body, 12, 16, [1, 0])
        with patch.object(
            schedule_algorithms,
            "decode_ia32_bijection_body",
            side_effect=AssertionError("standard v1 requested private boundary evidence"),
        ):
            image, proof = schedule_algorithms.apply_instruction_schedule(
                body,
                [window],
                EXTERNAL_CALL_BYTES,
                "s",
                relocations=EXTERNAL_CALL,
                compiler_identity=COMPILER_IDENTITY,
            )
        self.assertEqual(image, bytes.fromhex("83ec20e8000000008b4424188948045283c424c3"))
        receipt = proof["windows"][0]["stack_frontier"]
        self.assertEqual(receipt["compiler_identity"], COMPILER_IDENTITY.proof_receipt())
        self.assertEqual(receipt["discharged_memory_pairs"][0]["source_pair"], [0, 1])
        self.assertNotIn("boundary", receipt)

    def test_stack_frontier_moves_a_push_past_an_explicit_cell(self) -> None:
        body = bytes.fromhex("83ec20e8000000008d4424185289480483c424c3")
        window = full_stack_frontier_window(body, 12, 16, [1, 0])
        image, proof = schedule_algorithms.apply_instruction_schedule(
            body,
            [window],
            EXTERNAL_CALL_BYTES,
            "s",
            relocations=EXTERNAL_CALL,
            compiler_identity=COMPILER_IDENTITY,
        )
        self.assertEqual(image, bytes.fromhex("83ec20e8000000008d4424188948045283c424c3"))
        receipt = proof["windows"][0]["stack_frontier"]
        self.assertEqual(receipt["compiler_identity"], COMPILER_IDENTITY.proof_receipt())
        self.assertEqual(receipt["discharged_memory_pairs"][0]["source_pair"], [0, 1])
        self.assertNotIn("boundary", receipt)

    def test_direct_callee_cleanup_binds_one_decoded_stack_word(self) -> None:
        body = bytes.fromhex("83ec20e80000000050e8000000008d44241852890883c424c3")
        relocations = {
            4: {"width": 4, "target": "?Probe@@YAXXZ"},
            10: {"width": 4, "target": "?foo@@QAEJH@Z"},
        }
        instructions = decode(body)
        successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
        floor, first_call = frame_floor(body, instructions, "s")
        sink = next(index for index, item in enumerate(instructions) if item["offset"] == 18)
        ancestor_set = ancestors(predecessors(successors), {sink})
        _depths, calls = frontier_balance.derive_stack_depths(
            body,
            instructions,
            successors,
            ancestor_set,
            floor,
            first_call,
            relocations,
            "s",
        )
        call = calls[0]
        self.assertEqual(call["argument_push_offsets"], [8])
        shape = call["stack_argument_shape"]
        self.assertIsInstance(shape, dict)
        assert isinstance(shape, dict)
        self.assertEqual(shape["stack_argument_bytes"], 4)

    def test_direct_cleanup_precedes_a_saved_register_pop(self) -> None:
        body = bytes.fromhex("83ec1053e80000000052e8000000005b83c410c3")
        relocations = {
            5: {"width": 4, "target": "?Probe@@YAXXZ"},
            11: {"width": 4, "target": "?foo@@QAEJH@Z"},
        }
        instructions = decode(body)
        successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
        floor, first_call = frame_floor(body, instructions, "s")
        sink = next(index for index, item in enumerate(instructions) if item["offset"] == 10)
        ancestor_set = ancestors(predecessors(successors), {sink})
        _depths, receipts = frontier_balance.derive_stack_depths(
            body,
            instructions,
            successors,
            ancestor_set,
            floor,
            first_call,
            relocations,
            "s",
        )
        self.assertEqual(receipts[-1]["kind"], "decorated-fixed-thiscall")

    def test_saved_word_crosses_only_proved_zero_cleanup_direct_calls(self) -> None:
        cases = (
            ("?PlayWhistleSound@Act2Brick@@QAEXXZ", "decorated-fixed-thiscall"),
            ("?StaticProbe@@YAXXZ", "direct-cdecl-caller-clean"),
        )
        for target, expected_kind in cases:
            with self.subTest(target=target):
                body = bytes.fromhex("83ec10e80000000052e8000000005a83c410c3")
                relocations = {
                    4: {"width": 4, "target": "?Probe@@YAXXZ"},
                    10: {"width": 4, "target": target},
                }
                instructions = decode(body)
                successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
                sink = next(index for index, item in enumerate(instructions) if item["offset"] == 9)
                ancestor_set = ancestors(predecessors(successors), {sink})
                floor, first_call = frame_floor(body, instructions, "s")
                _depths, receipts = frontier_balance.derive_stack_depths(
                    body,
                    instructions,
                    successors,
                    ancestor_set,
                    floor,
                    first_call,
                    relocations,
                    "s",
                )
                self.assertEqual(receipts[-1]["kind"], expected_kind)
                self.assertEqual(receipts[-1]["cleanup_bytes"], 0)

    def test_saved_register_push_is_not_a_zero_word_vcall_argument(self) -> None:
        # The ESI save sits next to a zero-argument receiver/vtable call but
        # there is no post-vtable LEA defining an EAX argument.
        body = bytes.fromhex("83ec10e8000000008bce8b0656ff105e83c410c3")
        relocations = {4: {"width": 4, "target": "?Probe@@YAXXZ"}}
        instructions = decode(body)
        successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
        sink = next(index for index, item in enumerate(instructions) if item["offset"] == 13)
        ancestor_set = ancestors(predecessors(successors), {sink})
        floor, first_call = frame_floor(body, instructions, "s")
        with self.assertRaises(ByteIdentityError) as caught:
            frontier_balance.derive_stack_depths(
                body,
                instructions,
                successors,
                ancestor_set,
                floor,
                first_call,
                relocations,
                "s",
            )
        self.assertIn("unresolved pending bytes", str(caught.exception))

    def test_frame_floor_refuses_a_first_call_argument_push(self) -> None:
        body = bytes.fromhex("83ec2050e8000000008b44241852890883c420c3")
        with self.assertRaises(ByteIdentityError) as caught:
            frame_floor(body, decode(body), "s")
        self.assertIn("non-frame PUSH precedes the first call", str(caught.exception))

    def test_frame_floor_refuses_a_push_before_the_fixed_allocation(self) -> None:
        body = bytes.fromhex("5083ec10e800000000c3")
        with self.assertRaises(ByteIdentityError) as caught:
            frame_floor(body, decode(body), "s")
        self.assertIn("PUSH precedes the fixed ESP allocation", str(caught.exception))

    def test_delayed_pop_does_not_authorize_a_weak_vcall_shape(self) -> None:
        body = bytes.fromhex("83ec10e8000000008bce8b0652ff109090909090905a83c410c3")
        relocations = {4: {"width": 4, "target": "?Probe@@YAXXZ"}}
        instructions = decode(body)
        successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
        predecessor_rows = predecessors(successors)
        sink = next(index for index, item in enumerate(instructions) if item["offset"] == 20)
        ancestor_set = ancestors(predecessor_rows, {sink})
        floor, first_call = frame_floor(body, instructions, "s")
        with self.assertRaises(ByteIdentityError) as caught:
            frontier_balance.derive_stack_depths(
                body,
                instructions,
                successors,
                ancestor_set,
                floor,
                first_call,
                relocations,
                "s",
            )
        self.assertIn("unresolved pending bytes", str(caught.exception))

    def test_two_weak_vcalls_with_one_later_cleanup_are_refused(self) -> None:
        # Delayed cleanup cannot turn either weak receiver/vtable/PUSH/call
        # sequence into the exact strong compiler shape.
        body = bytes.fromhex("83ec10e8000000008bce8b0652ff108bce8b0652ff109090909090905a83c410c3")
        relocations = {4: {"width": 4, "target": "?Probe@@YAXXZ"}}
        instructions = decode(body)
        successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
        floor, first_call = frame_floor(body, instructions, "s")
        with self.assertRaises(ByteIdentityError) as caught:
            frontier_balance.derive_stack_depths(
                body,
                instructions,
                successors,
                set(range(len(instructions))),
                floor,
                first_call,
                relocations,
                "s",
            )
        self.assertIn("unresolved pending bytes", str(caught.exception))

    def test_vcall_shape_refuses_a_second_push_in_the_same_call_setup(self) -> None:
        # The second site's extra EBX PUSH is after the preceding call
        # boundary, so the local epoch cannot certify a one-word call setup.
        body = bytes.fromhex("83ec10e8000000008bce8b0652ff1090538bce8b0657ff105a83c410c3")
        relocations = {4: {"width": 4, "target": "?Probe@@YAXXZ"}}
        instructions = decode(body)
        successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
        floor, first_call = frame_floor(body, instructions, "s")
        with self.assertRaises(ByteIdentityError):
            frontier_balance.derive_stack_depths(
                body,
                instructions,
                successors,
                set(range(len(instructions))),
                floor,
                first_call,
                relocations,
                "s",
            )

    def test_nested_argument_evaluation_cannot_hide_a_wide_vcall(self) -> None:
        body = bytes.fromhex(
            "83ec10e8000000008bce8b0652ff105352e8000000008bf88bce8b0657ff105a83c410c3"
        )
        relocations = {
            4: {"width": 4, "target": "?Probe@@YAXXZ"},
            18: {"width": 4, "target": "?helper@@QAEJH@Z"},
        }
        instructions = decode(body)
        successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
        floor, first_call = frame_floor(body, instructions, "s")
        with self.assertRaises(ByteIdentityError) as caught:
            frontier_balance.derive_stack_depths(
                body,
                instructions,
                successors,
                set(range(len(instructions))),
                floor,
                first_call,
                relocations,
                "s",
            )
        self.assertIn("unresolved pending bytes", str(caught.exception))

    def test_control_boundary_cannot_hide_a_wide_vcall(self) -> None:
        body = bytes.fromhex("83ec10e80000000053eb008bce8b0657ff105b83c410c3")
        relocations = {4: {"width": 4, "target": "?Probe@@YAXXZ"}}
        instructions = decode(body)
        successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
        floor, first_call = frame_floor(body, instructions, "s")
        with self.assertRaises(ByteIdentityError) as caught:
            frontier_balance.derive_stack_depths(
                body,
                instructions,
                successors,
                set(range(len(instructions))),
                floor,
                first_call,
                relocations,
                "s",
            )
        self.assertIn("unresolved pending bytes", str(caught.exception))

    def test_explicit_restore_does_not_authorize_a_weak_vcall(self) -> None:
        body = bytes.fromhex("83ec10e8000000008bce8b0652ff1083c4048bce8b0652ff1083c410c3")
        relocations = {4: {"width": 4, "target": "?Probe@@YAXXZ"}}
        instructions = decode(body)
        successors = schedule_algorithms.ia32_web_control_flow(instructions, "s")
        floor, first_call = frame_floor(body, instructions, "s")
        with self.assertRaises(ByteIdentityError) as caught:
            frontier_balance.derive_stack_depths(
                body,
                instructions,
                successors,
                set(range(len(instructions))),
                floor,
                first_call,
                relocations,
                "s",
            )
        self.assertIn("unresolved pending bytes", str(caught.exception))

    def test_stack_frontier_refuses_segment_overridden_explicit_memory(self):
        body = bytes.fromhex("558bec83ec20e80000000052648b4510c3")
        with self.assertRaises(ByteIdentityError) as caught:
            full_stack_frontier_window(body, 11, 16, [1, 0])
        self.assertIn("segment override", str(caught.exception))

    def test_stack_frontier_refuses_an_esp_derived_explicit_memory_base(self):
        # mov eax,esp / sub eax,4 / mov [eax],edx / push ecx
        # The register-only chain computes the PUSH seat without spelling an
        # ESP-relative memory operand.  Source and target taint both refuse it.
        body = bytes.fromhex("8bc483e804891051")
        instructions = decode(body)
        order = [0, 1, 3, 2]
        _facts, edges = schedule_algorithms.ia32_schedule_dependence_edges(
            instructions, "w", body, False
        )
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [item["length"] for item in instructions],
            "target_order": order,
            "expected_dependence_edges": edges,
            "expected_line_rows": [],
            "stack_frontier_theorem": STACK_FRONTIER,
        }
        with self.assertRaises(ByteIdentityError) as caught:
            schedule_algorithms.apply_instruction_schedule(
                body + b"\xc3",
                [window],
                frozenset(),
                "s",
                compiler_identity=COMPILER_IDENTITY,
            )
        self.assertIn("ESP-derived register", str(caught.exception))

    def test_stack_frontier_refuses_absent_or_wrong_compiler_scope(self):
        body = PUSH + FRAME_LOAD
        window = stack_frontier_window(body, [1, 0])
        for compiler_identity in (None, "msvc-5.00-win32-i386"):
            with self.subTest(compiler_identity=compiler_identity):
                with self.assertRaises(ByteIdentityError) as caught:
                    schedule_algorithms.apply_instruction_schedule(
                        body + b"\xc3",
                        [window],
                        frozenset(),
                        "s",
                        compiler_identity=compiler_identity,  # type: ignore[arg-type]
                    )
                self.assertIn("canonical MSVC 4.20 Win32 i386", str(caught.exception))

    def test_stack_frontier_refuses_a_derived_external_entry_inside_the_window(self):
        body = PUSH + FRAME_LOAD
        window = stack_frontier_window(body, [1, 0])
        with self.assertRaises(ByteIdentityError) as caught:
            schedule_algorithms.apply_instruction_schedule(
                body + b"\xc3",
                [window],
                frozenset(),
                "s",
                external_entries=frozenset({1}),
                compiler_identity=COMPILER_IDENTITY,
            )
        self.assertIn("derived external entry", str(caught.exception))

    def test_stack_frontier_refuses_when_its_discharged_pair_does_not_move(self):
        body = PUSH + FRAME_LOAD + bytes.fromhex("8d4e04")
        instructions = decode(body)
        _facts, edges = schedule_algorithms.ia32_schedule_dependence_edges(instructions, "w", body)
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [item["length"] for item in instructions],
            "target_order": [0, 2, 1],
            "expected_dependence_edges": edges,
            "expected_line_rows": [],
            "stack_frontier_theorem": STACK_FRONTIER,
        }
        with self.assertRaises(ByteIdentityError) as caught:
            schedule_algorithms.apply_instruction_schedule(
                body + b"\xc3",
                [window],
                frozenset(),
                "s",
                compiler_identity=COMPILER_IDENTITY,
            )
        self.assertIn("no moved PUSH-memory crossing", str(caught.exception))

    def test_stack_frontier_refuses_when_there_is_no_explicit_memory_pair(self):
        body = PUSH + bytes.fromhex("8d4e04")
        instructions = decode(body)
        _facts, edges = schedule_algorithms.ia32_schedule_dependence_edges(instructions, "w", body)
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [item["length"] for item in instructions],
            "target_order": [1, 0],
            "expected_dependence_edges": edges,
            "expected_line_rows": [],
            "stack_frontier_theorem": STACK_FRONTIER,
        }
        with self.assertRaises(ByteIdentityError) as caught:
            schedule_algorithms.apply_instruction_schedule(
                body + b"\xc3",
                [window],
                frozenset(),
                "s",
                compiler_identity=COMPILER_IDENTITY,
            )
        self.assertIn("no moved PUSH-memory crossing", str(caught.exception))

    def test_stack_frontier_refuses_a_prefixed_register_push(self):
        body = bytes.fromhex("2e52") + FRAME_LOAD
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [2, 3],
            "target_order": [1, 0],
            "expected_dependence_edges": [],
            "expected_line_rows": [],
            "stack_frontier_theorem": STACK_FRONTIER,
        }
        with self.assertRaises(ByteIdentityError) as caught:
            schedule_algorithms.apply_instruction_schedule(
                body + b"\xc3",
                [window],
                frozenset(),
                "s",
                compiler_identity=COMPILER_IDENTITY,
            )
        self.assertIn("unprefixed 32-bit register PUSH", str(caught.exception))

    def test_stack_frontier_refuses_another_esp_writer(self):
        body = bytes.fromhex("8d642404") + PUSH  # lea esp,[esp+4] / push edx
        window = {
            "start": 0,
            "end": len(body),
            "source_instruction_lengths": [4, 1],
            "target_order": [1, 0],
            "expected_dependence_edges": [],
            "expected_line_rows": [],
            "stack_frontier_theorem": STACK_FRONTIER,
        }
        with self.assertRaises(ByteIdentityError) as caught:
            schedule_algorithms.apply_instruction_schedule(
                body + b"\xc3",
                [window],
                frozenset(),
                "s",
                compiler_identity=COMPILER_IDENTITY,
            )
        self.assertIn("declares no stack adjustment", str(caught.exception))

    def test_stack_frontier_declaration_is_an_exact_marker(self):
        body = PUSH + FRAME_LOAD
        window = stack_frontier_window(body, [1, 0])
        window["stack_frontier_theorem"] = "msvc-4.20-stack-frontier"
        with self.assertRaises(ByteIdentityError) as caught:
            schedule_algorithms._validate_schedule_windows([window], "s", len(body))
        self.assertIn("stack_frontier_theorem differs", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
