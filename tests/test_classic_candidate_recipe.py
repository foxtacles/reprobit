"""The shared candidate-recipe skeleton reproduces each producer's own checks.

The producers' `_full` tests pin every message end to end; these tests pin
the skeleton's own contract: which pin each recipe field switches, the exact
message each variant emits, and the shape of the effective declarations and
the proof it assembles.  The instruction-schedule fixture supplies a golden
seed/donor pair and declaration.
"""

from __future__ import annotations

import copy
import unittest
from typing import Any, ClassVar

import test_classic_instruction_schedule_full as fixture

import reprobit.classic.candidate_recipe as recipe_module
import reprobit.classic.coff as coff_algorithms
import reprobit.coff_format as coff_format
from reprobit.binary import ByteIdentityError
from reprobit.classic.candidate_recipe import (
    CandidateRecipe,
    candidate_proof,
    comdat_body_range,
    equal_body_effective,
    internal_relocation_targets,
    open_candidate_seats,
    pin_candidate_bodies,
    relocated_byte_offsets,
    relocation_symbol_map,
    require_changes_within,
    require_closure_children_unchanged,
    require_declared_internal_targets,
    require_pinned_length,
    same_slot_effective,
)

FPO = (".debug$F", ".debug$S")
EH = (".debug$S", ".xdata$x")

SCHEDULE = CandidateRecipe(
    label="instruction-schedule",
    splice_class="retail_exact_instruction_schedule",
    spec_key="instruction_schedule",
    admissible_closures=(FPO, EH),
    donor_seat="declared",
)


def _with(recipe: CandidateRecipe, **changes: object) -> CandidateRecipe:
    values = {name: getattr(recipe, name) for name in recipe.__slots__}
    values.update(changes)
    return CandidateRecipe(**values)  # type: ignore[arg-type]


class SeatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = fixture.make_coff()
        self.donor = fixture.make_coff()
        self.record = fixture.function_record(self.seed, self.donor, fixture.IMAGE)

    def refusal(self, recipe: CandidateRecipe, record=None, seed=None, donor=None) -> str:
        with self.assertRaises(ByteIdentityError) as caught:
            open_candidate_seats(
                seed or self.seed, donor or self.donor, record or self.record, recipe
            )
        return str(caught.exception)

    def test_the_golden_declaration_opens_both_seats(self) -> None:
        seats = open_candidate_seats(self.seed, self.donor, self.record, SCHEDULE)
        self.assertEqual(seats.mangled, fixture.TARGET_SYMBOL)
        self.assertEqual(seats.seed_section["number"], self.record["expected_section_number"])
        self.assertEqual(
            seats.donor_section["number"], self.record["expected_donor_section_number"]
        )
        self.assertIs(seats.spec, self.record["instruction_schedule"])
        self.assertEqual(seats.expected_closure, FPO)
        seed_body, donor_body = pin_candidate_bodies(seats, self.record, SCHEDULE)
        self.assertEqual(seed_body, fixture.BODY)
        self.assertEqual(donor_body, fixture.BODY)

    def test_the_declaration_must_be_payload_free(self) -> None:
        record = copy.deepcopy(self.record)
        record["instruction_schedule"]["stray"] = b"\x90"
        message = self.refusal(SCHEDULE, record)
        self.assertTrue(message.startswith("instruction-schedule declaration."), message)
        message = self.refusal(_with(SCHEDULE, declaration_label="schedule re-run"), record)
        self.assertTrue(message.startswith("schedule re-run declaration."), message)

    def test_the_class_and_the_absent_source_refactor_are_named(self) -> None:
        record = dict(self.record, splice_class="other")
        self.assertEqual(
            self.refusal(SCHEDULE, record), "splice class is not retail_exact_instruction_schedule"
        )
        record = dict(self.record, target_source_refactor={})
        self.assertEqual(
            self.refusal(SCHEDULE, record),
            "instruction-schedule functions carry no source refactor",
        )
        self.assertEqual(
            self.refusal(_with(SCHEDULE, source_refactor_label="register-bijection"), record),
            "register-bijection functions carry no source refactor",
        )

    def test_a_declared_kind_is_required_before_the_objects_are_read(self) -> None:
        recipe = _with(SCHEDULE, kind=("other-kind", "schedule kind differs"))
        self.assertEqual(self.refusal(recipe, seed=b"not a coff"), "schedule kind differs")

    def test_the_seat_pin_has_three_forms(self) -> None:
        record = dict(
            self.record, expected_section_number=self.record["expected_section_number"] + 1
        )
        self.assertEqual(
            self.refusal(SCHEDULE, record), "instruction-schedule target section seat changed"
        )
        shared = _with(SCHEDULE, donor_seat="shared")
        self.assertEqual(
            self.refusal(shared, record), "instruction-schedule target section seat changed"
        )
        optional = _with(
            SCHEDULE, donor_seat="optional", declared_seat_message="declared seat moved"
        )
        record = dict(self.record, expected_donor_section_number=99)
        self.assertEqual(self.refusal(optional, record), "declared seat moved")
        record = dict(self.record)
        del record["expected_donor_section_number"]
        open_candidate_seats(self.seed, self.donor, record, optional)
        record["expected_section_number"] += 1
        self.assertEqual(
            self.refusal(optional, record), "instruction-schedule target section seat changed"
        )
        verbose = _with(SCHEDULE, verbose=True)
        record = dict(self.record, expected_donor_section_number=99)
        seat = self.record["expected_section_number"]
        self.assertEqual(
            self.refusal(verbose, record),
            f"instruction-schedule target section seat changed: seed {seat} donor {seat}",
        )

    def test_the_section_count_pin_has_three_forms(self) -> None:
        count = self.record["expected_section_count"]
        record = dict(self.record, expected_section_count=count + 1)
        self.assertEqual(
            self.refusal(SCHEDULE, record), "instruction-schedule global section count changed"
        )
        declared = _with(SCHEDULE, donor_section_count="declared", verbose=True)
        record = dict(self.record, expected_donor_section_count=count + 1)
        self.assertEqual(
            self.refusal(declared, record),
            f"instruction-schedule global section count changed: seed {count} donor {count}",
        )
        optional = _with(SCHEDULE, donor_section_count="optional")
        open_candidate_seats(self.seed, self.donor, self.record, optional)
        self.assertEqual(
            self.refusal(optional, record), "instruction-schedule global section count changed"
        )

    def test_the_census_names_the_witness_and_its_measured_sizes(self) -> None:
        functions = self.record["expected_function_count"]
        record = dict(self.record, expected_function_count=functions + 1)
        self.assertEqual(
            self.refusal(SCHEDULE, record), "instruction-schedule donor function set differs"
        )
        witness = _with(SCHEDULE, witness_word="witness", verbose=True)
        self.assertEqual(
            self.refusal(witness, record),
            f"instruction-schedule witness function set differs: {functions} vs {functions}",
        )
        comdats = self.record["expected_comdat_count"]
        record = dict(self.record, expected_comdat_count=comdats + 1)
        self.assertEqual(
            self.refusal(SCHEDULE, record),
            "instruction-schedule donor COMDAT identity set differs",
        )
        self.assertEqual(
            self.refusal(witness, record),
            f"instruction-schedule witness COMDAT identity set differs: {comdats} vs {comdats}",
        )

    def test_the_extras_census_admits_only_declared_extra_functions(self) -> None:
        extras = _with(SCHEDULE, census="extras")
        open_candidate_seats(self.seed, self.donor, self.record, extras)
        record = dict(self.record, expected_donor_extra_functions=["?Extra@@YAXXZ"])
        self.assertEqual(
            self.refusal(extras, record),
            "instruction-schedule donor function set differs from its declared extras",
        )

    def test_the_length_pins_can_be_named_separately(self) -> None:
        length = self.record["expected_body_length"]
        record = dict(self.record, expected_body_length=length + 1)
        self.assertEqual(
            self.refusal(SCHEDULE, record), "instruction-schedule target header/count pins changed"
        )
        named = _with(SCHEDULE, length_pins=("seed_length_pin", "donor_length_pin"))
        record = dict(record, seed_length_pin=length, donor_length_pin=length)
        open_candidate_seats(self.seed, self.donor, record, named)
        record["donor_length_pin"] += 1
        self.assertEqual(
            self.refusal(named, record), "instruction-schedule target header/count pins changed"
        )

    def test_the_closure_checks_can_be_merged_under_one_message(self) -> None:
        record = dict(self.record, expected_closure=[".debug$S"])
        self.assertEqual(
            self.refusal(SCHEDULE, record), "instruction-schedule target closure changed"
        )
        record = dict(self.record, expected_closure=list(FPO))
        narrow = _with(SCHEDULE, admissible_closures=(EH,))
        self.assertEqual(
            self.refusal(narrow, record),
            "instruction-schedule closure pin names no installation delegate",
        )
        merged = _with(narrow, closure_message="closure is not the EH pair")
        self.assertEqual(self.refusal(merged, record), "closure is not the EH pair")
        verbose = _with(SCHEDULE, verbose=True)
        record = dict(self.record, expected_closure=[".debug$S"])
        seed = coff_format.CoffObject(self.seed)
        closure = coff_algorithms._comdat_child_closure(
            seed, seed.function_section(fixture.TARGET_SYMBOL)
        )
        self.assertEqual(
            self.refusal(verbose, record),
            f"instruction-schedule target closure changed: seed {closure} donor {closure}",
        )

    def test_the_metadata_and_body_pins_follow_the_seats(self) -> None:
        seats = open_candidate_seats(self.seed, self.donor, self.record, SCHEDULE)
        record = dict(self.record, expected_seed_metadata_sha256="0" * 64)
        with self.assertRaises(ByteIdentityError) as caught:
            pin_candidate_bodies(seats, record, SCHEDULE)
        self.assertEqual(
            str(caught.exception), "instruction-schedule metadata differs from its pin"
        )
        record = dict(self.record, expected_donor_body_sha256="0" * 64)
        with self.assertRaises(ByteIdentityError) as caught:
            pin_candidate_bodies(seats, record, SCHEDULE)
        self.assertEqual(
            str(caught.exception), "instruction-schedule seed/donor body differs from its pin"
        )
        witness = _with(SCHEDULE, witness_word="witness", verbose=True)
        with self.assertRaises(ByteIdentityError) as caught:
            pin_candidate_bodies(seats, record, witness)
        digest = self.record["expected_seed_body_sha256"]
        self.assertEqual(
            str(caught.exception),
            "instruction-schedule seed/witness body differs from its pin"
            f": seed {digest} witness {digest}",
        )


class GeometryTests(unittest.TestCase):
    ROWS: ClassVar[list[dict[str, Any]]] = [
        {"offset": 4, "width": 4, "target": "a", "target_section": 3, "target_value": 20},
        {"offset": 12, "width": 2, "target": "b", "target_section": 5, "target_value": 8},
    ]

    def test_relocation_geometry(self) -> None:
        self.assertEqual(relocated_byte_offsets(self.ROWS), frozenset({4, 5, 6, 7, 12, 13}))
        self.assertEqual(
            relocation_symbol_map(self.ROWS),
            {4: {"width": 4, "target": "a"}, 12: {"width": 2, "target": "b"}},
        )
        self.assertEqual(internal_relocation_targets(self.ROWS, 3), frozenset({20}))
        self.assertEqual(internal_relocation_targets(self.ROWS, 7), frozenset())

    def test_declared_internal_targets_are_required_only_when_declared(self) -> None:
        require_declared_internal_targets({}, frozenset({20}), "x")
        require_declared_internal_targets(
            {"expected_internal_relocation_targets": [8, 20]}, frozenset({20, 8}), "x"
        )
        with self.assertRaises(ByteIdentityError) as caught:
            require_declared_internal_targets(
                {"expected_internal_relocation_targets": [8]}, frozenset({20}), "x"
            )
        self.assertEqual(str(caught.exception), "x in-body relocated target set changed")

    def test_the_pinned_length_and_the_body_range(self) -> None:
        require_pinned_length({"retail_oracle": {"length": 3}}, b"abc", "x")
        with self.assertRaises(ByteIdentityError) as caught:
            require_pinned_length({"retail_oracle": {"length": 4}}, b"abc", "x")
        self.assertEqual(str(caught.exception), "x linked length changed")
        self.assertEqual(comdat_body_range({"raw_offset": 10, "raw_size": 3}), {10, 11, 12})
        require_changes_within(b"abcd", b"abXd", {2}, "x")
        with self.assertRaises(ByteIdentityError) as caught:
            require_changes_within(b"abcd", b"abXd", {1}, "x")
        self.assertEqual(str(caught.exception), "x changed bytes outside its own COMDAT")


class EffectiveDeclarationTests(unittest.TestCase):
    FUNCTION: ClassVar[dict[str, Any]] = {
        "expected_body_length": 28,
        "expected_body_sha256": "a" * 64,
        "expected_changed_offsets": [1, 2],
        "expected_code_renames": [[4, "static"]],
        "expected_xdata_rename_offsets": [8],
        "expected_relocation_moves": [[4, 6]],
        "expected_seed_length": 28,
        "expected_donor_length": 38,
        "expected_linked_span": 48,
        "expected_seed_line_count": 3,
        "expected_donor_line_count": 4,
        "retail_oracle": {"length": 38},
        "retail_relocations": [],
    }

    def test_equal_body_effective_for_each_delegate(self) -> None:
        strict = equal_body_effective(
            self.FUNCTION, "f", "equal_body_strict", declared_renames=True
        )
        self.assertEqual(
            list(strict),
            [
                "mangled",
                "splice_class",
                "expected_body_length",
                "expected_body_sha256",
                "expected_changed_offsets",
            ],
        )
        self.assertEqual(strict["splice_class"], "equal_body_strict")
        local = equal_body_effective(
            self.FUNCTION, "f", "equal_body_eh_structural_local", declared_renames=True
        )
        self.assertEqual(local["expected_code_renames"], [[4, "static"]])
        self.assertEqual(local["expected_xdata_rename_offsets"], [8])
        empty = equal_body_effective(
            self.FUNCTION, "f", "equal_body_eh_structural_local", declared_renames=False
        )
        self.assertEqual(empty["expected_code_renames"], [])
        self.assertEqual(empty["expected_xdata_rename_offsets"], [])
        layout = equal_body_effective(
            self.FUNCTION, "f", "equal_body_eh_reloc_layout", declared_renames=True
        )
        self.assertEqual(layout["expected_relocation_moves"], [[4, 6]])
        self.assertEqual(layout["expected_xdata_rename_offsets"], [8])
        self.assertNotIn("expected_code_renames", layout)

    def test_same_slot_effective_names_the_reloc_divergent_delegate(self) -> None:
        effective = same_slot_effective(self.FUNCTION, "f")
        self.assertEqual(effective["splice_class"], "retail_exact_reloc_divergent")
        self.assertEqual(
            list(effective),
            [
                "mangled",
                "splice_class",
                "expected_seed_length",
                "expected_donor_length",
                "expected_linked_span",
                "expected_body_sha256",
                "expected_seed_line_count",
                "expected_donor_line_count",
                "retail_oracle",
                "retail_relocations",
            ],
        )

    def test_the_proof_keeps_delegate_detail_first_and_semantics_last(self) -> None:
        proof = candidate_proof(
            {"splice_class": "equal_body_strict", "seed_length": 28},
            "retail_exact_thing",
            {"windows": [], "changed_offsets": [1]},
            {"relocation_semantics": "declared"},
        )
        self.assertEqual(
            list(proof),
            [
                "splice_class",
                "seed_length",
                "windows",
                "changed_offsets",
                "candidate_only",
                "relocation_semantics",
            ],
        )
        self.assertEqual(proof["splice_class"], "retail_exact_thing")
        self.assertIs(proof["candidate_only"], True)


class ClosureChildTests(unittest.TestCase):
    def test_a_rewritten_child_is_named_unless_skipped(self) -> None:
        seed = fixture.make_coff()
        record = fixture.function_record(seed, seed, fixture.IMAGE)
        seats = open_candidate_seats(seed, seed, record, _with(SCHEDULE, donor_seat="shared"))
        checked = coff_format.CoffObject(seed)
        section = checked.function_section(fixture.TARGET_SYMBOL)
        require_closure_children_unchanged(seats, checked, section, "x")
        child = coff_algorithms._comdat_child(checked, section, ".debug$S")
        altered = bytearray(seed)
        altered[child["raw_offset"]] ^= 0x01
        rewritten = coff_format.CoffObject(bytes(altered))
        rewritten_section = rewritten.function_section(fixture.TARGET_SYMBOL)
        with self.assertRaises(ByteIdentityError) as caught:
            require_closure_children_unchanged(seats, rewritten, rewritten_section, "x")
        self.assertEqual(str(caught.exception), "x output changed its .debug$S child")
        require_closure_children_unchanged(
            seats, rewritten, rewritten_section, "x", skip=(".debug$S",)
        )


class ModuleShapeTests(unittest.TestCase):
    def test_the_recipe_is_frozen(self) -> None:
        with self.assertRaises(AttributeError):
            SCHEDULE.label = "other"  # type: ignore[misc]
        self.assertIs(recipe_module.CandidateRecipe, CandidateRecipe)


if __name__ == "__main__":
    unittest.main()
