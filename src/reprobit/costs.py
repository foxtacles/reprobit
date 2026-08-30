"""Stable, library-owned intervention cost model."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from enum import StrEnum
from fractions import Fraction
from types import MappingProxyType
from typing import Annotated, ClassVar, Literal

from pydantic import Field, model_validator

from reprobit.model import Digest, Identifier, Scope, StrictModel
from reprobit.schema import (
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    Intervention,
    intervention_authority_digest,
)
from reprobit.strict_json import canonical_json


class CostClass(StrEnum):
    STATE_CARRIER = "state_carrier"
    GENERATED_SUPPLIER = "generated_supplier"
    LINK_ORDERING = "link_ordering"
    EQUAL_BODY_DONOR = "equal_body_donor"
    STRUCTURAL_DONOR = "structural_donor"
    CROSS_TU_OR_OVERLAY = "cross_tu_or_overlay"
    SEMANTIC_REWRITE = "semantic_rewrite"
    BINARY_SURGERY = "binary_surgery"
    ORACLE_INSTALL = "oracle_install"


class CostUnitKind(StrEnum):
    """Closed units that make an intervention's charged work explicit."""

    INTERVENTION = "intervention"
    SOURCE_OVERLAY_EDIT = "source_overlay_edit"
    GENERATED_TRANSLATION_UNIT = "generated_translation_unit"
    LINK_ADMISSION = "link_admission"


class CostModel:
    """Immutable cost taxonomy. Projects cannot replace these weights."""

    version: ClassVar[Literal[2]] = 2
    weights: ClassVar[Mapping[CostClass, int]] = MappingProxyType(
        {
            CostClass.STATE_CARRIER: 1,
            CostClass.GENERATED_SUPPLIER: 5,
            CostClass.LINK_ORDERING: 10,
            CostClass.EQUAL_BODY_DONOR: 25,
            CostClass.STRUCTURAL_DONOR: 50,
            CostClass.CROSS_TU_OR_OVERLAY: 100,
            CostClass.SEMANTIC_REWRITE: 250,
            CostClass.BINARY_SURGERY: 500,
            CostClass.ORACLE_INSTALL: 10_000,
        }
    )
    _classes: ClassVar[Mapping[str, CostClass]] = MappingProxyType(
        {
            "state_carrier": CostClass.STATE_CARRIER,
            "generated_supplier": CostClass.GENERATED_SUPPLIER,
            "metadata_normalization": CostClass.GENERATED_SUPPLIER,
            "link_ordering": CostClass.LINK_ORDERING,
            "equal_body_donor": CostClass.EQUAL_BODY_DONOR,
            "structural_donor": CostClass.STRUCTURAL_DONOR,
            "cross_tu_donor": CostClass.CROSS_TU_OR_OVERLAY,
            "semantic_rewrite": CostClass.SEMANTIC_REWRITE,
            "binary_surgery": CostClass.BINARY_SURGERY,
            "legacy.oracle_install": CostClass.ORACLE_INSTALL,
        }
    )
    _classic_classes: ClassVar[Mapping[ClassicRecipeFamily, CostClass]] = MappingProxyType(
        {
            ClassicRecipeFamily.DECLARATION_SHAPE: CostClass.STATE_CARRIER,
            ClassicRecipeFamily.FORWARD_DECLARATION_RUN: CostClass.STATE_CARRIER,
            ClassicRecipeFamily.EXTERN_RUN_PAIR: CostClass.STATE_CARRIER,
            ClassicRecipeFamily.DECLARATION_RUN_TRIPLE: CostClass.STATE_CARRIER,
            ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN: CostClass.STATE_CARRIER,
            ClassicRecipeFamily.PAD_SHAPE: CostClass.GENERATED_SUPPLIER,
            ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE: CostClass.GENERATED_SUPPLIER,
            ClassicRecipeFamily.DONOR_SOURCE_OVERLAY: CostClass.CROSS_TU_OR_OVERLAY,
            ClassicRecipeFamily.EQUAL_BODY_STRICT: CostClass.EQUAL_BODY_DONOR,
            ClassicRecipeFamily.EQUAL_BODY_EH_STRUCTURAL_LOCAL: CostClass.STRUCTURAL_DONOR,
            ClassicRecipeFamily.SAME_SLOT_RESIZE: CostClass.STRUCTURAL_DONOR,
            ClassicRecipeFamily.EQUAL_BODY_EH_RELOC_LAYOUT: CostClass.STRUCTURAL_DONOR,
            ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT: (CostClass.CROSS_TU_OR_OVERLAY),
            ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY: (CostClass.CROSS_TU_OR_OVERLAY),
            ClassicRecipeFamily.RETAIL_EXACT_SOURCE_TARGET_CLOSURE: (CostClass.CROSS_TU_OR_OVERLAY),
            ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE: (
                CostClass.CROSS_TU_OR_OVERLAY
            ),
            ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING: CostClass.SEMANTIC_REWRITE,
            ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION: (CostClass.SEMANTIC_REWRITE),
            ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION_REENCODING: (
                CostClass.SEMANTIC_REWRITE
            ),
            ClassicRecipeFamily.RETAIL_EXACT_COMPOSED_REWRITING: (CostClass.SEMANTIC_REWRITE),
            ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR: CostClass.SEMANTIC_REWRITE,
            ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC: CostClass.BINARY_SURGERY,
            ClassicRecipeFamily.RETAIL_EXACT_SAME_TU_INSTRUCTION_HYBRID_RESIZE: (
                CostClass.BINARY_SURGERY
            ),
            ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH: CostClass.CROSS_TU_OR_OVERLAY,
            ClassicRecipeFamily.ARCHIVE_ADMISSION: CostClass.LINK_ORDERING,
            ClassicRecipeFamily.IMAGE_METADATA: CostClass.GENERATED_SUPPLIER,
            ClassicRecipeFamily.IMAGE_LINK_ORDER: CostClass.LINK_ORDERING,
            ClassicRecipeFamily.IMAGE_BINARY_REPACK: CostClass.BINARY_SURGERY,
        }
    )

    @classmethod
    def classify(cls, intervention: Intervention) -> CostClass:
        if isinstance(intervention, ClassicRecipeIntervention):
            return cls._classic_classes[intervention.family]
        return cls._classes[intervention.kind]

    @classmethod
    def classify_record(
        cls,
        *,
        kind: str,
        family: ClassicRecipeFamily | None,
    ) -> CostClass:
        """Classify the complete identity retained in a report cost record."""

        if kind == "classic_recipe":
            if family is None:
                raise ValueError("classic-recipe cost record lacks its family")
            try:
                return cls._classic_classes[family]
            except KeyError as exc:
                raise ValueError(f"classic recipe family {family.value!r} is not costable") from exc
        if family is not None:
            raise ValueError("only classic-recipe cost records may name a family")
        try:
            return cls._classes[kind]
        except KeyError as exc:
            raise ValueError(f"unknown intervention cost kind: {kind!r}") from exc

    @classmethod
    def weight(cls, intervention: Intervention) -> int:
        return cls.weights[cls.classify(intervention)]

    @classmethod
    def unit_counts(cls, intervention: Intervention) -> Mapping[CostUnitKind, int]:
        if not (
            isinstance(intervention, ClassicRecipeIntervention)
            and intervention.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
        ):
            return MappingProxyType({CostUnitKind.INTERVENTION: 1})

        parameters = {item.name: item.value for item in intervention.parameters}
        outputs = parameters.get("outputs")
        graph = parameters.get("graph")
        if not isinstance(outputs, list) or not isinstance(graph, dict):
            raise ValueError(f"source overlay {intervention.id!r} lacks typed outputs or graph")

        edit_count = 0
        for index, output in enumerate(outputs):
            operations = output.get("ops") if isinstance(output, dict) else None
            if not isinstance(operations, list):
                raise ValueError(
                    f"source overlay {intervention.id!r} output {index} lacks typed ops"
                )
            if not operations:
                raise ValueError(f"source overlay {intervention.id!r} output {index} has no ops")
            edit_count += len(operations)

        generated = graph.get("generated_tus")
        admissions = graph.get("link_admissions")
        if not isinstance(generated, list) or not isinstance(admissions, list):
            raise ValueError(f"source overlay {intervention.id!r} graph lacks typed action lists")
        counts = {
            CostUnitKind.SOURCE_OVERLAY_EDIT: edit_count,
            CostUnitKind.GENERATED_TRANSLATION_UNIT: len(generated),
            CostUnitKind.LINK_ADMISSION: len(admissions),
        }
        normalized = {kind: count for kind, count in counts.items() if count}
        if not normalized:
            raise ValueError(f"source overlay {intervention.id!r} has no chargeable units")
        return MappingProxyType(normalized)


class RationalCost(StrictModel):
    numerator: Annotated[int, Field(ge=0)]
    denominator: Annotated[int, Field(gt=0)] = 1

    @model_validator(mode="after")
    def is_reduced(self) -> RationalCost:
        reduced = Fraction(self.numerator, self.denominator)
        if (reduced.numerator, reduced.denominator) != (self.numerator, self.denominator):
            raise ValueError("rational cost must be reduced")
        return self

    @classmethod
    def from_fraction(cls, value: Fraction) -> RationalCost:
        return cls(numerator=value.numerator, denominator=value.denominator)

    def as_fraction(self) -> Fraction:
        return Fraction(self.numerator, self.denominator)


class CostUnitCharge(StrictModel):
    kind: CostUnitKind
    count: Annotated[int, Field(gt=0)]
    unit_cost: Annotated[int, Field(ge=0)]
    cost: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def total_matches_units(self) -> CostUnitCharge:
        if self.cost != self.count * self.unit_cost:
            raise ValueError("cost-unit total must equal count times unit cost")
        return self


class InterventionCost(StrictModel):
    intervention_id: Identifier
    intervention_authority_digest: Digest
    kind: str
    family: ClassicRecipeFamily | None = None
    cost_class: CostClass
    cost: Annotated[int, Field(ge=0)]
    scope: Scope
    beneficiaries: tuple[Scope, ...] = ()
    units: tuple[CostUnitCharge, ...]

    @model_validator(mode="after")
    def is_canonical_current_model(self) -> InterventionCost:
        expected_class = CostModel.classify_record(kind=self.kind, family=self.family)
        if self.cost_class is not expected_class:
            raise ValueError("intervention cost class differs from its canonical mapping")
        expected_unit_cost = CostModel.weights[self.cost_class]
        if any(unit.unit_cost != expected_unit_cost for unit in self.units):
            raise ValueError("intervention unit cost differs from its canonical class weight")
        if self.cost != sum(unit.cost for unit in self.units):
            raise ValueError("intervention cost must equal its typed-unit costs")
        unit_kinds = tuple(unit.kind for unit in self.units)
        canonical_kinds = tuple(kind for kind in CostUnitKind if kind in unit_kinds)
        if unit_kinds != canonical_kinds or len(unit_kinds) != len(set(unit_kinds)):
            raise ValueError("intervention cost units must be unique and canonical")
        is_overlay_graph = (
            self.kind == "classic_recipe"
            and self.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
        )
        if is_overlay_graph:
            admitted = {
                CostUnitKind.SOURCE_OVERLAY_EDIT,
                CostUnitKind.GENERATED_TRANSLATION_UNIT,
                CostUnitKind.LINK_ADMISSION,
            }
            if not self.units or any(unit.kind not in admitted for unit in self.units):
                raise ValueError("source-overlay cost record has invalid typed units")
        elif (
            len(self.units) != 1
            or self.units[0].kind is not CostUnitKind.INTERVENTION
            or self.units[0].count != 1
        ):
            raise ValueError("ordinary intervention cost requires one intervention unit")

        if self.scope.function is not None and self.beneficiaries:
            raise ValueError("direct intervention cost cannot declare shared beneficiaries")
        beneficiary_keys: list[tuple[str, str, str]] = []
        for beneficiary in self.beneficiaries:
            if beneficiary.function is None or beneficiary.translation_unit is None:
                raise ValueError("cost beneficiary must name a function scope")
            if beneficiary.target != self.scope.target:
                raise ValueError("cost beneficiary must remain within its intervention target")
            if (
                self.scope.translation_unit is not None
                and beneficiary.translation_unit != self.scope.translation_unit
            ):
                raise ValueError("cost beneficiary must remain within its intervention TU")
            beneficiary_keys.append(
                (beneficiary.target, beneficiary.translation_unit, beneficiary.function)
            )
        if beneficiary_keys != sorted(beneficiary_keys) or len(beneficiary_keys) != len(
            set(beneficiary_keys)
        ):
            raise ValueError("cost beneficiaries must be unique and canonical")
        return self


class ClassCost(StrictModel):
    cost_class: CostClass
    interventions: Annotated[int, Field(ge=0)]
    cost: Annotated[int, Field(ge=0)]
    units: Annotated[int, Field(ge=0)] = 0


class TargetCost(StrictModel):
    target: Identifier
    interventions: Annotated[int, Field(ge=0)]
    cost: Annotated[int, Field(ge=0)]
    units: Annotated[int, Field(ge=0)] = 0


class FunctionCost(StrictModel):
    scope: Scope
    direct_cost: Annotated[int, Field(ge=0)]
    allocated_shared_cost: RationalCost
    exposure_cost: Annotated[int, Field(ge=0)]

    @model_validator(mode="after")
    def is_function_scope(self) -> FunctionCost:
        if self.scope.function is None:
            raise ValueError("function cost requires a function scope")
        return self


def _function_key(scope: Scope) -> tuple[str, str, str]:
    assert scope.translation_unit is not None
    assert scope.function is not None
    return (scope.target, scope.translation_unit, scope.function)


def _derive_function_costs(
    interventions: Iterable[InterventionCost],
) -> tuple[tuple[FunctionCost, ...], int]:
    direct_costs: defaultdict[tuple[str, str, str], int] = defaultdict(int)
    allocated_costs: defaultdict[tuple[str, str, str], Fraction] = defaultdict(Fraction)
    exposure_costs: defaultdict[tuple[str, str, str], int] = defaultdict(int)
    function_scopes: dict[tuple[str, str, str], Scope] = {}
    unallocated_shared = 0

    for intervention in interventions:
        if intervention.scope.function is not None:
            key = _function_key(intervention.scope)
            function_scopes[key] = intervention.scope
            direct_costs[key] += intervention.cost
            continue
        if not intervention.beneficiaries:
            unallocated_shared += intervention.cost
            continue
        share = Fraction(intervention.cost, len(intervention.beneficiaries))
        for scope in intervention.beneficiaries:
            key = _function_key(scope)
            function_scopes[key] = scope
            allocated_costs[key] += share
            exposure_costs[key] += intervention.cost

    return (
        tuple(
            FunctionCost(
                scope=function_scopes[key],
                direct_cost=direct_costs[key],
                allocated_shared_cost=RationalCost.from_fraction(allocated_costs[key]),
                exposure_cost=exposure_costs[key],
            )
            for key in sorted(function_scopes)
        ),
        unallocated_shared,
    )


class CostBreakdown(StrictModel):
    model_version: Literal[2]
    project_total: Annotated[int, Field(ge=0)]
    unallocated_shared_cost: Annotated[int, Field(ge=0)]
    by_class: tuple[ClassCost, ...]
    by_target: tuple[TargetCost, ...]
    by_function: tuple[FunctionCost, ...]
    interventions: tuple[InterventionCost, ...]

    @model_validator(mode="after")
    def is_complete_and_canonical(self) -> CostBreakdown:
        intervention_ids = tuple(item.intervention_id for item in self.interventions)
        if intervention_ids != tuple(sorted(intervention_ids)) or len(intervention_ids) != len(
            set(intervention_ids)
        ):
            raise ValueError("cost interventions must be unique and canonical")
        if self.project_total != sum(item.cost for item in self.interventions):
            raise ValueError("project cost differs from typed intervention costs")

        class_expected: defaultdict[CostClass, tuple[int, int, int]] = defaultdict(
            lambda: (0, 0, 0)
        )
        target_expected: defaultdict[str, tuple[int, int, int]] = defaultdict(lambda: (0, 0, 0))
        for item in self.interventions:
            unit_count = sum(unit.count for unit in item.units)
            interventions, units, cost = class_expected[item.cost_class]
            class_expected[item.cost_class] = (
                interventions + 1,
                units + unit_count,
                cost + item.cost,
            )
            interventions, units, cost = target_expected[item.scope.target]
            target_expected[item.scope.target] = (
                interventions + 1,
                units + unit_count,
                cost + item.cost,
            )
        expected_by_class = tuple(
            ClassCost(
                cost_class=cost_class,
                interventions=class_expected[cost_class][0],
                units=class_expected[cost_class][1],
                cost=class_expected[cost_class][2],
            )
            for cost_class in CostClass
            if cost_class in class_expected
        )
        expected_by_target = tuple(
            TargetCost(
                target=target,
                interventions=target_expected[target][0],
                units=target_expected[target][1],
                cost=target_expected[target][2],
            )
            for target in sorted(target_expected)
        )
        if self.by_class != expected_by_class:
            raise ValueError("cost-by-class totals differ from typed intervention costs")
        if self.by_target != expected_by_target:
            raise ValueError("cost-by-target totals differ from typed intervention costs")
        expected_functions, expected_unallocated = _derive_function_costs(self.interventions)
        if self.by_function != expected_functions:
            raise ValueError("function costs differ from typed intervention attribution")
        if self.unallocated_shared_cost != expected_unallocated:
            raise ValueError("unallocated shared cost differs from typed interventions")
        return self


def calculate_intervention_cost(intervention: Intervention) -> InterventionCost:
    """Return the one canonical cost-ledger row for a typed intervention."""

    cost_class = CostModel.classify(intervention)
    unit_cost = CostModel.weight(intervention)
    counts = CostModel.unit_counts(intervention)
    units = tuple(
        CostUnitCharge(
            kind=kind,
            count=counts[kind],
            unit_cost=unit_cost,
            cost=counts[kind] * unit_cost,
        )
        for kind in CostUnitKind
        if counts.get(kind, 0)
    )
    return InterventionCost(
        intervention_id=intervention.id,
        intervention_authority_digest=intervention_authority_digest(intervention),
        kind=intervention.kind,
        family=(
            intervention.family if isinstance(intervention, ClassicRecipeIntervention) else None
        ),
        cost_class=cost_class,
        cost=sum(unit.cost for unit in units),
        scope=intervention.scope,
        beneficiaries=intervention.beneficiaries,
        units=units,
    )


def intervention_cost_row_digest(cost: InterventionCost) -> Digest:
    """Bind every visible field in one canonical intervention-cost row."""

    return Digest.from_bytes(
        canonical_json(
            {
                "schema": "reprobit-intervention-cost-row-v1",
                "cost": cost.model_dump(
                    mode="json",
                    exclude_computed_fields=True,
                ),
            }
        )
    )


def calculate_cost(interventions: Iterable[Intervention]) -> CostBreakdown:
    """Charge each intervention ID's typed units and derive non-duplicating views."""

    unique: dict[str, Intervention] = {}
    for intervention in interventions:
        previous = unique.get(intervention.id)
        if previous is not None and previous != intervention:
            raise ValueError(f"intervention id {intervention.id!r} has conflicting definitions")
        unique[intervention.id] = intervention

    item_costs = [
        calculate_intervention_cost(intervention)
        for intervention in sorted(unique.values(), key=lambda item: item.id)
    ]
    class_counts: defaultdict[CostClass, int] = defaultdict(int)
    class_unit_counts: defaultdict[CostClass, int] = defaultdict(int)
    class_costs: defaultdict[CostClass, int] = defaultdict(int)
    target_counts: defaultdict[str, int] = defaultdict(int)
    target_unit_counts: defaultdict[str, int] = defaultdict(int)
    target_costs: defaultdict[str, int] = defaultdict(int)

    for item in item_costs:
        unit_count = sum(unit.count for unit in item.units)
        class_counts[item.cost_class] += 1
        class_unit_counts[item.cost_class] += unit_count
        class_costs[item.cost_class] += item.cost
        target_counts[item.scope.target] += 1
        target_unit_counts[item.scope.target] += unit_count
        target_costs[item.scope.target] += item.cost
    by_function, unallocated_shared = _derive_function_costs(item_costs)
    by_class = tuple(
        ClassCost(
            cost_class=cost_class,
            interventions=class_counts[cost_class],
            cost=class_costs[cost_class],
            units=class_unit_counts[cost_class],
        )
        for cost_class in CostClass
        if class_counts[cost_class]
    )
    by_target = tuple(
        TargetCost(
            target=target,
            interventions=target_counts[target],
            cost=target_costs[target],
            units=target_unit_counts[target],
        )
        for target in sorted(target_costs)
    )
    return CostBreakdown(
        model_version=CostModel.version,
        project_total=sum(item.cost for item in item_costs),
        unallocated_shared_cost=unallocated_shared,
        by_class=by_class,
        by_target=by_target,
        by_function=by_function,
        interventions=tuple(item_costs),
    )


__all__ = [
    "ClassCost",
    "CostBreakdown",
    "CostClass",
    "CostModel",
    "CostUnitCharge",
    "CostUnitKind",
    "FunctionCost",
    "InterventionCost",
    "RationalCost",
    "TargetCost",
    "calculate_cost",
    "calculate_intervention_cost",
    "intervention_cost_row_digest",
]
