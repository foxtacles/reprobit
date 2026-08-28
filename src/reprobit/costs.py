"""Stable, library-owned intervention cost model."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from enum import StrEnum
from fractions import Fraction
from types import MappingProxyType
from typing import Annotated, ClassVar

from pydantic import Field, model_validator

from reprobit.model import Identifier, Scope, StrictModel
from reprobit.schema import ClassicRecipeFamily, ClassicRecipeIntervention, Intervention


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


class CostModelV1:
    """Immutable cost taxonomy. Projects cannot replace these weights."""

    version: ClassVar[int] = 1
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
            "source_overlay": CostClass.CROSS_TU_OR_OVERLAY,
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
            ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT: (
                CostClass.CROSS_TU_OR_OVERLAY
            ),
            ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY: (
                CostClass.CROSS_TU_OR_OVERLAY
            ),
            ClassicRecipeFamily.RETAIL_EXACT_SOURCE_TARGET_CLOSURE: (
                CostClass.CROSS_TU_OR_OVERLAY
            ),
            ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE: (
                CostClass.CROSS_TU_OR_OVERLAY
            ),
            ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING: CostClass.SEMANTIC_REWRITE,
            ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION: (
                CostClass.SEMANTIC_REWRITE
            ),
            ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION_REENCODING: (
                CostClass.SEMANTIC_REWRITE
            ),
            ClassicRecipeFamily.RETAIL_EXACT_COMPOSED_REWRITING: (
                CostClass.SEMANTIC_REWRITE
            ),
            ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR: CostClass.SEMANTIC_REWRITE,
            ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC: CostClass.BINARY_SURGERY,
            ClassicRecipeFamily.RETAIL_EXACT_SAME_TU_INSTRUCTION_HYBRID_RESIZE: (
                CostClass.BINARY_SURGERY
            ),
            ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION: CostClass.ORACLE_INSTALL,
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
    def weight(cls, intervention: Intervention) -> int:
        return cls.weights[cls.classify(intervention)]

    @classmethod
    def unit_counts(
        cls, intervention: Intervention
    ) -> Mapping[CostUnitKind, int]:
        del intervention
        return MappingProxyType({CostUnitKind.INTERVENTION: 1})


class CostModelV2(CostModelV1):
    """Typed-unit model that prevents source-overlay action bundling."""

    version: ClassVar[int] = 2

    @classmethod
    def unit_counts(
        cls, intervention: Intervention
    ) -> Mapping[CostUnitKind, int]:
        if not (
            isinstance(intervention, ClassicRecipeIntervention)
            and intervention.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
        ):
            return super().unit_counts(intervention)

        parameters = {item.name: item.value for item in intervention.parameters}
        outputs = parameters.get("outputs")
        graph = parameters.get("graph")
        if not isinstance(outputs, list) or not isinstance(graph, dict):
            raise ValueError(
                f"source overlay {intervention.id!r} lacks typed outputs or graph"
            )

        edit_count = 0
        for index, output in enumerate(outputs):
            operations = output.get("ops") if isinstance(output, dict) else None
            if not isinstance(operations, list):
                raise ValueError(
                    f"source overlay {intervention.id!r} output {index} lacks typed ops"
                )
            if not operations:
                raise ValueError(
                    f"source overlay {intervention.id!r} output {index} has no ops"
                )
            edit_count += len(operations)

        generated = graph.get("generated_tus")
        admissions = graph.get("link_admissions")
        if not isinstance(generated, list) or not isinstance(admissions, list):
            raise ValueError(
                f"source overlay {intervention.id!r} graph lacks typed action lists"
            )
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
    kind: str
    cost_class: CostClass
    cost: Annotated[int, Field(ge=0)]
    scope: Scope
    units: tuple[CostUnitCharge, ...] = ()

    @model_validator(mode="after")
    def total_matches_units(self) -> InterventionCost:
        if self.units and self.cost != sum(unit.cost for unit in self.units):
            raise ValueError("intervention cost must equal its typed-unit costs")
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


class CostBreakdown(StrictModel):
    model_version: Annotated[int, Field(ge=1)]
    project_total: Annotated[int, Field(ge=0)]
    unallocated_shared_cost: Annotated[int, Field(ge=0)]
    by_class: tuple[ClassCost, ...]
    by_target: tuple[TargetCost, ...]
    by_function: tuple[FunctionCost, ...]
    interventions: tuple[InterventionCost, ...]

    @model_validator(mode="after")
    def typed_units_are_complete(self) -> CostBreakdown:
        if self.model_version < 2:
            return self
        if any(not intervention.units for intervention in self.interventions):
            raise ValueError("cost model v2 requires typed units for every intervention")
        if self.project_total != sum(item.cost for item in self.interventions):
            raise ValueError("project cost differs from typed intervention costs")

        class_expected: defaultdict[CostClass, tuple[int, int, int]] = defaultdict(
            lambda: (0, 0, 0)
        )
        target_expected: defaultdict[str, tuple[int, int, int]] = defaultdict(
            lambda: (0, 0, 0)
        )
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
        class_actual = {
            item.cost_class: (item.interventions, item.units, item.cost)
            for item in self.by_class
        }
        target_actual = {
            item.target: (item.interventions, item.units, item.cost)
            for item in self.by_target
        }
        if len(class_actual) != len(self.by_class) or class_actual != dict(class_expected):
            raise ValueError("cost-by-class totals differ from typed intervention costs")
        if len(target_actual) != len(self.by_target) or target_actual != dict(target_expected):
            raise ValueError("cost-by-target totals differ from typed intervention costs")
        return self


def _function_key(scope: Scope) -> tuple[str, str, str]:
    assert scope.translation_unit is not None
    assert scope.function is not None
    return (scope.target, scope.translation_unit, scope.function)


def calculate_cost(
    interventions: Iterable[Intervention],
    model: type[CostModelV1] = CostModelV2,
) -> CostBreakdown:
    """Charge each intervention ID's typed units and derive non-duplicating views."""

    unique: dict[str, Intervention] = {}
    for intervention in interventions:
        previous = unique.get(intervention.id)
        if previous is not None and previous != intervention:
            raise ValueError(f"intervention id {intervention.id!r} has conflicting definitions")
        unique[intervention.id] = intervention

    item_costs: list[InterventionCost] = []
    class_counts: defaultdict[CostClass, int] = defaultdict(int)
    class_unit_counts: defaultdict[CostClass, int] = defaultdict(int)
    class_costs: defaultdict[CostClass, int] = defaultdict(int)
    target_counts: defaultdict[str, int] = defaultdict(int)
    target_unit_counts: defaultdict[str, int] = defaultdict(int)
    target_costs: defaultdict[str, int] = defaultdict(int)
    direct_costs: defaultdict[tuple[str, str, str], int] = defaultdict(int)
    allocated_costs: defaultdict[tuple[str, str, str], Fraction] = defaultdict(Fraction)
    exposure_costs: defaultdict[tuple[str, str, str], int] = defaultdict(int)
    function_scopes: dict[tuple[str, str, str], Scope] = {}
    unallocated_shared = 0

    for intervention in sorted(unique.values(), key=lambda item: item.id):
        cost_class = model.classify(intervention)
        unit_cost = model.weight(intervention)
        counts = model.unit_counts(intervention)
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
        cost = sum(unit.cost for unit in units)
        unit_count = sum(unit.count for unit in units)
        item_costs.append(
            InterventionCost(
                intervention_id=intervention.id,
                kind=intervention.kind,
                cost_class=cost_class,
                cost=cost,
                scope=intervention.scope,
                units=units,
            )
        )
        class_counts[cost_class] += 1
        class_unit_counts[cost_class] += unit_count
        class_costs[cost_class] += cost
        target_counts[intervention.scope.target] += 1
        target_unit_counts[intervention.scope.target] += unit_count
        target_costs[intervention.scope.target] += cost

        if intervention.scope.function is not None:
            key = _function_key(intervention.scope)
            function_scopes[key] = intervention.scope
            direct_costs[key] += cost
            continue

        beneficiaries = {
            _function_key(scope): scope
            for scope in intervention.beneficiaries
            if scope.function is not None
        }
        if not beneficiaries:
            unallocated_shared += cost
            continue
        share = Fraction(cost, len(beneficiaries))
        for key, scope in beneficiaries.items():
            function_scopes[key] = scope
            allocated_costs[key] += share
            exposure_costs[key] += cost

    by_function = tuple(
        FunctionCost(
            scope=function_scopes[key],
            direct_cost=direct_costs[key],
            allocated_shared_cost=RationalCost.from_fraction(allocated_costs[key]),
            exposure_cost=exposure_costs[key],
        )
        for key in sorted(function_scopes)
    )
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
        model_version=model.version,
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
    "CostModelV1",
    "CostModelV2",
    "CostUnitCharge",
    "CostUnitKind",
    "FunctionCost",
    "InterventionCost",
    "RationalCost",
    "TargetCost",
    "calculate_cost",
]
