"""Closed, inert metadata for intervention roles, costs, labels, and runtime coverage.

This catalog does not select semantic validators or execute recipe composers.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType


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


class ClassicRecipeFamily(StrEnum):
    """Closed classic recipe families supported by the current proof model.

    ``source_overlay_graph`` is project-level authority: after its closed typed-source
    proof and any exact sparse declaration-counterfactual compiler audits, rendered
    bytes may enter the primary compiler seat with origin
    ``certified-project-overlay``.
    ``donor_source_overlay`` remains donor-private and cannot enter a primary project
    compiler seat.
    """

    DECLARATION_SHAPE = "declaration_shape"
    DONOR_SOURCE_OVERLAY = "donor_source_overlay"
    FORWARD_DECLARATION_RUN = "forward_declaration_run"
    PAD_SHAPE = "pad_shape"
    EXTERN_RUN_PAIR = "extern_run_pair"
    FORWARD_RUN_WITH_SHAPE = "forward_run_with_shape"
    DECLARATION_RUN_TRIPLE = "declaration_run_triple"
    PREFIX_FORWARD_AFTER_INCLUDES_EXTERN = "prefix_forward_after_includes_extern"
    EQUAL_BODY_STRICT = "equal_body_strict"
    EQUAL_BODY_EH_STRUCTURAL_LOCAL = "equal_body_eh_structural_local"
    SAME_SLOT_RESIZE = "same_slot_resize"
    EQUAL_BODY_EH_RELOC_LAYOUT = "equal_body_eh_reloc_layout"
    RETAIL_EXACT_RELOC_DIVERGENT = "retail_exact_reloc_divergent"
    RETAIL_EXACT_DONOR_REWRITING = "retail_exact_donor_rewriting"
    RETAIL_EXACT_INSTRUCTION_MOSAIC = "retail_exact_instruction_mosaic"
    RETAIL_EXACT_REGISTER_BIJECTION = "retail_exact_register_bijection"
    RETAIL_EXACT_SOURCE_EQUAL_BODY = "retail_exact_source_equal_body"
    RETAIL_EXACT_COMPOSED_REWRITING = "retail_exact_composed_rewriting"
    RETAIL_EXACT_SOURCE_TARGET_CLOSURE = "retail_exact_source_target_closure"
    RETAIL_EXACT_WEB_RECOLOUR = "retail_exact_web_recolour"
    RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE = "retail_exact_cross_tu_complete_target_resize"
    RETAIL_EXACT_REGISTER_BIJECTION_REENCODING = "retail_exact_register_bijection_reencoding"
    RETAIL_EXACT_SAME_TU_INSTRUCTION_HYBRID_RESIZE = (
        "retail_exact_same_tu_instruction_hybrid_resize"
    )
    RETAIL_EXACT_SIMULATED_ELISION = "retail_exact_simulated_elision"
    SOURCE_OVERLAY_GRAPH = "source_overlay_graph"
    ARCHIVE_ADMISSION = "archive_admission"
    IMAGE_METADATA = "image_metadata"
    IMAGE_LINK_ORDER = "image_link_order"
    IMAGE_BINARY_REPACK = "image_binary_repack"


class ClassicRecipeRole(StrEnum):
    FUNCTION = "function"
    DONOR = "donor"
    PROJECT = "project"


class FamilyExecutionMode(StrEnum):
    SOURCE_OVERLAY = "source-overlay"
    DONOR_COMPILE = "donor-compile"
    CLEAN_CANDIDATE = "clean-candidate"
    LINK_OR_POSTLINK = "link-or-postlink"
    QUARANTINE_ONLY = "quarantine-only"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class FamilyCoverage:
    mode: FamilyExecutionMode
    implemented: bool
    detail: str


@dataclass(frozen=True, slots=True)
class ClassicRecipeMetadata:
    role: ClassicRecipeRole | None
    cost_class: CostClass | None
    coverage: FamilyCoverage


_DONOR_COVERAGE = FamilyCoverage(
    FamilyExecutionMode.DONOR_COMPILE,
    True,
    "closed declaration or donor-private overlay renderer is implemented",
)
_FUNCTION_COVERAGE = FamilyCoverage(
    FamilyExecutionMode.CLEAN_CANDIDATE,
    True,
    "oracle-free classic candidate producer is dispatchable",
)
_PROJECT_COVERAGE = FamilyCoverage(
    FamilyExecutionMode.LINK_OR_POSTLINK,
    True,
    "closed candidate-only terminal declaration is dispatchable",
)
_OVERLAY_COVERAGE = FamilyCoverage(
    FamilyExecutionMode.SOURCE_OVERLAY,
    True,
    "pinned source copy plus closed declarative generators; opaque legacy anchors fail",
)
_QUARANTINE_COVERAGE = FamilyCoverage(
    FamilyExecutionMode.QUARANTINE_ONLY,
    False,
    "must be represented and executed by the quarantined simulated-elision composer",
)
_UNIMPLEMENTED_COVERAGE = FamilyCoverage(
    FamilyExecutionMode.LINK_OR_POSTLINK,
    False,
    "typed declaration is preserved but the terminal producer is not implemented",
)


CLASSIC_RECIPE_METADATA: Mapping[ClassicRecipeFamily, ClassicRecipeMetadata] = MappingProxyType(
    {
        ClassicRecipeFamily.DECLARATION_SHAPE: ClassicRecipeMetadata(
            ClassicRecipeRole.DONOR, CostClass.STATE_CARRIER, _DONOR_COVERAGE
        ),
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY: ClassicRecipeMetadata(
            ClassicRecipeRole.DONOR, CostClass.CROSS_TU_OR_OVERLAY, _DONOR_COVERAGE
        ),
        ClassicRecipeFamily.FORWARD_DECLARATION_RUN: ClassicRecipeMetadata(
            ClassicRecipeRole.DONOR, CostClass.STATE_CARRIER, _DONOR_COVERAGE
        ),
        ClassicRecipeFamily.PAD_SHAPE: ClassicRecipeMetadata(
            ClassicRecipeRole.DONOR, CostClass.GENERATED_SUPPLIER, _DONOR_COVERAGE
        ),
        ClassicRecipeFamily.EXTERN_RUN_PAIR: ClassicRecipeMetadata(
            ClassicRecipeRole.DONOR, CostClass.STATE_CARRIER, _DONOR_COVERAGE
        ),
        ClassicRecipeFamily.FORWARD_RUN_WITH_SHAPE: ClassicRecipeMetadata(
            ClassicRecipeRole.DONOR, CostClass.GENERATED_SUPPLIER, _DONOR_COVERAGE
        ),
        ClassicRecipeFamily.DECLARATION_RUN_TRIPLE: ClassicRecipeMetadata(
            ClassicRecipeRole.DONOR, CostClass.STATE_CARRIER, _DONOR_COVERAGE
        ),
        ClassicRecipeFamily.PREFIX_FORWARD_AFTER_INCLUDES_EXTERN: ClassicRecipeMetadata(
            ClassicRecipeRole.DONOR, CostClass.STATE_CARRIER, _DONOR_COVERAGE
        ),
        ClassicRecipeFamily.EQUAL_BODY_STRICT: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.EQUAL_BODY_DONOR, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.EQUAL_BODY_EH_STRUCTURAL_LOCAL: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.STRUCTURAL_DONOR, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.SAME_SLOT_RESIZE: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.STRUCTURAL_DONOR, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.EQUAL_BODY_EH_RELOC_LAYOUT: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.STRUCTURAL_DONOR, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_RELOC_DIVERGENT: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.CROSS_TU_OR_OVERLAY, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_DONOR_REWRITING: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.SEMANTIC_REWRITE, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_INSTRUCTION_MOSAIC: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.BINARY_SURGERY, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.SEMANTIC_REWRITE, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_SOURCE_EQUAL_BODY: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.CROSS_TU_OR_OVERLAY, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_COMPOSED_REWRITING: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.SEMANTIC_REWRITE, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_SOURCE_TARGET_CLOSURE: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.CROSS_TU_OR_OVERLAY, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.SEMANTIC_REWRITE, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_CROSS_TU_COMPLETE_TARGET_RESIZE: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.CROSS_TU_OR_OVERLAY, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_REGISTER_BIJECTION_REENCODING: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.SEMANTIC_REWRITE, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_SAME_TU_INSTRUCTION_HYBRID_RESIZE: ClassicRecipeMetadata(
            ClassicRecipeRole.FUNCTION, CostClass.BINARY_SURGERY, _FUNCTION_COVERAGE
        ),
        ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION: ClassicRecipeMetadata(
            None, None, _QUARANTINE_COVERAGE
        ),
        ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH: ClassicRecipeMetadata(
            ClassicRecipeRole.PROJECT, CostClass.CROSS_TU_OR_OVERLAY, _OVERLAY_COVERAGE
        ),
        ClassicRecipeFamily.ARCHIVE_ADMISSION: ClassicRecipeMetadata(
            None, CostClass.LINK_ORDERING, _UNIMPLEMENTED_COVERAGE
        ),
        ClassicRecipeFamily.IMAGE_METADATA: ClassicRecipeMetadata(
            ClassicRecipeRole.PROJECT, CostClass.GENERATED_SUPPLIER, _PROJECT_COVERAGE
        ),
        ClassicRecipeFamily.IMAGE_LINK_ORDER: ClassicRecipeMetadata(
            ClassicRecipeRole.PROJECT, CostClass.LINK_ORDERING, _PROJECT_COVERAGE
        ),
        ClassicRecipeFamily.IMAGE_BINARY_REPACK: ClassicRecipeMetadata(
            ClassicRecipeRole.PROJECT, CostClass.BINARY_SURGERY, _PROJECT_COVERAGE
        ),
    }
)
if set(CLASSIC_RECIPE_METADATA) != set(ClassicRecipeFamily):
    raise AssertionError("classic recipe metadata must cover every family")


CLASSIC_RECIPE_FAMILIES_BY_ROLE: Mapping[ClassicRecipeRole, frozenset[ClassicRecipeFamily]] = (
    MappingProxyType(
        {
            role: frozenset(
                family
                for family, metadata in CLASSIC_RECIPE_METADATA.items()
                if metadata.role is role
            )
            for role in ClassicRecipeRole
        }
    )
)


def classic_recipe_family_role(family: ClassicRecipeFamily) -> ClassicRecipeRole | None:
    """Return the one runtime-supported role, or None for unavailable classic recipes."""

    return CLASSIC_RECIPE_METADATA[family].role


def classic_recipe_family_label(family: ClassicRecipeFamily) -> str:
    """Return the shared human label without changing the stable serialized family name."""

    return f"{family.value.replace('_', ' ').capitalize()} adjustment"


__all__ = [
    "CLASSIC_RECIPE_FAMILIES_BY_ROLE",
    "CLASSIC_RECIPE_METADATA",
    "ClassicRecipeFamily",
    "ClassicRecipeMetadata",
    "ClassicRecipeRole",
    "CostClass",
    "FamilyCoverage",
    "FamilyExecutionMode",
    "classic_recipe_family_label",
    "classic_recipe_family_role",
]
