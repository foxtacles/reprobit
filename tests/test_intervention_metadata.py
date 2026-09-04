from __future__ import annotations

from pathlib import Path

from reprobit.classic.semantic_contracts import CLASSIC_SEMANTIC_CONTRACTS
from reprobit.intervention_metadata import (
    CLASSIC_RECIPE_METADATA,
    ClassicRecipeFamily,
    FamilyExecutionMode,
)
from reprobit.recipe_reference import render_recipe_reference


def test_supported_recipe_metadata_matches_registered_semantic_contracts() -> None:
    supported = {
        family for family, metadata in CLASSIC_RECIPE_METADATA.items() if metadata.role is not None
    }

    assert supported == set(CLASSIC_SEMANTIC_CONTRACTS)
    assert all(CLASSIC_RECIPE_METADATA[family].coverage.implemented for family in supported)
    assert all(CLASSIC_RECIPE_METADATA[family].cost_class is not None for family in supported)
    assert set(CLASSIC_RECIPE_METADATA) - supported == {
        ClassicRecipeFamily.ARCHIVE_ADMISSION,
        ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION,
    }
    quarantine = CLASSIC_RECIPE_METADATA[ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION]
    assert quarantine.cost_class is None
    assert quarantine.coverage.mode is FamilyExecutionMode.QUARANTINE_ONLY


def test_committed_recipe_reference_is_current() -> None:
    path = Path(__file__).parents[1] / "docs" / "classic-recipe-reference.md"

    assert path.read_text(encoding="utf-8") == render_recipe_reference()
