from __future__ import annotations

from pathlib import Path

import pytest

from reprobit.discovery_contracts import (
    CellObservation,
    CompileReceipt,
    DeclarationFamily,
    DeclarationParameter,
    DeclarationShapeSearch,
    DeclarationState,
    DiscoveryArtifactReceipt,
    DiscoveryArtifactRole,
    DiscoveryCampaignReport,
    DiscoveryCompilerReceipt,
    DiscoveryFindingKind,
    DiscoveryInputReceipt,
    DiscoveryInputRole,
    DiscoveryPlan,
    DiscoveryProposal,
    DiscoveryStateExport,
    FunctionObservation,
    InclusiveRange,
    declaration_state_id,
)
from reprobit.discovery_report_html import render_discovery_report_html
from reprobit.model import Digest, Scope
from reprobit.schema import StateCarrierIntervention
from reprobit.strict_json import canonical_json


def _digest(value: str) -> Digest:
    return Digest.from_bytes(value.encode("utf-8"))


def _fixture_report() -> DiscoveryCampaignReport:
    state = DeclarationState(
        family=DeclarationFamily.DECLARATION_SHAPE,
        parameters=(
            DeclarationParameter(name="classes", value=3),
            DeclarationParameter(name="functions", value=10),
        ),
    )
    state_id = declaration_state_id(state)
    plan = DiscoveryPlan(
        target="sample",
        translation_unit="transform",
        symbols=("_transform",),
        searches=(
            DeclarationShapeSearch(
                family=DeclarationFamily.DECLARATION_SHAPE,
                classes=InclusiveRange(start=1, stop=4),
                functions=InclusiveRange(start=10, stop=10),
            ),
        ),
        max_cells=1000,
    )
    artifact_id = "artifact.carrier"
    rationale = (
        "This declaration combination produced an exact function-body match. "
        "Review the rest of the object file for unintended differences."
    )
    proposal = DiscoveryProposal(
        campaign_id="campaign.sample",
        finding_id="finding.000",
        kind=DiscoveryFindingKind.WHOLE_BODY,
        scope=Scope(target="sample", translation_unit="transform"),
        symbol="_transform",
        state_ids=(state_id,),
        reference_body=_digest("reference body"),
        proposed_output=_digest("reference body"),
        intervention=StateCarrierIntervention(
            id="intervention.carrier",
            scope=Scope(target="sample", translation_unit="transform"),
            rationale=rationale,
            beneficiaries=(
                Scope(
                    target="sample",
                    translation_unit="transform",
                    function="_transform",
                ),
            ),
            carrier=artifact_id,
        ),
        artifact_ids=(artifact_id,),
        rationale=rationale,
    )
    declarations = "class ReproBitDiscoveryClass0;\nint reprobit_discovery_function_0();\n"
    object_digest = _digest("candidate object")
    observation = CellObservation(
        cell_id="cell.000",
        state_id=state_id,
        state=state,
        object=object_digest,
        compile=CompileReceipt(
            compiler_context=_digest("compiler context"),
            command=_digest("compiler command"),
            working_directory="/sealed/discovery/cell.000",
        ),
        functions=(
            FunctionObservation(
                symbol="?RawObservationOnly@@YAHXZ",
                section_number=1,
                section_offset=0,
                body_size=1,
                body=_digest("body"),
                relocation_count=0,
                relocations=_digest("relocations"),
                line_count=0,
                metadata=_digest("metadata"),
                comdat_selection=2,
            ),
        ),
    )
    return DiscoveryCampaignReport(
        campaign_id="campaign.sample",
        plan=plan,
        plan_digest=Digest.from_bytes(canonical_json(plan)),
        compile_implementation_digest=_digest("compile implementation"),
        analysis_implementation_digest=_digest("analysis implementation"),
        compile_authority_digest=_digest("compile authority"),
        analysis_authority_digest=_digest("analysis authority"),
        adapter="msvc-4.2",
        compiler=DiscoveryCompilerReceipt(
            identity="msvc-4.2",
            executable="/toolchain/wine/x86/cl",
            arguments=("/nologo", "/O2", "/Gy"),
            toolchain_authority=_digest("toolchain authority"),
        ),
        inputs=(
            DiscoveryInputReceipt(
                role=DiscoveryInputRole.REQUEST,
                logical_path="campaign.json",
                digest=_digest("request"),
                size=123,
            ),
            DiscoveryInputReceipt(
                role=DiscoveryInputRole.SOURCE,
                logical_path="transform.cpp",
                digest=_digest("source"),
                size=456,
            ),
        ),
        cells_total=1,
        cells_built=1,
        cells_cached=0,
        observations=(observation,),
        proposals=(proposal,),
        selected_states=(
            DiscoveryStateExport(
                cell_id=observation.cell_id,
                state_id=state_id,
                state=state,
                generated_declarations=declarations,
                generated_declarations_digest=Digest.from_bytes(declarations.encode("ascii")),
            ),
        ),
        artifacts=(
            DiscoveryArtifactReceipt(
                artifact_id=artifact_id,
                role=DiscoveryArtifactRole.STATE_CARRIER,
                symbol="_transform",
                logical_path=".reprobit-discovery/cache/artifacts/carrier.obj",
                object=object_digest,
                object_size=2048,
                cell_id=observation.cell_id,
            ),
        ),
    )


def test_discovery_html_is_layered_noncertifying_and_semantic() -> None:
    report = _fixture_report()

    rendered = render_discovery_report_html(
        report,
        canonical_json_name="campaign.report.json",
    )
    assert rendered.count('<svg class="brand-mark"') == 1

    assert rendered.startswith("<!doctype html>")
    assert "Discovery preview" in rendered
    assert "Suggestions only" in rendered
    assert "1 candidate ready for review" in rendered
    assert "Combinations checked" in rendered
    assert "Reused from cache" in rendered
    assert "Nothing applied" in rendered
    assert "Search scope:" in rendered
    assert "target <code>sample</code>" in rendered
    assert "TU <code>transform</code>" in rendered
    assert "Review-only next steps" in rendered
    assert 'id="candidate-kind-chart-title"' in rendered
    assert 'id="candidate-symbol-chart-title"' in rendered
    assert "<code>_transform</code>" in rendered
    assert "<pre><code>class ReproBitDiscoveryClass0;" in rendered
    assert "Exact intervention JSON" in rendered
    assert "{\n  &quot;beneficiaries&quot;" in rendered
    assert "{\n  &quot;max_cells&quot;" in rendered
    assert '<details class="advanced"' in rendered
    assert '<a class="machine-link" href="campaign.report.json">' in rendered
    assert "?RawObservationOnly@@YAHXZ" not in rendered
    assert '<script type="application/json"' not in rendered
    assert "https://" not in rendered
    assert " src=" not in rendered


def test_discovery_html_caps_large_indexes_and_proposal_cards() -> None:
    fixture = _fixture_report()
    observation = fixture.observations[0]
    observations = tuple(
        observation.model_copy(update={"cell_id": f"cell.{index:03d}"}) for index in range(201)
    )
    proposal = fixture.proposals[0]
    proposals = tuple(
        proposal.model_copy(update={"finding_id": f"finding.{index:03d}"}) for index in range(101)
    )
    report = DiscoveryCampaignReport(
        **{
            **fixture.model_dump(mode="python"),
            "cells_total": len(observations),
            "cells_built": 0,
            "cells_cached": len(observations),
            "observations": observations,
            "proposals": proposals,
        }
    )

    rendered = render_discovery_report_html(
        report,
        canonical_json_name="campaign.report.json",
    )

    assert rendered.count('<article class="proposal-card">') == 100
    assert "1 more remain in the canonical JSON" in rendered
    assert "cell.199" in rendered
    assert "cell.200" not in rendered
    assert "all 201 function observations" in rendered.lower()
    assert len(rendered.encode("utf-8")) < 1_000_000


def test_discovery_html_rejects_non_sibling_machine_report_links(
    tmp_path: Path,
) -> None:
    del tmp_path
    with pytest.raises(ValueError, match="sibling file name"):
        render_discovery_report_html(
            _fixture_report(),
            canonical_json_name="../campaign.report.json",
        )
