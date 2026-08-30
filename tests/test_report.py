from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path

import pytest
from pydantic import ValidationError

import reprobit.report_io as report_io
from reprobit.costs import (
    CostBreakdown,
    CostClass,
    FunctionCost,
    RationalCost,
    calculate_cost,
    calculate_intervention_cost,
    intervention_cost_row_digest,
)
from reprobit.model import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    ByteRange,
    Certificate,
    Digest,
    ProofObligation,
    ProvenanceKind,
    ProvenanceNode,
    Quarantine,
    Scope,
    SemanticArtifactClaim,
    SemanticProof,
    Verdict,
    quarantine_proof_binding,
)
from reprobit.report import (
    AuditIssueSummary,
    BuildExecutionSummary,
    CacheMode,
    CacheSummary,
    ComponentIdentity,
    EvidenceSummary,
    ExecutionFileReceipt,
    ExecutionStepReceipt,
    ProducerSummary,
    ProofReport,
    Report,
    RuntimeBindingPreimage,
    RuntimeProofBinding,
    StageTiming,
    TargetComparisonSummary,
)
from reprobit.report_html import _scope_key
from reprobit.report_html_components import details, table
from reprobit.report_html_format import cost_class_label, format_fraction
from reprobit.report_io import (
    read_report_json,
    render_report_html,
    report_json_href,
    write_report_html,
    write_report_json,
)
from reprobit.schema import (
    ClassicField,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    InputTreeReceipt,
    InterventionDocument,
    LegacyOracleInstallIntervention,
    LiteralVerifier,
    LockedTool,
    LogicalPathProfile,
    ManifestLayout,
    MsvcRelease,
    OracleDocument,
    OracleInstallRange,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    ProjectSpec,
    ProofDocument,
    StateCarrierIntervention,
    TargetSpec,
    ToolchainLock,
    ToolchainRef,
    intervention_authority_digest,
)
from reprobit.strict_json import canonical_json


@pytest.mark.parametrize(
    ("cost_class", "label"),
    (
        (CostClass.CROSS_TU_OR_OVERLAY, "Cross TU or Overlay"),
        (CostClass.EQUAL_BODY_DONOR, "Equal-body donor"),
        (CostClass.BINARY_SURGERY, "Binary surgery"),
    ),
)
def test_html_cost_class_labels_are_intentionally_humanized(
    cost_class: CostClass,
    label: str,
) -> None:
    assert cost_class_label(cost_class) == label


def test_html_cost_helpers_keep_full_scope_and_compact_whole_fractions() -> None:
    assert _scope_key(
        Scope(target="program", translation_unit="first", function="same_name")
    ) != _scope_key(Scope(target="program", translation_unit="second", function="same_name"))
    assert format_fraction(Fraction(12, 1)) == "12"
    assert format_fraction(Fraction(5, 2)) == "5/2"


def test_shared_html_tables_and_disclosures_have_keyboard_semantics() -> None:
    rendered_table = table(
        ("Value",),
        (("sample",),),
        caption="Sample records",
    )
    rendered_details = details(
        identity="sample-details",
        title="Sample evidence",
        meta="1 record",
        body=rendered_table,
    )

    assert 'role="region" aria-label="Sample records" tabindex="0"' in rendered_table
    assert "<summary><h3>Sample evidence</h3>" in rendered_details


def digest(seed: bytes) -> Digest:
    return Digest.from_bytes(seed)


def runtime_binding(*, logical_artifact: str = "build/program.exe") -> RuntimeProofBinding:
    candidate = digest(b"oracle")
    artifact = "/work/sample/build/program.exe"
    return RuntimeProofBinding.create(
        RuntimeBindingPreimage(
            build=BuildExecutionSummary(
                cold=True,
                inputs=(),
                outputs=(
                    ExecutionFileReceipt(
                        path=artifact,
                        digest=candidate,
                        size=100,
                        fresh=True,
                        producer_step="link.program",
                        device=1,
                        inode=2,
                    ),
                ),
                steps=(
                    ExecutionStepReceipt(
                        id="link.program",
                        returncode=0,
                        attempts=1,
                        duration_seconds=0,
                        output_digest=digest(b"step-output"),
                        command_digest=digest(b"step-command"),
                    ),
                ),
            ),
            targets=(
                TargetComparisonSummary(
                    id="program",
                    logical_artifact=logical_artifact,
                    artifact=artifact,
                    candidate_digest=candidate,
                    candidate_size=100,
                    oracle_digest=candidate,
                    oracle_size=100,
                    byte_exact=True,
                    candidate_device=1,
                    candidate_inode=2,
                ),
            ),
        )
    )


def proof_report(seed: bytes = b"proof", *, logical_path: str = "build/program.exe") -> ProofReport:
    artifact = Artifact(
        id="program.image",
        kind=ArtifactKind.IMAGE,
        logical_path=logical_path,
        digest=digest(b"oracle"),
        size=100,
        origin=ArtifactOrigin.FRESH_SEED,
        producer="compiler",
    )
    component_digest = digest(seed + b"component")
    return ProofReport.create(
        runtime=runtime_binding(logical_artifact=logical_path),
        artifacts=(artifact,),
        provenance=(
            ProvenanceNode(
                id="program.origin",
                kind=ProvenanceKind.TOOLCHAIN,
                operation="link",
                origin=ArtifactOrigin.FRESH_SEED,
                artifact_id=artifact.id,
            ),
        ),
        certificates=(
            Certificate(
                id="certificate.program",
                intervention_id="stabilize.program",
                intervention_authority_digest=intervention_authority_digest(
                    stabilize_intervention()
                ),
                intervention_cost_digest=intervention_cost_row_digest(
                    calculate_intervention_cost(stabilize_intervention())
                ),
                obligations=(
                    ProofObligation(
                        name="semantic-equivalence",
                        passed=True,
                        evidence_digest=digest(seed + b"obligation"),
                    ),
                ),
                artifact_ids=(artifact.id,),
            ),
        ),
        producers=(
            ProducerSummary(
                id="producer.program",
                artifact_id=artifact.id,
                step_id="link.program",
                producer_kind="linker",
                tool_id="compiler",
                tool_digest=digest(b"compiler"),
                artifact_digest=artifact.digest,
                artifact_size=artifact.size,
            ),
        ),
        audit_issues=(),
        adapter=ComponentIdentity(
            role="adapter",
            id="classic-msvc-producer-graph-v1",
            implementation=("reprobit.classic_runtime.ClassicProducerGraphBuildExecutor"),
            package="reprobit",
            version="fixture",
            digest=component_digest,
        ),
        providers=(
            ComponentIdentity(
                role="evidence-provider",
                id="classic-msvc-cmake-v1",
                implementation=(
                    "reprobit.classic_runtime.ClassicProducerGraphRuntimeEvidenceProvider"
                ),
                package="reprobit",
                version="fixture",
                digest=component_digest,
            ),
        ),
        package=ComponentIdentity(
            role="package",
            id="reprobit",
            implementation="reprobit",
            package="reprobit",
            version="fixture",
            digest=digest(seed + b"package"),
        ),
    )


def evidence_summary(proof: ProofReport) -> EvidenceSummary:
    return proof.summary


def stabilize_intervention() -> StateCarrierIntervention:
    return StateCarrierIntervention(
        id="stabilize.program",
        scope=Scope(target="program"),
        rationale="bind the report fixture to its proof certificate",
        carrier="program-state",
    )


def bundle(artifact: str = "build/program.exe") -> ProjectBundle:
    spec = ProjectSpec(
        schema_version=3,
        project_id="sample",
        build=ProducerGraphBuildAdapter(),
        toolchain=ToolchainRef(profile="compiler-42"),
        paths=LogicalPathProfile(
            source="R:\\src",
            build="R:\\build",
            toolchain="R:\\toolchain",
        ),
        verifier=LiteralVerifier(),
        layout=ManifestLayout(),
        targets=(
            TargetSpec(
                id="program",
                artifact=artifact,
                oracle="references/program.exe",
            ),
        ),
    )
    lock = ToolchainLock(
        schema_version=3,
        profile="compiler-42",
        release=MsvcRelease.V4_2,
        tools=(
            LockedTool(
                id="compiler",
                path="tools/compiler.exe",
                digest=digest(b"compiler"),
                size=10,
            ),
        ),
        input_trees=(
            InputTreeReceipt(
                id="headers",
                path="include",
                entry_count=17,
                max_depth=3,
                membership_digest=digest(b"header membership"),
                content_digest=digest(b"header contents"),
            ),
        ),
    )
    return ProjectBundle(
        root="/work/sample",
        spec=spec,
        toolchain_lock=lock,
        intervention_documents=(
            InterventionDocument(
                schema_version=3,
                target_id="program",
                interventions=(stabilize_intervention(),),
            ),
        ),
        proof_documents=(ProofDocument(schema_version=3, target_id="program"),),
        oracle_documents=(
            OracleDocument(
                schema_version=3,
                target_id="program",
                image_size=100,
                image_digest=digest(b"oracle"),
            ),
        ),
    )


def test_report_rejects_costs_for_a_target_outside_its_receipts() -> None:
    proof = proof_report()
    baseline = Report.from_bundle(
        bundle(),
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
        ),
        evidence=proof.summary,
        proof=proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
    )
    ghost_costs = calculate_cost(
        (
            StateCarrierIntervention(
                id="ghost-cost",
                scope=Scope(target="ghost"),
                rationale="target-membership fixture",
                carrier="declaration",
            ),
        )
    )

    with pytest.raises(ValidationError, match="costs name unknown targets"):
        Report.create(
            project_id=baseline.project_id,
            runtime_binding=baseline.runtime_binding,
            toolchain=baseline.toolchain,
            paths=baseline.paths,
            verdict=baseline.verdict,
            costs=ghost_costs,
            targets=baseline.targets,
            evidence=baseline.evidence,
            proof=baseline.proof,
            timings=baseline.timings,
            cache=baseline.cache,
            previous=baseline.previous,
        )


def test_report_is_deterministic_and_canonical(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verdict = Verdict(
        cold=True,
        byte_exact=True,
        logic_certified=True,
        toolchain_origin=True,
    )
    proof = proof_report()
    evidence = evidence_summary(proof)
    first = Report.from_bundle(
        bundle(),
        verdict=verdict,
        evidence=evidence,
        proof=proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
    )
    second = Report.from_bundle(
        bundle(),
        verdict,
        evidence=evidence,
        proof=proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
    )
    assert first == second
    assert first.verdict.clean
    assert first.evidence == evidence
    assert first.costs.project_total == 1
    assert first.targets[0].candidate_size == 100
    assert first.targets[0].candidate_digest == digest(b"oracle")
    assert first.cache.mode is CacheMode.BYPASSED
    assert first.cache.hits == first.cache.misses == 0
    assert first.proof.artifacts[0].id == "program.image"
    assert first.proof.producers[0].tool_id == "compiler"
    assert first.proof.adapter.id == "classic-msvc-producer-graph-v1"
    assert first.schema_version == 2
    assert first.toolchain.input_trees[0].id == "headers"
    assert first.toolchain.input_trees[0].entry_count == 17

    destination = tmp_path / "report.json"
    write_report_json(first, destination)
    raw = destination.read_bytes()
    assert raw.endswith(b"\n")
    assert (
        raw
        == json.dumps(
            json.loads(raw),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        + b"\n"
    )
    assert b'"clean"' not in raw
    assert b'"quarantined"' not in raw
    monkeypatch.setattr(
        report_io,
        "canonical_json",
        lambda _value: pytest.fail("report reading must not reserialize parsed JSON"),
    )
    assert read_report_json(destination) == first


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (b'{"schema_version":2,"schema_version":2}', "duplicate JSON object key"),
        (b'{"schema_version":NaN}', "non-finite JSON number"),
        (b'{"schema_version":Infinity}', "non-finite JSON number"),
    ),
)
def test_report_reader_rejects_ambiguous_json_before_model_validation(
    tmp_path: Path,
    payload: bytes,
    message: str,
) -> None:
    source = tmp_path / "report.json"
    source.write_bytes(payload)

    with pytest.raises(ValueError, match=message):
        read_report_json(source)


def test_report_cost_rows_match_proof_certificates_exactly_once() -> None:
    proof = proof_report()
    baseline = Report.from_bundle(
        bundle(),
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
        ),
        evidence=proof.summary,
        proof=proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
    )

    extra = StateCarrierIntervention(
        id="extra.program",
        scope=Scope(target="program"),
        rationale="extra cost-row fixture",
        carrier="extra-program-state",
    )
    for mismatched_costs in (
        calculate_cost(()),
        calculate_cost((stabilize_intervention(), extra)),
    ):
        with pytest.raises(ValidationError, match="cost interventions differ"):
            Report.create(
                project_id=baseline.project_id,
                runtime_binding=baseline.runtime_binding,
                toolchain=baseline.toolchain,
                paths=baseline.paths,
                verdict=baseline.verdict,
                costs=mismatched_costs,
                targets=baseline.targets,
                evidence=baseline.evidence,
                proof=baseline.proof,
            )

    duplicate = proof.certificates[0].model_copy(update={"id": "certificate.program-copy"})
    duplicated_proof = ProofReport.create(
        runtime=proof.runtime,
        artifacts=proof.artifacts,
        provenance=proof.provenance,
        certificates=(*proof.certificates, duplicate),
        producers=proof.producers,
        audit_issues=proof.audit_issues,
        adapter=proof.adapter,
        providers=proof.providers,
        package=proof.package,
    )
    with pytest.raises(ValidationError, match="exactly one certificate"):
        Report.create(
            project_id=baseline.project_id,
            runtime_binding=baseline.runtime_binding,
            toolchain=baseline.toolchain,
            paths=baseline.paths,
            verdict=baseline.verdict,
            costs=baseline.costs,
            targets=baseline.targets,
            evidence=duplicated_proof.summary,
            proof=duplicated_proof,
        )


def test_report_classic_semantic_family_binds_its_cost_classification() -> None:
    ordinary = proof_report()
    artifact = ordinary.artifacts[0]
    classic = ClassicRecipeIntervention(
        id=ordinary.certificates[0].intervention_id,
        scope=Scope(target="program"),
        rationale="classic family cost binding fixture",
        family=ClassicRecipeFamily.IMAGE_METADATA,
        role=ClassicRecipeRole.PROJECT,
        build_target="program",
    )
    statement = {
        "artifact": {
            "digest": artifact.digest.model_dump(mode="json"),
            "size": artifact.size,
        }
    }
    evidence_digest = digest(b"classic family evidence")
    semantic = SemanticProof(
        family=ClassicRecipeFamily.IMAGE_METADATA.value,
        validator_id="fixture-classic-validator",
        validator_digest=digest(b"classic validator"),
        input_statement_digest=Digest.from_bytes(canonical_json(statement)),
        output_statement_digest=Digest.from_bytes(canonical_json(statement)),
        obligations=("metadata-shape",),
        evidence_digest=evidence_digest,
        input_statement=statement,
        output_statement=statement,
        artifact_claims=(
            SemanticArtifactClaim(
                artifact_id=artifact.id,
                relation="output",
                digest=artifact.digest,
                size=artifact.size,
            ),
        ),
    )
    certificate = ordinary.certificates[0].model_copy(
        update={
            "obligations": (
                ProofObligation(
                    name="metadata-shape",
                    passed=True,
                    evidence_digest=evidence_digest,
                ),
            ),
            "semantic_proofs": (semantic,),
            "intervention_authority_digest": intervention_authority_digest(classic),
            "intervention_cost_digest": intervention_cost_row_digest(
                calculate_intervention_cost(classic)
            ),
        }
    )
    proof = ProofReport.create(
        runtime=ordinary.runtime,
        artifacts=ordinary.artifacts,
        provenance=ordinary.provenance,
        certificates=(certificate,),
        producers=ordinary.producers,
        audit_issues=ordinary.audit_issues,
        adapter=ordinary.adapter,
        providers=ordinary.providers,
        package=ordinary.package,
    )
    baseline = Report.from_bundle(
        bundle(),
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
        ),
        evidence=ordinary.summary,
        proof=ordinary,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
    )
    matching = Report.create(
        project_id=baseline.project_id,
        runtime_binding=baseline.runtime_binding,
        toolchain=baseline.toolchain,
        paths=baseline.paths,
        verdict=baseline.verdict,
        costs=calculate_cost((classic,)),
        targets=baseline.targets,
        evidence=proof.summary,
        proof=proof,
    )
    assert matching.costs.interventions[0].family is ClassicRecipeFamily.IMAGE_METADATA

    tampered_payload = matching.costs.model_dump(mode="json")
    tampered_payload["interventions"][0]["scope"]["translation_unit"] = "relabeled"
    tampered_costs = CostBreakdown.model_validate_json(canonical_json(tampered_payload))
    with pytest.raises(ValidationError, match="intervention cost row differs"):
        Report.create(
            project_id=matching.project_id,
            runtime_binding=matching.runtime_binding,
            toolchain=matching.toolchain,
            paths=matching.paths,
            verdict=matching.verdict,
            costs=tampered_costs,
            targets=matching.targets,
            evidence=matching.evidence,
            proof=matching.proof,
        )

    altered_authority = ClassicRecipeIntervention(
        id=classic.id,
        scope=classic.scope,
        rationale=classic.rationale,
        family=classic.family,
        role=classic.role,
        build_target=classic.build_target,
        parameters=(ClassicField(name="timestamp", value=0),),
    )
    with pytest.raises(ValidationError, match="intervention authority differs"):
        Report.create(
            project_id=matching.project_id,
            runtime_binding=matching.runtime_binding,
            toolchain=matching.toolchain,
            paths=matching.paths,
            verdict=matching.verdict,
            costs=calculate_cost((altered_authority,)),
            targets=matching.targets,
            evidence=matching.evidence,
            proof=matching.proof,
        )

    relabeled_costs = calculate_cost((stabilize_intervention(),))
    relabeled_costs = relabeled_costs.model_copy(
        update={
            "interventions": (
                relabeled_costs.interventions[0].model_copy(
                    update={
                        "intervention_authority_digest": certificate.intervention_authority_digest
                    }
                ),
            )
        }
    )
    relabeled_certificate = certificate.model_copy(
        update={
            "intervention_cost_digest": intervention_cost_row_digest(
                relabeled_costs.interventions[0]
            )
        }
    )
    relabeled_proof = ProofReport.create(
        runtime=proof.runtime,
        artifacts=proof.artifacts,
        provenance=proof.provenance,
        certificates=(relabeled_certificate,),
        producers=proof.producers,
        audit_issues=proof.audit_issues,
        adapter=proof.adapter,
        providers=proof.providers,
        package=proof.package,
    )
    with pytest.raises(ValidationError, match="classic semantic family differs"):
        Report.create(
            project_id=matching.project_id,
            runtime_binding=matching.runtime_binding,
            toolchain=matching.toolchain,
            paths=matching.paths,
            verdict=matching.verdict,
            costs=relabeled_costs,
            targets=matching.targets,
            evidence=relabeled_proof.summary,
            proof=relabeled_proof,
        )


def test_html_reconciles_shared_cost_and_marks_only_the_exact_quarantine_scope() -> None:
    proof = proof_report()
    base = Report.from_bundle(
        bundle(),
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
        ),
        evidence=proof.summary,
        proof=proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
    )
    quarantined_scope = Scope(
        target="program",
        translation_unit="first",
        function="same_name",
    )
    costs = base.costs.model_copy(
        update={
            "project_total": 100,
            "unallocated_shared_cost": 40,
            "by_function": (
                FunctionCost(
                    scope=quarantined_scope,
                    direct_cost=30,
                    allocated_shared_cost=RationalCost(numerator=0),
                    exposure_cost=0,
                ),
                FunctionCost(
                    scope=Scope(
                        target="program",
                        translation_unit="second",
                        function="same_name",
                    ),
                    direct_cost=30,
                    allocated_shared_cost=RationalCost(numerator=0),
                    exposure_cost=0,
                ),
            ),
        }
    )
    verdict = Verdict(
        cold=True,
        byte_exact=True,
        logic_certified=True,
        toolchain_origin=False,
        quarantines=(
            Quarantine(
                id="scoped-exception",
                kind="legacy.oracle_install",
                artifact_id="program.image",
                ranges=(ByteRange(offset=0, length=1),),
                byte_count=1,
                reason="scoped fixture",
                scope=quarantined_scope,
            ),
        ),
    )

    rendered = render_report_html(base.model_copy(update={"costs": costs, "verdict": verdict}))

    assert rendered.count("Assigned to functions") == 2
    assert rendered.count("Shared project/TU cost") == 2
    assert rendered.count("40.0% is not assigned to one function") == 2
    assert "That is context, so do not add it to the" in rendered
    assert "Function-level cost attribution rows" in rendered
    assert "Complete function-cost allocation" not in rendered
    assert rendered.count('<span class="exception-note">authenticity exception</span>') == 1


def test_certified_report_cache_is_explicitly_bypassed() -> None:
    assert CacheSummary().model_dump(mode="json") == {
        "mode": "bypassed",
        "hits": 0,
        "misses": 0,
    }
    with pytest.raises(ValidationError, match="cannot record activity"):
        CacheSummary(hits=1)


def test_report_rejects_verdicts_that_contradict_targets_or_audit_issues() -> None:
    clean_verdict = Verdict(
        cold=True,
        byte_exact=True,
        logic_certified=True,
        toolchain_origin=True,
    )
    proof = proof_report()
    with pytest.raises(ValidationError, match="byte-exact verdict differs"):
        Report.from_bundle(
            bundle(),
            clean_verdict,
            evidence=evidence_summary(proof),
            proof=proof,
            target_results={"program": False},
            target_artifacts={"program": (100, digest(b"candidate"))},
        )

    issue_proof = ProofReport.create(
        runtime=proof.runtime,
        artifacts=proof.artifacts,
        provenance=proof.provenance,
        certificates=proof.certificates,
        producers=proof.producers,
        audit_issues=(
            AuditIssueSummary(
                claim="origin",
                code="unsealed-input",
                message="fixture origin failure",
            ),
        ),
        adapter=proof.adapter,
        providers=proof.providers,
        package=proof.package,
    )
    with pytest.raises(ValidationError, match="origin audit issues contradict"):
        Report.from_bundle(
            bundle(),
            clean_verdict,
            evidence=evidence_summary(issue_proof),
            proof=issue_proof,
            target_results={"program": True},
            target_artifacts={"program": (100, digest(b"oracle"))},
        )


def test_html_is_self_contained_escaped_and_warns_for_quarantine(tmp_path: Path) -> None:
    quarantine_scope = Scope(
        target="program",
        translation_unit="main",
        function="work()",
    )
    quarantine = Quarantine(
        id="legacy-action",
        kind="legacy.oracle_install",
        artifact_id="program.image",
        ranges=(ByteRange(offset=8, length=3),),
        byte_count=3,
        reason="disclosed legacy ancestry",
        scope=quarantine_scope,
    )
    legacy_intervention = LegacyOracleInstallIntervention.freeze(
        id="legacy-action",
        scope=quarantine_scope,
        rationale="disclosed legacy ancestry",
        dependencies=("stabilize.program",),
        proof_receipt_digest=digest(b"legacy receipt"),
        preimage_digest=digest(b"legacy preimage"),
        oracle_body_digest=digest(b"legacy oracle"),
        oracle_target="program",
        oracle_address=0,
        ranges=(
            OracleInstallRange(
                preimage_range=ByteRange(offset=8, length=3),
                output_range=ByteRange(offset=8, length=3),
                oracle_range=ByteRange(offset=8, length=3),
            ),
        ),
        byte_count=3,
        maximum_oracle_payload_bytes=3,
    )
    ordinary_proof = proof_report(logical_path="build/<script>.exe")
    final_artifact = ordinary_proof.artifacts[0].model_copy(update={"inputs": ("legacy.payload",)})
    legacy_payload = Artifact(
        id="legacy.payload",
        kind=ArtifactKind.OBJECT,
        logical_path=".reprobit/legacy/legacy-action.obj",
        digest=digest(b"legacy payload"),
        size=14,
        origin=ArtifactOrigin.ORACLE,
        first_party=False,
    )
    legacy_certificate = Certificate(
        id="certificate.legacy-action",
        intervention_id="legacy-action",
        intervention_authority_digest=intervention_authority_digest(legacy_intervention),
        intervention_cost_digest=intervention_cost_row_digest(
            calculate_intervention_cost(legacy_intervention)
        ),
        obligations=(
            ProofObligation(
                name="quarantined_oracle_install",
                passed=True,
                evidence_digest=digest(b"legacy proof"),
            ),
        ),
        artifact_ids=(legacy_payload.id,),
    )
    legacy_evidence_digest = legacy_certificate.obligations[0].evidence_digest
    assert legacy_evidence_digest is not None
    quarantine = quarantine.model_copy(
        update={
            "proof_binding": quarantine_proof_binding(
                quarantine,
                certificate_id=legacy_certificate.id,
                evidence_digest=legacy_evidence_digest,
            )
        }
    )
    verdict = Verdict(
        cold=True,
        byte_exact=True,
        logic_certified=True,
        toolchain_origin=False,
        quarantines=(quarantine,),
    )
    proof = ProofReport.create(
        runtime=ordinary_proof.runtime,
        artifacts=(final_artifact, legacy_payload),
        provenance=(
            ordinary_proof.provenance[0].model_copy(update={"parents": ("legacy.install",)}),
            ProvenanceNode(
                id="legacy.install",
                kind=ProvenanceKind.ORACLE_INSTALL,
                operation="oracle_install",
                origin=ArtifactOrigin.ORACLE,
                artifact_id=legacy_payload.id,
                intervention_id="legacy-action",
                certificate_ids=(legacy_certificate.id,),
            ),
        ),
        certificates=(*ordinary_proof.certificates, legacy_certificate),
        producers=ordinary_proof.producers,
        audit_issues=ordinary_proof.audit_issues,
        adapter=ordinary_proof.adapter,
        providers=ordinary_proof.providers,
        package=ordinary_proof.package,
    )
    baseline = Report.from_bundle(
        bundle("build/<script>.exe"),
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
        ),
        evidence=ordinary_proof.summary,
        proof=ordinary_proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
    )
    report = Report.create(
        project_id=baseline.project_id,
        runtime_binding=proof.runtime.digest,
        toolchain=baseline.toolchain,
        paths=baseline.paths,
        verdict=verdict,
        costs=calculate_cost((stabilize_intervention(), legacy_intervention)),
        targets=baseline.targets,
        evidence=proof.summary,
        proof=proof,
        timings=baseline.timings,
        cache=baseline.cache,
    )
    with pytest.raises(ValidationError, match="oracle costs differ"):
        Report.create(
            project_id=report.project_id,
            runtime_binding=report.runtime_binding,
            toolchain=report.toolchain,
            paths=report.paths,
            verdict=verdict.model_copy(update={"quarantines": ()}),
            costs=report.costs,
            targets=report.targets,
            evidence=report.evidence,
            proof=report.proof,
        )
    disguised_oracle = StateCarrierIntervention(
        id=legacy_intervention.id,
        scope=legacy_intervention.scope,
        rationale="adversarially underpriced oracle fixture",
        carrier="disguised-oracle",
    )
    disguised_costs = calculate_cost((stabilize_intervention(), disguised_oracle))
    disguised_costs = disguised_costs.model_copy(
        update={
            "interventions": tuple(
                item.model_copy(
                    update={
                        "intervention_authority_digest": (
                            legacy_certificate.intervention_authority_digest
                        )
                    }
                )
                if item.intervention_id == legacy_intervention.id
                else item
                for item in disguised_costs.interventions
            )
        }
    )
    disguised_row = next(
        item
        for item in disguised_costs.interventions
        if item.intervention_id == legacy_intervention.id
    )
    disguised_certificate = legacy_certificate.model_copy(
        update={"intervention_cost_digest": intervention_cost_row_digest(disguised_row)}
    )
    disguised_proof = ProofReport.create(
        runtime=proof.runtime,
        artifacts=proof.artifacts,
        provenance=proof.provenance,
        certificates=tuple(
            disguised_certificate if item.id == legacy_certificate.id else item
            for item in proof.certificates
        ),
        producers=proof.producers,
        audit_issues=proof.audit_issues,
        adapter=proof.adapter,
        providers=proof.providers,
        package=proof.package,
    )
    with pytest.raises(ValidationError, match="oracle costs differ from proof oracle installs"):
        Report.create(
            project_id=report.project_id,
            runtime_binding=report.runtime_binding,
            toolchain=report.toolchain,
            paths=report.paths,
            verdict=verdict.model_copy(update={"quarantines": (), "toolchain_origin": True}),
            costs=disguised_costs,
            targets=report.targets,
            evidence=disguised_proof.summary,
            proof=disguised_proof,
        )
    legacy_certificate = next(
        item for item in proof.certificates if item.intervention_id == legacy_intervention.id
    )
    renamed_obligation = legacy_certificate.obligations[0].model_copy(
        update={"name": "fresh_execution"}
    )
    proof_without_oracle_obligation = ProofReport.create(
        runtime=proof.runtime,
        artifacts=proof.artifacts,
        provenance=proof.provenance,
        certificates=tuple(
            item.model_copy(update={"obligations": (renamed_obligation,)})
            if item.id == legacy_certificate.id
            else item
            for item in proof.certificates
        ),
        producers=proof.producers,
        audit_issues=proof.audit_issues,
        adapter=proof.adapter,
        providers=proof.providers,
        package=proof.package,
    )
    with pytest.raises(ValidationError, match="provenance differs from certificate obligations"):
        Report.create(
            project_id=report.project_id,
            runtime_binding=report.runtime_binding,
            toolchain=report.toolchain,
            paths=report.paths,
            verdict=report.verdict,
            costs=report.costs,
            targets=report.targets,
            evidence=proof_without_oracle_obligation.summary,
            proof=proof_without_oracle_obligation,
        )
    mismatched_quarantine = quarantine.model_copy(
        update={
            "scope": Scope(
                target="program",
                translation_unit="main",
                function="other()",
            )
        }
    )
    with pytest.raises(ValidationError, match="cost scope differs"):
        Report.create(
            project_id=report.project_id,
            runtime_binding=report.runtime_binding,
            toolchain=report.toolchain,
            paths=report.paths,
            verdict=verdict.model_copy(update={"quarantines": (mismatched_quarantine,)}),
            costs=report.costs,
            targets=report.targets,
            evidence=report.evidence,
            proof=report.proof,
        )
    rendered = render_report_html(report, canonical_json_href="report.json")
    assert "Disclosed authenticity exceptions remain" in rendered
    assert "1 intervention affects 1 range" in rendered
    assert "3 bytes total" in rendered
    assert "action(s)" not in rendered
    assert "artifact-file" in rendered
    assert "[0x8, 0xb)" in rendered
    assert "disclosed legacy ancestry" in rendered
    assert "<code>build/&lt;script&gt;.exe</code>" in rendered
    assert '<code class="identifier">legacy-action</code>' in rendered
    assert "Portable input trees" in rendered
    assert "header contents" not in rendered
    assert digest(b"header contents").value in rendered
    assert "https://" not in rendered
    assert "src=" not in rendered
    assert '<script type="application/json"' not in rendered
    assert '<a class="machine-link" href="report.json">' in rendered
    assert "complete machine-readable record" in rendered
    assert "Raw function-cost table" in rendered
    assert "Raw intervention table" in rendered
    assert "Shared beneficiaries" in rendered
    assert "Filter by target, TU, or function" in rendered
    assert "Filter by ID, class, target, TU, or function" in rendered
    assert '<details class="advanced"' in rendered
    assert "data-table-filter" in rendered
    assert rendered.index("Exact match, with authenticity exceptions") < rendered.index(
        "Every disclosed reference-derived byte range"
    )

    destination = tmp_path / "report.html"
    write_report_html(
        report,
        destination,
        canonical_json_path=tmp_path / "report.json",
    )
    assert destination.read_text(encoding="utf-8") == rendered

    payload = report.model_dump(mode="json", exclude_computed_fields=True)
    payload["verdict"]["quarantines"][0]["ranges"][0]["offset"] = 9
    with pytest.raises(ValidationError, match="coordinates differ"):
        Report.model_validate_json(canonical_json(payload))


def test_html_uses_only_the_json_link_its_caller_published(tmp_path: Path) -> None:
    proof = proof_report()
    report = Report.from_bundle(
        bundle(),
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
        ),
        evidence=proof.summary,
        proof=proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
    )
    html_path = tmp_path / "pages" / "cold-verification.html"
    json_path = tmp_path / "records" / "cold verification.json"
    href = report_json_href(html_path, json_path)

    assert href == "../records/cold%20verification.json"
    linked = render_report_html(report, canonical_json_href=href)
    assert 'href="../records/cold%20verification.json"' in linked
    assert "<code>../records/cold%20verification.json</code>" in linked

    standalone = render_report_html(report)
    assert 'class="machine-link"' not in standalone
    assert "No machine-readable JSON report is linked from this page." in standalone


def test_report_identity_rejects_public_verdict_and_timing_tampering() -> None:
    proof = proof_report()
    report = Report.from_bundle(
        bundle(),
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
        ),
        evidence=proof.summary,
        proof=proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
        timings=(StageTiming(stage="build", seconds=1.0),),
    )
    rendered = render_report_html(report)
    assert "No interventions were needed" not in rendered
    assert 'id="cost-class-chart-title"' in rendered
    assert 'id="cost-target-chart-title"' in rendered
    assert 'id="cost-hotspot-chart-title"' in rendered
    assert 'id="timing-chart-title"' in rendered
    assert "Stage timing" in rendered
    assert "1.00 s" in rendered
    assert "Cost ranks interventions; it is not elapsed time." in rendered
    assert '<nav class="section-nav" aria-label="Report sections">' in rendered
    assert 'href="#advanced"' in rendered
    assert rendered.count('<svg class="brand-mark"') == 1
    assert "ReproBit · <code>sample</code>" in rendered

    mismatched = report.model_copy(
        update={
            "targets": (report.targets[0].model_copy(update={"byte_exact": False}),),
            "verdict": report.verdict.model_copy(update={"byte_exact": False}),
        }
    )
    mismatched_html = render_report_html(mismatched)
    assert "Inspect <code>program</code> before changing interventions." in mismatched_html
    assert "target comparison records" in mismatched_html
    assert '<a href="#outcome-details">Open comparison records</a>' in mismatched_html

    logic_failed = report.model_copy(
        update={
            "verdict": report.verdict.model_copy(update={"logic_certified": False}),
        }
    )
    logic_failed_html = render_report_html(logic_failed)
    assert "Exact match, with failed logic checks" in logic_failed_html
    assert "Resolve the failed logic checks" in logic_failed_html
    assert "already satisfies identity and authenticity" not in logic_failed_html

    not_cold = report.model_copy(
        update={
            "verdict": report.verdict.model_copy(update={"cold": False}),
        }
    )
    not_cold_html = render_report_html(not_cold)
    assert "Exact match, but not built from scratch" in not_cold_html
    assert "Confirm the match with a fresh build" in not_cold_html
    assert "already satisfies identity and authenticity" not in not_cold_html

    for field, value in (("toolchain_origin", False), ("logic_certified", False)):
        payload = report.model_dump(mode="json", exclude_computed_fields=True)
        payload["verdict"][field] = value
        with pytest.raises(ValidationError, match="run_id does not bind"):
            Report.model_validate_json(canonical_json(payload))
    payload = report.model_dump(mode="json", exclude_computed_fields=True)
    payload["timings"][0]["seconds"] = 2.0
    with pytest.raises(ValidationError, match="run_id does not bind"):
        Report.model_validate_json(canonical_json(payload))


def test_evidence_digest_changes_final_run_identity() -> None:
    verdict = Verdict(
        cold=True,
        byte_exact=True,
        logic_certified=True,
        toolchain_origin=True,
    )
    first_proof = proof_report(b"first")
    second_proof = proof_report(b"second")
    assert first_proof.runtime == second_proof.runtime
    binding = first_proof.runtime.digest
    first = Report.from_bundle(
        bundle(),
        verdict,
        evidence=evidence_summary(first_proof),
        proof=first_proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
        run_binding=binding,
    )
    second = Report.from_bundle(
        bundle(),
        verdict,
        evidence=evidence_summary(second_proof),
        proof=second_proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
        run_binding=binding,
    )
    assert first.proof.digest != second.proof.digest
    assert first.run_id != second.run_id


def test_report_writer_refuses_a_redirected_destination(tmp_path: Path) -> None:
    proof = proof_report()
    report = Report.from_bundle(
        bundle(),
        Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=True,
        ),
        evidence=proof.summary,
        proof=proof,
        target_results={"program": True},
        target_artifacts={"program": (100, digest(b"oracle"))},
    )
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"preserve me")
    destination = tmp_path / "reports" / "report.json"
    destination.parent.mkdir()
    destination.symlink_to(outside)
    with pytest.raises(OSError):
        write_report_json(report, destination)
    assert outside.read_bytes() == b"preserve me"


def test_proof_payload_refuses_an_unbound_digest() -> None:
    proof = proof_report()
    payload = proof.model_dump(exclude_computed_fields=True)
    payload["digest"] = digest(b"forged")
    with pytest.raises(ValidationError, match="does not bind"):
        ProofReport.model_validate(payload)


def test_proof_payload_requires_the_runtime_receipt_preimage() -> None:
    payload = proof_report().model_dump(exclude_computed_fields=True)
    del payload["runtime"]
    with pytest.raises(ValidationError, match="runtime"):
        ProofReport.model_validate(payload)


def test_proof_payload_rejects_object_work_after_an_image_link() -> None:
    proof = proof_report()
    image = proof.artifacts[0]
    late_object = Artifact(
        id="late.object",
        kind=ArtifactKind.OBJECT,
        logical_path="build/late.obj",
        digest=digest(b"late object"),
        size=11,
        origin=ArtifactOrigin.COMPOSED,
        inputs=(image.id,),
    )
    late_node = ProvenanceNode(
        id="late.compose",
        kind=ProvenanceKind.PRODUCER,
        operation="compose",
        origin=ArtifactOrigin.COMPOSED,
        parents=(proof.provenance[0].id,),
        artifact_id=late_object.id,
    )
    with pytest.raises(ValidationError, match="causality runs after link"):
        ProofReport.create(
            runtime=proof.runtime,
            artifacts=(*proof.artifacts, late_object),
            provenance=(*proof.provenance, late_node),
            certificates=proof.certificates,
            producers=proof.producers,
            audit_issues=proof.audit_issues,
            adapter=proof.adapter,
            providers=proof.providers,
            package=proof.package,
        )


def test_semantic_claim_must_name_the_object_receipt_in_its_statement() -> None:
    proof = proof_report()
    candidate = Artifact(
        id="candidate.object",
        kind=ArtifactKind.OBJECT,
        logical_path="build/candidate.obj",
        digest=digest(b"actual candidate"),
        size=16,
        origin=ArtifactOrigin.COMPOSED,
    )
    input_statement = {"seed": {"digest": digest(b"seed").model_dump(mode="json"), "size": 4}}
    output_statement = {
        "candidate": {
            "digest": digest(b"different candidate").model_dump(mode="json"),
            "size": candidate.size,
        }
    }
    semantic = SemanticProof(
        family="state_carrier",
        validator_id="fixture-validator",
        validator_digest=digest(b"validator"),
        input_statement_digest=Digest.from_bytes(canonical_json(input_statement)),
        output_statement_digest=Digest.from_bytes(canonical_json(output_statement)),
        obligations=("candidate-shape",),
        evidence_digest=digest(b"semantic evidence"),
        input_statement=input_statement,
        output_statement=output_statement,
        artifact_claims=(
            SemanticArtifactClaim(
                artifact_id=candidate.id,
                relation="output",
                digest=candidate.digest,
                size=candidate.size,
            ),
        ),
    )
    certificate = Certificate(
        id="certificate.candidate",
        intervention_id="candidate.transform",
        intervention_authority_digest=digest(b"candidate transform authority"),
        intervention_cost_digest=digest(b"candidate transform cost"),
        obligations=(
            ProofObligation(
                name="semantic-equivalence",
                passed=True,
                evidence_digest=semantic.evidence_digest,
            ),
        ),
        artifact_ids=(candidate.id,),
        semantic_proofs=(semantic,),
    )
    with pytest.raises(ValidationError, match="semantic claim is absent"):
        ProofReport.create(
            runtime=proof.runtime,
            artifacts=(*proof.artifacts, candidate),
            provenance=(
                *proof.provenance,
                ProvenanceNode(
                    id="candidate.transform",
                    kind=ProvenanceKind.INTERVENTION,
                    operation="candidate_transform",
                    origin=ArtifactOrigin.COMPOSED,
                    artifact_id=candidate.id,
                    intervention_id="candidate.transform",
                    certificate_ids=(certificate.id,),
                ),
            ),
            certificates=(*proof.certificates, certificate),
            producers=proof.producers,
            audit_issues=proof.audit_issues,
            adapter=proof.adapter,
            providers=proof.providers,
            package=proof.package,
        )
