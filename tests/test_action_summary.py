from __future__ import annotations

import ast
import inspect
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest

import reprobit.action_summary as action_summary_module
import reprobit.cli as cli_module
import reprobit.engine as engine_module
from reprobit.action_summary import main, publish_action_completion
from reprobit.build import BuildPlan
from reprobit.cli import _command_verify
from reprobit.cli_output import CLIOutput
from reprobit.costs import CostBreakdown
from reprobit.model import (
    Artifact,
    ArtifactKind,
    ArtifactOrigin,
    AuthenticityPolicy,
    ByteRange,
    Certificate,
    Digest,
    ProofObligation,
    ProvenanceKind,
    ProvenanceNode,
    Quarantine,
    Verdict,
    quarantine_proof_binding,
)
from reprobit.report import (
    AuditIssueSummary,
    BuildExecutionSummary,
    ComponentIdentity,
    ExecutionFileReceipt,
    LogicalPathSummary,
    ProofReport,
    Report,
    RuntimeBindingPreimage,
    RuntimeProofBinding,
    TargetComparisonSummary,
    TargetSummary,
    ToolchainSummary,
)
from reprobit.report_io import write_report_html, write_report_json
from reprobit.schema import MsvcRelease, ProducerGraphBuildAdapter
from reprobit.strict_json import canonical_json


def _fixture_report() -> Report:
    digest = Digest.from_bytes(b"fixture")
    target_path = "build/sample.exe"
    runtime = RuntimeProofBinding.create(
        RuntimeBindingPreimage(
            build=BuildExecutionSummary(
                cold=True,
                inputs=(),
                outputs=(
                    ExecutionFileReceipt(
                        path=target_path,
                        digest=digest,
                        size=2,
                        fresh=True,
                        device=1,
                        inode=1,
                    ),
                ),
                steps=(),
            ),
            targets=(
                TargetComparisonSummary(
                    id="sample",
                    logical_artifact=target_path,
                    artifact=target_path,
                    candidate_digest=digest,
                    candidate_size=2,
                    oracle_digest=digest,
                    oracle_size=2,
                    byte_exact=True,
                    candidate_device=1,
                    candidate_inode=1,
                ),
            ),
        )
    )
    quarantine = Quarantine(
        id="legacy",
        kind="legacy.oracle_install",
        artifact_id="sample-image",
        ranges=(ByteRange(offset=1, length=2),),
        byte_count=2,
        reason="fixture quarantine",
    )
    legacy_payload = Artifact(
        id="legacy-payload",
        kind=ArtifactKind.OBJECT,
        logical_path=".reprobit/legacy/legacy.obj",
        digest=digest,
        size=2,
        origin=ArtifactOrigin.ORACLE,
        first_party=False,
    )
    sample_image = Artifact(
        id="sample-image",
        kind=ArtifactKind.IMAGE,
        logical_path=target_path,
        digest=digest,
        size=2,
        origin=ArtifactOrigin.COMPOSED,
        inputs=(legacy_payload.id,),
    )
    legacy_certificate = Certificate(
        id="certificate.legacy",
        intervention_id="legacy",
        obligations=(
            ProofObligation(
                name="quarantined_oracle_install",
                passed=True,
                evidence_digest=digest,
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
    proof = ProofReport.create(
        runtime=runtime,
        artifacts=(legacy_payload, sample_image),
        provenance=(
            ProvenanceNode(
                id="legacy.install",
                kind=ProvenanceKind.ORACLE_INSTALL,
                operation="oracle_install",
                origin=ArtifactOrigin.ORACLE,
                artifact_id=legacy_payload.id,
                intervention_id="legacy",
                certificate_ids=(legacy_certificate.id,),
            ),
            ProvenanceNode(
                id="sample.publish",
                kind=ProvenanceKind.INTERVENTION,
                operation="publish",
                origin=ArtifactOrigin.COMPOSED,
                parents=("legacy.install",),
                artifact_id=sample_image.id,
                intervention_id="legacy",
            ),
        ),
        certificates=(legacy_certificate,),
        producers=(),
        audit_issues=(
            AuditIssueSummary(
                claim="origin",
                code="fixture-quarantine",
                message="fixture intentionally omits non-quarantined origin evidence",
            ),
        ),
        adapter=ComponentIdentity(
            role="adapter",
            id="fixture-adapter",
            implementation="fixture.Adapter",
            package="fixture",
            version="1",
            digest=digest,
        ),
        providers=(),
        package=ComponentIdentity(
            role="package",
            id="fixture",
            implementation="fixture",
            package="fixture",
            version="1",
            digest=digest,
        ),
    )
    return Report.create(
        project_id="sample",
        runtime_binding=runtime.digest,
        toolchain=ToolchainSummary(profile="compiler-42", release=MsvcRelease.V4_2, tools=()),
        paths=LogicalPathSummary(
            profile="paths-v1",
            source="R:\\src",
            build="R:\\build",
            toolchain="R:\\tools",
        ),
        verdict=Verdict(
            cold=True,
            byte_exact=True,
            logic_certified=True,
            toolchain_origin=False,
            quarantines=(quarantine,),
        ),
        costs=CostBreakdown(
            model_version=2,
            project_total=0,
            unallocated_shared_cost=0,
            by_class=(),
            by_target=(),
            by_function=(),
            interventions=(),
        ),
        targets=(
            TargetSummary(
                id="sample",
                artifact=target_path,
                candidate_size=2,
                candidate_digest=digest,
                oracle_size=2,
                oracle_digest=digest,
                byte_exact=True,
            ),
        ),
        evidence=proof.summary,
        proof=proof,
    )


def test_action_summary_writes_outputs(tmp_path: Path, monkeypatch: object) -> None:
    report = tmp_path / "report.json"
    fixture = _fixture_report()
    write_report_json(fixture, report)
    write_report_html(fixture, report.with_suffix(".html"))
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))  # type: ignore[attr-defined]
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))  # type: ignore[attr-defined]
    monkeypatch.setenv("REPROBIT_ACCEPTED", "true")  # type: ignore[attr-defined]

    assert main([str(report)]) == 0
    received = output.read_text(encoding="utf-8")
    assert "report-produced=true" in received
    assert "accepted=true" in received
    assert "clean=false" in received
    assert "byte-exact=true" in received
    assert "toolchain-origin=false" in received
    summary_text = summary.read_text(encoding="utf-8")
    assert "not clean" in summary_text
    assert "| Intervention cost | 0 relative points |" in summary_text


def test_action_summary_rejects_output_path_line_breaks(tmp_path: Path) -> None:
    assert main([str(tmp_path / "report\ninjected=value.json")]) == 2


def test_action_summary_publishes_safe_outputs_when_report_is_missing(
    tmp_path: Path, monkeypatch: object
) -> None:
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))  # type: ignore[attr-defined]
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))  # type: ignore[attr-defined]
    report = tmp_path / "absent" / "report.json"

    assert main(["--allow-missing", str(report)]) == 0
    received = output.read_text(encoding="utf-8")
    assert "report-produced=false" in received
    assert "accepted=false" in received
    assert "byte-exact=\n" in received
    assert "total-cost=\n" in received
    assert f"report-json={report}" in received
    assert "before it could publish" in summary.read_text(encoding="utf-8")


def test_action_summary_refuses_a_stale_report_from_another_invocation(
    tmp_path: Path, monkeypatch: object
) -> None:
    report_path = tmp_path / "report.json"
    receipt_path = tmp_path / "completion.json"
    report = _fixture_report()
    write_report_json(report, report_path)
    write_report_html(report, report_path.with_suffix(".html"))
    previous_nonce = "1" * 64
    current_nonce = "2" * 64
    publish_action_completion(
        report,
        report_path=report_path,
        html_path=report_path.with_suffix(".html"),
        receipt_path=receipt_path,
        nonce=previous_nonce,
    )

    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))  # type: ignore[attr-defined]
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))  # type: ignore[attr-defined]
    assert (
        main(
            [
                "--allow-missing",
                "--receipt",
                str(receipt_path),
                "--nonce",
                current_nonce,
                str(report_path),
            ]
        )
        == 0
    )
    received = output.read_text(encoding="utf-8")
    assert "report-produced=false" in received
    assert "clean=\n" in received
    assert "total-cost=\n" in received


def test_action_completion_requires_the_matching_html_report(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report = _fixture_report()
    write_report_json(report, report_path)
    with pytest.raises(OSError):
        publish_action_completion(
            report,
            report_path=report_path,
            html_path=report_path.with_suffix(".html"),
            receipt_path=tmp_path / "completion.json",
            nonce="3" * 64,
        )


def test_policy_rejection_still_publishes_current_negative_report(
    tmp_path: Path, monkeypatch: object
) -> None:
    report_path = tmp_path / "report.json"
    receipt_path = tmp_path / "completion.json"
    report = _fixture_report()
    write_report_json(report, report_path)
    write_report_html(report, report_path.with_suffix(".html"))
    publish_action_completion(
        report,
        report_path=report_path,
        html_path=report_path.with_suffix(".html"),
        receipt_path=receipt_path,
        nonce="4" * 64,
    )
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))  # type: ignore[attr-defined]
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))  # type: ignore[attr-defined]
    monkeypatch.setenv("REPROBIT_ACCEPTED", "false")  # type: ignore[attr-defined]
    assert (
        main(
            [
                "--receipt",
                str(receipt_path),
                "--nonce",
                "4" * 64,
                str(report_path),
            ]
        )
        == 0
    )
    received = output.read_text(encoding="utf-8")
    assert "report-produced=true" in received
    assert "accepted=false" in received
    assert "quarantined=true" in received


def test_action_refuses_tampered_authorized_quarantine(tmp_path: Path, monkeypatch: object) -> None:
    report_path = tmp_path / "report.json"
    receipt_path = tmp_path / "completion.json"
    report = _fixture_report()
    write_report_json(report, report_path)
    write_report_html(report, report_path.with_suffix(".html"))
    publish_action_completion(
        report,
        report_path=report_path,
        html_path=report_path.with_suffix(".html"),
        receipt_path=receipt_path,
        nonce="5" * 64,
    )
    payload = report.model_dump(mode="json", exclude_computed_fields=True)
    payload["verdict"]["quarantines"][0]["ranges"][0]["offset"] = 8
    report_path.write_bytes(canonical_json(payload))
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))  # type: ignore[attr-defined]
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))  # type: ignore[attr-defined]
    assert (
        main(
            [
                "--allow-missing",
                "--receipt",
                str(receipt_path),
                "--nonce",
                "5" * 64,
                str(report_path),
            ]
        )
        == 0
    )
    assert "report-produced=false" in output.read_text(encoding="utf-8")


def test_composite_action_preserves_reports_when_verification_fails() -> None:
    action = (Path(__file__).parents[1] / "action.yml").read_text(encoding="utf-8")
    assert "id: verification\n      continue-on-error: true" in action
    assert "id: summary\n      if: always()" in action
    assert "if: always() && steps.verification.outcome == 'failure'" in action
    assert "--execute-probe" in action
    assert "targets:" not in action
    assert 'policy_args+=(--policy "$REPROBIT_POLICY")' in action
    assert "--allow-missing" in action
    assert "--mark-complete" not in action
    assert '--action-receipt "$REPROBIT_ACTION_RECEIPT"' in action
    assert '--action-nonce "$REPROBIT_ACTION_NONCE"' in action
    assert "steps.invocation.outputs.nonce" in action
    assert "steps.invocation.outputs.receipt" in action
    assert "compiler-transport:" in action
    assert "resource-transport:" in action
    assert "compiler-transport and resource-transport must be supplied together" in action
    assert '"${transport_args[@]}"' in action
    assert "toolchain-profile:" not in action
    assert "REPROBIT_ACCEPTED: ${{ steps.verification.outcome == 'success' }}" in action


def test_action_completion_is_outside_prepared_cleanup_scope() -> None:
    tree = ast.parse(inspect.getsource(_command_verify))
    parents: dict[ast.AST, ast.AST] = {
        child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
    }
    publication = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "publish_action_completion"
    )
    ancestor = parents[publication]
    while ancestor is not tree:
        if isinstance(ancestor, ast.With):
            assert all(
                not (
                    (
                        isinstance(item.context_expr, ast.Call)
                        and isinstance(item.context_expr.func, ast.Name)
                        and item.context_expr.func.id == "ExitStack"
                    )
                    or (isinstance(item.context_expr, ast.Name) and item.context_expr.id == "arena")
                )
                for item in ancestor.items
            )
        ancestor = parents[ancestor]


def test_prepared_cleanup_failure_never_publishes_action_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = tmp_path / "reference.bin"
    reference.write_bytes(b"fixture")
    target = SimpleNamespace(
        id="sample",
        artifact="build/sample.exe",
        oracle="reference.bin",
    )
    bundle = SimpleNamespace(
        spec=SimpleNamespace(
            build=ProducerGraphBuildAdapter(),
            authenticity=SimpleNamespace(policy=AuthenticityPolicy.CLEAN),
            state_dir=".reprobit-state",
            targets=(target,),
        )
    )

    class Executor:
        def bind_legacy_oracles(self, _oracles: object) -> None:
            pass

    class Prepared:
        executor = Executor()
        evidence_provider = SimpleNamespace(name="fixture-provider")
        plan = BuildPlan(())

        def close(self) -> None:
            raise RuntimeError("fixture cleanup failure")

    prepared = Prepared()
    monkeypatch.setattr(cli_module, "load_project_tree", lambda _root: bundle)
    monkeypatch.setattr(
        cli_module,
        "_prepare_producer_graph_run",
        lambda *_args, **_kwargs: prepared,
    )
    monkeypatch.setattr(
        engine_module.ReproductionEngine,
        "run",
        lambda _self, _request: SimpleNamespace(report=_fixture_report()),
    )
    published = False

    def publish(*_args: object, **_kwargs: object) -> None:
        nonlocal published
        published = True

    monkeypatch.setattr(action_summary_module, "publish_action_completion", publish)
    receipt = tmp_path / "completion.json"
    arguments = SimpleNamespace(
        project=str(tmp_path),
        policy=None,
        report_dir="reports",
        report_json=None,
        report_html=None,
        action_receipt=str(receipt),
        action_nonce="6" * 64,
        keep_workspace="on-failure",
        jobs=1,
    )
    output = CLIOutput("text", StringIO(), StringIO())
    with pytest.raises(RuntimeError, match="fixture cleanup failure"):
        _command_verify(arguments, output)
    assert not published
    assert not receipt.exists()
