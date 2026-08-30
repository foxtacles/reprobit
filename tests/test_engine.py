from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import CodeType, ModuleType, SimpleNamespace
from typing import cast

import pytest

import reprobit.engine as engine_module
from reprobit.artifacts import digest_bytes
from reprobit.build import BuildPlan, BuildStep
from reprobit.classic.overlay_document import render_classic_overlay_declarations
from reprobit.costs import calculate_intervention_cost, intervention_cost_row_digest
from reprobit.engine import (
    BuildPlanExecutor,
    EngineRequest,
    ReportDestinations,
    ReproductionEngine,
)
from reprobit.evidence_audit import EvidenceAuditor, EvidenceClaim
from reprobit.execution import (
    BuildExecutionReceipt,
    EngineError,
    FileReceipt,
    ProducerAttestation,
    ProducerKind,
    RuntimeEvidence,
    RuntimeEvidenceContext,
    TargetOracle,
    classic_semantic_obligation_name,
)
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
    Scope,
)
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    InputTreeReceipt,
    InterventionDocument,
    LegacyOracleInstallIntervention,
    LockedTool,
    LogicalPathProfile,
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
from reprobit.strict_json import JsonValue
from reprobit.toolchains import portable_tree_receipt
from reprobit.verify import seal_file_oracle


class _FixtureEvidenceProvider:
    name = "fixture-provider"

    def __init__(
        self,
        artifacts: tuple[Artifact, ...],
        provenance: tuple[ProvenanceNode, ...],
        certificates: tuple[Certificate, ...],
    ) -> None:
        self.artifacts = artifacts
        self.provenance = provenance
        self.certificates = certificates

    def issue(self, context: RuntimeEvidenceContext) -> RuntimeEvidence:
        tool = context.bundle.toolchain_lock.tools[0]
        return RuntimeEvidence(
            provider_id=self.name,
            run_binding=context.run_binding,
            artifacts=self.artifacts,
            provenance=self.provenance,
            certificates=self.certificates,
            producers=tuple(
                ProducerAttestation(
                    id=(
                        "producer.seed"
                        if artifact.id == "seed.object"
                        else f"producer.{artifact.id}"
                    ),
                    artifact_id=artifact.id,
                    step_id="build.program",
                    producer_kind=(
                        ProducerKind.COMPILER
                        if artifact.kind is ArtifactKind.OBJECT
                        else ProducerKind.LINKER
                    ),
                    tool_id=tool.id,
                    tool_digest=tool.digest,
                    artifact_digest=artifact.digest,
                    artifact_size=artifact.size,
                )
                for artifact in self.artifacts
                if artifact.producer is not None
            ),
        )


def _builtin_identity_request(*, paired: bool) -> EngineRequest:
    from reprobit.classic_runtime import (
        ClassicProducerGraphBuildExecutor,
        ClassicProducerGraphRuntimeEvidenceProvider,
    )

    executor = object.__new__(ClassicProducerGraphBuildExecutor)
    provider = object.__new__(ClassicProducerGraphRuntimeEvidenceProvider)
    executor.evidence_provider = (
        provider if paired else object.__new__(ClassicProducerGraphRuntimeEvidenceProvider)
    )
    request = cast(
        EngineRequest,
        SimpleNamespace(
            build_executor=executor,
            evidence_providers=(provider,),
        ),
    )
    return request


def test_builtin_identity_accepts_the_executor_owned_evidence_provider() -> None:
    request = _builtin_identity_request(paired=True)

    identity = engine_module._resolve_builtin_identity(request)

    assert identity.providers[0].id == "classic-msvc-producer-graph-v1"


def test_builtin_identity_rejects_an_evidence_provider_from_another_executor() -> None:
    request = _builtin_identity_request(paired=False)

    with pytest.raises(EngineError, match="not paired with its executor"):
        engine_module._resolve_builtin_identity(request)


def test_module_digest_ignores_runtime_string_interning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_name = f"_reprobit_identity_{tmp_path.name.replace('-', '_')}"
    token = "-".join(("runtime", "path", tmp_path.name, "segment"))
    source = f"class IdentityFixture:\n    def value(self):\n        return {token!r}\n"
    source_path = tmp_path / "identity_fixture.py"
    source_path.write_text(source, encoding="utf-8")
    module = ModuleType(module_name)
    module.__file__ = str(source_path)
    monkeypatch.setitem(sys.modules, module_name, module)
    exec(compile(source, str(source_path), "exec"), module.__dict__)
    component = cast(type[object], module.__dict__["IdentityFixture"])
    method = vars(component)["value"]
    code = getattr(method, "__code__", None)
    assert isinstance(code, CodeType)
    literal = next(item for item in code.co_consts if item == token)
    assert isinstance(literal, str)

    before = engine_module._module_digest(component)
    # CPython 3.11 pathlib interns path components in place. Explicitly intern
    # the fresh literal as well so the regression remains effective on newer
    # interpreters whose pathlib implementation no longer does so.
    _ = Path("root") / literal
    assert sys.intern(literal) is literal
    after = engine_module._module_digest(component)

    assert after == before
    method.__code__ = (lambda _self: "changed loaded code").__code__
    assert engine_module._module_digest(component) != before


def test_builtin_identity_drift_message_names_the_changed_component() -> None:
    identity = engine_module._resolve_builtin_identity(_builtin_identity_request(paired=True))
    observed_digest = Digest.from_bytes(b"changed adapter implementation")
    observed = engine_module._ExecutionIdentity(
        adapter=identity.adapter.model_copy(update={"digest": observed_digest}),
        providers=identity.providers,
        package=identity.package,
    )

    message = engine_module._builtin_identity_drift_message(identity, observed)

    assert (
        "adapter expected 'reprobit.classic_runtime.ClassicProducerGraphBuildExecutor'" in message
    )
    assert f"at sha256:{identity.adapter.digest.value}" in message
    assert f"at sha256:{observed_digest.value}" in message


def _bundle(
    root: Path,
    expected: bytes,
    *,
    certificate_passed: bool = True,
    stale_origin: bool = False,
    oracle_digest: Digest | None = None,
) -> tuple[ProjectBundle, _FixtureEvidenceProvider]:
    target = TargetSpec(id="program", artifact="out/program.bin", oracle="reference.bin")
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
        targets=(target,),
    )
    toolchain = ToolchainLock(
        schema_version=3,
        profile="compiler-42",
        release=MsvcRelease.V4_2,
        tools=(
            LockedTool(
                id="compiler",
                path="tools/compiler.exe",
                digest=Digest.from_bytes(b"compiler"),
                size=8,
            ),
        ),
    )
    intervention = StateCarrierIntervention(
        id="stabilize.state",
        scope=Scope(target="program"),
        rationale="stabilize compiler state",
        carrier="state.carrier",
    )
    seed_origin = ArtifactOrigin.STALE_REFUSED if stale_origin else ArtifactOrigin.FRESH_SEED
    artifacts = (
        Artifact(
            id="seed.object",
            kind=ArtifactKind.OBJECT,
            logical_path="state/seed.obj",
            digest=Digest.from_bytes(b"seed"),
            size=4,
            origin=seed_origin,
            producer="compiler",
        ),
        Artifact(
            id="program.image",
            kind=ArtifactKind.IMAGE,
            logical_path=target.artifact,
            digest=Digest.from_bytes(expected),
            size=len(expected),
            origin=ArtifactOrigin.COMPOSED,
            producer="compiler",
            inputs=("seed.object",),
        ),
    )
    certificate = Certificate(
        id="certificate.state",
        intervention_id=intervention.id,
        intervention_authority_digest=intervention_authority_digest(intervention),
        intervention_cost_digest=intervention_cost_row_digest(
            calculate_intervention_cost(intervention)
        ),
        obligations=(
            ProofObligation(
                name="output_gate",
                passed=certificate_passed,
                evidence_digest=Digest.from_bytes(b"proof"),
            ),
        ),
        artifact_ids=("program.image",),
    )
    provenance = (
        ProvenanceNode(
            id="seed.origin",
            kind=ProvenanceKind.TOOLCHAIN,
            operation="compile",
            origin=seed_origin,
            artifact_id="seed.object",
        ),
        ProvenanceNode(
            id="program.compose",
            kind=ProvenanceKind.INTERVENTION,
            operation="compose",
            origin=ArtifactOrigin.COMPOSED,
            parents=("seed.origin",),
            artifact_id="program.image",
            intervention_id=intervention.id,
            certificate_ids=(certificate.id,),
        ),
    )
    bundle = ProjectBundle(
        root=str(root),
        spec=spec,
        toolchain_lock=toolchain,
        intervention_documents=(
            InterventionDocument(
                schema_version=3,
                target_id="program",
                interventions=(intervention,),
            ),
        ),
        proof_documents=(
            ProofDocument(
                schema_version=3,
                target_id="program",
            ),
        ),
        oracle_documents=(
            OracleDocument(
                schema_version=3,
                target_id="program",
                image_size=len(expected),
                image_digest=oracle_digest or Digest.from_bytes(expected),
            ),
        ),
    )
    return bundle, _FixtureEvidenceProvider(artifacts, provenance, (certificate,))


def _write_plan(root: Path, payload: bytes) -> BuildPlan:
    source = root / "source.txt"
    source.write_text("declared input\n", encoding="utf-8")
    output = root / "out" / "program.bin"
    seed = root / "state" / "seed.obj"
    script = (
        "from pathlib import Path;import sys;"
        "p=Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True);"
        "p.write_bytes(bytes.fromhex(sys.argv[2]));"
        "s=Path(sys.argv[3]);s.parent.mkdir(parents=True,exist_ok=True);"
        "s.write_bytes(b'seed')"
    )
    return BuildPlan(
        (
            BuildStep(
                "build.program",
                (sys.executable, "-c", script, str(output), payload.hex(), str(seed)),
                str(root),
                inputs=(str(source),),
                outputs=(str(output), str(seed)),
                timeout_seconds=20,
            ),
        )
    )


def test_report_publication_removes_stale_commit_when_target_changes_mid_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "out/program.bin"
    target.parent.mkdir()
    target.write_bytes(b"candidate")
    report_json = tmp_path / "reports/report.json"
    report_html = tmp_path / "reports/report.html"
    original_publish = engine_module.atomic_publish_relative
    published = False

    def publish_then_mutate(root: Path, relative: str, payload: bytes):
        nonlocal published
        snapshot = original_publish(root, relative, payload)
        if not published:
            target.write_bytes(b"same-inode mutation")
            published = True
        return snapshot

    monkeypatch.setattr(
        engine_module,
        "atomic_publish_relative",
        publish_then_mutate,
    )

    def reseal() -> None:
        if target.read_bytes() != b"candidate":
            raise EngineError("target changed")

    with pytest.raises(EngineError, match="target changed"):
        engine_module._publish_report_payloads(
            {
                report_json: b"{}",
                report_html: b"<html></html>",
            },
            final_reseal=reseal,
        )
    assert not report_json.exists()
    assert not report_html.exists()


def test_package_identity_is_revalidated_before_build_side_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"exact output"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, provider = _bundle(tmp_path, expected)

    with seal_file_oracle(reference) as oracle:
        request = EngineRequest(
            bundle=bundle,
            build_plan=_write_plan(tmp_path, expected),
            project_root=tmp_path,
            run_root=tmp_path / "state/run",
            oracles=(TargetOracle("program", oracle),),
            evidence_providers=(provider,),
        )
        unsafe = engine_module._resolve_unsafe_identity(request)
        identity = engine_module._ExecutionIdentity(
            adapter=unsafe.adapter,
            providers=unsafe.providers,
            package=unsafe.package,
        )
        received: list[Digest] = []

        def reject_changed_package(digest: Digest) -> None:
            received.append(digest)
            raise RuntimeError("ReproBit package implementation changed during execution")

        monkeypatch.setattr(
            engine_module,
            "revalidate_package_implementation",
            reject_changed_package,
        )

        with pytest.raises(EngineError, match="implementation changed"):
            ReproductionEngine()._run(request, identity)

    assert received == [identity.package.digest]
    assert not (tmp_path / "out/program.bin").exists()


def test_package_identity_change_during_report_commit_rolls_reports_back(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"exact output"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    reports = ReportDestinations(tmp_path / "report.json", tmp_path / "report.html")
    bundle, provider = _bundle(tmp_path, expected)

    with seal_file_oracle(reference) as oracle:
        request = EngineRequest(
            bundle=bundle,
            build_plan=_write_plan(tmp_path, expected),
            project_root=tmp_path,
            run_root=tmp_path / "state/run",
            oracles=(TargetOracle("program", oracle),),
            evidence_providers=(provider,),
            reports=reports,
        )
        unsafe = engine_module._resolve_unsafe_identity(request)
        identity = engine_module._ExecutionIdentity(
            adapter=unsafe.adapter,
            providers=unsafe.providers,
            package=unsafe.package,
        )
        received: list[Digest] = []

        def reject_after_report_publish(digest: Digest) -> None:
            received.append(digest)
            if len(received) == 3:
                raise RuntimeError("ReproBit package implementation changed during execution")

        monkeypatch.setattr(
            engine_module,
            "revalidate_package_implementation",
            reject_after_report_publish,
        )
        monkeypatch.setattr(
            engine_module,
            "_resolve_builtin_identity",
            lambda _request: identity,
        )

        with pytest.raises(EngineError, match="implementation changed"):
            ReproductionEngine()._run(request, identity)

    assert received == [identity.package.digest] * 3
    assert reports.json is not None and not reports.json.exists()
    assert reports.html is not None and not reports.html.exists()


def test_toolchain_header_root_is_bound_to_complete_portable_tree_lock(
    tmp_path: Path,
) -> None:
    bundle, _provider = _bundle(tmp_path, b"exact")
    tree_root = tmp_path / "toolchain/include"
    tree_root.mkdir(parents=True)
    header = tree_root / "stdio.h"
    header.write_bytes(b"#define EOF (-1)\n")
    received = portable_tree_receipt(tree_root, "include")
    tree = InputTreeReceipt(
        id="compiler-includes",
        path="include",
        entry_count=received.entry_count,
        max_depth=received.max_depth,
        membership_digest=Digest(value=received.membership_sha256),
        content_digest=Digest(value=received.content_sha256),
    )
    bundle = bundle.model_copy(
        update={"toolchain_lock": bundle.toolchain_lock.model_copy(update={"input_trees": (tree,)})}
    )
    artifact = Artifact(
        id="toolchain.header",
        kind=ArtifactKind.TOOLCHAIN,
        logical_path=r"R:\toolchain\include\stdio.h",
        digest=Digest.from_bytes(header.read_bytes()),
        size=header.stat().st_size,
        origin=ArtifactOrigin.FRESH_SEED,
        receipt_path=str(header.resolve()),
    )
    node = ProvenanceNode(
        id="toolchain.header.root",
        kind=ProvenanceKind.TOOLCHAIN,
        operation="locked_toolchain",
        origin=ArtifactOrigin.FRESH_SEED,
        artifact_id=artifact.id,
    )
    build = BuildExecutionReceipt(
        cold=True,
        inputs=(
            FileReceipt(
                header,
                artifact.digest,
                artifact.size,
                fresh=False,
            ),
        ),
        outputs=(),
        steps=(),
    )
    issues: list[tuple[EvidenceClaim, str, str]] = []
    EvidenceAuditor._validate_input_roots(
        bundle,
        build,
        {artifact.id: artifact},
        {node.id: node},
        lambda claim, code, message: issues.append((claim, code, message)),
    )
    assert issues == []

    injected = tree_root / "injected.h"
    injected.write_bytes(b"host injection\n")
    issues.clear()
    EvidenceAuditor._validate_input_roots(
        bundle,
        build,
        {artifact.id: artifact},
        {node.id: node},
        lambda claim, code, message: issues.append((claim, code, message)),
    )
    assert [code for _claim, code, _message in issues] == ["toolchain-root-lock"]


def test_engine_runs_build_verifies_evidence_and_materializes_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = b"exact output"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    state_root = tmp_path / ".reprobit-state"
    reports = ReportDestinations(
        state_root / "reports/report.json",
        state_root / "reports/report.html",
    )
    bundle, provider = _bundle(tmp_path, expected)
    publication_leases: list[Path] = []

    @contextmanager
    def observe_publication_lease(root: Path) -> Iterator[None]:
        publication_leases.append(root)
        yield

    monkeypatch.setattr(
        engine_module,
        "report_publication_lease",
        observe_publication_lease,
    )

    with seal_file_oracle(reference) as oracle:
        result = ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
                jobs=2,
                reports=reports,
            )
        )

    assert not result.verdict.clean
    assert result.build.cold
    assert result.build.outputs[0].fresh
    assert result.targets[0].comparison.byte_exact
    assert result.evidence.logic_certified
    assert not result.evidence.toolchain_origin
    assert any(issue.code == "unsafe-engine-request" for issue in result.evidence.issues)
    assert [item.id for item in result.report.proof.artifacts] == [
        "program.image",
        "seed.object",
    ]
    assert {item.id for item in result.report.proof.producers} == {
        "producer.program.image",
        "producer.seed",
    }
    assert result.report.proof.audit_issues[-1].code == "unsafe-engine-request"
    assert result.report.proof.adapter.id == "unsafe-engine-request"
    assert result.report.proof.providers[0].id == provider.name
    assert result.report.proof.package.id == "reprobit"
    assert reports.json is not None and reports.json.read_bytes().endswith(b"\n")
    assert reports.html is not None and "Cost overview" in reports.html.read_text()
    assert publication_leases == [state_root]


def test_high_assurance_entrypoint_rejects_a_name_spoofed_provider(
    tmp_path: Path,
) -> None:
    expected = b"exact output"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, provider = _bundle(tmp_path, expected)
    provider.name = "classic-msvc-cmake-v1"
    plan = _write_plan(tmp_path, expected)

    with (
        seal_file_oracle(reference) as oracle,
        pytest.raises(EngineError, match="closed built-in"),
    ):
        ReproductionEngine().run(
            EngineRequest(
                bundle=bundle,
                build_plan=plan,
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )

    assert not (tmp_path / "out" / "program.bin").exists()


def test_unsafe_entrypoint_cannot_be_overridden_to_restore_clean_claims(
    tmp_path: Path,
) -> None:
    class InjectedEngine(ReproductionEngine):
        pass

    expected = b"exact output"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, provider = _bundle(tmp_path, expected)
    plan = _write_plan(tmp_path, expected)

    with (
        seal_file_oracle(reference) as oracle,
        pytest.raises(EngineError, match="refuses engine subclasses"),
    ):
        InjectedEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=plan,
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )

    assert not (tmp_path / "out" / "program.bin").exists()


def test_engine_keeps_byte_logic_and_origin_claims_independent(tmp_path: Path) -> None:
    reference_bytes = b"reference"
    candidate_bytes = b"candidate"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(reference_bytes)
    bundle, provider = _bundle(
        tmp_path,
        candidate_bytes,
        certificate_passed=False,
        oracle_digest=Digest.from_bytes(reference_bytes),
    )

    with seal_file_oracle(reference) as oracle:
        result = ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, candidate_bytes),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )

    assert result.verdict.cold
    assert not result.verdict.byte_exact
    assert not result.verdict.logic_certified
    assert not result.verdict.toolchain_origin
    assert not result.verdict.clean


def test_stale_origin_does_not_change_literal_or_logic_claims(tmp_path: Path) -> None:
    expected = b"exact"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, provider = _bundle(tmp_path, expected, stale_origin=True)

    with seal_file_oracle(reference) as oracle:
        result = ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )

    assert result.verdict.byte_exact
    assert result.verdict.logic_certified
    assert not result.verdict.toolchain_origin
    assert any(issue.code == "forbidden-origin" for issue in result.evidence.issues)
    assert not result.accepts(AuthenticityPolicy.ALLOW_QUARANTINE)


def test_cold_execution_rejects_preexisting_output_before_running(tmp_path: Path) -> None:
    output = tmp_path / "out.bin"
    output.write_bytes(b"stale")
    marker = tmp_path / "ran.txt"
    script = "from pathlib import Path;import sys;Path(sys.argv[1]).write_text('ran')"
    plan = BuildPlan(
        (
            BuildStep(
                "write",
                (sys.executable, "-c", script, str(marker)),
                str(tmp_path),
                outputs=(str(output),),
            ),
        )
    )

    with pytest.raises(EngineError, match="already exist"):
        BuildPlanExecutor(run_root=tmp_path / "run", max_workers=1).execute(plan, cold=True)
    assert not marker.exists()


def test_produced_input_requires_a_dependency_edge(tmp_path: Path) -> None:
    intermediate = tmp_path / "intermediate.bin"
    plan = BuildPlan(
        (
            BuildStep(
                "produce",
                (sys.executable, "-c", "pass"),
                str(tmp_path),
                outputs=(str(intermediate),),
            ),
            BuildStep(
                "consume",
                (sys.executable, "-c", "pass"),
                str(tmp_path),
                inputs=(str(intermediate),),
            ),
        )
    )

    with pytest.raises(EngineError, match="without a dependency"):
        BuildPlanExecutor(run_root=tmp_path / "run", max_workers=2).execute(plan, cold=True)


def test_distinct_output_spellings_may_not_resolve_to_one_path(tmp_path: Path) -> None:
    output = tmp_path / "same.bin"
    plan = BuildPlan(
        (
            BuildStep(
                "one",
                (sys.executable, "-c", "pass"),
                str(tmp_path),
                outputs=("same.bin",),
            ),
            BuildStep(
                "two",
                (sys.executable, "-c", "pass"),
                str(tmp_path),
                outputs=(str(output),),
            ),
        )
    )

    with pytest.raises(EngineError, match="same path"):
        BuildPlanExecutor(run_root=tmp_path / "run", max_workers=2).execute(plan, cold=True)


def test_declared_input_must_remain_unchanged(tmp_path: Path) -> None:
    source = tmp_path / "source.txt"
    output = tmp_path / "output.bin"
    source.write_text("before", encoding="utf-8")
    script = (
        "from pathlib import Path;import sys;"
        "Path(sys.argv[1]).write_text('after');Path(sys.argv[2]).write_bytes(b'out')"
    )
    plan = BuildPlan(
        (
            BuildStep(
                "mutate",
                (sys.executable, "-c", script, str(source), str(output)),
                str(tmp_path),
                inputs=(str(source),),
                outputs=(str(output),),
            ),
        )
    )

    with pytest.raises(EngineError, match="input changed"):
        BuildPlanExecutor(run_root=tmp_path / "run", max_workers=1).execute(plan, cold=True)


def test_declared_output_may_not_be_a_hardlink_to_an_input(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    output = tmp_path / "output.bin"
    source.write_bytes(b"input")
    script = "import os,sys;os.link(sys.argv[1],sys.argv[2])"
    plan = BuildPlan(
        (
            BuildStep(
                "alias",
                (sys.executable, "-c", script, str(source), str(output)),
                str(tmp_path),
                inputs=(str(source),),
                outputs=(str(output),),
            ),
        )
    )

    with pytest.raises(EngineError, match="alias build inputs"):
        BuildPlanExecutor(run_root=tmp_path / "run", max_workers=1).execute(plan, cold=True)


def test_declared_output_must_be_created(tmp_path: Path) -> None:
    output = tmp_path / "missing.bin"
    plan = BuildPlan(
        (
            BuildStep(
                "noop",
                (sys.executable, "-c", "pass"),
                str(tmp_path),
                outputs=(str(output),),
            ),
        )
    )

    with pytest.raises(EngineError, match="declared artifact"):
        BuildPlanExecutor(run_root=tmp_path / "run", max_workers=1).execute(plan, cold=True)


def test_sealed_oracle_must_match_committed_receipt(tmp_path: Path) -> None:
    expected = b"expected"
    different = b"different"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(different)
    bundle, _ = _bundle(tmp_path, expected)

    with (
        seal_file_oracle(reference) as oracle,
        pytest.raises(EngineError, match="committed receipt"),
    ):
        ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
            )
        )


def test_producer_environment_has_no_oracle_capability(tmp_path: Path) -> None:
    expected = b"False"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    output = tmp_path / "out" / "program.bin"
    script = (
        "import os,sys;from pathlib import Path;"
        "p=Path(sys.argv[1]);p.parent.mkdir(parents=True,exist_ok=True);"
        "p.write_text(str(any('ORACLE' in k.upper() for k in os.environ)))"
    )
    plan = BuildPlan(
        (
            BuildStep(
                "build.program",
                (sys.executable, "-c", script, str(output)),
                str(tmp_path),
                outputs=(str(output),),
            ),
        )
    )
    bundle, provider = _bundle(tmp_path, expected)

    with seal_file_oracle(reference) as oracle:
        result = ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=plan,
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )

    assert result.verdict.byte_exact


def test_forged_committed_certificate_cannot_create_runtime_claims(tmp_path: Path) -> None:
    expected = b"exact"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, _provider = _bundle(tmp_path, expected, certificate_passed=True)
    forged_pin = ClassicProofReceipt(
        id="forged.receipt",
        intervention_id="stabilize.state",
        family=ClassicRecipeFamily.EQUAL_BODY_STRICT,
        expected_values={"output_gate": True},
        status="passed",
        authenticity="clean",
    )
    bundle = bundle.model_copy(
        update={
            "proof_documents": (
                ProofDocument(
                    schema_version=3,
                    target_id="program",
                    expected_observations=(forged_pin,),
                ),
            )
        }
    )

    with seal_file_oracle(reference) as oracle:
        result = ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
            )
        )

    assert result.verdict.byte_exact
    assert not result.verdict.logic_certified
    assert not result.verdict.toolchain_origin
    assert any(issue.code == "missing-certificate" for issue in result.evidence.issues)


def test_logic_changing_overlay_is_not_certified_by_renamed_execution_witness(
    tmp_path: Path,
) -> None:
    source = b"int main() {\n\tint values[1] = {0};\n\treturn values[0];\n}\n"
    generator: dict[str, JsonValue] = {
        "k": "fixed_array_fill",
        "array": "values",
        "index": "i",
        "index_type": "int",
        "count": 1,
        "value": -1,
        "declaration_indent": "\t",
    }
    fragment = b"\tfor (int i = 0; i < 1; i++) values[i] = -1;\n"
    effective = source.replace(b"return", fragment + b"return")
    anchor_tokens = ("0", "}", ";", "<SEAT>", "return", "values", "[", "0")
    declaration: dict[str, JsonValue] = {
        "path": "src/unit.cpp",
        "clean": digest_bytes(source),
        "effective": digest_bytes(effective),
        "size": len(effective),
        "ops": [
            {
                "op": "insert",
                "anchor": {
                    "ctx": digest_bytes("\0".join(anchor_tokens).encode("ascii")),
                    "b": 3,
                    "a": 4,
                    "at": "before_token",
                },
                "gen": generator,
            }
        ],
    }
    rendered = render_classic_overlay_declarations([declaration], {"src/unit.cpp": source})
    assert rendered.outputs["src/unit.cpp"] == effective
    assert fragment in effective
    assert b"return values[0]" in effective

    expected = b"exact"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    base_bundle, base_provider = _bundle(tmp_path, expected)
    intervention = ClassicRecipeIntervention(
        id="overlay.logic-change",
        scope=Scope(target="program"),
        rationale="negative semantic-equivalence fixture",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="app",
        parameters=(
            ClassicField(
                name="graph",
                value={"generated_tus": [], "link_admissions": []},
            ),
            ClassicField(name="outputs", value=[declaration]),
            ClassicField(name="schema", value=2),
        ),
    )
    certificate = Certificate(
        id="certificate.overlay",
        intervention_id=intervention.id,
        intervention_authority_digest=intervention_authority_digest(intervention),
        intervention_cost_digest=intervention_cost_row_digest(
            calculate_intervention_cost(intervention)
        ),
        obligations=(
            ProofObligation(
                name=classic_semantic_obligation_name(intervention.family),
                passed=True,
                evidence_digest=Digest.from_bytes(b"fresh overlay rendering"),
            ),
        ),
        artifact_ids=("program.image",),
    )
    provenance = (
        base_provider.provenance[0],
        base_provider.provenance[1].model_copy(
            update={
                "intervention_id": intervention.id,
                "certificate_ids": (certificate.id,),
            }
        ),
    )
    bundle = ProjectBundle(
        root=base_bundle.root,
        spec=base_bundle.spec,
        toolchain_lock=base_bundle.toolchain_lock,
        intervention_documents=(
            InterventionDocument(
                schema_version=3,
                target_id="program",
                interventions=(intervention,),
            ),
        ),
        proof_documents=(
            ProofDocument(
                schema_version=3,
                target_id="program",
                expected_observations=(
                    ClassicProofReceipt(
                        id="proof.overlay",
                        intervention_id=intervention.id,
                        family=intervention.family,
                    ),
                ),
            ),
        ),
        oracle_documents=base_bundle.oracle_documents,
    )
    provider = _FixtureEvidenceProvider(
        base_provider.artifacts,
        provenance,
        (certificate,),
    )

    with seal_file_oracle(reference) as oracle:
        result = ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )

    assert result.verdict.byte_exact
    assert not result.verdict.logic_certified
    assert any(issue.code == "missing-semantic-proof" for issue in result.evidence.issues)


def test_runtime_certificate_cannot_be_rebound_to_another_artifact(tmp_path: Path) -> None:
    expected = b"exact"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, provider = _bundle(tmp_path, expected)
    certificate = provider.certificates[0].model_copy(update={"artifact_ids": ("seed.object",)})
    provider = _FixtureEvidenceProvider(
        provider.artifacts,
        provider.provenance,
        (certificate,),
    )

    with (
        seal_file_oracle(reference) as oracle,
        pytest.raises(ValueError, match="provenance certificate differs"),
    ):
        ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )


def test_artifact_inputs_must_be_bound_into_provenance(tmp_path: Path) -> None:
    expected = b"exact"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, provider = _bundle(tmp_path, expected)
    seed, image = provider.artifacts
    external = Artifact(
        id="external.data",
        kind=ArtifactKind.EXTERNAL,
        logical_path="external/data.bin",
        digest=Digest.from_bytes(b"external"),
        size=8,
        origin=ArtifactOrigin.EXTERNAL,
        first_party=False,
    )
    image = image.model_copy(update={"inputs": ("seed.object", external.id)})
    external_node = ProvenanceNode(
        id="external.origin",
        kind=ProvenanceKind.EXTERNAL,
        operation="admit",
        origin=ArtifactOrigin.EXTERNAL,
        artifact_id=external.id,
    )
    provider = _FixtureEvidenceProvider(
        (seed, image, external),
        (*provider.provenance, external_node),
        provider.certificates,
    )

    with seal_file_oracle(reference) as oracle:
        result = ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )

    assert not result.verdict.toolchain_origin
    assert any(issue.code == "unproven-artifact-input" for issue in result.evidence.issues)


def test_reports_may_not_overwrite_target_artifacts(tmp_path: Path) -> None:
    expected = b"exact"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, provider = _bundle(tmp_path, expected)

    with (
        seal_file_oracle(reference) as oracle,
        pytest.raises(EngineError, match="overlap target artifacts"),
    ):
        ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
                reports=ReportDestinations(json=tmp_path / "out" / "program.bin"),
            )
        )


def test_engine_project_root_must_match_loaded_bundle(tmp_path: Path) -> None:
    expected = b"exact"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, provider = _bundle(tmp_path, expected)
    different = tmp_path / "different"
    different.mkdir()

    with (
        seal_file_oracle(reference) as oracle,
        pytest.raises(EngineError, match="project_root differs"),
    ):
        ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=different,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )


def test_runtime_legacy_evidence_is_logic_certified_but_quarantined(tmp_path: Path) -> None:
    expected = b"exact"
    reference = tmp_path / "reference.bin"
    reference.write_bytes(expected)
    bundle, provider = _bundle(tmp_path, expected)
    legacy = LegacyOracleInstallIntervention.freeze(
        id="legacy.install",
        scope=Scope(target="program"),
        rationale="frozen compatibility exception",
        proof_receipt_digest=Digest.from_bytes(b"expected receipt"),
        preimage_digest=Digest.from_bytes(expected),
        oracle_body_digest=Digest.from_bytes(expected),
        oracle_target="program",
        oracle_address=0,
        ranges=(
            OracleInstallRange(
                preimage_range=ByteRange(offset=0, length=1),
                output_range=ByteRange(offset=0, length=1),
                oracle_range=ByteRange(offset=0, length=1),
            ),
        ),
        byte_count=1,
        maximum_oracle_payload_bytes=1,
    )
    certificate = Certificate(
        id="certificate.legacy",
        intervention_id=legacy.id,
        intervention_authority_digest=intervention_authority_digest(legacy),
        intervention_cost_digest=intervention_cost_row_digest(calculate_intervention_cost(legacy)),
        obligations=(
            ProofObligation(
                name="quarantined_oracle_install",
                passed=True,
                evidence_digest=Digest.from_bytes(b"runtime proof"),
            ),
        ),
        artifact_ids=("program.image",),
    )
    provenance = (
        provider.provenance[0],
        ProvenanceNode(
            id="program.legacy",
            kind=ProvenanceKind.ORACLE_INSTALL,
            operation="legacy.install",
            origin=ArtifactOrigin.ORACLE,
            parents=("seed.origin",),
            artifact_id="program.image",
            intervention_id=legacy.id,
            certificate_ids=(certificate.id,),
        ),
    )
    bundle = bundle.model_copy(
        update={
            "intervention_documents": (
                InterventionDocument(
                    schema_version=3,
                    target_id="program",
                    interventions=(legacy,),
                ),
            )
        }
    )
    provider = _FixtureEvidenceProvider(provider.artifacts, provenance, (certificate,))

    with seal_file_oracle(reference) as oracle:
        result = ReproductionEngine().run_unsafe_for_testing(
            EngineRequest(
                bundle=bundle,
                build_plan=_write_plan(tmp_path, expected),
                project_root=tmp_path,
                run_root=tmp_path / "state" / "run",
                oracles=(TargetOracle("program", oracle),),
                evidence_providers=(provider,),
            )
        )

    assert result.verdict.byte_exact
    assert result.verdict.logic_certified
    assert not result.verdict.toolchain_origin
    assert result.verdict.quarantined
    assert result.verdict.quarantines[0].byte_count == 1
    assert not result.evidence.origin_integrity
    assert not result.accepts(AuthenticityPolicy.ALLOW_QUARANTINE)
    assert not result.accepts(AuthenticityPolicy.CLEAN)
