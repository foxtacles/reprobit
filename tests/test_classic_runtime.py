from __future__ import annotations

import os
import stat
import struct
import subprocess
import sys
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, nullcontext
from dataclasses import replace
from hashlib import sha256
from pathlib import Path, PureWindowsPath
from threading import Barrier, Event, Lock
from types import MappingProxyType, SimpleNamespace
from typing import cast

import pytest

import reprobit.classic_evidence as classic_evidence
import reprobit.classic_includes as classic_includes
import reprobit.classic_orchestration as classic_orchestration
import reprobit.classic_runtime as classic_runtime
import reprobit.classic_runtime_developer as classic_runtime_developer
import reprobit.classic_runtime_donor as classic_runtime_donor
import reprobit.classic_runtime_environment as classic_runtime_environment
import reprobit.classic_runtime_graph as classic_runtime_graph
import reprobit.classic_runtime_overlay as classic_runtime_overlay
import reprobit.classic_runtime_preparation as classic_runtime_preparation
import reprobit.classic_runtime_producer as classic_runtime_producer
from reprobit.backends import (
    BackendCapabilities,
    BackendError,
    ExecutionBackend,
    NativeWindowsBackend,
    PosixWineBackend,
    WorkerSandbox,
)
from reprobit.build import BuildPlan
from reprobit.classic.compiler_epoch import compiler_namespace_evidence_digest
from reprobit.classic.compiler_identity import (
    MSVC420_WIN32_I386_TARGET,
    Msvc420CompilerIdentity,
)
from reprobit.classic.semantic_contracts import (
    CleanSourceInput,
    CompilerEpochInvocation,
    CompilerNamespaceEvidence,
    CompilerProduct,
    ProjectOverlayCompilerEpochPlan,
    ProjectOverlayCounterfactualAudit,
    ProjectOverlaySourcePair,
)
from reprobit.classic_donors import (
    DonorCompilerAdditions,
    DonorCompileReceipt,
    DonorCompileRequest,
    DonorIncludeProjection,
)
from reprobit.classic_includes import IncludeOrigin
from reprobit.classic_orchestration import (
    classic_compiler_translation_unit_authority,
    classic_rdata_repack_graph_authority,
    prepare_classic_units,
)
from reprobit.classic_project import ClassicProjectError, InterventionWitness
from reprobit.execution import StepExecutionReceipt
from reprobit.model import ByteRange, Digest, Scope
from reprobit.paths import MaterializedSkeleton
from reprobit.process import (
    CancellationToken,
    CommandSpec,
    ProcessResult,
    ProcessSupervisor,
)
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole
from reprobit.schema import (
    BuildPlanDocument,
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicSdkArchiveAuthority,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    LegacyOracleInstallIntervention,
    LockedTool,
    LogicalPathProfile,
    MsvcRelease,
    OracleInstallRange,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    ProjectSpec,
    ProofDocument,
    SourceManifestDocument,
    SourceManifestEntry,
    TargetSpec,
    ToolchainLock,
    ToolchainProfileSource,
    ToolchainRef,
)
from reprobit.sealed_namespace import (
    NamespaceFile,
    NamespaceTree,
    SealedNamespaceLease,
    SealedNamespaceSnapshot,
)
from reprobit.secure_paths import atomic_publish_relative
from reprobit.toolchains import ClassicMSVCToolchain


def _directive_object(body: bytes) -> bytes:
    def symbol(
        name: str,
        *,
        section: int,
        symbol_type: int,
        storage: int,
        auxiliary_count: int = 0,
    ) -> bytes:
        encoded = name.encode("ascii")
        return encoded.ljust(8, b"\0") + struct.pack(
            "<IhHBB", 0, section, symbol_type, storage, auxiliary_count
        )

    symbols = (
        symbol(".drectve", section=1, symbol_type=0, storage=3, auxiliary_count=1)
        + struct.pack("<IHHIhBBH", len(body), 0, 0, 0, 0, 2, 0, 0)
        + symbol("_fixture", section=1, symbol_type=32, storage=2)
    )
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0, 60 + len(body), 3, 0, 0)
    section = b".drectve" + struct.pack("<IIIIIIHHI", 0, 0, len(body), 60, 0, 0, 0, 0, 0x60501020)
    return header + section + body + symbols + struct.pack("<I", 4)


def _directive_archive(name: str, payload: bytes) -> bytes:
    member_name = (name.encode("ascii") + b"/").ljust(16, b" ")
    header = (
        member_name
        + b"0".ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + b"100644".ljust(8, b" ")
        + str(len(payload)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    padding = b"\n" if len(payload) & 1 else b""
    return b"!<arch>\n" + header + payload + padding


def _prepare_bundle(project_root: Path) -> ProjectBundle:
    spec = ProjectSpec(
        schema_version=3,
        project_id="fixture",
        state_dir="state",
        build=ProducerGraphBuildAdapter(),
        toolchain=ToolchainRef(profile="msvc_4_2"),
        paths=LogicalPathProfile(
            source=r"R:\source",
            build=r"R:\build",
            toolchain=r"R:\toolchain",
        ),
        targets=(TargetSpec(id="program", artifact="state/program.exe", oracle="oracle.exe"),),
    )
    lock = ToolchainLock(
        schema_version=3,
        profile="msvc_4_2",
        release=MsvcRelease.V4_2,
        tools=(
            LockedTool(
                id="compiler",
                path="bin/CL.EXE",
                digest=Digest.from_bytes(b"compiler"),
            ),
        ),
    )
    build_plan = BuildPlanDocument(
        schema_version=3,
        source_manifest_digest=Digest.from_bytes(b"source"),
        translation_units=(),
        source_overlay_digest=Digest.from_bytes(b"overlay"),
        source_overlay_interventions=(),
        archives=(),
        target_gates=(),
    )
    return ProjectBundle.model_construct(
        root=str(project_root),
        spec=spec,
        toolchain_lock=lock,
        source_manifest=None,
        build_plan=build_plan,
        intervention_documents=(),
        proof_documents=(),
        oracle_documents=(),
    )


def test_prepared_unit_binds_only_the_exact_msvc42_win32_i386_target(
    tmp_path: Path,
) -> None:
    source = b"int fixture(void) { return 0; }\n"
    plan = ClassicTranslationUnitPlan(
        id="unit.fixture",
        target_id="program",
        build_target="program",
        source="unit.cpp",
        source_digest=Digest.from_bytes(source),
    )
    document = InterventionDocument(
        schema_version=3,
        target_id="program",
        translation_unit_id=plan.id,
        source=plan.source,
        source_digest=plan.source_digest,
        build_target=plan.build_target,
        interventions=(),
    )
    base = _prepare_bundle(tmp_path)
    assert base.build_plan is not None
    canonical_lock = ToolchainLock(
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
        tools=(
            LockedTool(
                id="compiler",
                path="bin/CL.EXE",
                size=37_888,
                digest=Digest(
                    value="c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f"
                ),
                roles=("compiler",),
            ),
            LockedTool(
                id="c1xx",
                path="bin/C1XX.EXE",
                size=793_088,
                digest=Digest(
                    value="9e0782ec157b30a387ca855374bc4c1b8a605dfb12364425497ba431541a5bf9"
                ),
                roles=("runtime",),
            ),
            LockedTool(
                id="c2",
                path="bin/C2.EXE",
                size=549_888,
                digest=Digest(
                    value="2aa1fcace0779531b3ec80b730663acd98f181aed3cdff51366440c602b724b5"
                ),
                roles=("runtime",),
            ),
        ),
    )
    bundle = base.model_copy(
        update={
            "toolchain_lock": canonical_lock,
            "build_plan": base.build_plan.model_copy(update={"translation_units": (plan,)}),
            "intervention_documents": (document,),
        }
    )
    units = prepare_classic_units(
        bundle,
        clean_sources={"unit.cpp": source},
        effective_sources={"unit.cpp": source},
    )
    assert isinstance(units[0].compiler_identity, Msvc420CompilerIdentity)
    assert units[0].compiler_identity.target == MSVC420_WIN32_I386_TARGET

    wrong = bundle.model_copy(
        update={
            "spec": bundle.spec.model_copy(
                update={"toolchain": ToolchainRef(profile="msvc_5_0_rtm")}
            ),
            "toolchain_lock": bundle.toolchain_lock.model_copy(
                update={"profile": "msvc_5_0_rtm", "release": MsvcRelease.V5_RTM}
            ),
        }
    )
    assert classic_orchestration._classic_compiler_identity(wrong) is None


@pytest.mark.skipif(os.name == "nt", reason="non-Windows host capability path")
def test_native_direct_runtime_fails_closed_off_windows(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ClassicProjectError,
        match="native Windows backend is unavailable",
    ):
        classic_runtime_preparation.prepare_classic_producer_graph_run(
            _prepare_bundle(tmp_path),
            project_root=tmp_path,
            session_root=tmp_path / "session",
            toolchain_root=tmp_path / "toolchain",
            backend=NativeWindowsBackend(),
            jobs=1,
        )


@pytest.mark.parametrize(
    ("intervention_targets", "reverse", "message"),
    (
        (
            ("app", "tool"),
            False,
            r"multiple rdata repacks name 'shared\.obj'",
        ),
        (
            ("app", "tool"),
            True,
            r"multiple rdata repacks name 'shared\.obj'",
        ),
        (
            ("app",),
            False,
            r"rdata repack 'rdata_app' terminal consumers differ",
        ),
    ),
    ids=("duplicate", "duplicate-reversed", "single-target-scoped-action"),
)
def test_cold_prepare_rejects_cross_target_rdata_before_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    intervention_targets: tuple[str, ...],
    reverse: bool,
    message: str,
) -> None:
    compiler = ProducerNode(
        id="compiler.shared.0000",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=(
            "/Zi",
            "/Fo${BUILD}/shared.obj",
            "/Fd${BUILD}/shared.pdb",
            "/c",
            "${SOURCE}/shared.cpp",
        ),
        inputs=("source/shared.cpp",),
        outputs=("build/shared.obj", "build/shared.pdb"),
    )
    linkers = tuple(
        ProducerNode(
            id=f"linker.{target}.0000",
            role=ProducerRole.LINKER,
            owner=target,
            target_id=target,
            arguments=("${BUILD}/shared.obj", f"/out:${{BUILD}}/{target}.exe"),
            inputs=("build/shared.obj",),
            outputs=(f"build/{target}.exe",),
            depends_on=(compiler.id,),
        )
        for target in ("app", "tool")
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(compiler, *linkers),
    )

    def repack(target: str) -> ClassicRecipeIntervention:
        return ClassicRecipeIntervention(
            id=f"rdata_{target}",
            scope=Scope(target=target),
            rationale="fixture cross-target duplicate",
            family=ClassicRecipeFamily.IMAGE_BINARY_REPACK,
            role=ClassicRecipeRole.PROJECT,
            build_target=target,
            parameters=(
                ClassicField(
                    name="rdata_pool_repack",
                    value={
                        "schema": "rdata_pool_repack_v1",
                        "object": "shared.obj",
                    },
                ),
            ),
        )

    interventions = tuple(repack(target) for target in intervention_targets)
    documents = tuple(
        InterventionDocument(
            schema_version=3,
            target_id=item.scope.target,
            interventions=(item,),
        )
        for item in interventions
    )
    proofs = tuple(
        ProofDocument(
            schema_version=3,
            target_id=item.scope.target,
            expected_observations=(
                ClassicProofReceipt(
                    id=f"proof_{item.id}",
                    intervention_id=item.id,
                    family=item.family,
                ),
            ),
        )
        for item in interventions
    )
    if reverse:
        documents = tuple(reversed(documents))
        proofs = tuple(reversed(proofs))
    base = _prepare_bundle(tmp_path)
    spec = base.spec.model_copy(
        update={
            "targets": tuple(
                TargetSpec(
                    id=target,
                    artifact=f"state/{target}.exe",
                    oracle=f"{target}.oracle",
                )
                for target in ("app", "tool")
            )
        }
    )
    bundle = base.model_copy(
        update={
            "spec": spec,
            "producer_graph": graph,
            "intervention_documents": documents,
            "proof_documents": proofs,
        }
    )
    monkeypatch.setattr(
        classic_runtime_preparation,
        "ClassicMSVCToolchain",
        lambda *_args, **_kwargs: pytest.fail("cold validation constructed a toolchain"),
    )
    session = tmp_path / "cold-session"

    with pytest.raises(
        ClassicProjectError,
        match=message,
    ):
        classic_runtime_preparation.prepare_classic_producer_graph_run(
            bundle,
            project_root=tmp_path,
            session_root=session,
            toolchain_root=tmp_path / "toolchain",
            backend=NativeWindowsBackend(),
            jobs=1,
        )

    assert not session.exists()


@pytest.mark.parametrize(
    ("app_consumes_shared", "actual_consumers"),
    (
        (False, r"\['tool'\]"),
        (True, r"\['app', 'tool'\]"),
    ),
    ids=("wrong-target", "shared-with-declared-target"),
)
def test_compiler_translation_unit_authority_rejects_wrong_or_shared_target(
    tmp_path: Path,
    app_consumes_shared: bool,
    actual_consumers: str,
) -> None:
    app_compiler = ProducerNode(
        id="compiler.app.0000",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=(
            "/Zi",
            "/Fo${BUILD}/app.obj",
            "/Fd${BUILD}/app.pdb",
            "/c",
            "${SOURCE}/app.cpp",
        ),
        inputs=("source/app.cpp",),
        outputs=("build/app.obj", "build/app.pdb"),
    )
    shared_compiler = ProducerNode(
        id="compiler.lib.0000",
        role=ProducerRole.COMPILER,
        owner="lib",
        arguments=(
            "/Zi",
            "/Fo${BUILD}/shared.obj",
            "/Fd${BUILD}/shared.pdb",
            "/c",
            "${SOURCE}/shared.cpp",
        ),
        inputs=("source/shared.cpp",),
        outputs=("build/shared.obj", "build/shared.pdb"),
    )
    app_inputs = (
        ("build/app.obj", "build/shared.obj") if app_consumes_shared else ("build/app.obj",)
    )
    app_dependencies = (
        (app_compiler.id, shared_compiler.id) if app_consumes_shared else (app_compiler.id,)
    )
    linkers = (
        ProducerNode(
            id="linker.app.0000",
            role=ProducerRole.LINKER,
            owner="app",
            target_id="app",
            arguments=(
                *(f"${{BUILD}}/{reference.removeprefix('build/')}" for reference in app_inputs),
                "/out:${BUILD}/app.exe",
            ),
            inputs=app_inputs,
            outputs=("build/app.exe",),
            depends_on=app_dependencies,
        ),
        ProducerNode(
            id="linker.tool.0000",
            role=ProducerRole.LINKER,
            owner="tool",
            target_id="tool",
            arguments=("${BUILD}/shared.obj", "/out:${BUILD}/tool.exe"),
            inputs=("build/shared.obj",),
            outputs=("build/tool.exe",),
            depends_on=(shared_compiler.id,),
        ),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(app_compiler, shared_compiler, *linkers),
    )
    unit = ClassicTranslationUnitPlan(
        id="unit.shared",
        target_id="app",
        build_target="lib",
        source="shared.cpp",
        source_digest=Digest.from_bytes(b"shared source"),
    )
    base = _prepare_bundle(tmp_path)
    assert base.build_plan is not None
    bundle = base.model_copy(
        update={"build_plan": base.build_plan.model_copy(update={"translation_units": (unit,)})}
    )

    with pytest.raises(
        ClassicProjectError,
        match=(
            r"translation-unit compiler terminal consumers differ: .*"
            rf"declared='app', actual={actual_consumers}"
        ),
    ):
        classic_compiler_translation_unit_authority(bundle, graph)


def test_compiler_and_rdata_authorities_stop_at_upstream_linker_boundary(
    tmp_path: Path,
) -> None:
    compiler = ProducerNode(
        id="compiler.lib.0000",
        role=ProducerRole.COMPILER,
        owner="lib",
        arguments=(
            "/Zi",
            "/Fo${BUILD}/shared.obj",
            "/Fd${BUILD}/shared.pdb",
            "/c",
            "${SOURCE}/shared.cpp",
        ),
        inputs=("source/shared.cpp",),
        outputs=("build/shared.obj", "build/shared.pdb"),
    )
    upstream = ProducerNode(
        id="linker.upstream.0000",
        role=ProducerRole.LINKER,
        owner="upstream",
        target_id="upstream",
        arguments=(
            "${BUILD}/shared.obj",
            "/out:${BUILD}/upstream.dll",
            "/implib:${BUILD}/upstream.lib",
        ),
        inputs=("build/shared.obj",),
        outputs=("build/upstream.dll", "build/upstream.lib"),
        depends_on=(compiler.id,),
    )
    downstream = ProducerNode(
        id="linker.downstream.0000",
        role=ProducerRole.LINKER,
        owner="downstream",
        target_id="downstream",
        arguments=("${BUILD}/upstream.lib", "/out:${BUILD}/downstream.exe"),
        inputs=("build/upstream.lib",),
        outputs=("build/downstream.exe",),
        depends_on=(upstream.id,),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(compiler, downstream, upstream),
    )
    unit = ClassicTranslationUnitPlan(
        id="unit.shared",
        target_id="upstream",
        build_target="lib",
        source="shared.cpp",
        source_digest=Digest.from_bytes(b"shared source"),
    )
    base = _prepare_bundle(tmp_path)
    assert base.build_plan is not None
    bundle = base.model_copy(
        update={"build_plan": base.build_plan.model_copy(update={"translation_units": (unit,)})}
    )

    assert classic_compiler_translation_unit_authority(bundle, graph) == {compiler.id: unit}

    declaration = {"schema": "rdata_pool_repack_v1", "object": "shared.obj"}
    intervention = ClassicRecipeIntervention(
        id="rdata_upstream",
        scope=Scope(target="upstream"),
        rationale="fixture terminal-linker boundary",
        family=ClassicRecipeFamily.IMAGE_BINARY_REPACK,
        role=ClassicRecipeRole.PROJECT,
        build_target="lib",
        parameters=(ClassicField(name="rdata_pool_repack", value=declaration),),
    )
    receipt = ClassicProofReceipt(
        id="proof_rdata_upstream",
        intervention_id=intervention.id,
        family=intervention.family,
    )
    bundle = bundle.model_copy(
        update={
            "intervention_documents": (
                InterventionDocument(
                    schema_version=3,
                    target_id="upstream",
                    interventions=(intervention,),
                ),
            ),
            "proof_documents": (
                ProofDocument(
                    schema_version=3,
                    target_id="upstream",
                    expected_observations=(receipt,),
                ),
            ),
        }
    )

    assert set(classic_rdata_repack_graph_authority(bundle, graph)) == {"shared.obj"}


@pytest.mark.parametrize(
    ("scope", "oracle_target", "dependencies", "message"),
    (
        (
            Scope(target="program", translation_unit="unit.legacy"),
            "program",
            ("donor.legacy",),
            "must have exact function and translation-unit scope",
        ),
        (
            Scope(
                target="program",
                translation_unit="unit.legacy",
                function="?legacy@@YAXXZ",
            ),
            "other",
            ("donor.legacy",),
            "oracle target differs from its scope",
        ),
        (
            Scope(
                target="program",
                translation_unit="unit.legacy",
                function="?legacy@@YAXXZ",
            ),
            "program",
            (),
            "requires exactly one donor dependency",
        ),
        (
            Scope(
                target="program",
                translation_unit="unit.legacy",
                function="?legacy@@YAXXZ",
            ),
            "program",
            ("not_a_donor",),
            "is not a donor in its translation-unit shard",
        ),
    ),
    ids=("missing-function", "oracle-target", "dependency-count", "dependency-role"),
)
def test_prepare_classic_units_rejects_invalid_temporary_legacy_shape(
    tmp_path: Path,
    scope: Scope,
    oracle_target: str,
    dependencies: tuple[str, ...],
    message: str,
) -> None:
    unit = ClassicTranslationUnitPlan(
        id="unit.legacy",
        target_id="program",
        build_target="program",
        source="unit.cpp",
        source_digest=Digest.from_bytes(b"unit source"),
    )
    donor = ClassicRecipeIntervention(
        id="donor.legacy",
        scope=Scope(target="program", translation_unit=unit.id),
        rationale="fixture temporary legacy donor",
        family=ClassicRecipeFamily.DECLARATION_SHAPE,
        role=ClassicRecipeRole.DONOR,
        build_target="program",
    )
    action = LegacyOracleInstallIntervention.freeze(
        id="legacy.shape",
        scope=scope,
        rationale="fixture temporary legacy authority shape",
        dependencies=dependencies,
        proof_receipt_digest=Digest.from_bytes(b"proof"),
        preimage_digest=Digest.from_bytes(b"preimage"),
        oracle_body_digest=Digest.from_bytes(b"oracle"),
        oracle_target=oracle_target,
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
    document = InterventionDocument(
        schema_version=3,
        target_id="program",
        translation_unit_id=unit.id,
        source=unit.source,
        source_digest=unit.source_digest,
        build_target=unit.build_target,
        interventions=(donor, action),
    )
    base = _prepare_bundle(tmp_path)
    assert base.build_plan is not None
    bundle = base.model_copy(
        update={
            "build_plan": base.build_plan.model_copy(update={"translation_units": (unit,)}),
            "intervention_documents": (document,),
        }
    )

    with pytest.raises(ClassicProjectError, match=message):
        prepare_classic_units(bundle, clean_sources={}, effective_sources={})


@pytest.mark.parametrize(
    ("receipt_introduces_selector", "planned_lane", "message"),
    (
        (True, True, "cannot introduce or remove the rdata repack selector"),
        (False, False, "has no prepared translation-unit compiler lane"),
    ),
    ids=("receipt-introduced-selector", "consumed-object-without-tu-lane"),
)
def test_cold_rdata_authority_rejects_before_runtime_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receipt_introduces_selector: bool,
    planned_lane: bool,
    message: str,
) -> None:
    compiler = ProducerNode(
        id="compiler.app.0000",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=(
            "/Zi",
            "/Fo${BUILD}/app.obj",
            "/Fd${BUILD}/app.pdb",
            "/c",
            "${SOURCE}/shared.cpp",
        ),
        inputs=("source/shared.cpp",),
        outputs=("build/app.obj", "build/app.pdb"),
    )
    linker = ProducerNode(
        id="linker.app.0000",
        role=ProducerRole.LINKER,
        owner="app",
        target_id="app",
        arguments=("${BUILD}/app.obj", "/out:${BUILD}/app.exe"),
        inputs=("build/app.obj",),
        outputs=("build/app.exe",),
        depends_on=(compiler.id,),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(compiler, linker),
    )
    declaration = {
        "schema": "rdata_pool_repack_v1",
        "object": "app.obj",
    }
    intervention = ClassicRecipeIntervention(
        id="rdata_preflight",
        scope=Scope(target="app"),
        rationale="fixture shared rdata authority preflight",
        family=ClassicRecipeFamily.IMAGE_BINARY_REPACK,
        role=ClassicRecipeRole.PROJECT,
        build_target="app",
        parameters=()
        if receipt_introduces_selector
        else (ClassicField(name="rdata_pool_repack", value=declaration),),
    )
    receipt = ClassicProofReceipt(
        id="proof_rdata_preflight",
        intervention_id=intervention.id,
        family=intervention.family,
        expected_values={"rdata_pool_repack": declaration} if receipt_introduces_selector else {},
    )
    translation_units = (
        (
            ClassicTranslationUnitPlan(
                id="unit.app",
                target_id="app",
                build_target="app",
                source="shared.cpp",
                source_digest=Digest.from_bytes(b"source"),
            ),
        )
        if planned_lane
        else ()
    )
    base = _prepare_bundle(tmp_path)
    assert base.build_plan is not None
    bundle = base.model_copy(
        update={
            "producer_graph": graph,
            "build_plan": base.build_plan.model_copy(
                update={"translation_units": translation_units}
            ),
            "intervention_documents": (
                InterventionDocument(
                    schema_version=3,
                    target_id="app",
                    interventions=(intervention,),
                ),
            ),
            "proof_documents": (
                ProofDocument(
                    schema_version=3,
                    target_id="app",
                    expected_observations=(receipt,),
                ),
            ),
        }
    )
    monkeypatch.setattr(
        classic_runtime_preparation,
        "ClassicMSVCToolchain",
        lambda *_args, **_kwargs: pytest.fail("cold preflight constructed a toolchain"),
    )
    session = tmp_path / "cold-rdata-session"

    with pytest.raises(ClassicProjectError, match=message):
        classic_runtime_preparation.prepare_classic_producer_graph_run(
            bundle,
            project_root=tmp_path,
            session_root=session,
            toolchain_root=tmp_path / "toolchain",
            backend=NativeWindowsBackend(),
            jobs=1,
        )

    assert not session.exists()


@pytest.mark.parametrize(
    ("variant", "message"),
    (
        ("case-drift", "must use the graph's exact object spelling"),
        ("multiple-objects", "must publish exactly one object and one PDB"),
        ("dependency-only", "which target 'app' does not consume"),
    ),
)
def test_shared_rdata_authority_closes_canonical_object_dataflow(
    tmp_path: Path,
    variant: str,
    message: str,
) -> None:
    primary = ProducerNode(
        id="compiler.app.0000",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=(
            "/Zi",
            "/Fo${BUILD}/app.obj",
            "/Fd${BUILD}/app.pdb",
            "/c",
            "${SOURCE}/app.cpp",
        ),
        inputs=("source/app.cpp",),
        outputs=(
            ("build/app.obj", "build/app.pdb", "build/spare.obj")
            if variant == "multiple-objects"
            else ("build/app.obj", "build/app.pdb")
        ),
    )
    unused = ProducerNode(
        id="compiler.app.0001",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=(
            "/Zi",
            "/Fo${BUILD}/unused.obj",
            "/Fd${BUILD}/unused.pdb",
            "/c",
            "${SOURCE}/unused.cpp",
        ),
        inputs=("source/unused.cpp",),
        outputs=("build/unused.obj", "build/unused.pdb"),
    )
    compilers = (primary, unused) if variant == "dependency-only" else (primary,)
    linker = ProducerNode(
        id="linker.app.0000",
        role=ProducerRole.LINKER,
        owner="app",
        target_id="app",
        arguments=("${BUILD}/app.obj", "/out:${BUILD}/app.exe"),
        inputs=("build/app.obj",),
        outputs=("build/app.exe",),
        depends_on=tuple(node.id for node in compilers),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(*compilers, linker),
    )
    object_value = {
        "case-drift": "App.obj",
        "multiple-objects": "app.obj",
        "dependency-only": "unused.obj",
    }[variant]
    declaration = {
        "schema": "rdata_pool_repack_v1",
        "object": object_value,
    }
    intervention = ClassicRecipeIntervention(
        id="rdata_closed_dataflow",
        scope=Scope(target="app"),
        rationale="fixture shared rdata canonical object dataflow authority",
        family=ClassicRecipeFamily.IMAGE_BINARY_REPACK,
        role=ClassicRecipeRole.PROJECT,
        build_target="app",
        parameters=(ClassicField(name="rdata_pool_repack", value=declaration),),
    )
    receipt = ClassicProofReceipt(
        id="proof_rdata_closed_dataflow",
        intervention_id=intervention.id,
        family=intervention.family,
    )
    units = tuple(
        ClassicTranslationUnitPlan(
            id=f"unit.{index}",
            target_id="app",
            build_target="app",
            source=source,
            source_digest=Digest.from_bytes(source.encode()),
        )
        for index, source in enumerate(("app.cpp",))
    )
    base = _prepare_bundle(tmp_path)
    assert base.build_plan is not None
    bundle = base.model_copy(
        update={
            "producer_graph": graph,
            "build_plan": base.build_plan.model_copy(update={"translation_units": units}),
            "intervention_documents": (
                InterventionDocument(
                    schema_version=3,
                    target_id="app",
                    interventions=(intervention,),
                ),
            ),
            "proof_documents": (
                ProofDocument(
                    schema_version=3,
                    target_id="app",
                    expected_observations=(receipt,),
                ),
            ),
        }
    )

    with pytest.raises(ClassicProjectError, match=message):
        classic_rdata_repack_graph_authority(bundle, graph)


@pytest.mark.skipif(os.name != "posix", reason="the POSIX proxy is a Bash program")
@pytest.mark.parametrize(
    ("tool_name", "logical_variable", "logical_program"),
    (
        ("cl", "REPROBIT_LOGICAL_CL", r"R:\toolchain\bin\CL.EXE"),
        ("rc", "REPROBIT_LOGICAL_RC", r"R:\toolchain\bin\RC.EXE"),
        ("link", "REPROBIT_LOGICAL_LINK", r"R:\toolchain\bin\LINK.EXE"),
        ("lib", "REPROBIT_LOGICAL_LIB", r"R:\toolchain\bin\LIB.EXE"),
    ),
)
def test_path_proxy_rewrites_cross_session_argv_without_run_tokens(
    tmp_path: Path,
    tool_name: str,
    logical_variable: str,
    logical_program: str,
) -> None:
    recorder = tmp_path / "record-argv"
    recorder.write_text(
        '#!/bin/sh\nset -eu\nprintf \'%s\\n\' "$@" > "$REPROBIT_CAPTURE"\n',
        encoding="utf-8",
    )
    recorder.chmod(stat.S_IRUSR | stat.S_IXUSR)

    captures: list[tuple[str, ...]] = []
    tokens = (
        "11111111111111111111111111111111",
        "22222222222222222222222222222222",
    )
    for index, token in enumerate(tokens):
        session = tmp_path / f"run-{token}"
        session.mkdir()
        proxies, _ = classic_runtime_environment._install_path_proxies(session)
        physical_drive = session / "logical-drive"
        physical_build = physical_drive / "build"
        physical_build.mkdir(parents=True)
        physical_toolchain = tmp_path / f"toolchain-{token}"
        capture = tmp_path / f"capture-{index}.txt"
        arguments = (
            f"/Fo{physical_build / 'unit.obj'}",
            f"/Fd{physical_build / 'unit.pdb'}",
            f"/I{physical_drive / 'source/include'}",
            f"/LIBPATH:{physical_toolchain / 'lib'}",
            str(physical_drive / "source/unit.cpp"),
            "@CMakeFiles/program.dir/objects1.rsp",
        )
        environment = {
            "PATH": os.defpath,
            "REPROBIT_WINE_MSVC_TRANSPORT": str(recorder),
            logical_variable: logical_program,
            "REPROBIT_CAPTURE": str(capture),
            "REPROBIT_PHYSICAL_DRIVE_ROOT": str(physical_drive),
            "REPROBIT_LOGICAL_DRIVE_ROOT": "R:",
            "REPROBIT_PHYSICAL_TOOLCHAIN_ROOT": str(physical_toolchain),
            "REPROBIT_LOGICAL_TOOLCHAIN_ROOT": "R:/toolchain",
        }
        subprocess.run(
            (str(proxies[tool_name]), *arguments),
            cwd=physical_build,
            env=environment,
            check=True,
            stdin=subprocess.DEVNULL,
            capture_output=True,
        )
        captures.append(tuple(capture.read_text(encoding="utf-8").splitlines()))

    assert captures[0] == captures[1]
    assert captures[0] == (
        logical_program,
        "/FoR:/build/unit.obj",
        "/FdR:/build/unit.pdb",
        "/IR:/source/include",
        "/LIBPATH:R:/toolchain/lib",
        "R:/source/unit.cpp",
        "@CMakeFiles/program.dir/objects1.rsp",
    )
    captured_material = "\n".join(captures[0])
    assert str(tmp_path) not in captured_material
    assert not any(token in captured_material for token in tokens)


@pytest.mark.skipif(os.name != "posix", reason="the POSIX proxy is a Bash program")
def test_path_proxy_leaves_z_drive_paths_for_one_transport_normalization(
    tmp_path: Path,
) -> None:
    recorder = tmp_path / "record-argv"
    capture = tmp_path / "capture.txt"
    recorder.write_text(
        '#!/bin/sh\nset -eu\nprintf \'%s\\n\' "$@" > "$REPROBIT_CAPTURE"\n',
        encoding="utf-8",
    )
    recorder.chmod(stat.S_IRUSR | stat.S_IXUSR)
    session = tmp_path / "run"
    session.mkdir()
    proxies, _ = classic_runtime_environment._install_path_proxies(session)
    physical_drive = session / "logical-drive"
    physical_drive.mkdir()
    physical_toolchain = tmp_path / "toolchain"
    subprocess.run(
        (
            str(proxies["cl"]),
            f"/FI{physical_drive / 'Users/project/source/carrier.h'}",
        ),
        cwd=session,
        env={
            "PATH": os.defpath,
            "REPROBIT_WINE_MSVC_TRANSPORT": str(recorder),
            "REPROBIT_LOGICAL_CL": r"Z:\toolchain\bin\CL.EXE",
            "REPROBIT_CAPTURE": str(capture),
            "REPROBIT_PHYSICAL_DRIVE_ROOT": str(physical_drive),
            "REPROBIT_LOGICAL_DRIVE_ROOT": "Z:",
            "REPROBIT_PHYSICAL_TOOLCHAIN_ROOT": str(physical_toolchain),
            "REPROBIT_LOGICAL_TOOLCHAIN_ROOT": "Z:/toolchain",
        },
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
    )
    captured = tuple(capture.read_text(encoding="utf-8").splitlines())
    assert captured == (
        r"Z:\toolchain\bin\CL.EXE",
        r"/FIz:\Users\project\source\carrier.h",
    )
    assert "Z:z:/" not in "\n".join(captured)


@pytest.mark.parametrize("failure_site", ("environment", "executor"))
def test_prepare_failure_releases_logical_drive_and_uses_stable_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_site: str,
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    toolchain_root = tmp_path / "toolchain"
    toolchain_root.mkdir()
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"source topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(
            ProducerNode(
                id="linker.program.0000",
                role=ProducerRole.LINKER,
                owner="program",
                target_id="program",
                arguments=("/out:${BUILD}/program.exe",),
                outputs=("build/program.exe",),
            ),
        ),
    )
    bundle = _prepare_bundle(project_root).model_copy(
        update={
            "source_manifest": SimpleNamespace(entries=()),
            "producer_graph": graph,
        }
    )
    graph_path = project_root / bundle.spec.layout.producer_graph
    graph_path.parent.mkdir(parents=True)
    graph_path.write_text("sealed graph fixture\n", encoding="utf-8")
    captured_temporary: list[str] = []

    class Binding:
        entered = False
        exited = False

        def __enter__(self) -> Binding:
            self.entered = True
            return self

        def __exit__(self, *args: object) -> None:
            self.exited = True

    binding = Binding()

    class Backend:
        capabilities = BackendCapabilities(
            identifier="test",
            host_systems=(),
            process_tree_primitive="test",
            logical_path_primitive="test",
            private_wine_prefix=False,
            native_windows=True,
        )

        @staticmethod
        def create_worker(state_root: Path, worker_id: str) -> object:
            del state_root, worker_id
            return object()

        @staticmethod
        def bind_skeleton(worker: object, skeleton: object) -> Binding:
            del worker, skeleton
            return binding

    class Doctor:
        @staticmethod
        def require_ok() -> None:
            return None

    class Installation:
        def __init__(self, profile: str, root: Path, *, logical_root: str) -> None:
            del profile
            self.root = root
            self.logical_root = logical_root
            self.profile = SimpleNamespace(
                compiler="bin/CL.EXE",
                resource_compiler="bin/RC.EXE",
                linker="bin/LINK.EXE",
                librarian="bin/LIB.EXE",
            )

        @staticmethod
        def doctor(lock: object) -> Doctor:
            del lock
            return Doctor()

        @staticmethod
        def default_environment(*, temp_directory: str) -> dict[str, str]:
            captured_temporary.append(temp_directory)
            if failure_site == "environment":
                raise RuntimeError("injected environment failure")
            return {
                "PATH": r"R:\toolchain\bin",
                "INCLUDE": r"R:\toolchain\include",
                "LIB": r"R:\toolchain\lib",
                "TMP": temp_directory,
                "TEMP": temp_directory,
            }

    def materialize(
        current_bundle: ProjectBundle,
        current_project_root: Path,
        effective_root: Path,
    ) -> tuple[()]:
        del current_bundle, current_project_root
        effective_root.mkdir(parents=True, exist_ok=True)
        return ()

    monkeypatch.setattr(classic_runtime_preparation, "ClassicMSVCToolchain", Installation)
    monkeypatch.setattr(
        "reprobit.classic_runtime_environment.shutil.which",
        lambda name: pytest.fail(f"runtime attempted build-system discovery: {name}"),
    )
    monkeypatch.setattr(classic_runtime_preparation, "materialize_effective_workspace", materialize)

    def project_toolchain(*args: object, **kwargs: object) -> tuple[()]:
        del args
        cast(Path, kwargs["destination"]).mkdir(parents=True)
        return ()

    monkeypatch.setattr(classic_runtime_preparation, "_project_locked_toolchain", project_toolchain)
    monkeypatch.setattr(
        classic_runtime_preparation,
        "read_producer_graph",
        lambda path: graph,
    )
    monkeypatch.setattr(
        classic_runtime_preparation,
        "_graph_role_bindings",
        lambda *args, **kwargs: (
            {role: role.value for role in ProducerRole},
            {
                ProducerRole.COMPILER: "bin/CL.EXE",
                ProducerRole.RESOURCE: "bin/RC.EXE",
                ProducerRole.LIBRARIAN: "bin/LIB.EXE",
                ProducerRole.LINKER: "bin/LINK.EXE",
            },
        ),
    )
    monkeypatch.setattr(classic_runtime_preparation, "prepare_classic_units", lambda *a, **k: ())
    monkeypatch.setattr(classic_runtime_preparation, "_graph_compile_records", lambda *a, **k: ())
    monkeypatch.setattr(
        classic_runtime_preparation,
        "_graph_targets",
        lambda *args, **kwargs: (
            classic_runtime_graph.ClassicProducerTarget(
                "program",
                "program",
                kwargs["build_root"] / "program.exe",
                None,
                "linker.program.0000",
            ),
        ),
    )
    monkeypatch.setattr(
        classic_runtime_preparation, "_graph_system_library_map", lambda *a, **k: {}
    )
    if failure_site == "executor":

        def fail_runtime(**kwargs: object) -> None:
            del kwargs
            raise RuntimeError("injected executor failure")

        monkeypatch.setattr(
            classic_runtime_preparation,
            "ClassicProducerExecution",
            fail_runtime,
        )

    with pytest.raises(RuntimeError, match=f"injected {failure_site} failure"):
        classic_runtime_preparation.prepare_classic_producer_graph_run(
            bundle,
            project_root=project_root,
            session_root=project_root / f"session-{sha256(failure_site.encode()).hexdigest()}",
            toolchain_root=toolchain_root,
            backend=cast(ExecutionBackend, Backend()),
            jobs=1,
        )

    assert captured_temporary == [r"R:\build\.reprobit-tmp\lane-0000"]
    assert "session-" not in captured_temporary[0]
    # Metadata-only preparation never creates a backend worker or drive
    # binding, so even an environment/executor failure has no runtime lease to
    # clean up.
    assert binding.entered is False
    assert binding.exited is False


def test_producer_write_closure_rejects_undeclared_file(tmp_path: Path) -> None:
    build_root = tmp_path / "build"
    build_root.mkdir()
    before = classic_runtime_producer._tree_file_seal(build_root)
    declared = build_root / "unit.obj"
    declared.write_bytes(b"object")
    classic_runtime_producer._require_declared_tree_writes(
        before,
        root=build_root,
        allowed_outputs=(declared,),
        phase="fixture",
    )
    unexpected = build_root / "unit.idb"
    unexpected.write_bytes(b"undeclared")
    with pytest.raises(ClassicProjectError, match=r"unit\.idb"):
        classic_runtime_producer._require_declared_tree_writes(
            before,
            root=build_root,
            allowed_outputs=(declared,),
            phase="fixture",
        )


def _source_sdk_library_fixture(
    tmp_path: Path,
    *,
    authorize: bool,
) -> tuple[ProjectBundle, ProducerGraphDocument, ClassicMSVCToolchain, Path, Path]:
    source_root = tmp_path / "source"
    build_root = tmp_path / "build"
    toolchain_root = tmp_path / "toolchain"
    sdk_payload = b"sealed project SDK archive"
    sdk_path = source_root / "sdk" / "ddraw.lib"
    sdk_path.parent.mkdir(parents=True)
    sdk_path.write_bytes(sdk_payload)
    build_root.mkdir()
    for relative in ("lib", "mfc/lib"):
        (toolchain_root / relative).mkdir(parents=True)
    node = ProducerNode(
        id="linker.program.0000",
        role=ProducerRole.LINKER,
        owner="program",
        target_id="program",
        arguments=(
            "/LIBPATH:${SOURCE}/sdk",
            "ddraw.lib",
            "/out:${BUILD}/APP.EXE",
        ),
        inputs=("system-library/ddraw.lib",),
        outputs=("build/APP.EXE",),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"source topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(node,),
    )
    bundle = _prepare_bundle(tmp_path)
    project_sdk_libraries = (
        (
            ClassicSdkArchiveAuthority(
                path="sdk/ddraw.lib",
                sha256=Digest.from_bytes(sdk_payload).value,
            ),
        )
        if authorize
        else ()
    )
    assert bundle.build_plan is not None
    bundle = bundle.model_copy(
        update={
            "build_plan": bundle.build_plan.model_copy(
                update={"project_sdk_libraries": project_sdk_libraries}
            ),
            "source_manifest": SourceManifestDocument(
                schema_version=3,
                complete=True,
                entries=(
                    SourceManifestEntry(
                        path="sdk/ddraw.lib",
                        size=len(sdk_payload),
                        digest=Digest.from_bytes(sdk_payload),
                    ),
                ),
            ),
        }
    )
    installation = ClassicMSVCToolchain("msvc_4_2", toolchain_root)
    return bundle, graph, installation, source_root, build_root


def test_source_resolved_system_library_requires_exact_sdk_authority(
    tmp_path: Path,
) -> None:
    bundle, graph, installation, source_root, build_root = _source_sdk_library_fixture(
        tmp_path, authorize=True
    )
    result = classic_runtime_graph._graph_system_library_map(
        bundle,
        graph,
        installation,
        effective_root=source_root,
        build_root=build_root,
    )
    assert result == {"system-library/ddraw.lib": source_root / "sdk" / "ddraw.lib"}


def test_source_resolved_system_library_rejects_missing_or_changed_sdk_pin(
    tmp_path: Path,
) -> None:
    bundle, graph, installation, source_root, build_root = _source_sdk_library_fixture(
        tmp_path, authorize=False
    )
    with pytest.raises(ClassicProjectError, match="lacks exact project SDK authority"):
        classic_runtime_graph._graph_system_library_map(
            bundle,
            graph,
            installation,
            effective_root=source_root,
            build_root=build_root,
        )

    bundle, graph, installation, source_root, build_root = _source_sdk_library_fixture(
        tmp_path / "changed", authorize=True
    )
    (source_root / "sdk" / "ddraw.lib").write_bytes(b"changed after source seal")
    with pytest.raises(ClassicProjectError, match="differs from its project SDK"):
        classic_runtime_graph._graph_system_library_map(
            bundle,
            graph,
            installation,
            effective_root=source_root,
            build_root=build_root,
        )


def test_published_target_reseal_detects_same_inode_mutation(tmp_path: Path) -> None:
    bundle = _prepare_bundle(tmp_path)
    snapshot = atomic_publish_relative(tmp_path, "state/program.exe", b"candidate")
    executor = object.__new__(classic_runtime.ClassicProducerGraphBuildExecutor)
    executor.bundle = bundle
    executor.project_root = tmp_path
    executor.record = classic_evidence.ClassicProducerGraphExecutionRecord(
        images=(
            classic_evidence.ClassicProducedImage(
                "program",
                tmp_path / "private/APP.EXE",
                snapshot.path,
                "linker.program.0000",
                "linker",
                (),
                snapshot,
            ),
        ),
        witnesses=(),
    )
    executor.reseal_published_targets()

    snapshot.path.write_bytes(b"mutated!!")
    with pytest.raises(ClassicProjectError, match="changed before report commit"):
        executor.reseal_published_targets()


def test_semantic_statement_receipts_are_collected_once_by_content() -> None:
    first = Digest.from_bytes(b"first")
    second = Digest.from_bytes(b"second")
    statement = {
        "seed": {"digest": first.model_dump(mode="json"), "size": 5},
        "nested": [
            {"candidate": {"digest": second.model_dump(mode="json"), "size": 6}},
            {"digest": "not-a-digest", "size": 7},
            {"digest": first.model_dump(mode="json"), "size": "5"},
        ],
    }

    assert classic_evidence._statement_receipt_keys(statement) == frozenset(
        {(first.value, 5), (second.value, 6)}
    )


def test_only_the_final_terminal_stage_owns_the_public_target_path() -> None:
    first = classic_evidence._terminal_stage_logical_path(
        target_id="config",
        public_path="build/CONFIG.EXE",
        intervention_id="project_metadata",
        index=0,
        count=2,
    )
    final = classic_evidence._terminal_stage_logical_path(
        target_id="config",
        public_path="build/CONFIG.EXE",
        intervention_id="project_link_order",
        index=1,
        count=2,
    )

    assert first == (
        ".reprobit/stages/terminal/config/0000-project_metadata.EXE"
    )
    assert final == "build/CONFIG.EXE"


def test_compiler_pdb_companion_resolves_only_the_declared_dos_path(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "CMakeFiles/config.dir/CONFIG"
    directory.mkdir(parents=True)
    actual = directory / "configcommandlineinfo.cpp.obj.pdb"
    actual.write_bytes(b"pdb")
    declared = directory / "ConfigCommandLineInfo.cpp.obj.pdb"

    resolved = classic_runtime_producer.ClassicProducerExecution.compiler_companion_output(declared)

    assert resolved == actual.resolve(strict=True)
    unrelated = directory / "configcommandlineinfo.cpp.obj.idb"
    unrelated.write_bytes(b"not a declared companion")
    with pytest.raises(ClassicProjectError, match="0 physical aliases"):
        classic_runtime_producer.ClassicProducerExecution.compiler_companion_output(
            directory / "Different.cpp.obj.pdb"
        )


def test_compiler_node_rejects_preexisting_lowercase_pdb_alias(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    build_root = tmp_path / "build"
    toolchain_root = tmp_path / "toolchain"
    source_root.mkdir()
    build_root.mkdir()
    toolchain_root.mkdir()
    (source_root / "Unit.cpp").write_bytes(b"int unit();\n")
    pdb_parent = build_root / "obj"
    pdb_parent.mkdir()
    (pdb_parent / "unit.cpp.obj.pdb").write_bytes(b"preexisting")
    node = ProducerNode(
        id="compiler.app.0000",
        role=ProducerRole.COMPILER,
        owner="app",
        arguments=("/nologo",),
        inputs=("source/Unit.cpp",),
        outputs=("build/obj/Unit.cpp.obj", "build/obj/Unit.cpp.obj.pdb"),
    )
    executor = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    executor.effective_root = source_root
    executor.build_root = build_root
    executor.toolchain_root = toolchain_root
    executor._output_lock = Lock()
    executor._physical_outputs = {}

    with (
        ProcessSupervisor() as supervisor,
        pytest.raises(ClassicProjectError, match="output already exists"),
    ):
        executor.run_node(supervisor, node, CancellationToken())


def test_compiler_pdb_companion_rejects_casefold_aliases_when_supported(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "objects"
    directory.mkdir()
    lower = directory / "unit.pdb"
    upper = directory / "UNIT.PDB"
    lower.write_bytes(b"lower")
    upper.write_bytes(b"upper")
    if lower.samefile(upper):
        pytest.skip("fixture filesystem is case-insensitive")

    with pytest.raises(ClassicProjectError, match="2 physical aliases"):
        classic_runtime_producer.ClassicProducerExecution.compiler_companion_output(
            directory / "Unit.Pdb"
        )


def test_generated_overlay_inputs_are_absent_until_the_sealed_epoch(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "project"
    effective_root = tmp_path / "effective"
    (project_root / "src").mkdir(parents=True)
    (effective_root / "src").mkdir(parents=True)
    clean = b"int unit();\n"
    effective = b"int unit(); /* entropy */\n"
    carrier = b"int carrier() { return 0; }\n"
    header = b"#define REPROBIT_CARRIER 1\n"
    (project_root / "src/unit.cpp").write_bytes(clean)
    (effective_root / "src/unit.cpp").write_bytes(effective)
    (effective_root / "src/carrier.cpp").write_bytes(carrier)
    (effective_root / "src/carrier.h").write_bytes(header)
    overlay = ClassicRecipeIntervention(
        id="overlay.program",
        scope=Scope(target="program"),
        rationale="sealed two-epoch fixture",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="program",
        parameters=(
            ClassicField(
                name="graph",
                value={
                    "generated_tus": [{"path": "src/carrier.cpp"}],
                    "link_admissions": [],
                },
            ),
            ClassicField(
                name="outputs",
                value=[
                    {
                        "path": "src/unit.cpp",
                        "clean": Digest.from_bytes(clean).value,
                        "effective": Digest.from_bytes(effective).value,
                        "size": len(effective),
                    },
                    {
                        "path": "src/carrier.cpp",
                        "effective": Digest.from_bytes(carrier).value,
                        "size": len(carrier),
                    },
                    {
                        "path": "src/carrier.h",
                        "effective": Digest.from_bytes(header).value,
                        "size": len(header),
                    },
                ],
            ),
            ClassicField(name="schema", value=2),
        ),
    )
    bundle = cast(
        ProjectBundle,
        SimpleNamespace(interventions=(overlay,)),
    )

    epoch = classic_runtime_preparation._capture_and_restore_overlay_outputs(
        bundle,
        project_root=project_root,
        effective_root=effective_root,
    )

    assert (effective_root / "src/unit.cpp").read_bytes() == clean
    assert not os.path.lexists(effective_root / "src/carrier.cpp")
    assert not os.path.lexists(effective_root / "src/carrier.h")
    assert epoch.generated_inputs == frozenset({"src/carrier.cpp", "src/carrier.h"})
    assert epoch.carrier_input_seals == {"src/carrier.cpp": ("src/carrier.cpp", "src/carrier.h")}

    events: list[tuple[int, int, str, str]] = []
    executor = object.__new__(classic_runtime_overlay.ClassicOverlayEpochs)
    executor.effective_root = effective_root
    executor.overlay_witnesses = (
        InterventionWitness("overlay.program", "program", Digest.from_bytes(b"overlay")),
    )
    executor.project_source_pairs = epoch.project_source_pairs
    executor.generated_inputs = epoch.generated_inputs
    executor.generated_translation_units = frozenset(epoch.carrier_input_seals)
    executor.ordinary_generated_inputs = ("src/carrier.h",)
    executor.overlay_effective_outputs = MappingProxyType(dict(epoch.effective_outputs))
    executor.carrier_input_seals = MappingProxyType(dict(epoch.carrier_input_seals))
    executor.producer = SimpleNamespace(
        require_regular=classic_runtime_producer.ClassicProducerExecution.require_regular
    )
    executor._progress = classic_runtime_producer.ClassicProgressReporter(
        2,
        lambda completed, total, phase, node_id, _kind, _reason: events.append(
            (completed, total, phase, node_id)
        ),
    )
    ordinary_seal = classic_runtime_producer._tree_file_seal(effective_root)
    effective_receipt, effective_seal = executor.materialize_certified_project_overlay_epoch(
        ordinary_seal
    )

    assert effective_receipt.step_id == "source.certified-project-overlay-epoch"
    assert (effective_root / "src/unit.cpp").read_bytes() == effective
    assert (effective_root / "src/carrier.h").read_bytes() == header
    assert not os.path.lexists(effective_root / "src/carrier.cpp")

    receipt, final_seal = executor.materialize_generated_input_epoch(effective_seal)

    assert receipt.step_id == "source.generated-input-epoch"
    assert (effective_root / "src/carrier.cpp").read_bytes() == carrier
    assert (effective_root / "src/carrier.h").read_bytes() == header
    classic_runtime_producer._require_unchanged_tree(
        final_seal,
        root=effective_root,
        label="fixture final source epoch",
    )
    assert events == [
        (1, 2, "source-epoch", "source.certified-project-overlay-epoch"),
        (2, 2, "source-epoch", "source.generated-input-epoch"),
    ]


def test_compiler_namespace_census_covers_every_source_and_toolchain_file(
    tmp_path: Path,
) -> None:
    logical_root = tmp_path / "logical-drive"
    source_root = logical_root / "source"
    toolchain_root = logical_root / "toolchain"
    include_root = toolchain_root / "include"
    source_root.mkdir(parents=True)
    include_root.mkdir(parents=True)
    main = source_root / "main.cpp"
    asset = source_root / "dialog.bmp"
    forced = include_root / "forced.h"
    main.write_bytes(b"int main();\n")
    asset.write_bytes(b"BMasset")
    forced.write_bytes(b"#define SEALED 1\n")

    executor = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    executor._logical_drive_root = logical_root
    executor._logical_drive_letter = "R"
    executor.effective_root = source_root
    executor.toolchain_root = toolchain_root
    executor._namespace_payload_intern = {}
    executor._compiler_namespaces = {}
    executor.bundle = cast(
        ProjectBundle,
        SimpleNamespace(
            spec=SimpleNamespace(
                paths=SimpleNamespace(source=r"R:\source", toolchain=r"R:\toolchain")
            )
        ),
    )

    with (
        SealedNamespaceLease(
            trees=(NamespaceTree("source", source_root, logical_root),),
            retain_payload_labels=("source",),
        ) as source,
        SealedNamespaceLease(
            trees=(NamespaceTree("toolchain", toolchain_root, logical_root),),
            retain_payload_labels=("toolchain",),
        ) as authority,
    ):
        namespace = executor.capture_compiler_namespace(
            "fixture-epoch",
            source=source.snapshot,
            authority=authority.snapshot,
        )
        reads = namespace.reads

    assert [item.logical_path for item in reads] == [
        r"R:\source\dialog.bmp",
        r"R:\source\main.cpp",
        r"R:\toolchain\include\forced.h",
    ]
    assert all(item.parent_index is None for item in reads)
    assert all(item.payload is not None for item in reads)
    assert {item.origin for item in reads} == {
        IncludeOrigin.PROJECT_SOURCE,
        IncludeOrigin.TOOLCHAIN_TREE,
    }
    assert namespace.evidence.namespace_id == "fixture-epoch"
    assert len(namespace.evidence.members) == 3


def test_compiler_namespace_payload_census_is_shared_across_nodes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    logical_root = tmp_path / "logical-drive"
    source_root = logical_root / "source"
    toolchain_root = logical_root / "toolchain"
    source_root.mkdir(parents=True)
    toolchain_root.mkdir(parents=True)
    (source_root / "unit.h").write_bytes(b"#define VALUE 1\n")
    (toolchain_root / "stddef.h").write_bytes(b"typedef unsigned size_t;\n")

    executor = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    executor._logical_drive_root = logical_root
    executor._logical_drive_letter = "R"
    executor.effective_root = source_root
    executor.toolchain_root = toolchain_root
    executor._namespace_payload_intern = {}
    executor._compiler_namespaces = {}
    executor._producer_reads = []
    executor._evidence_lock = Lock()
    executor.role_tool_ids = MappingProxyType({ProducerRole.COMPILER: "compiler"})
    compiler_digest = Digest.from_bytes(b"compiler")
    executor.bundle = cast(
        ProjectBundle,
        SimpleNamespace(
            spec=SimpleNamespace(
                paths=SimpleNamespace(
                    source=r"R:\source",
                    build=r"R:\build",
                    toolchain=r"R:\toolchain",
                )
            ),
            toolchain_lock=SimpleNamespace(
                tools=(SimpleNamespace(id="compiler", digest=compiler_digest),)
            ),
        ),
    )
    executor._compiler_environment_digest = Digest.from_bytes(b"environment")
    executor._compiler_path_profile_digest = Digest.from_bytes(b"path-profile")
    digest_calls = 0
    original_digest = compiler_namespace_evidence_digest

    def counted_digest(value: object) -> Digest:
        nonlocal digest_calls
        digest_calls += 1
        return original_digest(cast(CompilerNamespaceEvidence, value))

    monkeypatch.setattr(
        classic_runtime_producer,
        "compiler_namespace_evidence_digest",
        counted_digest,
    )
    with (
        SealedNamespaceLease(
            trees=(NamespaceTree("source", source_root, logical_root),),
            retain_payload_labels=("source",),
        ) as source,
        SealedNamespaceLease(
            trees=(NamespaceTree("toolchain", toolchain_root, logical_root),),
            retain_payload_labels=("toolchain",),
        ) as authority,
    ):
        namespace = executor.capture_compiler_namespace(
            "effective-project-epoch",
            source=source.snapshot,
            authority=authority.snapshot,
        )

    nodes = tuple(
        ProducerNode(
            id=f"compiler.program.{index:04d}",
            role=ProducerRole.COMPILER,
            owner="program",
            arguments=("/c", f"${{SOURCE}}/unit-{index}.cpp"),
            inputs=(f"source/unit-{index}.cpp",),
            outputs=(f"build/unit-{index}.obj", f"build/unit-{index}.pdb"),
        )
        for index in range(64)
    )
    executor._producer_reads.extend(
        classic_evidence.ClassicProducerReadReceipt(
            node.id,
            node.id,
            ProducerRole.COMPILER,
            "effective",
            (),
            "complete-readable-namespace-v1",
            namespace.evidence.namespace_id,
            namespace.evidence.namespace_digest,
            len(namespace.evidence.members),
        )
        for node in nodes
    )

    invocations = tuple(
        executor.compiler_epoch_invocation(node, epoch="effective") for node in nodes
    )

    assert digest_calls == 1
    assert len(namespace.reads) == 2
    assert all(not receipt.reads for receipt in executor._producer_reads)
    assert {item.namespace_digest for item in invocations} == {namespace.evidence.namespace_digest}


def test_counterfactual_compiler_audit_captures_and_erases_only_planned_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_root = tmp_path / "source"
    build_root = tmp_path / "build"
    toolchain_root = tmp_path / "toolchain"
    source_root.mkdir()
    build_root.mkdir()
    toolchain_root.mkdir()
    source = source_root / "Unit.cpp"
    source.write_bytes(b"int unit();\n")
    node = ProducerNode(
        id="compiler.program.0000",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=("/c", "${SOURCE}/Unit.cpp"),
        inputs=("source/Unit.cpp",),
        outputs=("build/obj/Unit.obj", "build/obj/Unit.pdb"),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"source topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(node,),
    )
    events: list[tuple[int, int, str, str]] = []
    executor = object.__new__(classic_runtime_overlay.ClassicOverlayEpochs)
    executor.graph = graph
    executor.bundle = cast(
        ProjectBundle,
        SimpleNamespace(
            source_manifest=SimpleNamespace(
                complete=True,
                entries=(
                    SimpleNamespace(
                        path="Unit.cpp",
                        size=source.stat().st_size,
                        digest=Digest.from_bytes(source.read_bytes()),
                    ),
                ),
            ),
        ),
    )
    executor.effective_root = source_root
    executor.build_root = build_root
    executor.toolchain_root = toolchain_root
    executor.generated_node_inputs = MappingProxyType({})
    executor.compiler_epoch_plan = ProjectOverlayCompilerEpochPlan(
        MappingProxyType({"Unit.cpp": source.read_bytes()}),
        frozenset({node.id}),
        frozenset(),
        MappingProxyType({"overlay.program": ()}),
    )
    executor.overlay_witnesses = (
        InterventionWitness("overlay.program", "program", Digest.from_bytes(b"overlay")),
    )
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer.effective_root = source_root
    producer.build_root = build_root
    producer.toolchain_root = toolchain_root
    producer._output_lock = Lock()
    producer._physical_outputs = {}
    executor.producer = producer
    executor._progress = classic_runtime_producer.ClassicProgressReporter(
        3,
        lambda completed, total, phase, node_id, _kind, _reason: events.append(
            (completed, total, phase, node_id)
        ),
    )
    producer._progress = executor._progress

    def run_nodes(
        self: classic_runtime_producer.ClassicProducerExecution,
        supervisor: ProcessSupervisor,
        nodes: tuple[ProducerNode, ...],
        *,
        completed: set[str],
        output_steps: dict[Path, str],
        cancellation: CancellationToken,
        step_id_prefix: str = "",
        progress_phase: str | None = None,
        log_namespace: str = "producers",
        include_authority: object | None = None,
        include_trace_epoch: str | None = None,
        compiler_namespace_id: str | None = None,
    ) -> list[StepExecutionReceipt]:
        del supervisor, cancellation, log_namespace
        assert include_authority is not None
        assert include_trace_epoch == "declaration-counterfactual"
        assert compiler_namespace_id == "fixture-counterfactual"
        assert nodes == (node,)
        declared = self.declared_outputs(node)
        declared[0].parent.mkdir(parents=True)
        declared[0].write_bytes(b"clean-object")
        physical_pdb = declared[1].with_name("unit.pdb")
        physical_pdb.write_bytes(b"clean-pdb")
        with self._output_lock:
            self._physical_outputs.update({declared[0]: declared[0], declared[1]: physical_pdb})
        completed.add(node.id)
        output_steps.update(
            {
                declared[0]: f"{step_id_prefix}{node.id}",
                physical_pdb: f"{step_id_prefix}{node.id}",
            }
        )
        step_id = f"{step_id_prefix}{node.id}"
        self._progress.emit(progress_phase or "compile", step_id)
        return [classic_runtime_producer._internal_step(step_id, {"ran": node.id}, 0.0)]

    monkeypatch.setattr(
        classic_runtime_producer.ClassicProducerExecution,
        "run_graph_nodes",
        run_nodes,
    )
    monkeypatch.setattr(
        producer,
        "include_authority",
        lambda: object(),
    )
    invocation = CompilerEpochInvocation(
        "compiler",
        Digest.from_bytes(b"compiler"),
        node.arguments,
        r"R:\build",
        Digest.from_bytes(b"environment"),
        Digest.from_bytes(b"path-profile"),
        Digest.from_bytes(b"invocation"),
        "fixture-counterfactual",
        Digest.from_bytes(b"namespace"),
        1,
    )
    monkeypatch.setattr(
        producer,
        "compiler_epoch_invocation",
        lambda current, *, epoch: invocation,
    )
    source_seal = classic_runtime_producer._tree_file_seal(source_root)
    clean_receipt = executor.capture_clean_source_inputs(source_seal)
    with ProcessSupervisor() as supervisor:
        receipts = executor.run_counterfactual_compiler_audit(
            supervisor,
            (node,),
            source_seal=source_seal,
            cancellation=CancellationToken(),
            compiler_namespace_id="fixture-counterfactual",
        )

    assert clean_receipt.step_id == "source.clean-authority-capture"
    assert [item.step_id for item in receipts] == [
        "audit.counterfactual.compiler.program.0000",
        "source.counterfactual-compiler-audit-capture",
    ]
    assert executor._counterfactual_compiler_audits == (
        ProjectOverlayCounterfactualAudit(
            node.id,
            "source/Unit.cpp",
            "build/obj/Unit.obj",
            b"clean-object",
            invocation,
        ),
    )
    assert executor._clean_source_inputs == (CleanSourceInput("Unit.cpp", b"int unit();\n"),)
    assert producer._physical_outputs == {}
    assert classic_runtime_producer._tree_file_seal(build_root) == {}
    assert events == [
        (1, 3, "source-epoch", "source.clean-authority-capture"),
        (
            2,
            3,
            "counterfactual-audit",
            "audit.counterfactual.compiler.program.0000",
        ),
        (3, 3, "source-epoch", "source.counterfactual-compiler-audit-capture"),
    ]


def test_counterfactual_compiler_audit_rejects_a_plan_mismatch(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    build_root = tmp_path / "build"
    source_root.mkdir()
    build_root.mkdir()
    node = ProducerNode(
        id="compiler.program.0000",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=("/c", "${SOURCE}/Unit.cpp"),
        inputs=("source/Unit.cpp",),
        outputs=("build/Unit.obj", "build/Unit.pdb"),
    )
    executor = object.__new__(classic_runtime_overlay.ClassicOverlayEpochs)
    executor.graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"source topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(node,),
    )
    executor.generated_node_inputs = MappingProxyType({})
    executor.compiler_epoch_plan = ProjectOverlayCompilerEpochPlan(
        MappingProxyType({"Unit.cpp": b"int unit();\n"}),
        frozenset({node.id}),
        frozenset(),
        MappingProxyType({"overlay.program": ()}),
    )
    executor.overlay_witnesses = (
        InterventionWitness("overlay.program", "program", Digest.from_bytes(b"overlay")),
    )
    executor.effective_root = source_root

    with (
        ProcessSupervisor() as supervisor,
        pytest.raises(ClassicProjectError, match="derived sparse plan"),
    ):
        executor.run_counterfactual_compiler_audit(
            supervisor,
            (),
            source_seal=classic_runtime_producer._tree_file_seal(source_root),
            cancellation=CancellationToken(),
            compiler_namespace_id="fixture-counterfactual",
        )


def test_certified_overlay_epoch_rejects_tampered_clean_source(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    path = source_root / "Unit.cpp"
    path.write_bytes(b"tampered")
    executor = object.__new__(classic_runtime_overlay.ClassicOverlayEpochs)
    executor.effective_root = source_root
    executor.overlay_witnesses = (
        InterventionWitness("overlay.program", "program", Digest.from_bytes(b"overlay")),
    )
    executor.project_source_pairs = (ProjectOverlaySourcePair("Unit.cpp", b"clean", b"effective"),)
    executor.generated_translation_units = frozenset()
    executor.ordinary_generated_inputs = ()
    executor.producer = SimpleNamespace(
        require_regular=classic_runtime_producer.ClassicProducerExecution.require_regular
    )
    executor._progress = classic_runtime_producer.ClassicProgressReporter(1, None)

    with pytest.raises(ClassicProjectError, match="source preimage changed"):
        executor.materialize_certified_project_overlay_epoch(
            classic_runtime_producer._tree_file_seal(source_root)
        )


def test_certified_overlay_epoch_rejects_preexisting_no_clean_input(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "generated.h").write_bytes(b"stale")
    executor = object.__new__(classic_runtime_overlay.ClassicOverlayEpochs)
    executor.effective_root = source_root
    executor.overlay_witnesses = (
        InterventionWitness("overlay.program", "program", Digest.from_bytes(b"overlay")),
    )
    executor.project_source_pairs = (
        ProjectOverlaySourcePair("generated.h", None, b"struct Generated {};\n"),
    )
    executor.generated_translation_units = frozenset()
    executor.ordinary_generated_inputs = ("generated.h",)
    executor.producer = SimpleNamespace(
        require_regular=classic_runtime_producer.ClassicProducerExecution.require_regular
    )
    executor._progress = classic_runtime_producer.ClassicProgressReporter(1, None)

    with pytest.raises(ClassicProjectError, match="already exists"):
        executor.materialize_certified_project_overlay_epoch(
            classic_runtime_producer._tree_file_seal(source_root)
        )


def test_effective_compiler_capture_freezes_raw_products_and_epoch_visibility(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "source"
    build_root = tmp_path / "build"
    toolchain_root = tmp_path / "toolchain"
    source_root.mkdir()
    build_root.mkdir()
    toolchain_root.mkdir()
    ordinary = ProducerNode(
        id="compiler.program.0000",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=("/c", "${SOURCE}/Unit.cpp"),
        inputs=("source/generated.h", "source/Unit.cpp"),
        outputs=("build/Unit.obj", "build/Unit.pdb"),
    )
    carrier = ProducerNode(
        id="compiler.program.0001",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=("/c", "${SOURCE}/carrier.cpp"),
        inputs=("source/carrier.cpp", "source/generated.h"),
        outputs=("build/carrier.obj", "build/carrier.pdb"),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"source topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(ordinary, carrier),
    )
    ordinary_object = build_root / "Unit.obj"
    carrier_object = build_root / "carrier.obj"
    ordinary_pdb = build_root / "Unit.pdb"
    carrier_pdb = build_root / "carrier.pdb"
    ordinary_object.write_bytes(b"raw-effective-ordinary")
    carrier_object.write_bytes(b"raw-effective-carrier")
    ordinary_pdb.write_bytes(b"ordinary-pdb")
    carrier_pdb.write_bytes(b"carrier-pdb")
    events: list[tuple[int, int, str, str]] = []
    executor = object.__new__(classic_runtime_overlay.ClassicOverlayEpochs)
    executor.graph = graph
    executor.bundle = cast(
        ProjectBundle,
        SimpleNamespace(spec=SimpleNamespace(paths=SimpleNamespace(build=r"R:\build"))),
    )
    executor.effective_root = source_root
    executor.build_root = build_root
    executor.toolchain_root = toolchain_root
    executor.generated_node_inputs = MappingProxyType({carrier.id: ("carrier.cpp", "generated.h")})
    executor.ordinary_generated_inputs = ("generated.h",)
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer.effective_root = source_root
    producer.build_root = build_root
    producer.toolchain_root = toolchain_root
    producer._output_lock = Lock()
    producer._physical_outputs = {
        ordinary_object: ordinary_object,
        ordinary_pdb: ordinary_pdb,
        carrier_object: carrier_object,
        carrier_pdb: carrier_pdb,
    }
    executor.producer = producer
    executor._effective_compiler_products = ()
    executor._captured_compiler_outputs = ()
    executor._counterfactual_compiler_audits = ()
    executor._progress = classic_runtime_producer.ClassicProgressReporter(
        1,
        lambda completed, total, phase, node_id, _kind, _reason: events.append(
            (completed, total, phase, node_id)
        ),
    )
    generated_invocation = CompilerEpochInvocation(
        "compiler",
        Digest.from_bytes(b"compiler"),
        carrier.arguments,
        r"R:\build",
        Digest.from_bytes(b"environment"),
        Digest.from_bytes(b"path-profile"),
        Digest.from_bytes(b"invocation"),
        "generated-project-epoch",
        Digest.from_bytes(b"namespace"),
        2,
    )
    effective_invocation = replace(
        generated_invocation,
        arguments=ordinary.arguments,
        namespace_id="effective-project-epoch",
    )
    monkeypatch.setattr(
        classic_runtime_producer.ClassicProducerExecution,
        "compiler_epoch_invocation",
        lambda self, node, *, epoch: (
            generated_invocation if epoch == "generated" else effective_invocation
        ),
    )

    receipt = executor.capture_effective_compiler_products()
    ordinary_object.write_bytes(b"composed-ordinary")
    carrier_object.write_bytes(b"mutated-carrier")
    products = executor._compiler_products()

    assert receipt.step_id == "source.effective-compiler-product-capture"
    assert products == (
        CompilerProduct(
            ordinary.id,
            "source/Unit.cpp",
            "build/Unit.obj",
            b"raw-effective-ordinary",
            ("generated.h",),
            effective_invocation,
        ),
        CompilerProduct(
            carrier.id,
            "source/carrier.cpp",
            "build/carrier.obj",
            b"raw-effective-carrier",
            ("carrier.cpp", "generated.h"),
            generated_invocation,
        ),
    )
    captured: tuple[classic_evidence.ClassicCapturedProducerOutput, ...] = (
        executor._captured_compiler_outputs
    )
    assert [item.reference for item in captured] == [
        "build/Unit.obj",
        "build/Unit.pdb",
        "build/carrier.obj",
        "build/carrier.pdb",
    ]
    assert events == [
        (
            1,
            1,
            "source-epoch",
            "source.effective-compiler-product-capture",
        )
    ]


def _link_control_executor(
    tmp_path: Path,
    *,
    definition: bytes,
    linker_controls: tuple[str, ...] = (),
) -> tuple[
    classic_runtime_overlay.ClassicOverlayEpochs,
    ProducerNode,
]:
    source_root = tmp_path / "source"
    build_root = tmp_path / "build"
    toolchain_root = tmp_path / "toolchain"
    source_root.mkdir()
    build_root.mkdir()
    toolchain_root.mkdir()
    (source_root / "app.def").write_bytes(definition)
    (build_root / "unit.obj").write_bytes(
        _directive_object(b"/INCLUDE:_forced /EXPORT:_directive_export ")
    )
    compiler = ProducerNode(
        id="compiler.program.0000",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=("/c", "${SOURCE}/unit.cpp"),
        inputs=("source/unit.cpp",),
        outputs=("build/unit.obj", "build/unit.pdb"),
    )
    linker = ProducerNode(
        id="linker.program.0001",
        role=ProducerRole.LINKER,
        owner="program",
        target_id="program",
        arguments=(
            "${BUILD}/unit.obj",
            "/DEF:${SOURCE}/app.def",
            *linker_controls,
            "/out:${BUILD}/APP.EXE",
        ),
        inputs=("build/unit.obj", "source/app.def"),
        outputs=("build/APP.EXE",),
        depends_on=(compiler.id,),
    )
    executor = object.__new__(classic_runtime_overlay.ClassicOverlayEpochs)
    executor.graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"source topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(compiler, linker),
    )
    executor.targets = (
        classic_runtime_graph.ClassicProducerTarget(
            "program", "program", build_root / "APP.EXE", None, linker.id
        ),
    )
    executor.effective_root = source_root
    executor.build_root = build_root
    executor.toolchain_root = toolchain_root
    executor.system_libraries = MappingProxyType({})
    executor._link_directive_closures = MappingProxyType({})
    executor._module_definition_receipts = MappingProxyType({})
    executor._progress = classic_runtime_producer.ClassicProgressReporter(1, None)
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer.graph = executor.graph
    producer.effective_root = source_root
    producer.build_root = build_root
    producer.toolchain_root = toolchain_root
    producer._output_lock = Lock()
    producer._physical_outputs = {}
    executor.producer = producer
    return executor, linker


def _analysis_link_executor(
    tmp_path: Path,
    *,
    arguments: tuple[str, ...] | None = None,
) -> tuple[
    classic_runtime.ClassicProducerGraphBuildExecutor,
    classic_runtime_producer.ClassicProducerExecution,
    classic_runtime_graph.ClassicProducerTarget,
    ProducerNode,
    Path,
    Path,
]:
    project_root = tmp_path / "project"
    drive_root = tmp_path / "drive"
    build_root = drive_root / "build"
    project_root.mkdir()
    build_root.mkdir(parents=True)
    bundle = _prepare_bundle(project_root)
    target = classic_runtime_graph.ClassicProducerTarget(
        "program",
        "program",
        build_root / "APP.EXE",
        None,
        "linker.program.0000",
    )
    node = ProducerNode(
        id=target.link_node_id,
        role=ProducerRole.LINKER,
        owner="program",
        target_id="program",
        arguments=(
            ("${BUILD}/unit.obj", *arguments)
            if arguments is not None
            else (
                "${BUILD}/unit.obj",
                "/out:${BUILD}/APP.EXE",
                "/implib:${BUILD}/APP.lib",
                "/pdb:${BUILD}/APP.pdb",
                "/incremental:no",
            )
        ),
        inputs=("build/unit.obj",),
        outputs=("build/APP.EXE",),
    )
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer.bundle = bundle
    producer.session_root = tmp_path / "session"
    producer.build_root = build_root
    producer._logical_drive_root = drive_root.resolve(strict=True)
    producer._logical_drive_letter = "R"
    producer.analysis_link_options = ("/DEBUG",)
    producer.role_commands = MappingProxyType({ProducerRole.LINKER: tmp_path / "LINK.EXE"})
    producer.link_timeout = 30.0
    producer._progress = classic_runtime_producer.ClassicProgressReporter(2, None)
    executor = object.__new__(classic_runtime.ClassicProducerGraphBuildExecutor)
    executor.producer = producer
    executor.analysis_pdb_paths = MappingProxyType({"program": "state/program.PDB"})
    executor._progress = producer._progress
    return executor, producer, target, node, project_root, drive_root


def test_analysis_link_plan_isolates_every_linker_output(tmp_path: Path) -> None:
    _executor, producer, target, node, _project_root, _drive_root = _analysis_link_executor(
        tmp_path
    )
    plan = producer._analysis_link_plan(target, node)

    assert plan.arguments[-1] == "/DEBUG"
    assert sum(argument.casefold() == "/debug" for argument in plan.arguments) == 1
    for prefix in ("/out:", "/implib:", "/pdb:"):
        values = [
            argument.split(":", 1)[1]
            for argument in plan.arguments
            if argument.casefold().startswith(prefix)
        ]
        assert len(values) == 1
        assert ".reprobit-analysis" in values[0]
    assert {path.suffix.casefold() for path in plan.allowed_outputs} == {
        ".exe",
        ".pdb",
        ".lib",
        ".exp",
    }


@pytest.mark.parametrize(
    ("arguments", "message"),
    (
        (
            ("/out:${BUILD}/APP.EXE", "/incremental:no"),
            "exactly one /OUT and one /PDB",
        ),
        (
            (
                "/out:${BUILD}/APP.EXE",
                "/pdb:${BUILD}/APP.pdb",
                "/DEBUG",
            ),
            "already contains an analysis-only debug option",
        ),
        (
            (
                "/out:${BUILD}/APP.EXE",
                "/pdb:${BUILD}/APP.pdb",
                "/incremental:yes",
            ),
            "does not admit incremental linker state",
        ),
        (
            (
                "/out:${BUILD}/APP.EXE",
                "/pdb:${BUILD}/APP.pdb",
            ),
            "requires exactly one /INCREMENTAL:NO",
        ),
    ),
)
def test_analysis_link_plan_rejects_widened_or_ambiguous_commands(
    tmp_path: Path,
    arguments: tuple[str, ...],
    message: str,
) -> None:
    _executor, producer, target, node, _project_root, _drive_root = _analysis_link_executor(
        tmp_path,
        arguments=arguments,
    )
    with pytest.raises(ClassicProjectError, match=message):
        producer._analysis_link_plan(target, node)


def test_analysis_link_stages_private_pair_without_publishing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor, producer, target, node, project_root, drive_root = _analysis_link_executor(tmp_path)
    target.output.write_bytes(b"exact raw image")
    (producer.build_root / "unit.obj").write_bytes(b"object")
    exact_snapshot = atomic_publish_relative(
        project_root,
        "state/program.exe",
        b"certified exact image",
    )
    lane = SimpleNamespace(environment={}, windows_lineage_planner=None)
    producer._lane_pool = SimpleNamespace(acquire=lambda: lane, release=lambda _lane: None)
    captured: list[tuple[str, ...]] = []

    def fake_run(
        _supervisor: object,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout: float,
        log: Path,
        **_kwargs: object,
    ) -> tuple[ProcessResult, CommandSpec]:
        captured.append(tuple(argv))

        def output_path(prefix: str) -> Path:
            value = next(
                argument.split(":", 1)[1]
                for argument in argv
                if argument.casefold().startswith(prefix)
            )
            windows = PureWindowsPath(value)
            assert windows.drive.casefold() == "r:"
            return drive_root.joinpath(*windows.parts[1:])

        image = output_path("/out:")
        pdb = output_path("/pdb:")
        image.parent.mkdir(parents=True, exist_ok=True)
        image.write_bytes(b"analysis image -- deliberately not certified")
        pdb.with_name(pdb.name.lower()).write_bytes(b"analysis pdb")
        spec = CommandSpec.create(
            argv,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout,
            log_path=log,
        )
        return ProcessResult(tuple(argv), 0, b"linked", 1, 0.01), spec

    monkeypatch.setattr(classic_runtime_producer, "_run", fake_run)
    pending = executor._run_analysis_link(
        cast(ProcessSupervisor, object()),
        target,
        node,
        CancellationToken(),
    )

    assert captured and captured[0][-1] == "/DEBUG"
    assert exact_snapshot.path.read_bytes() == b"certified exact image"
    assert target.output.read_bytes() == b"exact raw image"
    assert pending.logical_path == "state/program.PDB"
    assert pending.execution.pdb.read_bytes() == b"analysis pdb"
    assert pending.execution.image != target.output
    assert pending.link_receipt.step_id == "analysis-link.program"
    assert not (project_root / "state/program.PDB").exists()
    assert executor._progress.completed == 1


def test_analysis_link_rejects_mutation_of_exact_build_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor, producer, target, node, _project_root, drive_root = _analysis_link_executor(tmp_path)
    target.output.write_bytes(b"exact raw image")
    (producer.build_root / "unit.obj").write_bytes(b"object")
    lane = SimpleNamespace(environment={}, windows_lineage_planner=None)
    producer._lane_pool = SimpleNamespace(acquire=lambda: lane, release=lambda _lane: None)

    def mutating_run(
        _supervisor: object,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: object,
        timeout: float,
        log: Path,
        **_kwargs: object,
    ) -> tuple[ProcessResult, CommandSpec]:
        controls = {
            prefix: next(
                argument.split(":", 1)[1]
                for argument in argv
                if argument.casefold().startswith(prefix)
            )
            for prefix in ("/out:", "/pdb:")
        }
        for prefix, payload in (("/out:", b"analysis"), ("/pdb:", b"pdb")):
            windows = PureWindowsPath(controls[prefix])
            path = drive_root.joinpath(*windows.parts[1:])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        target.output.write_bytes(b"mutated")
        spec = CommandSpec.create(
            argv,
            cwd=cwd,
            environment={},
            timeout_seconds=timeout,
            log_path=log,
        )
        return ProcessResult(tuple(argv), 0, b"linked", 1, 0.01), spec

    monkeypatch.setattr(classic_runtime_producer, "_run", mutating_run)
    with pytest.raises(ClassicProjectError, match="wrote undeclared build-tree files"):
        executor._run_analysis_link(
            cast(ProcessSupervisor, object()),
            target,
            node,
            CancellationToken(),
        )


def _dependent_link_control_executor(
    tmp_path: Path,
) -> tuple[
    classic_runtime.ClassicProducerGraphBuildExecutor,
    classic_runtime_overlay.ClassicOverlayEpochs,
    classic_runtime_producer.ClassicProducerExecution,
    tuple[ProducerNode, ...],
]:
    source_root = tmp_path / "source"
    build_root = tmp_path / "build"
    toolchain_root = tmp_path / "toolchain"
    source_root.mkdir()
    build_root.mkdir()
    toolchain_root.mkdir()
    compilers = tuple(
        ProducerNode(
            id=f"compiler.{owner}.{index:04d}",
            role=ProducerRole.COMPILER,
            owner=owner,
            arguments=("/c", f"${{SOURCE}}/{owner}.cpp"),
            inputs=(f"source/{owner}.cpp",),
            outputs=(f"build/{owner}.obj", f"build/{owner}.pdb"),
        )
        for index, owner in enumerate(("app", "library", "tool"))
    )
    for compiler in compilers:
        (build_root / f"{compiler.owner}.obj").write_bytes(
            _directive_object(f"/INCLUDE:_{compiler.owner}_root ".encode("ascii"))
        )
    app_linker = ProducerNode(
        id="linker.app.0003",
        role=ProducerRole.LINKER,
        owner="app",
        target_id="app",
        arguments=(
            "${BUILD}/app.obj",
            "${BUILD}/LIBRARY.lib",
            "/OUT:${BUILD}/APP.EXE",
        ),
        inputs=("build/app.obj", "build/LIBRARY.lib"),
        outputs=("build/APP.EXE",),
        depends_on=(compilers[0].id, "linker.library.0004"),
    )
    library_linker = ProducerNode(
        id="linker.library.0004",
        role=ProducerRole.LINKER,
        owner="library",
        target_id="library",
        arguments=(
            "${BUILD}/library.obj",
            "/DLL",
            "/IMPLIB:${BUILD}/LIBRARY.lib",
            "/OUT:${BUILD}/LIBRARY.DLL",
        ),
        inputs=("build/library.obj",),
        outputs=("build/LIBRARY.DLL", "build/LIBRARY.exp", "build/LIBRARY.lib"),
        depends_on=(compilers[1].id,),
    )
    tool_linker = ProducerNode(
        id="linker.tool.0005",
        role=ProducerRole.LINKER,
        owner="tool",
        target_id="tool",
        arguments=("${BUILD}/tool.obj", "/OUT:${BUILD}/TOOL.EXE"),
        inputs=("build/tool.obj",),
        outputs=("build/TOOL.EXE",),
        depends_on=(compilers[2].id,),
    )
    linkers = (app_linker, library_linker, tool_linker)
    overlay = object.__new__(classic_runtime_overlay.ClassicOverlayEpochs)
    overlay.graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"source topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(*compilers, *linkers),
    )
    overlay.targets = (
        classic_runtime_graph.ClassicProducerTarget(
            "app", "app", build_root / "APP.EXE", None, app_linker.id
        ),
        classic_runtime_graph.ClassicProducerTarget(
            "library", "library", build_root / "LIBRARY.DLL", None, library_linker.id
        ),
        classic_runtime_graph.ClassicProducerTarget(
            "tool", "tool", build_root / "TOOL.EXE", None, tool_linker.id
        ),
    )
    overlay.effective_root = source_root
    overlay.build_root = build_root
    overlay.toolchain_root = toolchain_root
    overlay.system_libraries = MappingProxyType({})
    overlay._link_directive_closures = MappingProxyType({})
    overlay._module_definition_receipts = MappingProxyType({})
    overlay._progress = classic_runtime_producer.ClassicProgressReporter(3, None)
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer.graph = overlay.graph
    producer.effective_root = source_root
    producer.build_root = build_root
    producer.toolchain_root = toolchain_root
    producer._output_lock = Lock()
    producer._physical_outputs = {}
    overlay.producer = producer
    executor = object.__new__(classic_runtime.ClassicProducerGraphBuildExecutor)
    executor.targets = overlay.targets
    executor.build_root = build_root
    executor.overlay = overlay
    executor.producer = producer
    return executor, overlay, producer, linkers


def test_link_control_audit_binds_directive_and_def_roots(
    tmp_path: Path,
) -> None:
    executor, linker = _link_control_executor(
        tmp_path,
        definition=b"LIBRARY app.exe\nEXPORTS\n_public=_internal\n",
        linker_controls=("/INCLUDE:_command_line_forced",),
    )

    receipts = executor.audit_link_controls()

    assert [item.step_id for item in receipts] == ["link-controls.program"]
    demand, retention = executor._link_root_sets(linker)
    assert set(demand).issuperset(
        {"_command_line_forced", "_mainCRTStartup", "_WinMainCRTStartup"}
    )
    assert "_forced" not in demand
    assert set(retention) == {"_directive_export", "_internal"}
    assert executor._module_definition_receipts["program"].exports == ("_internal",)


def test_link_control_audit_rejects_def_stub_hidden_read(tmp_path: Path) -> None:
    executor, _linker = _link_control_executor(
        tmp_path,
        definition=b"LIBRARY app.exe\nSTUB host.exe\n",
    )

    with pytest.raises(ClassicProjectError, match="forbidden STUB"):
        executor.audit_link_controls()


def test_link_control_audit_accumulates_dependency_waves_atomically(
    tmp_path: Path,
) -> None:
    _coordinator, executor, _producer, _linkers = _dependent_link_control_executor(tmp_path)
    targets = {target.target_id: target for target in executor.targets}

    first = executor.audit_link_controls((targets["library"], targets["tool"]))

    assert [item.step_id for item in first] == [
        "link-controls.library",
        "link-controls.tool",
    ]
    assert set(executor._link_directive_closures) == {"library", "tool"}
    with pytest.raises(ClassicProjectError, match=r"semantic archive.*absent"):
        executor.audit_link_controls((targets["app"],))
    assert set(executor._link_directive_closures) == {"library", "tool"}
    assert executor._progress.completed == 2

    (executor.build_root / "LIBRARY.lib").write_bytes(
        _directive_archive("library.obj", _directive_object(b"/INCLUDE:_import_root "))
    )
    final = executor.audit_link_controls((targets["app"],))

    assert [item.step_id for item in final] == ["link-controls.app"]
    assert set(executor._link_directive_closures) == {"app", "library", "tool"}
    assert executor._module_definition_receipts == {}
    assert executor._progress.completed == 3
    assert {"_app_root", "_import_root"}.issubset(
        executor._link_directive_closures["app"].include_symbols
    )
    assert "_library_root" not in executor._link_directive_closures["app"].include_symbols
    semantic_closures = {closure.target_id: closure for closure in executor._target_link_closures()}
    assert semantic_closures["app"].compiler_node_ids == ("compiler.app.0000",)
    assert semantic_closures["app"].archive_refs == ("build/LIBRARY.lib",)
    assert (
        semantic_closures["app"].archives[0].payload
        == (executor.build_root / "LIBRARY.lib").read_bytes()
    )
    with pytest.raises(ClassicProjectError, match="already audited"):
        executor.audit_link_controls((targets["app"],))


def test_link_control_audit_does_not_borrow_upstream_default_library_edge(
    tmp_path: Path,
) -> None:
    _coordinator, executor, producer, linkers = _dependent_link_control_executor(tmp_path)
    app_linker, library_linker, _tool_linker = linkers
    runtime_reference = "system-library/runtime.lib"
    runtime_path = executor.toolchain_root / "runtime.lib"
    runtime_path.write_bytes(
        _directive_archive("runtime.obj", _directive_object(b"/INCLUDE:_runtime_root "))
    )
    executor.system_libraries = MappingProxyType({runtime_reference: runtime_path})
    (executor.build_root / "library.obj").write_bytes(
        _directive_object(b"/DEFAULTLIB:runtime /INCLUDE:_library_root ")
    )
    (executor.build_root / "app.obj").write_bytes(
        _directive_object(b"/DEFAULTLIB:runtime /INCLUDE:_app_root ")
    )
    admitted_library = ProducerNode.model_validate(
        {
            **library_linker.model_dump(mode="python"),
            "directive_inputs": (runtime_reference,),
        }
    )

    def graph_with(*replacements: ProducerNode) -> ProducerGraphDocument:
        by_id = {node.id: node for node in replacements}
        return ProducerGraphDocument(
            schema_version=executor.graph.schema_version,
            source_topology_digest=executor.graph.source_topology_digest,
            toolchain_lock_digest=executor.graph.toolchain_lock_digest,
            path_profile_id=executor.graph.path_profile_id,
            extractor=executor.graph.extractor,
            nodes=tuple(by_id.get(node.id, node) for node in executor.graph.nodes),
        )

    executor.graph = graph_with(admitted_library)
    producer.graph = executor.graph
    targets = {target.target_id: target for target in executor.targets}
    executor.audit_link_controls((targets["library"],))
    (executor.build_root / "LIBRARY.lib").write_bytes(
        _directive_archive("library.obj", _directive_object(b"/INCLUDE:_import_root "))
    )

    with pytest.raises(
        ClassicProjectError,
        match=r"--directive-input app=runtime\.lib",
    ):
        executor.audit_link_controls((targets["app"],))
    assert set(executor._link_directive_closures) == {"library"}

    admitted_app = ProducerNode.model_validate(
        {
            **app_linker.model_dump(mode="python"),
            "directive_inputs": (runtime_reference,),
        }
    )
    executor.graph = graph_with(admitted_library, admitted_app)
    producer.graph = executor.graph
    executor.audit_link_controls((targets["app"],))
    assert set(executor._link_directive_closures) == {"app", "library"}
    assert "_library_root" not in executor._link_directive_closures["app"].include_symbols


def test_link_control_audit_requires_final_compiler_ancestry(tmp_path: Path) -> None:
    _coordinator, executor, producer, linkers = _dependent_link_control_executor(tmp_path)
    orphan = ProducerNode(
        id="compiler.orphan.0006",
        role=ProducerRole.COMPILER,
        owner="orphan",
        arguments=("/c", "${SOURCE}/orphan.cpp"),
        inputs=("source/orphan.cpp",),
        outputs=("build/orphan.obj", "build/orphan.pdb"),
    )
    app_linker = linkers[0]
    app_with_order_only_orphan = app_linker.model_copy(
        update={"depends_on": tuple(sorted((*app_linker.depends_on, orphan.id), key=str.casefold))}
    )
    executor.graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=executor.graph.source_topology_digest,
        toolchain_lock_digest=executor.graph.toolchain_lock_digest,
        path_profile_id=executor.graph.path_profile_id,
        extractor=executor.graph.extractor,
        nodes=tuple(
            sorted(
                (
                    *(node for node in executor.graph.nodes if node.id != app_linker.id),
                    app_with_order_only_orphan,
                    orphan,
                ),
                key=lambda node: node.id.casefold(),
            )
        ),
    )
    producer.graph = executor.graph
    targets = {target.target_id: target for target in executor.targets}
    executor.audit_link_controls((targets["library"], targets["tool"]))
    (executor.build_root / "LIBRARY.lib").write_bytes(
        _directive_archive("library.obj", _directive_object(b"/INCLUDE:_import_root "))
    )

    with pytest.raises(ClassicProjectError, match=r"compiler outputs lack.*orphan"):
        executor.audit_link_controls((targets["app"],))

    assert set(executor._link_directive_closures) == {"library", "tool"}
    assert executor._progress.completed == 2


def test_linker_waves_audit_before_each_ready_wave(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor, overlay, _producer, linkers = _dependent_link_control_executor(tmp_path)
    completed = {node.id for node in overlay.graph.nodes if node.role is ProducerRole.COMPILER}
    waves: list[tuple[str, ...]] = []

    def run_ready_nodes(
        current: classic_runtime_producer.ClassicProducerExecution,
        _supervisor: ProcessSupervisor,
        nodes: tuple[ProducerNode, ...],
        **kwargs: object,
    ) -> list[StepExecutionReceipt]:
        current_completed = cast(set[str], kwargs["completed"])
        waves.append(tuple(node.id for node in nodes))
        for node in nodes:
            for output in current.declared_outputs(node):
                payload = (
                    _directive_archive("library.obj", _directive_object(b"/INCLUDE:_import_root "))
                    if output.suffix.casefold() == ".lib"
                    else b"linked"
                )
                output.write_bytes(payload)
            current_completed.add(node.id)
        return []

    monkeypatch.setattr(
        classic_runtime_producer.ClassicProducerExecution,
        "run_graph_nodes",
        run_ready_nodes,
    )

    receipts = executor._run_linker_waves(
        cast(ProcessSupervisor, object()),
        linkers,
        completed=completed,
        output_steps={},
        cancellation=CancellationToken(),
    )

    assert waves == [
        ("linker.library.0004", "linker.tool.0005"),
        ("linker.app.0003",),
    ]
    assert [item.step_id for item in receipts] == [
        "link-controls.library",
        "link-controls.tool",
        "link-controls.app",
    ]
    assert completed == {node.id for node in overlay.graph.nodes}


def test_linker_waves_do_not_run_a_wave_whose_audit_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor, overlay, _producer, linkers = _dependent_link_control_executor(tmp_path)
    completed = {node.id for node in overlay.graph.nodes if node.role is ProducerRole.COMPILER}
    waves: list[tuple[str, ...]] = []
    original_audit = classic_runtime_overlay.ClassicOverlayEpochs.audit_link_controls

    def fail_downstream_audit(
        current: classic_runtime_overlay.ClassicOverlayEpochs,
        targets: tuple[classic_runtime_graph.ClassicProducerTarget, ...] | None = None,
    ) -> tuple[StepExecutionReceipt, ...]:
        if targets is not None and any(target.target_id == "app" for target in targets):
            raise ClassicProjectError("downstream linker-control audit failed")
        return original_audit(current, targets)

    def run_ready_nodes(
        current: classic_runtime_producer.ClassicProducerExecution,
        _supervisor: ProcessSupervisor,
        nodes: tuple[ProducerNode, ...],
        **kwargs: object,
    ) -> list[StepExecutionReceipt]:
        waves.append(tuple(node.id for node in nodes))
        current_completed = cast(set[str], kwargs["completed"])
        for node in nodes:
            for output in current.declared_outputs(node):
                payload = (
                    _directive_archive("library.obj", _directive_object(b"/INCLUDE:_import_root "))
                    if output.suffix.casefold() == ".lib"
                    else b"linked"
                )
                output.write_bytes(payload)
            current_completed.add(node.id)
        return []

    monkeypatch.setattr(
        classic_runtime_overlay.ClassicOverlayEpochs,
        "audit_link_controls",
        fail_downstream_audit,
    )
    monkeypatch.setattr(
        classic_runtime_producer.ClassicProducerExecution,
        "run_graph_nodes",
        run_ready_nodes,
    )

    with pytest.raises(ClassicProjectError, match="downstream linker-control audit failed"):
        executor._run_linker_waves(
            cast(ProcessSupervisor, object()),
            linkers,
            completed=completed,
            output_steps={},
            cancellation=CancellationToken(),
        )

    assert waves == [("linker.library.0004", "linker.tool.0005")]
    assert not (executor.build_root / "APP.EXE").exists()


def test_linker_waves_reject_downstream_mutation_of_upstream_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor, overlay, _producer, linkers = _dependent_link_control_executor(tmp_path)
    completed = {node.id for node in overlay.graph.nodes if node.role is ProducerRole.COMPILER}

    def run_ready_nodes(
        current: classic_runtime_producer.ClassicProducerExecution,
        _supervisor: ProcessSupervisor,
        nodes: tuple[ProducerNode, ...],
        **kwargs: object,
    ) -> list[StepExecutionReceipt]:
        current_completed = cast(set[str], kwargs["completed"])
        if any(node.target_id == "app" for node in nodes):
            (current.build_root / "LIBRARY.lib").write_bytes(b"mutated downstream")
        for node in nodes:
            for output in current.declared_outputs(node):
                payload = (
                    _directive_archive("library.obj", _directive_object(b"/INCLUDE:_import_root "))
                    if output.suffix.casefold() == ".lib"
                    else b"linked"
                )
                output.write_bytes(payload)
            current_completed.add(node.id)
        return []

    monkeypatch.setattr(
        classic_runtime_producer.ClassicProducerExecution,
        "run_graph_nodes",
        run_ready_nodes,
    )

    with pytest.raises(
        ClassicProjectError,
        match=r"linker wave wrote undeclared.*LIBRARY\.lib",
    ):
        executor._run_linker_waves(
            cast(ProcessSupervisor, object()),
            linkers,
            completed=completed,
            output_steps={},
            cancellation=CancellationToken(),
        )


def test_linker_waves_reject_control_audit_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    executor, overlay, _producer, linkers = _dependent_link_control_executor(tmp_path)
    completed = {node.id for node in overlay.graph.nodes if node.role is ProducerRole.COMPILER}
    original_audit = classic_runtime_overlay.ClassicOverlayEpochs.audit_link_controls

    def mutate_after_audit(
        current: classic_runtime_overlay.ClassicOverlayEpochs,
        targets: tuple[classic_runtime_graph.ClassicProducerTarget, ...] | None = None,
    ) -> tuple[StepExecutionReceipt, ...]:
        receipts = original_audit(current, targets)
        if targets is not None and any(target.target_id == "app" for target in targets):
            (current.build_root / "LIBRARY.lib").write_bytes(b"mutated during audit")
        return receipts

    def run_ready_nodes(
        current: classic_runtime_producer.ClassicProducerExecution,
        _supervisor: ProcessSupervisor,
        nodes: tuple[ProducerNode, ...],
        **kwargs: object,
    ) -> list[StepExecutionReceipt]:
        current_completed = cast(set[str], kwargs["completed"])
        for node in nodes:
            for output in current.declared_outputs(node):
                payload = (
                    _directive_archive("library.obj", _directive_object(b"/INCLUDE:_import_root "))
                    if output.suffix.casefold() == ".lib"
                    else b"linked"
                )
                output.write_bytes(payload)
            current_completed.add(node.id)
        return []

    monkeypatch.setattr(
        classic_runtime_overlay.ClassicOverlayEpochs,
        "audit_link_controls",
        mutate_after_audit,
    )
    monkeypatch.setattr(
        classic_runtime_producer.ClassicProducerExecution,
        "run_graph_nodes",
        run_ready_nodes,
    )

    with pytest.raises(
        ClassicProjectError,
        match=r"linker wave wrote undeclared.*LIBRARY\.lib",
    ):
        executor._run_linker_waves(
            cast(ProcessSupervisor, object()),
            linkers,
            completed=completed,
            output_steps={},
            cancellation=CancellationToken(),
        )


def test_progress_reporter_serializes_parallel_events() -> None:
    events: list[tuple[int, int, str, str]] = []
    reporter = classic_runtime_producer.ClassicProgressReporter(
        32,
        lambda completed, total, phase, node_id, _kind, _reason: events.append(
            (completed, total, phase, node_id)
        ),
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(reporter.emit, "compile", f"compiler.unit.{index:04d}")
            for index in range(32)
        ]
        for future in futures:
            future.result()

    assert [item[0] for item in events] == list(range(1, 33))
    assert {item[1] for item in events} == {32}
    assert {item[2] for item in events} == {"compile"}
    assert {item[3] for item in events} == {f"compiler.unit.{index:04d}" for index in range(32)}


def test_progress_reporter_names_activity_without_advancing_work() -> None:
    events: list[tuple[int, int, str, str, str, str | None]] = []
    reporter = classic_runtime_producer.ClassicProgressReporter(
        1,
        lambda completed, total, phase, node_id, kind, reason: events.append(
            (completed, total, phase, node_id, kind, reason)
        ),
    )

    reporter.activity(
        "phase_started",
        "evidence",
        "assembling authenticity evidence",
    )
    reporter.emit("validation", "execution-record")

    assert events[0] == (
        0,
        1,
        "evidence",
        "assembling authenticity evidence",
        "phase_started",
        None,
    )
    assert events[1][0] == 1
    assert events[1][4] == "unit_finished"


def test_cold_progress_withholds_completion_until_runtime_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[int, int, str, str]] = []
    executor = object.__new__(classic_runtime.ClassicProducerGraphBuildExecutor)
    executor._progress = classic_runtime_producer.ClassicProgressReporter(
        2,
        lambda completed, total, phase, node_id, _kind, _reason: events.append(
            (completed, total, phase, node_id)
        ),
    )

    def execute_until_finalization(
        current: classic_runtime.ClassicProducerGraphBuildExecutor,
        _plan: BuildPlan,
        *,
        cold: bool,
        required_outputs: object,
    ) -> object:
        del cold, required_outputs
        current._progress.emit("terminal", "publish.program")
        return object()

    def fail_close() -> None:
        raise ClassicProjectError("runtime namespace changed while closing")

    executor.producer = SimpleNamespace(
        begin_certifying=lambda: None,
        close=fail_close,
    )

    monkeypatch.setattr(
        classic_runtime.ClassicProducerGraphBuildExecutor,
        "_execute",
        execute_until_finalization,
    )
    with pytest.raises(ClassicProjectError, match="namespace changed"):
        executor.execute(BuildPlan(()), cold=True)

    assert events == [(1, 2, "terminal", "publish.program")]


def test_classic_validator_revalidates_before_build_side_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    executor = object.__new__(classic_runtime.ClassicProducerGraphBuildExecutor)
    executor.producer = SimpleNamespace(
        begin_certifying=lambda: events.append("begin"),
        close=lambda: events.append("close"),
    )

    def reject_changed_validator() -> None:
        events.append("revalidate")
        raise ClassicProjectError("validator closure changed")

    monkeypatch.setattr(
        classic_runtime,
        "revalidate_classic_validator_implementation",
        reject_changed_validator,
    )

    with pytest.raises(ClassicProjectError, match="validator closure changed"):
        executor.execute(BuildPlan(()), cold=True)

    assert events == ["revalidate"]


def test_rooted_toolchain_environment_preserves_producer_spelling() -> None:
    environment = {
        "PATH": r"Z:\Users\builder\MSVC420\bin",
        "INCLUDE": (
            r"Z:\Users\builder\MSVC420\include;"
            r"Z:\Users\builder\MSVC420\mfc\include"
        ),
        "LIB": r"Z:\Users\builder\MSVC420\lib;Z:\Users\builder\MSVC420\mfc\lib",
        "LIBPATH": (r"Z:\Users\builder\MSVC420\lib;Z:\Users\builder\MSVC420\mfc\lib"),
        "TEMP": r"Z:\build\.reprobit-tmp\lane-0000",
        "TMP": r"Z:\build\.reprobit-tmp\lane-0000",
    }

    rendered = classic_runtime_environment._rooted_toolchain_environment(
        environment,
        logical_toolchain_root=r"Z:\Users\builder\MSVC420",
    )

    assert rendered == {
        "PATH": r"\Users\builder\MSVC420\bin",
        "INCLUDE": (
            r"\Users\builder\MSVC420\include;"
            r"\Users\builder\MSVC420\mfc\include"
        ),
        "LIB": r"\Users\builder\MSVC420\lib;\Users\builder\MSVC420\mfc\lib",
        "LIBPATH": r"\Users\builder\MSVC420\lib;\Users\builder\MSVC420\mfc\lib",
        "TEMP": r"Z:\build\.reprobit-tmp\lane-0000",
        "TMP": r"Z:\build\.reprobit-tmp\lane-0000",
    }
    assert environment["PATH"].startswith("Z:")


@pytest.mark.parametrize(
    "name,value",
    (
        ("PATH", r"Z:\other\bin"),
        ("INCLUDE", r"toolchain\include"),
        ("LIB", r"Z:\toolchain\lib;"),
    ),
)
def test_rooted_toolchain_environment_rejects_unsealed_paths(
    name: str,
    value: str,
) -> None:
    environment = {
        "PATH": r"Z:\toolchain\bin",
        "INCLUDE": r"Z:\toolchain\include",
        "LIB": r"Z:\toolchain\lib",
        "LIBPATH": r"Z:\toolchain\lib",
    }
    environment[name] = value

    with pytest.raises(ClassicProjectError, match=f"(?:{name} is malformed|{name} leaves)"):
        classic_runtime_environment._rooted_toolchain_environment(
            environment,
            logical_toolchain_root=r"Z:\toolchain",
        )


def test_compiler_environment_digest_binds_exact_path_presentation() -> None:
    drive_environment = {
        "INCLUDE": r"Z:\toolchain\include",
        "LIB": r"Z:\toolchain\lib",
        "LIBPATH": r"Z:\toolchain\lib",
        "WINEPATH": r"Z:\toolchain\bin",
    }
    rooted_environment = {name: value[2:] for name, value in drive_environment.items()}

    assert classic_runtime_environment._compiler_environment_digest(
        drive_environment
    ) != classic_runtime_environment._compiler_environment_digest(rooted_environment)
    assert classic_runtime_environment._compiler_environment_digest(
        rooted_environment
    ) == classic_runtime_environment._compiler_environment_digest(dict(rooted_environment))
    assert classic_runtime_environment._compiler_environment_digest(
        rooted_environment
    ) != classic_runtime_environment._compiler_environment_digest(
        {**rooted_environment, "WINEDLLOVERRIDES": "msvcrt40=n;msvcrt20=n"}
    )


@pytest.mark.parametrize(
    "value",
    (
        r"toolchain\include",
        r"\\server\share\include",
        r"\toolchain\..\include",
        r"/toolchain/include",
    ),
)
def test_compiler_environment_digest_rejects_ambiguous_paths(value: str) -> None:
    environment = {
        "INCLUDE": value,
        "LIB": r"\toolchain\lib",
        "LIBPATH": r"\toolchain\lib",
        "WINEPATH": r"\toolchain\bin",
    }

    with pytest.raises(ClassicProjectError, match="leaves the logical path profile"):
        classic_runtime_environment._compiler_environment_digest(environment)


@pytest.mark.skipif(os.name != "posix", reason="Wine lanes are POSIX-only")
def test_parallel_wine_lanes_have_private_prefixes_and_temporaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = PosixWineBackend(wine=sys.executable, wineserver=sys.executable)
    initialized: list[str] = []
    bound: list[str] = []

    class Binding:
        def __init__(self, worker_id: str) -> None:
            self.worker_id = worker_id

        def __enter__(self) -> Binding:
            bound.append(self.worker_id)
            return self

        def __exit__(self, *args: object) -> None:
            del args

    def initialize(worker: WorkerSandbox, *, timeout_seconds: float) -> None:
        assert timeout_seconds == 30
        initialized.append(worker.worker_id)

    def bind(worker: WorkerSandbox, skeleton: MaterializedSkeleton) -> Binding:
        assert skeleton.drive_letter == "R"
        return Binding(worker.worker_id)

    def verify(worker: WorkerSandbox, *, logical_drive: str) -> None:
        assert worker.worker_id in bound
        assert logical_drive == "R"

    monkeypatch.setattr(backend, "initialize_worker_prefix", initialize)
    monkeypatch.setattr(backend, "bind_skeleton", bind)
    monkeypatch.setattr(backend, "verify_worker_drive_mappings", verify)

    logical_root = tmp_path / "logical-drive"
    build_root = logical_root / "build"
    build_root.mkdir(parents=True)
    workspace = classic_runtime_environment._DirectLogicalWorkspace(
        logical_root,
        "R",
        logical_root / "source",
        build_root,
        logical_root / "toolchain",
        MaterializedSkeleton(logical_root, "R", ()),
    )

    class Installation:
        root = workspace.toolchain_entry
        logical_root = r"R:\toolchain"
        profile = SimpleNamespace(wine_dll_overrides=())

        @staticmethod
        def default_environment(*, temp_directory: str) -> dict[str, str]:
            return {
                "PATH": r"R:\toolchain\bin",
                "INCLUDE": r"R:\toolchain\include",
                "LIB": r"R:\toolchain\lib",
                "TEMP": temp_directory,
                "TMP": temp_directory,
            }

    alias = tmp_path / "aliases" / "wine"
    alias.parent.mkdir()
    alias.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    alias.chmod(stat.S_IRUSR | stat.S_IXUSR)
    role_commands = {role: Path(sys.executable) for role in ProducerRole}
    bundle = _prepare_bundle(tmp_path)

    def close_runtime(
        backend_arg: ExecutionBackend,
        worker: WorkerSandbox,
        stack: ExitStack,
        *,
        logical_drive: str,
        timeout_seconds: float = 10.0,
    ) -> None:
        del backend_arg, worker
        assert logical_drive == "R"
        assert timeout_seconds == 10
        stack.close()

    monkeypatch.setattr(classic_runtime_environment, "_close_backend_runtime", close_runtime)
    session_root = tmp_path / "session"
    session_root.mkdir()
    authority_root = session_root / "path-proxies"
    authority_root.mkdir()
    authority_file = authority_root / "cl"
    authority_file.write_bytes(b"sealed frontend")
    lane_pool = classic_runtime_environment._prepare_execution_lanes(
        bundle,
        installation=cast(ClassicMSVCToolchain, Installation()),
        backend=backend,
        logical_workspace=workspace,
        session_root=session_root,
        role_commands=role_commands,
        host_programs=(Path(sys.executable),),
        frontend_environment={
            "REPROBIT_WINE_MSVC_TRANSPORT": "/transport",
            "REPROBIT_LOGICAL_CL": r"R:\toolchain\bin\CL.EXE",
            "REPROBIT_LOGICAL_RC": r"R:\toolchain\bin\RC.EXE",
            "REPROBIT_LOGICAL_LINK": r"R:\toolchain\bin\LINK.EXE",
            "REPROBIT_LOGICAL_LIB": r"R:\toolchain\bin\LIB.EXE",
        },
        jobs=3,
        initialization_timeout=30,
        cleanup_timeout=10,
        wine_alias=alias,
    )
    try:
        assert lane_pool.created_count == 0
        assert initialized == []
        assert bound == []
        # The lazy workers are created after the exact frontend authority and
        # its ancestor chain are sealed.  Their pre-created sibling container
        # keeps that sound lease stable while lanes grow on demand.
        with SealedNamespaceLease(
            trees=(),
            files=(NamespaceFile("frontend", authority_file, Path(authority_file.anchor)),),
        ):
            lanes = tuple(lane_pool.acquire() for _ in range(3))
            for lane in reversed(lanes):
                lane_pool.release(lane)
        assert sorted(initialized) == [
            "producer-graph-0000",
            "producer-graph-0001",
            "producer-graph-0002",
        ]
        assert sorted(bound) == sorted(initialized)
        assert len({lane.environment["WINEPREFIX"] for lane in lanes}) == 3
        assert [lane.environment["TEMP"] for lane in lanes] == [
            rf"R:\build\.reprobit-tmp\lane-{index:04d}" for index in range(3)
        ]
        assert all(lane.environment["INCLUDE"] == r"\toolchain\include" for lane in lanes)
        assert all(lane.environment["LIB"] == r"\toolchain\lib" for lane in lanes)
        assert all(lane.environment["LIBPATH"] == r"\toolchain\lib" for lane in lanes)
        assert all(lane.environment["WINEPATH"] == r"\toolchain\bin" for lane in lanes)
        assert all(
            lane.environment["PATH"].split(os.pathsep)[0] == str(alias.parent) for lane in lanes
        )
    finally:
        lane_pool.close()


def test_lazy_lane_pool_reuses_one_lane_for_sequential_work() -> None:
    created: list[int] = []
    closed: list[bool] = []
    environment = MappingProxyType(
        {
            "INCLUDE": r"R:\toolchain\include",
            "LIB": r"R:\toolchain\lib",
            "LIBPATH": r"R:\toolchain\lib",
        }
    )

    def create(index: int) -> classic_runtime_environment._ExecutionLane:
        created.append(index)
        return classic_runtime_environment._ExecutionLane(
            f"lane-{index:04d}", environment, cast(WorkerSandbox, object())
        )

    pool = classic_runtime_environment._LazyExecutionLanePool(
        maximum=8,
        create=create,
        close_created=lambda: closed.append(True),
        compiler_environment_digest=classic_runtime_environment._compiler_environment_digest(
            environment
        ),
    )
    assert pool.created_count == 0
    first = pool.acquire()
    pool.release(first)
    second = pool.acquire()
    pool.release(second)
    assert first is second
    assert created == [0]
    assert pool.created_count == 1
    pool.close()
    assert closed == [True]


def test_lazy_lane_pool_rejects_close_with_borrowed_lane_then_cleans() -> None:
    environment = MappingProxyType(
        {
            "INCLUDE": r"R:\toolchain\include",
            "LIB": r"R:\toolchain\lib",
            "LIBPATH": r"R:\toolchain\lib",
        }
    )
    closed: list[bool] = []
    pool = classic_runtime_environment._LazyExecutionLanePool(
        maximum=1,
        create=lambda index: classic_runtime_environment._ExecutionLane(
            f"lane-{index:04d}", environment, cast(WorkerSandbox, object())
        ),
        close_created=lambda: closed.append(True),
        compiler_environment_digest=classic_runtime_environment._compiler_environment_digest(
            environment
        ),
    )
    lane = pool.acquire()
    with pytest.raises(ClassicProjectError, match="lanes were active"):
        pool.close()
    assert closed == []
    pool.release(lane)
    pool.close()
    assert closed == [True]


def test_native_logical_role_commands_stay_in_projected_toolchain_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The controller must not resolve a drive visible only to producer lineages."""

    logical_root = tmp_path / "logical-drive"
    source_root = logical_root / "source"
    build_root = logical_root / "build"
    toolchain_root = logical_root / "toolchain"
    for directory in (source_root, build_root, toolchain_root / "bin"):
        directory.mkdir(parents=True, exist_ok=True)
    role_relatives = {
        ProducerRole.COMPILER: "CL.EXE",
        ProducerRole.RESOURCE: "RC.EXE",
        ProducerRole.LIBRARIAN: "LIB.EXE",
        ProducerRole.LINKER: "LINK.EXE",
    }
    for relative in role_relatives.values():
        (toolchain_root / "bin" / relative).write_bytes(relative.encode("ascii"))

    bundle = cast(
        ProjectBundle,
        SimpleNamespace(
            spec=SimpleNamespace(
                paths=SimpleNamespace(
                    source=r"R:\source",
                    build=r"R:\build",
                    toolchain=r"R:\toolchain",
                )
            )
        ),
    )
    graph = cast(ProducerGraphDocument, object())
    monkeypatch.setattr(
        classic_runtime_producer,
        "classic_compiler_path_profile_digest",
        lambda _bundle, _graph: Digest.from_bytes(b"path-profile"),
    )
    lane_pool = cast(
        classic_runtime_environment._LazyExecutionLanePool,
        SimpleNamespace(
            maximum=1,
            compiler_environment_digest=Digest.from_bytes(b"environment"),
            created_count=0,
            close=lambda: None,
        ),
    )
    role_commands = {
        role: Path(rf"R:\toolchain\bin\{relative}")
        for role, relative in role_relatives.items()
    }

    producer = classic_runtime_producer.ClassicProducerExecution(
        bundle=bundle,
        session_root=tmp_path,
        build_root=build_root,
        effective_root=source_root,
        toolchain_root=toolchain_root,
        graph=graph,
        role_commands=role_commands,
        role_tool_ids={role: role.value for role in ProducerRole},
        wrapper_runtime_files=(),
        authority_inputs=(),
        analysis_link_options=(),
        lane_pool=lane_pool,
        jobs=1,
        compile_timeout=30,
        link_timeout=30,
        progress=classic_runtime_producer.ClassicProgressReporter(1, None),
    )
    try:
        assert producer.role_commands == role_commands
        assert producer.initialized_lane_count == 0
        assert producer._namespace_authority_files == ()
        with producer.authority_namespace_lease() as authority:
            assert {
                item.relative_path for item in authority.snapshot.files_for("toolchain")
            } == {f"bin/{relative}" for relative in role_relatives.values()}
    finally:
        producer.close()


def test_discarded_warm_dependency_replay_erases_arena_after_parse_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    build_root = tmp_path / "build"
    build_root.mkdir()
    session_root = tmp_path / "session"
    session_root.mkdir()
    node = ProducerNode(
        id="compiler.program.0000",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=("/c", "unit.cpp", "/Founit.obj", "/Fdunit.pdb"),
        inputs=("source/unit.cpp",),
        outputs=("build/unit.obj", "build/unit.pdb"),
    )

    class Pool:
        releases = 0

        def acquire(self) -> SimpleNamespace:
            return SimpleNamespace(
                environment={},
                windows_lineage_planner=None,
            )

        def release(self, _lane: object) -> None:
            self.releases += 1

    pool = Pool()
    executor = object.__new__(classic_runtime_developer.ClassicDeveloperExecution)
    executor.build_root = build_root
    executor.session_root = session_root
    executor.overlay = SimpleNamespace(generated_node_inputs=MappingProxyType({}))
    executor.producer = SimpleNamespace(
        role_commands=MappingProxyType({ProducerRole.COMPILER: Path("compiler")}),
        compile_timeout=30.0,
        lane_pool=cast(classic_runtime_environment._LazyExecutionLanePool, pool),
        node_arguments=lambda _node: node.arguments,
        logical_for_host_path=lambda path: str(path),
        producer_cwd=lambda _lane, path: path,
        compiler_companion_output=(
            classic_runtime_producer.ClassicProducerExecution.compiler_companion_output
        ),
    )
    executor._warm_node = lambda _node_id: node  # type: ignore[method-assign]
    executor._warm_epoch = lambda **_kwargs: (  # type: ignore[method-assign]
        cast(ProcessSupervisor, object()),
        object(),
    )

    def run(*_args: object, **_kwargs: object) -> tuple[ProcessResult, object]:
        arenas = tuple((build_root / ".reprobit-warm-replay").iterdir())
        assert len(arenas) == 1
        (arenas[0] / "discard.obj").write_bytes(b"discard-object")
        (arenas[0] / "discard.pdb").write_bytes(b"discard-pdb")
        (arenas[0] / "dependencies.sbr").write_bytes(b"not-an-sbr")
        return ProcessResult(("compiler",), 0, b"", 1, 0.01), object()

    monkeypatch.setattr(classic_runtime_developer, "_run", run)
    replay = executor.replay_warm_compiler_dependencies(
        node.id,
        cancellation=CancellationToken(),
    )

    assert replay.trace is None
    assert replay.reason is not None and "trace is unusable" in replay.reason
    assert pool.releases == 1
    assert tuple((build_root / ".reprobit-warm-replay").iterdir()) == ()


def test_runtime_authority_labels_preserve_same_basename_full_census(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "host-tools"
    second_root = tmp_path / "toolchain" / "x86"
    first_root.mkdir(parents=True)
    second_root.mkdir(parents=True)
    first = first_root / "CL.EXE"
    second = second_root / "cl.exe"
    first.write_bytes(b"host transport")
    second.write_bytes(b"toolchain compiler")
    first_label = classic_runtime_producer._runtime_authority_label(first)
    second_label = classic_runtime_producer._runtime_authority_label(second)
    assert first_label.casefold() != second_label.casefold()

    with SealedNamespaceLease(
        trees=(),
        files=(
            NamespaceFile(first_label, first, first.parent),
            NamespaceFile(second_label, second, second.parent),
        ),
    ) as lease:
        assert len(lease.snapshot.files) == 2
        assert {item.digest for item in lease.snapshot.files} == {
            Digest.from_bytes(b"host transport"),
            Digest.from_bytes(b"toolchain compiler"),
        }


def test_precreated_donor_root_keeps_probe_writes_outside_source_namespace(
    tmp_path: Path,
) -> None:
    logical_drive = tmp_path / "logical-drive"
    source_root = logical_drive / "Users" / "developer" / "project"
    build_root = logical_drive / "Users" / "developer" / "project-build"
    donor_root = build_root.parent / "donors"
    source_root.mkdir(parents=True)
    build_root.mkdir()
    # Preparation establishes this sibling before any readable lease exists.
    donor_root.mkdir()
    (source_root / "unit.cpp").write_bytes(b"int value;\n")

    with SealedNamespaceLease(
        trees=(NamespaceTree("source", source_root, logical_drive),),
        files=(),
    ):
        arena = donor_root / "donor.one"
        arena.mkdir()
        (arena / "o.obj").write_bytes(b"object")
        (arena / "o.pdb").write_bytes(b"pdb")

    assert (source_root / "unit.cpp").read_bytes() == b"int value;\n"


def _runtime_donor_request(
    *,
    source: str,
    projection: DonorIncludeProjection,
    force_include: bool,
    overlay: bool = False,
) -> DonorCompileRequest:
    family = (
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY
        if overlay or projection is not DonorIncludeProjection.NONE
        else (
            ClassicRecipeFamily.DECLARATION_SHAPE
            if force_include
            else ClassicRecipeFamily.FORWARD_DECLARATION_RUN
        )
    )
    parent = Path(source).parent.as_posix()
    include_directories = ()
    if family is ClassicRecipeFamily.DONOR_SOURCE_OVERLAY:
        include_directories = ("inc",)
        if projection is not DonorIncludeProjection.NONE:
            include_directories += (f"inc/source/{parent}",)
    files = {"s.cpp": b"rendered source\n"}
    if projection is not DonorIncludeProjection.NONE:
        files[f"inc/source/{parent}/rendered.h"] = b"rendered header\n"
    if force_include:
        files["run.h"] = b"class DonorCarrier {};\n"
    return DonorCompileRequest(
        intervention_id="donor_modern_identity",
        compiler_seat="d_0123456789ab",
        family=family,
        build_target="program",
        logical_source=source,
        staged_source="s.cpp",
        files=MappingProxyType(files),
        logical_outputs=MappingProxyType({source: b"rendered source\n"}),
        compiler_additions=DonorCompilerAdditions(
            force_includes=("run.h",) if force_include else (),
            include_directories=include_directories,
            include_projection=projection,
        ),
        carrier_identifiers=(frozenset({"DonorCarrier"}) if force_include else frozenset()),
        receipt=DonorCompileReceipt(
            "donor_modern_identity",
            family,
            Digest.from_bytes(b"constraints"),
            MappingProxyType({}),
            MappingProxyType({}),
            Digest.from_bytes(b"additions"),
            Digest.from_bytes(b"rendering"),
        ),
    )


def test_donor_compile_record_binds_exact_target_source_identity(tmp_path: Path) -> None:
    effective_root = tmp_path / "source"
    source = effective_root / "src/unit.cpp"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"int fixture;\n")
    build_root = tmp_path / "build"
    build_root.mkdir()

    def record(owner: str, *options: str) -> classic_runtime_graph.ClassicCompileRecord:
        return classic_runtime_graph.ClassicCompileRecord(
            f"compiler.{owner}.0000",
            build_root,
            source,
            build_root / f"{owner}.obj",
            build_root / f"{owner}.pdb",
            (
                "/nologo",
                "/Zi",
                *options,
                f"/Fo{build_root / f'{owner}.obj'}",
                f"/Fd{build_root / f'{owner}.pdb'}",
                "-c",
                str(source),
            ),
            owner,
        )

    request = _runtime_donor_request(
        source="src/unit.cpp",
        projection=DonorIncludeProjection.NONE,
        force_include=True,
    )
    donor = SimpleNamespace(
        intervention=SimpleNamespace(id=request.intervention_id),
        request=request,
    )
    unit = SimpleNamespace(
        plan=SimpleNamespace(build_target="program"),
        donors=(donor,),
    )
    owner_record = record("program")
    other_target = record("config", "-DUNRELATED_MARKER")
    executor = object.__new__(classic_runtime_donor.ClassicDonorComposition)
    executor.effective_root = effective_root
    executor.compile_records = (owner_record, other_target)

    selected = executor.record_for_donor(unit, 0)

    assert selected is owner_record
    assert selected.node_id == "compiler.program.0000"
    assert all(not argument.startswith("-D") for argument in selected.arguments)


def test_donor_compile_record_rejects_target_outside_its_owning_tu(
    tmp_path: Path,
) -> None:
    effective_root = tmp_path / "source"
    source = effective_root / "unit.cpp"
    effective_root.mkdir()
    source.write_bytes(b"int fixture;\n")
    request = replace(
        _runtime_donor_request(
            source="unit.cpp",
            projection=DonorIncludeProjection.NONE,
            force_include=True,
        ),
        build_target="other-target",
    )
    unit = SimpleNamespace(
        plan=SimpleNamespace(build_target="program"),
        donors=(
            SimpleNamespace(
                intervention=SimpleNamespace(id=request.intervention_id),
                request=request,
            ),
        ),
    )
    executor = object.__new__(classic_runtime_donor.ClassicDonorComposition)
    executor.effective_root = effective_root
    executor.compile_records = ()

    with pytest.raises(ClassicProjectError, match="target differs from its owning TU"):
        executor.record_for_donor(unit, 0)


@pytest.mark.parametrize(
    ("owners", "expected_count"),
    (
        (("program", "program"), 2),
        (("config",), 0),
    ),
    ids=("ambiguous", "missing"),
)
def test_donor_compile_record_rejects_non_unique_target_source_identity(
    tmp_path: Path,
    owners: tuple[str, ...],
    expected_count: int,
) -> None:
    effective_root = tmp_path / "source"
    source = effective_root / "unit.cpp"
    effective_root.mkdir()
    source.write_bytes(b"int fixture;\n")
    build_root = tmp_path / "build"
    build_root.mkdir()
    records = tuple(
        classic_runtime_graph.ClassicCompileRecord(
            f"compiler.{owner}.{index:04d}",
            build_root,
            source,
            build_root / f"lane{index}.obj",
            build_root / f"lane{index}.pdb",
            (
                "/nologo",
                "/Zi",
                f"/Fo{build_root / f'lane{index}.obj'}",
                f"/Fd{build_root / f'lane{index}.pdb'}",
                "-c",
                str(source),
            ),
            owner,
        )
        for index, owner in enumerate(owners)
    )
    request = _runtime_donor_request(
        source="unit.cpp",
        projection=DonorIncludeProjection.NONE,
        force_include=True,
    )
    unit = SimpleNamespace(
        plan=SimpleNamespace(build_target="program"),
        donors=(
            SimpleNamespace(
                intervention=SimpleNamespace(id=request.intervention_id),
                request=request,
            ),
        )
    )
    executor = object.__new__(classic_runtime_donor.ClassicDonorComposition)
    executor.effective_root = effective_root
    executor.compile_records = records

    with pytest.raises(
        ClassicProjectError,
        match=(
            rf"{expected_count} committed compile lanes for its target/source identity: "
            r"program/unit.cpp"
        ),
    ):
        executor.record_for_donor(unit, 0)


@pytest.mark.parametrize(
    ("source", "projection", "force_include", "overlay"),
    (
        ("src/unit.cpp", DonorIncludeProjection.NONE, False, False),
        ("cross/donor.cpp", DonorIncludeProjection.NONE, True, False),
        ("src/unit.cpp", DonorIncludeProjection.NONE, False, True),
        ("src/unit.cpp", DonorIncludeProjection.SOURCE_ROOT_MIRROR, False, True),
        ("src/unit.cpp", DonorIncludeProjection.SOURCE_ROOT_MIRROR_ONLY, True, True),
    ),
    ids=(
        "ordinary",
        "cross-tu-carrier",
        "overlay-none",
        "mirror",
        "mirror-only-carrier",
    ),
)
def test_donor_compiler_command_preserves_committed_visible_path_contract(
    tmp_path: Path,
    source: str,
    projection: DonorIncludeProjection,
    force_include: bool,
    overlay: bool,
) -> None:
    drive = tmp_path / "drive"
    effective_root = drive / "Users/project/source"
    source_path = effective_root / source
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(b"effective source\n")
    (effective_root / "include").mkdir()
    (effective_root / "shared").mkdir()
    (drive / "Toolchain/include").mkdir(parents=True)
    arena = drive / "Users/project/donors/arena"
    arena.mkdir(parents=True)
    request = _runtime_donor_request(
        source=source,
        projection=projection,
        force_include=force_include,
        overlay=overlay,
    )
    source_windows = source.replace("/", "\\")
    record = classic_runtime_graph.ClassicCompileRecord(
        "compiler.program.0000",
        drive / "Users/project/build",
        source_path,
        drive / "Users/project/build/unit.obj",
        drive / "Users/project/build/unit.pdb",
        (
            "cl",
            "/Zi",
            r"-IZ:\Users\project\source\include",
            "/I",
            r"Z:\Users\project\source\shared",
            r"-IZ:\Toolchain\include",
            r"/FoZ:\Users\project\build\unit.obj",
            r"/FdZ:\Users\project\build\unit.pdb",
            "/c",
            rf"Z:\Users\project\source\{source_windows}",
        ),
        "program",
    )
    executor = object.__new__(classic_runtime_donor.ClassicDonorComposition)
    executor.effective_root = effective_root
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer._logical_drive_root = drive.resolve(strict=True)
    producer._logical_drive_letter = "Z"
    executor.producer = producer

    command = executor._donor_compiler_command(record, request, arena)

    arena_visible = r"Z:\Users\project\donors\arena"
    parent_windows = Path(source).parent.as_posix().replace("/", "\\")
    source_parent = rf"Z:\Users\project\source\{parent_windows}"
    original_first = r"-IZ:\Users\project\source\include"
    first = command.index(original_first)
    inserted = [f"/I{source_parent}"]
    if overlay:
        inserted = [
            f"/I{arena_visible}\\inc",
            f"/I{source_parent}",
        ]
        if projection is not DonorIncludeProjection.NONE:
            inserted.insert(
                1,
                f"/I{arena_visible}\\inc\\source\\{parent_windows}",
            )
            inserted.append(f"-I{arena_visible}\\inc\\source\\include")
    assert list(command[first - len(inserted) : first]) == inserted
    if projection is not DonorIncludeProjection.NONE:
        second = command.index(r"Z:\Users\project\source\shared")
        assert command[second - 3 : second] == (
            "/I",
            f"{arena_visible}\\inc\\source\\shared",
            "/I",
        )
    assert command.count(f"-I{arena_visible}\\inc\\source\\Toolchain\\include") == 0
    object_index = command.index("/Foo.obj")
    expected_predecessor = "/FIrun.h" if force_include else "-IZ:\\Toolchain\\include"
    assert command[object_index - 1] == expected_predecessor
    expected_tail = (
        ("/FIrun.h", "/Foo.obj", "/Fdo.pdb", "/c", "s.cpp")
        if force_include
        else ("/Foo.obj", "/Fdo.pdb", "/c", "s.cpp")
    )
    assert command[-len(expected_tail) :] == expected_tail


def test_donor_invocation_uses_private_arena_layout_and_relative_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drive = tmp_path / "drive"
    effective_root = drive / "Users/project/source"
    build_root = drive / "Users/project/build"
    source = effective_root / "src/unit.cpp"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"effective source\n")
    (effective_root / "include").mkdir()
    (effective_root / "include/rendered.h").write_bytes(b"effective header\n")
    (drive / "Toolchain/include").mkdir(parents=True)
    build_root.mkdir()
    (build_root.parent / "donors").mkdir()
    session_root = tmp_path / "session"
    session_root.mkdir()
    request = _runtime_donor_request(
        source="src/unit.cpp",
        projection=DonorIncludeProjection.SOURCE_ROOT_MIRROR_ONLY,
        force_include=True,
        overlay=True,
    )
    record = classic_runtime_graph.ClassicCompileRecord(
        "compiler.program.0000",
        build_root,
        source,
        build_root / "unit.obj",
        build_root / "unit.pdb",
        (
            "cl",
            "/Zi",
            r"-IZ:\Users\project\source\include",
            r"-IZ:\Toolchain\include",
            r"/FoZ:\Users\project\build\unit.obj",
            r"/FdZ:\Users\project\build\unit.pdb",
            "/c",
            r"Z:\Users\project\source\src\unit.cpp",
        ),
        "program",
    )
    node = ProducerNode(
        id=record.node_id,
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=(
            "/Zi",
            "-I${SOURCE}/include",
            "-I${TOOLCHAIN}/include",
            "/Fo${BUILD}/unit.obj",
            "/Fd${BUILD}/unit.pdb",
            "/c",
            "${SOURCE}/src/unit.cpp",
        ),
        inputs=("source/src/unit.cpp",),
        outputs=("build/unit.obj", "build/unit.pdb"),
    )
    unit = SimpleNamespace(
        plan=SimpleNamespace(
            id="tu_fixture",
            build_target="program",
            source="owner/unit.cpp",
        ),
        donors=(
            SimpleNamespace(
                intervention=SimpleNamespace(id="donor_modern_identity"),
                request=request,
            ),
        ),
    )

    class Pool:
        def acquire(self) -> SimpleNamespace:
            return SimpleNamespace(
                environment=MappingProxyType({"INCLUDE": r"Z:\Toolchain\include"}),
                windows_lineage_planner=None,
            )

        def release(self, _lane: object) -> None:
            return None

    executor = object.__new__(classic_runtime_donor.ClassicDonorComposition)
    executor.effective_root = effective_root
    executor.build_root = build_root
    executor.session_root = session_root
    executor.compile_records = (record,)
    executor.graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"source topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(node,),
    )
    executor.compile_timeout = 30.0
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer._lane_pool = cast(classic_runtime_environment._LazyExecutionLanePool, Pool())
    producer._logical_drive_root = drive.resolve(strict=True)
    producer._logical_drive_letter = "Z"
    executor.producer = producer
    include_authority = classic_includes.SealedIncludeAuthority(
        (r"Z:\Toolchain", r"Z:\Users\project\source"),
        tuple(
            sorted(
                (
                    classic_includes.SealedIncludeFile(
                        r"Z:\Users\project\source\src\unit.cpp",
                        Digest.from_bytes(b"effective source\n"),
                        len(b"effective source\n"),
                        IncludeOrigin.PROJECT_SOURCE,
                    ),
                    classic_includes.SealedIncludeFile(
                        r"Z:\Users\project\source\include\rendered.h",
                        Digest.from_bytes(b"effective header\n"),
                        len(b"effective header\n"),
                        IncludeOrigin.PROJECT_SOURCE,
                    ),
                ),
                key=lambda item: item.logical_path.casefold(),
            )
        ),
    )
    captured: list[tuple[tuple[str, ...], Path]] = []

    def run(
        _supervisor: ProcessSupervisor,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        environment: MappingProxyType[str, str],
        timeout: float,
        log: Path,
        cancellation: CancellationToken,
        windows_lineage_planner: object,
    ) -> tuple[ProcessResult, CommandSpec]:
        del timeout, log, cancellation
        assert windows_lineage_planner is None
        captured.append((argv, cwd))
        assert cwd.name.endswith("-d_0123456789ab")
        assert (cwd / "s.cpp").read_bytes() == b"rendered source\n"
        assert (cwd / "run.h").read_bytes() == b"class DonorCarrier {};\n"
        assert (cwd / "inc/source/src/unit.cpp").read_bytes() == b"effective source\n"
        assert (cwd / "inc/source/src/rendered.h").read_bytes() == b"rendered header\n"
        if any(item.casefold().startswith(("/fr", "-fr")) for item in argv):
            assert (cwd / "o.obj").read_bytes() == b"object"
            assert (cwd / "o.pdb").read_bytes() == b"pdb"
            (cwd / ".reprobit-donor-dependencies.obj").write_bytes(b"discard object")
            (cwd / ".reprobit-donor-dependencies.pdb").write_bytes(b"discard pdb")
            working = producer.logical_for_host_path(cwd)
            mirror_header = working + r"\inc\source\include\rendered.h"
            sbr = bytearray(b"\x00\x02\x00\x07\x00")
            sbr.extend(working.encode("ascii") + b"\0")
            sbr.extend(b"\x01s.cpp\0")
            sbr.extend(b"\x01run.h\0\x0a")
            sbr.extend(b"\x01" + mirror_header.encode("ascii") + b"\0\x0a\x0a")
            (cwd / ".reprobit-donor-dependencies.sbr").write_bytes(sbr)
        else:
            (cwd / "o.obj").write_bytes(b"object")
            (cwd / "o.pdb").write_bytes(b"pdb")
        result = ProcessResult(argv, 0, b"", 1, 0.01)
        return result, CommandSpec.create(argv, cwd=cwd, environment=environment)

    monkeypatch.setattr(classic_runtime_donor, "_run", run)
    with ProcessSupervisor() as supervisor:
        invocation = executor.invoke_donor_compiler(
            supervisor,
            cast(classic_orchestration.ClassicPreparedUnit, unit),
            0,
            CancellationToken(),
            step_id="donor.fixture",
            compiler_epoch=classic_runtime_overlay.ClassicActiveCompilerEpoch(
                "fixture",
                include_authority,
                classic_runtime_producer._tree_file_seal(effective_root),
                False,
            ),
            capture_dependencies=True,
        )

    assert len(captured) == 2
    assert captured[0][1] == build_root.parent / "donors" / (
        "composed-program-owner_unit.cpp-d_0123456789ab"
    )
    assert captured[0][0][-5:] == (
        "/FIrun.h",
        "/Foo.obj",
        "/Fdo.pdb",
        "/c",
        "s.cpp",
    )
    assert all(not item.casefold().startswith(("/fr", "-fr")) for item in captured[0][0])
    assert any(item.casefold().startswith(("/fr", "-fr")) for item in captured[1][0])
    assert captured[1][0][-1] == "s.cpp"
    replay_command = list(captured[1][0])
    replay_command.pop(
        next(
            index
            for index, item in enumerate(replay_command)
            if item.casefold().startswith(("/fr", "-fr"))
        )
    )
    for prefix in ("/fo", "/fd"):
        canonical_index = next(
            index for index, item in enumerate(captured[0][0]) if item.casefold().startswith(prefix)
        )
        replay_index = next(
            index for index, item in enumerate(replay_command) if item.casefold().startswith(prefix)
        )
        replay_command[replay_index] = captured[0][0][canonical_index]
    assert tuple(replay_command) == captured[0][0]
    assert invocation.object_path == captured[0][1] / "o.obj"
    assert invocation.pdb_path == captured[0][1] / "o.pdb"
    assert invocation.object_payload == b"object"
    assert invocation.pdb_payload == b"pdb"
    assert invocation.dependency_replay is not None
    assert invocation.dependency_replay.reason is None
    assert [item.logical_path for item in invocation.dependency_replay.reads] == [
        producer.logical_for_host_path(captured[0][1] / "s.cpp"),
        producer.logical_for_host_path(captured[0][1] / "run.h"),
        producer.logical_for_host_path(captured[0][1] / "inc/source/include/rendered.h"),
    ]
    assert not tuple(
        item
        for item in captured[0][1].iterdir()
        if item.name.startswith(".reprobit-donor-dependencies")
    )


def test_projected_donor_dependency_parse_failure_is_discarded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    drive = tmp_path / "drive"
    arena = drive / "donors" / "fixture"
    arena.mkdir(parents=True)
    (arena / "s.cpp").write_bytes(b"donor source\n")
    session_root = tmp_path / "session"
    session_root.mkdir()
    executor = object.__new__(classic_runtime_donor.ClassicDonorComposition)
    executor.session_root = session_root
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer._logical_drive_root = drive.resolve(strict=True)
    producer._logical_drive_letter = "R"
    executor.producer = producer
    include_authority = classic_includes.SealedIncludeAuthority(
        (r"R:\source", r"R:\toolchain"),
        (),
    )
    lane = SimpleNamespace(
        environment=MappingProxyType({"INCLUDE": r"R:\toolchain\include"}),
        windows_lineage_planner=None,
    )

    def run(
        _supervisor: ProcessSupervisor,
        argv: tuple[str, ...],
        **_kwargs: object,
    ) -> tuple[ProcessResult, CommandSpec]:
        (arena / ".reprobit-donor-dependencies.obj").write_bytes(b"discard")
        (arena / ".reprobit-donor-dependencies.pdb").write_bytes(b"discard")
        (arena / ".reprobit-donor-dependencies.sbr").write_bytes(b"malformed")
        return (
            ProcessResult(argv, 0, b"", 1, 0.01),
            CommandSpec.create(argv, cwd=arena, environment=lane.environment),
        )

    monkeypatch.setattr(classic_runtime_donor, "_run", run)
    with ProcessSupervisor() as supervisor:
        replay = executor._replay_projected_donor_dependencies(
            supervisor,
            donor_id="donor.fixture",
            command=(
                "cl",
                "/Zi",
                r"-IR:\source",
                "/Foo.obj",
                "/Fdo.pdb",
                "/c",
                "s.cpp",
            ),
            arena=arena,
            arena_seal=classic_runtime_producer._tree_file_seal(arena),
            lane=cast(classic_runtime_environment._ExecutionLane, lane),
            timeout=30.0,
            step_id="donor.fixture",
            cancellation=CancellationToken(),
            compiler_epoch=classic_runtime_overlay.ClassicActiveCompilerEpoch(
                "fixture",
                include_authority,
                MappingProxyType({}),
                False,
            ),
        )

    assert replay.trace is None
    assert replay.reads == ()
    assert replay.reason is not None and "trace is unusable" in replay.reason
    assert tuple(arena.iterdir()) == (arena / "s.cpp",)


def test_exact_compiler_probe_returns_raw_outputs_and_closes_runtime(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    build_root = tmp_path / "build"
    source_root.mkdir()
    build_root.mkdir()
    (source_root / "unit.cpp").write_bytes(b"int value;\n")
    node = ProducerNode(
        id="compiler.program.0000",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=("/c", "${SOURCE}/unit.cpp"),
        inputs=("source/unit.cpp",),
        outputs=("build/unit.obj", "build/unit.pdb"),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"source topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(node,),
    )

    class Pool:
        created_count = 0
        closed = False

        def close(self) -> None:
            self.closed = True

    pool = Pool()
    executor = object.__new__(classic_runtime_developer.ClassicDeveloperExecution)
    executor._warm_stack = None
    executor.graph = graph
    executor.overlay = SimpleNamespace(
        generated_node_inputs=MappingProxyType({}),
        overlay_witnesses=(),
    )
    executor.effective_root = source_root
    executor.build_root = build_root
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer._runtime_open = True
    producer._mode = None
    producer._lane_pool = cast(classic_runtime_environment._LazyExecutionLanePool, pool)
    producer._output_lock = Lock()
    producer._physical_outputs = {}
    executor.producer = producer
    empty_snapshot = SimpleNamespace(files=())
    producer.authority_namespace_lease = lambda: nullcontext(  # type: ignore[method-assign]
        SimpleNamespace(snapshot=empty_snapshot)
    )
    producer.source_namespace_lease = lambda: nullcontext(  # type: ignore[method-assign]
        SimpleNamespace(snapshot=empty_snapshot)
    )
    producer.capture_compiler_namespace = (  # type: ignore[method-assign]
        lambda *args, **kwargs: SimpleNamespace(evidence=SimpleNamespace(namespace_id="probe"))
    )
    producer.include_authority = lambda: object()  # type: ignore[method-assign]

    def reference(value: str) -> Path | None:
        prefix, relative = value.split("/", 1)
        return (source_root if prefix == "source" else build_root) / relative

    producer.reference = reference  # type: ignore[method-assign]

    def run_nodes(
        supervisor: ProcessSupervisor,
        nodes: tuple[ProducerNode, ...],
        **kwargs: object,
    ) -> list[StepExecutionReceipt]:
        del supervisor
        assert nodes == (node,)
        object_path = build_root / "unit.obj"
        pdb_path = build_root / "unit.pdb"
        object_path.write_bytes(b"raw object")
        pdb_path.write_bytes(b"raw pdb")
        producer._physical_outputs[object_path] = object_path
        producer._physical_outputs[pdb_path] = pdb_path
        cast(set[str], kwargs["completed"]).add(node.id)
        return [classic_runtime_producer._internal_step(f"probe.{node.id}", {}, 0.0)]

    producer.run_graph_nodes = run_nodes  # type: ignore[method-assign]

    outputs = executor.probe_compiler_nodes((node.id,))

    assert len(outputs) == 1
    assert outputs[0].object_payload == b"raw object"
    assert outputs[0].pdb_payload == b"raw pdb"
    assert outputs[0].object_digest == Digest.from_bytes(b"raw object")
    assert outputs[0].pdb_digest == Digest.from_bytes(b"raw pdb")
    assert pool.closed is True
    assert producer._runtime_open is False


class _DonorProbePool:
    created_count = 0

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _donor_probe_executor(
    tmp_path: Path,
    *,
    donors: tuple[tuple[str, bytes], ...],
    jobs: int,
) -> tuple[
    classic_runtime_developer.ClassicDeveloperExecution,
    _DonorProbePool,
    SimpleNamespace,
    SealedNamespaceSnapshot,
    Path,
]:
    source_root = tmp_path / "source"
    source_root.mkdir()
    source = source_root / "unit.cpp"
    source.write_bytes(b"int value;\n")

    def prepared_donor(donor_id: str, payload: bytes) -> SimpleNamespace:
        return SimpleNamespace(
            intervention=SimpleNamespace(id=donor_id),
            request=SimpleNamespace(
                build_target="program",
                logical_source="unit.cpp",
                logical_outputs=MappingProxyType({"unit.cpp": payload}),
            ),
        )

    prepared_donors = tuple(prepared_donor(donor_id, payload) for donor_id, payload in donors)
    unit = SimpleNamespace(
        plan=SimpleNamespace(id="tu.program.unit"),
        donors=prepared_donors,
    )

    pool = _DonorProbePool()
    executor = object.__new__(classic_runtime_developer.ClassicDeveloperExecution)
    executor._warm_stack = None
    executor.units = cast(tuple[classic_orchestration.ClassicPreparedUnit, ...], (unit,))
    executor.overlay = SimpleNamespace(
        overlay_witnesses=(),
        generated_translation_units=frozenset(),
    )
    executor.effective_root = source_root
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer._runtime_open = True
    producer._mode = None
    producer._lane_pool = cast(classic_runtime_environment._LazyExecutionLanePool, pool)
    producer.jobs = jobs
    executor.producer = producer
    empty_snapshot = SealedNamespaceSnapshot(())
    producer.authority_namespace_lease = lambda: nullcontext(  # type: ignore[method-assign]
        SimpleNamespace(snapshot=empty_snapshot)
    )
    producer.source_namespace_lease = lambda: nullcontext(  # type: ignore[method-assign]
        SimpleNamespace(snapshot=empty_snapshot)
    )
    producer.capture_compiler_namespace = (  # type: ignore[method-assign]
        lambda *args, **kwargs: SimpleNamespace(
            evidence=SimpleNamespace(namespace_id="donor-probe")
        )
    )
    producer.include_authority = lambda: object()  # type: ignore[method-assign]

    return executor, pool, unit, empty_snapshot, source


def test_exact_donor_probe_runs_in_parallel_with_stable_output_and_progress(
    tmp_path: Path,
) -> None:
    executor, pool, _unit, empty_snapshot, source = _donor_probe_executor(
        tmp_path,
        donors=(
            ("donor.first", b"rendered first\n"),
            ("donor.second", b"rendered second\n"),
        ),
        jobs=2,
    )

    invoked: list[str] = []
    invocation_lock = Lock()
    both_started = Barrier(2)

    def invoke(
        supervisor: ProcessSupervisor,
        unit_arg: SimpleNamespace,
        donor_index: int,
        cancellation: CancellationToken,
        *,
        step_id: str,
        compiler_epoch: classic_runtime_overlay.ClassicActiveCompilerEpoch,
    ) -> classic_runtime_donor._DonorCompilerInvocation:
        del supervisor, cancellation, compiler_epoch
        donor = unit_arg.donors[donor_index]
        with invocation_lock:
            invoked.append(donor.intervention.id)
        both_started.wait(timeout=5)
        object_payload = f"object:{donor.intervention.id}".encode()
        pdb_payload = f"pdb:{donor.intervention.id}".encode()
        record = classic_runtime_graph.ClassicCompileRecord(
            "compiler.program.0000",
            tmp_path,
            source,
            tmp_path / "unit.obj",
            tmp_path / "unit.pdb",
            ("cl",),
            "program",
        )
        spec = CommandSpec.create(("cl",), cwd=tmp_path, timeout_seconds=1)
        return classic_runtime_donor._DonorCompilerInvocation(
            record,
            tmp_path / "donor.obj",
            tmp_path / "donor.pdb",
            object_payload,
            pdb_payload,
            ProcessResult(("cl",), 0, b"ok", 1, 0.01),
            spec,
            empty_snapshot,
            step_id,
        )

    executor.donors = SimpleNamespace(invoke_donor_compiler=invoke)
    progress: list[tuple[int, int, str]] = []

    outputs = executor.probe_donor_compilers(
        ("donor.second", "donor.first"),
        progress=lambda completed, total, donor_id: progress.append((completed, total, donor_id)),
    )

    assert set(invoked) == {"donor.first", "donor.second"}
    assert [item.donor_id for item in outputs] == ["donor.second", "donor.first"]
    assert [(completed, total) for completed, total, _donor_id in progress] == [
        (1, 2),
        (2, 2),
    ]
    assert {donor_id for _completed, _total, donor_id in progress} == {
        "donor.first",
        "donor.second",
    }
    assert outputs[0].translation_unit_id == "tu.program.unit"
    assert outputs[0].source_reference == "unit.cpp"
    assert outputs[0].producer_node_id == "compiler.program.0000"
    assert outputs[0].rendered_inputs == (
        classic_runtime_developer.ClassicDonorProbeInput(
            "unit.cpp",
            Digest.from_bytes(b"rendered second\n"),
            len(b"rendered second\n"),
            b"rendered second\n",
        ),
    )
    assert outputs[0].object_payload == b"object:donor.second"
    assert outputs[0].pdb_payload == b"pdb:donor.second"
    assert outputs[0].object_digest == Digest.from_bytes(outputs[0].object_payload)
    assert outputs[0].pdb_digest == Digest.from_bytes(outputs[0].pdb_payload)
    assert pool.closed is True
    assert executor.producer._runtime_open is False


def test_donor_probe_failure_cancels_active_sibling_without_replenishing(
    tmp_path: Path,
) -> None:
    executor, pool, _unit, _empty_snapshot, _source = _donor_probe_executor(
        tmp_path,
        donors=(
            ("donor.waiting", b"waiting\n"),
            ("donor.failure", b"failure\n"),
            ("donor.unstarted", b"unstarted\n"),
        ),
        jobs=2,
    )
    invoked: list[str] = []
    invocation_lock = Lock()
    both_started = Barrier(2)
    cancellation_observed = Event()

    def invoke(
        supervisor: ProcessSupervisor,
        unit_arg: SimpleNamespace,
        donor_index: int,
        cancellation: CancellationToken,
        *,
        step_id: str,
        compiler_epoch: classic_runtime_overlay.ClassicActiveCompilerEpoch,
    ) -> classic_runtime_donor._DonorCompilerInvocation:
        del supervisor, step_id, compiler_epoch
        donor_id = unit_arg.donors[donor_index].intervention.id
        with invocation_lock:
            invoked.append(donor_id)
        both_started.wait(timeout=5)
        if donor_id == "donor.failure":
            raise RuntimeError("deliberate donor failure")
        assert donor_id == "donor.waiting"
        for _ in range(500):
            if cancellation.cancelled:
                cancellation_observed.set()
                cancellation.raise_if_cancelled()
            cancellation_observed.wait(0.01)
        raise AssertionError("probe sibling did not observe cancellation")

    executor.donors = SimpleNamespace(invoke_donor_compiler=invoke)

    with pytest.raises(RuntimeError, match="deliberate donor failure"):
        executor.probe_donor_compilers(("donor.waiting", "donor.failure", "donor.unstarted"))

    assert cancellation_observed.is_set()
    assert set(invoked) == {"donor.waiting", "donor.failure"}
    assert pool.closed is True
    assert executor.producer._runtime_open is False


def test_donor_probe_rejects_unprepared_id_and_still_closes_runtime(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()

    class Pool:
        created_count = 0
        closed = False

        def close(self) -> None:
            self.closed = True

    pool = Pool()
    executor = object.__new__(classic_runtime_developer.ClassicDeveloperExecution)
    executor._warm_stack = None
    executor.units = ()
    executor.effective_root = source_root
    producer = object.__new__(classic_runtime_producer.ClassicProducerExecution)
    producer._runtime_open = True
    producer._mode = None
    producer._lane_pool = cast(classic_runtime_environment._LazyExecutionLanePool, pool)
    executor.producer = producer

    with pytest.raises(ClassicProjectError, match="unknown prepared donors"):
        executor.probe_donor_compilers(("donor.absent",))

    assert pool.closed is True
    assert producer._runtime_open is False


def test_legacy_oracle_binding_requires_the_exact_prepared_capability_set() -> None:
    executor = object.__new__(classic_runtime_donor.ClassicDonorComposition)
    executor._started = False
    executor._legacy_oracles = MappingProxyType({})
    executor.units = cast(
        tuple[classic_orchestration.ClassicPreparedUnit, ...],
        (SimpleNamespace(legacy_actions=(SimpleNamespace(oracle_target="program"),)),),
    )

    with pytest.raises(ClassicProjectError, match=r"extra=\['unused'\]"):
        executor.bind_legacy_oracles(
            cast(
                object,
                {"program": object(), "unused": object()},
            )
        )


def _bound_wine_runtime(
    tmp_path: Path,
) -> tuple[PosixWineBackend, WorkerSandbox, Path, Path, ExitStack]:
    backend = PosixWineBackend(wine=sys.executable, wineserver=sys.executable)
    worker = backend.create_worker(tmp_path / "workers", "cmake")
    assert worker.wine_prefix is not None
    drive_c = worker.wine_prefix / "drive_c"
    drive_c.mkdir()
    dosdevices = worker.wine_prefix / "dosdevices"
    dosdevices.mkdir()
    c_drive = dosdevices / "c:"
    c_drive.symlink_to(drive_c, target_is_directory=True)
    for name in ("system.reg", "user.reg", "userdef.reg"):
        (worker.wine_prefix / name).write_text("sealed\n", encoding="utf-8")

    logical_root = tmp_path / "logical-drive"
    logical_root.mkdir()
    stack = ExitStack()
    stack.enter_context(
        backend.bind_skeleton(
            worker,
            MaterializedSkeleton(logical_root, "Z", ()),
        )
    )
    assert tuple(sorted(path.name for path in dosdevices.iterdir())) == ("c:", "z:")
    return backend, worker, dosdevices, c_drive, stack


@pytest.mark.skipif(os.name != "posix", reason="Wine drive leases require POSIX symlinks")
def test_close_runtime_rejects_drive_exposed_while_producers_were_live(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, worker, dosdevices, c_drive, stack = _bound_wine_runtime(tmp_path)
    (dosdevices / "d:").symlink_to(tmp_path, target_is_directory=True)
    lifecycle: list[str] = []

    def terminate(worker_arg: WorkerSandbox, *, timeout_seconds: float) -> None:
        assert worker_arg is worker
        assert timeout_seconds == 10.0
        lifecycle.extend(("-k", "-w"))

    monkeypatch.setattr(backend, "terminate_worker_server", terminate)

    with pytest.raises(BackendError, match="mapping changed during producer execution"):
        classic_runtime_environment._close_backend_runtime(
            backend,
            worker,
            stack,
            logical_drive="Z",
        )

    assert lifecycle == ["-k", "-w"]
    assert tuple(dosdevices.iterdir()) == (c_drive,)


@pytest.mark.skipif(os.name != "posix", reason="Wine drive leases require POSIX symlinks")
def test_close_runtime_rejects_transient_drive_mapping_create_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, worker, dosdevices, c_drive, stack = _bound_wine_runtime(tmp_path)
    transient = dosdevices / "d:"
    transient.symlink_to(tmp_path, target_is_directory=True)
    transient.unlink()
    lifecycle: list[str] = []

    def terminate(worker_arg: WorkerSandbox, *, timeout_seconds: float) -> None:
        assert worker_arg is worker
        assert timeout_seconds == 10.0
        lifecycle.extend(("-k", "-w"))

    monkeypatch.setattr(backend, "terminate_worker_server", terminate)

    with pytest.raises(BackendError, match="mapping changed during producer execution"):
        classic_runtime_environment._close_backend_runtime(
            backend,
            worker,
            stack,
            logical_drive="Z",
        )

    assert lifecycle == ["-k", "-w"]
    assert tuple(dosdevices.iterdir()) == (c_drive,)


@pytest.mark.parametrize("residual_kind", ("symlink", "regular"))
@pytest.mark.skipif(os.name != "posix", reason="Wine drive leases require POSIX symlinks")
def test_close_runtime_scrubs_recreated_wine_drives_after_server_reap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    residual_kind: str,
) -> None:
    backend, worker, dosdevices, c_drive, stack = _bound_wine_runtime(tmp_path)

    lifecycle: list[str] = []

    def terminate(worker_arg: WorkerSandbox, *, timeout_seconds: float) -> None:
        assert worker_arg is worker
        assert timeout_seconds == 10.0
        lifecycle.extend(("-k", "-w"))
        if residual_kind:
            residual = dosdevices / "d:"
            if residual_kind == "symlink":
                residual.symlink_to(tmp_path, target_is_directory=True)
            else:
                residual.write_text("unowned\n", encoding="utf-8")

    monkeypatch.setattr(backend, "terminate_worker_server", terminate)

    if residual_kind == "regular":
        with pytest.raises(BackendError, match="drive"):
            classic_runtime_environment._close_backend_runtime(
                backend,
                worker,
                stack,
                logical_drive="Z",
            )
    else:
        classic_runtime_environment._close_backend_runtime(
            backend,
            worker,
            stack,
            logical_drive="Z",
        )

    assert lifecycle == ["-k", "-w"]
    assert not os.path.lexists(dosdevices / "z:")
    if residual_kind == "symlink":
        assert tuple(dosdevices.iterdir()) == (c_drive,)
