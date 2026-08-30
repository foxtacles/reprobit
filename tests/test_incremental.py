from __future__ import annotations

from pathlib import Path

import pytest

import reprobit.implementation as implementation
from reprobit.cache import IncrementalCache, cache_key
from reprobit.implementation import package_implementation_digest
from reprobit.incremental import (
    PRODUCER_CACHE_IMPLEMENTATION,
    PRODUCER_IMPLEMENTATION_DIGEST,
    IncrementalAuthorityError,
    IncrementalBuildSummary,
    current_worktree_authority,
    producer_cache_implementation,
    producer_cache_key,
    require_fresh_protected_recursive_inputs,
)
from reprobit.model import Digest, Scope
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    source_topology_digest,
    toolchain_document_digest,
)
from reprobit.schema import (
    BuildPlanDocument,
    ClassicTargetGate,
    ClassicTranslationUnitPlan,
    InterventionDocument,
    LockedTool,
    LogicalPathProfile,
    MsvcRelease,
    OracleDocument,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    ProjectSpec,
    ProofDocument,
    StateCarrierIntervention,
    TargetSpec,
    ToolchainLock,
    ToolchainRef,
    source_manifest_digest,
)
from reprobit.source_lock import build_source_manifest


def test_incremental_summary_accepts_bounded_parallel_lane_count() -> None:
    summary = IncrementalBuildSummary(0, 4, 0, 0, 1.5, runtime_init_count=3)
    assert summary.runtime_init_count == 3
    with pytest.raises(ValueError, match="cannot be negative"):
        IncrementalBuildSummary(0, 0, 0, 0, 0, runtime_init_count=-1)


def test_package_implementation_digest_change_is_a_cache_miss(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    output = tmp_path / "out.obj"
    output.write_bytes(b"object")
    first_implementation = producer_cache_implementation(Digest(value="1" * 64))
    second_implementation = producer_cache_implementation(Digest(value="2" * 64))
    assert first_implementation != second_implementation
    key = "a" * 64
    with IncrementalCache(state, implementation=first_implementation).lease() as lease:
        lease.store("producer", key, {"build/out.obj": output})
    with IncrementalCache(state, implementation=second_implementation).lease() as lease:
        assert lease.lookup("producer", key) is None


def test_captured_producer_digest_defines_cache_namespace() -> None:
    assert (
        producer_cache_implementation(PRODUCER_IMPLEMENTATION_DIGEST)
        == PRODUCER_CACHE_IMPLEMENTATION
    )


def test_package_reseal_includes_runtime_proxy_asset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = package_implementation_digest()
    proxy = tmp_path / "ReproBitPathProxy.sh"
    original = implementation.runtime_asset_path("ReproBitPathProxy.sh").read_bytes()
    proxy.write_bytes(original)
    monkeypatch.setattr(implementation, "runtime_asset_path", lambda _name: proxy)
    implementation.revalidate_package_implementation(expected)

    proxy.write_bytes(original + b"\n# editable drift\n")
    with pytest.raises(RuntimeError, match="implementation changed"):
        implementation.revalidate_package_implementation(expected)


def _bundle(root: Path, *, protected: bool = False) -> ProjectBundle:
    files = {
        "include/common.h": b"#define VALUE 1\n",
        "notes.txt": b"note\n",
        "src/unit.cpp": b'#include "common.h"\nint value = VALUE;\n',
    }
    for relative, payload in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    spec = ProjectSpec(
        schema_version=3,
        project_id="incremental-fixture",
        state_dir=".state",
        build=ProducerGraphBuildAdapter(),
        toolchain=ToolchainRef(profile="compiler-42"),
        paths=LogicalPathProfile(
            source=r"R:\source",
            build=r"R:\build",
            toolchain=r"R:\toolchain",
        ),
        targets=(
            TargetSpec(
                id="program",
                artifact="build/program.exe",
                oracle="reference/program.exe",
            ),
        ),
    )
    manifest = build_source_manifest(root, files, spec=spec)
    toolchain = ToolchainLock(
        schema_version=3,
        profile="compiler-42",
        release=MsvcRelease.V4_2,
        tools=(
            LockedTool(
                id="compiler",
                path="bin/CL.EXE",
                digest=Digest.from_bytes(b"compiler"),
            ),
        ),
    )
    unit_digest = next(item.digest for item in manifest.entries if item.path == "src/unit.cpp")
    plan = BuildPlanDocument(
        schema_version=3,
        source_manifest_digest=source_manifest_digest(manifest),
        translation_units=(
            ClassicTranslationUnitPlan(
                id="unit",
                target_id="program",
                build_target="program",
                source="src/unit.cpp",
                source_digest=unit_digest,
            ),
        ),
        source_overlay_digest=Digest.from_bytes(b"no overlays"),
        source_overlay_interventions=(),
        archives=(),
        target_gates=(
            ClassicTargetGate(
                target_id="program",
                build_target="program",
            ),
        ),
    )
    compiler = ProducerNode(
        id="compiler.unit",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=(
            "/c",
            "${SOURCE}/src/unit.cpp",
            "/Fo${BUILD}/unit.obj",
        ),
        inputs=("source/src/unit.cpp",),
        outputs=("build/unit.obj",),
    )
    linker = ProducerNode(
        id="linker.program",
        role=ProducerRole.LINKER,
        owner="program",
        target_id="program",
        arguments=("${BUILD}/unit.obj", "/out:${BUILD}/program.exe"),
        inputs=("build/unit.obj",),
        outputs=("build/program.exe",),
        depends_on=("compiler.unit",),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=source_topology_digest(files),
        toolchain_lock_digest=toolchain_document_digest(toolchain),
        path_profile_id=spec.paths.id,
        extractor="cmake-makefiles-v1",
        nodes=(compiler, linker),
    )
    interventions = (
        (
            StateCarrierIntervention(
                id="reviewed.unit",
                scope=Scope(target="program", translation_unit="unit"),
                rationale="test a reviewed translation-unit boundary",
                carrier="unit",
            ),
        )
        if protected
        else ()
    )
    return ProjectBundle(
        root=str(root),
        spec=spec,
        toolchain_lock=toolchain,
        source_manifest=manifest,
        build_plan=plan,
        producer_graph=graph,
        intervention_documents=(
            InterventionDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="unit",
                source="src/unit.cpp",
                source_digest=unit_digest,
                build_target="program",
                interventions=interventions,
            ),
        ),
        proof_documents=(
            ProofDocument(
                schema_version=3,
                target_id="program",
                translation_unit_id="unit",
            ),
        ),
        oracle_documents=(
            OracleDocument(
                schema_version=3,
                target_id="program",
                image_size=1,
                image_digest=Digest.from_bytes(b"oracle"),
            ),
        ),
    )


def test_current_worktree_authority_is_ephemeral_and_updates_unreviewed_tu(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path)
    manifest_before = bundle.source_manifest
    plan_before = bundle.build_plan
    (tmp_path / "src/unit.cpp").write_bytes(b"int value = 2;\n")

    developer = current_worktree_authority(bundle, tmp_path)

    assert developer.changed_paths == ("src/unit.cpp",)
    assert developer.changed_translation_units == ("unit",)
    assert developer.bundle.source_manifest != manifest_before
    assert developer.bundle.build_plan != plan_before
    assert bundle.source_manifest == manifest_before
    assert bundle.build_plan == plan_before


def test_unrelated_admitted_edit_does_not_repin_translation_unit(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path, protected=True)
    assert bundle.build_plan is not None
    original = bundle.build_plan.translation_units[0].source_digest
    (tmp_path / "notes.txt").write_bytes(b"changed note\n")

    developer = current_worktree_authority(bundle, tmp_path)

    assert developer.changed_paths == ("notes.txt",)
    assert developer.changed_translation_units == ()
    assert developer.bundle.build_plan is not None
    assert developer.bundle.build_plan.translation_units[0].source_digest == original


def test_reviewed_translation_unit_edit_names_affected_intervention(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path, protected=True)
    (tmp_path / "src/unit.cpp").write_bytes(b"int value = 3;\n")

    with pytest.raises(IncrementalAuthorityError, match=r"reviewed\.unit"):
        current_worktree_authority(bundle, tmp_path)


def test_reviewed_translation_unit_rejects_changed_recursive_header(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path, protected=True)
    (tmp_path / "include/common.h").write_bytes(b"#define VALUE 2\n")
    developer = current_worktree_authority(bundle, tmp_path)

    with pytest.raises(
        IncrementalAuthorityError,
        match=r"common\.h.*unit.*reviewed\.unit",
    ):
        require_fresh_protected_recursive_inputs(
            developer,
            translation_unit_id="unit",
            source="src/unit.cpp",
            recursive_logical_paths=(
                r"R:\source\src\unit.cpp",
                r"R:\source\include\common.h",
                r"R:\toolchain\include\stdio.h",
            ),
        )


def test_unrelated_edit_does_not_trip_protected_recursive_guard(
    tmp_path: Path,
) -> None:
    bundle = _bundle(tmp_path, protected=True)
    (tmp_path / "notes.txt").write_bytes(b"unrelated\n")
    developer = current_worktree_authority(bundle, tmp_path)

    require_fresh_protected_recursive_inputs(
        developer,
        translation_unit_id="unit",
        source="src/unit.cpp",
        recursive_logical_paths=(
            r"R:\source\src\unit.cpp",
            r"R:\source\include\common.h",
        ),
    )


def test_path_deletion_cannot_be_hidden_by_ephemeral_authority(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    (tmp_path / "notes.txt").unlink()

    with pytest.raises(IncrementalAuthorityError, match="path topology"):
        current_worktree_authority(bundle, tmp_path)


def test_producer_key_requires_every_dependency_class() -> None:
    material = {
        "graph": "g",
        "node": "compiler.unit",
        "role": "compiler",
        "toolchain": [],
        "runtime": [],
        "argv": [],
        "cwd": "R:/build",
        "environment": [],
        "path_profile": "p",
        "direct_inputs": [],
        "producer_dependencies": [],
        "recursive_reads": [],
        "overlay_inputs": [],
        "generated_inputs": [],
        "donor_inputs": [],
        "composition_inputs": [],
        "transform_inputs": [],
    }
    expected = cache_key(
        "producer",
        material,  # type: ignore[arg-type]
        implementation=PRODUCER_CACHE_IMPLEMENTATION,
    )
    assert producer_cache_key(material) == expected  # type: ignore[arg-type]
    assert producer_cache_key(dict(reversed(tuple(material.items())))) == expected  # type: ignore[arg-type]

    invalid = dict(material)
    invalid["runtime"] = float("nan")
    with pytest.raises(ValueError, match="finite"):
        producer_cache_key(invalid)  # type: ignore[arg-type]

    del material["recursive_reads"]
    with pytest.raises(IncrementalAuthorityError, match="recursive_reads"):
        producer_cache_key(material)  # type: ignore[arg-type]
