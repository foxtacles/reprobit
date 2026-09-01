from __future__ import annotations

import os
import shutil
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest

import reprobit.classic.composition as classic_composition
import reprobit.classic.scheduling as classic_scheduling
import reprobit.source_export as source_export
from reprobit.classic.compiler_identity import (
    Msvc420CompilerIdentity,
    issue_msvc420_compiler_identity,
)
from reprobit.classic_project import (
    FAMILY_COVERAGE,
    ClassicDispatchMaterials,
    ClassicFamilyDispatcher,
    ClassicProjectError,
    _copy_effective_source,
    materialize_effective_workspace,
    write_cmake_project_plan,
)
from reprobit.cmake import cmake_module_path
from reprobit.model import Digest, Scope
from reprobit.schema import (
    BuildPlanDocument,
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTargetGate,
    InterventionDocument,
    LockedTool,
    LogicalPathProfile,
    MsvcRelease,
    OracleDocument,
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
    source_manifest_digest,
)
from reprobit.source_authority import SourceAuthorityError, inspect_source_authority
from reprobit.source_export import SourceExportError, refresh_effective_source_export
from reprobit.source_lock import build_source_manifest
from reprobit.strict_json import canonical_json


def _digest(data: bytes) -> Digest:
    return Digest.from_bytes(data)


def _bundle(root: Path) -> tuple[ProjectBundle, bytes]:
    module = (cmake_module_path() / "ReproBit.cmake").as_posix()
    files = {
        "CMakeLists.txt": f'''cmake_minimum_required(VERSION 3.20)
project(classic_adapter_fixture CXX)
include("{module}")
add_library(app STATIC first.cpp last.cpp)
set(REPROBIT_EFFECTIVE_SOURCE_ROOT "${{CMAKE_CURRENT_SOURCE_DIR}}")
include("${{REPROBIT_PROJECT_PLAN}}")
get_target_property(final_sources app SOURCES)
file(WRITE "${{CMAKE_BINARY_DIR}}/sources.txt" "${{final_sources}}\n")
'''.encode(),
        "first.cpp": b"int first() { return 1; }\n",
        "last.cpp": b"int last() { return 3; }\n",
    }
    for relative, data in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    spec = ProjectSpec(
        schema_version=3,
        project_id="fixture",
        state_dir="state",
        build=ProducerGraphBuildAdapter(),
        toolchain=ToolchainRef(profile="compiler-42"),
        paths=LogicalPathProfile(
            source=r"R:\source",
            build=r"R:\build",
            toolchain=r"R:\toolchain",
        ),
        targets=(TargetSpec(id="program", artifact="state/program.exe", oracle="reference.exe"),),
    )
    source_manifest = build_source_manifest(root, files, spec=spec)
    generated = b"class Generated;\n"
    output = {
        "path": "generated.cpp",
        "effective": sha256(generated).hexdigest(),
        "size": len(generated),
        "ops": [{"op": "append", "gen": {"k": "fwd", "id": "Generated"}}],
    }
    graph = {
        "generated_tus": [
            {
                "path": "generated.cpp",
                "ordinal": 2,
                "after": "first.cpp",
            }
        ],
        "link_admissions": [],
    }
    intervention = ClassicRecipeIntervention(
        id="overlay.graph",
        scope=Scope(target="program"),
        rationale="exercise the generic generated-source seat",
        family=ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH,
        role=ClassicRecipeRole.PROJECT,
        build_target="app",
        parameters=(
            ClassicField.model_validate({"name": "graph", "value": graph}),
            ClassicField.model_validate({"name": "outputs", "value": [output]}),
            ClassicField.model_validate({"name": "schema", "value": 2}),
        ),
    )
    source_pin = source_manifest_digest(source_manifest)
    bundle = ProjectBundle(
        root=str(root),
        spec=spec,
        toolchain_lock=ToolchainLock(
            schema_version=3,
            profile="compiler-42",
            release=MsvcRelease.V4_2,
            tools=(
                LockedTool(
                    id="compiler",
                    path="bin/CL.EXE",
                    digest=_digest(b"compiler"),
                ),
            ),
        ),
        source_manifest=source_manifest,
        build_plan=BuildPlanDocument(
            schema_version=3,
            source_manifest_digest=source_pin,
            translation_units=(),
            source_overlay_digest=_digest(canonical_json(graph)),
            source_overlay_interventions=(intervention.id,),
            archives=(),
            target_gates=(ClassicTargetGate(target_id="program", build_target="app"),),
        ),
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
        oracle_documents=(
            OracleDocument(
                schema_version=3,
                target_id="program",
                image_size=1,
                image_digest=_digest(b"oracle"),
            ),
        ),
    )
    return bundle, generated


def test_effective_source_copy_rejects_symlinked_manifest_ancestor(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    payload = b"outside header"
    (outside / "input.h").write_bytes(payload)
    (project / "vendor").symlink_to(outside, target_is_directory=True)
    bundle, _generated = _bundle(project)
    assert bundle.source_manifest is not None
    manifest = SourceManifestDocument(
        schema_version=3,
        complete=True,
        entries=tuple(
            sorted(
                (
                    *bundle.source_manifest.entries,
                    SourceManifestEntry(
                        path="vendor/input.h",
                        size=len(payload),
                        digest=Digest.from_bytes(payload),
                    ),
                ),
                key=lambda item: (item.path.casefold(), item.path),
            )
        ),
    )
    redirected = bundle.model_copy(update={"source_manifest": manifest})

    with pytest.raises(ClassicProjectError, match="without redirection"):
        _copy_effective_source(
            project,
            tmp_path / "effective",
            bundle=redirected,
        )


def test_source_export_refreshes_a_real_overlay_and_removes_stale_files(
    tmp_path: Path,
) -> None:
    project = tmp_path / "project"
    bundle, generated = _bundle(project)
    destination = project / "build/comparison-source"
    destination.mkdir(parents=True)
    (destination / "stale.cpp").write_bytes(b"remove me")

    witnesses = refresh_effective_source_export(bundle, project, destination)

    assert tuple(item.intervention_id for item in witnesses) == ("overlay.graph",)
    assert (destination / "generated.cpp").read_bytes() == generated
    assert not (destination / "stale.cpp").exists()

    (destination / "generated.cpp").write_bytes(b"stale generated source")
    (destination / "removed-on-refresh.txt").write_bytes(b"stale")
    refresh_effective_source_export(bundle, project, destination)

    assert (destination / "generated.cpp").read_bytes() == generated
    assert not (destination / "removed-on-refresh.txt").exists()
    assert not tuple(destination.parent.glob(".rbit-source-*-*"))


def test_source_export_failed_promotion_restores_the_previous_complete_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    bundle, _generated = _bundle(project)
    destination = project / "build/comparison-source"
    refresh_effective_source_export(bundle, project, destination)
    before = {
        path.relative_to(destination): path.read_bytes()
        for path in destination.rglob("*")
        if path.is_file()
    }
    real_replace = source_export._replace_directory
    calls = 0

    def fail_new_export(source: Path, target: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated promotion failure")
        real_replace(source, target)

    monkeypatch.setattr(source_export, "_replace_directory", fail_new_export)

    with pytest.raises(SourceExportError, match="previous export was preserved"):
        refresh_effective_source_export(bundle, project, destination)

    after = {
        path.relative_to(destination): path.read_bytes()
        for path in destination.rglob("*")
        if path.is_file()
    }
    assert after == before
    assert not tuple(destination.parent.glob(".rbit-source-*-*"))


def test_source_export_rejects_a_redirected_destination(tmp_path: Path) -> None:
    project = tmp_path / "project"
    bundle, _generated = _bundle(project)
    outside = tmp_path / "outside"
    outside.mkdir()
    redirected = project / "redirected"
    redirected.symlink_to(outside, target_is_directory=True)

    with pytest.raises(SourceExportError, match="destination is redirected"):
        refresh_effective_source_export(bundle, project, redirected)

    assert not tuple(outside.iterdir())


@pytest.mark.skipif(shutil.which("cmake") is None, reason="CMake is not installed")
@pytest.mark.skipif(os.name != "posix", reason="project-plan fixture requires POSIX")
def test_generated_project_plan_configures_at_exact_graph_seat(tmp_path: Path) -> None:
    bundle, generated = _bundle(tmp_path)
    effective = tmp_path / "state/effective"
    build = tmp_path / "state/configure"
    intervention_witnesses = materialize_effective_workspace(bundle, tmp_path, effective)
    assert tuple(item.intervention_id for item in intervention_witnesses) == ("overlay.graph",)
    assert (effective / "generated.cpp").read_bytes() == generated
    plan = tmp_path / "state/project-plan.cmake"
    target_plan = build / "target-plan.json"
    write_cmake_project_plan(bundle, effective, plan)
    completed = subprocess.run(
        [
            "cmake",
            "-S",
            str(effective),
            "-B",
            str(build),
            f"-DREPROBIT_PROJECT_PLAN={plan}",
            f"-DREPROBIT_TARGET_PLAN={target_plan}",
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert target_plan.is_file()
    sources = (build / "sources.txt").read_text(encoding="utf-8")
    assert "first.cpp;" in sources
    assert "/generated.cpp;last.cpp" in sources


def test_source_authority_rejects_stale_clean_overlay_pin(tmp_path: Path) -> None:
    bundle, generated = _bundle(tmp_path)
    clean = b"int value;\n"
    (tmp_path / "first.cpp").write_bytes(clean)
    output = {
        "path": "first.cpp",
        "clean": sha256(clean).hexdigest(),
        "effective": sha256(generated + clean).hexdigest(),
        "size": len(generated + clean),
        "ops": [
            {
                "op": "insert",
                "anchor": {
                    "ctx": sha256(b"<SEAT>\0int\0value\0;").hexdigest(),
                    "b": 0,
                    "a": 3,
                    "at": "start",
                },
                "gen": {"k": "fwd", "id": "Generated"},
            }
        ],
    }
    graph = {"generated_tus": [], "link_admissions": []}
    overlay = next(
        item
        for item in bundle.interventions
        if isinstance(item, ClassicRecipeIntervention)
        and item.family is ClassicRecipeFamily.SOURCE_OVERLAY_GRAPH
    ).model_copy(
        update={
            "parameters": (
                ClassicField.model_validate({"name": "graph", "value": graph}),
                ClassicField.model_validate({"name": "outputs", "value": [output]}),
                ClassicField.model_validate({"name": "schema", "value": 2}),
            )
        }
    )
    documents = tuple(
        document.model_copy(
            update={
                "interventions": tuple(
                    overlay if item.id == overlay.id else item for item in document.interventions
                )
            }
        )
        for document in bundle.intervention_documents
    )
    candidate_bundle = bundle.model_copy(update={"intervention_documents": documents})
    assert candidate_bundle.source_manifest is not None
    baseline = build_source_manifest(
        tmp_path,
        (entry.path for entry in candidate_bundle.source_manifest.entries),
        spec=candidate_bundle.spec,
    )
    inspect_source_authority(candidate_bundle, tmp_path, source_manifest=baseline)

    (tmp_path / "first.cpp").write_bytes(b"int first() { return 2; }\n")
    refreshed = build_source_manifest(
        tmp_path,
        (entry.path for entry in candidate_bundle.source_manifest.entries),
        spec=candidate_bundle.spec,
    )
    with pytest.raises(SourceAuthorityError, match="requires regeneration"):
        inspect_source_authority(
            candidate_bundle,
            tmp_path,
            source_manifest=refreshed,
        )


def test_family_coverage_is_exhaustive_and_quarantine_fails_closed() -> None:
    assert set(FAMILY_COVERAGE) == set(ClassicRecipeFamily)
    simulated = FAMILY_COVERAGE[ClassicRecipeFamily.RETAIL_EXACT_SIMULATED_ELISION]
    assert not simulated.implemented
    assert simulated.mode.value == "quarantine-only"


def test_function_dispatch_materializes_typed_candidate_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symbol = "?Function@@YAHXZ"
    intervention = ClassicRecipeIntervention(
        id="function.same-slot",
        scope=Scope(
            target="program",
            translation_unit="unit",
            function=symbol,
        ),
        rationale="exercise the typed schema-v3 producer seam",
        family=ClassicRecipeFamily.SAME_SLOT_RESIZE,
        role=ClassicRecipeRole.FUNCTION,
        build_target="app",
        dependencies=("donor",),
        symbol=symbol,
    )
    captured: dict[str, object] = {}

    def compose(
        seed: bytes, donor: bytes, values: dict[str, object]
    ) -> tuple[bytes, dict[str, object]]:
        assert donor == b"donor"
        captured.update(values)
        return seed, {"accepted": True}

    monkeypatch.setattr(classic_composition, "compose_same_slot_resize", compose)
    result = ClassicFamilyDispatcher().dispatch(
        intervention,
        ClassicDispatchMaterials(
            seed_object=b"seed",
            donor_object=b"donor",
            candidate_constraints={"expected_seed_length": 4},
        ),
    )
    assert result.output == b"seed"
    assert captured["splice_class"] == "same_slot_resize"
    assert captured["symbol"] == symbol
    assert captured["mangled"] == symbol

    with pytest.raises(ClassicProjectError, match="splice class differs"):
        ClassicFamilyDispatcher().dispatch(
            intervention,
            ClassicDispatchMaterials(
                seed_object=b"seed",
                donor_object=b"donor",
                candidate_constraints={"splice_class": "equal_body_strict"},
            ),
        )


def test_web_dispatch_preserves_exact_compiler_scope_and_never_synthesizes_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symbol = "?Function@@YAHXZ"
    intervention = ClassicRecipeIntervention(
        id="function.web",
        scope=Scope(target="program", translation_unit="unit", function=symbol),
        rationale="exercise exact compiler-target authority at the dispatcher seam",
        family=ClassicRecipeFamily.RETAIL_EXACT_WEB_RECOLOUR,
        role=ClassicRecipeRole.FUNCTION,
        build_target="app",
        dependencies=("donor",),
        symbol=symbol,
    )
    tools = (
        (
            "bin/CL.EXE",
            37_888,
            "c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f",
            ("compiler",),
        ),
        (
            "bin/C1XX.EXE",
            793_088,
            "9e0782ec157b30a387ca855374bc4c1b8a605dfb12364425497ba431541a5bf9",
            ("runtime",),
        ),
        (
            "bin/C2.EXE",
            549_888,
            "2aa1fcace0779531b3ec80b730663acd98f181aed3cdff51366440c602b724b5",
            ("runtime",),
        ),
    )
    identity = issue_msvc420_compiler_identity(
        ToolchainLock(
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
            tools=tuple(
                LockedTool(
                    id=f"compiler-{index}",
                    path=path,
                    size=size,
                    digest=Digest(value=digest),
                    roles=roles,
                )
                for index, (path, size, digest, roles) in enumerate(tools)
            ),
        )
    )
    assert identity is not None
    received: list[object] = []

    def produce(
        seed: bytes,
        _donor: bytes,
        _function: dict[str, object],
        *,
        compiler_identity: Msvc420CompilerIdentity | None = None,
    ) -> tuple[bytes, dict[str, object]]:
        received.append(compiler_identity)
        if compiler_identity != identity:
            raise ClassicProjectError("compiler target is absent or wrong")
        return seed, {"accepted": True}

    monkeypatch.setattr(classic_scheduling, "produce_web_recolour_candidate", produce)
    result = ClassicFamilyDispatcher().dispatch(
        intervention,
        ClassicDispatchMaterials(
            seed_object=b"seed",
            donor_object=b"donor",
            compiler_identity=identity,
        ),
    )
    assert result.output == b"seed"
    assert received == [identity]

    for compiler_identity in (None, "msvc-5.00-win32-i386"):
        with pytest.raises(ClassicProjectError, match="absent or wrong"):
            ClassicFamilyDispatcher().dispatch(
                intervention,
                ClassicDispatchMaterials(
                    seed_object=b"seed",
                    donor_object=b"donor",
                    compiler_identity=compiler_identity,  # type: ignore[arg-type]
                ),
            )
    assert received[-2:] == [None, "msvc-5.00-win32-i386"]


def test_reloc_layout_dispatch_uses_equal_body_composer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symbol = "?Function@@YAHXZ"
    intervention = ClassicRecipeIntervention(
        id="function.reloc-layout",
        scope=Scope(
            target="program",
            translation_unit="unit",
            function=symbol,
        ),
        rationale="exercise the relocation-layout producer route",
        family=ClassicRecipeFamily.EQUAL_BODY_EH_RELOC_LAYOUT,
        role=ClassicRecipeRole.FUNCTION,
        build_target="app",
        dependencies=("donor",),
        symbol=symbol,
    )
    captured: dict[str, object] = {}

    def compose(
        seed: bytes, donor: bytes, values: dict[str, object]
    ) -> tuple[bytes, dict[str, object]]:
        assert donor == b"donor"
        captured.update(values)
        return seed, {"accepted": True}

    monkeypatch.setattr(classic_composition, "compose_equal_body_comdat", compose)

    result = ClassicFamilyDispatcher().dispatch(
        intervention,
        ClassicDispatchMaterials(
            seed_object=b"seed",
            donor_object=b"donor",
            candidate_constraints={"expected_relocation_moves": [[1, 2]]},
        ),
    )

    assert result.output == b"seed"
    assert captured["splice_class"] == "equal_body_eh_reloc_layout"
    assert captured["symbol"] == symbol
    assert captured["mangled"] == symbol
