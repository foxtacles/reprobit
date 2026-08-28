from __future__ import annotations

import os
import stat
import struct
import sys
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import cast

import pytest

import reprobit.classic_incremental as classic_incremental
import reprobit.incremental_executor as incremental_executor
from reprobit.backends import BackendCapabilities
from reprobit.cache import CacheLease, CacheRecord, cache_key
from reprobit.classic_donors import (
    DonorCompilerAdditions,
    DonorCompileReceipt,
    DonorCompileRequest,
    DonorIncludeProjection,
)
from reprobit.classic_includes import (
    IncludeOrigin,
    MsvcSbrSource,
    MsvcSbrTrace,
    ResolvedInclude,
    SealedIncludeAuthority,
    SealedIncludeFile,
)
from reprobit.classic_orchestration import (
    ClassicPreparedDonor,
    ClassicPreparedUnit,
    classic_rdata_repack_authority,
    classic_terminal_pipeline_authority,
)
from reprobit.classic_runtime import (
    _ClassicWarmCompilerReplay,
    _ClassicWarmCompilerTransformResult,
    _ClassicWarmDonorDependencyReplay,
)
from reprobit.incremental import DeveloperAuthority
from reprobit.incremental_executor import IncrementalProgress, PreparedNodeInputs
from reprobit.model import Digest, Scope
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
)
from reprobit.progress import ProgressKind
from reprobit.schema import (
    ClassicField,
    ClassicProofReceipt,
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    ClassicTranslationUnitPlan,
    LogicalPathProfile,
    ProducerGraphBuildAdapter,
)
from reprobit.secure_paths import SecurePathError, atomic_publish_relative
from reprobit.strict_json import JsonValue
from reprobit.toolchains import ClassicMSVCToolchain


class _FakeInstallation:
    def __init__(
        self,
        _profile: str,
        _root: Path,
        *,
        logical_root: str,
    ) -> None:
        self.logical_root = logical_root

    def doctor(self, _lock: object) -> SimpleNamespace:
        return SimpleNamespace(require_ok=lambda: None)

    def logical_path(self, relative: str) -> str:
        return self.logical_root.rstrip("\\") + "\\" + relative.replace("/", "\\")

    def default_environment(self, *, temp_directory: str) -> dict[str, str]:
        return {
            "INCLUDE": r"R:\toolchain\include",
            "LIB": r"R:\toolchain\lib",
            "PATH": r"R:\toolchain\bin",
            "TEMP": temp_directory,
            "TMP": temp_directory,
        }


def test_warm_wine_environment_binds_rendered_frontend_paths() -> None:
    class Installation:
        logical_root = r"Z:\Users\builder\MSVC420"

        @staticmethod
        def default_environment(*, temp_directory: str) -> dict[str, str]:
            return {
                "PATH": r"Z:\Users\builder\MSVC420\bin",
                "INCLUDE": (
                    r"Z:\Users\builder\MSVC420\include;"
                    r"Z:\Users\builder\MSVC420\mfc\include"
                ),
                "LIB": (
                    r"Z:\Users\builder\MSVC420\lib;"
                    r"Z:\Users\builder\MSVC420\mfc\lib"
                ),
                "TEMP": temp_directory,
                "TMP": temp_directory,
            }

    environment = classic_incremental._warm_cache_environment(
        cast(ClassicMSVCToolchain, Installation()),
        build_root=r"Z:\build",
        posix_wine=True,
    )

    assert "PATH" not in environment
    assert environment["WINEPATH"] == r"\Users\builder\MSVC420\bin"
    assert environment["INCLUDE"] == (
        r"\Users\builder\MSVC420\include;\Users\builder\MSVC420\mfc\include"
    )
    assert environment["LIB"] == (
        r"\Users\builder\MSVC420\lib;\Users\builder\MSVC420\mfc\lib"
    )
    assert environment["LIBPATH"] == environment["LIB"]
    assert environment["TEMP"] == r"Z:\build\.reprobit-tmp\$LANE"
    assert environment["TMP"] == r"Z:\build\.reprobit-tmp\$LANE"

    native = classic_incremental._warm_cache_environment(
        cast(ClassicMSVCToolchain, Installation()),
        build_root=r"Z:\build",
        posix_wine=False,
    )
    assert native["PATH"] == r"\Users\builder\MSVC420\bin"
    assert native["INCLUDE"].startswith(r"\Users\builder\MSVC420\include")
    assert "WINEPATH" not in native


class _FakeWarmExecutor:
    def __init__(self, sources: dict[str, str]) -> None:
        self.sources = sources
        self.lanes = 0
        self.staging_root: Path | None = None
        self.bound_oracles: tuple[str, ...] = ()
        self.explicit_authority_verifications = 0
        self.donor_dependencies: dict[
            str, tuple[_ClassicWarmDonorDependencyReplay, ...]
        ] = {}

    def bind_warm_staging_root(self, root: Path) -> None:
        self.staging_root = root

    def bind_legacy_oracles(self, values: object) -> None:
        self.bound_oracles = tuple(sorted(cast(dict[str, object], values)))

    def verify_warm_authority(self) -> None:
        self.explicit_authority_verifications += 1

    def execute_warm_graph_node(
        self,
        node_id: str,
        *,
        inputs: object,
        outputs: MappingProxyType[str, Path] | dict[str, Path],
        cancellation: object,
    ) -> tuple[()]:
        del inputs, cancellation
        self.lanes = max(self.lanes, 1)
        for name, output in outputs.items():
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(f"raw:{node_id}:{name}".encode())
        return ()

    def replay_warm_compiler_dependencies(
        self,
        node_id: str,
        *,
        cancellation: object,
    ) -> _ClassicWarmCompilerReplay:
        del cancellation
        return _ClassicWarmCompilerReplay(
            MsvcSbrTrace(
                r"R:\build",
                (MsvcSbrSource(self.sources[node_id], None),),
            ),
            None,
        )

    def execute_warm_compiler_transform(
        self,
        compiler_node_id: str,
        *,
        inputs: object,
        outputs: MappingProxyType[str, Path] | dict[str, Path],
        cancellation: object,
    ) -> _ClassicWarmCompilerTransformResult:
        del inputs, cancellation
        for name, output in outputs.items():
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(f"transformed:{compiler_node_id}:{name}".encode())
        return _ClassicWarmCompilerTransformResult(
            (),
            self.donor_dependencies.get(compiler_node_id, ()),
        )

    def execute_warm_terminal(
        self,
        target_id: str,
        *,
        inputs: PreparedNodeInputs,
        destination: Path,
    ) -> None:
        assert len(inputs.entries) == 1
        input_path = next(iter(inputs.entries.values())).snapshot.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(input_path.read_bytes() + f":terminal:{target_id}".encode())


class _FakePrepared:
    def __init__(self, executor: _FakeWarmExecutor) -> None:
        self.executor = executor
        self.closed = False

    @property
    def initialized_lane_count(self) -> int:
        return self.executor.lanes

    def close(self) -> None:
        self.closed = True


def _compiler(
    target: str,
    ordinal: int,
    *,
    source: str = "shared.cpp",
) -> ProducerNode:
    stem = f"{target}-{ordinal}"
    return ProducerNode(
        id=f"compiler.{target}.{ordinal:04d}",
        role=ProducerRole.COMPILER,
        owner=target,
        arguments=(
            "/Zi",
            f"/Fo${{BUILD}}/{stem}.obj",
            f"/Fd${{BUILD}}/{stem}.pdb",
            "/c",
            f"${{SOURCE}}/{source}",
        ),
        inputs=(f"source/{source}",),
        outputs=(f"build/{stem}.obj", f"build/{stem}.pdb"),
    )


def _linker(target: str, compiler: ProducerNode) -> ProducerNode:
    object_reference = compiler.outputs[0]
    return ProducerNode(
        id=f"linker.{target}.0000",
        role=ProducerRole.LINKER,
        owner=target,
        target_id=target,
        arguments=(
            "${BUILD}/" + object_reference.removeprefix("build/"),
            f"/out:${{BUILD}}/{target}.exe",
        ),
        inputs=(object_reference,),
        outputs=(f"build/{target}.exe",),
        depends_on=(compiler.id,),
    )


def _directive_object(body: bytes) -> bytes:
    def symbol(name: str, *, section: int, symbol_type: int, storage: int) -> bytes:
        return name.encode("ascii").ljust(8, b"\0") + struct.pack(
            "<IhHBB", 0, section, symbol_type, storage, 0
        )

    section_table_end = 60
    symbols = (
        symbol(".drectve", section=1, symbol_type=0, storage=3)
        + struct.pack("<IHHIhBBH", len(body), 0, 0, 0, 0, 2, 0, 0)
        + symbol("_fixture", section=1, symbol_type=32, storage=2)
    )
    symbol_offset = section_table_end + len(body)
    header = struct.pack("<HHIIIHH", 0x14C, 1, 0, symbol_offset, 3, 0, 0)
    section = b".drectve" + struct.pack(
        "<IIIIIIHHI",
        0,
        0,
        len(body),
        section_table_end,
        0,
        0,
        0,
        0,
        0x60501020,
    )
    return header + section + body + symbols + struct.pack("<I", 4)


def test_warm_link_control_audit_binds_and_rejects_hidden_directives() -> None:
    compiler = _compiler("app", 0)
    baseline_linker = _linker("app", compiler)
    suppressed_linker = ProducerNode(
        id=baseline_linker.id,
        role=baseline_linker.role,
        owner=baseline_linker.owner,
        target_id=baseline_linker.target_id,
        arguments=(
            baseline_linker.arguments[0],
            "/NODEFAULTLIB:runtime",
            baseline_linker.arguments[1],
        ),
        inputs=baseline_linker.inputs,
        outputs=baseline_linker.outputs,
        depends_on=baseline_linker.depends_on,
    )
    baseline = classic_incremental._warm_link_control_material(
        baseline_linker,
        (compiler, baseline_linker),
        payload_for_reference=lambda _reference: _directive_object(b"/INCLUDE:_entry "),
    )
    added = classic_incremental._warm_link_control_material(
        suppressed_linker,
        (compiler, suppressed_linker),
        payload_for_reference=lambda _reference: _directive_object(
            b"/INCLUDE:_entry /DEFAULTLIB:runtime "
        ),
    )
    assert added != baseline

    with pytest.raises(
        classic_incremental.ClassicIncrementalError,
        match="lacks committed DEFAULTLIB edges",
    ):
        classic_incremental._warm_link_control_material(
            baseline_linker,
            (compiler, baseline_linker),
            payload_for_reference=lambda _reference: _directive_object(
                b"/DEFAULTLIB:runtime "
            ),
        )
    with pytest.raises(
        classic_incremental.ClassicIncrementalError,
        match="conflicts with DISALLOWLIB",
    ):
        classic_incremental._warm_link_control_material(
            baseline_linker,
            (compiler, baseline_linker),
            payload_for_reference=lambda _reference: _directive_object(
                b"/DEFAULTLIB:runtime /DISALLOWLIB:runtime "
            ),
        )


def _project_recipe(
    recipe_id: str,
    family: ClassicRecipeFamily,
    parameters: dict[str, object],
) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id=recipe_id,
        scope=Scope(target="app"),
        rationale="fixture project-scoped deterministic transform",
        family=family,
        role=ClassicRecipeRole.PROJECT,
        build_target="app",
        parameters=tuple(
            ClassicField(name=name, value=cast(JsonValue, value))
            for name, value in sorted(parameters.items())
        ),
    )


def _project_receipt(
    recipe_id: str,
    family: ClassicRecipeFamily,
    revision: int,
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id=f"proof_{recipe_id}",
        intervention_id=recipe_id,
        family=family,
        expected_values={"review_revision": revision},
    )


def _rdata_receipt(
    recipe_id: str,
    *,
    revision: int = 1,
) -> ClassicProofReceipt:
    return ClassicProofReceipt(
        id=f"proof_{recipe_id}",
        intervention_id=recipe_id,
        family=ClassicRecipeFamily.IMAGE_BINARY_REPACK,
        expected_values={
            "rdata_pool_repack.schema": "rdata_pool_repack_v1",
        },
        status=f"review-{revision}",
    )


def _authority_bundle(
    intervention: ClassicRecipeIntervention,
    receipt: ClassicProofReceipt,
) -> SimpleNamespace:
    return SimpleNamespace(
        interventions=(intervention,),
        proof_documents=(SimpleNamespace(expected_observations=(receipt,)),),
    )


def test_terminal_and_rdata_keys_bind_exact_matching_proof_receipts() -> None:
    terminal = _project_recipe(
        "terminal_recipe",
        ClassicRecipeFamily.IMAGE_METADATA,
        {"metadata_mode": "fixture"},
    )
    terminal_v1 = _authority_bundle(
        terminal,
        _project_receipt(terminal.id, terminal.family, 1),
    )
    terminal_v2 = _authority_bundle(
        terminal,
        _project_receipt(terminal.id, terminal.family, 2),
    )
    first_terminal = classic_terminal_pipeline_authority(
        cast(object, terminal_v1),  # type: ignore[arg-type]
        target_id="app",
    )
    second_terminal = classic_terminal_pipeline_authority(
        cast(object, terminal_v2),  # type: ignore[arg-type]
        target_id="app",
    )
    assert cache_key(
        "producer",
        {"terminal_authority": [item.model_dump(mode="json") for _, item in first_terminal]},
        implementation="test-v1",
    ) != cache_key(
        "producer",
        {"terminal_authority": [item.model_dump(mode="json") for _, item in second_terminal]},
        implementation="test-v1",
    )

    rdata = _project_recipe(
        "rdata_recipe",
        ClassicRecipeFamily.IMAGE_BINARY_REPACK,
        {"rdata_pool_repack": {"object": "app-0.obj"}},
    )
    first_rdata = classic_rdata_repack_authority(
        cast(object, _authority_bundle(rdata, _rdata_receipt(rdata.id, revision=1))),  # type: ignore[arg-type]
        target_id="app",
        object_path="app-0.obj",
    )
    second_rdata = classic_rdata_repack_authority(
        cast(object, _authority_bundle(rdata, _rdata_receipt(rdata.id, revision=2))),  # type: ignore[arg-type]
        target_id="app",
        object_path="app-0.obj",
    )
    assert first_rdata is not None and second_rdata is not None
    assert cache_key(
        "producer",
        {"rdata_authority": first_rdata[1].model_dump(mode="json")},
        implementation="test-v1",
    ) != cache_key(
        "producer",
        {"rdata_authority": second_rdata[1].model_dump(mode="json")},
        implementation="test-v1",
    )


def test_warm_runtime_material_binds_path_independent_proxy_asset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy = tmp_path / "ReproBitPathProxy.sh"
    proxy.write_bytes(b"#!/bin/sh\nexit 0\n")
    monkeypatch.setattr(classic_incremental, "runtime_asset_path", lambda _name: proxy)
    backend = SimpleNamespace(
        identifier="fixture",
        capabilities=BackendCapabilities(
            identifier="fixture",
            host_systems=("fixture",),
            process_tree_primitive="fixture",
            logical_path_primitive="fixture",
            private_wine_prefix=False,
            native_windows=False,
        ),
        wine_pin=None,
        wineserver_pin=None,
    )
    first = classic_incremental._runtime_material(cast(object, backend), None, None)  # type: ignore[arg-type]
    proxy.write_bytes(b"#!/bin/sh\nexit 7\n")
    second = classic_incremental._runtime_material(cast(object, backend), None, None)  # type: ignore[arg-type]

    assert first != second
    rendered = cast(dict[str, object], first)
    programs = cast(list[dict[str, object]], rendered["programs"])
    proxy_material = programs[-1]
    assert proxy_material["role"] == "runtime-path-proxy-template"
    assert "path" not in proxy_material

def _fixture_bundle(
    root: Path,
    *,
    targets: tuple[str, ...] = ("app",),
) -> tuple[SimpleNamespace, tuple[ClassicPreparedUnit, ...], dict[str, str]]:
    source = b"int shared(void) { return 7; }\n"
    (root / "shared.cpp").write_bytes(source)
    compilers = tuple(_compiler(target, index) for index, target in enumerate(targets))
    linkers = tuple(
        _linker(target, compiler) for target, compiler in zip(targets, compilers, strict=True)
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=(*compilers, *linkers),
    )
    paths = LogicalPathProfile(
        id="fixture",
        source=r"R:\source",
        build=r"R:\build",
        toolchain=r"R:\toolchain",
    )
    target_specs = tuple(
        SimpleNamespace(
            id=target,
            artifact=f"artifacts/{target}.exe",
            oracle=f"{target}.oracle",
        )
        for target in targets
    )
    spec = SimpleNamespace(
        build=ProducerGraphBuildAdapter(),
        paths=paths,
        toolchain=SimpleNamespace(profile="fake"),
        targets=target_specs,
        authenticity=SimpleNamespace(model_dump=lambda **_kwargs: {"policy": "clean"}),
    )
    units = tuple(
        ClassicPreparedUnit(
            ClassicTranslationUnitPlan(
                id=f"unit.{target}",
                target_id=target,
                build_target=target,
                source="shared.cpp",
                source_digest=Digest.from_bytes(source),
                mode=f"mode-{target}",
            ),
            (),
            (),
            (),
            (),
            (),
        )
        for target in targets
    )
    documents = tuple(
        SimpleNamespace(
            translation_unit_id=unit.plan.id,
            interventions=(),
            model_dump=lambda unit=unit, **_kwargs: {"unit": unit.plan.id},
        )
        for unit in units
    )
    bundle = SimpleNamespace(
        spec=spec,
        producer_graph=graph,
        build_plan=SimpleNamespace(
            translation_units=tuple(unit.plan for unit in units),
        ),
        toolchain_lock=SimpleNamespace(model_dump=lambda **_kwargs: {"lock": "fake"}),
        intervention_documents=documents,
        proof_documents=(),
        interventions=(),
    )
    sources = {compiler.id: r"R:\source\shared.cpp" for compiler in compilers}
    return bundle, units, sources


def _patch_planner(
    monkeypatch: pytest.MonkeyPatch,
    *,
    bundle: SimpleNamespace,
    units: tuple[ClassicPreparedUnit, ...],
    sources: dict[str, str],
    project_root: Path,
    runtime_calls: list[_FakePrepared],
    source_payloads: dict[str, bytes] | None = None,
    generated_tus: frozenset[str] = frozenset(),
    cleanless_outputs: frozenset[str] = frozenset(),
    deferred_outputs: frozenset[str] = frozenset(),
    warm_executor: _FakeWarmExecutor | None = None,
) -> None:
    payloads = source_payloads or {"shared.cpp": (project_root / "shared.cpp").read_bytes()}
    source_files = tuple(
        SealedIncludeFile(
            "R:\\source\\" + path.replace("/", "\\"),
            Digest.from_bytes(payload),
            len(payload),
            IncludeOrigin.PROJECT_SOURCE,
        )
        for path, payload in sorted(payloads.items())
    )
    generated_authority = SealedIncludeAuthority(
        (r"R:\source", r"R:\toolchain"),
        source_files,
    )
    ordinary_authority = SealedIncludeAuthority(
        (r"R:\source", r"R:\toolchain"),
        tuple(
            item
            for item in source_files
            if item.logical_path.removeprefix("R:\\source\\").replace("\\", "/").casefold()
            not in deferred_outputs
        ),
    )
    monkeypatch.setattr(classic_incremental, "ClassicMSVCToolchain", _FakeInstallation)
    monkeypatch.setattr(
        classic_incremental.ToolchainLock,
        "from_schema_v3",
        lambda _value: object(),
    )
    relatives = {role: f"bin/{role.value}.exe" for role in ProducerRole}
    monkeypatch.setattr(
        classic_incremental,
        "_graph_role_bindings",
        lambda *_args: ({role: role.value for role in ProducerRole}, relatives),
    )
    monkeypatch.setattr(classic_incremental, "_runtime_material", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        classic_incremental,
        "_warm_link_control_material",
        lambda linker, _nodes, **_kwargs: {
            "schema": 1,
            "target_id": linker.target_id,
            "linker_node": linker.id,
            "directives": {},
            "module_definition": None,
        },
    )
    monkeypatch.setattr(classic_incremental, "_overlay_dialect", lambda *_args: object())
    monkeypatch.setattr(classic_incremental, "_graph_system_library_map", lambda *_a, **_k: {})
    monkeypatch.setattr(classic_incremental, "prepare_classic_units", lambda *_a, **_k: units)
    monkeypatch.setattr(
        classic_incremental,
        "_render_sources",
        lambda *_args, **_kwargs: (
            MappingProxyType(
                {
                    path: payload
                    for path, payload in payloads.items()
                    if path.casefold() not in cleanless_outputs
                }
            ),
            MappingProxyType(dict(payloads)),
            MappingProxyType({}),
            generated_tus,
            cleanless_outputs,
        ),
    )
    monkeypatch.setattr(
        classic_incremental,
        "_include_authorities",
        lambda *_a, **_k: (
            ordinary_authority,
            generated_authority,
            MappingProxyType(
                {
                    ("R:\\source\\" + path.replace("/", "\\")).casefold(): (
                        project_root.joinpath(*path.split("/"))
                    )
                    for path in payloads
                }
            ),
            MappingProxyType(
                {
                    "R:\\source\\" + path.replace("/", "\\"): payload
                    for path, payload in payloads.items()
                }
            ),
        ),
    )

    def prepare(*_args: object, **_kwargs: object) -> _FakePrepared:
        prepared = _FakePrepared(warm_executor or _FakeWarmExecutor(sources))
        runtime_calls.append(prepared)
        return prepared

    monkeypatch.setattr(classic_incremental, "prepare_classic_producer_graph_run", prepare)


def _run(
    bundle: SimpleNamespace,
    *,
    root: Path,
    state: Path,
    session: Path,
    jobs: int = 1,
    progress: IncrementalProgress | None = None,
) -> classic_incremental.ClassicIncrementalResult:
    toolchain = root / "toolchain"
    toolchain.mkdir(exist_ok=True)
    return classic_incremental.execute_classic_incremental_build(
        DeveloperAuthority(cast(object, bundle), (), (), MappingProxyType({})),  # type: ignore[arg-type]
        project_root=root,
        session_root=session,
        state_root=state,
        toolchain_root=toolchain,
        backend=cast(object, SimpleNamespace(identifier="fake")),  # type: ignore[arg-type]
        jobs=jobs,
        progress=progress,
    )


def test_all_hit_build_skips_full_prepare_and_clean_project_ignores_oracle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )
    indexed_records: list[str] = []
    original_index_record = CacheLease.index_record

    def count_index_record(
        lease: CacheLease,
        domain: str,
        index: str,
        value: str,
        record: CacheRecord,
    ) -> None:
        indexed_records.append(record.key)
        original_index_record(lease, domain, index, value, record)

    monkeypatch.setattr(CacheLease, "index_record", count_index_record)

    first = _run(bundle, root=root, state=state, session=tmp_path / "run-1")
    assert first.summary.misses == 4
    assert first.summary.runtime_init_count == 1
    assert first.summary.published_targets == 1
    assert first.summary.unchanged_targets == 0
    assert len(runtime_calls) == 1
    assert not (root / "app.oracle").exists()
    assert indexed_records
    index_files = tuple((state / "cache" / "v1" / "indexes").rglob("*.json"))
    index_mtimes = {path: path.stat().st_mtime_ns for path in index_files}
    target_before = (root / "artifacts" / "app.exe").stat()
    indexed_records.clear()

    monkeypatch.setattr(
        classic_incremental,
        "prepare_classic_producer_graph_run",
        lambda *_a, **_k: pytest.fail("all-hit build constructed a prepared run"),
    )
    expected_implementation = classic_incremental.package_implementation_digest()
    implementation_revalidations: list[Digest] = []
    monkeypatch.setattr(
        classic_incremental,
        "revalidate_package_implementation",
        implementation_revalidations.append,
    )
    monkeypatch.setattr(
        incremental_executor,
        "digest_relative_file",
        lambda *_a, **_k: pytest.fail("all-hit executor resealed the workspace"),
    )
    second = _run(bundle, root=root, state=state, session=tmp_path / "run-2")
    assert second.summary.hits == 4
    assert second.summary.misses == 0
    assert second.summary.runtime_init_count == 0
    assert second.summary.published_targets == 0
    assert second.summary.unchanged_targets == 1
    assert len(runtime_calls) == 1
    assert implementation_revalidations == [expected_implementation]
    assert indexed_records == []
    assert {path: path.stat().st_mtime_ns for path in index_files} == index_mtimes
    target_after = (root / "artifacts" / "app.exe").stat()
    assert (target_after.st_dev, target_after.st_ino, target_after.st_mtime_ns) == (
        target_before.st_dev,
        target_before.st_ino,
        target_before.st_mtime_ns,
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX terminal mode publication")
def test_all_hit_publication_restores_staged_executable_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExecutableTerminalExecutor(_FakeWarmExecutor):
        def execute_warm_terminal(
            self,
            target_id: str,
            *,
            inputs: PreparedNodeInputs,
            destination: Path,
        ) -> None:
            super().execute_warm_terminal(
                target_id,
                inputs=inputs,
                destination=destination,
            )
            destination.chmod(0o755)

    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    runtime_calls: list[_FakePrepared] = []
    executor = ExecutableTerminalExecutor(sources)
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
        warm_executor=executor,
    )

    first = _run(bundle, root=root, state=state, session=tmp_path / "run-1")
    target = root / "artifacts" / "app.exe"
    assert first.summary.published_targets == 1
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    target.chmod(0o644)
    altered_inode = target.stat().st_ino

    second = _run(bundle, root=root, state=state, session=tmp_path / "run-2")

    assert second.summary.hits == 4
    assert second.summary.published_targets == 1
    assert second.summary.unchanged_targets == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o755
    assert target.stat().st_ino != altered_inode


def test_progress_reserves_publication_and_summary_covers_the_whole_build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )
    clock = iter((100.0, 104.25))
    monkeypatch.setattr(classic_incremental, "monotonic", lambda: next(clock))
    events: list[tuple[ProgressKind, int, int, str, str, str | None]] = []

    result = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "run",
        progress=lambda *event: events.append(event),
    )

    assert result.summary.elapsed_seconds == pytest.approx(4.25)
    assert events[-1] == (
        ProgressKind.UNIT_FINISHED,
        6,
        6,
        "publication",
        "target-set",
        None,
    )
    assert {event[2] for event in events} == {6}
    assert all(event[1] < event[2] for event in events[:-1])


def test_target_publication_uses_terminal_record_not_mutable_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )
    original_execute = classic_incremental.IncrementalDAGExecutor.execute
    expected: list[bytes] = []

    def execute_then_mutate(
        executor: object,
        nodes: tuple[object, ...],
    ) -> object:
        result = original_execute(executor, nodes)  # type: ignore[arg-type]
        terminal = next(
            node for node in nodes if cast(object, node).id == "terminal.app"
        )
        artifact = cast(object, terminal).outputs["artifact"]
        expected.append(artifact.read_bytes())
        artifact.write_bytes(b"peer-mutated-terminal-workspace")
        return result

    monkeypatch.setattr(
        classic_incremental.IncrementalDAGExecutor,
        "execute",
        execute_then_mutate,
    )
    _run(bundle, root=root, state=state, session=tmp_path / "run")

    assert expected
    assert (root / "artifacts" / "app.exe").read_bytes() == expected[0]


def test_shared_source_targets_keep_distinct_units_and_compiler_base_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root, targets=("app", "tool"))
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )
    observed_material: list[dict[str, object]] = []
    compiler_probes: list[tuple[str, dict[str, object]]] = []
    original_key = classic_incremental.producer_cache_key
    original_probe = classic_incremental.probe_compiler_cache

    def capture(material: dict[str, object]) -> str:
        observed_material.append(material)
        return original_key(cast(dict[str, object], material))  # type: ignore[arg-type]

    def capture_probe(*args: object, **kwargs: object) -> object:
        compiler_probes.append(
            (
                cast(str, kwargs["base_key"]),
                cast(dict[str, object], kwargs["base_material"]),
            )
        )
        return original_probe(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(classic_incremental, "producer_cache_key", capture)
    monkeypatch.setattr(classic_incremental, "probe_compiler_cache", capture_probe)
    result = _run(bundle, root=root, state=state, session=tmp_path / "run")
    transforms = [item for item in observed_material if item.get("role") == "compiler-transform"]
    assert len({key for key, _material in compiler_probes}) == 2
    assert {
        cast(dict[str, object], material["node"])["id"] for _key, material in compiler_probes
    } == {"compiler.app.0000", "compiler.tool.0001"}
    assert {
        cast(dict[str, object], cast(dict[str, object], item["node"])["translation_unit"])["id"]
        for item in transforms
    } == {"unit.app", "unit.tool"}
    assert result.summary.runtime_init_count == 1


@pytest.mark.parametrize("reverse", (False, True))
def test_multiple_target_scoped_rdata_repacks_for_one_object_fail_before_cache(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reverse: bool,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root, targets=("app", "tool"))
    compiler = next(
        node
        for node in bundle.producer_graph.nodes
        if node.role is ProducerRole.COMPILER and node.owner == "app"
    )
    linkers = tuple(
        node for node in bundle.producer_graph.nodes if node.role is ProducerRole.LINKER
    )
    shared_linkers = tuple(
        linker.model_copy(
            update={
                "depends_on": (compiler.id,),
                "inputs": compiler.outputs,
            }
        )
        for linker in linkers
    )
    bundle.producer_graph = bundle.producer_graph.model_copy(
        update={"nodes": (compiler, *shared_linkers)}
    )
    bundle.build_plan = SimpleNamespace(
        translation_units=(next(unit.plan for unit in units if unit.plan.build_target == "app"),)
    )
    object_value = compiler.outputs[0].removeprefix("build/")
    app = _project_recipe(
        "rdata_app",
        ClassicRecipeFamily.IMAGE_BINARY_REPACK,
        {"rdata_pool_repack": {"object": object_value}},
    )
    tool = _project_recipe(
        "rdata_tool",
        ClassicRecipeFamily.IMAGE_BINARY_REPACK,
        {"rdata_pool_repack": {"object": object_value}},
    ).model_copy(update={"scope": Scope(target="tool"), "build_target": "tool"})
    interventions = (tool, app) if reverse else (app, tool)
    bundle.interventions = interventions
    bundle.proof_documents = (
        SimpleNamespace(
            expected_observations=tuple(
                _rdata_receipt(item.id) for item in interventions
            )
        ),
    )
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )

    with pytest.raises(
        classic_incremental.ClassicIncrementalError,
        match="multiple rdata repacks name",
    ):
        _run(bundle, root=root, state=state, session=tmp_path / "run")

    assert runtime_calls == []
    assert not (state / "cache").exists()


@pytest.mark.parametrize(
    ("receipt_introduces_selector", "planned_lane", "message"),
    (
        (True, True, "cannot introduce or remove the rdata repack selector"),
        (False, False, "has no prepared translation-unit compiler lane"),
    ),
    ids=("receipt-introduced-selector", "consumed-object-without-tu-lane"),
)
def test_rdata_authority_rejects_before_warm_setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    receipt_introduces_selector: bool,
    planned_lane: bool,
    message: str,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, _sources = _fixture_bundle(root)
    compiler = next(
        node for node in bundle.producer_graph.nodes if node.role is ProducerRole.COMPILER
    )
    object_path = compiler.outputs[0].removeprefix("build/")
    declaration = {
        "schema": "rdata_pool_repack_v1",
        "object": object_path,
    }
    intervention = _project_recipe(
        "rdata_preflight",
        ClassicRecipeFamily.IMAGE_BINARY_REPACK,
        {} if receipt_introduces_selector else {"rdata_pool_repack": declaration},
    )
    receipt = ClassicProofReceipt(
        id="proof_rdata_preflight",
        intervention_id=intervention.id,
        family=intervention.family,
        expected_values={"rdata_pool_repack": declaration}
        if receipt_introduces_selector
        else {},
    )
    bundle.interventions = (intervention,)
    bundle.proof_documents = (
        SimpleNamespace(expected_observations=(receipt,)),
    )
    bundle.build_plan = SimpleNamespace(
        translation_units=tuple(unit.plan for unit in units) if planned_lane else (),
    )
    monkeypatch.setattr(
        classic_incremental,
        "ClassicMSVCToolchain",
        lambda *_args, **_kwargs: pytest.fail("warm preflight constructed a toolchain"),
    )
    monkeypatch.setattr(
        classic_incremental,
        "prepare_classic_producer_graph_run",
        lambda *_args, **_kwargs: pytest.fail("warm preflight prepared a runtime"),
    )
    session = tmp_path / "run"

    with pytest.raises(classic_incremental.ClassicIncrementalError, match=message):
        _run(bundle, root=root, state=state, session=session)

    assert not session.exists()
    assert not (state / "cache").exists()


def test_donor_source_mirror_header_edit_invalidates_only_its_transform_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    compiler = next(
        node for node in bundle.producer_graph.nodes if node.role is ProducerRole.COMPILER
    )
    compiler = compiler.model_copy(
        update={
            "arguments": (
                "/Zi",
                "-DREPROBIT_DONOR",
                "-I${SOURCE}",
                *compiler.arguments[1:],
            )
        }
    )
    bundle.producer_graph = bundle.producer_graph.model_copy(
        update={
            "nodes": tuple(
                compiler if node.role is ProducerRole.COMPILER else node
                for node in bundle.producer_graph.nodes
            )
        }
    )
    intervention = _project_recipe(
        "donor_recipe",
        ClassicRecipeFamily.DONOR_SOURCE_OVERLAY,
        {"donor": True},
    )
    receipt = DonorCompileReceipt(
        intervention.id,
        intervention.family,
        Digest.from_bytes(b"constraints"),
        MappingProxyType({}),
        MappingProxyType({}),
        Digest.from_bytes(b"additions"),
        Digest.from_bytes(b"rendering"),
    )
    request = DonorCompileRequest(
        intervention_id=intervention.id,
        legacy_recipe_id="d_000000000000",
        family=intervention.family,
        build_target="app",
        logical_source="shared.cpp",
        staged_source="s.cpp",
        files=MappingProxyType({"s.cpp": b"rendered donor source\n"}),
        logical_outputs=MappingProxyType({}),
        compiler_additions=DonorCompilerAdditions(
            "REPROBIT_DONOR",
            include_directories=("inc", "inc/source"),
            include_projection=DonorIncludeProjection.SOURCE_ROOT_MIRROR,
        ),
        carrier_identifiers=frozenset(),
        receipt=receipt,
    )
    donor_units = (
        replace(
            units[0],
            donors=(ClassicPreparedDonor(intervention, request),),
        ),
    )
    header = root / "donor-only.h"
    header.write_bytes(b"#define DONOR_VALUE 1\n")
    unrelated = root / "unrelated.h"
    unrelated.write_bytes(b"#define UNRELATED_VALUE 1\n")
    runtime_calls: list[_FakePrepared] = []

    def patch(header_payload: bytes, unrelated_payload: bytes) -> None:
        arena = r"R:\donors\composed-app-shared.cpp-d_000000000000"
        mirror_header = arena + r"\inc\source\donor-only.h"
        executor = _FakeWarmExecutor(sources)
        trace = MsvcSbrTrace(
            arena,
            (
                MsvcSbrSource("s.cpp", None),
                MsvcSbrSource(mirror_header, 0),
            ),
        )
        executor.donor_dependencies[compiler.id] = (
            _ClassicWarmDonorDependencyReplay(
                intervention.id,
                trace,
                (
                    ResolvedInclude(
                        "s.cpp",
                        arena + r"\s.cpp",
                        Digest.from_bytes(b"rendered donor source\n"),
                        len(b"rendered donor source\n"),
                        IncludeOrigin.DONOR_ARENA,
                        None,
                    ),
                    ResolvedInclude(
                        mirror_header,
                        mirror_header,
                        Digest.from_bytes(header_payload),
                        len(header_payload),
                        IncludeOrigin.DONOR_ARENA,
                        0,
                    ),
                ),
                None,
            ),
        )
        _patch_planner(
            monkeypatch,
            bundle=bundle,
            units=donor_units,
            sources=sources,
            project_root=root,
            runtime_calls=runtime_calls,
            source_payloads={
                "shared.cpp": (root / "shared.cpp").read_bytes(),
                "donor-only.h": header_payload,
                "unrelated.h": unrelated_payload,
            },
            warm_executor=executor,
        )

    patch(header.read_bytes(), unrelated.read_bytes())
    first = _run(bundle, root=root, state=state, session=tmp_path / "run-1")
    assert first.summary.misses == 4

    patch(header.read_bytes(), unrelated.read_bytes())
    unchanged = _run(bundle, root=root, state=state, session=tmp_path / "run-2")
    assert unchanged.summary.hits == 4
    assert unchanged.summary.misses == 0

    unrelated.write_bytes(b"#define UNRELATED_VALUE 2\n")
    patch(header.read_bytes(), unrelated.read_bytes())
    unrelated_changed = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "run-unrelated",
    )
    assert unrelated_changed.summary.hits == 4
    assert unrelated_changed.summary.misses == 0

    header.write_bytes(b"#define DONOR_VALUE 2\n")
    patch(header.read_bytes(), unrelated.read_bytes())
    changed = _run(bundle, root=root, state=state, session=tmp_path / "run-3")
    assert changed.summary.hits == 1
    assert changed.summary.misses == 3


def test_intervention_free_compiler_stays_raw_and_reaches_its_linker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, all_units, sources = _fixture_bundle(root, targets=("app", "tool"))
    bundle.build_plan = SimpleNamespace(translation_units=(all_units[0].plan,))

    class MixedExecutor(_FakeWarmExecutor):
        def __init__(self) -> None:
            super().__init__(sources)
            self.link_inputs: dict[str, tuple[bytes, ...]] = {}

        def execute_warm_graph_node(self, node_id: str, **kwargs: object) -> tuple[()]:
            if node_id.startswith("linker."):
                inputs = cast(PreparedNodeInputs, kwargs["inputs"])
                self.link_inputs[node_id] = tuple(
                    item.snapshot.path.read_bytes()
                    for _reference, item in sorted(
                        inputs.entries.items(), key=lambda item: item[0]
                    )
                )
            return super().execute_warm_graph_node(node_id, **kwargs)  # type: ignore[arg-type]

    executor = MixedExecutor()
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        # Only app has a reviewed composition plan.  The tool compiler is a
        # normal graph producer and must not acquire a synthetic transform.
        units=(all_units[0],),
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
        warm_executor=executor,
    )

    result = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "run",
        jobs=2,
    )

    assert result.summary.misses == 7
    assert executor.link_inputs["linker.app.0000"][0].startswith(
        b"transformed:compiler.app.0000"
    )
    assert executor.link_inputs["linker.tool.0000"][0].startswith(
        b"raw:compiler.tool.0001"
    )
    assert not (tmp_path / "run/transforms/compiler.tool.0001").exists()


def test_independent_misses_do_not_reverify_global_authority_per_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root, targets=("app", "tool"))
    executor = _FakeWarmExecutor(sources)
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
        warm_executor=executor,
    )

    result = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "run",
        jobs=2,
    )

    assert result.summary.misses >= 2
    # Global namespace verification is owned by the one prepared-run close,
    # after all blobs are staged and before record names are published.  The
    # node pre-store hooks must not redigest that authority once per miss.
    assert executor.explicit_authority_verifications == 0
    assert len(runtime_calls) == 1
    assert runtime_calls[0].closed is True


@pytest.mark.parametrize("peer_replaces_first", (False, True))
def test_target_set_publication_rolls_back_without_overwriting_peer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    peer_replaces_first: bool,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    artifacts = root / "artifacts"
    artifacts.mkdir()
    (artifacts / "app.exe").write_bytes(b"original-app")
    (artifacts / "tool.exe").write_bytes(b"original-tool")
    (artifacts / "app.exe").chmod(0o751)
    (artifacts / "tool.exe").chmod(0o750)
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root, targets=("app", "tool"))
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )
    original_publish = classic_incremental.atomic_publish_relative_if_current

    def fail_second(
        project: Path,
        relative: str,
        payload: bytes,
        *,
        expected: object,
        **publication_options: object,
    ) -> object:
        if relative == "artifacts/tool.exe":
            if peer_replaces_first:
                atomic_publish_relative(project, "artifacts/app.exe", b"peer-app")
            raise SecurePathError("injected target-2 failure")
        return original_publish(  # type: ignore[arg-type]
            project,
            relative,
            payload,
            expected=expected,
            **publication_options,  # type: ignore[arg-type]
        )

    monkeypatch.setattr(
        classic_incremental,
        "atomic_publish_relative_if_current",
        fail_second,
    )
    with pytest.raises(
        classic_incremental.ClassicIncrementalError,
        match="target set could not be published",
    ):
        _run(bundle, root=root, state=state, session=tmp_path / "run", jobs=2)

    assert (artifacts / "app.exe").read_bytes() == (
        b"peer-app" if peer_replaces_first else b"original-app"
    )
    assert (artifacts / "tool.exe").read_bytes() == b"original-tool"
    if os.name != "nt" and not peer_replaces_first:
        assert (artifacts / "app.exe").stat().st_mode & 0o777 == 0o751
    if os.name != "nt":
        assert (artifacts / "tool.exe").stat().st_mode & 0o777 == 0o750


@pytest.mark.parametrize("race_after_last_publish", (False, True))
def test_target_set_publication_rejects_preimage_and_final_reseal_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    race_after_last_publish: bool,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    artifacts = root / "artifacts"
    artifacts.mkdir()
    (artifacts / "app.exe").write_bytes(b"original-app")
    (artifacts / "tool.exe").write_bytes(b"original-tool")
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root, targets=("app", "tool"))
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )
    original_publish = classic_incremental.atomic_publish_relative_if_current
    raced = False

    def race_publication(
        project: Path,
        relative: str,
        payload: bytes,
        *,
        expected: object,
        **publication_options: object,
    ) -> object:
        nonlocal raced
        if not race_after_last_publish and relative == "artifacts/app.exe" and not raced:
            atomic_publish_relative(project, relative, b"peer-app")
            raced = True
        published = original_publish(
            project,
            relative,
            payload,
            expected=expected,  # type: ignore[arg-type]
            **publication_options,  # type: ignore[arg-type]
        )
        if race_after_last_publish and relative == "artifacts/tool.exe" and not raced:
            atomic_publish_relative(project, "artifacts/app.exe", b"peer-app")
            raced = True
        return published

    monkeypatch.setattr(
        classic_incremental,
        "atomic_publish_relative_if_current",
        race_publication,
    )
    with pytest.raises(
        classic_incremental.ClassicIncrementalError,
        match="target set could not be published",
    ):
        _run(bundle, root=root, state=state, session=tmp_path / "run", jobs=2)

    assert raced
    assert (artifacts / "app.exe").read_bytes() == b"peer-app"
    assert (artifacts / "tool.exe").read_bytes() == b"original-tool"


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS fixed root aliases")
def test_warm_secure_location_canonicalizes_macos_var_alias(tmp_path: Path) -> None:
    source = tmp_path / "input.txt"
    source.write_bytes(b"input")
    assert str(source).startswith("/private/var/")
    alias = Path(str(source).removeprefix("/private"))

    payload, snapshot = classic_incremental._payload(alias)

    assert payload == b"input"
    assert snapshot.path == source


def test_cleanless_header_is_ordinary_but_carrier_is_deferred(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    toolchain = tmp_path / "toolchain"
    project.mkdir()
    toolchain.mkdir()
    paths = LogicalPathProfile(
        id="fixture",
        source=r"R:\source",
        build=r"R:\build",
        toolchain=r"R:\toolchain",
    )
    bundle = SimpleNamespace(
        spec=SimpleNamespace(paths=paths),
        toolchain_lock=SimpleNamespace(tools=(), runtime_files=()),
    )
    monkeypatch.setattr(classic_incremental, "_toolchain_tree_files", lambda *_args: set())
    ordinary, generated, _physical, _payloads = classic_incremental._include_authorities(
        cast(object, bundle),  # type: ignore[arg-type]
        project_root=project,
        toolchain_root=toolchain,
        effective_sources={
            "ordinary.cpp": b"int ordinary(void) { return 0; }\n",
            "generated.h": b"#define GENERATED_VALUE 7\n",
            "carrier.cpp": b"int carrier(void) { return GENERATED_VALUE; }\n",
        },
        deferred_outputs=frozenset({"carrier.cpp"}),
    )

    ordinary_paths = {item.logical_path.casefold() for item in ordinary.files}
    generated_paths = {item.logical_path.casefold() for item in generated.files}
    assert r"r:\source\generated.h" in ordinary_paths
    assert r"r:\source\generated.h" in generated_paths
    assert r"r:\source\carrier.cpp" not in ordinary_paths
    assert r"r:\source\carrier.cpp" in generated_paths


def test_legacy_oracle_invalidates_only_owning_transform_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, base_units, sources = _fixture_bundle(root, targets=("app", "tool"))
    legacy = SimpleNamespace(oracle_target="app")
    action = SimpleNamespace(
        model_dump=lambda **_kwargs: {
            "kind": "legacy-oracle-install",
            "oracle_target": "app",
        }
    )
    units = (
        replace(base_units[0], legacy_actions=(legacy,), actions=(action,)),  # type: ignore[arg-type]
        base_units[1],
    )
    (root / "app.oracle").write_bytes(b"oracle-v1")
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )
    oracle_bindings: list[tuple[str, ...]] = []

    def bind(runtime: classic_incremental._WarmRuntime) -> None:
        oracle_bindings.append(tuple(sorted(runtime.oracle_paths)))

    monkeypatch.setattr(classic_incremental._WarmRuntime, "ensure_oracles", bind)
    first = _run(bundle, root=root, state=state, session=tmp_path / "legacy-1")
    assert first.summary.misses == 8
    assert oracle_bindings == [("app",)]
    assert not (root / "tool.oracle").exists()

    second = _run(bundle, root=root, state=state, session=tmp_path / "legacy-2")
    assert second.summary.hits == 8
    assert oracle_bindings == [("app",)]

    (root / "app.oracle").write_bytes(b"oracle-v2")
    third = _run(bundle, root=root, state=state, session=tmp_path / "legacy-3")
    assert third.summary.misses == 3
    assert third.summary.hits == 5
    assert third.summary.runtime_init_count == 1
    assert oracle_bindings == [("app",), ("app",)]


def test_generated_epoch_waits_for_all_ordinary_transforms_and_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    payloads = {
        "ordinary.cpp": b'#include "generated.h"\nint ordinary(void) { return VALUE; }\n',
        "app.rc": b"#define APP_RESOURCE 1\n",
        "carrier.cpp": b'#include "generated.h"\nint carrier(void) { return VALUE; }\n',
        "generated.h": b"#define VALUE 7\n",
    }
    for path, payload in payloads.items():
        (root / path).write_bytes(payload)
    ordinary = _compiler("app", 0, source="ordinary.cpp")
    generated = _compiler("app", 1, source="carrier.cpp")
    resource = ProducerNode(
        id="resource.app.0000",
        role=ProducerRole.RESOURCE,
        owner="app",
        arguments=("/fo", "${BUILD}/app.res", "${SOURCE}/app.rc"),
        inputs=("source/app.rc",),
        outputs=("build/app.res",),
    )
    linker = ProducerNode(
        id="linker.app.0000",
        role=ProducerRole.LINKER,
        owner="app",
        target_id="app",
        arguments=(
            "${BUILD}/app-0.obj",
            "${BUILD}/app-1.obj",
            "${BUILD}/app.res",
            "/out:${BUILD}/app.exe",
        ),
        inputs=(ordinary.outputs[0], generated.outputs[0], resource.outputs[0]),
        outputs=("build/app.exe",),
        depends_on=(ordinary.id, generated.id, resource.id),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=Digest.from_bytes(b"barrier-topology"),
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-unix-makefiles-v1",
        nodes=tuple(
            sorted((ordinary, resource, generated, linker), key=lambda item: item.id)
        ),
    )
    paths = LogicalPathProfile(
        id="fixture",
        source=r"R:\source",
        build=r"R:\build",
        toolchain=r"R:\toolchain",
    )
    units = tuple(
        ClassicPreparedUnit(
            ClassicTranslationUnitPlan(
                id=f"unit.{source}",
                target_id="app",
                build_target="app",
                source=source,
                source_digest=Digest.from_bytes(payloads[source]),
                mode="fixture",
            ),
            (),
            (),
            (),
            (),
            (),
        )
        for source in ("ordinary.cpp", "carrier.cpp")
    )
    documents = tuple(
        SimpleNamespace(
            translation_unit_id=unit.plan.id,
            interventions=(),
            model_dump=lambda unit=unit, **_kwargs: {"unit": unit.plan.id},
        )
        for unit in units
    )
    bundle = SimpleNamespace(
        spec=SimpleNamespace(
            build=ProducerGraphBuildAdapter(),
            paths=paths,
            toolchain=SimpleNamespace(profile="fake"),
            targets=(SimpleNamespace(id="app", artifact="artifacts/app.exe", oracle="app.oracle"),),
            authenticity=SimpleNamespace(model_dump=lambda **_kwargs: {"policy": "clean"}),
        ),
        producer_graph=graph,
        build_plan=SimpleNamespace(
            translation_units=tuple(unit.plan for unit in units),
        ),
        toolchain_lock=SimpleNamespace(model_dump=lambda **_kwargs: {"lock": "fake"}),
        intervention_documents=documents,
        proof_documents=(),
        interventions=(),
    )

    class BarrierExecutor(_FakeWarmExecutor):
        def __init__(self) -> None:
            super().__init__(
                {
                    ordinary.id: r"R:\source\ordinary.cpp",
                    generated.id: r"R:\source\carrier.cpp",
                }
            )
            self.completed: set[str] = set()

        def execute_warm_graph_node(self, node_id: str, **kwargs: object) -> tuple[()]:
            if node_id == generated.id:
                assert f"transform:{ordinary.id}" in self.completed
                assert resource.id in self.completed
            result = super().execute_warm_graph_node(node_id, **kwargs)  # type: ignore[arg-type]
            self.completed.add(node_id)
            return result

        def execute_warm_compiler_transform(
            self, compiler_node_id: str, **kwargs: object
        ) -> tuple[()]:
            result = super().execute_warm_compiler_transform(
                compiler_node_id,
                **kwargs,  # type: ignore[arg-type]
            )
            self.completed.add(f"transform:{compiler_node_id}")
            return result

        def replay_warm_compiler_dependencies(
            self,
            node_id: str,
            *,
            cancellation: object,
        ) -> _ClassicWarmCompilerReplay:
            if node_id != ordinary.id:
                return super().replay_warm_compiler_dependencies(
                    node_id,
                    cancellation=cancellation,
                )
            return _ClassicWarmCompilerReplay(
                MsvcSbrTrace(
                    r"R:\build",
                    (
                        MsvcSbrSource(r"R:\source\ordinary.cpp", None),
                        MsvcSbrSource("generated.h", 0),
                    ),
                ),
                None,
            )

    barrier_executor = BarrierExecutor()
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=barrier_executor.sources,
        project_root=root,
        runtime_calls=runtime_calls,
        source_payloads=payloads,
        generated_tus=frozenset({"carrier.cpp"}),
        cleanless_outputs=frozenset({"carrier.cpp", "generated.h"}),
        deferred_outputs=frozenset({"carrier.cpp"}),
        warm_executor=barrier_executor,
    )

    result = _run(
        bundle,
        root=root,
        state=tmp_path / "state",
        session=tmp_path / "barrier-run",
        jobs=3,
    )
    assert result.summary.misses == 7
    assert f"transform:{ordinary.id}" in barrier_executor.completed
    assert f"transform:{generated.id}" in barrier_executor.completed
    assert resource.id in barrier_executor.completed

    monkeypatch.setattr(
        classic_incremental,
        "prepare_classic_producer_graph_run",
        lambda *_a, **_k: pytest.fail("all-hit epoch build constructed a prepared run"),
    )
    second = _run(
        bundle,
        root=root,
        state=tmp_path / "state",
        session=tmp_path / "barrier-run-2",
        jobs=3,
    )
    assert second.summary.hits == 7
    assert second.summary.misses == 0
    assert second.summary.runtime_init_count == 0
