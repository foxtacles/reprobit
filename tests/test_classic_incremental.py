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

import reprobit.classic_incremental_context as incremental_context
import reprobit.classic_incremental_execution as incremental_execution
import reprobit.classic_incremental_keys as incremental_keys
import reprobit.classic_incremental_nodes as incremental_nodes
import reprobit.classic_incremental_planning as incremental_planning
import reprobit.classic_publication as classic_publication
import reprobit.classic_runtime_graph as classic_runtime_graph
import reprobit.incremental as incremental
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
from reprobit.classic_runtime_donor import ClassicWarmDonorDependencyReplay
from reprobit.classic_runtime_producer import ClassicProducerExecution
from reprobit.classic_runtime_warm import (
    ClassicWarmCompilerReplay,
    ClassicWarmCompilerTransformResult,
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
from reprobit.secure_path_contracts import SecurePathError
from reprobit.secure_paths import atomic_publish_relative
from reprobit.strict_json import JsonValue, canonical_json
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


@pytest.mark.parametrize(
    ("created_lane_count", "expected_runtime_count"),
    ((0, 0), (1, 1), (4, 1)),
)
def test_shared_backend_runtime_count_is_independent_of_scheduling_lanes(
    created_lane_count: int,
    expected_runtime_count: int,
) -> None:
    producer = object.__new__(ClassicProducerExecution)
    producer.__dict__["_lane_pool"] = SimpleNamespace(created_count=created_lane_count)

    assert producer.initialized_runtime_count == expected_runtime_count


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

    environment = incremental_planning._warm_cache_environment(
        cast(ClassicMSVCToolchain, Installation()),
        build_root=r"Z:\build",
        posix_wine=True,
    )

    assert "PATH" not in environment
    assert environment["WINEPATH"] == r"\Users\builder\MSVC420\bin"
    assert environment["INCLUDE"] == (
        r"\Users\builder\MSVC420\include;\Users\builder\MSVC420\mfc\include"
    )
    assert environment["LIB"] == (r"\Users\builder\MSVC420\lib;\Users\builder\MSVC420\mfc\lib")
    assert environment["LIBPATH"] == environment["LIB"]
    assert environment["TEMP"] == r"Z:\Users\reprobit\AppData\Local\Temp"
    assert environment["TMP"] == environment["TEMP"]

    native = incremental_planning._warm_cache_environment(
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
        self.runtime_started = False
        self.staging_root: Path | None = None
        self.bound_oracles: tuple[str, ...] = ()
        self.explicit_authority_verifications = 0
        self.analysis_link_calls: list[str] = []
        self.analysis_link_inputs: list[tuple[str, ...]] = []
        self.donor_dependencies: dict[str, tuple[ClassicWarmDonorDependencyReplay, ...]] = {}

    def bind_warm_staging_root(self, root: Path) -> None:
        self.staging_root = root

    @property
    def initialized_runtime_count(self) -> int:
        return int(self.runtime_started)

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
        self.runtime_started = True
        for name, output in outputs.items():
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(f"raw:{node_id}:{name}".encode())
        return ()

    def replay_warm_compiler_dependencies(
        self,
        node_id: str,
        *,
        cancellation: object,
    ) -> ClassicWarmCompilerReplay:
        del cancellation
        return ClassicWarmCompilerReplay(
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
    ) -> ClassicWarmCompilerTransformResult:
        del inputs, cancellation
        for name, output in outputs.items():
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(f"transformed:{compiler_node_id}:{name}".encode())
        return ClassicWarmCompilerTransformResult(
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

    def execute_warm_analysis_link(
        self,
        target_id: str,
        *,
        inputs: PreparedNodeInputs,
        outputs: MappingProxyType[str, Path] | dict[str, Path],
        certified_image: Path,
        cancellation: object,
    ) -> None:
        del cancellation
        assert certified_image.is_file()
        self.analysis_link_calls.append(target_id)
        self.analysis_link_inputs.append(tuple(sorted(inputs.entries, key=str.casefold)))
        generation = len(self.analysis_link_calls)
        input_payload = b"|".join(
            item.snapshot.path.read_bytes() for _name, item in sorted(inputs.entries.items())
        )
        assert set(outputs) == {"image", "pdb"}
        for output in outputs.values():
            output.parent.mkdir(parents=True, exist_ok=True)
        outputs["image"].write_bytes(
            b"analysis-image:" + str(generation).encode() + b":" + input_payload
        )
        outputs["pdb"].write_bytes(
            b"analysis-pdb:" + str(generation).encode() + b":" + input_payload
        )


class _FakePrepared:
    def __init__(self, runtime: _FakeWarmExecutor) -> None:
        self.warm = runtime
        self.donors = runtime
        self.producer = runtime
        self.closed = False

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


def test_analysis_debug_inputs_follow_only_object_and_archive_provenance() -> None:
    direct = _compiler("app", 0)
    archived = _compiler("static", 1)
    unrelated = _compiler("other", 2)
    imported = _compiler("upstream", 3)
    librarian = ProducerNode(
        id="librarian.static.0000",
        role=ProducerRole.LIBRARIAN,
        owner="static",
        arguments=("/out:${BUILD}/static.lib", "${BUILD}/static-1.obj"),
        inputs=("build/static-1.obj",),
        outputs=("build/static.lib",),
        depends_on=(archived.id,),
    )
    upstream = ProducerNode(
        id="linker.upstream.0000",
        role=ProducerRole.LINKER,
        owner="upstream",
        target_id="upstream",
        arguments=(
            "${BUILD}/upstream-3.obj",
            "/dll",
            "/implib:${BUILD}/upstream.lib",
            "/out:${BUILD}/upstream.dll",
        ),
        inputs=("build/upstream-3.obj",),
        outputs=("build/upstream.dll", "build/upstream.lib"),
        depends_on=(imported.id,),
    )
    linker = ProducerNode(
        id="linker.app.0000",
        role=ProducerRole.LINKER,
        owner="app",
        target_id="app",
        arguments=(
            "${BUILD}/app-0.obj",
            "${BUILD}/static.lib",
            "${BUILD}/upstream.lib",
            "/out:${BUILD}/app.exe",
        ),
        inputs=(
            "build/app-0.obj",
            "build/static.lib",
            "build/upstream.lib",
        ),
        outputs=("build/app.exe",),
        depends_on=tuple(
            sorted(
                (direct.id, librarian.id, unrelated.id, upstream.id),
                key=str.casefold,
            )
        ),
    )
    graph = ProducerGraphDocument(
        schema_version=3,
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-makefiles-v1",
        nodes=tuple(
            sorted(
                (direct, archived, unrelated, imported, librarian, upstream, linker),
                key=lambda node: node.id.casefold(),
            )
        ),
    )

    assert classic_runtime_graph.classic_analysis_compiler_pdb_refs(graph, linker) == (
        "build/app-0.pdb",
        "build/static-1.pdb",
    )


def _directive_object(body: bytes) -> bytes:
    def symbol(
        name: str,
        *,
        section: int,
        symbol_type: int,
        storage: int,
        auxiliary_count: int = 0,
    ) -> bytes:
        return name.encode("ascii").ljust(8, b"\0") + struct.pack(
            "<IhHBB", 0, section, symbol_type, storage, auxiliary_count
        )

    section_table_end = 60
    symbols = (
        symbol(".drectve", section=1, symbol_type=0, storage=3, auxiliary_count=1)
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
    baseline = incremental_keys._warm_link_control_material(
        baseline_linker,
        (compiler, baseline_linker),
        payload_for_reference=lambda _reference: _directive_object(b"/INCLUDE:_entry "),
    )
    added = incremental_keys._warm_link_control_material(
        suppressed_linker,
        (compiler, suppressed_linker),
        payload_for_reference=lambda _reference: _directive_object(
            b"/INCLUDE:_entry /DEFAULTLIB:runtime "
        ),
    )
    assert added != baseline

    with pytest.raises(
        incremental_context.ClassicIncrementalError,
        match="lacks committed DEFAULTLIB edges",
    ):
        incremental_keys._warm_link_control_material(
            baseline_linker,
            (compiler, baseline_linker),
            payload_for_reference=lambda _reference: _directive_object(b"/DEFAULTLIB:runtime "),
        )
    with pytest.raises(
        incremental_context.ClassicIncrementalError,
        match="conflicts with DISALLOWLIB",
    ):
        incremental_keys._warm_link_control_material(
            baseline_linker,
            (compiler, baseline_linker),
            payload_for_reference=lambda _reference: _directive_object(
                b"/DEFAULTLIB:runtime /DISALLOWLIB:runtime "
            ),
        )


def test_warm_link_control_stops_at_upstream_linker_boundary() -> None:
    upstream_compiler = _compiler("library", 0)
    upstream_linker = ProducerNode(
        id="linker.library.0000",
        role=ProducerRole.LINKER,
        owner="library",
        target_id="library",
        arguments=(
            "${BUILD}/library-0.obj",
            "/dll",
            "/implib:${BUILD}/library.lib",
            "/out:${BUILD}/library.dll",
        ),
        inputs=(upstream_compiler.outputs[0],),
        directive_inputs=("system-library/runtime.lib",),
        outputs=("build/library.dll", "build/library.exp", "build/library.lib"),
        depends_on=(upstream_compiler.id,),
    )
    downstream_compiler = _compiler("app", 1)
    downstream_linker = ProducerNode(
        id="linker.app.0000",
        role=ProducerRole.LINKER,
        owner="app",
        target_id="app",
        arguments=(
            "${BUILD}/app-1.obj",
            "${BUILD}/library.lib",
            "/out:${BUILD}/app.exe",
        ),
        inputs=(downstream_compiler.outputs[0], "build/library.lib"),
        outputs=("build/app.exe",),
        depends_on=(downstream_compiler.id, upstream_linker.id),
    )
    graph_nodes = (
        upstream_compiler,
        upstream_linker,
        downstream_compiler,
        downstream_linker,
    )
    payloads = {
        upstream_compiler.outputs[0]: _directive_object(b"/DEFAULTLIB:runtime /INCLUDE:_upstream "),
        downstream_compiler.outputs[0]: _directive_object(b"/DEFAULTLIB:runtime "),
        "build/library.lib": _directive_archive(
            "library.obj", _directive_object(b"/INCLUDE:_import_root ")
        ),
        "system-library/runtime.lib": _directive_archive(
            "runtime.obj", _directive_object(b"/INCLUDE:_runtime_root ")
        ),
    }
    requested: list[str] = []

    def payload_for_reference(reference: str) -> bytes:
        requested.append(reference)
        return payloads[reference]

    with pytest.raises(
        incremental_context.ClassicIncrementalError,
        match=r"--directive-input app=runtime\.lib",
    ):
        incremental_keys._warm_link_control_material(
            downstream_linker,
            graph_nodes,
            payload_for_reference=payload_for_reference,
        )
    assert set(requested) == {downstream_compiler.outputs[0], "build/library.lib"}

    admitted_downstream = ProducerNode.model_validate(
        {
            **downstream_linker.model_dump(mode="python"),
            "directive_inputs": ("system-library/runtime.lib",),
        }
    )
    with pytest.raises(
        incremental_context.ClassicIncrementalError,
        match="graph is incomplete or ambiguous",
    ):
        incremental_keys._warm_link_control_material(
            admitted_downstream,
            graph_nodes,
            payload_for_reference=payload_for_reference,
        )
    incremental_keys._warm_link_control_material(
        admitted_downstream,
        (*graph_nodes[:-1], admitted_downstream),
        payload_for_reference=payload_for_reference,
    )


def test_incremental_base_key_material_bytes_are_stable() -> None:
    bundle = SimpleNamespace(
        producer_graph=SimpleNamespace(path_profile_id="fixture"),
        spec=SimpleNamespace(
            paths=SimpleNamespace(
                source=r"R:\source",
                build=r"R:\build",
                toolchain=r"R:\toolchain",
            )
        ),
    )

    material = incremental_keys._base_material(
        bundle=cast(object, bundle),  # type: ignore[arg-type]
        graph_digest="graph-digest",
        node_identity=cast(JsonValue, {"id": "compiler.unit"}),
        role="compiler",
        toolchain=cast(JsonValue, {"lock": "toolchain"}),
        runtime=cast(JsonValue, {"backend": "fixture"}),
        argv=("cl", "/c"),
        environment={"B": "2", "A": "1"},
        direct_inputs=(cast(JsonValue, {"path": "source/unit.cpp", "digest": "abc"}),),
        dependencies={},
        recursive_reads=(cast(JsonValue, {"path": "source/unit.h", "digest": "def"}),),
        overlay_inputs=(cast(JsonValue, {"overlay": "decl"}),),
        generated_inputs=(cast(JsonValue, {"generated": "carrier"}),),
        donor_inputs=(cast(JsonValue, {"donor": "unit"}),),
        composition_inputs=(cast(JsonValue, {"proof": "receipt"}),),
        transform_inputs=(cast(JsonValue, {"transform": "rdata"}),),
    )

    expected = (
        rb'{"argv":["cl","/c"],"composition_inputs":[{"proof":"receipt"}],'
        rb'"cwd":"R:\\build","direct_inputs":[{"digest":"abc",'
        rb'"path":"source/unit.cpp"}],"donor_inputs":[{"donor":"unit"}],'
        rb'"environment":{"A":"1","B":"2"},"generated_inputs":'
        rb'[{"generated":"carrier"}],"graph":"graph-digest","node":'
        rb'{"id":"compiler.unit"},"overlay_inputs":[{"overlay":"decl"}],'
        rb'"path_profile":{"build":"R:\\build","id":"fixture",'
        rb'"source":"R:\\source","toolchain":"R:\\toolchain"},'
        rb'"producer_dependencies":[],"recursive_reads":[{"digest":"def",'
        rb'"path":"source/unit.h"}],"role":"compiler","runtime":'
        rb'{"backend":"fixture"},"toolchain":{"lock":"toolchain"},'
        rb'"transform_inputs":[{"transform":"rdata"}]}'
        b"\n"
    )
    assert canonical_json(material) == expected


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


def _donor_recipe(
    recipe_id: str,
    family: ClassicRecipeFamily,
    parameters: dict[str, object],
) -> ClassicRecipeIntervention:
    return ClassicRecipeIntervention(
        id=recipe_id,
        scope=Scope(target="app", translation_unit="unit.app"),
        rationale="fixture translation-unit-scoped donor transform",
        family=family,
        role=ClassicRecipeRole.DONOR,
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
    monkeypatch.setattr(incremental_planning, "runtime_asset_path", lambda _name: proxy)
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
    first = incremental_planning._runtime_material(cast(object, backend), None, None)  # type: ignore[arg-type]
    proxy.write_bytes(b"#!/bin/sh\nexit 7\n")
    second = incremental_planning._runtime_material(cast(object, backend), None, None)  # type: ignore[arg-type]

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
        schema_version=3,
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-makefiles-v1",
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
            analysis_link_options=(),
            project_sdk_libraries=(),
        ),
        toolchain_lock=SimpleNamespace(model_dump=lambda **_kwargs: {"lock": "fake"}),
        intervention_documents=documents,
        proof_documents=(),
        interventions=(),
    )
    sources = {compiler.id: r"R:\source\shared.cpp" for compiler in compilers}
    return bundle, units, sources


def _enable_analysis_links(bundle: SimpleNamespace) -> None:
    bundle.producer_graph = bundle.producer_graph.model_copy(
        update={
            "nodes": tuple(
                node.model_copy(
                    update={
                        "arguments": (
                            *node.arguments,
                            f"/PDB:${{BUILD}}/{node.target_id}.PDB",
                            "/INCREMENTAL:NO",
                        )
                    }
                )
                if node.role is ProducerRole.LINKER
                else node
                for node in bundle.producer_graph.nodes
            )
        }
    )
    bundle.build_plan.analysis_link_options = ("/DEBUG",)
    bundle.source_manifest = SimpleNamespace(entries=(SimpleNamespace(path="shared.cpp"),))
    bundle.spec.state_dir = ".reprobit-state"
    bundle.spec.toolchain.lock_file = "reprobit/toolchain.lock.json"
    bundle.spec.layout = SimpleNamespace(
        source_manifest="reprobit/source-manifest.json",
        build_plan="reprobit/build-plan.json",
        producer_graph="reprobit/producer-graph.json",
        interventions="reprobit/interventions",
        proofs="reprobit/proofs",
        oracles="reprobit/oracles",
    )


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
    monkeypatch.setattr(incremental_planning, "ClassicMSVCToolchain", _FakeInstallation)
    relatives = {role: f"bin/{role.value}.exe" for role in ProducerRole}
    monkeypatch.setattr(
        incremental_planning,
        "_graph_role_bindings",
        lambda *_args: ({role: role.value for role in ProducerRole}, relatives),
    )
    monkeypatch.setattr(
        incremental_planning,
        "_runtime_material",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        incremental_keys,
        "_warm_link_control_material",
        lambda linker, _nodes, **_kwargs: {
            "schema": 1,
            "target_id": linker.target_id,
            "linker_node": linker.id,
            "directives": {},
            "module_definition": None,
        },
    )
    monkeypatch.setattr(
        incremental_planning,
        "_graph_system_library_map",
        lambda *_a, **_k: {},
    )
    monkeypatch.setattr(
        incremental_planning,
        "prepare_classic_units",
        lambda *_a, **_k: units,
    )
    monkeypatch.setattr(
        incremental_planning,
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
        incremental_planning,
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

    monkeypatch.setattr(
        incremental_context,
        "prepare_classic_producer_graph_run",
        prepare,
    )


def _run(
    bundle: SimpleNamespace,
    *,
    root: Path,
    state: Path,
    session: Path,
    jobs: int = 1,
    progress: IncrementalProgress | None = None,
    repair_analysis: bool = False,
) -> incremental_context.ClassicIncrementalResult:
    toolchain = root / "toolchain"
    toolchain.mkdir(exist_ok=True)
    return incremental_execution.execute_classic_incremental_build(
        DeveloperAuthority(cast(object, bundle), (), (), MappingProxyType({})),  # type: ignore[arg-type]
        project_root=root,
        session_root=session,
        state_root=state,
        toolchain_root=toolchain,
        backend=cast(object, SimpleNamespace(identifier="fake")),  # type: ignore[arg-type]
        jobs=jobs,
        progress=progress,
        repair_analysis=repair_analysis,
    )


def test_repair_analysis_runs_only_transform_closure_and_never_caches_provisional_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    unrelated_source = b"int unrelated(void) { return 0; }\n"
    (root / "unrelated.cpp").write_bytes(unrelated_source)
    unrelated_compiler = _compiler("utility", 99, source="unrelated.cpp")
    bundle.producer_graph = bundle.producer_graph.model_copy(
        update={"nodes": (unrelated_compiler, *bundle.producer_graph.nodes)}
    )
    sources[unrelated_compiler.id] = r"R:\source\unrelated.cpp"

    class ProvisionalExecutor(_FakeWarmExecutor):
        provisional = True

        def execute_warm_compiler_transform(
            self,
            compiler_node_id: str,
            *,
            inputs: object,
            outputs: MappingProxyType[str, Path] | dict[str, Path],
            cancellation: object,
        ) -> ClassicWarmCompilerTransformResult:
            result = super().execute_warm_compiler_transform(
                compiler_node_id,
                inputs=inputs,
                outputs=outputs,
                cancellation=cancellation,
            )
            return ClassicWarmCompilerTransformResult(
                result.steps,
                result.donor_dependencies,
                self.provisional,
            )

        def execute_warm_terminal(self, *_args: object, **_kwargs: object) -> None:
            if self.provisional:
                pytest.fail("repair analysis reached the terminal pipeline")
            super().execute_warm_terminal(*_args, **_kwargs)  # type: ignore[arg-type]

    executor = ProvisionalExecutor(sources)
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
        source_payloads={
            "shared.cpp": (root / "shared.cpp").read_bytes(),
            "unrelated.cpp": unrelated_source,
        },
        warm_executor=executor,
    )

    first = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "analysis-1",
        repair_analysis=True,
    )
    second = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "analysis-2",
        repair_analysis=True,
    )

    assert first.receipt.outputs == ()
    assert first.summary.misses == 2
    assert second.summary.hits == 1
    assert second.summary.misses == 1
    assert not (root / "artifacts/app.exe").exists()

    executor.provisional = False
    ordinary = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "ordinary",
    )
    assert ordinary.summary.hits == 1
    assert ordinary.summary.misses == 4
    assert (root / "artifacts/app.exe").is_file()


def test_implementation_drift_is_rejected_before_planning_mutates_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, _units, _sources = _fixture_bundle(root)
    session = tmp_path / "run"
    monkeypatch.setattr(
        incremental,
        "producer_implementation_digest",
        lambda: Digest.from_bytes(b"changed incremental producer closure"),
    )

    with pytest.raises(RuntimeError, match="implementation changed"):
        _run(bundle, root=root, state=state, session=session)

    assert not session.exists()


def test_implementation_drift_after_planning_leaves_cache_records_unpublished(
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
    calls = 0

    def drift_after_planning() -> Digest:
        nonlocal calls
        calls += 1
        if calls == 1:
            return incremental.PRODUCER_IMPLEMENTATION_DIGEST
        return Digest.from_bytes(b"changed incremental producer closure")

    monkeypatch.setattr(
        incremental,
        "producer_implementation_digest",
        drift_after_planning,
    )

    with pytest.raises(RuntimeError, match="implementation changed"):
        _run(bundle, root=root, state=state, session=tmp_path / "run")

    assert calls == 2
    assert not tuple((state / "cache" / "v1" / "records").rglob("*.json"))
    assert not (root / "artifacts" / "app.exe").exists()


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
        incremental_context,
        "prepare_classic_producer_graph_run",
        lambda *_a, **_k: pytest.fail("all-hit build constructed a prepared run"),
    )
    expected_implementation = incremental.PRODUCER_IMPLEMENTATION_DIGEST
    implementation_revalidations: list[Digest] = []
    monkeypatch.setattr(
        incremental_execution,
        "revalidate_producer_implementation",
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


def test_implementation_drift_after_all_hit_planning_blocks_target_publication(
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
    _run(bundle, root=root, state=state, session=tmp_path / "run-1")
    artifact = root / "artifacts" / "app.exe"
    before = artifact.stat()
    calls = 0

    def drift_after_planning() -> Digest:
        nonlocal calls
        calls += 1
        if calls == 1:
            return incremental.PRODUCER_IMPLEMENTATION_DIGEST
        return Digest.from_bytes(b"changed incremental producer closure")

    monkeypatch.setattr(
        incremental,
        "producer_implementation_digest",
        drift_after_planning,
    )

    with pytest.raises(RuntimeError, match="implementation changed"):
        _run(bundle, root=root, state=state, session=tmp_path / "run-2")

    assert calls == 2
    after = artifact.stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (
        before.st_dev,
        before.st_ino,
        before.st_mtime_ns,
    )


def test_analysis_link_pair_is_cacheable_and_both_members_are_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    _enable_analysis_links(bundle)
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

    first = _run(bundle, root=root, state=state, session=tmp_path / "run-1")

    exact = root / "artifacts" / "app.exe"
    companion_dir = root / "artifacts" / "reprobit-debug"
    companion_image = companion_dir / "app.exe"
    pdb = companion_dir / "app.PDB"
    assert first.summary.misses == 5
    assert first.summary.published_comparison_pairs == 1
    assert first.summary.unchanged_comparison_pairs == 0
    assert executor.analysis_link_calls == ["app"]
    assert executor.analysis_link_inputs == [
        ("build/app-0.obj", "build/app-0.pdb"),
    ]
    assert exact.read_bytes() == b"raw:linker.app.0000:build/app.exe:terminal:app"
    assert companion_image.read_bytes().startswith(b"analysis-image:1:")
    assert pdb.read_bytes().startswith(b"analysis-pdb:1:")
    assert {item.producer_step for item in first.receipt.outputs} == {
        "terminal.app",
        "analysis-link.app",
    }
    assert sorted(path.name for path in (root / "artifacts").iterdir()) == [
        "app.exe",
        "reprobit-debug",
    ]
    assert sorted(path.name for path in companion_dir.iterdir()) == ["app.PDB", "app.exe"]
    image_before = companion_image.stat()
    pdb_before = pdb.stat()

    monkeypatch.setattr(
        incremental_context,
        "prepare_classic_producer_graph_run",
        lambda *_a, **_k: pytest.fail("all-hit analysis build constructed a runtime"),
    )
    second = _run(bundle, root=root, state=state, session=tmp_path / "run-2")

    assert second.summary.hits == 5
    assert second.summary.misses == 0
    assert second.summary.published_targets == 0
    assert second.summary.unchanged_targets == 1
    assert second.summary.published_comparison_pairs == 0
    assert second.summary.unchanged_comparison_pairs == 1
    assert executor.analysis_link_calls == ["app"]
    image_after = companion_image.stat()
    pdb_after = pdb.stat()
    assert (image_after.st_dev, image_after.st_ino, image_after.st_mtime_ns) == (
        image_before.st_dev,
        image_before.st_ino,
        image_before.st_mtime_ns,
    )
    assert (pdb_after.st_dev, pdb_after.st_ino, pdb_after.st_mtime_ns) == (
        pdb_before.st_dev,
        pdb_before.st_ino,
        pdb_before.st_mtime_ns,
    )


def test_analysis_pair_relinks_when_link_authority_changes_even_if_exact_image_does_not(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    _enable_analysis_links(bundle)
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

    _run(bundle, root=root, state=state, session=tmp_path / "run-1")
    exact = root / "artifacts" / "app.exe"
    companion = root / "artifacts" / "reprobit-debug" / "app.exe"
    pdb = root / "artifacts" / "reprobit-debug" / "app.PDB"
    first_exact = exact.read_bytes()
    first_companion = companion.read_bytes()
    first_pdb = pdb.read_bytes()

    bundle.producer_graph = bundle.producer_graph.model_copy(
        update={
            "nodes": tuple(
                node.model_copy(update={"arguments": (*node.arguments, "/FIXED:NO")})
                if node.role is ProducerRole.LINKER
                else node
                for node in bundle.producer_graph.nodes
            )
        }
    )
    second = _run(bundle, root=root, state=state, session=tmp_path / "run-2")

    assert executor.analysis_link_calls == ["app", "app"]
    assert second.summary.misses >= 3
    assert second.summary.published_comparison_pairs == 1
    assert second.summary.unchanged_comparison_pairs == 0
    assert exact.read_bytes() == first_exact
    assert companion.read_bytes() != first_companion
    assert pdb.read_bytes() != first_pdb
    assert pdb.read_bytes().startswith(b"analysis-pdb:2:")


def test_analysis_link_cache_is_local_to_its_target_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, original_units, sources = _fixture_bundle(
        root,
        targets=("app", "tool"),
    )
    tool_payload = b"int tool(void) { return 11; }\n"
    (root / "tool.cpp").write_bytes(tool_payload)
    tool_compiler = next(
        node
        for node in bundle.producer_graph.nodes
        if node.role is ProducerRole.COMPILER and node.owner == "tool"
    )
    split_tool_compiler = tool_compiler.model_copy(
        update={
            "arguments": (*tool_compiler.arguments[:-1], "${SOURCE}/tool.cpp"),
            "inputs": ("source/tool.cpp",),
        }
    )
    bundle.producer_graph = bundle.producer_graph.model_copy(
        update={
            "nodes": tuple(
                split_tool_compiler if node.id == tool_compiler.id else node
                for node in bundle.producer_graph.nodes
            )
        }
    )
    units = tuple(
        replace(
            unit,
            plan=unit.plan.model_copy(
                update={
                    "source": "tool.cpp",
                    "source_digest": Digest.from_bytes(tool_payload),
                }
            ),
        )
        if unit.plan.build_target == "tool"
        else unit
        for unit in original_units
    )
    bundle.build_plan.translation_units = tuple(unit.plan for unit in units)
    sources[tool_compiler.id] = r"R:\source\tool.cpp"
    _enable_analysis_links(bundle)
    bundle.source_manifest.entries = (
        SimpleNamespace(path="shared.cpp"),
        SimpleNamespace(path="tool.cpp"),
    )
    executor = _FakeWarmExecutor(sources)
    runtime_calls: list[_FakePrepared] = []

    def patch() -> None:
        _patch_planner(
            monkeypatch,
            bundle=bundle,
            units=units,
            sources=sources,
            project_root=root,
            runtime_calls=runtime_calls,
            source_payloads={
                "shared.cpp": (root / "shared.cpp").read_bytes(),
                "tool.cpp": (root / "tool.cpp").read_bytes(),
            },
            warm_executor=executor,
        )

    patch()
    _run(bundle, root=root, state=state, session=tmp_path / "run-1", jobs=2)
    assert executor.analysis_link_calls == ["app", "tool"]
    assert executor.analysis_link_inputs == [
        ("build/app-0.obj", "build/app-0.pdb"),
        ("build/tool-1.obj", "build/tool-1.pdb"),
    ]
    companion_dir = root / "artifacts" / "reprobit-debug"
    app_image = companion_dir / "app.exe"
    app_pdb = companion_dir / "app.PDB"
    tool_image = companion_dir / "tool.exe"
    tool_pdb = companion_dir / "tool.PDB"
    app_image_before = app_image.stat()
    app_before = app_pdb.stat()
    tool_image_before = tool_image.read_bytes()
    tool_before = tool_pdb.read_bytes()

    (root / "tool.cpp").write_bytes(b"int tool(void) { return 12; }\n")
    patch()
    second = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "run-2",
        jobs=2,
    )

    assert executor.analysis_link_calls == ["app", "tool", "tool"]
    assert executor.analysis_link_inputs[-1] == (
        "build/tool-1.obj",
        "build/tool-1.pdb",
    )
    assert second.summary.hits == 5
    assert second.summary.misses == 5
    assert second.summary.published_comparison_pairs == 1
    assert second.summary.unchanged_comparison_pairs == 1
    app_image_after = app_image.stat()
    app_after = app_pdb.stat()
    assert (
        app_image_after.st_dev,
        app_image_after.st_ino,
        app_image_after.st_mtime_ns,
    ) == (
        app_image_before.st_dev,
        app_image_before.st_ino,
        app_image_before.st_mtime_ns,
    )
    assert (app_after.st_dev, app_after.st_ino, app_after.st_mtime_ns) == (
        app_before.st_dev,
        app_before.st_ino,
        app_before.st_mtime_ns,
    )
    assert tool_image.read_bytes() != tool_image_before
    assert tool_pdb.read_bytes() != tool_before


def test_analysis_link_missing_pdb_fails_before_target_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MissingPdbExecutor(_FakeWarmExecutor):
        def execute_warm_analysis_link(self, target_id: str, **kwargs: object) -> None:
            self.analysis_link_calls.append(target_id)
            outputs = cast(dict[str, Path], kwargs["outputs"])
            outputs["image"].parent.mkdir(parents=True, exist_ok=True)
            outputs["image"].write_bytes(b"analysis-image-without-pdb")

    root = tmp_path / "project"
    root.mkdir()
    artifacts = root / "artifacts"
    artifacts.mkdir()
    companion_dir = artifacts / "reprobit-debug"
    companion_dir.mkdir()
    (artifacts / "app.exe").write_bytes(b"prior-exact")
    (companion_dir / "app.exe").write_bytes(b"prior-companion")
    (companion_dir / "app.PDB").write_bytes(b"prior-pdb")
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    _enable_analysis_links(bundle)
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
        warm_executor=MissingPdbExecutor(sources),
    )

    with pytest.raises(RuntimeError, match="omitted output 'pdb'"):
        _run(bundle, root=root, state=state, session=tmp_path / "run")

    assert (artifacts / "app.exe").read_bytes() == b"prior-exact"
    assert (companion_dir / "app.exe").read_bytes() == b"prior-companion"
    assert (companion_dir / "app.PDB").read_bytes() == b"prior-pdb"


def test_debug_companion_publication_failure_rolls_back_exact_image_and_pair(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    artifacts = root / "artifacts"
    artifacts.mkdir()
    companion_dir = artifacts / "reprobit-debug"
    companion_dir.mkdir()
    (artifacts / "app.exe").write_bytes(b"prior-exact")
    (companion_dir / "app.exe").write_bytes(b"prior-companion")
    (companion_dir / "app.PDB").write_bytes(b"prior-pdb")
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    _enable_analysis_links(bundle)
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )
    original_publish = classic_publication.atomic_publish_relative_if_current

    def fail_pdb(
        project: Path,
        relative: str,
        payload: bytes,
        *,
        expected: object,
        **publication_options: object,
    ) -> object:
        if relative == "artifacts/reprobit-debug/app.PDB":
            raise SecurePathError("injected debug-companion PDB failure")
        return original_publish(  # type: ignore[arg-type]
            project,
            relative,
            payload,
            expected=expected,
            **publication_options,  # type: ignore[arg-type]
        )

    monkeypatch.setattr(
        classic_publication,
        "atomic_publish_relative_if_current",
        fail_pdb,
    )
    with pytest.raises(
        incremental_context.ClassicIncrementalError,
        match="target set could not be published",
    ):
        _run(bundle, root=root, state=state, session=tmp_path / "run")

    assert (artifacts / "app.exe").read_bytes() == b"prior-exact"
    assert (companion_dir / "app.exe").read_bytes() == b"prior-companion"
    assert (companion_dir / "app.PDB").read_bytes() == b"prior-pdb"


def test_multi_target_debug_pair_failure_rolls_back_every_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    artifacts = root / "artifacts"
    artifacts.mkdir()
    originals = {
        "app.exe": b"prior-app-exact",
        "tool.exe": b"prior-tool-exact",
        "reprobit-debug/app.exe": b"prior-app-companion",
        "reprobit-debug/app.PDB": b"prior-app-pdb",
        "reprobit-debug/tool.exe": b"prior-tool-companion",
        "reprobit-debug/tool.PDB": b"prior-tool-pdb",
    }
    for name, payload in originals.items():
        destination = artifacts / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root, targets=("app", "tool"))
    _enable_analysis_links(bundle)
    runtime_calls: list[_FakePrepared] = []
    _patch_planner(
        monkeypatch,
        bundle=bundle,
        units=units,
        sources=sources,
        project_root=root,
        runtime_calls=runtime_calls,
    )
    original_publish = classic_publication.atomic_publish_relative_if_current

    def fail_last_pdb(
        project: Path,
        relative: str,
        payload: bytes,
        *,
        expected: object,
        **publication_options: object,
    ) -> object:
        if relative == "artifacts/reprobit-debug/tool.PDB":
            raise SecurePathError("injected final debug-companion PDB failure")
        return original_publish(  # type: ignore[arg-type]
            project,
            relative,
            payload,
            expected=expected,
            **publication_options,  # type: ignore[arg-type]
        )

    monkeypatch.setattr(
        classic_publication,
        "atomic_publish_relative_if_current",
        fail_last_pdb,
    )
    with pytest.raises(
        incremental_context.ClassicIncrementalError,
        match="target set could not be published",
    ):
        _run(bundle, root=root, state=state, session=tmp_path / "run", jobs=2)

    assert {name: (artifacts / name).read_bytes() for name in originals} == originals


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

    def read_clock() -> float:
        return next(clock)

    monkeypatch.setattr(incremental_execution, "monotonic", read_clock)
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
    original_execute = incremental_execution.IncrementalDAGExecutor.execute
    expected: list[bytes] = []

    def execute_then_mutate(
        executor: object,
        nodes: tuple[object, ...],
    ) -> object:
        result = original_execute(executor, nodes)  # type: ignore[arg-type]
        terminal = next(node for node in nodes if cast(object, node).id == "terminal.app")
        artifact = cast(object, terminal).outputs["artifact"]
        expected.append(artifact.read_bytes())
        artifact.write_bytes(b"peer-mutated-terminal-workspace")
        return result

    monkeypatch.setattr(
        incremental_execution.IncrementalDAGExecutor,
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
    original_key = incremental_nodes.producer_cache_key
    original_probe = incremental_nodes.probe_compiler_cache

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

    monkeypatch.setattr(incremental_nodes, "producer_cache_key", capture)
    monkeypatch.setattr(incremental_nodes, "probe_compiler_cache", capture_probe)
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
        translation_units=(next(unit.plan for unit in units if unit.plan.build_target == "app"),),
        analysis_link_options=(),
        project_sdk_libraries=(),
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
            expected_observations=tuple(_rdata_receipt(item.id) for item in interventions)
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
        incremental_context.ClassicIncrementalError,
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
        expected_values={"rdata_pool_repack": declaration} if receipt_introduces_selector else {},
    )
    bundle.interventions = (intervention,)
    bundle.proof_documents = (SimpleNamespace(expected_observations=(receipt,)),)
    bundle.build_plan = SimpleNamespace(
        translation_units=tuple(unit.plan for unit in units) if planned_lane else (),
        analysis_link_options=(),
        project_sdk_libraries=(),
    )
    monkeypatch.setattr(
        incremental_planning,
        "ClassicMSVCToolchain",
        lambda *_args, **_kwargs: pytest.fail("warm preflight constructed a toolchain"),
    )
    monkeypatch.setattr(
        incremental_context,
        "prepare_classic_producer_graph_run",
        lambda *_args, **_kwargs: pytest.fail("warm preflight prepared a runtime"),
    )
    session = tmp_path / "run"

    with pytest.raises(incremental_context.ClassicIncrementalError, match=message):
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
    intervention = _donor_recipe(
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
        compiler_seat="d_0123456789ab",
        family=intervention.family,
        build_target="app",
        logical_source="shared.cpp",
        staged_source="s.cpp",
        files=MappingProxyType({"s.cpp": b"rendered donor source\n"}),
        logical_outputs=MappingProxyType({}),
        compiler_additions=DonorCompilerAdditions(
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
        arena = r"R:\donors\composed-app-shared.cpp-d_0123456789ab"
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
            ClassicWarmDonorDependencyReplay(
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


def test_cross_target_donor_header_edit_invalidates_owning_transform_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root, targets=("app", "config"))
    app_compiler = next(
        node
        for node in bundle.producer_graph.nodes
        if node.role is ProducerRole.COMPILER and node.owner == "app"
    )
    config_compiler = next(
        node
        for node in bundle.producer_graph.nodes
        if node.role is ProducerRole.COMPILER and node.owner == "config"
    )
    bundle.producer_graph = bundle.producer_graph.model_copy(
        update={
            "nodes": tuple(
                node.model_copy(
                    update={
                        "arguments": (
                            node.arguments[0],
                            "-I${SOURCE}/config-only",
                            *node.arguments[1:],
                        )
                    }
                )
                if node.id == config_compiler.id
                else node
                for node in bundle.producer_graph.nodes
            )
        }
    )
    intervention = _donor_recipe(
        "cross_target_donor_recipe",
        ClassicRecipeFamily.DECLARATION_SHAPE,
        {"declarations": True},
    ).model_copy(update={"build_target": "config"})
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
        compiler_seat="d_0123456789ab",
        family=intervention.family,
        build_target="config",
        logical_source="shared.cpp",
        staged_source="s.cpp",
        files=MappingProxyType(
            {
                "s.cpp": b"rendered donor source\n",
                "run.h": b"struct DonorCarrier {};\n",
            }
        ),
        logical_outputs=MappingProxyType({}),
        compiler_additions=DonorCompilerAdditions(force_includes=("run.h",)),
        carrier_identifiers=frozenset({"DonorCarrier"}),
        receipt=receipt,
    )
    same_target_unit = replace(
        units[0],
        donors=(
            ClassicPreparedDonor(
                intervention.model_copy(update={"build_target": "app"}),
                replace(request, build_target="app"),
            ),
        ),
    )
    assert (
        incremental_planning._donor_dependency_resolution_contexts(
            same_target_unit,
            compiler_nodes={},
            compiler_sources={},
            node_arguments=lambda _node: (),
            source_root=r"R:\source",
            build_root=r"R:\build",
            environment={"INCLUDE": r"R:\toolchain\include"},
            authority=SealedIncludeAuthority((r"R:\source", r"R:\toolchain"), ()),
        )
        == ()
    )
    donor_units = (
        replace(
            units[0],
            donors=(ClassicPreparedDonor(intervention, request),),
        ),
        units[1],
    )
    config_directory = root / "config-only"
    config_directory.mkdir()
    header = config_directory / "config.h"
    header.write_bytes(b"#define CONFIG_VALUE 1\n")
    unrelated = root / "unrelated.h"
    unrelated.write_bytes(b"#define UNRELATED_VALUE 1\n")
    runtime_calls: list[_FakePrepared] = []

    def patch(header_payload: bytes, unrelated_payload: bytes) -> None:
        arena = r"R:\donors\composed-app-shared.cpp-d_0123456789ab"
        config_header = r"R:\source\config-only\config.h"
        executor = _FakeWarmExecutor(sources)
        trace = MsvcSbrTrace(
            arena,
            (
                MsvcSbrSource("s.cpp", None),
                MsvcSbrSource("run.h", 0),
                MsvcSbrSource("config.h", 0),
            ),
        )
        executor.donor_dependencies[app_compiler.id] = (
            ClassicWarmDonorDependencyReplay(
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
                        "run.h",
                        arena + r"\run.h",
                        Digest.from_bytes(b"struct DonorCarrier {};\n"),
                        len(b"struct DonorCarrier {};\n"),
                        IncludeOrigin.DONOR_ARENA,
                        0,
                    ),
                    ResolvedInclude(
                        "config.h",
                        config_header,
                        Digest.from_bytes(header_payload),
                        len(header_payload),
                        IncludeOrigin.PROJECT_SOURCE,
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
                "config-only/config.h": header_payload,
                "unrelated.h": unrelated_payload,
            },
            warm_executor=executor,
        )

    patch(header.read_bytes(), unrelated.read_bytes())
    first = _run(bundle, root=root, state=state, session=tmp_path / "run-1")
    assert first.summary.misses == 8

    patch(header.read_bytes(), unrelated.read_bytes())
    unchanged = _run(bundle, root=root, state=state, session=tmp_path / "run-2")
    assert unchanged.summary.hits == 8
    assert unchanged.summary.misses == 0

    unrelated.write_bytes(b"#define UNRELATED_VALUE 2\n")
    patch(header.read_bytes(), unrelated.read_bytes())
    unrelated_changed = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "run-unrelated",
    )
    assert unrelated_changed.summary.hits == 8
    assert unrelated_changed.summary.misses == 0

    header.write_bytes(b"#define CONFIG_VALUE 2\n")
    patch(header.read_bytes(), unrelated.read_bytes())
    changed = _run(bundle, root=root, state=state, session=tmp_path / "run-3")
    assert changed.summary.hits == 5
    assert changed.summary.misses == 3


def test_same_target_cross_source_donor_header_edit_invalidates_transform_closure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    bundle, units, sources = _fixture_bundle(root)
    owning_compiler = next(
        node for node in bundle.producer_graph.nodes if node.role is ProducerRole.COMPILER
    )
    linker = next(node for node in bundle.producer_graph.nodes if node.role is ProducerRole.LINKER)
    donor_source = b"int donor(void) { return 11; }\n"
    (root / "donor.cpp").write_bytes(donor_source)
    donor_compiler = _compiler("app", 1, source="donor.cpp")
    donor_compiler = donor_compiler.model_copy(
        update={
            "arguments": (
                donor_compiler.arguments[0],
                "-I${SOURCE}/donor-only",
                *donor_compiler.arguments[1:],
            )
        }
    )
    donor_object = donor_compiler.outputs[0]
    linker = linker.model_copy(
        update={
            "arguments": (
                linker.arguments[0],
                "${BUILD}/" + donor_object.removeprefix("build/"),
                *linker.arguments[1:],
            ),
            "inputs": (*linker.inputs, donor_object),
            "depends_on": (*linker.depends_on, donor_compiler.id),
        }
    )
    bundle.producer_graph = bundle.producer_graph.model_copy(
        update={"nodes": (owning_compiler, donor_compiler, linker)}
    )
    sources[donor_compiler.id] = r"R:\source\donor.cpp"

    intervention = _donor_recipe(
        "same_target_cross_source_donor_recipe",
        ClassicRecipeFamily.DECLARATION_SHAPE,
        {"declarations": True},
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
        compiler_seat="d_0123456789ab",
        family=intervention.family,
        build_target="app",
        logical_source="donor.cpp",
        staged_source="s.cpp",
        files=MappingProxyType(
            {
                "s.cpp": b"rendered donor source\n",
                "run.h": b"struct DonorCarrier {};\n",
            }
        ),
        logical_outputs=MappingProxyType({}),
        compiler_additions=DonorCompilerAdditions(force_includes=("run.h",)),
        carrier_identifiers=frozenset({"DonorCarrier"}),
        receipt=receipt,
    )
    donor_units = (
        replace(
            units[0],
            donors=(ClassicPreparedDonor(intervention, request),),
        ),
    )
    donor_only_directory = root / "donor-only"
    donor_only_directory.mkdir()
    header = donor_only_directory / "dependency.h"
    header.write_bytes(b"#define DONOR_VALUE 1\n")
    unrelated = root / "unrelated.h"
    unrelated.write_bytes(b"#define UNRELATED_VALUE 1\n")
    runtime_calls: list[_FakePrepared] = []

    def patch(header_payload: bytes, unrelated_payload: bytes) -> None:
        arena = r"R:\donors\composed-app-shared.cpp-d_0123456789ab"
        logical_header = r"R:\source\donor-only\dependency.h"
        executor = _FakeWarmExecutor(sources)
        executor.donor_dependencies[owning_compiler.id] = (
            ClassicWarmDonorDependencyReplay(
                intervention.id,
                MsvcSbrTrace(
                    arena,
                    (
                        MsvcSbrSource("s.cpp", None),
                        MsvcSbrSource("run.h", 0),
                        MsvcSbrSource("dependency.h", 0),
                    ),
                ),
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
                        "run.h",
                        arena + r"\run.h",
                        Digest.from_bytes(b"struct DonorCarrier {};\n"),
                        len(b"struct DonorCarrier {};\n"),
                        IncludeOrigin.DONOR_ARENA,
                        0,
                    ),
                    ResolvedInclude(
                        "dependency.h",
                        logical_header,
                        Digest.from_bytes(header_payload),
                        len(header_payload),
                        IncludeOrigin.PROJECT_SOURCE,
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
                "donor.cpp": donor_source,
                "donor-only/dependency.h": header_payload,
                "unrelated.h": unrelated_payload,
            },
            warm_executor=executor,
        )

    patch(header.read_bytes(), unrelated.read_bytes())
    first = _run(bundle, root=root, state=state, session=tmp_path / "run-1")
    assert first.summary.misses == 5

    patch(header.read_bytes(), unrelated.read_bytes())
    unchanged = _run(bundle, root=root, state=state, session=tmp_path / "run-2")
    assert unchanged.summary.hits == 5
    assert unchanged.summary.misses == 0

    unrelated.write_bytes(b"#define UNRELATED_VALUE 2\n")
    patch(header.read_bytes(), unrelated.read_bytes())
    unrelated_changed = _run(
        bundle,
        root=root,
        state=state,
        session=tmp_path / "run-unrelated",
    )
    assert unrelated_changed.summary.hits == 5
    assert unrelated_changed.summary.misses == 0

    header.write_bytes(b"#define DONOR_VALUE 2\n")
    patch(header.read_bytes(), unrelated.read_bytes())
    changed = _run(bundle, root=root, state=state, session=tmp_path / "run-3")
    assert changed.summary.hits == 2
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
    bundle.build_plan = SimpleNamespace(
        translation_units=(all_units[0].plan,),
        analysis_link_options=(),
        project_sdk_libraries=(),
    )

    class MixedExecutor(_FakeWarmExecutor):
        def __init__(self) -> None:
            super().__init__(sources)
            self.link_inputs: dict[str, tuple[bytes, ...]] = {}

        def execute_warm_graph_node(self, node_id: str, **kwargs: object) -> tuple[()]:
            if node_id.startswith("linker."):
                inputs = cast(PreparedNodeInputs, kwargs["inputs"])
                self.link_inputs[node_id] = tuple(
                    item.snapshot.path.read_bytes()
                    for _reference, item in sorted(inputs.entries.items(), key=lambda item: item[0])
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
    assert executor.link_inputs["linker.app.0000"][0].startswith(b"transformed:compiler.app.0000")
    assert executor.link_inputs["linker.tool.0000"][0].startswith(b"raw:compiler.tool.0001")
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
    original_publish = classic_publication.atomic_publish_relative_if_current

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
        classic_publication,
        "atomic_publish_relative_if_current",
        fail_second,
    )
    with pytest.raises(
        incremental_context.ClassicIncrementalError,
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
    original_publish = classic_publication.atomic_publish_relative_if_current
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
        classic_publication,
        "atomic_publish_relative_if_current",
        race_publication,
    )
    with pytest.raises(
        incremental_context.ClassicIncrementalError,
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

    payload, snapshot = incremental_context.read_payload(alias)

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
    monkeypatch.setattr(
        incremental_planning,
        "_toolchain_tree_files",
        lambda *_args: set(),
    )
    ordinary, generated, _physical, _payloads = incremental_planning._include_authorities(
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

    def bind(runtime: incremental_context.WarmRuntime) -> None:
        oracle_bindings.append(tuple(sorted(runtime.oracle_paths)))

    monkeypatch.setattr(incremental_context.WarmRuntime, "ensure_oracles", bind)
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


def test_runtime_factory_binds_all_legacy_oracles_before_donor_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oracle_paths = {target_id: tmp_path / f"{target_id}.oracle" for target_id in ("app", "tool")}
    for target_id, path in oracle_paths.items():
        path.write_bytes(f"oracle:{target_id}".encode())
    oracle_snapshots = {
        target_id: incremental_context.snapshot_file(path)
        for target_id, path in oracle_paths.items()
    }

    class SealedOracle:
        def __init__(self, target_id: str) -> None:
            self.target_id = target_id

        def _digest_receipt(self) -> tuple[str, int]:
            snapshot = oracle_snapshots[self.target_id]
            return snapshot.digest.value, snapshot.size

    class OracleLease:
        def __init__(self, target_id: str) -> None:
            self.oracle = SealedOracle(target_id)

        def __enter__(self) -> SealedOracle:
            return self.oracle

        def __exit__(self, *_args: object) -> None:
            return None

    class LifecycleExecutor(_FakeWarmExecutor):
        def __init__(self) -> None:
            super().__init__({})
            self.composition_started = False
            self.binding_attempts = 0

        def bind_legacy_oracles(self, values: object) -> None:
            self.binding_attempts += 1
            if self.composition_started:
                raise RuntimeError("legacy capabilities were bound after donor use")
            capabilities = cast(dict[str, object], values)
            if set(capabilities) != {"app", "tool"}:
                raise RuntimeError("legacy capability set was incomplete")
            super().bind_legacy_oracles(values)

    lifecycle = LifecycleExecutor()
    prepared = _FakePrepared(lifecycle)
    monkeypatch.setattr(
        incremental_context,
        "prepare_classic_producer_graph_run",
        lambda *_args, **_kwargs: prepared,
    )

    import reprobit.oracle_pe32 as legacy
    import reprobit.verify as verify

    by_path = {path: target_id for target_id, path in oracle_paths.items()}
    monkeypatch.setattr(
        verify,
        "seal_file_oracle",
        lambda path: OracleLease(by_path[path]),
    )
    monkeypatch.setattr(legacy, "bind_pe32_oracle", lambda sealed: sealed.target_id)
    plan = SimpleNamespace(
        runtime_lock=incremental_context.Lock(),
        runtime_holder={},
        bundle=object(),
        project_root=tmp_path,
        session_root=tmp_path / "session",
        toolchain_root=tmp_path / "toolchain",
        toolchain_report=None,
        backend=object(),
        jobs=2,
        compiler_transport=None,
        resource_transport=None,
        initialization_timeout=1.0,
        compile_timeout=1.0,
        link_timeout=1.0,
        cleanup_timeout=1.0,
        measured_receipt_repair=None,
        staging_root=tmp_path / "staging",
        oracle_paths=MappingProxyType(oracle_paths),
        oracle_snapshots=MappingProxyType(oracle_snapshots),
    )

    runtime = incremental_context.runtime_factory(cast(object, plan))  # type: ignore[arg-type]

    assert lifecycle.bound_oracles == ("app", "tool")
    assert lifecycle.binding_attempts == 1
    assert plan.runtime_holder == {"runtime": runtime}
    lifecycle.composition_started = True
    runtime.ensure_oracles()
    assert lifecycle.binding_attempts == 1
    runtime.close()
    assert prepared.closed is True


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
        schema_version=3,
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-makefiles-v1",
        nodes=tuple(sorted((ordinary, resource, generated, linker), key=lambda item: item.id)),
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
            analysis_link_options=(),
            project_sdk_libraries=(),
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
        ) -> ClassicWarmCompilerReplay:
            if node_id != ordinary.id:
                return super().replay_warm_compiler_dependencies(
                    node_id,
                    cancellation=cancellation,
                )
            return ClassicWarmCompilerReplay(
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
        incremental_context,
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
