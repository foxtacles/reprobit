from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from reprobit.model import Digest
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerGraphError,
    ProducerNode,
    ProducerRole,
    extract_cmake_unix_makefiles_graph,
    materialize_argument,
    materialize_reference,
    producer_graph_accepts_source,
    producer_graph_digest,
    read_producer_graph,
    source_topology_digest,
    write_producer_graph,
)


def _digest(value: str) -> Digest:
    return Digest(value=value * 64)


def test_node_refuses_unseated_commands_and_response_files() -> None:
    common = {
        "id": "compiler.unit",
        "role": ProducerRole.COMPILER,
        "owner": "core",
        "inputs": ("source/src/unit.cpp",),
        "outputs": ("build/obj/unit.obj",),
    }
    with pytest.raises(ValidationError, match="unseated Windows path"):
        ProducerNode(arguments=("/FoC:\\outside\\unit.obj",), **common)
    with pytest.raises(ValidationError, match="response files must be expanded"):
        ProducerNode(arguments=("@objects.rsp",), **common)
    with pytest.raises(ValidationError, match="unknown placeholder"):
        ProducerNode(arguments=("/I${ORACLE}/include",), **common)


@pytest.mark.parametrize(
    "arguments",
    (
        ("/I/tmp/host-include",),
        ("-I", "/tmp/host-include"),
        ("/DEF:${SOURCE}/../retail.def",),
        ("${SOURCE}suffix/unit.cpp",),
        ("../../outside/unit.cpp",),
        ("/out:${BUILD}/bin//program.exe",),
    ),
)
def test_node_refuses_paths_outside_logical_seats(arguments: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError):
        ProducerNode(
            id="compiler.unit",
            role=ProducerRole.COMPILER,
            owner="core",
            arguments=arguments,
            inputs=("source/src/unit.cpp",),
            outputs=("build/obj/unit.obj",),
        )


def test_node_accepts_normalized_seated_and_relative_paths() -> None:
    node = ProducerNode(
        id="compiler.unit",
        role=ProducerRole.COMPILER,
        owner="core",
        arguments=(
            "/I${SOURCE}/include",
            "/FI",
            "${SOURCE}/include/prefix.hpp",
            "/Fo${BUILD}/obj/unit.obj",
            "kernel32.lib",
        ),
        inputs=("source/src/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )
    assert node.arguments[0] == "/I${SOURCE}/include"


def test_linker_directive_inputs_are_explicit_non_argv_edges() -> None:
    node = ProducerNode(
        id="linker.app",
        role=ProducerRole.LINKER,
        owner="app",
        target_id="app",
        arguments=("${BUILD}/unit.obj", "/out:${BUILD}/APP.EXE"),
        inputs=("build/unit.obj",),
        directive_inputs=(
            "system-library/comctl32.lib",
            "system-library/mfcs42.lib",
        ),
        outputs=("build/APP.EXE",),
    )
    assert node.directive_inputs == (
        "system-library/comctl32.lib",
        "system-library/mfcs42.lib",
    )


@pytest.mark.parametrize(
    ("role", "inputs", "directive_inputs", "message"),
    (
        (
            ProducerRole.COMPILER,
            ("source/src/unit.cpp",),
            ("system-library/mfcs42.lib",),
            "only terminal linkers",
        ),
        (
            ProducerRole.LINKER,
            ("build/unit.obj",),
            ("source/vendor/mfcs42.lib",),
            "bare locked system-library",
        ),
        (
            ProducerRole.LINKER,
            ("build/unit.obj",),
            ("system-library/vendor/mfcs42.lib",),
            "bare .lib",
        ),
        (
            ProducerRole.LINKER,
            ("build/unit.obj",),
            ("system-library/MFCS42.lib", "system-library/mfcs42.lib"),
            "unique and canonically ordered",
        ),
        (
            ProducerRole.LINKER,
            ("build/unit.obj", "system-library/mfcs42.lib"),
            ("system-library/mfcs42.lib",),
            "distinct from argv inputs",
        ),
    ),
)
def test_directive_inputs_fail_closed(
    role: ProducerRole,
    inputs: tuple[str, ...],
    directive_inputs: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        ProducerNode(
            id=f"{role.value}.directive",
            role=role,
            owner="app",
            target_id="app" if role is ProducerRole.LINKER else None,
            arguments=(
                ("${BUILD}/unit.obj", "/out:${BUILD}/APP.EXE")
                if role is ProducerRole.LINKER
                else ("/c", "${SOURCE}/src/unit.cpp", "/Fo${BUILD}/unit.obj")
            ),
            inputs=inputs,
            directive_inputs=directive_inputs,
            outputs=("build/APP.EXE",)
            if role is ProducerRole.LINKER
            else ("build/unit.obj",),
        )


def test_graph_requires_closed_build_dependencies() -> None:
    compiler = ProducerNode(
        id="compiler.unit",
        role=ProducerRole.COMPILER,
        owner="core",
        arguments=("/c", "${SOURCE}/src/unit.cpp", "/Fo${BUILD}/obj/unit.obj"),
        inputs=("source/src/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )
    linker = ProducerNode(
        id="linker.app",
        role=ProducerRole.LINKER,
        owner="app",
        target_id="app",
        arguments=("${BUILD}/obj/unit.obj", "/out:${BUILD}/APP.EXE"),
        inputs=("build/obj/unit.obj",),
        outputs=("build/APP.EXE",),
    )
    with pytest.raises(ValidationError, match="without a direct dependency"):
        ProducerGraphDocument(
            schema_version=1,
            source_manifest_digest=_digest("1"),
            toolchain_lock_digest=_digest("2"),
            path_profile_id="stable",
            extractor="cmake-unix-makefiles-v1",
            nodes=(compiler, linker),
        )


def test_graph_v2_binds_path_topology_but_not_source_content() -> None:
    node = ProducerNode(
        id="compiler.unit",
        role=ProducerRole.COMPILER,
        owner="core",
        arguments=("/c", "${SOURCE}/src/unit.cpp", "/Fo${BUILD}/obj/unit.obj"),
        inputs=("source/src/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )
    graph = ProducerGraphDocument(
        schema_version=2,
        source_topology_digest=source_topology_digest(
            ("include/unit.h", "src/unit.cpp")
        ),
        toolchain_lock_digest=_digest("2"),
        path_profile_id="stable",
        extractor="cmake-unix-makefiles-v1",
        nodes=(node,),
    )

    assert producer_graph_accepts_source(
        graph,
        manifest_digest=_digest("3"),
        paths=("src/unit.cpp", "include/unit.h"),
    )
    assert producer_graph_accepts_source(
        graph,
        manifest_digest=_digest("4"),
        paths=("include/unit.h", "src/unit.cpp"),
    )
    assert not producer_graph_accepts_source(
        graph,
        manifest_digest=_digest("4"),
        paths=("include/unit.h", "src/added.cpp", "src/unit.cpp"),
    )


@pytest.mark.parametrize(
    "values",
    (
        {
            "schema_version": 1,
            "source_topology_digest": _digest("1"),
        },
        {
            "schema_version": 2,
            "source_manifest_digest": _digest("1"),
        },
        {
            "schema_version": 2,
            "source_manifest_digest": _digest("1"),
            "source_topology_digest": _digest("2"),
        },
    ),
)
def test_graph_versions_require_exactly_one_source_binding(
    values: dict[str, object],
) -> None:
    node = ProducerNode(
        id="compiler.unit",
        role=ProducerRole.COMPILER,
        owner="core",
        arguments=("/c", "${SOURCE}/src/unit.cpp", "/Fo${BUILD}/obj/unit.obj"),
        inputs=("source/src/unit.cpp",),
        outputs=("build/obj/unit.obj",),
    )
    with pytest.raises(ValidationError, match="requires only"):
        ProducerGraphDocument(
            **values,
            toolchain_lock_digest=_digest("2"),
            path_profile_id="stable",
            extractor="cmake-unix-makefiles-v1",
            nodes=(node,),
        )


@pytest.mark.parametrize(
    ("role", "arguments", "outputs"),
    (
        (
            ProducerRole.RESOURCE,
            ("/fo", "${BUILD}/res/app.rc.res", "${SOURCE}/res/app.rc"),
            ("build/res/app.rc.res",),
        ),
        (
            ProducerRole.LIBRARIAN,
            ("/out:${BUILD}/core.lib", "${SOURCE}/payload.obj"),
            ("build/core.lib",),
        ),
        (
            ProducerRole.LINKER,
            ("${SOURCE}/payload.obj", "/out:${BUILD}/APP.EXE"),
            ("build/APP.EXE",),
        ),
    ),
)
def test_noncompiler_argv_files_require_declared_input_edges(
    role: ProducerRole,
    arguments: tuple[str, ...],
    outputs: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError, match="argv/input edges differ"):
        ProducerNode(
            id=f"{role.value}.closed",
            role=role,
            owner="app",
            target_id="app" if role is ProducerRole.LINKER else None,
            arguments=arguments,
            inputs=(),
            outputs=outputs,
        )


def test_noncompiler_declared_edges_must_appear_in_argv() -> None:
    with pytest.raises(ValidationError, match="argv/input edges differ"):
        ProducerNode(
            id="linker.app",
            role=ProducerRole.LINKER,
            owner="app",
            target_id="app",
            arguments=("kernel32.lib", "/out:${BUILD}/APP.EXE"),
            inputs=("source/payload.obj", "system-library/kernel32.lib"),
            outputs=("build/APP.EXE",),
        )


def test_noncompiler_primary_output_must_match_argv() -> None:
    with pytest.raises(ValidationError, match="linker /out edge differs"):
        ProducerNode(
            id="linker.app",
            role=ProducerRole.LINKER,
            owner="app",
            target_id="app",
            arguments=("kernel32.lib", "/out:${BUILD}/OTHER.EXE"),
            inputs=("system-library/kernel32.lib",),
            outputs=("build/APP.EXE",),
        )


@pytest.mark.parametrize(
    ("role", "arguments", "inputs", "outputs"),
    (
        (
            ProducerRole.LINKER,
            (
                "${BUILD}/unit.obj",
                "/DEFAULTLIB:secret",
                "/out:${BUILD}/APP.EXE",
            ),
            ("build/unit.obj",),
            ("build/APP.EXE",),
        ),
        (
            ProducerRole.LINKER,
            ("${BUILD}/unit.obj", "/STUB:stub", "/out:${BUILD}/APP.EXE"),
            ("build/unit.obj",),
            ("build/APP.EXE",),
        ),
        (
            ProducerRole.LINKER,
            ("${BUILD}/unit.obj", "/ORDER:@order", "/out:${BUILD}/APP.EXE"),
            ("build/unit.obj",),
            ("build/APP.EXE",),
        ),
        (
            ProducerRole.RESOURCE,
            ("/fm:messages.bin", "/fo", "${BUILD}/app.res", "${SOURCE}/app.rc"),
            ("source/app.rc",),
            ("build/app.res",),
        ),
        (
            ProducerRole.LIBRARIAN,
            ("/extract:member.obj", "/out:${BUILD}/core.lib", "${BUILD}/unit.obj"),
            ("build/unit.obj",),
            ("build/core.lib",),
        ),
    ),
)
def test_noncompiler_roles_reject_unmodeled_read_bearing_options(
    role: ProducerRole,
    arguments: tuple[str, ...],
    inputs: tuple[str, ...],
    outputs: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError):
        ProducerNode(
            id=f"{role.value}.hidden-read",
            role=role,
            owner="app",
            target_id="app" if role is ProducerRole.LINKER else None,
            arguments=arguments,
            inputs=inputs,
            outputs=outputs,
        )


@pytest.mark.parametrize(
    ("role", "argument", "declared_input", "message"),
    (
        (
            ProducerRole.LIBRARIAN,
            "${SOURCE}/payload.obj",
            "source/payload.obj",
            "current-run build objects",
        ),
        (
            ProducerRole.LINKER,
            "${SOURCE}/payload.obj",
            "source/payload.obj",
            "current-run ancestry",
        ),
        (
            ProducerRole.LINKER,
            "${TOOLCHAIN}/payload.obj",
            "toolchain/payload.obj",
            "current-run ancestry",
        ),
        (
            ProducerRole.LINKER,
            "${TOOLCHAIN}/payload.lib",
            "toolchain/payload.lib",
            "producer or quarantine ancestry",
        ),
    ),
)
def test_archive_and_object_inputs_require_current_run_ancestry(
    role: ProducerRole,
    argument: str,
    declared_input: str,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        ProducerNode(
            id=f"{role.value}.ancestry",
            role=role,
            owner="app",
            target_id="app" if role is ProducerRole.LINKER else None,
            arguments=(argument, "/out:${BUILD}/APP.EXE"),
            inputs=(declared_input,),
            outputs=("build/APP.EXE",),
        )


def test_source_archive_requires_an_explicit_quarantine_edge(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="argv/input edges differ"):
        ProducerNode(
            id="linker.unquarantined",
            role=ProducerRole.LINKER,
            owner="app",
            target_id="app",
            arguments=("${SOURCE}/vendor/payload.lib", "/out:${BUILD}/APP.EXE"),
            inputs=("source/vendor/payload.lib",),
            outputs=("build/APP.EXE",),
        )

    node = ProducerNode(
        id="linker.quarantined",
        role=ProducerRole.LINKER,
        owner="app",
        target_id="app",
        arguments=("${SOURCE}/vendor/payload.lib", "/out:${BUILD}/APP.EXE"),
        inputs=("quarantine-archive/vendor/payload.lib",),
        outputs=("build/APP.EXE",),
    )
    assert node.inputs == ("quarantine-archive/vendor/payload.lib",)

    source = tmp_path / "source"
    build = tmp_path / "build"
    toolchain = tmp_path / "toolchain"
    assert (
        materialize_reference(
            node.inputs[0],
            source_root=source,
            build_root=build,
            toolchain_root=toolchain,
        )
        == source / "vendor/payload.lib"
    )


def _configured_fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    source = tmp_path / "effective"
    build = tmp_path / "configured"
    toolchain = tmp_path / "toolchain"
    source_shell = source.as_posix()
    toolchain_shell = toolchain.as_posix()
    for path in (
        source / "src/unit.cpp",
        source / "res/app.rc",
        source / "app.def",
        toolchain / "wine/x86/cl",
        toolchain / "wine/x86/rc",
        toolchain / "wine/x86/lib",
        toolchain / "wine/x86/link",
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture\n", encoding="utf-8")
    compile_output = "CMakeFiles/core.dir/src/unit.cpp.obj"
    compile_pdb = compile_output + ".pdb"
    (build / "compile_commands.json").parent.mkdir(parents=True, exist_ok=True)
    (build / "compile_commands.json").write_text(
        json.dumps(
            [
                {
                    "directory": str(build),
                    "file": str(source / "src/unit.cpp"),
                    "command": " ".join(
                        (
                            f"{toolchain_shell}/wine/x86/cl",
                            "/nologo",
                            f"-I{source_shell}/include",
                            f"/Fo{compile_output}",
                            f"/Fd{compile_pdb}",
                            "-c",
                            f"{source_shell}/src/unit.cpp",
                        )
                    ),
                }
            ]
        ),
        encoding="utf-8",
    )
    app_dir = build / "CMakeFiles/app.dir"
    core_dir = build / "CMakeFiles/core.dir"
    app_dir.mkdir(parents=True)
    core_dir.mkdir(parents=True)
    (app_dir / "flags.make").write_text(
        f"RC_DEFINES = -DWIN32\nRC_INCLUDES = -I {source_shell}/include\nRC_FLAGS =\n",
        encoding="utf-8",
    )
    (app_dir / "build.make").write_text(
        "\n".join(
            (
                "Building RC object",
                f"\t{toolchain_shell}/wine/x86/rc $(RC_DEFINES) $(RC_INCLUDES) "
                f"$(RC_FLAGS) /fo CMakeFiles/app.dir/res/app.rc.res {source_shell}/res/app.rc",
            )
        ),
        encoding="utf-8",
    )
    (core_dir / "objects1.rsp").write_text(compile_output, encoding="utf-8")
    (core_dir / "link.txt").write_text(
        f"{toolchain_shell}/wine/x86/lib /nologo /out:core.lib "
        "@CMakeFiles/core.dir/objects1.rsp",
        encoding="utf-8",
    )
    (app_dir / "objects1.rsp").write_text("CMakeFiles/app.dir/res/app.rc.res", encoding="utf-8")
    (app_dir / "link.txt").write_text(
        " ".join(
            (
                f"{toolchain_shell}/wine/x86/link",
                "/nologo",
                "@CMakeFiles/app.dir/objects1.rsp",
                "core.lib",
                "kernel32.lib",
                f"/DEF:{source_shell}/app.def",
                "/out:APP.EXE",
                "/implib:APP.lib",
                "/pdb:APP.pdb",
            )
        ),
        encoding="utf-8",
    )
    return source, build, toolchain


def test_extracts_closed_direct_graph_and_round_trips(tmp_path: Path) -> None:
    source, build, toolchain = _configured_fixture(tmp_path)
    graph = extract_cmake_unix_makefiles_graph(
        configured_build_root=build,
        effective_source_root=source,
        toolchain_root=toolchain,
        source_topology_digest_value=_digest("3"),
        toolchain_lock_digest=_digest("4"),
        path_profile_id="stable",
        target_outputs={"app": "APP.EXE"},
        directive_inputs={
            "app": (
                "system-library/comctl32.lib",
                "system-library/mfcs42.lib",
            )
        },
    )
    assert graph.schema_version == 2
    assert graph.source_manifest_digest is None
    assert graph.source_topology_digest == _digest("3")
    roles = [node.role for node in graph.nodes]
    assert roles.count(ProducerRole.COMPILER) == 1
    assert roles.count(ProducerRole.RESOURCE) == 1
    assert roles.count(ProducerRole.LIBRARIAN) == 1
    assert roles.count(ProducerRole.LINKER) == 1
    linker = next(node for node in graph.nodes if node.role is ProducerRole.LINKER)
    assert linker.target_id == "app"
    assert "build/core.lib" in linker.inputs
    assert "source/app.def" in linker.inputs
    assert "system-library/kernel32.lib" in linker.inputs
    assert linker.directive_inputs == (
        "system-library/comctl32.lib",
        "system-library/mfcs42.lib",
    )
    assert all("objects1.rsp" not in item for item in linker.arguments)
    assert any(item == "${BUILD}/core.lib" for item in linker.arguments)
    assert any(item == "/DEF:${SOURCE}/app.def" for item in linker.arguments)
    assert len(linker.depends_on) == 2  # resource plus archive

    destination = tmp_path / "producer-graph.json"
    write_producer_graph(destination, graph)
    received = read_producer_graph(destination)
    assert received == graph
    assert producer_graph_digest(received) == producer_graph_digest(graph)


@pytest.mark.parametrize(
    ("directive_inputs", "message"),
    (
        (
            {"missing": ("system-library/mfcs42.lib",)},
            "unknown target",
        ),
        (
            {
                "app": (
                    "system-library/MFCS42.lib",
                    "system-library/mfcs42.lib",
                )
            },
            "not canonical and unique",
        ),
        (
            {"app": ("system-library/vendor/mfcs42.lib",)},
            "bare .lib",
        ),
    ),
)
def test_extractor_rejects_invalid_directive_inputs(
    tmp_path: Path,
    directive_inputs: dict[str, tuple[str, ...]],
    message: str,
) -> None:
    source, build, toolchain = _configured_fixture(tmp_path)
    with pytest.raises((ProducerGraphError, ValueError), match=message):
        extract_cmake_unix_makefiles_graph(
            configured_build_root=build,
            effective_source_root=source,
            toolchain_root=toolchain,
            source_topology_digest_value=_digest("3"),
            toolchain_lock_digest=_digest("4"),
            path_profile_id="stable",
            target_outputs={"app": "APP.EXE"},
            directive_inputs=directive_inputs,
        )


def test_materialize_argument_is_literal_and_complete() -> None:
    assert (
        materialize_argument(
            "/I${SOURCE}/include",
            source_root="Z:\\src",
            build_root="Z:\\build",
            toolchain_root="Z:\\msvc",
        )
        == "/IZ:\\src/include"
    )
    with pytest.raises(ProducerGraphError, match="unresolved"):
        materialize_argument(
            "${UNKNOWN}/x",
            source_root="Z:\\src",
            build_root="Z:\\build",
            toolchain_root="Z:\\msvc",
        )
