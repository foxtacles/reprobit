from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
from typing import cast

import pytest

import reprobit.cmake_configure as cmake_configure
from reprobit.cmake_configure import effective_source_digest
from reprobit.model import Digest
from reprobit.schema import (
    BuildPlanDocument,
    LockedTool,
    LogicalPathProfile,
    MsvcRelease,
    ProducerGraphBuildAdapter,
    ProjectBundle,
    ProjectSpec,
    TargetSpec,
    ToolchainLock,
    ToolchainRef,
)
from reprobit.strict_json import canonical_json


def _bundle(project_root: Path) -> ProjectBundle:
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
        targets=(TargetSpec(id="program", artifact="build/program.exe", oracle="oracle.exe"),),
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
        source_manifest=SimpleNamespace(complete=True, entries=()),
        build_plan=build_plan,
        producer_graph=None,
        intervention_documents=(),
        proof_documents=(),
        oracle_documents=(),
    )


def _executable(path: Path, payload: str = "#!/bin/sh\nexit 0\n") -> Path:
    path.write_text(payload, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return path


@pytest.mark.parametrize(
    "declarations, message",
    (
        (("FEATURE",), "NAME=VALUE"),
        (("1FEATURE=on",), "NAME=VALUE"),
        (("FEATURE=on", "FEATURE=off"), "repeats"),
        (("CMAKE_C_COMPILER=other",), "cannot replace"),
        (("REPROBIT_PROJECT_PLAN=other",), "cannot replace"),
        (("FEATURE=bad\nvalue",), "control character"),
    ),
)
def test_cmake_defines_are_narrow_and_cannot_replace_import_controls(
    declarations: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(cmake_configure.CMakeConfigureError, match=message):
        cmake_configure.cmake_define_arguments(declarations)


def test_cmake_paths_use_forward_slashes_for_native_windows_values() -> None:
    assert (
        cmake_configure._cmake_path(PureWindowsPath(r"D:\a\_temp\archaic-msvc42\bin\RC.EXE"))
        == "D:/a/_temp/archaic-msvc42/bin/RC.EXE"
    )


@pytest.mark.skipif(os.name != "posix", reason="executable transport fixture is POSIX")
def test_transport_sibling_rejects_symlink_only_and_two_real_aliases(
    tmp_path: Path,
) -> None:
    real = _executable(tmp_path / "elsewhere")
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(
        cmake_configure.CMakeConfigureError,
        match="does not uniquely provide 'link'",
    ):
        cmake_configure._transport_sibling(tmp_path, "link")

    (tmp_path / "link").unlink()
    _executable(tmp_path / "link")
    _executable(tmp_path / "link.exe")
    with pytest.raises(
        cmake_configure.CMakeConfigureError,
        match="does not uniquely provide 'link'",
    ):
        cmake_configure._transport_sibling(tmp_path, "link")


@pytest.mark.skipif(os.name != "posix", reason="executable transport fixture is POSIX")
def test_graph_configure_surfaces_the_bounded_process_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    workspace = tmp_path / "cmake-configure"
    toolchain = tmp_path / "toolchain"
    transports = toolchain / "wine/x86"
    transports.mkdir(parents=True)
    for name in ("cl", "rc", "link", "lib"):
        _executable(transports / name)
    module_root = tmp_path / "cmake"
    module_root.mkdir()
    (module_root / "ReproBit.cmake").write_text("# fixture\n", encoding="utf-8")
    fake_cmake = _executable(
        tmp_path / "cmake-fixture",
        "#!/bin/sh\necho 'compiler probe failed clearly' >&2\nexit 7\n",
    )

    def materialize(bundle: ProjectBundle, root: Path, effective: Path) -> tuple[()]:
        del bundle, root
        effective.mkdir(parents=True)
        (effective / "CMakeLists.txt").write_text("# fixture\n", encoding="utf-8")
        return ()

    monkeypatch.setattr(cmake_configure, "materialize_effective_workspace", materialize)
    monkeypatch.setattr(cmake_configure, "write_cmake_project_plan", lambda *args: None)
    monkeypatch.setattr(cmake_configure, "cmake_module_path", lambda: module_root)
    with pytest.raises(cmake_configure.CMakeConfigureError) as caught:
        cmake_configure.configure_cmake_project(
            _bundle(project_root),
            project_root=project_root,
            workspace_root=workspace,
            toolchain_root=toolchain,
            cmake=fake_cmake,
            compiler_transport=transports / "cl",
            resource_transport=transports / "rc",
            timeout_seconds=30,
        )

    message = str(caught.value)
    assert "CMake import configure failed" in message
    assert "exit code 7" in message
    assert "compiler probe failed clearly" in message
    assert f"full output: {workspace / 'build/configure.log'}" in message


@pytest.mark.parametrize(
    ("mutate_source", "link_admission", "generator"),
    (
        (False, False, "Unix Makefiles"),
        (True, False, "Unix Makefiles"),
        (False, True, "Unix Makefiles"),
        (False, False, "NMake Makefiles"),
    ),
)
@pytest.mark.skipif(os.name != "posix", reason="executable transport fixture is POSIX")
def test_graph_configure_is_fresh_bounded_and_never_builds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate_source: bool,
    link_admission: bool,
    generator: str,
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    workspace = tmp_path / "cmake-configure"
    toolchain = tmp_path / "toolchain"
    transports = toolchain / "wine/x86"
    transports.mkdir(parents=True)
    for name in ("cl", "rc", "link", "lib"):
        _executable(transports / name)
        (transports / f"{name}.exe").symlink_to(name)
    make_program = _executable(transports / "nmake") if generator == "NMake Makefiles" else None
    module_root = tmp_path / "cmake"
    module_root.mkdir()
    (module_root / "ReproBit.cmake").write_bytes(
        (Path(__file__).parents[1] / "cmake/ReproBit.cmake").read_bytes()
    )

    admissions = (
        [
            {
                "id": "unsupported",
                "target": "app",
                "artifact_id": "generated.object",
                "object_path": "R:/build/generated.obj",
                "before": "runtime.lib",
                "insertion_index": None,
                "after": None,
                "expected_symbol": "_entry",
            }
        ]
        if link_admission
        else []
    )
    fake_cmake = _executable(
        tmp_path / "cmake-fixture",
        "\n".join(
            (
                f"#!{sys.executable}",
                "import json, pathlib, sys",
                "args = sys.argv[1:]",
                "source = pathlib.Path(args[args.index('-S') + 1])",
                "build = pathlib.Path(args[args.index('-B') + 1])",
                "build.joinpath('argv.json').write_text(json.dumps(args))",
                "build.joinpath('Makefile').write_text('configured only\\n')",
                "build.joinpath('compile_commands.json').write_text('[]')",
                "build.joinpath('reprobit-target-plan.json').write_text(json.dumps({",
                "  'schema_version': 1,",
                "  'targets': [{'name': 'app', 'artifact_id': 'program',",
                "               'output': str(build / 'program.exe')}],",
                f"  'link_admissions': {admissions!r}}}))",
                ("source.joinpath('changed.txt').write_text('bad')" if mutate_source else ""),
                "",
            )
        ),
    )

    def materialize(
        bundle: ProjectBundle,
        root: Path,
        effective: Path,
    ) -> tuple[()]:
        del bundle, root
        assert effective == workspace / "source"
        effective.mkdir(parents=True)
        (effective / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.20)\n"
            "project(fixture C)\n"
            "add_executable(app main.c)\n",
            encoding="utf-8",
        )
        (effective / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        return ()

    def write_plan(bundle: ProjectBundle, effective: Path, output: Path) -> None:
        del bundle, effective
        output.write_text(
            "reprobit_register_target(TARGET app ARTIFACT_ID program)\n"
            'reprobit_write_plan(OUTPUT "${REPROBIT_TARGET_PLAN}")\n',
            encoding="utf-8",
        )

    monkeypatch.setattr(cmake_configure, "materialize_effective_workspace", materialize)
    monkeypatch.setattr(cmake_configure, "write_cmake_project_plan", write_plan)
    monkeypatch.setattr(cmake_configure, "cmake_module_path", lambda: module_root)

    if mutate_source:
        with pytest.raises(
            cmake_configure.CMakeConfigureError,
            match="changed effective source",
        ):
            cmake_configure.configure_cmake_project(
                _bundle(project_root),
                project_root=project_root,
                workspace_root=workspace,
                toolchain_root=toolchain,
                cmake=fake_cmake,
                compiler_transport=transports / "cl",
                resource_transport=transports / "rc",
                timeout_seconds=30,
                generator=generator,
                make_program=make_program,
            )
        assert (workspace / "build/configure.log").is_file()
        return

    if link_admission:
        with pytest.raises(
            cmake_configure.CMakeConfigureError,
            match=r"link admissions.*cannot encode",
        ):
            cmake_configure.configure_cmake_project(
                _bundle(project_root),
                project_root=project_root,
                workspace_root=workspace,
                toolchain_root=toolchain,
                cmake=fake_cmake,
                compiler_transport=transports / "cl",
                resource_transport=transports / "rc",
                timeout_seconds=30,
                generator=generator,
                make_program=make_program,
            )
        return

    result = cmake_configure.configure_cmake_project(
        _bundle(project_root),
        project_root=project_root,
        workspace_root=workspace,
        toolchain_root=toolchain,
        cmake=fake_cmake,
        compiler_transport=transports / "cl",
        resource_transport=transports / "rc",
        timeout_seconds=30,
        defer_project_plan=True,
        generator=generator,
        make_program=make_program,
        cmake_defines=("FEATURE_SET=classic", "SDK_LABEL=value with spaces"),
    )

    assert result.configured_build_root == (workspace / "build").resolve()
    assert result.effective_source_root == (workspace / "source").resolve()
    assert result.effective_source_digest == effective_source_digest(workspace / "source")
    assert result.target_plan == (workspace / "build/reprobit-target-plan.json").resolve()
    assert result.compile_database == (workspace / "build/compile_commands.json").resolve()
    assert result.configure_log.is_file()
    arguments = cast(
        list[str],
        json.loads((workspace / "build/argv.json").read_text(encoding="utf-8")),
    )
    assert arguments[arguments.index("-G") + 1] == generator
    assert "-DFEATURE_SET=classic" in arguments
    assert "-DSDK_LABEL=value with spaces" in arguments
    if generator == "NMake Makefiles":
        assert f"-DCMAKE_MAKE_PROGRAM={make_program}" in arguments
        assert "-DCMAKE_RULE_MESSAGES=OFF" in arguments
        assert "-DCMAKE_TRY_COMPILE_PLATFORM_VARIABLES=CMAKE_RULE_MESSAGES" in arguments
    else:
        assert "-DCMAKE_RULE_MESSAGES=OFF" not in arguments
    assert "-DCMAKE_C_COMPILER_FORCED=ON" not in arguments
    assert "-DCMAKE_CXX_COMPILER_FORCED=ON" not in arguments
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in arguments
    assert f"-DREPROBIT_EFFECTIVE_SOURCE_ROOT={workspace / 'source'}" in arguments
    assert "-DREPROBIT_TERMINAL=ON" in arguments
    bootstrap = workspace / "reprobit-cmake-import.cmake"
    assert f"-DCMAKE_PROJECT_INCLUDE={bootstrap}" in arguments
    bootstrap_text = bootstrap.read_text(encoding="utf-8")
    assert f'include("{module_root / "ReproBit.cmake"}")' in bootstrap_text
    assert "cmake_language(DEFER DIRECTORY" in bootstrap_text
    assert "ID reprobit_import_plan CALL include" in bootstrap_text
    assert str(workspace / "reprobit-project-plan.cmake") in bootstrap_text
    assert "add_executable(app main.c)" in (workspace / "source/CMakeLists.txt").read_text(
        encoding="utf-8"
    )
    assert not (workspace / "build/program.exe").exists()
    assert result.command_digest == Digest.from_bytes(
        canonical_json(
            {
                "schema": 1,
                "argv": list(result.command),
                "returncode": 0,
                "output": Digest.from_bytes(b"").model_dump(mode="json"),
            }
        )
    )

    system_cmake = shutil.which("cmake")
    if system_cmake is not None:
        actual_build = workspace / "actual-cmake-build"
        actual_plan = actual_build / "target-plan.json"
        subprocess.run(
            (
                system_cmake,
                "-S",
                str(workspace / "source"),
                "-B",
                str(actual_build),
                f"-DCMAKE_PROJECT_INCLUDE={bootstrap}",
                f"-DREPROBIT_EFFECTIVE_SOURCE_ROOT={workspace / 'source'}",
                f"-DREPROBIT_TARGET_PLAN={actual_plan}",
            ),
            check=True,
            capture_output=True,
        )
        imported_plan = json.loads(actual_plan.read_text(encoding="utf-8"))
        assert imported_plan["targets"][0]["name"] == "app"
        assert imported_plan["targets"][0]["artifact_id"] == "program"
