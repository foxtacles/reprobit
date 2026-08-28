from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import reprobit.classic_migration as classic_migration
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
        phase=None,
        translation_units=(),
        source_overlay_digest=Digest.from_bytes(b"overlay"),
        source_overlay_interventions=(),
        archives=(),
        terminal_producers={},
        execution_backends={},
        toolchain_policy={},
        target_policies=[],
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
    ("mutate_source", "link_admission"),
    ((False, False), (True, False), (False, True)),
)
def test_graph_configure_is_fresh_bounded_and_never_builds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutate_source: bool,
    link_admission: bool,
) -> None:
    project_root = tmp_path / "project"
    project_root.mkdir()
    workspace = tmp_path / "migration"
    toolchain = tmp_path / "toolchain"
    transports = toolchain / "wine/x86"
    transports.mkdir(parents=True)
    for name in ("cl", "rc", "link", "lib"):
        _executable(transports / name)
    module_root = tmp_path / "cmake"
    module_root.mkdir()
    (module_root / "ReproBit.cmake").write_text("# fixture\n", encoding="utf-8")

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
        (effective / "CMakeLists.txt").write_text("project(fixture)\n")
        return ()

    def write_plan(bundle: ProjectBundle, effective: Path, output: Path) -> None:
        del bundle, effective
        output.write_text("# generated fixture\n", encoding="utf-8")

    monkeypatch.setattr(classic_migration, "materialize_effective_workspace", materialize)
    monkeypatch.setattr(classic_migration, "write_cmake_project_plan", write_plan)
    monkeypatch.setattr(classic_migration, "cmake_module_path", lambda: module_root)

    if mutate_source:
        with pytest.raises(
            classic_migration.ClassicMigrationError,
            match="changed effective source",
        ):
            classic_migration.configure_classic_producer_graph(
                _bundle(project_root),
                project_root=project_root,
                workspace_root=workspace,
                toolchain_root=toolchain,
                cmake=fake_cmake,
                compiler_transport=transports / "cl",
                resource_transport=transports / "rc",
                timeout_seconds=30,
            )
        assert (workspace / "build/configure.log").is_file()
        return

    if link_admission:
        with pytest.raises(
            classic_migration.ClassicMigrationError,
            match=r"link admissions.*cannot encode",
        ):
            classic_migration.configure_classic_producer_graph(
                _bundle(project_root),
                project_root=project_root,
                workspace_root=workspace,
                toolchain_root=toolchain,
                cmake=fake_cmake,
                compiler_transport=transports / "cl",
                resource_transport=transports / "rc",
                timeout_seconds=30,
            )
        return

    result = classic_migration.configure_classic_producer_graph(
        _bundle(project_root),
        project_root=project_root,
        workspace_root=workspace,
        toolchain_root=toolchain,
        cmake=fake_cmake,
        compiler_transport=transports / "cl",
        resource_transport=transports / "rc",
        timeout_seconds=30,
    )

    assert result.configured_build_root == (workspace / "build").resolve()
    assert result.effective_source_root == (workspace / "source").resolve()
    assert result.target_plan == (workspace / "build/reprobit-target-plan.json").resolve()
    assert result.compile_database == (workspace / "build/compile_commands.json").resolve()
    assert result.configure_log.is_file()
    arguments = cast(
        list[str],
        json.loads((workspace / "build/argv.json").read_text(encoding="utf-8")),
    )
    assert arguments[arguments.index("-G") + 1] == "Unix Makefiles"
    assert "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON" in arguments
    assert "-DREPROBIT_TERMINAL=ON" in arguments
    assert not (workspace / "build/program.exe").exists()
