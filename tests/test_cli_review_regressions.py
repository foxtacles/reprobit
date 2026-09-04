"""Regressions for onboarding recovery and consistent developer input selection."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_cli import (
    _cmake_refresh_project,
    _fresh_cmake_import_project,
    _select_non_native_cmake_import_backend,
)

from reprobit.cli import main
from reprobit.cli_paths import CLIError
from reprobit.project_loader import load_project
from reprobit.source_lock import build_source_manifest
from reprobit.strict_json import canonical_json


def test_initial_import_source_drift_points_back_to_source_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _select_non_native_cmake_import_backend(monkeypatch)
    project = tmp_path / "project"
    _fresh_cmake_import_project(project)
    spec = load_project(project)
    ignores = project / ".gitignore"
    manifest = build_source_manifest(project, (".gitignore", "project-input.txt"), spec=spec)
    (project / spec.layout.source_manifest).write_bytes(canonical_json(manifest))
    ignores.write_text(ignores.read_text() + "/reference/\n/build/\n")
    before = {
        path: path.read_bytes()
        for path in (
            ignores,
            project / spec.layout.source_manifest,
            project / spec.toolchain.lock_file,
            project / "reference/program.bin",
        )
    }
    toolchain = tmp_path / "toolchain"
    toolchain.mkdir()
    monkeypatch.setattr(
        "reprobit.toolchains.ClassicMSVCToolchain.doctor",
        lambda _self, _lock=None: SimpleNamespace(ok=True, checks=(), require_ok=lambda: None),
    )

    def unexpected_configure(*_args: object, **_kwargs: object) -> None:
        pytest.fail("initial source drift must be rejected before configuring")

    monkeypatch.setattr("reprobit.cli_cmake_import.configure_cmake_project", unexpected_configure)
    capsys.readouterr()
    assert (
        main(
            [
                "import",
                "cmake",
                str(project),
                "--toolchain-root",
                str(toolchain),
                "--compiler-transport",
                sys.executable,
                "--resource-transport",
                sys.executable,
                "--cmake",
                sys.executable,
            ]
        )
        == 2
    )
    error = capsys.readouterr().err
    assert "source input differs from portable manifest: '.gitignore'" in error
    assert f"Next: rbit source preview {project}" in error
    assert "run rbit repair" not in error
    assert not (project / spec.layout.build_plan).exists()
    assert not (project / spec.layout.producer_graph).exists()
    assert {path: path.read_bytes() for path in before} == before


@pytest.mark.parametrize("cold", (False, True))
def test_developer_modes_accept_the_same_unreviewed_edit_but_verify_rejects_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    cold: bool,
) -> None:
    project = tmp_path / "project"
    _cmake_refresh_project(project)
    source = project / "src/remove.c"
    source.write_text("int remove(void) { return 3; }\n")
    before = {path: path.read_bytes() for path in (project / "reprobit").rglob("*.json")}
    selected: list[str] = []

    def stop_after_source_selection(**_kwargs: object) -> None:
        selected.append("ready")
        raise CLIError("source selection passed; compiler deliberately not started")

    monkeypatch.setattr(
        "reprobit.cli_environment.resolve_classic_execution_inputs", stop_after_source_selection
    )
    capsys.readouterr()
    command = ["build", str(project), *(("--cold",) if cold else ())]
    assert main(command) == 2
    assert "source selection passed" in capsys.readouterr().err
    assert selected == ["ready"]
    assert not (project / ".reprobit-state/runs").exists()
    assert main(["verify", str(project)]) == 2
    assert "source input differs from portable manifest" in capsys.readouterr().err
    assert selected == ["ready"]
    assert {path: path.read_bytes() for path in before} == before
