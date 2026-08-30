from __future__ import annotations

import json
from pathlib import Path

import pytest

from reprobit.cli import main
from reprobit.cli_output import human_command
from reprobit.project_loader import load_project
from reprobit.toolchains import MSVC_42, TOOLCHAIN_PROFILES


def _fake_toolchain(root: Path) -> Path:
    selected = TOOLCHAIN_PROFILES[MSVC_42]
    for relative in (*selected.required_producers, *selected.required_runtime_files):
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(relative.encode("ascii"))
    for relative in (*selected.include_roots, *selected.library_roots):
        directory = root.joinpath(*relative.split("/"))
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "fixture.dat").write_text(relative, encoding="utf-8")
    return root


def test_setup_creates_and_rechecks_the_project_toolchain_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "sample"
    toolchain = _fake_toolchain(tmp_path / "toolchain")
    monkeypatch.setattr("reprobit.onboarding.verify_msvc42", lambda _root: None)
    monkeypatch.setattr(
        "reprobit.onboarding._backend_failures",
        lambda _backend, *, execute_probe: (),
    )

    assert main(["init", str(project)]) == 0
    capsys.readouterr()
    command = [
        "setup",
        str(project),
        "--toolchain-root",
        str(toolchain),
        "--no-save",
        "--skip-probe",
    ]
    assert main(command) == 0
    first = capsys.readouterr().out
    assert "Environment ready" in first
    assert "Project lock: created" in first
    assert (project / "reprobit" / "toolchain.lock.json").is_file()

    assert main(command) == 0
    second = capsys.readouterr().out
    assert "Project lock: matches" in second
    assert load_project(project).project_id == "sample"

    assert main(["--format", "ndjson", *command]) == 0
    machine_events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    setup = machine_events[-1]
    assert setup["event"] == "setup"
    assert setup["environment_ready"] is True
    assert setup["project_ready"] is False
    assert setup["readiness"][0] == {
        "detail": "project ID sample",
        "id": "project",
        "label": "Project",
        "next_command": None,
        "ready": True,
    }


def test_setup_requires_init_first(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project with spaces"
    project.mkdir()
    assert main(["setup", str(project), "--no-provision"]) == 2
    error = capsys.readouterr().err
    assert human_command(("rbit", "init", project)) in error
    assert "`" not in error


def test_toolchain_provision_has_a_short_human_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    destination = tmp_path / "installed"

    def provision(path: Path, progress: object = None) -> Path:
        del progress
        path.mkdir(parents=True)
        return path

    monkeypatch.setattr("reprobit.onboarding.provision_msvc42", provision)

    assert (
        main(
            [
                "toolchain",
                "provision",
                "--destination",
                str(destination),
                "--no-save",
            ]
        )
        == 0
    )
    rendered = capsys.readouterr().out
    assert f"Compiler ready at {destination}" in rendered
    assert "Next in a ReproBit project: rbit setup ." in rendered
