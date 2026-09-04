"""Keep the composite action's preflight compatible with the public doctor CLI."""

from __future__ import annotations

import shlex
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_onboarding import _fake_toolchain

import reprobit.onboarding as onboarding
from reprobit.backends import BackendDoctorReport
from reprobit.cli import main
from reprobit.toolchains import ClassicMSVCToolchain


def test_action_doctor_checks_the_selected_project_lock_and_runs_the_backend_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    action = (Path(__file__).parents[1] / "action.yml").read_text(encoding="utf-8")
    step = action.split("    - name: Verify the backend and toolchain\n", 1)[1].split(
        "\n    - name:", 1
    )[0]
    assert "working-directory: ${{ inputs.project-directory }}" in step
    command = shlex.split(step.split("      run: >-\n", 1)[1])
    assert command.pop(0) == "rbit"

    project = tmp_path / "workspace" / "nested project"
    toolchain = _fake_toolchain(tmp_path / "compiler with spaces")
    probes: list[bool] = []

    def doctor(*, execute_probe: bool = False) -> BackendDoctorReport:
        probes.append(execute_probe)
        return BackendDoctorReport("fixture", "fixture", (), execute_probe)

    monkeypatch.setattr(
        onboarding,
        "selected_backend",
        lambda _args: SimpleNamespace(identifier="fixture", doctor=doctor),
    )
    monkeypatch.setattr(onboarding, "verify_msvc42", lambda _root: None)
    assert main(["init", str(project)]) == 0
    assert main(["setup", str(project), "--toolchain-root", str(toolchain), "--skip-probe"]) == 0
    original_lock = (project / "reprobit/toolchain.lock.json").read_bytes()
    probes.clear()
    capsys.readouterr()

    checked_locks: list[object] = []
    real_doctor = ClassicMSVCToolchain.doctor

    def check_locked_toolchain(installation: ClassicMSVCToolchain, lock: object = None) -> object:
        assert installation.root == toolchain
        checked_locks.append(lock)
        return real_doctor(installation, lock)  # type: ignore[arg-type]

    monkeypatch.setattr(ClassicMSVCToolchain, "doctor", check_locked_toolchain)
    monkeypatch.chdir(project)
    command = [
        str(toolchain) if argument == "$REPROBIT_TOOLCHAIN_ROOT" else argument
        for argument in command
    ]

    assert main(command) == 0
    assert probes == [True]
    assert len(checked_locks) == 1
    assert checked_locks[0] is not None
    assert "ok project/schema:" in capsys.readouterr().out
    assert (project / "reprobit/toolchain.lock.json").read_bytes() == original_lock
