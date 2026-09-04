from __future__ import annotations

import json
from pathlib import Path

import pytest

import reprobit.onboarding as onboarding
from reprobit.backends import BackendDoctorReport
from reprobit.cli import main
from reprobit.cli_output import human_command
from reprobit.project_loader import load_project
from reprobit.toolchains import (
    MSVC_42,
    TOOLCHAIN_PROFILES,
    ClassicMSVCToolchain,
    ToolchainDoctorReport,
)


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
    doctor_calls = 0
    real_doctor = ClassicMSVCToolchain.doctor

    def counted_doctor(
        installation: ClassicMSVCToolchain,
        lock: object = None,
    ) -> object:
        nonlocal doctor_calls
        doctor_calls += 1
        return real_doctor(installation, lock)  # type: ignore[arg-type]

    monkeypatch.setattr(ClassicMSVCToolchain, "doctor", counted_doctor)

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
    assert setup["next_argv"] == ["rbit", "source", "preview", str(project)]
    assert setup["next_command"] == human_command(setup["next_argv"])
    assert setup["readiness"][0] == {
        "detail": "project ID sample",
        "id": "project",
        "label": "Project",
        "next_argv": [],
        "next_command": None,
        "ready": True,
    }
    # The first setup validates once before creating the lock and once against
    # the new lock. Later setup runs validate only once; readiness reuses it.
    assert doctor_calls == 4


def test_doctor_checks_the_compiler_remembered_for_the_project(
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
    assert (
        main(
            [
                "setup",
                str(project),
                "--toolchain-root",
                str(toolchain),
                "--skip-probe",
            ]
        )
        == 0
    )
    capsys.readouterr()

    class PassingBackend:
        identifier = "fixture"

        @staticmethod
        def doctor(*, execute_probe: bool = False) -> BackendDoctorReport:
            return BackendDoctorReport("fixture", "fixture", (), execute_probe)

    monkeypatch.setattr(onboarding, "selected_backend", lambda _args: PassingBackend())
    explicit_roots: list[object] = []
    real_resolve = onboarding.resolve_toolchain_root

    def observed_resolve(profile: object, explicit: object = None) -> Path:
        explicit_roots.append(explicit)
        return real_resolve(profile, explicit)  # type: ignore[arg-type]

    monkeypatch.setattr(onboarding, "resolve_toolchain_root", observed_resolve)

    assert main(["doctor", str(project)]) == 0

    rendered = capsys.readouterr().out
    assert explicit_roots == [None]
    assert "ok project/schema: sample" in rendered
    assert "doctor checks passed" in rendered


def test_doctor_without_a_project_is_explicitly_host_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class PassingBackend:
        identifier = "fixture"

        @staticmethod
        def doctor(*, execute_probe: bool = False) -> BackendDoctorReport:
            return BackendDoctorReport("fixture", "fixture", (), execute_probe)

    monkeypatch.setattr(onboarding, "selected_backend", lambda _args: PassingBackend())

    assert main(["doctor"]) == 0
    assert "host checks passed; no project compiler was checked" in capsys.readouterr().out


def test_projectless_doctor_checks_the_compiler_remembered_for_a_profile(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class PassingBackend:
        identifier = "fixture"

        @staticmethod
        def doctor(*, execute_probe: bool = False) -> BackendDoctorReport:
            return BackendDoctorReport("fixture", "fixture", (), execute_probe)

    remembered = tmp_path / "remembered-toolchain"
    remembered.mkdir()
    observed: list[tuple[object, object]] = []

    def resolve(profile: object, explicit: object = None) -> Path:
        observed.append((profile, explicit))
        return remembered

    monkeypatch.setattr(onboarding, "selected_backend", lambda _args: PassingBackend())
    monkeypatch.setattr(onboarding, "resolve_toolchain_root", resolve)
    monkeypatch.setattr(
        ClassicMSVCToolchain,
        "doctor",
        lambda installation: ToolchainDoctorReport(
            installation.profile.identifier,
            installation.root,
            (),
        ),
    )

    assert main(["doctor", "--profile", MSVC_42]) == 0

    assert observed == [(MSVC_42, None)]
    rendered = capsys.readouterr().out
    assert "doctor checks passed" in rendered
    assert "no project compiler was checked" not in rendered


def test_projectless_doctor_reports_a_missing_toolchain_as_a_failed_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class PassingBackend:
        identifier = "fixture"

        @staticmethod
        def doctor(*, execute_probe: bool = False) -> BackendDoctorReport:
            return BackendDoctorReport("fixture", "fixture", (), execute_probe)

    monkeypatch.setattr(onboarding, "selected_backend", lambda _args: PassingBackend())
    missing = tmp_path / "missing-toolchain"

    assert (
        main(
            [
                "--format",
                "ndjson",
                "doctor",
                "--profile",
                MSVC_42,
                "--toolchain-root",
                str(missing),
            ]
        )
        == 1
    )

    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    failure = next(event for event in events if event["event"] == "doctor_check")
    assert failure["component"] == "toolchain"
    assert failure["name"] == "root"
    assert failure["passed"] is False
    assert events[-1]["event"] == "doctor_result"
    assert events[-1]["passed"] is False


def test_doctor_rejects_an_explicit_non_project(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing = tmp_path / "not-a-project"

    assert main(["doctor", str(missing)]) == 2
    assert f"no ReproBit project found at {missing / 'reprobit.toml'}" in capsys.readouterr().err


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
