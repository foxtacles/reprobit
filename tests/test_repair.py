from __future__ import annotations

import argparse
from pathlib import Path

import pytest
from test_cli import _complete_translation_unit_project

from reprobit.cli import main
from reprobit.cli_output import CLIOutput
from reprobit.cli_paths import CLIError
from reprobit.project_loader import load_project_tree


def _authority_bytes(project: Path) -> dict[Path, bytes]:
    return {
        path.relative_to(project): path.read_bytes()
        for path in sorted((project / "reprobit").rglob("*.json"))
    }


def test_repair_refreshes_source_records_and_verifies_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    edited = b"int main() { return 1; }\n"
    (project / "src/unit.cpp").write_bytes(edited)
    verified: list[Path] = []

    def verify(args: argparse.Namespace, _output: CLIOutput) -> int:
        root = Path(args.project)
        load_project_tree(root)
        verified.append(root)
        return 0

    monkeypatch.setattr("reprobit.cli_repair.command_verify", verify)
    capsys.readouterr()

    assert main(["repair", str(project)]) == 0

    output = capsys.readouterr().out
    assert "Repair complete" in output
    assert verified == [project]
    load_project_tree(project)


def test_repair_restores_authority_when_exact_verification_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    edited = b"int main() { return 1; }\n"
    (project / "src/unit.cpp").write_bytes(edited)
    before = _authority_bytes(project)

    def reject(_args: argparse.Namespace, _output: CLIOutput) -> int:
        raise CLIError("candidate output differs")

    monkeypatch.setattr("reprobit.cli_repair.command_verify", reject)
    capsys.readouterr()

    assert main(["repair", str(project)]) == 2

    assert "restored" in capsys.readouterr().err
    assert _authority_bytes(project) == before
    assert (project / "src/unit.cpp").read_bytes() == edited


def test_repair_restores_authority_when_verification_returns_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    edited = b"int main() { return 1; }\n"
    (project / "src/unit.cpp").write_bytes(edited)
    before = _authority_bytes(project)

    monkeypatch.setattr("reprobit.cli_repair.command_verify", lambda *_args: 1)
    capsys.readouterr()

    assert main(["repair", str(project)]) == 2

    assert "did not pass exact verification" in capsys.readouterr().err
    assert _authority_bytes(project) == before
    assert (project / "src/unit.cpp").read_bytes() == edited


def test_repair_never_overwrites_concurrent_authority_edits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    (project / "src/unit.cpp").write_bytes(b"int main() { return 1; }\n")
    unit_authority = project / "reprobit/interventions/unit.json"
    concurrent_edit = unit_authority.read_bytes() + b" \n"

    def edit_then_reject(_args: argparse.Namespace, _output: CLIOutput) -> int:
        unit_authority.write_bytes(concurrent_edit)
        raise CLIError("candidate output differs")

    monkeypatch.setattr("reprobit.cli_repair.command_verify", edit_then_reject)
    capsys.readouterr()

    assert main(["repair", str(project)]) == 2

    message = capsys.readouterr().err
    assert "could not restore" in message
    assert "changed concurrently" in message
    assert unit_authority.read_bytes() == concurrent_edit
