from __future__ import annotations

import argparse
from pathlib import Path

import pytest
from test_cli import _complete_translation_unit_project

from reprobit.cli import main
from reprobit.cli_output import CLIOutput
from reprobit.cli_paths import CLIError
from reprobit.project_loader import load_project_tree
from reprobit.repair import RepairError, capture_repair_snapshot, collect_repair_candidate
from reprobit.schema import classic_debug_companion_paths


def _authority_bytes(project: Path) -> dict[Path, bytes]:
    return {
        path.relative_to(project): path.read_bytes()
        for path in sorted((project / "reprobit").rglob("*.json"))
    }


def _write_candidate_reports(args: argparse.Namespace) -> None:
    project = Path(args.project)
    bundle = load_project_tree(project)
    for relative in (
        *(target.artifact for target in bundle.spec.targets),
        *(
            relative
            for companion in classic_debug_companion_paths(bundle)
            for relative in (companion.image, companion.pdb)
        ),
    ):
        output = project / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(f"verified:{relative}\n".encode())
    report_directory = project / args.report_dir
    report_directory.mkdir(parents=True, exist_ok=True)
    (report_directory / "report.json").write_bytes(b"{}\n")
    (report_directory / "report.html").write_bytes(b"<!doctype html>\n")


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
        _write_candidate_reports(args)
        return 0

    monkeypatch.setattr("reprobit.cli_repair.command_verify", verify)
    capsys.readouterr()

    assert main(["repair", str(project)]) == 0

    output = capsys.readouterr().out
    assert "Repair complete" in output
    assert len(verified) == 1 and verified[0] != project
    load_project_tree(project)
    assert (project / ".reprobit-state/reports/report.html").is_file()
    assert (project / "out/program.bin").read_bytes() == b"verified:out/program.bin\n"


def test_repair_publishes_reports_to_the_requested_project_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    (project / "src/unit.cpp").write_bytes(b"int main() { return 1; }\n")

    def verify(args: argparse.Namespace, _output: CLIOutput) -> int:
        _write_candidate_reports(args)
        return 0

    monkeypatch.setattr("reprobit.cli_repair.command_verify", verify)
    capsys.readouterr()

    assert main(["repair", str(project), "--report-dir", "build/repair-report"]) == 0

    output = capsys.readouterr().out
    assert str(project / "build/repair-report/report.html") in output
    assert (project / "build/repair-report/report.json").read_bytes() == b"{}\n"
    assert (project / "build/repair-report/report.html").read_bytes() == b"<!doctype html>\n"


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

    message = capsys.readouterr().err
    assert "source edits were kept" in message
    assert "saved project records were not changed" in message
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

    assert "did not satisfy exact verification" in capsys.readouterr().err
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

    def edit_then_accept(args: argparse.Namespace, _output: CLIOutput) -> int:
        unit_authority.write_bytes(concurrent_edit)
        _write_candidate_reports(args)
        return 0

    monkeypatch.setattr("reprobit.cli_repair.command_verify", edit_then_accept)
    capsys.readouterr()

    assert main(["repair", str(project)]) == 2

    message = capsys.readouterr().err
    assert "saved project records were not changed" in message
    assert "preimage conflict" in message
    assert unit_authority.read_bytes() == concurrent_edit


def test_repair_never_overwrites_concurrent_public_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    (project / "src/unit.cpp").write_bytes(b"int main() { return 1; }\n")
    artifact = project / "out/program.bin"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_bytes(b"old output\n")

    def edit_then_accept(args: argparse.Namespace, _output: CLIOutput) -> int:
        _write_candidate_reports(args)
        artifact.write_bytes(b"concurrent output\n")
        return 0

    monkeypatch.setattr("reprobit.cli_repair.command_verify", edit_then_accept)
    capsys.readouterr()

    assert main(["repair", str(project)]) == 2

    message = capsys.readouterr().err
    assert "preimage conflict" in message
    assert artifact.read_bytes() == b"concurrent output\n"


def test_repair_never_overwrites_concurrent_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    (project / "src/unit.cpp").write_bytes(b"int main() { return 1; }\n")
    live_report = project / ".reprobit-state/reports/report.html"
    live_report.parent.mkdir(parents=True, exist_ok=True)
    live_report.write_bytes(b"old report\n")

    def edit_then_accept(args: argparse.Namespace, _output: CLIOutput) -> int:
        _write_candidate_reports(args)
        live_report.write_bytes(b"concurrent report\n")
        return 0

    monkeypatch.setattr("reprobit.cli_repair.command_verify", edit_then_accept)
    capsys.readouterr()

    assert main(["repair", str(project)]) == 2

    message = capsys.readouterr().err
    assert "preimage conflict" in message
    assert live_report.read_bytes() == b"concurrent report\n"


def test_repair_refuses_report_directory_inside_saved_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    called = False

    def verify(_args: argparse.Namespace, _output: CLIOutput) -> int:
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr("reprobit.cli_repair.command_verify", verify)
    capsys.readouterr()

    assert (
        main(
            [
                "repair",
                str(project),
                "--report-dir",
                "reprobit/interventions/reports",
            ]
        )
        == 2
    )

    assert "enters saved authority" in capsys.readouterr().err
    assert not called


def test_repair_refuses_staged_oracle_mutation(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    snapshot = capture_repair_snapshot(project)
    staged = tmp_path / "staged"
    staged.mkdir()
    for source in snapshot.files:
        destination = staged / source.relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.payload)
    oracle = next(
        staged / source.relative_path
        for source in snapshot.files
        if source.relative_path.startswith("reprobit/oracles/")
    )
    oracle.write_bytes(oracle.read_bytes() + b" \n")

    with pytest.raises(RepairError, match="sealed input"):
        collect_repair_candidate(
            snapshot,
            staged,
            report_directory=".candidate-reports",
        )


def test_repair_refuses_staged_oracle_membership_change(tmp_path: Path) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    snapshot = capture_repair_snapshot(project)
    staged = tmp_path / "staged"
    staged.mkdir()
    for source in snapshot.files:
        destination = staged / source.relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.payload)
    extra = staged / "reprobit/oracles/extra.json"
    extra.write_bytes(b"{}\n")

    with pytest.raises(RepairError, match="sealed authority membership"):
        collect_repair_candidate(
            snapshot,
            staged,
            report_directory=".candidate-reports",
        )


def test_repair_reports_cleanup_failure_after_success_truthfully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    (project / "src/unit.cpp").write_bytes(b"int main() { return 1; }\n")

    def verify(args: argparse.Namespace, _output: CLIOutput) -> int:
        _write_candidate_reports(args)
        return 0

    from reprobit.repair import StagedRepairProject

    original_exit = StagedRepairProject.__exit__

    def fail_cleanup(self: StagedRepairProject, *args: object) -> None:
        original_exit(self, *args)  # type: ignore[arg-type]
        raise OSError("simulated cleanup failure")

    monkeypatch.setattr("reprobit.cli_repair.command_verify", verify)
    monkeypatch.setattr(StagedRepairProject, "__exit__", fail_cleanup)
    capsys.readouterr()

    assert main(["repair", str(project)]) == 0

    captured = capsys.readouterr()
    assert "Repair complete" in captured.out
    assert "published and verified" in captured.err
    assert "saved project records were not changed" not in captured.err
    load_project_tree(project)
