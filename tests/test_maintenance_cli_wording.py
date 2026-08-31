from __future__ import annotations

from pathlib import Path

import pytest
from test_cli import _complete_translation_unit_project

from reprobit.cli import main


def test_repair_help_identifies_the_everyday_source_edit_workflow(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["repair", "--help"])

    assert stopped.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "already part of the project" in help_text
    assert "shared header used by many source files" in help_text
    assert "For added or removed files, use source preview and source lock first" in help_text


def test_source_regenerate_help_marks_it_as_an_advanced_preview_primitive(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as stopped:
        main(["source", "regenerate", "--help"])

    assert stopped.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "Advanced maintenance tool" in help_text
    assert "normally run rbit repair . instead" in help_text
    assert "does not build or verify the project" in help_text
    assert "preview without writing" in help_text


def test_source_regenerate_uses_future_tense_for_preview_and_past_tense_for_apply(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    capsys.readouterr()
    (project / "src/unit.cpp").write_bytes(b"int main() { return 1; }\n")

    assert main(["source", "regenerate", "--project", str(project)]) == 0
    preview = capsys.readouterr().out
    assert "Source-check preview" in preview
    assert "would be saved" in preview
    assert "no project files changed" in preview

    assert main(["source", "regenerate", "--project", str(project), "--apply"]) == 0
    applied = capsys.readouterr().out
    assert "Source checks refreshed" in applied
    assert "update(s) saved" in applied
    assert "would be saved" not in applied


def test_source_regenerate_plainly_reports_when_no_update_is_needed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    _complete_translation_unit_project(project)
    capsys.readouterr()

    assert main(["source", "regenerate", "--project", str(project)]) == 0
    assert (
        "No source-check updates are needed; saved records already match current files."
        in capsys.readouterr().out
    )
