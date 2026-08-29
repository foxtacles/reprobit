from __future__ import annotations

from pathlib import Path

import pytest

from reprobit.cli import main
from reprobit.project_readiness import inspect_project_readiness, render_project_readiness


def test_readiness_points_an_empty_directory_to_init(tmp_path: Path) -> None:
    readiness = inspect_project_readiness(tmp_path)

    assert not readiness.ready
    assert readiness.items[0].id == "project"
    assert readiness.next_command == f"rbit init {tmp_path}"


def test_fresh_init_reports_all_remaining_authority_at_once(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "fresh-project"
    assert main(["init", str(project)]) == 0

    readiness = inspect_project_readiness(project)
    rendered = render_project_readiness(readiness)

    assert not readiness.ready
    assert readiness.items[0].ready
    assert "Compiler lock" in rendered
    assert "Build plan" in rendered
    assert "Build graph" in rendered
    assert "Reference metadata" in rendered
    assert "Protected references" in rendered
    assert f"Next: rbit setup {project}" in rendered

    # Status is useful interactively and returns non-zero for automation.
    assert main(["status", str(project)]) == 1
    captured = capsys.readouterr()
    assert "Compiler lock" in captured.out


def test_derived_project_id_is_human_and_schema_safe(tmp_path: Path) -> None:
    project = tmp_path / "1997 LEGO Island!"
    assert main(["init", str(project)]) == 0

    from reprobit.project_loader import load_project

    assert load_project(project).project_id == "project-1997-lego-island"
