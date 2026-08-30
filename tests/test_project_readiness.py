from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from reprobit.cli import main
from reprobit.project_readiness import inspect_project_readiness, render_project_readiness
from reprobit.schema import BuildPlanDocument
from reprobit.strict_json import canonical_json


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
    assert "source review is incomplete" in rendered
    assert "Build plan" in rendered
    assert f"Place the original at {project / 'reference/program.exe'}" in rendered
    references = next(item for item in readiness.items if item.id == "references")
    build_plan_index = next(
        index for index, item in enumerate(readiness.items) if item.id == "build_plan"
    )
    reference_index = next(
        index for index, item in enumerate(readiness.items) if item.id == "references"
    )
    assert not references.ready
    assert references.next_command is None
    assert reference_index < build_plan_index
    build_plan = next(item for item in readiness.items if item.id == "build_plan")
    assert build_plan.next_command is None
    source_lock = next(item for item in readiness.items if item.id == "source_manifest")
    assert source_lock.next_command == f"rbit source preview --project {project}"
    assert "Build graph" in rendered
    assert "Reference metadata" in rendered
    assert "Protected references" in rendered
    assert f"Next: rbit setup {project}" in rendered

    # Status is useful interactively and returns non-zero for automation.
    assert main(["status", str(project)]) == 1
    captured = capsys.readouterr()
    assert "Compiler lock" in captured.out

    assert main(["--format", "ndjson", "status", str(project)]) == 1
    event = json.loads(capsys.readouterr().out)
    assert event["event"] == "project_readiness"
    assert event["checks"][0] == {
        "detail": "project ID fresh-project",
        "id": "project",
        "label": "Project",
        "next_command": None,
        "ready": True,
    }

    reference = project / "reference/program.exe"
    reference.parent.mkdir()
    reference.write_bytes(b"original")
    with_reference = inspect_project_readiness(project)
    build_plan = next(item for item in with_reference.items if item.id == "build_plan")
    assert build_plan.next_command == f"rbit import cmake {project}"


def test_valid_project_can_have_no_intervention_or_proof_documents(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    example = Path(__file__).parents[1] / "examples/grind"
    shutil.copytree(example, project)
    for directory in ("interventions", "proofs"):
        for document in (project / "reprobit" / directory).glob("*.json"):
            document.unlink()
    plan_path = project / "reprobit/build-plan.json"
    plan = BuildPlanDocument.model_validate_json(plan_path.read_bytes()).model_copy(
        update={"translation_units": (), "source_overlay_interventions": ()}
    )
    plan_path.write_bytes(canonical_json(plan))
    reference = project / "reference/grind.exe"
    reference.parent.mkdir()
    reference.write_bytes(b"reference")

    readiness = inspect_project_readiness(project)

    assert readiness.ready
    checks = {item.id: item for item in readiness.items}
    assert checks["interventions"].detail == (
        "0 documents (valid when no build adjustment is needed)"
    )
    assert checks["proofs"].detail == "0 documents (valid when there is nothing to prove)"
    assert checks["authority"].label == "Final project check"
    assert checks["authority"].detail == "all saved project files agree"
    assert render_project_readiness(readiness) == "Project files ready: 10/10 checks passed"
    assert main(["status", str(project)]) == 0
    assert "Project files ready: 10/10 checks passed" in capsys.readouterr().out


def test_derived_project_id_is_human_and_schema_safe(tmp_path: Path) -> None:
    project = tmp_path / "1997 Some Game!"
    assert main(["init", str(project)]) == 0

    from reprobit.project_loader import load_project

    assert load_project(project).project_id == "project-1997-some-game"
