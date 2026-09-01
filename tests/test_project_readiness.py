from __future__ import annotations

import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from reprobit.cli import main
from reprobit.cli_output import human_command
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
    assert "run rbit source preview to finish reviewing and locking" in rendered
    assert "Build plan" in rendered
    assert rendered.startswith(f"Project: {project}\n")
    assert "[  ] Protected references: place the original at reference/program.exe" in rendered
    assert "[  ] Compiler lock: run rbit setup to create reprobit/toolchain.lock.json" in rendered
    assert "Final project check" not in rendered
    assert str(project) not in rendered.removeprefix(f"Project: {project}\n").replace(
        f"Next: rbit setup {project}", ""
    )
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
    assert source_lock.next_command == f"rbit source preview {project}"
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
    monkeypatch: pytest.MonkeyPatch,
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
    assert render_project_readiness(readiness) == (
        f"Project: {project}\nProject files ready: 10/10 checks passed"
    )

    local_toolchain = tmp_path / "toolchain"
    local_toolchain.mkdir()
    monkeypatch.setattr(
        "reprobit.project_readiness.resolve_toolchain_root",
        lambda *_args, **_kwargs: local_toolchain,
    )
    monkeypatch.setattr(
        "reprobit.project_readiness.ClassicMSVCToolchain.doctor",
        lambda _self, _lock=None: SimpleNamespace(ok=True, checks=()),
    )
    assert main(["status", str(project)]) == 0
    assert "Project and machine ready: 11/11 checks passed" in capsys.readouterr().out

    assert main(["status", str(project), "--all"]) == 0
    detailed = capsys.readouterr().out
    assert "Project and machine ready: 11/11 checks passed" in detailed
    assert "[ok] Project: project ID grind" in detailed
    assert f"[ok] Local compiler: available at {local_toolchain}" in detailed
    assert "[ok] Final project check: all saved project files agree" in detailed


def test_status_points_a_ready_project_without_a_local_compiler_to_setup(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(Path(__file__).parents[1] / "examples/grind", project)
    reference = project / "reference/grind.exe"
    reference.parent.mkdir()
    reference.write_bytes(b"reference")
    missing = tmp_path / "missing-toolchain"
    monkeypatch.setattr(
        "reprobit.project_readiness.resolve_toolchain_root",
        lambda *_args, **_kwargs: missing,
    )

    assert main(["status", str(project), "--all"]) == 1
    rendered = capsys.readouterr().out
    assert f"[  ] Local compiler: not available on this machine at {missing}" in rendered
    assert f"Next: rbit setup {project}" in rendered


def test_status_rejects_an_empty_local_compiler_directory(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(Path(__file__).parents[1] / "examples/grind", project)
    reference = project / "reference/grind.exe"
    reference.parent.mkdir()
    reference.write_bytes(b"reference")
    empty = tmp_path / "empty-toolchain"
    empty.mkdir()
    monkeypatch.setattr(
        "reprobit.project_readiness.resolve_toolchain_root",
        lambda *_args, **_kwargs: empty,
    )

    assert main(["status", str(project), "--all"]) == 1
    rendered = capsys.readouterr().out
    assert f"[  ] Local compiler: incomplete at {empty}:" in rendered
    assert "absent or unsafe" in rendered
    assert f"Next: rbit setup {project}" in rendered


def test_status_rewrites_source_repair_guidance_for_the_supplied_project(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project with spaces"
    shutil.copytree(Path(__file__).parents[1] / "examples/grind", project)
    reference = project / "reference/grind.exe"
    reference.parent.mkdir()
    reference.write_bytes(b"reference")
    toolchain = tmp_path / "toolchain"
    toolchain.mkdir()
    monkeypatch.setattr(
        "reprobit.project_readiness.resolve_toolchain_root",
        lambda *_args, **_kwargs: toolchain,
    )
    monkeypatch.setattr(
        "reprobit.project_readiness.ClassicMSVCToolchain.doctor",
        lambda _self, _lock=None: SimpleNamespace(ok=True, checks=()),
    )
    (project / "transform.cpp").write_text("int changed;\n", encoding="utf-8")

    assert main(["status", str(project), "--all"]) == 1
    rendered = capsys.readouterr().out
    repair_command = human_command(("rbit", "repair", project))
    assert "source input differs from portable manifest" in rendered
    assert "invalid project tree:" not in rendered
    assert "run rbit repair ." not in rendered
    assert f"Next: {repair_command}" in rendered
    assert rendered.count(repair_command) == 1


def test_derived_project_id_is_human_and_schema_safe(tmp_path: Path) -> None:
    project = tmp_path / "1997 Some Game!"
    assert main(["init", str(project)]) == 0

    from reprobit.project_loader import load_project

    assert load_project(project).project_id == "project-1997-some-game"


def test_status_flags_a_saved_document_that_is_not_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    shutil.copytree(Path(__file__).parents[1] / "examples/grind", project)
    reference = project / "reference/grind.exe"
    reference.parent.mkdir()
    reference.write_bytes(b"reference")
    monkeypatch.setattr(
        "reprobit.project_readiness.resolve_toolchain_root",
        lambda *_args, **_kwargs: tmp_path / "missing-toolchain",
    )
    document = project / "reprobit/interventions/program.json"
    document.write_bytes(document.read_bytes()[:20])

    assert main(["status", str(project)]) == 1
    rendered = capsys.readouterr().out
    assert (
        "[!!] Interventions: reprobit/interventions/program.json is not valid JSON; "
        "run rbit validate"
    ) in rendered
    assert "Final project check" not in rendered
    checks = {item.id: item for item in inspect_project_readiness(project).items}
    assert not checks["interventions"].ready
    assert checks["interventions"].next_command == f"rbit validate {project}"
    assert checks["authority"].pending
    assert checks["authority"].detail == "not checked until the project files above are ready"
