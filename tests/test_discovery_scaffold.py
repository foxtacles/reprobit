from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import reprobit.discovery_grind_cli as discovery_grind_cli
from reprobit.cli import main
from reprobit.discovery_project import ProjectGrindPlan


def test_cli_creates_a_ready_to_grind_project_plan_without_compiling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    reference = tmp_path / "reference" / "widget.obj"
    reference.parent.mkdir()
    reference.write_bytes(b"sealed COFF fixture")
    unit = SimpleNamespace(
        id="tu.widget",
        source="src/widget.cpp",
        target_id="widget",
    )
    bundle = SimpleNamespace(
        build_plan=SimpleNamespace(translation_units=(unit,)),
    )
    monkeypatch.setattr(discovery_grind_cli, "load_project_tree", lambda _root: bundle)

    assert (
        main(
            [
                "discover",
                "init",
                str(tmp_path),
                "--source",
                "src/widget.cpp",
                "--reference",
                "reference/widget.obj",
                "--symbol",
                "?Transform@Widget@@QAEHH@Z",
                "--plan",
                "plans/widget.json",
            ]
        )
        == 0
    )

    plan_path = tmp_path / "plans" / "widget.json"
    plan = ProjectGrindPlan.model_validate_json(plan_path.read_bytes())
    assert plan.translation_unit == "tu.widget"
    assert plan.target == "widget"
    assert plan.symbol == "?Transform@Widget@@QAEHH@Z"
    rendered = capsys.readouterr().out
    assert "No compiler was run" in rendered
    assert f"Next: rbit discover grind {tmp_path} --plan plans/widget.json" in rendered


def test_grind_help_does_not_promise_workspace_retention(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["discover", "grind", "--help"])

    assert raised.value.code == 0
    rendered = capsys.readouterr().out
    assert "--keep-workspace" not in rendered
    assert "--project-wide" in rendered
    assert "--reference-object TU=PROJECT_PATH" in rendered
    assert "--max-symbols COUNT" in rendered


def test_cli_grind_plan_scaffold_refuses_to_overwrite_an_existing_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    reference = tmp_path / "reference.obj"
    reference.write_bytes(b"sealed COFF fixture")
    destination = tmp_path / "reprobit" / "discovery.json"
    destination.parent.mkdir()
    destination.write_bytes(b"existing plan")
    unit = SimpleNamespace(id="tu.unit", source="unit.cpp", target_id="program")
    bundle = SimpleNamespace(
        build_plan=SimpleNamespace(translation_units=(unit,)),
    )
    monkeypatch.setattr(discovery_grind_cli, "load_project_tree", lambda _root: bundle)

    assert (
        main(
            [
                "discover",
                "init",
                str(tmp_path),
                "--source",
                "unit.cpp",
                "--reference",
                "reference.obj",
                "--symbol",
                "_unit",
            ]
        )
        == 2
    )
    assert destination.read_bytes() == b"existing plan"
    error = capsys.readouterr().err
    assert "transaction preimage conflict" in error
    assert "expected None" in error
