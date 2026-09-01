from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from reprobit.cli import main
from reprobit.discovery_contracts import (
    DiscoveryCampaignReport,
    DiscoveryFindingKind,
)
from reprobit.model import Digest

TARGET = "_transform"


@pytest.mark.msvc42
def test_msvc42_discovery_cold_resume_and_one_cell_extension(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    configured = os.environ.get("REPROBIT_MSVC_4_2_ROOT")
    if configured is None:
        pytest.skip("set REPROBIT_MSVC_4_2_ROOT to run MSVC 4.2 discovery")
    root = Path(configured).resolve(strict=True)
    if os.name == "posix":
        if shutil.which("wine") is None or shutil.which("wineserver") is None:
            pytest.skip("the configured MSVC 4.2 installation requires Wine")
    elif os.name != "nt":
        pytest.skip("MSVC 4.2 discovery supports POSIX/Wine and native Windows")
    sample = Path(__file__).parents[1] / "examples" / "declaration-discovery"
    for name in ("campaign.json", "campaign-extended.json", "transform.cpp"):
        shutil.copyfile(sample / name, tmp_path / name)
    prepared = subprocess.run(
        (
            sys.executable,
            sample / "prepare_reference.py",
            "--toolchain-root",
            root,
            "--request",
            tmp_path / "campaign.json",
        ),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert prepared.returncode == 0, prepared.stderr
    assert (tmp_path / "reference.obj").is_file()

    base_command = (
        "--format",
        "ndjson",
        "discover",
        "run",
        os.fspath(tmp_path / "campaign.json"),
        "--toolchain-root",
        os.fspath(root),
        "--state-directory",
        ".sample-state",
        "--report-json",
        "campaign.report.json",
        "--jobs",
        "4",
    )

    assert main(list(base_command)) == 0
    first_events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    cold = DiscoveryCampaignReport.model_validate_json(
        (tmp_path / "campaign.report.json").read_bytes()
    )
    reviewed = subprocess.run(
        (
            sys.executable,
            sample / "review_report.py",
            tmp_path / "campaign.report.json",
        ),
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert reviewed.returncode == 0, reviewed.stderr
    assert reviewed.stdout.startswith("NON-CERTIFYING DISCOVERY REVIEW")
    assert "whole_body: _transform" in reviewed.stdout
    assert main(list(base_command)) == 0
    capsys.readouterr()
    resumed = DiscoveryCampaignReport.model_validate_json(
        (tmp_path / "campaign.report.json").read_bytes()
    )
    extended_command = list(base_command)
    extended_command[4] = os.fspath(tmp_path / "campaign-extended.json")
    extended_command[10] = "campaign-extended.report.json"
    assert main(extended_command) == 0
    capsys.readouterr()
    extended = DiscoveryCampaignReport.model_validate_json(
        (tmp_path / "campaign-extended.report.json").read_bytes()
    )

    assert (cold.cells_built, cold.cells_cached) == (4, 0)
    assert (resumed.cells_built, resumed.cells_cached) == (0, 4)
    assert (extended.cells_built, extended.cells_cached) == (1, 4)
    assert any(proposal.kind is DiscoveryFindingKind.WHOLE_BODY for proposal in cold.proposals)
    whole_body = next(
        proposal for proposal in cold.proposals if proposal.kind is DiscoveryFindingKind.WHOLE_BODY
    )
    selected = {item.state_id: item.state for item in cold.selected_states}
    assert len(whole_body.state_ids) == 1
    assert selected[whole_body.state_ids[0]].parameter("classes") == 3
    assert selected[whole_body.state_ids[0]].parameter("functions") == 10
    assert all(
        {item.symbol for item in observation.functions} >= {TARGET}
        for observation in cold.observations
    )
    assert cold.artifacts
    assert cold.selected_states
    assert {item.role.value for item in cold.inputs} == {"request", "source", "reference"}
    assert cold.compiler.arguments == ("/nologo", "/O2", "/Ob1", "/Gy", "/Z7")
    assert Path(cold.compiler.executable).name.casefold() in {"cl", "cl.exe"}
    for artifact in cold.artifacts:
        exported = tmp_path / artifact.logical_path
        assert exported.is_file()
        assert Digest.from_path(exported) == artifact.object
        assert exported.stat().st_size == artifact.object_size
    assert any(event.get("kind") == "cache_miss" for event in first_events)
    assert {
        event.get("phase") for event in first_events if event.get("kind") == "phase_started"
    } >= {"discovery-compile", "discovery-analyze", "discovery-finalize"}
    final = next(event for event in first_events if event["event"] == "discovery_complete")
    assert final["built"] == 4
    assert final["proposals"] >= 1
    assert final["reused"] == 0
    assert final["applied"] is False
    assert final["report_json"] == "campaign.report.json"
    assert final["report_html"] == "campaign.report.html"
    assert "report_json_digest" in final
    assert "report_html_digest" in final
    rendered = (tmp_path / "campaign.report.html").read_text(encoding="utf-8")
    assert "Discovery preview" in rendered
    assert 'href="campaign.report.json"' in rendered
