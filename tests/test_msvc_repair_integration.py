from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from reprobit.costs import calculate_cost
from reprobit.model import Digest
from reprobit.project_loader import load_project_tree
from reprobit.report import CacheMode, Report
from reprobit.schema import (
    ClassicDebugCompanionPaths,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
    classic_debug_companion_paths,
    source_manifest_digest,
)

ROOT = Path(__file__).parents[1]
SAMPLE = ROOT / "examples" / "repair"
REFERENCE_IMAGE_SHA256 = "eef3d6d69f7b8db8666973ec6533a849fe5230e03b2d6c4a91053dc897a31f62"

pytestmark = [
    pytest.mark.msvc42,
    pytest.mark.skipif(
        not os.environ.get("REPROBIT_MSVC_4_2_ROOT"),
        reason="requires an authenticated MSVC 4.2 CI lane",
    ),
]


def _rbit() -> Path:
    name = "rbit.exe" if os.name == "nt" else "rbit"
    beside_python = Path(sys.executable).parent / name
    if beside_python.is_file():
        return beside_python
    discovered = shutil.which(name)
    assert discovered is not None, "the installed public rbit entry point is unavailable"
    return Path(discovered).resolve(strict=True)


def _run(
    argv: tuple[os.PathLike[str] | str, ...],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        tuple(str(item) for item in argv),
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=600,
    )


def _events(completed: subprocess.CompletedProcess[str]) -> list[dict[str, Any]]:
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not completed.stderr.strip(), completed.stderr
    events: list[dict[str, Any]] = []
    for line in completed.stdout.splitlines():
        value = json.loads(line)
        assert isinstance(value, dict)
        events.append(value)
    assert events, "the public CLI emitted no progress or completion events"
    return events


def _published_bytes(project: Path) -> dict[str, bytes]:
    relatives = {
        path.relative_to(project).as_posix() for path in (project / "reprobit").rglob("*.json")
    }
    relatives.update(
        {
            "build/repair.exe",
            ".reprobit-state/reports/report.html",
            ".reprobit-state/reports/report.json",
        }
    )
    relatives.update(
        path.relative_to(project).as_posix()
        for path in (project / "build/reprobit-debug").rglob("*")
        if path.is_file()
    )
    return {
        relative: (project / relative).read_bytes()
        for relative in sorted(relatives, key=lambda item: (item.casefold(), item))
    }


def test_authenticated_msvc42_repair_handles_shared_header_and_publishes_atomically(
    tmp_path: Path,
) -> None:
    configured = os.environ.get("REPROBIT_MSVC_4_2_ROOT")
    assert configured, "CI must provision REPROBIT_MSVC_4_2_ROOT"
    toolchain_root = Path(configured).resolve(strict=True)

    project = tmp_path / "repair"
    shutil.copytree(
        SAMPLE,
        project,
        ignore=shutil.ignore_patterns(
            "__pycache__",
            ".reprobit-state",
            ".reprobit-transactions",
            "build",
            "reference",
        ),
    )
    environment = os.environ.copy()
    environment["REPROBIT_MSVC_4_2_ROOT"] = os.fspath(toolchain_root)
    environment["PYTHONUTF8"] = "1"

    prepared = _run(
        (
            sys.executable,
            project / "prepare_reference.py",
            "--toolchain-root",
            toolchain_root,
        ),
        cwd=project,
        environment=environment,
    )
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr
    reference = project / "reference" / "repair.exe"
    assert Digest.from_path(reference).value == REFERENCE_IMAGE_SHA256

    initial = load_project_tree(project)
    assert {unit.id for unit in initial.build_plan.translation_units} == {
        "tu.support",
        "tu.transform",
    }
    assert calculate_cost(initial.interventions).project_total == 31
    assert classic_debug_companion_paths(initial) == (
        ClassicDebugCompanionPaths(
            target_id="program",
            image="build/reprobit-debug/repair.exe",
            pdb="build/reprobit-debug/repair.PDB",
        ),
    )
    classic = tuple(
        item for item in initial.interventions if isinstance(item, ClassicRecipeIntervention)
    )
    assert {item.role for item in classic} == {
        ClassicRecipeRole.PROJECT,
        ClassicRecipeRole.DONOR,
        ClassicRecipeRole.FUNCTION,
    }
    graph = json.loads((project / "reprobit/producer-graph.json").read_bytes())
    compiler_nodes = tuple(node for node in graph["nodes"] if node["role"] == "compiler")
    assert {node["id"] for node in compiler_nodes} == {
        "compiler.repair.0000",
        "compiler.repair.0001",
    }
    for source in (project / "support.cpp", project / "transform.cpp"):
        assert '#include "shared.h"' in source.read_text(encoding="utf-8")

    verification = _run(
        (_rbit(), "--format", "ndjson", "verify", project),
        cwd=project,
        environment=environment,
    )
    initial_events = _events(verification)
    initial_complete = [event for event in initial_events if event.get("event") == "verification"]
    assert len(initial_complete) == 1
    assert initial_complete[0]["accepted"] is True
    assert initial_complete[0]["targets"] == initial_complete[0]["exact_targets"] == 1
    assert {
        path.name for path in (project / "build/reprobit-debug").iterdir() if path.is_file()
    } == {"repair.exe", "repair.PDB"}

    guidance_before = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for directory in ("interventions", "proofs")
        for path in sorted((project / "reprobit" / directory).glob("*.json"))
    }
    graph_before = (project / "reprobit/producer-graph.json").read_bytes()
    plan_before = (project / "reprobit/build-plan.json").read_bytes()
    manifest_before = (project / "reprobit/source-manifest.json").read_bytes()

    shared_header = project / "shared.h"
    original_header = shared_header.read_text(encoding="utf-8")
    harmless_header = original_header.replace(
        "#define REPAIR_IDENTITY(value) (value)",
        "class RepairUnusedForward;\n#define REPAIR_IDENTITY(value) (value)",
    )
    assert harmless_header != original_header
    shared_header.write_text(harmless_header, encoding="utf-8", newline="\n")

    repaired = _run(
        (_rbit(), "--format", "ndjson", "repair", project),
        cwd=project,
        environment=environment,
    )
    repair_events = _events(repaired)
    repair_complete = [event for event in repair_events if event.get("event") == "repair_complete"]
    assert len(repair_complete) == 1
    completion = repair_complete[0]
    assert completion["exact"] is True
    assert completion["source_inputs"] == 3
    assert completion["donor_retunes"] == 0
    assert completion["retired_actions"] == 1
    assert completion["removed_donors"] == 1
    assert completion["repaired_translation_units"] == 1
    assert completion["compiler_candidates"] == 0
    assert completion["changed_records"] == [
        "reprobit/build-plan.json",
        "reprobit/interventions/tu.transform.json",
        "reprobit/proofs/tu.transform.json",
        "reprobit/source-manifest.json",
    ]
    assert completion["transaction_id"]

    assert Digest.from_path(project / "build/repair.exe") == Digest.from_path(reference)
    assert (project / "reprobit/build-plan.json").read_bytes() != plan_before
    assert (project / "reprobit/source-manifest.json").read_bytes() != manifest_before
    assert (project / "reprobit/producer-graph.json").read_bytes() == graph_before
    changed_guidance = {
        "reprobit/interventions/tu.transform.json",
        "reprobit/proofs/tu.transform.json",
    }
    assert all(
        ((project / relative).read_bytes() != payload) == (relative in changed_guidance)
        for relative, payload in guidance_before.items()
    )

    repaired_bundle = load_project_tree(project)
    repaired_classic = tuple(
        item
        for item in repaired_bundle.interventions
        if isinstance(item, ClassicRecipeIntervention)
    )
    assert [(item.id, item.role) for item in repaired_classic] == [
        ("project.metadata", ClassicRecipeRole.PROJECT)
    ]
    assert calculate_cost(repaired_bundle.interventions).project_total == 5

    report_path = project / ".reprobit-state/reports/report.json"
    report = Report.model_validate_json(report_path.read_bytes())
    assert report.verdict.cold is True
    assert report.verdict.byte_exact is True
    assert report.verdict.logic_certified is True
    assert report.verdict.toolchain_origin is True
    assert report.verdict.clean is True
    assert report.cache.mode is CacheMode.BYPASSED
    assert report.cache.hits == report.cache.misses == 0
    assert report.costs.project_total == 5

    authority_after_first_repair = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in (project / "reprobit").rglob("*.json")
    }
    transform = project / "transform.cpp"
    transform_before_comment = transform.read_text(encoding="utf-8")
    transform.write_text(
        transform_before_comment + "\n// A source-only edit should need no repair search.\n",
        encoding="utf-8",
        newline="\n",
    )
    no_search = _run(
        (_rbit(), "--format", "ndjson", "repair", project),
        cwd=project,
        environment=environment,
    )
    no_search_events = _events(no_search)
    no_search_complete = [
        event for event in no_search_events if event.get("event") == "repair_complete"
    ]
    assert len(no_search_complete) == 1
    no_search_completion = no_search_complete[0]
    assert no_search_completion["exact"] is True
    assert no_search_completion["compiler_candidates"] == 0
    assert no_search_completion["donor_retunes"] == 0
    assert no_search_completion["retired_actions"] == 0
    expected_no_search_changes = [
        "reprobit/build-plan.json",
        "reprobit/interventions/tu.transform.json",
        "reprobit/source-manifest.json",
    ]
    assert no_search_completion["changed_records"] == expected_no_search_changes
    assert no_search_completion["transaction_id"]
    assert no_search_completion["transaction_id"] != completion["transaction_id"]
    assert Digest.from_path(project / "build/repair.exe") == Digest.from_path(reference)

    authority_after_no_search = {
        path.relative_to(project).as_posix(): path.read_bytes()
        for path in (project / "reprobit").rglob("*.json")
    }
    assert authority_after_no_search.keys() == authority_after_first_repair.keys()
    assert {
        relative
        for relative in authority_after_no_search
        if authority_after_no_search[relative] != authority_after_first_repair[relative]
    } == set(expected_no_search_changes)
    no_search_bundle = load_project_tree(project)
    assert no_search_bundle.source_manifest is not None
    assert no_search_bundle.build_plan is not None
    assert repaired_bundle.build_plan is not None
    current_source_digest = Digest.from_path(transform)
    expected_units = tuple(
        unit.model_copy(update={"source_digest": current_source_digest})
        if unit.id == "tu.transform"
        else unit
        for unit in repaired_bundle.build_plan.translation_units
    )
    assert no_search_bundle.build_plan == repaired_bundle.build_plan.model_copy(
        update={
            "source_manifest_digest": source_manifest_digest(no_search_bundle.source_manifest),
            "translation_units": expected_units,
        }
    )
    transform_shard = next(
        document
        for document in no_search_bundle.intervention_documents
        if document.translation_unit_id == "tu.transform"
    )
    prior_transform_shard = next(
        document
        for document in repaired_bundle.intervention_documents
        if document.translation_unit_id == "tu.transform"
    )
    assert transform_shard.interventions == ()
    assert transform_shard == prior_transform_shard.model_copy(
        update={"source_digest": current_source_digest}
    )
    assert no_search_bundle.proof_documents == repaired_bundle.proof_documents
    no_search_report = Report.model_validate_json(report_path.read_bytes())
    assert no_search_report.verdict.cold is True
    assert no_search_report.verdict.byte_exact is True
    assert no_search_report.cache.mode is CacheMode.BYPASSED

    published_after_success = _published_bytes(project)
    semantic_header = harmless_header.replace(
        "#define REPAIR_SUPPORT_BIAS 1",
        "#define REPAIR_SUPPORT_BIAS 2",
    )
    assert semantic_header != harmless_header
    shared_header.write_text(semantic_header, encoding="utf-8", newline="\n")

    refused = _run(
        (_rbit(), "--format", "ndjson", "repair", project),
        cwd=project,
        environment=environment,
    )
    assert refused.returncode != 0, refused.stdout + refused.stderr
    refusal_output = refused.stdout + refused.stderr
    assert "did not publish its staged project records or outputs" in refusal_output
    assert _published_bytes(project) == published_after_success
    assert shared_header.read_text(encoding="utf-8") == semantic_header
