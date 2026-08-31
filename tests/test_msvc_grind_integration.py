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
    ClassicRecipeFamily,
    ClassicRecipeIntervention,
    ClassicRecipeRole,
)

ROOT = Path(__file__).parents[1]
SAMPLE = ROOT / "examples" / "grind"
PROGRESS_SAMPLE = ROOT / "examples" / "grind-progress"
REFERENCE_BODY_SHA256 = "0592ba1107856e319c261ed45129ab9b518486acbde960ada58b2ace9435ccfb"
REFERENCE_IMAGE_SHA256 = "9c78bd9cfe3c8ded8a9a587165237d2a394719b48be34021a3cb09aff8220aab"

pytestmark = pytest.mark.skipif(
    not os.environ.get("REPROBIT_MSVC_4_2_ROOT"),
    reason="requires an authenticated MSVC 4.2 installation",
)


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


def _classic(bundle: Any) -> tuple[ClassicRecipeIntervention, ...]:
    return tuple(
        item for item in bundle.interventions if isinstance(item, ClassicRecipeIntervention)
    )


def _parameters(intervention: ClassicRecipeIntervention) -> dict[str, Any]:
    return {item.name: item.value for item in intervention.parameters}


@pytest.mark.skipif(os.name != "nt", reason="covers the native Windows compiler transport")
def test_native_msvc42_grind_publishes_minimal_authority_then_cold_verifies(
    tmp_path: Path,
) -> None:
    # This is mandatory in the authenticated native-msvc42 job; the module
    # marker keeps ordinary developer test runs portable on other hosts.
    assert os.name == "nt", "this contract must run on the native Windows lane"
    configured = os.environ.get("REPROBIT_MSVC_4_2_ROOT")
    assert configured, "native CI must provision REPROBIT_MSVC_4_2_ROOT"
    toolchain_root = Path(configured).resolve(strict=True)

    project = tmp_path / "grind"
    shutil.copytree(
        SAMPLE,
        project,
        ignore=shutil.ignore_patterns(
            "__pycache__",
            ".reprobit-discovery",
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
    reference_object = project / "reference" / "reference.obj"
    reference_image = project / "reference" / "grind.exe"
    assert reference_object.is_file()
    assert Digest.from_path(reference_image).value == REFERENCE_IMAGE_SHA256

    initial = load_project_tree(project)
    initial_classic = _classic(initial)
    assert len(initial_classic) == 1
    assert initial_classic[0].family is ClassicRecipeFamily.IMAGE_METADATA
    assert initial_classic[0].role is ClassicRecipeRole.PROJECT
    assert not any(
        item.role in {ClassicRecipeRole.DONOR, ClassicRecipeRole.FUNCTION}
        for item in initial_classic
    )
    assert calculate_cost(initial.interventions).project_total == 5

    immutable_authority = (
        "reprobit.toml",
        "reprobit/build-plan.json",
        "reprobit/discovery.json",
        "reprobit/interventions/program.json",
        "reprobit/oracles/program.json",
        "reprobit/producer-graph.json",
        "reprobit/proofs/program.proof.json",
        "reprobit/source-manifest.json",
        "reprobit/toolchain.lock.json",
    )
    before = {relative: Digest.from_path(project / relative) for relative in immutable_authority}
    tu_interventions = project / "reprobit" / "interventions" / "tu.transform.json"
    tu_proofs = project / "reprobit" / "proofs" / "tu.transform.proof.json"
    initial_tu_digests = (Digest.from_path(tu_interventions), Digest.from_path(tu_proofs))

    grind = _run(
        (
            _rbit(),
            "--format",
            "ndjson",
            "discover",
            "grind",
            project,
            "--accept-exact",
        ),
        cwd=project,
        environment=environment,
    )
    grind_events = _events(grind)
    completed = [
        event for event in grind_events if event.get("event") == "discovery_project_grind_complete"
    ]
    assert len(completed) == 1
    assert completed[0]["published_symbols"] == 1
    assert completed[0]["exact_symbols"] == 1
    assert completed[0]["attempted_symbols"] == 1
    assert completed[0]["outcomes"][0]["added_cost"] == 26
    grind_report_html = (
        project / ".reprobit-state" / "reports" / "grind" / "project" / "report.html"
    )
    cold_report_path = grind_report_html.parent / "cold" / "001-verification.json"
    cold_report_html = grind_report_html.parent / "cold" / "001-verification.html"
    assert completed[0]["report_html"] == str(grind_report_html)
    assert completed[0]["report_json"] == str(grind_report_html.with_suffix(".json"))
    assert grind_report_html.is_file()
    assert cold_report_html.is_file()
    grind_report = Report.model_validate_json(cold_report_path.read_bytes())
    assert grind_report.verdict.cold is True
    assert grind_report.verdict.byte_exact is True
    assert grind_report.verdict.logic_certified is True
    assert grind_report.verdict.toolchain_origin is True
    assert grind_report.verdict.clean is True

    accepted = load_project_tree(project)
    accepted_classic = _classic(accepted)
    added_ids = {item.id for item in accepted_classic} - {item.id for item in initial_classic}
    added = tuple(item for item in accepted_classic if item.id in added_ids)
    assert len(added) == 2
    donor = next(
        item
        for item in added
        if item.family is ClassicRecipeFamily.DECLARATION_SHAPE
        and item.role is ClassicRecipeRole.DONOR
    )
    function = next(
        item
        for item in added
        if item.family is ClassicRecipeFamily.EQUAL_BODY_STRICT
        and item.role is ClassicRecipeRole.FUNCTION
    )
    assert _parameters(donor)["classes"] == 1
    assert _parameters(donor)["functions"] == 10
    assert "compile_lane" not in _parameters(donor)
    assert donor.beneficiaries == (function.scope,)
    assert function.symbol == "_transform"
    assert function.dependencies == (donor.id,)
    assert function.parameters == ()

    receipts = {
        receipt.intervention_id: receipt
        for document in accepted.proof_documents
        for receipt in document.expected_observations
    }
    assert receipts[donor.id].expected_values == {}
    assert receipts[function.id].expected_values == {
        "expected_body_length": 137,
        "expected_body_sha256": REFERENCE_BODY_SHA256,
        "expected_changed_offsets": [65],
    }
    assert calculate_cost(accepted.interventions).project_total == 31
    assert all(
        Digest.from_path(project / relative) == digest for relative, digest in before.items()
    )
    assert (Digest.from_path(tu_interventions), Digest.from_path(tu_proofs)) != initial_tu_digests
    assert not tuple(project.glob(".reprobit-grind-*"))
    assert not (project / "build").exists(), "grind leaked its private candidate build"

    verification = _run(
        (_rbit(), "--format", "ndjson", "verify", project),
        cwd=project,
        environment=environment,
    )
    verify_events = _events(verification)
    final = [event for event in verify_events if event.get("event") == "verification"]
    assert len(final) == 1
    assert final[0]["accepted"] is True
    assert final[0]["targets"] == final[0]["exact_targets"] == 1
    assert final[0]["total_cost"] == 31

    report_path = project / ".reprobit-state" / "reports" / "report.json"
    report = Report.model_validate_json(report_path.read_bytes())
    assert report.verdict.cold is True
    assert report.verdict.byte_exact is True
    assert report.verdict.logic_certified is True
    assert report.verdict.toolchain_origin is True
    assert report.verdict.clean is True
    assert report.cache.mode is CacheMode.BYPASSED
    assert report.cache.hits == report.cache.misses == 0
    assert report.costs.project_total == 31
    assert len(report.targets) == 1
    target = report.targets[0]
    assert target.byte_exact is True
    assert target.candidate_size == target.oracle_size == 1536
    assert target.candidate_digest == target.oracle_digest == Digest(value=REFERENCE_IMAGE_SHA256)
    build = report.proof.runtime.preimage.build
    assert build.cold is True
    assert build.outputs and all(item.fresh for item in build.outputs)


def test_msvc42_progress_grind_saves_two_mismatches_then_cold_verifies(
    tmp_path: Path,
) -> None:
    configured = os.environ.get("REPROBIT_MSVC_4_2_ROOT")
    assert configured, "CI must provision REPROBIT_MSVC_4_2_ROOT"
    toolchain_root = Path(configured).resolve(strict=True)

    project = tmp_path / "grind-progress"
    shutil.copytree(
        PROGRESS_SAMPLE,
        project,
        ignore=shutil.ignore_patterns(
            "__pycache__",
            ".reprobit-discovery",
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
    reference_image = project / "reference" / "grind-progress.exe"
    reference_digest = Digest.from_path(reference_image)
    assert (project / "reference" / "transform_one.obj").is_file()
    assert (project / "reference" / "transform_two.obj").is_file()

    initial = load_project_tree(project)
    initial_classic = _classic(initial)
    assert len(initial_classic) == 1
    assert initial_classic[0].family is ClassicRecipeFamily.IMAGE_METADATA
    tu_paths = tuple(
        sorted(
            (project / "reprobit" / "interventions").glob("tu.*.json"),
            key=lambda item: item.name,
        )
    )
    assert len(tu_paths) == 2
    before = {path.name: Digest.from_path(path) for path in tu_paths}

    grind = _run(
        (
            _rbit(),
            "--format",
            "ndjson",
            "discover",
            "grind",
            project,
            "--accept-progress",
        ),
        cwd=project,
        environment=environment,
    )
    grind_events = _events(grind)
    completed = [
        event for event in grind_events if event.get("event") == "discovery_project_grind_complete"
    ]
    assert len(completed) == 1
    event = completed[0]
    assert event["accepted"] is True
    assert event["accept_mode"] == "progress"
    assert event["attempted_symbols"] == 2
    assert event["locally_qualified_symbols"] == 2
    assert event["published_symbols"] == 2
    assert event["published_progress_symbols"] == 1
    assert event["exact_symbols"] == 1
    assert [outcome["published"] for outcome in event["outcomes"]] == [True, True]
    assert [outcome["exact"] for outcome in event["outcomes"]] == [False, True]

    report_json = Path(event["report_json"])
    summary = json.loads(report_json.read_bytes())
    transaction_ids = [outcome["transaction_id"] for outcome in summary["outcomes"]]
    assert all(isinstance(item, str) and item for item in transaction_ids)
    assert len(set(transaction_ids)) == 2

    accepted = load_project_tree(project)
    accepted_classic = _classic(accepted)
    functions = tuple(item for item in accepted_classic if item.role is ClassicRecipeRole.FUNCTION)
    donors = tuple(item for item in accepted_classic if item.role is ClassicRecipeRole.DONOR)
    assert {item.symbol for item in functions} == {"_transform_one", "_transform_two"}
    assert len(donors) == 2
    assert calculate_cost(accepted.interventions).project_total == 57
    assert all(Digest.from_path(path) != before[path.name] for path in tu_paths)
    assert not tuple(project.glob(".reprobit-grind-*"))
    assert not (project / "build").exists(), "grind leaked its private candidate build"

    verification = _run(
        (_rbit(), "--format", "ndjson", "verify", project),
        cwd=project,
        environment=environment,
    )
    verify_events = _events(verification)
    final = [event for event in verify_events if event.get("event") == "verification"]
    assert len(final) == 1
    assert final[0]["accepted"] is True
    assert final[0]["targets"] == final[0]["exact_targets"] == 1
    assert final[0]["total_cost"] == 57

    report = Report.model_validate_json(
        (project / ".reprobit-state" / "reports" / "report.json").read_bytes()
    )
    assert report.verdict.cold is True
    assert report.verdict.byte_exact is True
    assert report.verdict.logic_certified is True
    assert report.verdict.toolchain_origin is True
    assert report.verdict.clean is True
    assert report.cache.mode is CacheMode.BYPASSED
    assert report.targets[0].candidate_digest == report.targets[0].oracle_digest
    assert report.targets[0].oracle_digest == reference_digest
