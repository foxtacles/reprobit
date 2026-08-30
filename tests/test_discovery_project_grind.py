from __future__ import annotations

import argparse
import gc
import json
import weakref
from dataclasses import replace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import reprobit.discovery_grind_cli as grind_cli
import reprobit.discovery_project_grind as project_grind
import reprobit.discovery_project_grind_cli as project_grind_cli
from reprobit.cli_output import CLIOutput, human_command
from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationParameter,
    DeclarationState,
)
from reprobit.discovery_grind import (
    DonorProgress,
    GrindSolution,
    ProjectGrindCallbacks,
    ProjectGrindResult,
)
from reprobit.discovery_project import ProjectGrindPlan
from reprobit.discovery_project_grind import (
    ProjectAutoGrindError,
    ProjectAutoGrindResult,
    ProjectGrindArtifacts,
    ProjectGrindCampaign,
    ProjectGrindOutcome,
    ProjectGrindSkip,
    ProjectGrindWorkItem,
    enumerate_project_grind_campaign,
    run_project_auto_grind,
)
from reprobit.discovery_project_grind_report import (
    render_project_auto_grind_report_html,
)
from reprobit.model import Digest
from reprobit.progress import ProgressKind
from reprobit.report import Report
from reprobit.report_html_style import REPROBIT_MARK_SVG
from reprobit.schema import (
    ClassicTranslationUnitPlan,
    InterventionDocument,
    ProofDocument,
)
from reprobit.strict_json import canonical_json


def _unit(identifier: str, source: str) -> ClassicTranslationUnitPlan:
    return ClassicTranslationUnitPlan(
        id=identifier,
        target_id="program",
        build_target="program",
        source=source,
        source_digest=Digest.from_bytes(source.encode()),
    )


def _bundle(*units: ClassicTranslationUnitPlan) -> SimpleNamespace:
    return SimpleNamespace(
        spec=SimpleNamespace(project_id="sample"),
        build_plan=SimpleNamespace(translation_units=units),
        producer_graph=object(),
        intervention_documents=tuple(
            InterventionDocument(
                schema_version=3,
                target_id=unit.target_id,
                translation_unit_id=unit.id,
                interventions=(),
            )
            for unit in units
        ),
        proof_documents=tuple(
            ProofDocument(
                schema_version=3,
                target_id=unit.target_id,
                translation_unit_id=unit.id,
                expected_observations=(),
            )
            for unit in units
        ),
    )


def _install_authority(
    monkeypatch: pytest.MonkeyPatch,
    bundle: SimpleNamespace,
) -> None:
    monkeypatch.setattr(project_grind, "load_project_tree", lambda _root: bundle)
    monkeypatch.setattr(
        project_grind,
        "classic_compiler_translation_unit_authority",
        lambda _bundle, _graph: {
            f"compiler.{unit.id}": unit for unit in bundle.build_plan.translation_units
        },
    )


def test_project_campaign_round_robins_translation_units_before_reusing_one(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _unit("tu.alpha", "src/alpha.cpp")
    second = _unit("tu.beta", "src/beta.cpp")
    bundle = _bundle(first, second)
    _install_authority(monkeypatch, bundle)
    reference = tmp_path / "reference"
    reference.mkdir()
    (reference / "tu.alpha.obj").write_bytes(b"alpha")
    (reference / "beta.obj").write_bytes(b"beta")
    monkeypatch.setattr(
        project_grind,
        "isolated_msvc_function_symbols",
        lambda payload: ("_omega", "_zeta", "_alpha") if payload == b"alpha" else ("_beta",),
    )
    monkeypatch.setattr(
        project_grind,
        "_existing_function_symbols",
        lambda document: (
            frozenset({"_zeta"}) if document.translation_unit_id == "tu.alpha" else frozenset()
        ),
    )

    campaign = enumerate_project_grind_campaign(tmp_path, max_symbols=2)

    assert campaign.eligible_units == 2
    assert campaign.reference_objects == 2
    assert campaign.discovered_symbols == 3
    assert campaign.truncated_symbols == 1
    assert tuple(
        (item.translation_unit_id, item.symbol, item.reference_object) for item in campaign.items
    ) == (
        ("tu.alpha", "_alpha", "reference/tu.alpha.obj"),
        ("tu.beta", "_beta", "reference/beta.obj"),
    )


def test_project_campaign_uses_only_the_documented_single_unit_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = _unit("tu.transform", "transform.cpp")
    _install_authority(monkeypatch, _bundle(unit))
    reference = tmp_path / "reference"
    reference.mkdir()
    (reference / "reference.obj").write_bytes(b"reference")
    monkeypatch.setattr(
        project_grind,
        "isolated_msvc_function_symbols",
        lambda _payload: ("_transform",),
    )

    campaign = enumerate_project_grind_campaign(tmp_path)

    assert campaign.items == (
        ProjectGrindWorkItem(
            "program",
            "tu.transform",
            "_transform",
            "reference/reference.obj",
        ),
    )


def test_project_reference_scan_stops_after_4096_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unit = _unit("tu.transform", "transform.cpp")
    _install_authority(monkeypatch, _bundle(unit))
    reference = tmp_path / "reference"
    reference.mkdir()
    for index in range(4_097):
        (reference / f"entry-{index:04d}.txt").write_bytes(b"")

    with pytest.raises(ProjectAutoGrindError, match="at most 4096 entries"):
        enumerate_project_grind_campaign(tmp_path)


def test_campaign_probe_cache_replays_progress_without_recompiling(
    tmp_path: Path,
) -> None:
    seed_calls: list[tuple[Path, str]] = []
    donor_calls: list[tuple[Path, tuple[str, ...]]] = []

    def seed(root: Path, node_id: str) -> bytes:
        seed_calls.append((root, node_id))
        return b"seed"

    def donors(
        root: Path,
        donor_ids: tuple[str, ...],
        progress: DonorProgress | None,
    ) -> dict[str, bytes]:
        donor_calls.append((root, donor_ids))
        if progress is not None:
            for completed, donor_id in enumerate(donor_ids, start=1):
                progress(completed, len(donor_ids), donor_id)
        return {donor_id: donor_id.encode() for donor_id in donor_ids}

    callbacks = project_grind_cli._campaign_callbacks(
        ProjectGrindCallbacks(
            probe_seed=seed,
            probe_donors=donors,
            cold_verify=cast(object, lambda _root: None),  # type: ignore[arg-type]
        ),
        reuse_across_symbols=True,
    )
    first = tmp_path / "first"
    second = tmp_path / "second"
    progress: list[tuple[int, int, str]] = []

    assert callbacks.probe_seed(first, "compiler.tu") == b"seed"
    assert callbacks.probe_seed(second, "compiler.tu") == b"seed"
    assert callbacks.probe_donors(
        first,
        ("donor.b", "donor.a"),
        lambda *event: progress.append(event),
    ) == {"donor.a": b"donor.a", "donor.b": b"donor.b"}
    assert callbacks.probe_donors(
        second,
        ("donor.a", "donor.b"),
        lambda *event: progress.append(event),
    ) == {"donor.a": b"donor.a", "donor.b": b"donor.b"}

    assert seed_calls == [(first, "compiler.tu")]
    assert donor_calls == [(first, ("donor.b", "donor.a"))]
    assert progress == [
        (1, 2, "donor.b"),
        (2, 2, "donor.a"),
        (1, 2, "donor.a"),
        (2, 2, "donor.b"),
    ]


def test_accepted_campaign_does_not_reuse_probes_after_project_changes() -> None:
    callbacks = ProjectGrindCallbacks(
        probe_seed=cast(object, lambda _root, _node: b"seed"),  # type: ignore[arg-type]
        probe_donors=cast(object, lambda _root, _ids, _progress: {}),  # type: ignore[arg-type]
        cold_verify=cast(object, lambda _root: None),  # type: ignore[arg-type]
    )

    assert (
        project_grind_cli._campaign_callbacks(
            callbacks,
            reuse_across_symbols=False,
        )
        is callbacks
    )


def test_project_auto_grind_reuses_per_symbol_engine_and_aggregates_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    items = (
        ProjectGrindWorkItem("program", "tu.one", "_one", "reference/one.obj"),
        ProjectGrindWorkItem("program", "tu.two", "_two", "reference/two.obj"),
    )
    campaign = ProjectGrindCampaign("sample", 2, 2, 2, 0, items, ())
    monkeypatch.setattr(
        project_grind,
        "enumerate_project_grind_campaign",
        lambda *_args, **_kwargs: campaign,
    )
    monkeypatch.setattr(
        project_grind,
        "load_project",
        lambda _root: SimpleNamespace(state_dir=".reprobit-state"),
    )
    plans: list[ProjectGrindPlan] = []
    acceptances: list[bool] = []
    report_refs: list[weakref.ReferenceType[object]] = []

    class ColdReportMarker:
        def __init__(self, run_id: Digest) -> None:
            self.run_id = run_id

    def run_one(
        root: Path,
        *,
        plan_relative: str,
        accept_exact: bool,
        progress: project_grind.GrindProgress,
        **_kwargs: object,
    ) -> ProjectGrindResult:
        plans.append(ProjectGrindPlan.model_validate_json((root / plan_relative).read_bytes()))
        acceptances.append(accept_exact)
        progress(14, 14, "grind-finalize", "done", ProgressKind.UNIT_FINISHED, None)
        cold_report = ColdReportMarker(Digest.from_bytes(b"compact outcome"))
        report_refs.append(weakref.ref(cold_report))
        return cast(
            ProjectGrindResult,
            SimpleNamespace(
                exact=True,
                published=accept_exact,
                states=4,
                compiler_trials=5,
                qualified_candidates=1,
                cold_trials=1,
                solution=SimpleNamespace(
                    added_cost=26,
                    report=cold_report,
                ),
                transaction_id="published" if accept_exact else None,
            ),
        )

    monkeypatch.setattr(project_grind, "run_project_grind", run_one)
    observed: list[tuple[int, int]] = []
    finalized: list[tuple[int, str]] = []

    def finalize(
        index: int,
        item: ProjectGrindWorkItem,
        _plan: ProjectGrindPlan,
        _result: ProjectGrindResult,
    ) -> ProjectGrindArtifacts:
        finalized.append((index, item.symbol))
        return ProjectGrindArtifacts(
            plan=f"plans/{index}.json",
            decision_report=f"outcomes/{index}.html",
            cold_verification_json=f"cold/{index}.json",
            cold_verification_html=f"cold/{index}.html",
        )

    result = run_project_auto_grind(
        tmp_path,
        callbacks=cast(object, SimpleNamespace()),  # type: ignore[arg-type]
        accept_exact=True,
        progress=lambda completed, total, *_args: observed.append((completed, total)),
        finalize_outcome=finalize,
    )

    assert tuple(plan.symbol for plan in plans) == ("_one", "_two")
    assert acceptances == [True, True]
    assert result.exact == result.published == 2
    assert all(not hasattr(outcome, "result") for outcome in result.outcomes)
    assert [outcome.added_cost for outcome in result.outcomes] == [26, 26]
    assert finalized == [(1, "_one"), (2, "_two")]
    assert result.outcomes[1].artifacts == ProjectGrindArtifacts(
        plan="plans/2.json",
        decision_report="outcomes/2.html",
        cold_verification_json="cold/2.json",
        cold_verification_html="cold/2.html",
    )
    gc.collect()
    assert all(reference() is None for reference in report_refs)
    assert observed[-1] == (30, 30)
    assert not tuple(tmp_path.glob(".reprobit-project-grind-*"))
    assert not tuple((tmp_path / ".reprobit-state/runs").glob("grind-*"))


def test_project_grind_report_header_uses_shared_reprobit_mark() -> None:
    result = ProjectAutoGrindResult(
        ProjectGrindCampaign(
            "sample",
            0,
            0,
            0,
            0,
            (),
            (
                ProjectGrindSkip(
                    "tu.unmatched",
                    None,
                    None,
                    "several reference objects matched; use --reference-object TU=PATH",
                ),
            ),
        ),
        (),
        False,
    )

    html = render_project_auto_grind_report_html(
        result,
        outcome_reports=(),
        summary_json="report.json",
    )

    assert html.count(REPROBIT_MARK_SVG) == 1
    assert "Project-wide automatic search" in html
    assert "use <code>--reference-object TU=PATH</code>" in html


def test_project_grind_report_renders_status_and_evidence_as_markup() -> None:
    item = ProjectGrindWorkItem("program", "tu.transform", "_transform", "reference.obj")
    outcome = ProjectGrindOutcome(
        item=item,
        exact=False,
        published=False,
        states=1,
        compiler_trials=1,
        qualified_candidates=0,
        cold_trials=0,
        added_cost=0,
        transaction_id=None,
        cold_report_run_id=None,
    )
    result = ProjectAutoGrindResult(
        ProjectGrindCampaign("sample", 1, 1, 1, 0, (item,), ()),
        (outcome,),
        False,
    )

    html = render_project_auto_grind_report_html(
        result,
        outcome_reports=("result/transform.html",),
        summary_json="report.json",
    )

    assert '<span class="outcome-muted">No exact state</span>' in html
    assert 'href="result/transform.html"' in html
    assert 'aria-label="Open decision for _transform in tu.transform"' in html
    assert "&lt;span" not in html


def test_project_report_persists_plan_decision_and_copyable_next_step(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project with spaces"
    root.mkdir()
    item = ProjectGrindWorkItem(
        "program",
        "tu.transform",
        "_transform",
        "reference/reference.obj",
    )
    state = DeclarationState(
        family=DeclarationFamily.DECLARATION_SHAPE,
        parameters=(
            DeclarationParameter(name="classes", value=1),
            DeclarationParameter(name="functions", value=10),
        ),
    )
    cold_report = cast(
        Report,
        SimpleNamespace(run_id=Digest.from_bytes(b"cold project grind")),
    )
    solution = GrindSolution(
        state=state,
        symbol=item.symbol,
        donor_id="donor.transform",
        function_id="function.transform",
        added_cost=26,
        added_interventions=2,
        reused_donor=False,
        authority_files=(
            "reprobit/interventions/tu.transform.json",
            "reprobit/proofs/tu.transform.json",
        ),
        report=cold_report,
    )
    symbol_result = ProjectGrindResult(
        "sample",
        "program",
        item.translation_unit_id,
        item.symbol,
        4,
        5,
        1,
        1,
        (),
        solution,
        False,
        None,
    )
    monkeypatch.setattr(
        project_grind_cli,
        "load_project",
        lambda _root: SimpleNamespace(state_dir=".reprobit-state"),
    )
    observed_hrefs: list[str | None] = []

    def render_cold(_report: object, *, canonical_json_href: str | None) -> str:
        observed_hrefs.append(canonical_json_href)
        return "<!doctype html><title>Cold verification</title>"

    monkeypatch.setattr(project_grind_cli, "render_report_html", render_cold)
    real_canonical_json = canonical_json
    monkeypatch.setattr(
        project_grind_cli,
        "canonical_json",
        lambda value: b"{}" if value is cold_report else real_canonical_json(value),
    )
    approval_argv = (
        "rbit",
        "discover",
        "grind",
        str(root),
        "--project-wide",
        "--max-symbols",
        "8",
        "--accept-exact",
    )
    verify_argv = ("rbit", "verify", str(root))
    state_root = root / ".reprobit-state"
    report_directory = state_root / "reports/grind/project"
    artifacts = project_grind_cli._publish_project_grind_outcome(
        root,
        state_root,
        1,
        item,
        project_grind.project_grind_plan(item),
        symbol_result,
        verify_argv=verify_argv,
    )
    stale_owned = (
        report_directory / "plans/002-plan.json",
        report_directory / "outcomes/002-decision.html",
        report_directory / "cold/002-verification.json",
        report_directory / "cold/002-verification.html",
    )
    for path in stale_owned:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"stale")
    unrelated = report_directory / "cold/notes.txt"
    out_of_range = report_directory / "cold/065-verification.json"
    unrelated.write_bytes(b"keep")
    out_of_range.write_bytes(b"keep")
    result = ProjectAutoGrindResult(
        ProjectGrindCampaign("sample", 1, 1, 1, 0, (item,), ()),
        (project_grind._compact_outcome(item, symbol_result, artifacts),),
        False,
    )

    report_json, report_html, _transaction, decisions, plans = (
        project_grind_cli._project_grind_reports(
            root,
            state_root,
            result,
            approval_argv=approval_argv,
            verify_argv=verify_argv,
        )
    )

    assert report_json.is_file()
    assert report_html.is_file()
    assert all(not path.exists() for path in stale_owned)
    assert unrelated.read_bytes() == b"keep"
    assert out_of_range.read_bytes() == b"keep"
    assert observed_hrefs == ["001-verification.json"]
    assert len(decisions) == len(plans) == 1
    assert decisions[0].is_file()
    assert plans[0].is_file()
    persisted = ProjectGrindPlan.model_validate_json(plans[0].read_bytes())
    assert persisted.symbol == "_transform"
    summary = json.loads(report_json.read_text(encoding="utf-8"))
    assert summary["next_step"]["argv"] == list(approval_argv)
    assert summary["next_step"]["command"] == human_command(approval_argv)
    assert summary["outcomes"][0]["decision_report"] == "outcomes/001-decision.html"
    assert summary["outcomes"][0]["plan"].endswith("plans/001-plan.json")
    project_html = report_html.read_text(encoding="utf-8")
    assert "Next step" in project_html
    assert "outcomes/001-decision.html" in project_html
    decision_html = decisions[0].read_text(encoding="utf-8")
    assert "../cold/001-verification.html" in decision_html
    assert plans[0].relative_to(root).as_posix() in decision_html

    published = ProjectAutoGrindResult(
        result.campaign,
        (
            replace(
                result.outcomes[0],
                published=True,
                transaction_id="accepted",
            ),
        ),
        True,
    )
    project_grind_cli._project_grind_reports(
        root,
        state_root,
        published,
        approval_argv=approval_argv,
        verify_argv=verify_argv,
    )
    published_summary = json.loads(report_json.read_text(encoding="utf-8"))
    assert published_summary["next_step"] == {
        "kind": "verify",
        "argv": list(verify_argv),
        "command": human_command(verify_argv),
    }


def test_project_outcome_replaces_stale_cold_reports_with_no_solution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.setattr(
        project_grind_cli,
        "load_project",
        lambda _root: SimpleNamespace(state_dir=".reprobit-state"),
    )
    state_root = root / ".reprobit-state"
    report_directory = state_root / "reports/grind/project"
    stale_json = report_directory / "cold/001-verification.json"
    stale_html = report_directory / "cold/001-verification.html"
    unrelated = report_directory / "cold/notes.txt"
    for path in (stale_json, stale_html, unrelated):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"old")
    item = ProjectGrindWorkItem(
        "program",
        "tu.transform",
        "_transform",
        "reference/reference.obj",
    )
    result = ProjectGrindResult(
        "sample",
        "program",
        item.translation_unit_id,
        item.symbol,
        4,
        5,
        0,
        0,
        (),
        None,
        False,
        None,
    )

    artifacts = project_grind_cli._publish_project_grind_outcome(
        root,
        state_root,
        1,
        item,
        project_grind.project_grind_plan(item),
        result,
        verify_argv=("rbit", "verify", str(root)),
    )

    assert artifacts.cold_verification_json is None
    assert artifacts.cold_verification_html is None
    assert not stale_json.exists()
    assert not stale_html.exists()
    assert unrelated.read_bytes() == b"old"


def test_project_wide_cli_preview_reports_copyable_acceptance_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = ProjectGrindWorkItem(
        "program",
        "tu.transform",
        "_transform",
        "reference/reference.obj",
    )
    result = ProjectAutoGrindResult(
        ProjectGrindCampaign("sample", 1, 1, 1, 0, (item,), ()),
        (
            ProjectGrindOutcome(
                item=item,
                exact=True,
                published=False,
                states=4,
                compiler_trials=5,
                qualified_candidates=1,
                cold_trials=1,
                added_cost=26,
                transaction_id=None,
                cold_report_run_id=Digest.from_bytes(b"cold run"),
            ),
        ),
        False,
    )
    observed: dict[str, object] = {}
    project_loads = 0

    def run(*_args: object, **kwargs: object) -> ProjectAutoGrindResult:
        observed.update(kwargs)
        return result

    def load(_root: Path) -> SimpleNamespace:
        nonlocal project_loads
        project_loads += 1
        return SimpleNamespace(state_dir=".reprobit-state")

    monkeypatch.setattr(project_grind_cli, "run_project_auto_grind", run)
    monkeypatch.setattr(project_grind_cli, "load_project", load)
    report_json = tmp_path / ".reprobit-state/reports/grind/project/report.json"
    report_html = report_json.with_suffix(".html")
    monkeypatch.setattr(
        project_grind_cli,
        "_project_grind_reports",
        lambda *_args, **_kwargs: (
            report_json,
            report_html,
            "report-transaction",
            (),
            (),
        ),
    )
    machine = StringIO()
    args = argparse.Namespace(
        project=str(tmp_path),
        project_wide=True,
        reference_object=["tu.transform=reference/reference.obj"],
        max_symbols=3,
        plan="reprobit/discovery.json",
        accept_exact=False,
    )

    status = grind_cli.command_discover_grind(
        args,
        CLIOutput("ndjson", machine, StringIO()),
        prepare_run=lambda *_args, **_kwargs: None,
        verify_command=lambda *_args, **_kwargs: 0,
    )

    event = next(
        json.loads(line)
        for line in machine.getvalue().splitlines()
        if json.loads(line).get("event") == "discovery_project_grind_complete"
    )
    assert status == 0
    assert project_loads == 1
    assert observed["accept_exact"] is False
    assert event["approval_argv"][-1] == "--accept-exact"
    assert "--project-wide" in event["approval_argv"]
    assert event["report_html"] == str(report_html)


def test_project_wide_report_failure_is_nonfatal_and_keeps_compact_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = ProjectGrindWorkItem(
        "program",
        "tu.transform",
        "_transform",
        "reference/reference.obj",
    )
    outcome = ProjectGrindOutcome(
        item=item,
        exact=True,
        published=True,
        states=4,
        compiler_trials=5,
        qualified_candidates=1,
        cold_trials=1,
        added_cost=26,
        transaction_id="authority-transaction",
        cold_report_run_id=Digest.from_bytes(b"cold run"),
    )
    result = ProjectAutoGrindResult(
        ProjectGrindCampaign("sample", 1, 1, 1, 0, (item,), ()),
        (outcome,),
        True,
    )

    def run(*_args: object, **kwargs: object) -> ProjectAutoGrindResult:
        finalize = cast(project_grind.ProjectGrindOutcomeFinalizer, kwargs["finalize_outcome"])
        assert (
            finalize(
                1,
                item,
                project_grind.project_grind_plan(item),
                cast(ProjectGrindResult, SimpleNamespace()),
            )
            is None
        )
        return result

    def fail_report(*_args: object, **_kwargs: object) -> ProjectGrindArtifacts:
        raise OSError("diagnostic disk full")

    monkeypatch.setattr(project_grind_cli, "run_project_auto_grind", run)
    monkeypatch.setattr(project_grind_cli, "_publish_project_grind_outcome", fail_report)
    monkeypatch.setattr(
        project_grind_cli,
        "load_project",
        lambda _root: SimpleNamespace(state_dir=".reprobit-state"),
    )
    report_json = tmp_path / ".reprobit-state/reports/grind/project/report.json"
    report_html = report_json.with_suffix(".html")
    monkeypatch.setattr(
        project_grind_cli,
        "_project_grind_reports",
        lambda *_args, **_kwargs: (
            report_json,
            report_html,
            "summary-transaction",
            (),
            (),
        ),
    )
    machine = StringIO()

    status = project_grind_cli.command_discover_project_grind(
        argparse.Namespace(
            project=str(tmp_path),
            project_wide=True,
            reference_object=[],
            max_symbols=1,
            plan="reprobit/discovery.json",
            accept_exact=True,
        ),
        CLIOutput("ndjson", machine, StringIO()),
        callbacks=cast(object, SimpleNamespace()),  # type: ignore[arg-type]
    )

    events = [json.loads(line) for line in machine.getvalue().splitlines()]
    warning = next(
        event for event in events if event["event"] == "discovery_project_grind_report_warning"
    )
    complete = next(
        event for event in events if event["event"] == "discovery_project_grind_complete"
    )
    assert status == 0
    assert warning["nonfatal"] is True
    assert warning["error"] == "diagnostic disk full"
    assert complete["published_symbols"] == 1
    assert result.outcomes[0].transaction_id == "authority-transaction"
    assert "diagnostic disk full" in complete["report_warning"]
