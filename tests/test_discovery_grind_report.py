from __future__ import annotations

import argparse
import json
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import reprobit.discovery_grind_cli as grind_cli
from reprobit.cli_output import CLIOutput
from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationParameter,
    DeclarationState,
)
from reprobit.discovery_grind import (
    GrindRejection,
    GrindSolution,
    ProjectGrindResult,
)
from reprobit.discovery_grind_report import render_grind_report_html
from reprobit.model import Digest
from reprobit.report import Report


class _HTMLStructure(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        attributes = dict(attrs)
        self.tags.append((tag, attributes))
        identity = attributes.get("id")
        if identity is not None:
            self.ids.add(identity)


def _state() -> DeclarationState:
    return DeclarationState(
        family=DeclarationFamily.DECLARATION_SHAPE,
        parameters=(
            DeclarationParameter(name="classes", value=1),
            DeclarationParameter(name="functions", value=10),
        ),
    )


def _solution() -> GrindSolution:
    report = cast(
        Report,
        SimpleNamespace(run_id=Digest.from_bytes(b"cold report")),
    )
    return GrindSolution(
        state=_state(),
        symbol="?Transform@Widget@@QAEHH@Z",
        donor_id="discovery.declaration_shape.c1.f10",
        function_id="discovery.equal_body.transform",
        added_cost=26,
        added_interventions=2,
        reused_donor=False,
        authority_files=(
            "reprobit/interventions/tu.widget.json",
            "reprobit/proofs/tu.widget.proof.json",
        ),
        report=report,
    )


def _result(
    *,
    solution: GrindSolution | None,
    published: bool = False,
) -> ProjectGrindResult:
    return ProjectGrindResult(
        project_id="sample.project",
        target_id="widget.target",
        translation_unit_id="tu.widget",
        symbol="?Transform@Widget@@QAEHH@Z",
        states=4,
        compiler_trials=5,
        qualified_candidates=2,
        cold_trials=2,
        rejections=(
            GrindRejection(
                state_id="declaration_shape.classes-2.functions-10",
                stage="qualification",
                reason="candidate object does not match the reference symbol",
            ),
            GrindRejection(
                state_id="declaration_shape.classes-3.functions-10",
                stage="cold_verification",
                reason="cold verification did not reproduce every target byte-identically",
            ),
        ),
        solution=solution,
        published=published,
        transaction_id="transaction-123" if published else None,
    )


def test_discovery_probe_passes_resolved_execution_inputs_to_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = SimpleNamespace(spec=SimpleNamespace(toolchain=SimpleNamespace(profile="msvc_4_2")))
    backend = object()
    execution = object()
    args = SimpleNamespace(
        toolchain_root=tmp_path / "toolchain",
        backend="auto",
        wine=None,
        wineserver=None,
        compiler_transport=None,
        resource_transport=None,
    )
    resolved: dict[str, object] = {}
    prepared: dict[str, object] = {}

    monkeypatch.setattr(grind_cli, "load_project_tree", lambda _root: bundle)
    monkeypatch.setattr(grind_cli, "selected_backend", lambda _args: backend)

    def resolve_execution(**values: object) -> object:
        resolved.update(values)
        return execution

    def prepare_run(*values: object, **options: object) -> object:
        prepared["args"] = values
        prepared.update(options)
        return "prepared"

    monkeypatch.setattr(
        grind_cli,
        "resolve_classic_execution_inputs",
        resolve_execution,
    )

    result, session = grind_cli._prepare_probe(
        args,
        staged_root=tmp_path,
        label="seed",
        prepare_run=prepare_run,
    )

    assert result == "prepared"
    assert session.is_dir()
    assert resolved == {
        "profile": "msvc_4_2",
        "explicit_toolchain_root": tmp_path / "toolchain",
        "backend": backend,
        "compiler_transport": None,
        "resource_transport": None,
    }
    assert prepared["args"] == (args, bundle)
    assert prepared["project_root"] == tmp_path
    assert prepared["session_root"] == session
    assert prepared["execution"] is execution
    assert callable(prepared["progress"])


def test_grind_report_layers_success_funnel_decision_and_technical_details() -> None:
    rendered = render_grind_report_html(
        _result(solution=_solution(), published=True),
        plan_relative="reprobit/discovery.json",
        cold_report_html="cold-verification.html",
        cold_report_json="cold-verification.json",
    )
    assert rendered.count('<svg class="brand-mark"') == 1
    structure = _HTMLStructure()
    structure.feed(rendered)

    assert rendered.startswith("<!doctype html>")
    assert {
        "overview",
        "funnel",
        "rejections",
        "decision",
        "technical-details",
    } <= structure.ids
    assert sum(tag == "figure" for tag, _attrs in structure.tags) == 2
    assert "<code>sample.project</code>" in rendered
    assert "<code>widget.target</code>" in rendered
    assert "<code>?Transform@Widget@@QAEHH@Z</code>" in rendered
    assert "Search funnel" in rendered
    assert "Why states stopped" in rendered
    assert rendered.index('<section class="section" id="decision"') < rendered.index(
        '<section class="section" id="funnel"'
    )
    assert "Exact adjustment saved" in rendered
    assert "Fresh verification passed" in rendered
    assert "Candidate did not match the reference function" in rendered
    assert "Final executable did not match" in rendered
    assert "Project files updated" in rendered
    assert (
        "Two adjustment records and their supporting verification records were saved." in rendered
    )
    assert "Changed files" in rendered
    assert "Review the changed project files" in rendered
    assert "git diff\nrbit verify ." in rendered
    assert "<code>discovery.declaration_shape.c1.f10</code>" in rendered
    assert "<code>discovery.equal_body.transform</code>" in rendered
    assert 'href="cold-verification.html"' in rendered
    assert "Path: <code>cold-verification.html</code>" in rendered
    assert '<details class="advanced" id="technical-details">' in rendered
    assert '<details class="advanced" id="technical-details" open>' not in rendered
    assert "Donor intervention" in rendered
    assert "Cold trials" in rendered
    assert "Every recorded grind rejection" in rendered
    assert "<script src=" not in rendered


def test_grind_report_explains_bounded_failure_without_a_verification_link() -> None:
    result = _result(solution=None)
    rendered = render_grind_report_html(
        result,
        plan_relative="reprobit/discovery.json",
    )

    assert rendered == render_grind_report_html(
        result,
        plan_relative="reprobit/discovery.json",
    )
    assert "No exact adjustment within these search limits" in rendered
    assert "No state chosen" in rendered
    assert "Project files unchanged" in rendered
    assert "candidate object does not match the reference symbol" in rendered
    assert "cold verification did not reproduce every target byte-identically" in rendered
    assert "cold-verification.html" not in rendered
    assert '<code class="identifier">declaration_shape.classes-2.functions-10</code>' in rendered


def test_grind_preview_shows_the_exact_approval_command_and_prospective_files() -> None:
    rendered = render_grind_report_html(
        _result(solution=_solution()),
        plan_relative="reprobit/discovery.json",
    )

    assert "Files approval would change" in rendered
    assert "Changed files:" not in rendered
    assert "Exact adjustment ready for review" in rendered
    assert "Approval will save two adjustment records" in rendered
    assert "rbit discover grind . --plan reprobit/discovery.json --accept-exact" in rendered


def _args(root: Path, *, accept_exact: bool) -> argparse.Namespace:
    return argparse.Namespace(
        project=str(root),
        plan="reprobit/discovery.json",
        accept_exact=accept_exact,
    )


def _install_cli_result(
    monkeypatch: pytest.MonkeyPatch,
    result: ProjectGrindResult,
) -> None:
    monkeypatch.setattr(
        grind_cli,
        "load_project",
        lambda _root: SimpleNamespace(state_dir=".reprobit-state"),
    )
    monkeypatch.setattr(grind_cli, "run_project_grind", lambda *_args, **_kwargs: result)


def test_cli_writes_a_human_grind_report_for_no_solution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_cli_result(monkeypatch, _result(solution=None))
    machine = StringIO()
    report_directory = tmp_path / ".reprobit-state/reports/grind"
    report_directory.mkdir(parents=True)
    stale_json = report_directory / "cold-verification.json"
    stale_html = report_directory / "cold-verification.html"
    unrelated = report_directory / "notes.txt"
    stale_json.write_bytes(b"old cold json")
    stale_html.write_bytes(b"old cold html")
    unrelated.write_bytes(b"keep")

    status = grind_cli.command_discover_grind(
        _args(tmp_path, accept_exact=False),
        CLIOutput("ndjson", machine, StringIO()),
        prepare_run=lambda *_args, **_kwargs: None,
        verify_command=lambda *_args, **_kwargs: 0,
    )

    report = tmp_path / ".reprobit-state/reports/grind/report.html"
    assert status == 1
    assert report.is_file()
    assert not stale_json.exists()
    assert not stale_html.exists()
    assert unrelated.read_bytes() == b"keep"
    assert "No exact adjustment within these search limits" in report.read_text(encoding="utf-8")
    complete = next(
        item
        for item in (json.loads(line) for line in machine.getvalue().splitlines())
        if item["event"] == "discovery_grind_complete"
    )
    assert complete["grind_report_html"] == str(report)
    assert complete["cold_verification_report_html"] is None


def test_cli_cold_report_links_its_actual_json_sibling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_cli_result(monkeypatch, _result(solution=_solution()))
    monkeypatch.setattr(grind_cli, "canonical_json", lambda _value: b"{}")
    observed_hrefs: list[str | None] = []

    def render_cold(_report: object, *, canonical_json_href: str | None) -> str:
        observed_hrefs.append(canonical_json_href)
        return "<!doctype html><title>Cold verification</title>"

    monkeypatch.setattr(grind_cli, "render_report_html", render_cold)

    status = grind_cli.command_discover_grind(
        _args(tmp_path, accept_exact=False),
        CLIOutput("ndjson", StringIO(), StringIO()),
        prepare_run=lambda *_args, **_kwargs: None,
        verify_command=lambda *_args, **_kwargs: 0,
    )

    assert status == 0
    assert observed_hrefs == ["cold-verification.json"]


def test_report_failure_after_publication_is_an_explicit_nonfatal_event(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_cli_result(
        monkeypatch,
        _result(solution=_solution(), published=True),
    )
    monkeypatch.setattr(grind_cli, "canonical_json", lambda _value: b"{}")
    monkeypatch.setattr(
        grind_cli,
        "render_report_html",
        lambda _report, **_kwargs: "<!doctype html><title>Cold verification</title>",
    )
    monkeypatch.setattr(
        grind_cli,
        "render_grind_report_html",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("report disk unavailable")),
    )
    machine = StringIO()

    status = grind_cli.command_discover_grind(
        _args(tmp_path, accept_exact=True),
        CLIOutput("ndjson", machine, StringIO()),
        prepare_run=lambda *_args, **_kwargs: None,
        verify_command=lambda *_args, **_kwargs: 0,
    )

    events = [json.loads(line) for line in machine.getvalue().splitlines()]
    warning = next(item for item in events if item["event"] == "discovery_grind_report_warning")
    complete = next(item for item in events if item["event"] == "discovery_grind_complete")
    assert status == 0
    assert warning["nonfatal"] is True
    assert warning["published"] is True
    assert warning["error_type"] == "OSError"
    assert complete["published"] is True
    assert complete["grind_report_html"] is None
    assert "report disk unavailable" in complete["report_warning"]


def test_cold_report_failure_still_writes_the_human_grind_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_cli_result(monkeypatch, _result(solution=_solution()))
    monkeypatch.setattr(grind_cli, "canonical_json", lambda _value: b"{}")
    monkeypatch.setattr(
        grind_cli,
        "render_report_html",
        lambda _report, **_kwargs: (_ for _ in ()).throw(OSError("cold report unavailable")),
    )
    machine = StringIO()

    status = grind_cli.command_discover_grind(
        _args(tmp_path, accept_exact=False),
        CLIOutput("ndjson", machine, StringIO()),
        prepare_run=lambda *_args, **_kwargs: None,
        verify_command=lambda *_args, **_kwargs: 0,
    )

    report = tmp_path / ".reprobit-state/reports/grind/report.html"
    events = [json.loads(line) for line in machine.getvalue().splitlines()]
    warning = next(item for item in events if item["event"] == "discovery_grind_report_warning")
    complete = next(item for item in events if item["event"] == "discovery_grind_complete")
    assert status == 0
    assert report.is_file()
    assert 'href="cold-verification.html"' not in report.read_text(encoding="utf-8")
    assert warning["report"].endswith("cold-verification.html")
    assert warning["nonfatal"] is True
    assert complete["grind_report_html"] == str(report)
    assert complete["cold_verification_report_html"] is None
    assert "cold report unavailable" in complete["report_warning"]
