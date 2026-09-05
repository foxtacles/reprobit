"""Self-contained human report for one bounded project grind."""

from __future__ import annotations

import os
import posixpath
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from reprobit.cli_paths import relative_output
from reprobit.discovery_contracts import declaration_state_id
from reprobit.discovery_grind import GrindRejection, GrindSolution, ProjectGrindResult
from reprobit.report_html_components import (
    Bar,
    OutcomeBranch,
    bar_chart,
    code,
    count_phrase,
    details,
    escape,
    format_integer,
    metric_cards,
    outcome_summary,
    page_shell,
    table,
)
from reprobit.report_io import render_report_html
from reprobit.state import report_publication_lease
from reprobit.strict_json import canonical_json
from reprobit.transactions import CASTransaction

_GRIND_CSS = r"""
.metric-grid { margin-top: 1rem; }
.metric-grid .value { font-variant-numeric: tabular-nums; }
.decision-card { border-left: 4px solid var(--line-strong); }
.decision-card.ok { border-left-color: var(--ok); }
.decision-card.warn { border-left-color: var(--warn); }
.decision-card .status.warn { color: var(--warn); }
.technical-path { margin: .45rem 0 0; color: var(--muted); }
""".strip()


def _claim(label: str, *, tone: str) -> str:
    return f'<span class="claim {escape(tone)}">{escape(label)}</span>'


_OUTCOME_COPY: Mapping[OutcomeBranch, tuple[str, str]] = MappingProxyType(
    {
        "published-exact": (
            "Exact adjustment saved",
            "The selected compiler choices passed a fresh verification build, matched every "
            "target byte for byte, and passed the required logic checks. ReproBit then saved "
            "the adjustment and its supporting verification records together.",
        ),
        "published": (
            "Locally proven adjustment saved",
            "The selected compiler choices reproduced this function from the project-owned "
            "reference object and passed the required logic checks in a fresh build. The "
            "complete project does not match yet, so this is saved progress—not project "
            "certification.",
        ),
        "exact": (
            "Exact adjustment ready for review",
            "The selected compiler choices passed a fresh verification build, matched every "
            "target byte for byte, and passed the required logic checks. This preview wrote "
            "only review reports; the project files stayed unchanged.",
        ),
        "qualified": (
            "Locally proven adjustment ready for review",
            "The selected compiler choices reproduced this function from the project-owned "
            "reference object and passed the required logic checks in a fresh build. The "
            "complete project does not match yet, and this preview left project files "
            "unchanged. This local result is not project certification.",
        ),
        "exhausted": (
            "No safe adjustment within these search limits",
            "The complete bounded search finished without a locally proven function "
            "adjustment. No project files changed.",
        ),
    }
)

_OUTCOME_CLAIMS: Mapping[OutcomeBranch, tuple[tuple[str, str], ...]] = MappingProxyType(
    {
        "published-exact": (
            ("Exact match", "ok"),
            ("Fresh verification passed", "ok"),
            ("Project files updated", "ok"),
        ),
        "published": (
            ("Function matched", "ok"),
            ("Logic checks passed", "ok"),
            ("Project not exact", "warn"),
        ),
        "exact": (
            ("Exact match", "ok"),
            ("Fresh verification passed", "ok"),
            ("Review only", "warn"),
        ),
        "qualified": (
            ("Function matched", "ok"),
            ("Logic checks passed", "ok"),
            ("Review only", "warn"),
        ),
        "exhausted": (
            ("Search complete", "ok"),
            ("No local match", "warn"),
            ("Project files unchanged", "ok"),
        ),
    }
)


def _summary(result: ProjectGrindResult) -> tuple[str, str, str, tuple[str, ...]]:
    branch, tone, heading, explanation = outcome_summary(
        published=result.published,
        exact=result.exact,
        qualified=result.locally_qualified,
        copy=_OUTCOME_COPY,
    )
    claims = tuple(_claim(label, tone=claim_tone) for label, claim_tone in _OUTCOME_CLAIMS[branch])
    return tone, heading, explanation, claims


def _funnel(result: ProjectGrindResult) -> str:
    bars = (
        Bar(
            label="States",
            detail="Bounded declaration states",
            value=float(result.states),
            display_value=format_integer(result.states),
        ),
        Bar(
            label="Qualified",
            detail="Passed the quick function check",
            value=float(result.qualified_candidates),
            display_value=format_integer(result.qualified_candidates),
        ),
        Bar(
            label="Fresh verifications",
            detail="Ran a fresh verification build",
            value=float(result.cold_trials),
            display_value=format_integer(result.cold_trials),
        ),
        Bar(
            label="Locally proven",
            detail="Function matched and logic checks passed",
            value=float(int(result.locally_qualified)),
            display_value=str(int(result.locally_qualified)),
        ),
        Bar(
            label="Project exact",
            detail="Every target matched byte for byte",
            value=float(int(result.exact)),
            display_value=str(int(result.exact)),
        ),
    )
    return bar_chart(
        identity="grind-funnel",
        title="Search funnel",
        description="How the bounded states narrowed to safe progress or an exact project.",
        bars=bars,
    )


def _rejection_chart(result: ProjectGrindResult) -> str:
    def friendly_reason(rejection: GrindRejection) -> str:
        reason = rejection.reason.casefold()
        if rejection.stage == "qualification":
            if "same length" in reason:
                return "Function size did not match"
            if "identical" in reason:
                return "Candidate made no useful byte change"
            if "reference symbol" in reason:
                return "Candidate did not match the reference function"
            return "Candidate did not pass the quick function check"
        if "byte-ident" in reason or "reproduce every target" in reason:
            return "Final executable did not match"
        if any(word in reason for word in ("logic", "certificate", "semantic")):
            return "Required logic proof did not pass"
        if any(word in reason for word in ("authenticity", "exception", "origin")):
            return "Authenticity checks did not pass"
        return "Fresh verification did not pass"

    labelled = tuple((friendly_reason(item), item.stage) for item in result.rejections)
    reason_counts = Counter(reason for reason, _stage in labelled)
    stage_counts = Counter(labelled)
    bars = tuple(
        Bar(
            label=reason,
            detail=(
                f"{stage_counts[(reason, 'qualification')]} quick check · "
                f"{stage_counts[(reason, 'cold_verification')]} fresh verification"
            ),
            value=float(count),
            display_value=format_integer(count),
            tone="hot" if stage_counts[(reason, "cold_verification")] else "normal",
        )
        for reason, count in sorted(
            reason_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
    )
    return bar_chart(
        identity="grind-rejections",
        title="Why states stopped",
        description="Quick-check and fresh-verification failures by reason.",
        bars=bars,
        empty_message="No candidate was rejected before the chosen state was found.",
    )


def _decision(
    result: ProjectGrindResult,
    *,
    plan_relative: str,
    cold_report_html: str | None,
    approval_command: str | None,
    verify_command: str,
    continue_command: str,
) -> str:
    solution = result.solution
    if solution is None:
        return """
<article class="card decision-card warn">
  <h3>No state chosen</h3>
  <div class="status warn">Project files unchanged</div>
  <p>Review why candidates stopped before widening the search plan.</p>
</article>"""

    state_id = declaration_state_id(solution.state)
    parameters = " · ".join(
        f"<code>{escape(item.name)}={escape(item.value)}</code>"
        for item in solution.state.parameters
    )
    authority = ", ".join(f"<code>{escape(path)}</code>" for path in solution.authority_files)
    if solution.reused_donor:
        record_change = (
            "One function adjustment was saved; the matching shared donor was reused "
            "and its cost assignment was updated."
            if result.published
            else "Approval will save one function adjustment, reuse the matching shared donor, "
            "and update its cost assignment."
        )
    else:
        record_change = (
            "Two adjustment records and their supporting verification records were saved."
            if result.published
            else "Approval will save two adjustment records and their supporting verification "
            "records."
        )
    if result.published:
        if result.exact:
            publish_status = '<div class="status">Exact project files updated</div>'
            publish_detail = "The adjustment and verification records were saved together."
            next_instruction = "Review the changed project files, then verify again from scratch:"
            next_command = verify_command
        else:
            publish_status = (
                '<div class="status warn">Local progress saved — project not exact</div>'
            )
            publish_detail = (
                "The adjustment and its local proof records were saved together without "
                "claiming project certification."
            )
            next_instruction = "Review the changed files, then continue the bounded search:"
            next_command = continue_command
        files_label = "Changed files"
        next_commands = f"""
  <p><strong>{escape(next_instruction)}</strong></p>
  <pre><code>git diff
{escape(next_command)}</code></pre>"""
    else:
        publish_status = '<div class="status warn">Preview only — project files unchanged</div>'
        publish_detail = "Run the approval command only after reviewing this result."
        files_label = "Files approval would change"
        rendered_approval = approval_command or (
            f"rbit discover grind . --expert-plan {plan_relative} "
            f"{'--accept-exact' if result.exact else '--accept-progress'}"
        )
        next_commands = f"""
  <p><strong>Rerun the proof and save the result if it still passes:</strong></p>
  <pre><code>{escape(rendered_approval)}</code></pre>"""
    verification = ""
    if cold_report_html is not None:
        report_label = (
            "Open fresh exact verification report"
            if result.exact
            else "Open fresh local proof report"
        )
        verification = f"""
  <a class="machine-link" href="{escape(cold_report_html)}">{report_label}</a>
  <p class="technical-path">Path: <code>{escape(cold_report_html)}</code></p>"""
    tone = "ok" if result.exact else "warn"
    return f"""
<article class="card decision-card {tone}">
  <p class="eyebrow"><code>{escape(state_id)}</code></p>
  <h3>Selected compiler choices</h3>
  {publish_status}
  <p>{parameters}</p>
  <p>Symbol <code>{escape(solution.symbol)}</code> · added cost
    <strong>{format_integer(solution.added_cost)}</strong> relative points</p>
  <p>{escape(record_change)}</p>
  <p>{publish_detail}</p>
  <p>{escape(files_label)}: {authority}</p>
  {verification}
  {next_commands}
</article>"""


def _technical_details(
    result: ProjectGrindResult,
    *,
    plan_relative: str,
    cold_report_json: str | None,
) -> str:
    solution_values = (
        (
            ("Donor intervention", result.solution.donor_id),
            ("Function intervention", result.solution.function_id),
        )
        if result.solution is not None
        else ()
    )
    values = (
        ("Project", result.project_id),
        ("Target", result.target_id),
        ("Translation unit", result.translation_unit_id),
        ("Symbol", result.symbol),
        ("Plan", plan_relative),
        ("Compiler trials", str(result.compiler_trials)),
        ("Qualified candidates", str(result.qualified_candidates)),
        ("Fresh candidate checks", str(result.cold_trials)),
        (
            "New interventions",
            str(result.solution.added_interventions) if result.solution is not None else "0",
        ),
        (
            "Shared donor reused",
            "yes" if result.solution is not None and result.solution.reused_donor else "no",
        ),
        *solution_values,
        ("Transaction", result.transaction_id or "not published"),
        ("Fresh candidate report JSON", cold_report_json or "not available"),
    )
    definitions = "".join(
        f"<dt>{escape(label)}</dt><dd><code>{escape(value)}</code></dd>" for label, value in values
    )
    rejection_rows = tuple(
        (
            code(item.state_id, css_class="identifier"),
            "Qualification" if item.stage == "qualification" else "Fresh candidate check",
            item.reason,
        )
        for item in result.rejections
    )
    body = f'<dl class="identity-list">{definitions}</dl>' + table(
        ("State", "Stage", "Reason"),
        rejection_rows,
        caption="Every recorded grind rejection",
        empty_message="No rejection was recorded.",
    )
    return details(
        identity="technical-details",
        title="Technical details",
        meta=(
            f"{count_phrase(len(result.rejections), 'rejection')} · "
            f"{count_phrase(result.compiler_trials, 'compiler trial')}"
        ),
        body=body,
    )


def render_grind_report_html(
    result: ProjectGrindResult,
    *,
    plan_relative: str,
    cold_report_html: str | None = None,
    cold_report_json: str | None = None,
    approval_command: str | None = None,
    verify_command: str = "rbit verify .",
    continue_command: str = "rbit discover grind .",
) -> str:
    """Render one deterministic grind outcome, including bounded failure."""

    tone, heading, explanation, claims = _summary(result)
    metrics = metric_cards(
        (
            ("States", result.states, "bounded and attempted"),
            ("Compiler trials", result.compiler_trials, "current source plus alternatives"),
            ("Fresh verifications", result.cold_trials, "fresh verification runs"),
        )
    )
    nav = """<nav class="section-nav" aria-label="Report sections"><ul>
  <li><a href="#overview">Overview</a></li>
  <li><a href="#decision">Decision</a></li>
  <li><a href="#funnel">Funnel</a></li>
  <li><a href="#rejections">Rejections</a></li>
  <li><a href="#technical-details">Technical details</a></li>
</ul></nav>"""
    main = f"""<section class="hero {escape(tone)}" id="overview" aria-labelledby="report-title">
  <p class="eyebrow">Automatic adjustment search</p>
  <h1 id="report-title">{escape(heading)}</h1>
  <p class="lede">{escape(explanation)}</p>
  <div class="claim-row" aria-label="Search outcome">{"".join(claims)}</div>
  <div class="card-grid metric-grid">{metrics}</div>
</section>
<section class="section" id="decision" aria-labelledby="decision-title">
  <p class="eyebrow">What to do next</p>
  <h2 id="decision-title">Selected settings and project changes</h2>
  {
        _decision(
            result,
            plan_relative=plan_relative,
            cold_report_html=cold_report_html,
            approval_command=approval_command,
            verify_command=verify_command,
            continue_command=continue_command,
        )
    }
</section>
<section class="section" id="funnel" aria-labelledby="funnel-title">
  <p class="eyebrow">What progressed</p><h2 id="funnel-title">Candidate funnel</h2>
  {_funnel(result)}
</section>
<section class="section" id="rejections" aria-labelledby="rejections-title">
  <p class="eyebrow">What did not progress</p><h2 id="rejections-title">Rejection breakdown</h2>
  {_rejection_chart(result)}
</section>
<section class="section" id="advanced" aria-labelledby="advanced-title">
  <p class="eyebrow">Evidence and diagnostics</p><h2 id="advanced-title">Advanced</h2>
  {_technical_details(result, plan_relative=plan_relative, cold_report_json=cold_report_json)}
</section>"""
    return page_shell(
        title=f"{result.project_id} — ReproBit grind report",
        brand=f"ReproBit grind · <code>{escape(result.project_id)}</code>",
        run_label=f"Target <code>{escape(result.target_id)}</code>",
        nav=nav,
        main=main,
        footer=(
            f"ReproBit bounded grind · plan <code>{escape(plan_relative)}</code> · "
            "deterministic local HTML ·\n  no external assets"
        ),
        extra_css=_GRIND_CSS,
    )


@dataclass(frozen=True, slots=True)
class GrindReportLayout:
    """Absolute output paths for one grind decision and its cold verification pair."""

    report: Path
    cold_json: Path
    cold_html: Path


@dataclass(frozen=True, slots=True)
class GrindReportCommands:
    """Copyable commands shown in one grind decision report."""

    approval: str
    verify: str
    proceed: str


@dataclass(frozen=True, slots=True)
class GrindPublication:
    """Project-relative outputs written by one grind report transaction."""

    transaction_id: str
    report: Path
    cold_json: Path | None
    cold_html: Path | None


def grind_approval_argv(
    root: Path,
    plan_relative: str,
    *,
    exact: bool,
    execution_argv: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Return the argv that re-runs one plan with the acceptance its outcome earned."""

    return (
        "rbit",
        "discover",
        "grind",
        str(root),
        "--expert-plan",
        plan_relative,
        "--accept-exact" if exact else "--accept-progress",
        *execution_argv,
    )


def render_cold_verification(
    root: Path,
    layout: GrindReportLayout,
    solution: GrindSolution,
) -> dict[Path, bytes]:
    """Render the cold verification pair keyed by project-relative output path."""

    return {
        relative_output(root, str(layout.cold_json)): canonical_json(solution.report),
        relative_output(root, str(layout.cold_html)): render_report_html(
            solution.report,
            canonical_json_href=layout.cold_json.name,
        ).encode("utf-8"),
    }


def publish_grind_outcome(
    root: Path,
    state_root: Path,
    layout: GrindReportLayout,
    result: ProjectGrindResult,
    *,
    plan_relative: str,
    commands: GrindReportCommands,
    cold_files: Mapping[Path, bytes],
    extra_files: Mapping[Path, bytes] = MappingProxyType({}),
) -> GrindPublication:
    """Atomically publish one grind decision report with its cold verification pair.

    ``cold_files`` comes from :func:`render_cold_verification` (or is empty when
    there is nothing to link); stale cold outputs from an earlier run are
    deleted in the same transaction so a report never links a foreign result.
    """

    report_output = relative_output(root, str(layout.report))
    cold_json_output = relative_output(root, str(layout.cold_json))
    cold_html_output = relative_output(root, str(layout.cold_html))
    files = dict(extra_files)
    files.update(cold_files)
    cold_json_link: str | None = None
    cold_html_link: str | None = None
    if cold_files:
        start = report_output.parent.as_posix()
        cold_json_link = posixpath.relpath(cold_json_output.as_posix(), start=start)
        cold_html_link = posixpath.relpath(cold_html_output.as_posix(), start=start)
    files[report_output] = render_grind_report_html(
        result,
        plan_relative=plan_relative,
        cold_report_html=cold_html_link,
        cold_report_json=cold_json_link,
        approval_command=commands.approval,
        verify_command=commands.verify,
        continue_command=commands.proceed,
    ).encode("utf-8")
    with report_publication_lease(state_root):
        transaction = CASTransaction(root)
        for owned in (cold_json_output, cold_html_output):
            if owned not in files and os.path.lexists(root / owned):
                transaction.delete(owned)
        for relative, payload in sorted(files.items(), key=lambda item: item[0].as_posix()):
            transaction.write(relative, payload)
        transaction_id = transaction.commit().transaction_id
    return GrindPublication(
        transaction_id=transaction_id,
        report=report_output,
        cold_json=cold_json_output if cold_files else None,
        cold_html=cold_html_output if cold_files else None,
    )


__all__ = [
    "GrindPublication",
    "GrindReportCommands",
    "GrindReportLayout",
    "grind_approval_argv",
    "publish_grind_outcome",
    "render_cold_verification",
    "render_grind_report_html",
]
