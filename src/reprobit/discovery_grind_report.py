"""Self-contained human report for one bounded project grind."""

from __future__ import annotations

from collections import Counter

from reprobit.discovery_contracts import declaration_state_id
from reprobit.discovery_grind import GrindRejection, ProjectGrindResult
from reprobit.report_html_components import (
    Bar,
    bar_chart,
    code,
    count_phrase,
    details,
    escape,
    format_integer,
    table,
)
from reprobit.report_html_style import REPORT_CSS, REPORT_SCRIPT, REPROBIT_MARK_SVG

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


def _summary(result: ProjectGrindResult) -> tuple[str, str, str, tuple[str, ...]]:
    if result.published:
        return (
            "ok",
            "Exact adjustment saved",
            "The chosen compiler settings passed a fresh verification build, matched every "
            "target byte for byte, and passed the required logic checks. ReproBit then saved "
            "the adjustment and its supporting verification records together.",
            (
                _claim("Exact match", tone="ok"),
                _claim("Fresh verification passed", tone="ok"),
                _claim("Project files updated", tone="ok"),
            ),
        )
    if result.exact:
        return (
            "ok",
            "Exact adjustment ready for review",
            "The chosen compiler settings passed a fresh verification build, matched every "
            "target byte for byte, and passed the required logic checks. This preview wrote "
            "only review reports; the project files stayed unchanged.",
            (
                _claim("Exact match", tone="ok"),
                _claim("Fresh verification passed", tone="ok"),
                _claim("Review only", tone="warn"),
            ),
        )
    return (
        "warn",
        "No exact adjustment within these search limits",
        "The complete bounded search finished without an admissible byte-identical state. "
        "No project files changed.",
        (
            _claim("Search complete", tone="ok"),
            _claim("No exact match", tone="warn"),
            _claim("Project files unchanged", tone="ok"),
        ),
    )


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
            label="Exact",
            detail="Passed byte identity and logic checks",
            value=float(int(result.exact)),
            display_value=str(int(result.exact)),
        ),
    )
    return bar_chart(
        identity="grind-funnel",
        title="Search funnel",
        description="How the bounded states narrowed to a verified exact result.",
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
        empty_message="No candidate was rejected before the exact state was chosen.",
    )


def _decision(
    result: ProjectGrindResult,
    *,
    plan_relative: str,
    cold_report_html: str | None,
    approval_command: str | None,
    verify_command: str,
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
        publish_status = '<div class="status">Project files updated</div>'
        publish_detail = "The adjustment and verification records were saved together."
        files_label = "Changed files"
        next_commands = f"""
  <p><strong>Review the changed project files, then verify again from scratch:</strong></p>
  <pre><code>git diff
{escape(verify_command)}</code></pre>"""
    else:
        publish_status = '<div class="status warn">Preview only — project files unchanged</div>'
        publish_detail = "Run the approval command only after reviewing this result."
        files_label = "Files approval would change"
        rendered_approval = approval_command or (
            f"rbit discover grind . --plan {plan_relative} --accept-exact"
        )
        next_commands = f"""
  <p><strong>Rerun the proof and save the result if it still passes:</strong></p>
  <pre><code>{escape(rendered_approval)}</code></pre>"""
    verification = ""
    if cold_report_html is not None:
        verification = f"""
  <a class="machine-link" href="{escape(cold_report_html)}">Open fresh verification report</a>
  <p class="technical-path">Path: <code>{escape(cold_report_html)}</code></p>"""
    return f"""
<article class="card decision-card ok">
  <p class="eyebrow"><code>{escape(state_id)}</code></p>
  <h3>Selected compiler settings</h3>
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
        ("Cold trials", str(result.cold_trials)),
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
        ("Cold report JSON", cold_report_json or "not available"),
    )
    definitions = "".join(
        f"<dt>{escape(label)}</dt><dd><code>{escape(value)}</code></dd>" for label, value in values
    )
    rejection_rows = tuple(
        (
            code(item.state_id, css_class="identifier"),
            "Qualification" if item.stage == "qualification" else "Cold verification",
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
) -> str:
    """Render one deterministic grind outcome, including bounded failure."""

    tone, heading, explanation, claims = _summary(result)
    title = f"{result.project_id} — ReproBit grind report"
    metrics = "".join(
        (
            f'<article class="card"><h3>States</h3><div class="value">'
            f"{format_integer(result.states)}</div><p>bounded and attempted</p></article>",
            f'<article class="card"><h3>Compiler trials</h3><div class="value">'
            f"{format_integer(result.compiler_trials)}</div>"
            "<p>current source plus alternatives</p></article>",
            f'<article class="card"><h3>Fresh verifications</h3><div class="value">'
            f"{format_integer(result.cold_trials)}</div><p>fresh verification runs</p></article>",
        )
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{escape(title)}</title>
<style>{REPORT_CSS}\n{_GRIND_CSS}</style>
</head>
<body>
<a class="skip-link" href="#overview">Skip to report</a>
<header class="topbar"><div class="topbar-inner">
  <div class="brand">{REPROBIT_MARK_SVG}<span class="brand-label">
    ReproBit grind · <code>{escape(result.project_id)}</code>
  </span></div>
  <div class="run-label">Target <code>{escape(result.target_id)}</code></div>
</div></header>
<nav class="section-nav" aria-label="Report sections"><ul>
  <li><a href="#overview">Overview</a></li>
  <li><a href="#decision">Decision</a></li>
  <li><a href="#funnel">Funnel</a></li>
  <li><a href="#rejections">Rejections</a></li>
  <li><a href="#technical-details">Technical details</a></li>
</ul></nav>
<main>
<section class="hero {escape(tone)}" id="overview" aria-labelledby="report-title">
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
</section>
</main>
<footer class="footer"><div class="footer-inner">
  ReproBit bounded grind · plan <code>{escape(plan_relative)}</code> · deterministic local HTML ·
  no external assets
</div></footer>
<script>{REPORT_SCRIPT}</script>
</body>
</html>
"""


__all__ = ["render_grind_report_html"]
