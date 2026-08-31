"""Human report for one bounded project-wide grind campaign."""

from __future__ import annotations

from reprobit.discovery_project_grind import ProjectAutoGrindResult
from reprobit.report_html_components import (
    Markup,
    code,
    count_phrase,
    escape,
    format_integer,
    table,
)
from reprobit.report_html_style import REPORT_CSS, REPORT_SCRIPT, REPROBIT_MARK_SVG

_PROJECT_GRIND_CSS = r"""
.metric-grid { margin-top: 1rem; }
.metric-grid .value { font-variant-numeric: tabular-nums; }
.outcome-ok { color: var(--ok); font-weight: 700; }
.outcome-muted { color: var(--muted); }
""".strip()

_REFERENCE_ARGUMENT = "--reference-object TU=PATH"


def _skip_reason(reason: str) -> str | Markup:
    """Code-style the one documented command fragment without trusting skip text."""

    if _REFERENCE_ARGUMENT not in reason:
        return reason
    before, after = reason.split(_REFERENCE_ARGUMENT, 1)
    return Markup(
        f"{escape(before)}{code(_REFERENCE_ARGUMENT).html}{escape(after)}",
        reason,
    )


def render_project_auto_grind_report_html(
    result: ProjectAutoGrindResult,
    *,
    outcome_reports: tuple[str | None, ...],
    summary_json: str,
    next_step_label: str | None = None,
    next_step_command: str | None = None,
) -> str:
    """Render a compact campaign index with links to per-symbol evidence."""

    if len(outcome_reports) != len(result.outcomes):
        raise ValueError("project grind report links differ from campaign outcomes")
    if result.published and result.exact:
        tone = "ok"
        heading = "Exact project reproduced"
        explanation = (
            "ReproBit saved locally proven adjustments in sequence. The final fresh build "
            "matched every target byte for byte, which is the project certification gate."
        )
    elif result.published:
        tone = "warn"
        heading = "Locally proven progress saved"
        explanation = (
            "ReproBit saved only functions that matched their project-owned reference objects "
            "and passed the required logic checks. The complete project does not match yet, "
            "so no project certification was issued."
        )
    elif result.exact:
        tone = "ok"
        heading = "Proven adjustments ready for review"
        explanation = (
            "ReproBit found exact low-cost adjustments, but this preview left project files "
            "unchanged."
        )
    elif result.qualified:
        tone = "warn"
        heading = "Locally proven adjustments ready for review"
        explanation = (
            "ReproBit found low-cost function adjustments that passed their local proof checks, "
            "but the complete project does not match yet. This preview left project files "
            "unchanged."
        )
    else:
        tone = "warn"
        heading = "Bounded project search complete"
        explanation = (
            "No attempted function produced a locally proven adjustment within the current "
            "low-cost search limits. Project files stayed unchanged."
        )
    metrics = (
        ("Functions tried", len(result.outcomes), "bounded project scope"),
        ("Locally proven", result.qualified, "function and logic checks passed"),
        ("Project exact", result.exact, "all targets matched in a fresh build"),
        ("Saved", result.published, "explicitly accepted"),
        ("Skipped", len(result.campaign.skips), "unavailable or ineligible"),
    )
    metric_cards = "".join(
        f'<article class="card"><h3>{escape(label)}</h3>'
        f'<div class="value">{format_integer(value)}</div><p>{escape(detail)}</p></article>'
        for label, value, detail in metrics
    )
    outcome_rows = []
    for outcome, report in zip(result.outcomes, outcome_reports, strict=True):
        if outcome.published:
            label = "Exact saved" if outcome.exact else "Progress saved"
            status = Markup(f'<span class="outcome-ok">{label}</span>', label)
        elif outcome.exact:
            status = Markup(
                '<span class="outcome-ok">Exact preview</span>',
                "Exact preview",
            )
        elif outcome.locally_qualified:
            status = Markup(
                '<span class="outcome-ok">Local preview</span>',
                "Local preview",
            )
        else:
            status = Markup(
                '<span class="outcome-muted">No proven state</span>',
                "No proven state",
            )
        evidence = (
            Markup(
                f'<a class="machine-link" href="{escape(report)}" '
                f'aria-label="Open decision for {escape(outcome.item.symbol)} in '
                f'{escape(outcome.item.translation_unit_id)}">Open decision</a>',
                "Open decision",
            )
            if report is not None
            else "Unavailable"
        )
        outcome_rows.append(
            (
                code(outcome.item.translation_unit_id, css_class="identifier"),
                code(outcome.item.symbol, css_class="identifier"),
                status,
                format_integer(outcome.added_cost) if outcome.locally_qualified else "—",
                evidence,
            )
        )
    skip_rows = tuple(
        (
            code(skip.translation_unit_id or "—", css_class="identifier"),
            code(skip.reference_object or "—"),
            _skip_reason(skip.reason),
        )
        for skip in result.campaign.skips
    )
    truncation = ""
    if result.campaign.truncated_symbols:
        truncation = (
            f"<p><strong>Bound reached:</strong> "
            f"{count_phrase(result.campaign.truncated_symbols, 'additional function')} "
            "was not attempted. Increase <code>--max-symbols</code> deliberately to continue."
            "</p>"
        )
    next_step = ""
    if next_step_label is not None and next_step_command is not None:
        next_step = f"""
<section class="section" id="next-step" aria-labelledby="next-step-title">
  <p class="eyebrow">Copy and run</p>
  <h2 id="next-step-title">Next step</h2>
  <article class="card">
    <p>{escape(next_step_label)}</p>
    <pre><code>{escape(next_step_command)}</code></pre>
  </article>
</section>"""
    title = f"{result.campaign.project_id} — ReproBit project grind"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{escape(title)}</title>
<style>{REPORT_CSS}\n{_PROJECT_GRIND_CSS}</style>
</head>
<body>
<a class="skip-link" href="#overview">Skip to report</a>
<header class="topbar"><div class="topbar-inner">
  <div class="brand">{REPROBIT_MARK_SVG}<span class="brand-label">
    ReproBit project grind · <code>{escape(result.campaign.project_id)}</code>
  </span></div>
  <div class="run-label">Bounded low-cost search</div>
</div></header>
<nav class="section-nav" aria-label="Report sections"><ul>
  <li><a href="#overview">Overview</a></li>
  <li><a href="#outcomes">Outcomes</a></li>
  {('<li><a href="#next-step">Next step</a></li>' if next_step else "")}
  <li><a href="#skips">Skipped</a></li>
</ul></nav>
<main>
<section class="hero {escape(tone)}" id="overview" aria-labelledby="report-title">
  <p class="eyebrow">Project-wide automatic search</p>
  <h1 id="report-title">{escape(heading)}</h1>
  <p class="lede">{escape(explanation)}</p>
  <div class="card-grid metric-grid">{metric_cards}</div>
  {truncation}
</section>
<section class="section" id="outcomes" aria-labelledby="outcomes-title">
  <p class="eyebrow">Freshly checked functions</p>
  <h2 id="outcomes-title">Search outcomes</h2>
  {
        table(
            ("Translation unit", "Function", "Outcome", "Added cost", "Evidence"),
            tuple(outcome_rows),
            caption="Every attempted project function",
            empty_message="No eligible function was available within the project scope.",
        )
    }
</section>
{next_step}
<section class="section" id="skips" aria-labelledby="skips-title">
  <p class="eyebrow">Scope diagnostics</p>
  <h2 id="skips-title">What was not attempted</h2>
  {
        table(
            ("Translation unit", "Reference object", "Reason"),
            skip_rows,
            caption="Unavailable or ineligible project inputs",
            empty_message="No project input was skipped.",
        )
    }
</section>
</main>
<footer class="footer"><div class="footer-inner">
  Canonical summary:
  <a class="machine-link" href="{escape(summary_json)}"><code>{escape(summary_json)}</code></a>
  · deterministic local HTML ·
  no external assets
</div></footer>
<script>{REPORT_SCRIPT}</script>
</body>
</html>
"""


__all__ = ["render_project_auto_grind_report_html"]
