"""Human report for one bounded project-wide grind campaign."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from reprobit.discovery_project_grind import ProjectAutoGrindResult
from reprobit.report_html_components import (
    Markup,
    OutcomeBranch,
    code,
    count_phrase,
    escape,
    format_integer,
    metric_cards,
    outcome_summary,
    page_shell,
    table,
)

_PROJECT_GRIND_CSS = r"""
.metric-grid { margin-top: 1rem; }
.metric-grid .value { font-variant-numeric: tabular-nums; }
.outcome-ok { color: var(--ok); font-weight: 700; }
.outcome-muted { color: var(--muted); }
""".strip()

_REFERENCE_ARGUMENT = "--reference-object TU=PATH"

_OUTCOME_COPY: Mapping[OutcomeBranch, tuple[str, str]] = MappingProxyType(
    {
        "published-exact": (
            "Exact project reproduced",
            "ReproBit saved locally proven adjustments in sequence. The final fresh build "
            "matched every target byte for byte, which is the project certification gate.",
        ),
        "published": (
            "Locally proven progress saved",
            "ReproBit saved only functions that matched their project-owned reference objects "
            "and passed the required logic checks. The complete project does not match yet, "
            "so no project certification was issued.",
        ),
        "exact": (
            "Proven adjustments ready for review",
            "ReproBit found exact low-cost adjustments, but this preview left project files "
            "unchanged.",
        ),
        "qualified": (
            "Locally proven adjustments ready for review",
            "ReproBit found low-cost function adjustments that passed their local proof checks, "
            "but the complete project does not match yet. This preview left project files "
            "unchanged.",
        ),
        "exhausted": (
            "Bounded project search complete",
            "No attempted function produced a locally proven adjustment within the current "
            "low-cost search limits. Project files stayed unchanged.",
        ),
    }
)


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
    _branch, tone, heading, explanation = outcome_summary(
        published=bool(result.published),
        exact=bool(result.exact),
        qualified=bool(result.qualified),
        copy=_OUTCOME_COPY,
    )
    metrics = (
        ("Functions tried", len(result.outcomes), "bounded project scope"),
        ("Locally proven", result.qualified, "function and logic checks passed"),
        ("Project exact", result.exact, "all targets matched in a fresh build"),
        ("Saved", result.published, "explicitly accepted"),
        ("Skipped", len(result.campaign.skips), "unavailable or ineligible"),
    )
    rendered_metrics = metric_cards(metrics)
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
    nav = f"""<nav class="section-nav" aria-label="Report sections"><ul>
  <li><a href="#overview">Overview</a></li>
  <li><a href="#outcomes">Outcomes</a></li>
  {('<li><a href="#next-step">Next step</a></li>' if next_step else "")}
  <li><a href="#skips">Skipped</a></li>
</ul></nav>"""
    main = f"""<section class="hero {escape(tone)}" id="overview" aria-labelledby="report-title">
  <p class="eyebrow">Project-wide automatic search</p>
  <h1 id="report-title">{escape(heading)}</h1>
  <p class="lede">{escape(explanation)}</p>
  <div class="card-grid metric-grid">{rendered_metrics}</div>
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
</section>"""
    return page_shell(
        title=f"{result.campaign.project_id} — ReproBit project grind",
        brand=f"ReproBit project grind · <code>{escape(result.campaign.project_id)}</code>",
        run_label="Bounded low-cost search",
        nav=nav,
        main=main,
        footer=(
            "Canonical summary:\n"
            f'  <a class="machine-link" href="{escape(summary_json)}">'
            f"<code>{escape(summary_json)}</code></a>\n"
            "  · deterministic local HTML ·\n  no external assets"
        ),
        extra_css=_PROJECT_GRIND_CSS,
    )


__all__ = ["render_project_auto_grind_report_html"]
