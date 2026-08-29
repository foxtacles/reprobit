"""Human-first, deterministic HTML rendering for ReproBit reports."""

from __future__ import annotations

from reprobit.model import Scope
from reprobit.report import Report
from reprobit.report_html_advanced import render_advanced
from reprobit.report_html_components import (
    Bar,
    Content,
    Markup,
    bar_chart,
    code,
    count_phrase,
    escape,
    format_integer,
    join_markup,
    render_content,
    short_digest,
)
from reprobit.report_html_format import (
    cost_class_label,
    format_bytes,
    format_fraction,
    format_seconds,
    function_total,
    human_label,
    readable_function,
)
from reprobit.report_html_style import REPORT_CSS, REPORT_SCRIPT


def _status_copy(report: Report) -> tuple[str, str, str]:
    if report.verdict.clean:
        return (
            "ok",
            "Exact and clean",
            "Every target matches its reference byte for byte. The evidence traces every "
            "output to this run's sources, locked toolchain, and reviewed interventions.",
        )
    if not report.verdict.byte_exact:
        starting_point = (
            "unresolved audit findings"
            if report.proof.audit_issues
            else "the target comparison records"
        )
        return (
            "bad",
            "Targets do not yet match",
            "At least one rebuilt target differs from its reference. Start with the target "
            f"cards and {starting_point} below.",
        )
    if (
        report.verdict.cold
        and report.verdict.logic_certified
        and report.verdict.quarantined
    ):
        return (
            "warn",
            "Exact match, with authenticity exceptions",
            "Every target matches its reference byte for byte. A small, explicitly listed "
            "set of bytes still comes from the reference binaries rather than this run's "
            "compiler toolchain.",
        )
    issues: list[str] = []
    if not report.verdict.cold:
        issues.append("the result did not come from a cold build")
    if not report.verdict.logic_certified:
        issues.append("the required logic checks did not pass")
    if report.verdict.quarantined:
        issues.append("some bytes came from disclosed reference data")
    elif not report.verdict.toolchain_origin:
        issues.append("fresh-output origin is not fully proven")
    if len(issues) == 1:
        heading = {
            "the result did not come from a cold build": "Exact match, but not cold-verified",
            "the required logic checks did not pass": "Exact match, with failed logic checks",
            "fresh-output origin is not fully proven": "Exact match, with origin evidence issues",
        }.get(issues[0], "Exact match, with authenticity exceptions")
        issue_text = issues[0]
    elif len(issues) == 2:
        heading = "Exact match, with verification issues"
        issue_text = f"{issues[0]} and {issues[1]}"
    else:
        heading = "Exact match, with verification issues"
        issue_text = ", ".join(issues[:-1]) + f", and {issues[-1]}"
    return (
        "warn",
        heading,
        "Every target matches its reference byte for byte. However, "
        f"{issue_text}. This result is not yet clean.",
    )


def _claim(label: str, value: bool, *, warning: bool = False) -> str:
    tone = "ok" if value else ("warn" if warning else "bad")
    state = "passed" if value else ("exception" if warning else "not passed")
    return f'<span class="claim {tone}">{escape(label)}: {escape(state)}</span>'


def _scope_key(scope: Scope) -> tuple[str, str | None, str | None]:
    return (scope.target, scope.translation_unit, scope.function)


def _render_overview(report: Report) -> str:
    tone, heading, explanation = _status_copy(report)
    claims = "".join(
        (
            _claim("Byte identity", report.verdict.byte_exact),
            _claim("Logic checks", report.verdict.logic_certified),
            _claim(
                "Fresh-output origin",
                report.verdict.toolchain_origin,
                warning=report.verdict.quarantined,
            ),
            _claim("Cold build", report.verdict.cold),
        )
    )
    quarantine = ""
    if report.verdict.quarantined:
        action_count = len(report.verdict.quarantines)
        range_count = sum(len(item.ranges) for item in report.verdict.quarantines)
        byte_count = sum(item.byte_count for item in report.verdict.quarantines)
        intervention_summary = count_phrase(action_count, "intervention")
        range_summary = count_phrase(range_count, "range")
        byte_summary = count_phrase(byte_count, "byte")
        effect_verb = "affects" if action_count == 1 else "affect"
        quarantine = f"""
<aside class="callout" aria-labelledby="quarantine-summary-title">
  <h2 id="quarantine-summary-title">Disclosed authenticity exceptions remain</h2>
  <p><strong>{escape(intervention_summary)} {escape(effect_verb)} {escape(range_summary)}
    ({escape(byte_summary)} total).</strong> Those bytes come from frozen reference data.
    These exceptions are one reason why the result is exact but not yet clean.</p>
  <a href="#quarantine-details">Review the exact ranges and supporting evidence</a>
</aside>"""
    return f"""
<section class="hero {tone}" id="overview" aria-labelledby="report-title">
  <p class="eyebrow">Reproduction outcome</p>
  <h1 id="report-title">{escape(heading)}</h1>
  <p class="lede">{escape(explanation)}</p>
  <div class="claim-row" aria-label="Result checks">{claims}</div>
  {quarantine}
</section>"""


def _render_target_cards(report: Report) -> str:
    cards = []
    for target in report.targets:
        candidate_recorded = (
            target.candidate_digest is not None and target.candidate_size is not None
        )
        digest = target.candidate_digest.value if target.candidate_digest is not None else None
        if target.byte_exact:
            status = "Byte-for-byte match"
        elif not candidate_recorded:
            status = "No rebuilt output recorded"
        else:
            status = "Does not match"
        status_tone = "" if target.byte_exact else " bad"
        size = (
            format_bytes(target.candidate_size)
            if target.candidate_size is not None
            else "Size not recorded"
        )
        digest_line = (
            f'<code class="digest" title="{escape(digest)}">'
            f"SHA-256 {escape(short_digest(digest))}</code>"
            if digest is not None
            else '<span class="digest missing">SHA-256 not recorded</span>'
        )
        comparison_link = (
            ""
            if target.byte_exact
            else '<p><a href="#outcome-details">Open comparison records</a></p>'
        )
        cards.append(
            f"""<article class="card">
  <p class="eyebrow"><code>{escape(target.id)}</code></p>
  <div class="status{status_tone}">{escape(status)}</div>
  <div class="value">{escape(size)}</div>
  <p class="token"><code>{escape(target.artifact)}</code></p>
  {digest_line}
  {comparison_link}
</article>"""
        )
    return f"""
<section class="section" id="targets" aria-labelledby="targets-title">
  <div class="section-heading"><div><p class="eyebrow">What was rebuilt</p>
    <h2 id="targets-title">Target results</h2></div>
    <p>{sum(item.byte_exact for item in report.targets)} of {len(report.targets)} exact</p></div>
  <div class="card-grid">{''.join(cards)}</div>
</section>"""


def _render_costs(report: Report) -> str:
    if report.costs.project_total == 0:
        return """
<section class="section" id="costs" aria-labelledby="costs-title">
  <div class="section-heading"><div><p class="eyebrow">Intervention effort</p>
    <h2 id="costs-title">Cost overview</h2></div>
    <p><strong>0</strong> relative points</p></div>
  <div class="card"><h3>No interventions were needed</h3>
    <p>This run reached its result without any ReproBit intervention cost.</p></div>
</section>"""
    class_bars = tuple(
        Bar(
            label=cost_class_label(item.cost_class),
            detail=(
                f"{count_phrase(item.interventions, 'intervention')} · "
                f"{count_phrase(item.units, 'unit')}"
            ),
            value=float(item.cost),
            display_value=format_integer(item.cost),
            tone="hot" if item.cost_class.value == "oracle_install" else "normal",
        )
        for item in sorted(report.costs.by_class, key=lambda row: (-row.cost, row.cost_class.value))
    )
    target_bars = tuple(
        Bar(
            label=code(item.target),
            detail=(
                f"{count_phrase(item.interventions, 'intervention')} · "
                f"{count_phrase(item.units, 'unit')}"
            ),
            value=float(item.cost),
            display_value=format_integer(item.cost),
        )
        for item in sorted(report.costs.by_target, key=lambda row: (-row.cost, row.target))
    )
    quarantine_scopes = {
        _scope_key(item.scope)
        for item in report.verdict.quarantines
        if item.scope is not None and item.scope.function is not None
    }
    hotspots = sorted(
        report.costs.by_function,
        key=lambda item: (
            -function_total(item),
            item.scope.target,
            item.scope.translation_unit or "",
            item.scope.function or "",
        ),
    )[:10]
    hotspot_bars = tuple(
        Bar(
            label=code(readable_function(item.scope.function or "Unnamed function")),
            detail=join_markup(
                (
                    code(item.scope.target),
                    code(item.scope.translation_unit or "shared"),
                    *(
                        (
                            Markup(
                                '<span class="exception-note">authenticity exception</span>',
                                "authenticity exception",
                            ),
                        )
                        if _scope_key(item.scope) in quarantine_scopes
                        else ()
                    ),
                ),
                separator=" · ",
            ),
            value=float(function_total(item)),
            display_value=format_fraction(function_total(item)),
            tone=(
                "hot"
                if _scope_key(item.scope) in quarantine_scopes
                else "normal"
            ),
        )
        for item in hotspots
    )
    charts = "".join(
        (
            bar_chart(
                identity="cost-class-chart",
                title="Cost by intervention class",
                description="Where the relative intervention effort is concentrated.",
                bars=class_bars,
            ),
            bar_chart(
                identity="cost-target-chart",
                title="Cost by target",
                description="Which output carries the intervention work.",
                bars=target_bars,
            ),
        )
    )
    hotspot_chart = bar_chart(
        identity="cost-hotspot-chart",
        title="Top function hotspots",
        description="Direct cost plus the function's allocated share of broader work.",
        bars=hotspot_bars,
    )
    attributed = report.costs.project_total - report.costs.unallocated_shared_cost
    unallocated_percent = (
        0.0
        if report.costs.project_total == 0
        else report.costs.unallocated_shared_cost / report.costs.project_total * 100
    )
    return f"""
<section class="section" id="costs" aria-labelledby="costs-title">
  <div class="section-heading"><div><p class="eyebrow">Where intervention effort lives</p>
    <h2 id="costs-title">Cost overview</h2></div>
    <p><strong>{format_integer(report.costs.project_total)}</strong> relative points</p></div>
  <p class="explain"><strong>Cost ranks interventions; it is not elapsed time.</strong>
    Higher scores mark more invasive or less authentic work. A TU is one source file as the
    compiler sees it. <code>Oracle install</code> identifies the disclosed reference-byte
    exceptions and is deliberately weighted heavily.</p>
  <div class="card-grid cost-reconciliation" aria-label="Function cost attribution">
    <div class="card"><h3>Project total</h3>
      <div class="value">{format_integer(report.costs.project_total)}</div>
      <p>All typed work; intervention IDs deduplicated</p></div>
    <div class="card"><h3>Attributed to functions</h3>
      <div class="value">{format_integer(attributed)}</div>
      <p>Direct work plus allocated shares</p></div>
    <div class="card"><h3>Unallocated project/TU shared</h3>
      <div class="value">{format_integer(report.costs.unallocated_shared_cost)}</div>
      <p>{unallocated_percent:.1f}% of the project total</p></div>
  </div>
  <p class="explain"><strong>Function totals are direct cost plus allocated shared cost.</strong>
    The advanced table also shows exposure: the full shared intervention cost touching each
    function. Exposure is context, not an additive total, so do not sum it.</p>
  <div class="chart-grid">{charts}</div>
  <div style="margin-top:1rem">{hotspot_chart}</div>
</section>"""


def _render_timings(report: Report) -> str:
    if not report.timings:
        return ""
    bars = tuple(
        Bar(
            label=human_label(item.stage),
            detail="Recorded wall time",
            value=item.seconds,
            display_value=format_seconds(item.seconds),
        )
        for item in sorted(report.timings, key=lambda row: (-row.seconds, row.stage))
    )
    chart = bar_chart(
        identity="timing-chart",
        title="Stage timing",
        description="Time spent in each top-level verification stage.",
        bars=bars,
    )
    total = sum(item.seconds for item in report.timings)
    return f"""
<section class="section" id="timing" aria-labelledby="timing-title">
  <div class="section-heading"><div><p class="eyebrow">How long the run took</p>
    <h2 id="timing-title">Build and verification timing</h2></div>
    <p>{escape(format_seconds(total))} recorded</p></div>
  {chart}
</section>"""


def _next_steps(report: Report) -> tuple[tuple[str, Content], ...]:
    if not report.verdict.byte_exact:
        mismatches = tuple(item.id for item in report.targets if not item.byte_exact)
        mismatch_html = (
            ", ".join(code(item).html for item in mismatches)
            or "the target receipts"
        )
        mismatch_markup = Markup(
            "Inspect " + mismatch_html + " before changing interventions.",
            "Inspect "
            + (", ".join(mismatches) or "the target receipts")
            + " before changing interventions.",
        )
        return (
            (
                "Start with the mismatched targets",
                mismatch_markup,
            ),
            (
                "Use the highest-cost hotspot as a guide",
                "Review the responsible intervention and its exact semantic receipt.",
            ),
            (
                "Rerun cold",
                "Confirm the next result from a fresh build before treating a match as stable.",
            ),
        )
    if not report.verdict.cold or not report.verdict.logic_certified:
        steps: list[tuple[str, Content]] = []
        if not report.verdict.cold:
            steps.append(
                (
                    "Confirm the match with a cold build",
                    "Rebuild from a clean workspace before treating the byte match as stable.",
                )
            )
        if not report.verdict.logic_certified:
            steps.append(
                (
                    "Resolve the failed logic checks",
                    "Review the proof details and fix every intervention whose required check "
                    "did not pass.",
                )
            )
        if report.verdict.quarantined:
            steps.append(
                (
                    "Remove the disclosed reference-byte exceptions",
                    "Replace those ranges with fresh compiler output while preserving the exact "
                    "match.",
                )
            )
        elif not report.verdict.toolchain_origin:
            steps.append(
                (
                    "Restore fresh-output origin evidence",
                    "Use the audit details below to trace every output back to this run.",
                )
            )
        if len(steps) < 3:
            steps.append(
                (
                    "Keep release blocked until every check passes",
                    "Require a cold, exact, logic-certified, clean report in CI.",
                )
            )
        return tuple(steps[:3])
    if report.verdict.quarantined:
        return (
            (
                "Rebuild the exception functions without reference bytes",
                "Replace the disclosed ranges with fresh compiler output while keeping every "
                "target byte-for-byte exact.",
            ),
            (
                "Confirm the result with another cold build",
                "The next milestone is an exact result with complete origin evidence and no "
                "authenticity exceptions.",
            ),
            (
                "Keep byte identity enforced in CI",
                "Continue checking every target digest while the remaining exceptions are "
                "removed.",
            ),
        )
    if report.proof.audit_issues or not report.verdict.toolchain_origin:
        return (
            (
                "Resolve the evidence findings",
                "Use the audit details below to restore complete current-run ancestry.",
            ),
            (
                "Rerun against the locked toolchain",
                "A cold run should close both byte identity and origin checks.",
            ),
            (
                "Promote only a clean result",
                "Treat exact output and clean authenticity as separate release gates.",
            ),
        )
    return (
        (
            "Keep this result reproducible",
            "Retain the source, toolchain lock, interventions, and canonical report together.",
        ),
        ("Enforce it in CI", "Require a cold, exact, clean report for future changes."),
        (
            "Investigate cost only when useful",
            "Lower cost improves maintainability, but this result already satisfies "
            "identity and authenticity.",
        ),
    )


def _render_next_steps(report: Report) -> str:
    items = "".join(
        f'<li class="next-step"><strong>{escape(title)}</strong>'
        f"<span>{render_content(detail)}</span></li>"
        for title, detail in _next_steps(report)
    )
    return f"""
<section class="section" id="next-steps" aria-labelledby="next-title">
  <p class="eyebrow">What to do next</p><h2 id="next-title">Recommended next steps</h2>
  <ol class="steps">{items}</ol>
</section>"""



def _render_navigation(report: Report) -> str:
    links = [
        ("Overview", "#overview"),
        ("Targets", "#targets"),
        ("Costs", "#costs"),
    ]
    if report.timings:
        links.append(("Timing", "#timing"))
    links.extend((("Next steps", "#next-steps"), ("Advanced", "#advanced")))
    items = "".join(
        f'<li><a href="{escape(target)}">{escape(label)}</a></li>'
        for label, target in links
    )
    return f'<nav class="section-nav" aria-label="Report sections"><ul>{items}</ul></nav>'


def render_report_html(report: Report) -> str:
    """Render a deterministic, dependency-free report with layered evidence detail."""

    title = f"{report.project_id} — ReproBit report"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{escape(title)}</title>
<style>{REPORT_CSS}</style>
</head>
<body>
<a class="skip-link" href="#overview">Skip to report</a>
<header class="topbar"><div class="topbar-inner">
  <div class="brand">ReproBit · <code>{escape(report.project_id)}</code></div>
  <div class="run-label">Run <code>{escape(short_digest(report.run_id.value))}</code></div>
</div></header>
{_render_navigation(report)}
<main>
{_render_overview(report)}
{_render_target_cards(report)}
{_render_costs(report)}
{_render_timings(report)}
{_render_next_steps(report)}
{render_advanced(report)}
</main>
<footer class="footer"><div class="footer-inner">
  ReproBit report schema <code>v{report.schema_version}</code> · deterministic local HTML ·
  no external assets
</div></footer>
<script>{REPORT_SCRIPT}</script>
</body>
</html>
"""


__all__ = ["render_report_html"]
