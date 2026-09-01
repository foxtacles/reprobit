"""Human-first HTML rendering for non-certifying discovery reports."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from pathlib import PurePosixPath

from reprobit.discovery_contracts import (
    DeclarationFamily,
    DeclarationState,
    DiscoveryArtifactReceipt,
    DiscoveryCampaignReport,
    DiscoveryFindingKind,
    DiscoveryProposal,
    DiscoveryStateExport,
)
from reprobit.report_html_components import (
    Bar,
    bar_chart,
    code,
    count_phrase,
    details,
    escape,
    format_integer,
    metric_cards,
    page_shell,
    table,
)
from reprobit.strict_json import canonical_json, strict_loads

_PROPOSAL_CARD_LIMIT = 100
_OBSERVATION_ROW_LIMIT = 200
_SELECTED_RECEIPT_LIMIT = 200
_DECLARATION_DETAIL_LIMIT = 50
_DECLARATION_HTML_BYTE_LIMIT = 256 * 1024

_DISCOVERY_CSS = r"""
.discovery-hero { border-left-color: var(--warn); }
.metric-grid { margin-top: 1rem; }
.metric-grid .card .value { font-variant-numeric: tabular-nums; }
.proposal-list { display: grid; gap: .85rem; }
.proposal-card {
  padding: 1rem;
  background: var(--panel);
  border: 1px solid var(--line);
  border-left: 4px solid var(--accent);
  border-radius: .65rem;
  box-shadow: var(--shadow);
}
.proposal-card header {
  display: flex;
  align-items: start;
  justify-content: space-between;
  gap: 1rem;
}
.proposal-card h3 { margin: 0; font-size: 1.08rem; }
.proposal-kind {
  flex: 0 0 auto;
  padding: .25rem .5rem;
  border-radius: 999px;
  background: var(--accent-soft);
  color: var(--accent);
  font-size: .78rem;
  font-weight: 720;
}
.proposal-rationale { margin: .65rem 0; }
.proposal-facts {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 220px), 1fr));
  gap: .65rem;
  margin-top: .7rem;
}
.proposal-fact {
  min-width: 0;
  padding: .7rem;
  border: 1px solid var(--line);
  border-radius: .45rem;
  background: #fafcfc;
}
.proposal-fact strong { display: block; margin-bottom: .25rem; font-size: .82rem; }
.proposal-fact ul { margin: 0; padding-left: 1.1rem; }
.proposal-fact li + li { margin-top: .2rem; }
.proposal-card details { margin-top: .8rem; }
.proposal-card details > summary { cursor: pointer; font-weight: 680; color: var(--accent); }
.proposal-card .detail-body { padding: .8rem 0 0; }
.notice {
  margin: 1rem 0;
  padding: .8rem 1rem;
  border: 1px solid var(--line);
  border-radius: .55rem;
  background: var(--accent-soft);
}
pre {
  max-height: 28rem;
  overflow: auto;
  padding: .8rem;
  border: 1px solid var(--line);
  border-radius: .45rem;
  background: #f5f8f9;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.compact-list { margin: .4rem 0 0; padding-left: 1.2rem; }
.compact-list li + li { margin-top: .25rem; }
@media (max-width: 680px) {
  .proposal-card header { flex-direction: column; }
}
""".strip()


def _pretty_json(value: object) -> str:
    return json.dumps(
        strict_loads(canonical_json(value)),
        ensure_ascii=False,
        allow_nan=False,
        indent=2,
        sort_keys=True,
    )


def _kind_label(kind: DiscoveryFindingKind) -> str:
    return {
        DiscoveryFindingKind.WHOLE_BODY: "Whole-function match",
        DiscoveryFindingKind.PRIVATE_DONOR: "Private donor",
        DiscoveryFindingKind.INSTRUCTION_MOSAIC: "Instruction mosaic",
    }[kind]


def _family_label(family: DeclarationFamily) -> str:
    return {
        DeclarationFamily.DECLARATION_SHAPE: "Declaration shape",
        DeclarationFamily.PAD_SHAPE: "Padding shape",
        DeclarationFamily.FORWARD_DECLARATION_RUN: "Forward-declaration run",
        DeclarationFamily.EXTERN_RUN_PAIR: "Paired extern run",
    }[family]


def _intervention_label(kind: str) -> str:
    return {
        "state_carrier": "State carrier",
        "equal_body_donor": "Equal-body donor",
        "binary_surgery": "Instruction mosaic",
    }.get(kind, kind.replace("_", " ").capitalize())


def _artifact_role_label(value: str) -> str:
    return {
        "state_carrier": "State carrier",
        "private_donor": "Private donor",
        "mosaic_seed": "Mosaic seed",
        "mosaic_donor": "Mosaic donor",
    }.get(value, value.replace("_", " ").capitalize())


def _input_role_label(value: str) -> str:
    return {
        "request": "Request",
        "source": "Source",
        "reference": "Reference object",
        "seed": "Seed object",
    }.get(value, value.replace("_", " ").capitalize())


def _proposal_counts(
    report: DiscoveryCampaignReport,
) -> tuple[Counter[DiscoveryFindingKind], Counter[str]]:
    return (
        Counter(item.kind for item in report.proposals),
        Counter(item.symbol for item in report.proposals),
    )


def _render_overview(report: DiscoveryCampaignReport) -> str:
    proposals = len(report.proposals)
    symbols = len({item.symbol for item in report.proposals})
    heading = (
        f"{format_integer(proposals)} candidate"
        + ("" if proposals == 1 else "s")
        + " ready for review"
        if proposals
        else "No candidate matched this search"
    )
    cards = (
        ("Combinations checked", report.cells_total, "Declaration combinations tried"),
        ("Built this run", report.cells_built, "New compiled results"),
        ("Reused from cache", report.cells_cached, "Previously compiled results"),
        ("Exact candidates", proposals, f"Across {count_phrase(symbols, 'symbol')}"),
    )
    rendered_cards = metric_cards(cards)
    return f"""
<section class="hero discovery-hero" id="overview" aria-labelledby="report-title">
  <p class="eyebrow">Discovery preview</p>
  <h1 id="report-title">{escape(heading)}</h1>
  <p class="lede">ReproBit tried the declaration combinations allowed by this request and
    compared each compiled result with the supplied references. These are suggestions only:
    nothing was proved, approved, saved, or changed in a project.</p>
  <p><strong>Search scope:</strong> target {code(report.plan.target)} ·
    TU {code(report.plan.translation_unit)}</p>
  <div class="claim-row" aria-label="Discovery status">
    <span class="claim warn">Suggestions only</span>
    <span class="claim ok">Search complete</span>
    <span class="claim ok">Nothing applied</span>
  </div>
  <div class="card-grid metric-grid">{rendered_cards}</div>
</section>"""


def _render_candidate_charts(report: DiscoveryCampaignReport) -> str:
    kind_counts, symbol_counts = _proposal_counts(report)
    kind_bars = tuple(
        Bar(
            label=_kind_label(kind),
            detail="Review candidate type",
            value=kind_counts[kind],
            display_value=format_integer(kind_counts[kind]),
        )
        for kind in DiscoveryFindingKind
        if kind_counts[kind]
    )
    ordered_symbols = sorted(
        symbol_counts.items(),
        key=lambda item: (-item[1], item[0].casefold(), item[0]),
    )
    visible_symbols = ordered_symbols[:12]
    remaining_symbols = len(ordered_symbols) - len(visible_symbols)
    symbol_bars = tuple(
        Bar(
            label=code(symbol),
            detail="Symbol or signature",
            value=count,
            display_value=format_integer(count),
        )
        for symbol, count in visible_symbols
    )
    symbol_description = "Candidate count for the most active symbols."
    if remaining_symbols:
        symbol_description += (
            f" The canonical JSON contains {count_phrase(remaining_symbols, 'more symbol')}."
        )
    return f"""
<section class="section" id="results" aria-labelledby="results-title">
  <div class="section-heading"><div><p class="eyebrow">What the search found</p>
    <h2 id="results-title">Candidate overview</h2></div>
    <p>{count_phrase(len(report.proposals), "review-only proposal")}</p></div>
  <div class="chart-grid">
    {
        bar_chart(
            identity="candidate-kind-chart",
            title="Candidates by kind",
            description="The intervention shapes suggested by this search.",
            bars=kind_bars,
            empty_message="No candidates were found.",
        )
    }
    {
        bar_chart(
            identity="candidate-symbol-chart",
            title="Candidates by symbol",
            description=symbol_description,
            bars=symbol_bars,
            empty_message="No candidates were found.",
        )
    }
  </div>
  <p class="explain"><strong>Candidate terms:</strong> a private donor offers a compatible
    function body from another compiled state; an instruction mosaic combines selected
    instruction ranges from compiled candidates. Both still require project-level review and
    separate verification.</p>
</section>"""


def _state_summary(state: DeclarationState) -> str:
    parameters = " · ".join(
        f"{escape(item.name.replace('_', ' '))} {code(item.value)}" for item in state.parameters
    )
    return f"{escape(_family_label(state.family))} · {parameters}"


def _proposal_state_list(
    proposal: DiscoveryProposal,
    states: Mapping[str, DiscoveryStateExport],
) -> str:
    rows: list[str] = []
    for state_id in proposal.state_ids:
        export = states[state_id]
        state = export.state
        rows.append(f"<li>{_state_summary(state)}</li>")
    return '<ul class="compact-list">' + "".join(rows) + "</ul>"


def _proposal_artifact_list(
    proposal: DiscoveryProposal,
    artifacts: dict[str, DiscoveryArtifactReceipt],
) -> str:
    rows = "".join(
        f"<li>{escape(_artifact_role_label(artifacts[item].role.value))}: "
        f"{code(artifacts[item].logical_path)}</li>"
        for item in proposal.artifact_ids
    )
    return f'<ul class="compact-list">{rows}</ul>'


def _proposal_advanced(
    proposal: DiscoveryProposal,
    artifacts: dict[str, DiscoveryArtifactReceipt],
) -> str:
    artifact_rows = tuple(
        (
            _artifact_role_label(artifacts[item].role.value),
            code(artifacts[item].artifact_id),
            code(artifacts[item].logical_path),
            str(artifacts[item].object_size),
            code(artifacts[item].object.value),
        )
        for item in proposal.artifact_ids
    )
    range_table = ""
    if proposal.ranges:
        range_table = table(
            ("Donor cell", "Offset", "Length", "Seed SHA-256", "Donor SHA-256"),
            tuple(
                (
                    code(item.donor_cell_id),
                    str(item.offset),
                    str(item.length),
                    code(item.seed.value),
                    code(item.donor.value),
                )
                for item in proposal.ranges
            ),
            caption="Exact instruction-mosaic ranges",
        )
    exact_json = _pretty_json(proposal.intervention)
    return f"""
<dl class="identity-list">
  <dt>Finding ID</dt><dd>{code(proposal.finding_id)}</dd>
  <dt>Intervention ID</dt><dd>{code(proposal.intervention.id)}</dd>
  <dt>Reference body SHA-256</dt><dd>{code(proposal.reference_body.value)}</dd>
  <dt>Proposed output SHA-256</dt><dd>{code(proposal.proposed_output.value)}</dd>
</dl>
{
        table(
            ("Role", "Artifact ID", "Path", "Bytes", "Object SHA-256"),
            artifact_rows,
            caption="Proposal artifact records",
        )
    }
{range_table}
<h4>Exact intervention JSON</h4>
<pre><code>{escape(exact_json)}</code></pre>"""


def _render_proposal_card(
    proposal: DiscoveryProposal,
    states: Mapping[str, DiscoveryStateExport],
    artifacts: dict[str, DiscoveryArtifactReceipt],
) -> str:
    scope = proposal.scope
    scope_text = f"{code(scope.target)} · TU {code(scope.translation_unit or 'not set')}"
    if scope.function is not None:
        scope_text += f" · function {code(scope.function)}"
    return f"""
<article class="proposal-card">
  <header><div><p class="eyebrow">{escape(_intervention_label(proposal.intervention.kind))}</p>
    <h3>{code(proposal.symbol)}</h3></div>
    <span class="proposal-kind">{escape(_kind_label(proposal.kind))}</span></header>
  <p class="proposal-rationale">{escape(proposal.rationale)}</p>
  <div class="proposal-facts">
    <div class="proposal-fact"><strong>Affected scope</strong>{scope_text}</div>
    <div class="proposal-fact"><strong>Declaration state</strong>
      {_proposal_state_list(proposal, states)}</div>
    <div class="proposal-fact"><strong>Review artifacts</strong>
      {_proposal_artifact_list(proposal, artifacts)}</div>
  </div>
  <details><summary>Advanced proposal evidence</summary>
    <div class="detail-body">{_proposal_advanced(proposal, artifacts)}</div>
  </details>
</article>"""


def _render_proposals(report: DiscoveryCampaignReport) -> str:
    states = {item.state_id: item for item in report.selected_states}
    artifacts = {item.artifact_id: item for item in report.artifacts}
    ordered = sorted(
        report.proposals,
        key=lambda item: (item.symbol.casefold(), item.symbol, item.kind.value, item.finding_id),
    )
    visible = ordered[:_PROPOSAL_CARD_LIMIT]
    cards = "".join(_render_proposal_card(item, states, artifacts) for item in visible)
    if not cards:
        cards = (
            '<div class="advanced-intro"><p>No compiler state in this bounded campaign '
            "produced a review candidate. No project state was changed.</p></div>"
        )
    omitted = len(ordered) - len(visible)
    limit_note = ""
    if omitted:
        limit_note = f"""
<p class="notice"><strong>This page shows the first {format_integer(len(visible))}
  proposals.</strong> {format_integer(omitted)} more remain in the canonical JSON so the report
  stays responsive.</p>"""
    return f"""
<section class="section" id="proposals" aria-labelledby="proposals-title">
  <div class="section-heading"><div><p class="eyebrow">Review one candidate at a time</p>
    <h2 id="proposals-title">Proposed interventions</h2></div>
    <p>Suggestions only · never auto-applied</p></div>
  {limit_note}
  <div class="proposal-list">{cards}</div>
</section>"""


def _render_next_steps(report: DiscoveryCampaignReport) -> str:
    if report.proposals:
        steps = (
            (
                "Review the smallest plausible candidate",
                "Check its rationale, declaration state, affected scope, and selected object.",
            ),
            (
                "Reproduce it in project context",
                "Confirm the intended bytes and inspect collateral output before adding "
                "an intervention to the project.",
            ),
            (
                "Certify separately",
                "If accepted, create reviewed intervention and proof records, then require "
                "a cold ReproBit verification.",
            ),
        )
    else:
        steps = (
            (
                "Check the sealed inputs",
                "Confirm the reference object, symbol spelling, compiler switches, "
                "and source are intended.",
            ),
            (
                "Adjust only a justified bound",
                "Extend a declaration range deliberately; unchanged compiler cells can be reused.",
            ),
            (
                "Run the revised campaign",
                "A discovery result remains review evidence and never changes the "
                "project automatically.",
            ),
        )
    items = "".join(
        f'<li class="next-step"><strong>{escape(title)}</strong><span>{escape(detail)}</span></li>'
        for title, detail in steps
    )
    return f"""
<section class="section" id="next-steps" aria-labelledby="next-steps-title">
  <p class="eyebrow">What to do next</p><h2 id="next-steps-title">Review-only next steps</h2>
  <ol class="steps">{items}</ol>
</section>"""


def _render_campaign_identity(report: DiscoveryCampaignReport) -> str:
    values = (
        ("Campaign ID", report.campaign_id),
        ("Adapter", report.adapter),
        ("Plan SHA-256", report.plan_digest.value),
        ("Compile implementation SHA-256", report.compile_implementation_digest.value),
        ("Analysis implementation SHA-256", report.analysis_implementation_digest.value),
        ("Compile authority SHA-256", report.compile_authority_digest.value),
        ("Analysis authority SHA-256", report.analysis_authority_digest.value),
    )
    definitions = "".join(
        f"<dt>{escape(label)}</dt><dd>{code(value)}</dd>" for label, value in values
    )
    return f"""
<dl class="identity-list">{definitions}</dl>
<h4>Exact campaign plan</h4>
<pre><code>{escape(_pretty_json(report.plan))}</code></pre>"""


def _render_compiler_inputs(report: DiscoveryCampaignReport) -> str:
    arguments = " ".join(str(code(item)) for item in report.compiler.arguments) or "None"
    compiler = f"""
<dl class="identity-list">
  <dt>Compiler identity</dt><dd>{code(report.compiler.identity)}</dd>
  <dt>Executable</dt><dd>{code(report.compiler.executable)}</dd>
  <dt>Arguments</dt><dd>{arguments}</dd>
  <dt>Toolchain authority SHA-256</dt><dd>{code(report.compiler.toolchain_authority.value)}</dd>
</dl>"""
    inputs = table(
        ("Role", "Symbol", "Path", "Bytes", "SHA-256"),
        tuple(
            (
                _input_role_label(item.role.value),
                code(item.symbol) if item.symbol is not None else "—",
                code(item.logical_path),
                str(item.size),
                code(item.digest.value),
            )
            for item in report.inputs
        ),
        caption="Sealed discovery inputs",
    )
    return compiler + inputs


def _render_observation_index(report: DiscoveryCampaignReport) -> str:
    function_count = sum(len(item.functions) for item in report.observations)
    visible = report.observations[:_OBSERVATION_ROW_LIMIT]
    rows = tuple(
        (
            code(item.cell_id),
            code(item.state_id),
            _family_label(item.state.family),
            str(len(item.functions)),
            code(item.object.value),
            code(item.compile.command.value),
        )
        for item in visible
    )
    omitted = len(report.observations) - len(visible)
    note = (
        f"Showing {format_integer(len(visible))} of {format_integer(len(report.observations))} "
        f"cell records. The canonical JSON contains every cell and all "
        f"{format_integer(function_count)} function observations."
    )
    if not omitted:
        note = (
            f"All {format_integer(len(visible))} cell records are indexed here. The canonical "
            f"JSON contains all {format_integer(function_count)} raw function observations."
        )
    return f"<p>{escape(note)}</p>" + table(
        ("Cell ID", "State ID", "Family", "Functions", "Object SHA-256", "Command SHA-256"),
        rows,
        caption="Bounded compiler-cell observation index",
    )


def _render_selected_evidence(report: DiscoveryCampaignReport) -> str:
    visible_states = report.selected_states[:_SELECTED_RECEIPT_LIMIT]
    visible_artifacts = report.artifacts[:_SELECTED_RECEIPT_LIMIT]
    states = table(
        ("Cell ID", "State ID", "Family", "Declarations SHA-256"),
        tuple(
            (
                code(item.cell_id),
                code(item.state_id),
                _family_label(item.state.family),
                code(item.generated_declarations_digest.value),
            )
            for item in visible_states
        ),
        caption="Selected declaration-state records",
    )
    artifacts = table(
        ("Role", "Symbol", "Artifact ID", "Path", "Bytes", "Object SHA-256"),
        tuple(
            (
                _artifact_role_label(item.role.value),
                code(item.symbol),
                code(item.artifact_id),
                code(item.logical_path),
                str(item.object_size),
                code(item.object.value),
            )
            for item in visible_artifacts
        ),
        caption="Selected artifact records",
    )
    state_omitted = len(report.selected_states) - len(visible_states)
    artifact_omitted = len(report.artifacts) - len(visible_artifacts)
    receipt_note = ""
    if state_omitted or artifact_omitted:
        omitted_phrases = []
        if state_omitted:
            omitted_phrases.append(count_phrase(state_omitted, "state record"))
        if artifact_omitted:
            omitted_phrases.append(count_phrase(artifact_omitted, "artifact record"))
        receipt_note = (
            '<p class="notice">The responsive HTML omits '
            f"{' and '.join(omitted_phrases)}. "
            "Every record remains in the canonical JSON.</p>"
        )

    declaration_details: list[str] = []
    declaration_bytes = 0
    for item in report.selected_states:
        escaped = escape(item.generated_declarations or "(no generated declarations)")
        escaped_size = len(escaped.encode("utf-8"))
        if (
            len(declaration_details) >= _DECLARATION_DETAIL_LIMIT
            or declaration_bytes + escaped_size > _DECLARATION_HTML_BYTE_LIMIT
        ):
            break
        declaration_bytes += escaped_size
        declaration_details.append(
            '<details class="subdetails"><summary>State '
            f"{code(item.state_id)} · {escape(_family_label(item.state.family))}"
            "</summary>"
            f"<pre><code>{escaped}</code></pre></details>"
        )
    declaration_omitted = len(report.selected_states) - len(declaration_details)
    declaration_note = ""
    if declaration_omitted:
        declaration_note = (
            '<p class="notice">The canonical JSON retains '
            f"{count_phrase(declaration_omitted, 'exact declaration payload')} "
            "that this compact page does not repeat.</p>"
        )
    declarations = (
        "<h4>Exact generated declarations</h4>" + "".join(declaration_details) + declaration_note
    )
    return receipt_note + states + artifacts + declarations


def _canonical_json_name(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or "\0" in value
        or "\\" in value
        or path.is_absolute()
        or len(path.parts) != 1
        or path.name != value
    ):
        raise ValueError("canonical discovery JSON link must be a sibling file name")
    return value


def _render_advanced(report: DiscoveryCampaignReport, canonical_json_name: str) -> str:
    function_count = sum(len(item.functions) for item in report.observations)
    sections = (
        details(
            identity="campaign-identity",
            title="Campaign identity and authority",
            meta="full IDs and hashes",
            body=_render_campaign_identity(report),
        ),
        details(
            identity="compiler-inputs",
            title="Compiler and input records",
            meta=f"{len(report.inputs)} sealed inputs",
            body=_render_compiler_inputs(report),
        ),
        details(
            identity="observation-index",
            title="Compiler-cell observation index",
            meta=f"{report.cells_total:,} cells · {function_count:,} functions",
            body=_render_observation_index(report),
        ),
        details(
            identity="selected-evidence",
            title="Selected states and artifact records",
            meta=(
                f"{count_phrase(len(report.selected_states), 'state')} · "
                f"{count_phrase(len(report.artifacts), 'artifact')}"
            ),
            body=_render_selected_evidence(report),
        ),
    )
    return f"""
<section class="section" id="advanced" aria-labelledby="advanced-title">
  <p class="eyebrow">For debugging and audit</p><h2 id="advanced-title">Advanced evidence</h2>
  <div class="advanced-intro">
    <p>This page shows only the technical records most useful for review. The full records,
      including every raw function observation and exact proposal, are in the canonical JSON
      file beside this page.</p>
    <a class="machine-link" href="{escape(canonical_json_name)}">Open canonical
      {code(canonical_json_name)}</a>
    <p><small>Keep the HTML review and its canonical JSON sibling together when sharing a
      campaign.</small></p>
  </div>
  {"".join(sections)}
</section>"""


def _render_navigation() -> str:
    links = (
        ("Overview", "#overview"),
        ("Candidates", "#results"),
        ("Proposals", "#proposals"),
        ("Next steps", "#next-steps"),
        ("Advanced", "#advanced"),
    )
    items = "".join(f'<li><a href="{target}">{escape(label)}</a></li>' for label, target in links)
    return f'<nav class="section-nav" aria-label="Report sections"><ul>{items}</ul></nav>'


def render_discovery_report_html(
    report: DiscoveryCampaignReport,
    *,
    canonical_json_name: str,
) -> str:
    """Render a deterministic, bounded review page with no external assets."""

    json_name = _canonical_json_name(canonical_json_name)
    schema_label = code(f"v{report.schema_version}")
    sections = (
        _render_overview(report),
        _render_candidate_charts(report),
        _render_proposals(report),
        _render_next_steps(report),
        _render_advanced(report, json_name),
    )
    return page_shell(
        title=f"{report.plan.target} — ReproBit discovery review",
        brand="ReproBit · Discovery review",
        run_label=f"Run {code(report.campaign_id)}",
        nav=_render_navigation(),
        main="\n".join(sections),
        footer=(
            f"ReproBit discovery schema {schema_label} · non-certifying review · no external assets"
        ),
        extra_css=_DISCOVERY_CSS,
        skip_label="Skip to discovery review",
    )


__all__ = ["render_discovery_report_html"]
