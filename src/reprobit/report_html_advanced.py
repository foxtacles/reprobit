"""Collapsed technical evidence sections for verification reports."""

from __future__ import annotations

from reprobit.report import Report
from reprobit.report_html_components import (
    Content,
    code,
    count_phrase,
    details,
    escape,
    filter_control,
    format_integer,
    table,
)
from reprobit.report_html_format import (
    format_fraction,
    format_seconds,
    function_total,
    yes_no,
)


def _verdict_rows(report: Report) -> tuple[tuple[str, ...], ...]:
    return tuple(
        (label, yes_no(value))
        for label, value in (
            ("Cold build", report.verdict.cold),
            ("Byte exact", report.verdict.byte_exact),
            ("Logic certified", report.verdict.logic_certified),
            ("Toolchain origin", report.verdict.toolchain_origin),
            ("Quarantined", report.verdict.quarantined),
            ("Clean", report.verdict.clean),
        )
    )


def _target_rows(report: Report) -> tuple[tuple[Content, ...], ...]:
    return tuple(
        (
            code(item.id, css_class="identifier"),
            code(item.artifact, css_class="path"),
            format_integer(item.candidate_size)
            if item.candidate_size is not None
            else "not recorded",
            code(item.candidate_digest.value)
            if item.candidate_digest is not None
            else "not recorded",
            format_integer(item.oracle_size),
            code(item.oracle_digest.value),
            yes_no(item.byte_exact),
        )
        for item in report.targets
    )


def _render_outcome_details(report: Report) -> str:
    return table(
        ("Claim", "Result"),
        _verdict_rows(report),
        caption="Complete verdict claims",
    ) + table(
        (
            "Target",
            "Artifact",
            "Candidate bytes",
            "Candidate SHA-256",
            "Reference bytes",
            "Reference SHA-256",
            "Exact",
        ),
        _target_rows(report),
        caption="Exact target comparison records",
    )


def _render_debug_companion_details(report: Report) -> str:
    files = table(
        (
            "Target",
            "Role",
            "Project path",
            "Bytes",
            "Published SHA-256",
            "Raw SHA-256",
            "Outside-policy SHA-256",
            "Changed bytes",
            "Policy",
        ),
        tuple(
            (
                code(item.target_id, css_class="identifier"),
                code(file.role, css_class="identifier"),
                code(file.logical_path, css_class="path"),
                format_integer(file.size),
                code(file.digest.value),
                code(file.raw_digest.value),
                code(file.outside_policy_digest.value),
                format_integer(file.changed_bytes),
                code(item.policy, css_class="identifier"),
            )
            for item in report.proof.supplemental_outputs
            for file in item.files
        ),
        caption="Receipt-bound debug companion files",
    )
    bindings = table(
        ("Target", "Role", "Host path", "Source step", "Publish step"),
        tuple(
            (
                code(item.target_id, css_class="identifier"),
                code(file.role, css_class="identifier"),
                code(file.path, css_class="path"),
                code(item.source_step_id, css_class="identifier"),
                code(item.publish_step_id, css_class="identifier"),
            )
            for item in report.proof.supplemental_outputs
            for file in item.files
        ),
        caption="Current-run output receipt bindings",
    )
    categories = table(
        (
            "Target",
            "Role",
            "Category",
            "Eligible bytes",
            "Changed bytes",
            "Changed ranges",
            "Range preview",
        ),
        tuple(
            (
                code(item.target_id, css_class="identifier"),
                code(file.role, css_class="identifier"),
                code(category.category, css_class="identifier"),
                format_integer(category.normalized_bytes),
                format_integer(category.changed_bytes),
                format_integer(category.changed_range_count),
                code(
                    ", ".join(
                        f"[0x{span.offset:x}, 0x{span.end:x})" for span in category.changed_ranges
                    )
                    + (
                        f" + {category.omitted_changed_ranges:,} more"
                        if category.omitted_changed_ranges
                        else ""
                    ),
                    css_class="ranges",
                )
                if category.changed_ranges
                else "none",
            )
            for item in report.proof.supplemental_outputs
            for file in item.files
            for category in file.categories
        ),
        caption="Named bookkeeping normalization categories",
    )
    return f"""
<p><strong>For comparison and analysis only; not a byte-identity target or release
  artifact.</strong> Each published hash and size below is bound to a fresh build-output
  receipt. Range previews are intentionally bounded; complete counts remain in the record.</p>
{files}{bindings}{categories}"""


def _render_quarantine_details(report: Report) -> str:
    rows = tuple(
        (
            code(item.id, css_class="identifier"),
            code(item.artifact_id, css_class="identifier"),
            code(item.scope.function, css_class="symbol")
            if item.scope is not None and item.scope.function
            else "",
            code(item.coordinate_space, css_class="identifier"),
            code(f"0x{item.base_address:08x}", css_class="identifier")
            if item.base_address is not None
            else "",
            code(
                ", ".join(f"[0x{span.offset:x}, 0x{span.end:x})" for span in item.ranges),
                css_class="ranges",
            ),
            format_integer(item.byte_count),
            code(item.proof_binding.value, css_class="identifier")
            if item.proof_binding is not None
            else "not bound",
            item.reason,
        )
        for item in report.verdict.quarantines
    )
    return table(
        (
            "Action",
            "Artifact",
            "Function",
            "Coordinate system",
            "Function address",
            "Ranges",
            "Bytes",
            "Proof binding",
            "Reason",
        ),
        rows,
        caption="Every disclosed reference-derived byte range",
    )


def _render_identity_details(report: Report, canonical_json_href: str | None) -> str:
    build = report.proof.runtime.preimage.build
    step_total = sum(item.duration_seconds for item in build.steps)
    previous = "none"
    if report.previous is not None:
        previous = (
            f"{report.previous.report_digest.value} · cost delta {report.previous.cost_delta:+d}"
        )
    values = (
        ("Project", report.project_id),
        ("Run SHA-256", report.run_id.value),
        ("Runtime binding", report.runtime_binding.value),
        ("Evidence SHA-256", report.proof.digest.value),
        ("Source path", report.paths.source),
        ("Build path", report.paths.build),
        ("Toolchain path", report.paths.toolchain),
        ("Cost model", f"v{report.costs.model_version}"),
        ("Previous report", previous),
        ("Build inputs", format_integer(len(build.inputs))),
        ("Build outputs", format_integer(len(build.outputs))),
        ("Execution steps", format_integer(len(build.steps))),
        ("Summed step time", format_seconds(step_total)),
    )
    definitions = "".join(
        f"<dt>{escape(label)}</dt><dd><code>{escape(value)}</code></dd>" for label, value in values
    )
    slowest = sorted(
        build.steps,
        key=lambda item: (-item.duration_seconds, item.id.casefold(), item.id),
    )[:25]
    slow_rows = tuple(
        (
            code(item.id),
            format_seconds(item.duration_seconds),
            str(item.attempts),
            str(item.returncode),
            code(item.command_digest.value),
            code(item.output_digest.value),
        )
        for item in slowest
    )
    slow_table = table(
        ("Step", "Duration", "Attempts", "Exit", "Command SHA-256", "Output SHA-256"),
        slow_rows,
        caption="25 slowest execution steps",
    )
    machine_record = (
        f"in <code>{escape(canonical_json_href)}</code>"
        if canonical_json_href is not None
        else "in the machine-readable JSON report"
    )
    return f"""
<dl class="identity-list">{definitions}</dl>
<p>The complete input, output, build-step, target, producer, artifact, provenance, and
 certificate records are available {machine_record}.</p>
{slow_table}"""


def _render_toolchain_details(report: Report) -> str:
    tools = table(
        ("Tool", "Bytes", "SHA-256"),
        tuple(
            (
                code(item.id),
                str(item.size) if item.size is not None else "not recorded",
                code(item.digest.value),
            )
            for item in report.toolchain.tools
        ),
        caption="Locked executable and runtime files",
    )
    trees = table(
        ("Tree", "Path", "Entries", "Depth", "Membership SHA-256", "Content SHA-256"),
        tuple(
            (
                code(item.id),
                code(item.path, css_class="path"),
                str(item.entry_count),
                str(item.max_depth),
                code(item.membership_digest.value),
                code(item.content_digest.value),
            )
            for item in report.toolchain.input_trees
        ),
        caption="Portable input trees",
    )
    return (
        f"<p>Profile <code>{escape(report.toolchain.profile)}</code> · "
        f"MSVC <code>{escape(report.toolchain.release.value)}</code></p>{tools}{trees}"
    )


def _render_evidence_details(report: Report) -> str:
    components = (
        report.proof.adapter,
        *report.proof.providers,
        report.proof.package,
    )
    component_table = table(
        ("Role", "ID", "Implementation", "Version", "SHA-256"),
        tuple(
            (
                code(item.role),
                code(item.id),
                code(item.implementation),
                code(item.version),
                code(item.digest.value),
            )
            for item in components
        ),
        caption="Trusted report components",
    )
    issue_table = table(
        ("Claim", "Code", "Message"),
        tuple(
            (code(item.claim), code(item.code), item.message) for item in report.proof.audit_issues
        ),
        caption="All unresolved audit issues",
    )
    artifact_count = format_integer(report.evidence.artifacts)
    provenance_count = format_integer(report.evidence.provenance_nodes)
    passed_count = format_integer(report.evidence.passed_certificates)
    certificate_count = format_integer(report.evidence.certificates)
    producer_count = format_integer(len(report.proof.producers))
    counts = f"""
<div class="card-grid">
  <div class="card"><h3>Artifacts</h3><div class="value">{artifact_count}</div></div>
  <div class="card"><h3>Provenance nodes</h3>
    <div class="value">{provenance_count}</div></div>
  <div class="card"><h3>Certificates passed</h3>
    <div class="value">{passed_count} / {certificate_count}</div></div>
  <div class="card"><h3>Producer attestations</h3>
    <div class="value">{producer_count}</div></div>
</div>"""
    return counts + component_table + issue_table


def _render_cost_details(report: Report) -> str:
    attributed = report.costs.project_total - report.costs.unallocated_shared_cost
    unallocated_percent = (
        0.0
        if report.costs.project_total == 0
        else report.costs.unallocated_shared_cost / report.costs.project_total * 100
    )
    reconciliation = table(
        ("Cost view", "Points", "Meaning"),
        (
            (
                "Project total",
                format_integer(report.costs.project_total),
                "All intervention cost in this project",
            ),
            (
                "Attributed to functions",
                format_integer(attributed),
                "Function-specific cost plus assigned shares of broader adjustments",
            ),
            (
                "Remaining at target/TU scope",
                format_integer(report.costs.unallocated_shared_cost),
                f"{unallocated_percent:.1f}% remains at target or TU scope",
            ),
        ),
        caption="Project-to-function cost reconciliation",
    )
    classes = table(
        ("Class", "Interventions", "Units", "Cost"),
        tuple(
            (
                code(item.cost_class.value),
                str(item.interventions),
                str(item.units),
                str(item.cost),
            )
            for item in report.costs.by_class
        ),
        caption="Exact costs by intervention class",
    )
    targets = table(
        ("Target", "Interventions", "Units", "Cost"),
        tuple(
            (code(item.target), str(item.interventions), str(item.units), str(item.cost))
            for item in report.costs.by_target
        ),
        caption="Exact costs by target",
    )
    return (
        reconciliation
        + '<p class="explain">The class and target tables are separate views of the same '
        "project total; do not add them together.</p>" + classes + targets
    )


def _render_function_details(report: Report) -> str:
    table_id = "function-cost-table"
    rows = tuple(
        (
            code(item.scope.target),
            code(item.scope.translation_unit) if item.scope.translation_unit else "",
            code(item.scope.function) if item.scope.function else "",
            str(item.direct_cost),
            format_fraction(item.allocated_shared_cost.as_fraction()),
            str(item.exposure_cost),
            format_fraction(function_total(item)),
        )
        for item in report.costs.by_function
    )
    explanation = """
<p class="explain"><strong>Direct</strong> is work scoped to that function.
  <strong>Allocated shared</strong> is its equal share of broader work.
  <strong>Attributed total</strong> adds those two values. <strong>Exposure</strong> shows the
  full shared intervention cost touching the function and is non-additive; do not sum it.</p>"""
    return (
        explanation
        + filter_control(
            table_id=table_id,
            label="Filter by target, TU, or function",
            count=len(rows),
        )
        + table(
            (
                "Target",
                "TU",
                "Function",
                "Direct",
                "Allocated shared",
                "Exposure (non-additive)",
                "Attributed total",
            ),
            rows,
            caption="Function-level cost attribution rows",
            table_id=table_id,
        )
    )


def _render_intervention_details(report: Report) -> str:
    table_id = "intervention-cost-table"
    rows = tuple(
        (
            code(item.intervention_id),
            code(item.kind),
            code(item.cost_class.value),
            code(item.scope.target),
            code(item.scope.translation_unit) if item.scope.translation_unit else "",
            code(item.scope.function) if item.scope.function else "",
            code(
                ", ".join(
                    "/".join(
                        part
                        for part in (
                            scope.target,
                            scope.translation_unit,
                            scope.function,
                        )
                        if part is not None
                    )
                    for scope in item.beneficiaries
                )
            )
            if item.beneficiaries
            else "",
            code(", ".join(f"{unit.kind.value} x {unit.count}" for unit in item.units)),
            str(item.cost),
        )
        for item in report.costs.interventions
    )
    return filter_control(
        table_id=table_id,
        label="Filter by ID, class, target, TU, or function",
        count=len(rows),
    ) + table(
        (
            "ID",
            "Kind",
            "Class",
            "Target",
            "TU",
            "Function",
            "Shared beneficiaries",
            "Units",
            "Cost",
        ),
        rows,
        caption="Complete intervention ledger",
        table_id=table_id,
    )


def render_advanced(report: Report, *, canonical_json_href: str | None) -> str:
    """Render collapsed, complete-enough-for-review technical report sections."""

    if canonical_json_href is None:
        machine_record = (
            "<p><small>No machine-readable JSON report is linked from this page.</small></p>"
        )
    else:
        machine_record = f"""
    <a class="machine-link" href="{escape(canonical_json_href)}">Open full
      <code>{escape(canonical_json_href)}</code></a>
    <p><small>Keep this HTML report and <code>{escape(canonical_json_href)}</code> together
      when sharing a run.</small></p>"""

    sections = [
        details(
            identity="outcome-details",
            title="Verdict and target comparison records",
            meta=f"{count_phrase(len(report.targets), 'target')} · full hashes",
            body=_render_outcome_details(report),
        )
    ]
    if report.proof.supplemental_outputs:
        file_count = sum(len(item.files) for item in report.proof.supplemental_outputs)
        changed_bytes = sum(
            file.changed_bytes for item in report.proof.supplemental_outputs for file in item.files
        )
        sections.append(
            details(
                identity="debug-companion-details",
                title="Debug companion normalization audit",
                meta=(
                    f"{count_phrase(file_count, 'file')} · "
                    f"{count_phrase(changed_bytes, 'changed byte')}"
                ),
                body=_render_debug_companion_details(report),
            )
        )
    if report.verdict.quarantines:
        range_count = sum(len(item.ranges) for item in report.verdict.quarantines)
        sections.append(
            details(
                identity="quarantine-details",
                title="Reference-derived byte ranges",
                meta=(
                    f"{count_phrase(len(report.verdict.quarantines), 'intervention')} · "
                    f"{count_phrase(range_count, 'range')}"
                ),
                body=_render_quarantine_details(report),
            )
        )
    sections.extend(
        (
            details(
                identity="identity-details",
                title="Run identity and build records",
                meta=count_phrase(
                    len(report.proof.runtime.preimage.build.steps),
                    "step",
                ),
                body=_render_identity_details(report, canonical_json_href),
            ),
            details(
                identity="toolchain-details",
                title="Locked toolchain",
                meta=(
                    f"{count_phrase(len(report.toolchain.tools), 'file')} · "
                    f"{count_phrase(len(report.toolchain.input_trees), 'tree')}"
                ),
                body=_render_toolchain_details(report),
            ),
            details(
                identity="evidence-details",
                title="Evidence coverage, trusted components, and audit",
                meta=(
                    f"{count_phrase(report.evidence.artifacts, 'artifact')} · "
                    f"{count_phrase(len(report.proof.audit_issues), 'issue')}"
                ),
                body=_render_evidence_details(report),
            ),
            details(
                identity="cost-details",
                title="Exact cost totals",
                meta=(
                    f"model v{report.costs.model_version} · "
                    f"{count_phrase(report.costs.project_total, 'point')}"
                ),
                body=_render_cost_details(report),
            ),
            details(
                identity="function-details",
                title="Raw function-cost table",
                meta=count_phrase(len(report.costs.by_function), "function"),
                body=_render_function_details(report),
            ),
            details(
                identity="intervention-details",
                title="Raw intervention table",
                meta=count_phrase(len(report.costs.interventions), "intervention"),
                body=_render_intervention_details(report),
            ),
        )
    )
    return f"""
<section class="section" id="advanced" aria-labelledby="advanced-title">
  <p class="eyebrow">For debugging and audit</p><h2 id="advanced-title">Advanced evidence</h2>
  <div class="advanced-intro">
    <p>The sections below expose the most useful technical records without crowding the summary.
      The complete machine-readable record can be kept alongside this page.</p>
    {machine_record}
  </div>
  {"".join(sections)}
</section>"""


__all__ = ["render_advanced"]
