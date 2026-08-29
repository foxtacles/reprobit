#!/usr/bin/env python3
"""Render the review-relevant parts of a noncertifying discovery report."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from reprobit.discovery_contracts import DiscoveryCampaignReport


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize a ReproBit discovery report for human review. "
            "This command never applies or approves a proposal."
        )
    )
    parser.add_argument(
        "report",
        nargs="?",
        type=Path,
        default=Path("campaign.report.json"),
        help="discovery report (default: campaign.report.json)",
    )
    return parser


def render_report(report: DiscoveryCampaignReport) -> str:
    lines = [
        "NON-CERTIFYING DISCOVERY REVIEW",
        (
            f"Cells: {report.cells_total} total; {report.cells_built} built; "
            f"{report.cells_cached} reused"
        ),
        f"Proposals: {len(report.proposals)}",
    ]
    states = {item.state_id: item for item in report.selected_states}
    artifacts = {item.artifact_id: item for item in report.artifacts}
    for index, proposal in enumerate(report.proposals, start=1):
        lines.extend(
            (
                "",
                f"[{index}] {proposal.kind.value}: {proposal.symbol}",
                f"Finding: {proposal.finding_id}",
                f"Rationale: {proposal.rationale}",
            )
        )
        for state_id in proposal.state_ids:
            state = states[state_id]
            declarations = state.generated_declarations.rstrip() or "(none)"
            lines.append(f"State {state_id} declarations:")
            lines.extend(f"  {line}" for line in declarations.splitlines())
        lines.append("Artifacts:")
        lines.extend(
            f"  {artifacts[artifact_id].role.value}: "
            f"{artifacts[artifact_id].logical_path}"
            for artifact_id in proposal.artifact_ids
        )
    if not report.proposals:
        lines.extend(("", "No proposal matched the sealed reference."))
    lines.extend(
        (
            "",
            "Review only: these proposals are evidence to investigate, not certified authority.",
        )
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        report_path = args.report.expanduser().resolve(strict=True)
        report = DiscoveryCampaignReport.model_validate_json(report_path.read_bytes())
    except (OSError, ValueError) as exc:
        parser.exit(2, f"review_report.py: error: {exc}\n")
    print(render_report(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
