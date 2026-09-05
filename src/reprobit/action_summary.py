"""Export a canonical report to GitHub Action outputs and the job summary."""

from __future__ import annotations

import argparse
import html
import os
import re
import sys
from pathlib import Path, PurePosixPath

from reprobit.cli_output import count_phrase
from reprobit.model import Digest
from reprobit.report import Report
from reprobit.report_io import render_report_html, report_json_href
from reprobit.secure_paths import atomic_publish_new_relative, read_relative_file
from reprobit.strict_json import canonical_json, strict_loads

_NONCE = re.compile(r"^[0-9a-f]{64}$")
_MAX_FAILURE_REASON_LENGTH = 512


def _bool(value: bool) -> str:
    return "true" if value is True else "false"


def _yes_no(value: bool) -> str:
    """Render a human result without changing the Action's boolean outputs."""

    return "Yes" if value is True else "No"


def _accepted(report: Report) -> bool:
    """Return the Action step result, conservatively defaulting to clean."""

    value = os.environ.get("REPROBIT_ACCEPTED")
    if value is None:
        return report.verdict.clean
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError("REPROBIT_ACCEPTED must be exactly 'true' or 'false'")


def _quarantine_metrics(report: Report) -> tuple[int, int, int, str]:
    quarantines = report.verdict.quarantines
    boundary = tuple(
        quarantine.model_dump(
            mode="json",
            exclude={"proof_binding"},
            exclude_none=True,
            exclude_computed_fields=True,
        )
        for quarantine in quarantines
    )
    return (
        len(quarantines),
        sum(item.byte_count for item in quarantines),
        sum(len(item.ranges) for item in quarantines),
        Digest.from_bytes(canonical_json(boundary)).value,
    )


def _write_outputs(report_path: Path, report: Report, *, accepted: bool) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    quarantine_count, quarantine_bytes, quarantine_ranges, quarantine_digest = _quarantine_metrics(
        report
    )
    lines = [
        "report-produced=true",
        f"accepted={_bool(accepted)}",
        f"clean={_bool(report.verdict.clean)}",
        f"byte-exact={_bool(report.verdict.byte_exact)}",
        f"logic-certified={_bool(report.verdict.logic_certified)}",
        f"toolchain-origin={_bool(report.verdict.toolchain_origin)}",
        f"quarantined={_bool(report.verdict.quarantined)}",
        f"quarantine-count={quarantine_count}",
        f"quarantine-bytes={quarantine_bytes}",
        f"quarantine-ranges={quarantine_ranges}",
        f"quarantine-digest={quarantine_digest}",
        f"total-cost={report.costs.project_total}",
        f"report-json={report_path}",
        f"report-html={report_path.with_suffix('.html')}",
    ]
    with Path(output_path).open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")


def _write_missing_outputs(report_path: Path) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    lines = [
        "report-produced=false",
        "accepted=false",
        "clean=",
        "byte-exact=",
        "logic-certified=",
        "toolchain-origin=",
        "quarantined=",
        "quarantine-count=",
        "quarantine-bytes=",
        "quarantine-ranges=",
        "quarantine-digest=",
        "total-cost=",
        f"report-json={report_path}",
        f"report-html={report_path.with_suffix('.html')}",
    ]
    with Path(output_path).open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")


def _write_summary(report: Report, *, accepted: bool) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    quarantine_count, quarantine_bytes, quarantine_ranges, quarantine_digest = _quarantine_metrics(
        report
    )
    lines = [
        "## ReproBit byte identity",
        "",
        "| Check | Result |",
        "| --- | --- |",
        f"| Accepted by selected policy | {_yes_no(accepted)} |",
        f"| Clean result | {_yes_no(report.verdict.clean)} |",
        f"| Exact bytes | {_yes_no(report.verdict.byte_exact)} |",
        f"| Adjustments verified | {_yes_no(report.verdict.logic_certified)} |",
        f"| Built from declared source and compiler | {_yes_no(report.verdict.toolchain_origin)} |",
        f"| Adjustment cost | {report.costs.project_total} relative points |",
        "",
    ]
    if report.verdict.quarantined:
        lines.extend(
            [
                "> [!WARNING]",
                "> This run used a quarantined reference-byte exception. It is not clean.",
                f"> Coverage: {count_phrase(quarantine_count, 'exception')}, "
                f"{count_phrase(quarantine_bytes, 'byte')}, "
                f"{count_phrase(quarantine_ranges, 'range')}.",
                f"> Quarantine set: `{quarantine_digest}`",
                "",
            ]
        )
    if report.targets:
        lines.extend(["| Target | Exact bytes |", "| --- | --- |"])
        for target in report.targets:
            lines.append(f"| `{target.id}` | {_yes_no(target.byte_exact)} |")
        lines.append("")
    with Path(summary_path).open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines))


def _failure_reason(error: Exception) -> str:
    reason = " ".join(str(error).split()) or type(error).__name__
    reason = "".join(character if character.isprintable() else "\ufffd" for character in reason)
    if len(reason) > _MAX_FAILURE_REASON_LENGTH:
        reason = reason[: _MAX_FAILURE_REASON_LENGTH - 3] + "..."
    return reason


def _write_missing_summary(report_path: Path, *, reason: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = [
        "## ReproBit byte identity",
        "",
        "> [!ERROR]",
        "> A current canonical report could not be validated.",
        "",
        f"Expected report: `{report_path}`",
        "",
        f"<pre>{html.escape(reason)}</pre>",
        "",
    ]
    with Path(summary_path).open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines))


def _secure_location(path: Path) -> tuple[Path, str]:
    absolute = Path(os.path.abspath(path))
    if not absolute.anchor or len(absolute.parts) < 2:
        raise ValueError(f"Action evidence path has no secure relative location: {path}")
    return Path(absolute.anchor), PurePosixPath(*absolute.parts[1:]).as_posix()


def _rendered_report_html(report: Report, report_path: Path, html_path: Path) -> bytes:
    return render_report_html(
        report,
        canonical_json_href=report_json_href(html_path, report_path),
    ).encode("utf-8")


def _receipt_material(
    report: Report,
    nonce: str,
    *,
    report_json: bytes,
    report_html: bytes,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "nonce": nonce,
        "report_run_id": report.run_id.value,
        "report_json_sha256": Digest.from_bytes(report_json).value,
        "report_html_sha256": Digest.from_bytes(report_html).value,
    }


def publish_action_completion(
    report: Report,
    *,
    report_path: Path,
    html_path: Path,
    receipt_path: Path,
    nonce: str,
) -> None:
    """Publish the invocation receipt after exact report bytes are finalized.

    This function is called by the same ``rbit verify`` process that owns the
    in-memory report.  A separate process is deliberately not allowed to infer
    completion by rereading a potentially reused project path.
    """

    if _NONCE.fullmatch(nonce) is None:
        raise ValueError("Action nonce must be exactly 64 lowercase hexadecimal characters")
    paths = (report_path, html_path, receipt_path)
    if any(character in str(path) for path in paths for character in ("\r", "\n")):
        raise ValueError("Action report or receipt path contains a forbidden line break")
    expected_json = canonical_json(report)
    expected_html = _rendered_report_html(report, report_path, html_path)
    report_root, report_relative = _secure_location(report_path)
    html_root, html_relative = _secure_location(html_path)
    received_json, _ = read_relative_file(report_root, report_relative)
    received_html, _ = read_relative_file(html_root, html_relative)
    if received_json != expected_json:
        raise ValueError("published report JSON differs from the completed verification")
    if received_html != expected_html:
        raise ValueError("published report HTML differs from the completed verification")
    receipt_root, receipt_relative = _secure_location(receipt_path)
    atomic_publish_new_relative(
        receipt_root,
        receipt_relative,
        canonical_json(
            _receipt_material(
                report,
                nonce,
                report_json=expected_json,
                report_html=expected_html,
            )
        ),
    )


def _read_current_report(report_path: Path, receipt_path: Path, nonce: str) -> Report:
    report_root, report_relative = _secure_location(report_path)
    report_bytes, _ = read_relative_file(report_root, report_relative)
    report = Report.model_validate_json(report_bytes)
    if report_bytes != canonical_json(report):
        raise ValueError("Action report JSON is not canonical")
    html_path = report_path.with_suffix(".html")
    html_root, html_relative = _secure_location(html_path)
    html_bytes, _ = read_relative_file(html_root, html_relative)
    if html_bytes != _rendered_report_html(report, report_path, html_path):
        raise ValueError("report HTML is absent or differs from the canonical JSON report")
    expected = _receipt_material(
        report,
        nonce,
        report_json=report_bytes,
        report_html=html_bytes,
    )
    receipt_root, receipt_relative = _secure_location(receipt_path)
    receipt_bytes, _ = read_relative_file(receipt_root, receipt_relative)
    received = strict_loads(receipt_bytes)
    if received != expected:
        raise ValueError("Action completion receipt does not bind this report invocation")
    return report


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m reprobit.action_summary",
        description="Publish a current nonce-bound ReproBit Action report.",
    )
    parser.add_argument("--allow-missing", action="store_true")
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--nonce")
    parser.add_argument("report_json", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    # This entry point runs as ``python -m reprobit.action_summary`` inside the
    # GitHub Action, not under the rbit funnel, so its few diagnostics go to
    # stderr directly instead of through CLIOutput (there is no --format here).
    parsed = _parser().parse_args(sys.argv[1:] if argv is None else argv)
    report_path = parsed.report_json.resolve(strict=False)
    receipt_path = parsed.receipt.resolve(strict=False) if parsed.receipt is not None else None
    paths = (report_path,) if receipt_path is None else (report_path, receipt_path)
    if any(character in str(path) for path in paths for character in ("\r", "\n")):
        print("report or receipt path contains a forbidden line break", file=sys.stderr)
        return 2
    if (receipt_path is None) != (parsed.nonce is None):
        print("--receipt and --nonce must be supplied together", file=sys.stderr)
        return 2
    if parsed.nonce is not None and _NONCE.fullmatch(parsed.nonce) is None:
        print("--nonce must be exactly 64 lowercase hexadecimal characters", file=sys.stderr)
        return 2
    try:
        if receipt_path is None or parsed.nonce is None:
            report_root, report_relative = _secure_location(report_path)
            report_bytes, _ = read_relative_file(report_root, report_relative)
            report = Report.model_validate_json(report_bytes)
            if report_bytes != canonical_json(report):
                raise ValueError("Action report JSON is not canonical")
            html_root, html_relative = _secure_location(report_path.with_suffix(".html"))
            html_bytes, _ = read_relative_file(html_root, html_relative)
            if html_bytes != _rendered_report_html(
                report,
                report_path,
                report_path.with_suffix(".html"),
            ):
                raise ValueError("report HTML is absent or differs from the canonical JSON report")
        else:
            report = _read_current_report(report_path, receipt_path, parsed.nonce)
    except (OSError, ValueError) as exc:
        reason = _failure_reason(exc)
        print(f"cannot publish Action report: {reason}", file=sys.stderr)
        if not parsed.allow_missing:
            return 1
        _write_missing_outputs(report_path)
        _write_missing_summary(report_path, reason=reason)
        return 1 if os.environ.get("REPROBIT_ACCEPTED") == "true" else 0
    accepted = _accepted(report)
    _write_outputs(report_path, report, accepted=accepted)
    _write_summary(report, accepted=accepted)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "publish_action_completion"]
