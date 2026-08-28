"""Export a canonical report to GitHub Action outputs and the job summary."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path, PurePosixPath

from reprobit.model import Digest
from reprobit.report import Report, render_report_html
from reprobit.secure_paths import atomic_publish_new_relative, read_relative_file
from reprobit.strict_json import canonical_json, strict_loads

_NONCE = re.compile(r"^[0-9a-f]{64}$")


def _bool(value: bool) -> str:
    return "true" if value is True else "false"


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


def _write_outputs(report_path: Path, report: Report, *, accepted: bool) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    lines = [
        "report-produced=true",
        f"accepted={_bool(accepted)}",
        f"clean={_bool(report.verdict.clean)}",
        f"byte-exact={_bool(report.verdict.byte_exact)}",
        f"logic-certified={_bool(report.verdict.logic_certified)}",
        f"toolchain-origin={_bool(report.verdict.toolchain_origin)}",
        f"quarantined={_bool(report.verdict.quarantined)}",
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
    lines = [
        "## ReproBit byte identity",
        "",
        "| Claim | Result |",
        "| --- | --- |",
        f"| Accepted by requested policy | {_bool(accepted)} |",
        f"| Clean | {_bool(report.verdict.clean)} |",
        f"| Byte exact | {_bool(report.verdict.byte_exact)} |",
        f"| Logic certified | {_bool(report.verdict.logic_certified)} |",
        f"| Toolchain origin | {_bool(report.verdict.toolchain_origin)} |",
        f"| Total cost | {report.costs.project_total} |",
        "",
    ]
    if report.verdict.quarantined:
        lines.extend(
            [
                "> [!WARNING]",
                "> This run used explicitly quarantined legacy oracle payload. It is not clean.",
                "",
            ]
        )
    if report.targets:
        lines.extend(["| Target | Byte exact |", "| --- | --- |"])
        for target in report.targets:
            lines.append(f"| {target.id} | {_bool(target.byte_exact)} |")
        lines.append("")
    with Path(summary_path).open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines))


def _write_missing_summary(report_path: Path) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    lines = [
        "## ReproBit byte identity",
        "",
        "> [!ERROR]",
        "> Verification ended before it could publish a canonical report.",
        "",
        f"Expected report: `{report_path}`",
        "",
    ]
    with Path(summary_path).open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines))


def _secure_location(path: Path) -> tuple[Path, str]:
    absolute = Path(os.path.abspath(path))
    if not absolute.anchor or len(absolute.parts) < 2:
        raise ValueError(f"Action evidence path has no secure relative location: {path}")
    return Path(absolute.anchor), PurePosixPath(*absolute.parts[1:]).as_posix()


def _receipt_material(report: Report, nonce: str) -> dict[str, object]:
    expected_json = canonical_json(report)
    expected_html = render_report_html(report).encode("utf-8")
    return {
        "schema_version": 1,
        "nonce": nonce,
        "report_run_id": report.run_id.value,
        "report_json_sha256": Digest.from_bytes(expected_json).value,
        "report_html_sha256": Digest.from_bytes(expected_html).value,
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
    expected_html = render_report_html(report).encode("utf-8")
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
        canonical_json(_receipt_material(report, nonce)),
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
    if html_bytes != render_report_html(report).encode("utf-8"):
        raise ValueError("report HTML is absent or differs from the canonical JSON report")
    expected = _receipt_material(report, nonce)
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
            if html_bytes != render_report_html(report).encode("utf-8"):
                raise ValueError(
                    "report HTML is absent or differs from the canonical JSON report"
                )
        else:
            report = _read_current_report(report_path, receipt_path, parsed.nonce)
    except (OSError, ValueError) as exc:
        if not parsed.allow_missing:
            print(f"cannot publish Action report: {exc}", file=sys.stderr)
            return 1
        _write_missing_outputs(report_path)
        _write_missing_summary(report_path)
        return 0
    accepted = _accepted(report)
    _write_outputs(report_path, report, accepted=accepted)
    _write_summary(report, accepted=accepted)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main", "publish_action_completion"]
