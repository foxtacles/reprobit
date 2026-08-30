"""Canonical JSON and deterministic self-contained HTML report I/O."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
from urllib.parse import quote

from reprobit.report import Report
from reprobit.report_html import render_report_html as _render_report_html
from reprobit.secure_paths import atomic_publish_relative
from reprobit.strict_json import JsonValue, StrictJSONError, canonical_json, strict_loads


def _atomic_write(path: str | Path, data: bytes) -> None:
    destination = Path(os.path.abspath(path))
    if not destination.anchor or len(destination.parts) < 2:
        raise OSError(f"report destination has no secure relative path: {path}")
    root = Path(destination.anchor)
    relative = PurePosixPath(*destination.parts[1:]).as_posix()
    atomic_publish_relative(root, relative, data)


def write_report_json(report: Report, path: str | Path) -> None:
    """Write canonical report JSON atomically."""

    _atomic_write(path, canonical_json(report))


def read_report_json(path: str | Path) -> Report:
    """Read and strictly validate a canonical report-v2 document."""

    source = Path(path)
    try:
        payload = source.read_bytes()
        # The strict parser is the ambiguity gate.  Discard its temporary tree
        # before Pydantic validates the original JSON bytes so large evidence
        # reports are never held as a Python tree and reserialized copy at once.
        strict_loads(payload)
        return Report.model_validate_json(payload)
    except (OSError, StrictJSONError, ValueError) as exc:
        raise ValueError(f"invalid report {source}: {exc}") from exc


def report_json_href(
    html_path: str | Path,
    json_path: str | Path | None,
) -> str | None:
    """Return a portable local link from one report artifact to its JSON sibling."""

    if json_path is None:
        return None
    html = Path(os.path.abspath(html_path))
    canonical_json = Path(os.path.abspath(json_path))
    try:
        relative = os.path.relpath(canonical_json, start=html.parent)
    except ValueError:
        return None
    return quote(Path(relative).as_posix(), safe="/.")


def render_report_html(
    report: Report,
    *,
    canonical_json_href: str | None = None,
) -> str:
    """Render a deterministic local report with no external runtime or assets."""

    return _render_report_html(report, canonical_json_href=canonical_json_href)


def write_report_html(
    report: Report,
    path: str | Path,
    *,
    canonical_json_path: str | Path | None = None,
) -> None:
    """Write a self-contained report atomically."""

    _atomic_write(
        path,
        render_report_html(
            report,
            canonical_json_href=report_json_href(path, canonical_json_path),
        ).encode("utf-8"),
    )


def report_json_schema() -> JsonValue:
    """Return the self-contained, stably identified report schema."""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:reprobit:schema:report:2",
        **Report.model_json_schema(
            mode="validation",
            ref_template="#/$defs/{model}",
        ),
    }


def write_report_json_schema(path: str | Path) -> None:
    """Write the canonical report schema atomically."""

    _atomic_write(path, canonical_json(report_json_schema()))


__all__ = [
    "read_report_json",
    "render_report_html",
    "report_json_href",
    "report_json_schema",
    "write_report_html",
    "write_report_json",
    "write_report_json_schema",
]
