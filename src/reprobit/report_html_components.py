"""Small, dependency-free HTML components shared by ReproBit reports."""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, TypeAlias

from reprobit.report_html_style import REPORT_CSS, REPORT_SCRIPT, REPROBIT_MARK_SVG


def escape(value: object) -> str:
    """Escape an arbitrary value for HTML text or attribute content."""

    return html.escape(str(value), quote=True)


@dataclass(frozen=True, slots=True)
class Markup:
    """Escaped, renderer-owned markup with a plain-text equivalent."""

    html: str
    text: str

    def __str__(self) -> str:
        return self.html


Content: TypeAlias = str | Markup


def render_content(value: Content) -> str:
    return value.html if isinstance(value, Markup) else escape(value)


def plain_content(value: Content) -> str:
    return value.text if isinstance(value, Markup) else value


def code(value: object, *, css_class: str | None = None, title: str | None = None) -> Markup:
    """Render a technical value as escaped semantic inline code."""

    text = str(value)
    attributes = f' class="{escape(css_class)}"' if css_class else ""
    if title is not None:
        attributes += f' title="{escape(title)}"'
    return Markup(f"<code{attributes}>{escape(text)}</code>", text)


def join_markup(parts: tuple[Content, ...], *, separator: str = "") -> Markup:
    return Markup(
        separator.join(render_content(part) for part in parts),
        separator.join(plain_content(part) for part in parts),
    )


def format_integer(value: int) -> str:
    return f"{value:,}"


def count_phrase(value: int, singular: str, plural: str | None = None) -> str:
    noun = singular if value == 1 else (plural or f"{singular}s")
    return f"{format_integer(value)} {noun}"


def short_digest(value: str) -> str:
    return f"{value[:12]}…{value[-8:]}"


def table(
    headers: tuple[str, ...],
    rows: tuple[tuple[Content, ...], ...],
    *,
    caption: str,
    table_id: str | None = None,
    empty_message: str = "No entries were recorded.",
) -> str:
    """Render an accessible, horizontally scrollable data table."""

    identity = f' id="{escape(table_id)}"' if table_id is not None else ""
    head = "".join(f'<th scope="col">{escape(value)}</th>' for value in headers)
    if rows:
        body = "".join(
            "<tr>" + "".join(f"<td>{render_content(value)}</td>" for value in row) + "</tr>"
            for row in rows
        )
    else:
        body = f'<tr><td class="empty" colspan="{len(headers)}">{escape(empty_message)}</td></tr>'
    return (
        f'<div class="table-scroll" role="region" aria-label="{escape(caption)}" tabindex="0">'
        f"<table{identity}><caption>{escape(caption)}</caption>"
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def filter_control(*, table_id: str, label: str, count: int) -> str:
    if count == 0:
        return ""
    return f"""
<div class="table-tools">
  <label class="filter-label">{escape(label)}
    <input type="search" data-table-filter="{escape(table_id)}"
      autocomplete="off" spellcheck="false" placeholder="Type to filter this table">
  </label>
  <output class="filter-count" data-filter-count="{escape(table_id)}" aria-live="polite">
    {format_integer(count)} of {format_integer(count)}
  </output>
</div>"""


def details(*, identity: str, title: str, meta: str, body: str) -> str:
    return f"""
<details class="advanced" id="{escape(identity)}">
  <summary><h3>{escape(title)}</h3><span class="summary-meta">{escape(meta)}</span></summary>
  <div class="detail-body">{body}</div>
</details>"""


@dataclass(frozen=True, slots=True)
class Bar:
    label: Content
    detail: Content
    value: float
    display_value: str
    tone: Literal["normal", "hot"] = "normal"


def bar_chart(
    *,
    identity: str,
    title: str,
    description: str,
    bars: tuple[Bar, ...],
    empty_message: str = "No data was recorded.",
) -> str:
    """Render a compact text-backed bar chart without external assets."""

    maximum = max((item.value for item in bars), default=0.0)
    rows: list[str] = []
    for item in bars:
        percent = 0.0 if maximum <= 0 else (item.value / maximum) * 100
        if item.value > 0:
            percent = max(percent, 1.5)
        tone = " hot" if item.tone == "hot" else ""
        rows.append(
            f"""<div class="bar-row{tone}">
  <div class="bar-label" title="{escape(plain_content(item.label))}">
    <span>{render_content(item.label)}</span><small>{render_content(item.detail)}</small>
  </div>
  <div class="bar-track" aria-hidden="true">
    <span class="bar-fill" style="--bar:{percent:.2f}%"></span>
  </div>
  <strong class="bar-value">{escape(item.display_value)}</strong>
</div>"""
        )
    content = "".join(rows) if rows else f'<p class="empty">{escape(empty_message)}</p>'
    return f"""
<figure class="chart" aria-labelledby="{escape(identity)}-title">
  <figcaption id="{escape(identity)}-title"><strong>{escape(title)}</strong>
    <span>{escape(description)}</span></figcaption>
  <div class="bar-list">{content}</div>
</figure>"""


def metric_cards(items: Sequence[tuple[str, int, str]]) -> str:
    """Render one row of ``(label, value, detail)`` metric cards."""

    return "".join(
        f'<article class="card"><h3>{escape(label)}</h3>'
        f'<div class="value">{format_integer(value)}</div><p>{escape(detail)}</p></article>'
        for label, value, detail in items
    )


OutcomeBranch: TypeAlias = Literal[
    "published-exact",
    "published",
    "exact",
    "qualified",
    "exhausted",
]

OUTCOME_TONES: Mapping[OutcomeBranch, str] = MappingProxyType(
    {
        "published-exact": "ok",
        "published": "warn",
        "exact": "ok",
        "qualified": "warn",
        "exhausted": "warn",
    }
)


def outcome_summary(
    *,
    published: bool,
    exact: bool,
    qualified: bool,
    copy: Mapping[OutcomeBranch, tuple[str, str]],
) -> tuple[OutcomeBranch, str, str, str]:
    """Classify one bounded search outcome and pick its hero tone, heading and explanation.

    The five branches are ordered by strength: a saved exact result, saved local
    progress, an exact result left for review, a locally proven result left for
    review, and an exhausted search. ``copy`` supplies ``(heading, explanation)``
    for every branch.
    """

    branch: OutcomeBranch
    if published and exact:
        branch = "published-exact"
    elif published:
        branch = "published"
    elif exact:
        branch = "exact"
    elif qualified:
        branch = "qualified"
    else:
        branch = "exhausted"
    heading, explanation = copy[branch]
    return branch, OUTCOME_TONES[branch], heading, explanation


def page_shell(
    *,
    title: str,
    brand: str,
    run_label: str,
    nav: str,
    main: str,
    footer: str,
    extra_css: str = "",
    skip_label: str = "Skip to report",
) -> str:
    """Wrap rendered sections in the shared deterministic, asset-free page skeleton.

    ``brand``, ``run_label``, ``nav``, ``main`` and ``footer`` are already-rendered
    markup; ``title`` and ``skip_label`` are plain text.
    """

    style = f"{REPORT_CSS}\n{extra_css}" if extra_css else REPORT_CSS
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<title>{escape(title)}</title>
<style>{style}</style>
</head>
<body>
<a class="skip-link" href="#overview">{escape(skip_label)}</a>
<header class="topbar"><div class="topbar-inner">
  <div class="brand">{REPROBIT_MARK_SVG}<span class="brand-label">
    {brand}
  </span></div>
  <div class="run-label">{run_label}</div>
</div></header>
{nav}
<main>
{main}
</main>
<footer class="footer"><div class="footer-inner">
  {footer}
</div></footer>
<script>{REPORT_SCRIPT}</script>
</body>
</html>
"""


__all__ = [
    "OUTCOME_TONES",
    "Bar",
    "Content",
    "Markup",
    "OutcomeBranch",
    "bar_chart",
    "code",
    "count_phrase",
    "details",
    "escape",
    "filter_control",
    "format_integer",
    "join_markup",
    "metric_cards",
    "outcome_summary",
    "page_shell",
    "plain_content",
    "render_content",
    "short_digest",
    "table",
]
