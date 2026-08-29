"""Small, dependency-free HTML components shared by ReproBit reports."""

from __future__ import annotations

import html
from dataclasses import dataclass
from typing import Literal, TypeAlias


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
            "<tr>"
            + "".join(f"<td>{render_content(value)}</td>" for value in row)
            + "</tr>"
            for row in rows
        )
    else:
        body = (
            f'<tr><td class="empty" colspan="{len(headers)}">'
            f"{escape(empty_message)}</td></tr>"
        )
    return (
        '<div class="table-scroll">'
        f"<table{identity}><caption>{escape(caption)}</caption>"
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def filter_control(*, table_id: str, label: str, count: int) -> str:
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
  <summary><span>{escape(title)}</span><span class="summary-meta">{escape(meta)}</span></summary>
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


__all__ = [
    "Bar",
    "Content",
    "Markup",
    "bar_chart",
    "code",
    "count_phrase",
    "details",
    "escape",
    "filter_control",
    "format_integer",
    "join_markup",
    "plain_content",
    "render_content",
    "short_digest",
    "table",
]
