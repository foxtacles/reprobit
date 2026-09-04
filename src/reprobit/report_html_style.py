"""Static, dependency-free assets for the human ReproBit report."""

# ruff: noqa: E501

from __future__ import annotations

REPORT_CSS = r"""
:root {
  color-scheme: light;
  --bg: #f3f6f8;
  --panel: #ffffff;
  --ink: #17232d;
  --muted: #586975;
  --line: #d7e0e5;
  --line-strong: #aebdc6;
  --accent: #245f73;
  --accent-soft: #e7f2f5;
  --ok: #176b45;
  --ok-soft: #e8f5ee;
  --warn: #8a4b08;
  --warn-soft: #fff5df;
  --bad: #a12b2b;
  --bad-soft: #fff0ef;
  --shadow: 0 1px 2px rgb(22 35 45 / 8%);
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 15px/1.5 system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
a { color: var(--accent); text-underline-offset: .16em; }
a:hover { text-decoration-thickness: 2px; }
:focus-visible { outline: 3px solid #d78324; outline-offset: 3px; }
.skip-link {
  position: fixed;
  z-index: 20;
  top: .5rem;
  left: .5rem;
  padding: .6rem .8rem;
  background: var(--ink);
  color: white;
  border-radius: .4rem;
  transform: translateY(-150%);
}
.skip-link:focus { transform: none; }
.topbar {
  background: #163440;
  color: white;
  border-bottom: 1px solid #0f2933;
}
.topbar-inner, main, .footer-inner {
  width: min(1180px, calc(100% - 2rem));
  margin-inline: auto;
}
.topbar-inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  padding: .8rem 0;
}
.brand {
  display: flex;
  min-width: 0;
  align-items: center;
  gap: .55rem;
  font-weight: 760;
  letter-spacing: .01em;
}
.brand-mark { width: 2.35rem; height: 2.35rem; flex: 0 0 auto; }
.brand-label { min-width: 0; }
.run-label { color: #c9dbe2; font-size: .82rem; }
.section-nav {
  position: sticky;
  z-index: 10;
  top: 0;
  overflow-x: auto;
  background: rgb(255 255 255 / 96%);
  border-bottom: 1px solid var(--line);
  backdrop-filter: blur(8px);
}
.section-nav ul {
  display: flex;
  width: min(1180px, calc(100% - 2rem));
  margin: 0 auto;
  padding: 0;
  list-style: none;
}
.section-nav a {
  display: block;
  padding: .75rem .85rem;
  color: var(--ink);
  font-size: .88rem;
  font-weight: 650;
  text-decoration: none;
  white-space: nowrap;
}
.section-nav a:hover { background: var(--accent-soft); }
main { padding-block: 2rem 3rem; }
h1, h2, h3 { line-height: 1.18; text-wrap: balance; }
h1 { margin: 0; font-size: clamp(2rem, 5vw, 3.2rem); letter-spacing: -.035em; }
h2 { margin: 0 0 .85rem; font-size: clamp(1.35rem, 3vw, 1.8rem); }
h3 { margin: 0 0 .6rem; font-size: 1rem; }
p { max-width: 76ch; }
code, pre, .mono {
  font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
}
code, .token { overflow-wrap: anywhere; }
:not(pre) > code {
  padding: .08em .28em;
  border: 1px solid #d5dfe4;
  border-radius: .28rem;
  background: #f1f5f7;
  font-size: .91em;
  box-decoration-break: clone;
  -webkit-box-decoration-break: clone;
}
pre {
  max-width: 100%;
  overflow: auto;
  padding: .85rem 1rem;
  border: 1px solid var(--line);
  border-radius: .45rem;
  background: #f1f5f7;
  font-size: .84rem;
  line-height: 1.55;
}
pre > code { white-space: pre; }
.topbar code, .machine-link code {
  border-color: rgb(255 255 255 / 24%);
  background: rgb(255 255 255 / 10%);
  color: inherit;
}
.eyebrow code {
  padding: 0;
  border: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  letter-spacing: inherit;
  text-transform: none;
}
.eyebrow {
  margin: 0 0 .5rem;
  color: var(--accent);
  font-size: .78rem;
  font-weight: 760;
  letter-spacing: .1em;
  text-transform: uppercase;
}
.lede { color: var(--muted); font-size: 1.05rem; }
.hero {
  scroll-margin-top: 4.5rem;
  padding: clamp(1.2rem, 3vw, 2rem);
  background: var(--panel);
  border: 1px solid var(--line);
  border-left: 6px solid var(--accent);
  border-radius: .75rem;
  box-shadow: var(--shadow);
}
.hero.ok { border-left-color: var(--ok); }
.hero.warn { border-left-color: var(--warn); }
.hero.bad { border-left-color: var(--bad); }
.claim-row { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: 1rem; }
.claim {
  display: inline-flex;
  align-items: center;
  gap: .4rem;
  padding: .35rem .62rem;
  border: 1px solid var(--line-strong);
  border-radius: 999px;
  background: #f8fafb;
  font-size: .85rem;
  font-weight: 650;
}
.claim::before { content: ""; width: .55rem; height: .55rem; border-radius: 50%; background: var(--muted); }
.claim.ok::before { background: var(--ok); }
.claim.warn::before { background: var(--warn); }
.claim.bad::before { background: var(--bad); }
.callout {
  margin-top: 1rem;
  padding: 1rem 1.1rem;
  border: 1px solid #efc276;
  border-radius: .65rem;
  background: var(--warn-soft);
}
.callout h2 { color: #653806; font-size: 1.08rem; }
.callout p { margin-bottom: .25rem; }
.section { margin-top: 2rem; scroll-margin-top: 4.5rem; }
#failed-targets, #failed-logic, #failed-audit { scroll-margin-top: 4.5rem; }
.section-heading { display: flex; align-items: end; justify-content: space-between; gap: 1rem; }
.section-heading p { margin: 0 0 .85rem; color: var(--muted); }
.card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 240px), 1fr));
  gap: .85rem;
}
.card, .chart, .next-step {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: .65rem;
  box-shadow: var(--shadow);
}
.card { padding: 1rem; }
.card p { margin: .35rem 0 0; color: var(--muted); }
.card .value { margin-top: .15rem; font-size: 1.45rem; font-weight: 760; color: var(--ink); }
.card .status { color: var(--ok); font-weight: 720; }
.card .status.bad { color: var(--bad); }
.card .digest { display: block; margin-top: .45rem; font-size: .78rem; }
.card .digest.missing { color: var(--muted); }
.cost-reconciliation { margin: 1rem 0; }
.chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 430px), 1fr)); gap: 1rem; }
.chart { margin: 0; padding: 1rem; min-width: 0; }
.chart figcaption { margin-bottom: .85rem; }
.chart figcaption strong { display: block; }
.chart figcaption span { color: var(--muted); font-size: .88rem; }
.bar-list { display: grid; gap: .62rem; }
.bar-row {
  display: grid;
  grid-template-columns: minmax(8rem, 1.2fr) minmax(6rem, 2fr) auto;
  align-items: center;
  gap: .7rem;
}
.bar-label { min-width: 0; }
.bar-label span { display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-weight: 620; }
.bar-label small {
  display: block;
  color: var(--muted);
  line-height: 1.3;
  overflow-wrap: anywhere;
}
.bar-label code { font-size: .9em; }
.exception-note { color: var(--warn); font-weight: 700; }
.bar-track { height: .65rem; overflow: hidden; border-radius: 999px; background: #e8eef1; }
.bar-fill { display: block; width: var(--bar); height: 100%; border-radius: inherit; background: var(--accent); }
.bar-row.hot .bar-fill { background: var(--warn); }
.bar-value { font-variant-numeric: tabular-nums; white-space: nowrap; }
.explain {
  margin: 1rem 0 0;
  padding: .8rem 1rem;
  border-left: 3px solid var(--accent);
  background: var(--accent-soft);
  color: #274955;
}
.steps { display: grid; gap: .65rem; margin: 0; padding: 0; list-style: none; counter-reset: step; }
.next-step { position: relative; padding: .9rem 1rem .9rem 3.2rem; }
.next-step::before {
  counter-increment: step;
  content: counter(step);
  position: absolute;
  left: 1rem;
  top: .9rem;
  display: grid;
  place-items: center;
  width: 1.45rem;
  height: 1.45rem;
  border-radius: 50%;
  background: var(--accent);
  color: white;
  font-weight: 760;
}
.next-step strong { display: block; }
.next-step span { color: var(--muted); }
.advanced-intro {
  padding: 1rem;
  border: 1px solid var(--line);
  border-radius: .65rem;
  background: var(--panel);
}
details.advanced {
  margin-top: .7rem;
  scroll-margin-top: 4.5rem;
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: .55rem;
  box-shadow: var(--shadow);
}
details.advanced > summary {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 1rem;
  padding: .85rem 1rem;
  cursor: pointer;
  font-weight: 700;
  list-style: none;
}
details.advanced > summary::-webkit-details-marker { display: none; }
details.advanced > summary > h3 { margin: 0; font: inherit; }
details.advanced > summary::before {
  content: "\203A";
  color: var(--accent);
  font-size: 1.25rem;
  line-height: 1;
}
details.advanced[open] > summary::before { transform: rotate(90deg); }
details.advanced[open] > summary { border-bottom: 1px solid var(--line); }
.summary-meta { color: var(--muted); font-size: .82rem; font-weight: 500; text-align: right; }
.detail-body { padding: 1rem; }
.detail-body > :first-child { margin-top: 0; }
.detail-body > :last-child { margin-bottom: 0; }
.subdetails { margin-top: .75rem; border-left: 3px solid var(--line); padding-left: .8rem; }
.subdetails summary { cursor: pointer; font-weight: 650; }
.table-tools { display: flex; align-items: end; justify-content: space-between; gap: .8rem; margin: .7rem 0; }
.filter-label { display: grid; gap: .25rem; width: min(100%, 32rem); font-weight: 650; }
.filter-label input {
  width: 100%;
  padding: .55rem .65rem;
  border: 1px solid var(--line-strong);
  border-radius: .4rem;
  background: white;
  color: var(--ink);
  font: inherit;
}
.filter-count { color: var(--muted); white-space: nowrap; }
.table-scroll { max-width: 100%; overflow: auto; border: 1px solid var(--line); border-radius: .4rem; }
table { width: 100%; border-collapse: collapse; font-size: .84rem; }
caption { padding: .6rem; text-align: left; font-weight: 700; }
th, td { padding: .48rem .55rem; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
th { position: sticky; top: 0; z-index: 1; background: #edf2f4; white-space: nowrap; }
td { max-width: 34rem; overflow-wrap: anywhere; }
.table-scroll code {
  overflow-wrap: normal;
  word-break: normal;
}
.table-scroll code.path,
.table-scroll code.identifier,
.table-scroll code.symbol,
.table-scroll code.ranges { white-space: nowrap; }
tbody tr:nth-child(even) { background: #fafcfc; }
tbody tr:hover { background: var(--accent-soft); }
.empty { padding: .8rem; color: var(--muted); font-style: italic; }
.identity-list { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: .45rem 1rem; }
.identity-list dt { color: var(--muted); }
.identity-list dd { margin: 0; overflow-wrap: anywhere; }
.machine-link {
  display: inline-block;
  margin-top: .35rem;
  padding: .5rem .7rem;
  border-radius: .4rem;
  background: var(--accent);
  color: white;
  font-weight: 700;
  text-decoration: none;
}
.machine-link:hover { background: #194b5d; }
.footer { padding: 1rem 0 2rem; color: var(--muted); font-size: .82rem; }
.footer-inner { border-top: 1px solid var(--line); padding-top: 1rem; }
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}
@media (max-width: 680px) {
  .topbar-inner { align-items: flex-start; flex-direction: column; }
  .section-nav { overflow-x: visible; }
  .section-nav ul { flex-wrap: wrap; }
  .section-nav a { padding: .55rem .7rem; }
  .section-heading, .table-tools { align-items: stretch; flex-direction: column; }
  details.advanced > summary { grid-template-columns: auto minmax(0, 1fr); gap: .2rem .7rem; }
  .summary-meta { grid-column: 2; text-align: left; }
  .bar-row { grid-template-columns: minmax(0, 1fr) auto; }
  .bar-label span { white-space: normal; }
  .bar-track { grid-column: 1 / -1; grid-row: 2; }
  .bar-value { grid-column: 2; grid-row: 1; }
  .identity-list { grid-template-columns: 1fr; gap: .1rem; }
  .identity-list dd { margin-bottom: .55rem; }
}
@media print {
  body { background: white; }
  .section-nav, .skip-link, .table-tools { display: none; }
  .hero, .card, .chart, details.advanced { box-shadow: none; break-inside: avoid; }
}
@media (prefers-reduced-motion: reduce) {
  html { scroll-behavior: auto; }
}
""".strip()


REPORT_SCRIPT = r"""
(() => {
  const revealHashTarget = () => {
    if (!location.hash) return;
    const target = document.getElementById(location.hash.slice(1));
    if (!target) return;
    const disclosure = target instanceof HTMLDetailsElement
      ? target
      : target.closest("details");
    if (!disclosure) return;
    disclosure.open = true;
    requestAnimationFrame(() => target.scrollIntoView({block: "start"}));
  };
  window.addEventListener("hashchange", revealHashTarget);
  revealHashTarget();
  for (const input of document.querySelectorAll("[data-table-filter]")) {
    const table = document.getElementById(input.dataset.tableFilter);
    const count = document.querySelector(`[data-filter-count="${input.dataset.tableFilter}"]`);
    if (!table || !table.tBodies.length) continue;
    const rows = Array.from(table.tBodies[0].rows);
    const update = () => {
      const query = input.value.trim().toLocaleLowerCase();
      let visible = 0;
      for (const row of rows) {
        const match = !query || row.textContent.toLocaleLowerCase().includes(query);
        row.hidden = !match;
        if (match) visible += 1;
      }
      if (count) count.textContent = `${visible.toLocaleString()} of ${rows.length.toLocaleString()}`;
    };
    input.addEventListener("input", update);
    update();
  }
})();
""".strip()


# Kept inline so every report remains a single, portable file with a crisp vector mark.
REPROBIT_MARK_SVG = r"""
<svg class="brand-mark" viewBox="0 0 512 512" aria-hidden="true" focusable="false">
  <rect x="24" y="24" width="464" height="464" rx="112" fill="#0b1020"/>
  <rect x="26" y="26" width="460" height="460" rx="110"
    fill="none" stroke="#34436f" stroke-width="4"/>
  <g fill="#22d3ee">
    <circle cx="140" cy="82" r="21"/><circle cx="140" cy="140" r="21"/>
    <circle cx="140" cy="198" r="21"/><circle cx="140" cy="256" r="21"/>
    <circle cx="140" cy="314" r="21"/><circle cx="140" cy="372" r="21"/>
    <circle cx="140" cy="430" r="21"/><circle cx="198" cy="82" r="21"/>
    <circle cx="256" cy="82" r="21"/><circle cx="314" cy="82" r="21"/>
    <circle cx="372" cy="140" r="21"/><circle cx="372" cy="198" r="21"/>
    <circle cx="198" cy="256" r="21"/><circle cx="256" cy="256" r="21"/>
    <circle cx="314" cy="256" r="21"/>
  </g>
  <g fill="#8b5cf6">
    <circle cx="256" cy="314" r="21"/><circle cx="314" cy="372" r="21"/>
    <circle cx="372" cy="430" r="21"/>
  </g>
</svg>
""".strip()


__all__ = ["REPORT_CSS", "REPORT_SCRIPT", "REPROBIT_MARK_SVG"]
