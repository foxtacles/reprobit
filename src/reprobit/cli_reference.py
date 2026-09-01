"""Render docs/cli-reference.md from the argparse tree so it cannot drift.

``python -m reprobit.cli_reference`` writes the document; the test suite
asserts that the committed file equals the rendered text.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

from reprobit.cli import _parser

_SHARED_GROUPS = ("advanced execution options",)
_HIDDEN_FLAGS = frozenset({"--format", "--quiet", "--project"})


def _flag_cell(action: argparse.Action) -> str:
    if action.option_strings:
        flags = ", ".join(f"`{flag}`" for flag in action.option_strings)
    else:
        flags = f"`{action.dest}`"
    if action.nargs == 0:
        return flags
    if action.choices is not None:
        return f"{flags} `{{{','.join(str(choice) for choice in action.choices)}}}`"
    metavar = action.metavar or (action.dest.upper() if action.option_strings else "")
    return f"{flags} `{metavar}`" if metavar else flags


def _default_cell(action: argparse.Action) -> str:
    if action.nargs == 0 or action.default in (None, argparse.SUPPRESS, []):
        return "required" if action.required and action.option_strings else ""
    return f"`{action.default}`"


def _help_cell(action: argparse.Action) -> str:
    return " ".join((action.help or "").split()).replace("|", "\\|")


def _rows(actions: list[argparse.Action]) -> list[str]:
    lines = ["| Argument | Default | Description |", "|---|---|---|"]
    for action in actions:
        lines.append(f"| {_flag_cell(action)} | {_default_cell(action)} | {_help_cell(action)} |")
    return lines


def _visible(action: argparse.Action) -> bool:
    if action.help == argparse.SUPPRESS:
        return False
    if isinstance(action, (argparse._HelpAction, argparse._VersionAction)):
        return False
    return not (action.option_strings and set(action.option_strings) & _HIDDEN_FLAGS)


def _subparsers(
    parser: argparse.ArgumentParser,
) -> argparse._SubParsersAction[argparse.ArgumentParser] | None:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    return None


def _usage(parser: argparse.ArgumentParser) -> str:
    """Render the usage line unwrapped so the output does not depend on COLUMNS."""

    formatter = argparse.HelpFormatter(prog=parser.prog, width=10_000)
    formatter.add_usage(parser.usage, parser._actions, parser._mutually_exclusive_groups)
    return formatter.format_help().strip().removeprefix("usage: ")


def _walk(
    parser: argparse.ArgumentParser,
    prefix: str,
    lines: list[str],
    shared: dict[str, _SharedGroup],
) -> None:
    subparsers = _subparsers(parser)
    if subparsers is not None:
        for name, child in subparsers.choices.items():
            _walk(child, f"{prefix} {name}", lines, shared)
        return
    lines.append(f"### `{prefix}`")
    lines.append("")
    lines.append(" ".join((parser.description or "").split()))
    lines.append("")
    lines.append("```")
    lines.append(_usage(parser))
    lines.append("```")
    lines.append("")
    for group in parser._action_groups:
        actions = [action for action in group._group_actions if _visible(action)]
        if not actions:
            continue
        title = group.title or ""
        if title in _SHARED_GROUPS:
            lines.append(f"Shared: see [{title}](#{title.replace(' ', '-')}).")
            lines.append("")
            entry = shared.setdefault(title, _SharedGroup(group.description or "", _rows(actions)))
            entry.commands.append(prefix)
            continue
        if title not in ("positional arguments", "options"):
            lines.append(f"**{title}**")
            if group.description:
                lines.append("")
                lines.append(" ".join(group.description.split()))
            lines.append("")
        lines.extend(_rows(actions))
        lines.append("")


@dataclass
class _SharedGroup:
    description: str
    rows: list[str]
    commands: list[str] = field(default_factory=list)


def render_cli_reference() -> str:
    """Return the Markdown reference for the current parser tree."""

    shared: dict[str, _SharedGroup] = {}
    parser = _parser()
    lines = [
        "# rbit command reference",
        "",
        "Generated from the argparse tree by `python -m reprobit.cli_reference`;",
        "`tests/test_cli_reference.py` fails when this file is stale. Commands appear",
        "in parser order. [docs/cli.md](cli.md) explains the workflow around them.",
        "",
        "## Global options",
        "",
        "| Argument | Default | Description |",
        "|---|---|---|",
        "| `--version` | | show the program version and exit |",
        "| `--format` `{text,ndjson}` | `text` | human-readable text or stable machine events; "
        "accepted before or after the sub-command |",
        "| `--quiet` | | silence text-mode progress (phase starts, heartbeats, unit counts); "
        "results, warnings and errors still print; ndjson output is unchanged; "
        "accepted before or after the sub-command |",
        "",
        "Every command also accepts `-h`/`--help`. The exit-status contract is in",
        "[docs/cli.md](cli.md#exit-status).",
        "",
        "## Commands",
        "",
    ]
    _walk(parser, "rbit", lines, shared)
    for title, group in shared.items():
        lines.append(f"## {title}")
        lines.append("")
        if group.description:
            lines.append(group.description)
            lines.append("")
        commands = ", ".join(f"`{command}`" for command in group.commands)
        lines.append(f"Accepted by {commands}. Flags a command's handler does not use are")
        lines.append("omitted from that command (for example `--cold` outside `build`).")
        lines.append("")
        lines.extend(group.rows)
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    destination = Path(arguments[0]) if arguments else Path("docs/cli-reference.md")
    destination.write_text(render_cli_reference(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["render_cli_reference"]
