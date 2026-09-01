"""The committed command reference must match the argparse tree."""

from __future__ import annotations

from pathlib import Path

from reprobit.cli_reference import render_cli_reference

ROOT = Path(__file__).parents[1]


def test_committed_cli_reference_is_current() -> None:
    committed = (ROOT / "docs" / "cli-reference.md").read_text(encoding="utf-8")
    assert committed == render_cli_reference(), (
        "docs/cli-reference.md is stale; run python -m reprobit.cli_reference"
    )


def test_cli_reference_lists_every_leaf_command() -> None:
    rendered = render_cli_reference()
    for command in (
        "rbit init",
        "rbit setup",
        "rbit status",
        "rbit build",
        "rbit verify",
        "rbit repair",
        "rbit source preview",
        "rbit import cmake",
        "rbit discover grind",
    ):
        assert f"### `{command}`" in rendered
    assert "## advanced execution options" in rendered
    assert "--format" not in rendered.split("## Commands", 1)[1]
