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


def test_cli_reference_prefers_consistent_current_option_names() -> None:
    rendered = render_cli_reference()

    init = rendered.split("### `rbit init`", 1)[1].split("### `", 1)[0]
    doctor = rendered.split("### `rbit doctor`", 1)[1].split("### `", 1)[0]
    lock = rendered.split("### `rbit toolchain lock`", 1)[1].split("### `", 1)[0]
    provision = rendered.split("### `rbit toolchain provision`", 1)[1].split("### `", 1)[0]
    export = rendered.split("### `rbit source export`", 1)[1].split("### `", 1)[0]
    cmake_import = rendered.split("### `rbit import cmake`", 1)[1].split("### `", 1)[0]
    graph_configure = rendered.split("### `rbit graph configure`", 1)[1].split("### `", 1)[0]
    repair = rendered.split("### `rbit repair`", 1)[1].split("### `", 1)[0]
    clean = rendered.split("### `rbit clean`", 1)[1].split("### `", 1)[0]

    assert "--profile" in init
    assert "--toolchain-profile" not in init
    assert "--profile" in doctor
    assert "--toolchain-profile" not in doctor
    assert "project's remembered compiler" in doctor
    assert "--profile" in lock
    assert "--toolchain-root" in lock
    assert "--root" not in lock
    assert "{msvc_4_2}" in provision
    assert "msvc_5_0" not in provision
    assert "[project]" in export
    assert "--destination PROJECT_RELATIVE_DIRECTORY" in export
    assert "--refresh" in cmake_import
    assert "--path PATH" in cmake_import
    assert "--cmake-define NAME=VALUE" in cmake_import
    assert "--cmake-define NAME=VALUE" in graph_configure
    assert "--candidate-limit COUNT" in repair
    assert "--donor-candidates" not in repair
    assert "incremental and repair-search cache data selected by age" in clean
    assert "complete repair search cache" not in clean
    assert "| `project` | `.` |" in init
    assert "| `project` | `.` |" in lock


def test_user_guides_do_not_restore_retired_cli_spellings() -> None:
    paths = (
        ROOT / "README.md",
        *(ROOT / "docs").glob("*.md"),
        *(ROOT / "examples").glob("**/README.md"),
        ROOT / "action.yml",
        *(ROOT / ".github/workflows").glob("*.yml"),
    )
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)

    assert "--toolchain-profile" not in text
    assert "rbit toolchain lock . --root" not in text
    assert "rbit source export build/" not in text
    assert "--donor-candidates" not in text
