from __future__ import annotations

import argparse
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import reprobit.cli_environment as environment
import reprobit.cli_output as cli_output
from reprobit.backends import NativeWindowsBackend, PosixWineBackend
from reprobit.cli import _parser, main


def test_auto_backend_checks_explicit_wine_programs(monkeypatch: pytest.MonkeyPatch) -> None:
    default = PosixWineBackend(wine=sys.executable, wineserver=sys.executable)
    monkeypatch.setattr(environment, "backend_for_host", lambda: default)
    args = argparse.Namespace(
        backend="auto", wine="missing-fixture-wine", wineserver="missing-fixture-wineserver"
    )

    selected = environment.selected_backend(args)

    assert isinstance(selected, PosixWineBackend)
    assert selected.wine == args.wine
    assert selected.wineserver == args.wineserver
    checks = {check.name: check for check in selected.doctor().checks}
    assert checks["wine"].passed is False
    assert checks["wine"].detail == "missing-fixture-wine not found"
    assert checks["wineserver"].passed is False
    assert checks["wineserver"].detail == "missing-fixture-wineserver not found"


@pytest.mark.parametrize("wine", [None, "wine"])
def test_auto_backend_defaults_reuse_the_host_selection(
    monkeypatch: pytest.MonkeyPatch, wine: str | None
) -> None:
    default = PosixWineBackend(wine=sys.executable, wineserver=sys.executable)
    monkeypatch.setattr(environment, "backend_for_host", lambda: default)
    args = argparse.Namespace(backend="auto", wine=wine, wineserver=None)

    assert environment.selected_backend(args) is default


def test_auto_native_backend_keeps_host_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    default = NativeWindowsBackend()
    monkeypatch.setattr(environment, "backend_for_host", lambda: default)
    args = argparse.Namespace(backend="auto", wine="custom-wine", wineserver="custom-wineserver")

    assert environment.selected_backend(args) is default


def test_followup_execution_options_round_trip_explicit_overrides() -> None:
    invocation = [
        "discover",
        "grind",
        ".",
        "--jobs=2",
        "--jobs",
        "3",
        "--backend",
        "auto",
        "--wine",
        "/custom Wine/wine",
        "--wineserver=/custom Wine/wineserver",
        "--toolchain-root",
        "/compiler root",
        "--compiler-transport",
        "/compiler wrapper",
        "--resource-transport",
        "/resource wrapper",
        "--initialization-timeout",
        "700",
        "--compile-timeout",
        "701",
        "--link-timeout",
        "901",
        "--cleanup-timeout",
        "11",
    ]
    parser = _parser()
    original = parser.parse_args(invocation)
    followup = parser.parse_args(
        ["verify", ".", *environment.execution_option_argv(original, invocation)]
    )

    for name in (
        "jobs",
        "backend",
        "wine",
        "wineserver",
        "toolchain_root",
        "compiler_transport",
        "resource_transport",
        "initialization_timeout",
        "compile_timeout",
        "link_timeout",
        "cleanup_timeout",
    ):
        assert getattr(followup, name) == getattr(original, name)
    assert followup.jobs == 3


def test_followup_options_keep_abbreviations_but_omit_automatic_defaults() -> None:
    parser = _parser()
    invocation = ["discover", "grind", ".", "--initialization-t=712", "--jobs", "2"]
    args = parser.parse_args(invocation)
    assert environment.execution_option_argv(args, invocation) == (
        "--jobs",
        "2",
        "--initialization-timeout",
        "712.0",
    )
    default_args = parser.parse_args(["discover", "grind", "."])
    assert environment.execution_option_argv(default_args, ["discover", "grind", "."]) == ()


def test_windows_human_commands_quote_powershell_metacharacters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Replace only this module's platform view: changing os.name globally would
    # also make pathlib choose WindowsPath on a POSIX test host.
    monkeypatch.setattr(cli_output, "os", SimpleNamespace(name="nt", fspath=str))
    assert (
        cli_output.human_command(
            ("rbit", "verify", r"C:\work\O'Brien & $project`copy", "--jobs", "2")
        )
        == "rbit verify 'C:\\work\\O''Brien & $project`copy' --jobs 2"
    )
    assert cli_output.human_command(("rbit", "verify", r"C:\work\plain")) == (
        r"rbit verify C:\work\plain"
    )


def test_windows_human_commands_invoke_a_quoted_executable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(cli_output, "os", SimpleNamespace(name="nt", fspath=str))
    assert cli_output.human_command((r"C:\Program Files\rbit.exe", "verify", ".")) == (
        r"& 'C:\Program Files\rbit.exe' verify ."
    )
    assert cli_output.human_command(("rbit", "verify", ".")) == "rbit verify ."


@pytest.mark.parametrize("platform", ["nt", "posix"])
def test_human_commands_preserve_empty_input(
    monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    monkeypatch.setattr(cli_output, "os", SimpleNamespace(name=platform, fspath=str))
    assert cli_output.human_command(()) == ""


@pytest.mark.parametrize(
    "option",
    [
        "--jobs",
        "--initialization-timeout",
        "--compile-timeout",
        "--link-timeout",
        "--cleanup-timeout",
    ],
)
def test_initial_cmake_import_refuses_unused_refresh_controls(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], option: str
) -> None:
    assert main(["import", "cmake", str(tmp_path), option, "2"]) == 2
    assert f"{option} requires --refresh" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []
