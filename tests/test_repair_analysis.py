from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from reprobit.classic_project import ClassicProjectError
from reprobit.cli_output import CLIOutput
from reprobit.repair_analysis import RepairAnalysisError, analyze_classic_repair


def _args() -> argparse.Namespace:
    return argparse.Namespace(cold=True, keep_workspace="always")


def _output() -> CLIOutput:
    import io

    return CLIOutput("text", io.StringIO(), io.StringIO())


def test_analysis_uses_private_warm_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[argparse.Namespace] = []

    def build(args: argparse.Namespace, _output: CLIOutput) -> int:
        observed.append(args)
        return 0

    monkeypatch.setattr("reprobit.repair_analysis.command_build", build)

    cache_root = tmp_path / "shared-state"
    result = analyze_classic_repair(_args(), _output(), cache_root=cache_root)

    assert result.completed is True
    assert observed[0].cold is False
    assert observed[0].keep_workspace == "never"
    assert callable(observed[0]._classic_measured_receipt_repair)
    assert observed[0]._classic_repair_analysis_only is True
    assert observed[0]._incremental_cache_root == cache_root
    assert observed[0]._incremental_progress_description == "checking affected source files"


def test_analysis_never_misclassifies_an_unrelated_runtime_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def build(_args: argparse.Namespace, _output: CLIOutput) -> int:
        raise ClassicProjectError("compiler environment failed")

    monkeypatch.setattr("reprobit.repair_analysis.command_build", build)

    with pytest.raises(RepairAnalysisError, match="compiler environment failed"):
        analyze_classic_repair(_args(), _output())
