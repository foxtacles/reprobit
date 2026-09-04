from __future__ import annotations

import argparse
from pathlib import Path
from types import SimpleNamespace

import pytest

import reprobit.repair_workflow as subject
from reprobit.classic_project import ClassicProjectError
from reprobit.cli_output import CLIOutput
from reprobit.repair_workflow import RepairAnalysisError, analyze_classic_repair


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

    monkeypatch.setattr("reprobit.repair_workflow.command_build", build)

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

    monkeypatch.setattr("reprobit.repair_workflow.command_build", build)

    with pytest.raises(RepairAnalysisError, match="compiler environment failed"):
        analyze_classic_repair(_args(), _output())


def test_analysis_discards_results_after_each_units_first_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before_first = SimpleNamespace(unit_id="tu.first", action_index=1)
    after_first = SimpleNamespace(unit_id="tu.first", action_index=3)
    before_second = SimpleNamespace(unit_id="tu.second", action_index=2)
    after_second = SimpleNamespace(unit_id="tu.second", action_index=6)
    unaffected = SimpleNamespace(unit_id="tu.clean", action_index=9)
    first_refusal = SimpleNamespace(unit_id="tu.first", action_index=2)
    downstream_refusal = SimpleNamespace(unit_id="tu.first", action_index=4)
    second_refusal = SimpleNamespace(unit_id="tu.second", action_index=5)
    session = SimpleNamespace(
        repairs=(before_first, after_first, before_second, after_second, unaffected),
        refusals=(first_refusal, downstream_refusal, second_refusal),
        seed_objects={},
    )
    monkeypatch.setattr(subject, "ClassicRepairSession", lambda: session)
    monkeypatch.setattr(subject, "command_build", lambda *_args: 0)

    result = subject.analyze_classic_repair(_args(), _output())

    assert result.measured_repairs == (before_first, before_second, unaffected)
    assert result.structural_refusals == (first_refusal, second_refusal)
