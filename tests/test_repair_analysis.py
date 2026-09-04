from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import reprobit.repair_workflow as subject
from reprobit.classic_project import ClassicProjectError
from reprobit.cli_output import CLIOutput
from reprobit.repair_workflow import (
    RepairAnalysisError,
    RepairWorkflowOptions,
    analyze_classic_repair,
)


def _options() -> RepairWorkflowOptions:
    return RepairWorkflowOptions(cast(Any, object()))


def _output() -> CLIOutput:
    import io

    return CLIOutput("text", io.StringIO(), io.StringIO())


def test_analysis_uses_private_warm_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[object] = []

    def build(request: object, _output: CLIOutput) -> object:
        observed.append(request)
        return SimpleNamespace(seed_objects={})

    monkeypatch.setattr("reprobit.repair_workflow.execute_build", build)

    cache_root = tmp_path / "shared-state"
    result = analyze_classic_repair(
        _options(),
        _output(),
        staged_root=tmp_path,
        cache_root=cache_root,
    )

    assert result.completed is True
    request = cast(Any, observed[0])
    assert request.cold is False
    assert request.keep_workspace.value == "never"
    assert callable(request.repair_analysis.receipt_repair)
    assert request.cache_root == cache_root
    assert request.progress_description == "checking affected source files"


def test_analysis_never_misclassifies_an_unrelated_runtime_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def build(_request: object, _output: CLIOutput) -> object:
        raise ClassicProjectError("compiler environment failed")

    monkeypatch.setattr("reprobit.repair_workflow.execute_build", build)

    with pytest.raises(RepairAnalysisError, match="compiler environment failed"):
        analyze_classic_repair(_options(), _output(), staged_root=Path.cwd())


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
    )
    monkeypatch.setattr(subject, "ClassicRepairSession", lambda: session)
    monkeypatch.setattr(
        subject,
        "execute_build",
        lambda *_args: SimpleNamespace(seed_objects={}),
    )

    result = subject.analyze_classic_repair(
        _options(),
        _output(),
        staged_root=Path.cwd(),
    )

    assert result.measured_repairs == (before_first, before_second, unaffected)
    assert result.structural_refusals == (first_refusal, second_refusal)
