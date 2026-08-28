from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from reprobit.process import CommandSpec
from reprobit.scheduler import SchedulerError, TaskScheduler, TaskSpec, TaskWorkspace


def python_command(workspace: TaskWorkspace, code: str) -> CommandSpec:
    return CommandSpec.create(
        (sys.executable, "-c", code),
        cwd=workspace.root,
        environment={},
        timeout_seconds=3,
        log_path=workspace.logs / "command.log",
    )


def test_scheduler_runs_a_dependency_dag_in_private_workspaces(tmp_path: Path) -> None:
    marker = tmp_path / "first-complete"
    tasks = (
        TaskSpec(
            "compile.one",
            lambda workspace: python_command(
                workspace, f"from pathlib import Path; Path({str(marker)!r}).write_text('yes')"
            ),
        ),
        TaskSpec(
            "link",
            lambda workspace: python_command(
                workspace,
                f"from pathlib import Path; assert Path({str(marker)!r}).read_text() == 'yes'",
            ),
            dependencies=("compile.one",),
        ),
    )
    with TaskScheduler(run_root=tmp_path / "run", max_workers=2) as scheduler:
        results = scheduler.run(tasks)

    assert tuple(results) == ("compile.one", "link")
    assert results["compile.one"].workspace.objects.is_dir()
    assert results["compile.one"].workspace.pdb.is_dir()
    assert results["compile.one"].workspace != results["link"].workspace


def test_scheduler_validates_unknown_dependencies_and_cycles(tmp_path: Path) -> None:
    static = CommandSpec.create((sys.executable, "-c", "pass"), cwd=tmp_path)
    with (
        TaskScheduler(run_root=tmp_path / "unknown", max_workers=1) as scheduler,
        pytest.raises(SchedulerError, match="unknown dependencies"),
    ):
        scheduler.run((TaskSpec("a", static, dependencies=("missing",)),))
    with (
        TaskScheduler(run_root=tmp_path / "cycle", max_workers=1) as scheduler,
        pytest.raises(SchedulerError, match="cycle"),
    ):
        scheduler.run(
            (
                TaskSpec("a", static, dependencies=("b",)),
                TaskSpec("b", static, dependencies=("a",)),
            )
        )


def test_scheduler_cancels_siblings_after_failure(tmp_path: Path) -> None:
    tasks = (
        TaskSpec("fail", lambda workspace: python_command(workspace, "raise SystemExit(9)")),
        TaskSpec(
            "slow",
            lambda workspace: python_command(workspace, "import time; time.sleep(10)"),
        ),
        TaskSpec(
            "never",
            lambda workspace: python_command(workspace, "raise AssertionError('ran')"),
            dependencies=("slow",),
        ),
    )
    started = time.monotonic()
    with (
        TaskScheduler(run_root=tmp_path / "run", max_workers=2) as scheduler,
        pytest.raises(SchedulerError) as caught,
    ):
        scheduler.run(tasks)
    assert "fail" in caught.value.failures
    assert "never" in caught.value.skipped
    assert time.monotonic() - started < 3


def test_resource_limit_serializes_one_class(tmp_path: Path) -> None:
    timeline = tmp_path / "timeline"

    def timed(name: str):
        def factory(workspace: TaskWorkspace) -> CommandSpec:
            code = (
                "from pathlib import Path; import time; "
                f"p=Path({str(timeline)!r}); "
                f"p.open('a').write('{name}-start\\n'); time.sleep(.08); "
                f"p.open('a').write('{name}-end\\n')"
            )
            return python_command(workspace, code)

        return factory

    tasks = (
        TaskSpec("a", timed("a"), resource_class="compiler"),
        TaskSpec("b", timed("b"), resource_class="compiler"),
    )
    with TaskScheduler(
        run_root=tmp_path / "run", max_workers=2, resource_limits={"compiler": 1}
    ) as scheduler:
        scheduler.run(tasks)
    lines = timeline.read_text().splitlines()
    serial_orders = (
        ["a-start", "a-end", "b-start", "b-end"],
        ["b-start", "b-end", "a-start", "a-end"],
    )
    assert lines in serial_orders
