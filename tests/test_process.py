from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

import reprobit.process as process_module
from reprobit.process import (
    CancellationToken,
    CommandFailed,
    CommandSpec,
    ProcessCancelled,
    ProcessOutputLimitExceeded,
    ProcessSupervisor,
    ProcessTimedOut,
    ProcessTreeLeak,
    RetryPolicy,
)


def command(tmp_path: Path, program: str, *, timeout: float = 5) -> CommandSpec:
    return CommandSpec.create(
        (sys.executable, "-c", program),
        cwd=tmp_path,
        environment={},
        timeout_seconds=timeout,
        log_path=tmp_path / "command.log",
    )


def test_windows_job_wait_empty_polls_accounting_until_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = object.__new__(process_module._WindowsJob)
    active = iter((1, 0))
    sleeps: list[float] = []
    job.active_processes = lambda: next(active)
    monkeypatch.setattr(process_module.time, "sleep", sleeps.append)

    assert job.wait_empty(None) is True
    assert sleeps == [0.01]


def test_windows_job_wait_empty_returns_false_at_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = object.__new__(process_module._WindowsJob)
    monotonic = iter((10.0, 10.0, 10.01))
    sleeps: list[float] = []
    job.active_processes = lambda: 1
    monkeypatch.setattr(process_module.time, "monotonic", lambda: next(monotonic))
    monkeypatch.setattr(process_module.time, "sleep", sleeps.append)

    assert job.wait_empty(0.01) is False
    assert len(sleeps) == 1
    assert 0 < sleeps[0] <= 0.01


def test_windows_job_wait_empty_propagates_accounting_failure() -> None:
    job = object.__new__(process_module._WindowsJob)

    def fail_query() -> int:
        raise OSError("accounting unavailable")

    job.active_processes = fail_query
    with pytest.raises(OSError, match="accounting unavailable"):
        job.wait_empty(1.0)


def test_windows_job_process_handle_close_is_idempotent() -> None:
    closes = 0

    class Handle:
        closed = False

        def Close(self) -> None:
            nonlocal closes
            if not self.closed:
                self.closed = True
                closes += 1

    class Process:
        returncode = 0
        _handle = Handle()

    job = object.__new__(process_module._WindowsJob)
    process = Process()
    job.close_process_handle(process)  # type: ignore[arg-type]
    job.close_process_handle(process)  # type: ignore[arg-type]

    assert closes == 1


@pytest.mark.parametrize(("drains", "leaked"), [(True, False), (False, True)])
def test_windows_child_waits_before_classifying_a_job_leak(
    monkeypatch: pytest.MonkeyPatch,
    drains: bool,
    leaked: bool,
) -> None:
    events: list[object] = []

    class Process:
        pid = 4312
        returncode = 0

    class Job:
        @staticmethod
        def close_process_handle(process: object) -> None:
            assert process is child_process
            events.append("close-process-handle")

        @staticmethod
        def wait_empty(timeout: float) -> bool:
            events.append(("wait-empty", timeout))
            return drains

        @staticmethod
        def terminate_and_drain(timeout: float) -> None:
            events.append(("terminate-and-drain", timeout))

    monkeypatch.setattr(process_module.os, "name", "nt")
    child_process = Process()
    child = process_module._OwnedChild(  # type: ignore[arg-type]
        child_process,
        Job(),
    )

    assert child.drain_after_leader_exit(2.0) is leaked
    expected: list[object] = ["close-process-handle", ("wait-empty", 2.0)]
    if leaked:
        expected.append(("terminate-and-drain", 2.0))
    assert events == expected


def test_windows_job_close_retains_handle_after_close_failure() -> None:
    class Kernel32:
        @staticmethod
        def CloseHandle(_handle: int) -> int:
            return 0

    job = object.__new__(process_module._WindowsJob)
    job.handle = 4312
    job._kernel32 = Kernel32()
    job._last_error = lambda: 5

    with pytest.raises(OSError, match="CloseHandle"):
        job.close()

    assert job.handle == 4312


def test_windows_lineage_broker_contract_is_isolated_and_minimal() -> None:
    assert process_module._windows_lineage_broker_command()[1:3] == ("-I", "-m")
    assert process_module._windows_lineage_broker_environment(
        {
            "PYTHONPATH": "/attacker",
            "SystemRoot": r"C:\Windows",
            "windir": r"C:\Windows",
        }
    ) == {"SystemRoot": r"C:\Windows", "WINDIR": r"C:\Windows"}


def test_windows_lineage_plan_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class Planner:
        @staticmethod
        def windows_lineage_plan(_spec: CommandSpec) -> bytes:
            return b"12345"

    monkeypatch.setattr(process_module, "_WINDOWS_LINEAGE_PLAN_LIMIT", 4)

    with pytest.raises(process_module.ProcessLaunchError, match="larger than 16 MiB"):
        process_module._windows_lineage_plan(Planner(), command(tmp_path, "pass"))


def test_abort_launch_uses_only_bounded_waits_and_job_close_fallback() -> None:
    events: list[object] = []

    class StuckProcess:
        pid = 4312
        returncode = None

        @staticmethod
        def poll() -> None:
            return None

        @staticmethod
        def kill() -> None:
            events.append("kill")

        @staticmethod
        def wait(timeout: float | None = None) -> int:
            events.append(("wait", timeout))
            raise process_module.subprocess.TimeoutExpired(("producer",), timeout)

    class Job:
        @staticmethod
        def terminate() -> None:
            events.append("job-terminate")

        @staticmethod
        def close() -> None:
            events.append("job-close")

    with pytest.raises(process_module.ProcessError, match="could not be reaped"):
        ProcessSupervisor._abort_launch(  # type: ignore[arg-type]
            StuckProcess(),
            Job(),
        )

    assert events == [
        "job-terminate",
        "kill",
        ("wait", 2),
        "kill",
        ("wait", 2),
        "job-close",
    ]


def test_forget_attempts_all_cleanup_and_preserves_primary_error() -> None:
    events: list[str] = []

    class Process:
        pid = 4312

    class Job:
        @staticmethod
        def close() -> None:
            events.append("job-close")
            raise OSError("job close failed")

    class Capture:
        @staticmethod
        def close() -> None:
            events.append("capture-close")
            raise OSError("capture close failed")

    child = process_module._OwnedChild(  # type: ignore[arg-type]
        Process(),
        Job(),
        Capture(),
    )
    primary = RuntimeError("primary")
    with ProcessSupervisor() as supervisor:
        supervisor._active[4312] = child
        supervisor._forget(child, primary_error=primary)

    assert events == ["job-close", "capture-close"]
    assert supervisor.active_pids == ()
    assert getattr(primary, "__notes__", ()) == [
        "process cleanup also failed: job close failed",
        "process cleanup also failed: capture close failed",
    ]


def test_supervisor_captures_output_and_log(tmp_path: Path) -> None:
    with ProcessSupervisor() as supervisor:
        result = supervisor.run(
            command(tmp_path, "import sys; sys.stdout.buffer.write(b'complete\\n')")
        )

    assert result.succeeded
    assert result.output == b"complete\n"
    assert (tmp_path / "command.log").read_bytes() == result.output


def test_supervisor_terminates_a_timed_out_tree(tmp_path: Path) -> None:
    with ProcessSupervisor(poll_interval=0.01, termination_grace=0.2) as supervisor:
        with pytest.raises(ProcessTimedOut):
            supervisor.run(command(tmp_path, "import time; time.sleep(10)", timeout=0.08))
        assert supervisor.active_pids == ()


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
def test_successful_parent_cannot_leave_a_process_group_descendant(
    tmp_path: Path,
) -> None:
    pid_file = tmp_path / "grandchild.pid"
    program = (
        "import subprocess,sys; from pathlib import Path; "
        "child=subprocess.Popen([sys.executable,'-c',"
        "'import time; time.sleep(60)']); "
        f"Path({str(pid_file)!r}).write_text(str(child.pid))"
    )
    with (
        ProcessSupervisor(poll_interval=0.01, termination_grace=0.2) as supervisor,
        pytest.raises(ProcessTreeLeak, match="process group drained"),
    ):
        supervisor.run(command(tmp_path, program))

    grandchild = int(pid_file.read_text())
    deadline = time.monotonic() + 2
    while True:
        try:
            os.kill(grandchild, 0)
        except ProcessLookupError:
            break
        if time.monotonic() >= deadline:
            pytest.fail(f"grandchild {grandchild} survived process-group drain")
        time.sleep(0.01)
    assert supervisor.active_pids == ()


def test_deliberate_cancellation_is_never_retried(tmp_path: Path) -> None:
    counter = tmp_path / "counter"
    token = CancellationToken()
    timer = threading.Timer(0.08, lambda: token.cancel("requested stop"))
    timer.start()
    program = (
        "from pathlib import Path; import time; "
        f"p=Path({str(counter)!r}); p.write_text(p.read_text()+'x' if p.exists() else 'x'); "
        "time.sleep(10)"
    )
    try:
        with (
            ProcessSupervisor(poll_interval=0.01, termination_grace=0.2) as supervisor,
            pytest.raises(ProcessCancelled, match="requested stop"),
        ):
            supervisor.run(
                command(tmp_path, program),
                cancellation=token,
                retry_policy=RetryPolicy(max_attempts=2, transient_returncodes=frozenset({75})),
            )
    finally:
        timer.cancel()
    assert counter.read_text() == "x"


def test_specific_positive_wrapper_code_gets_one_retry(tmp_path: Path) -> None:
    counter = tmp_path / "attempts"
    program = (
        "from pathlib import Path; import sys; "
        f"p=Path({str(counter)!r}); n=int(p.read_text())+1 if p.exists() else 1; "
        "p.write_text(str(n)); "
        "sys.exit(75 if n == 1 else 0)"
    )
    with ProcessSupervisor() as supervisor:
        result = supervisor.run(
            command(tmp_path, program),
            retry_policy=RetryPolicy(max_attempts=2, transient_returncodes=frozenset({75})),
        )
    assert result.attempts == 2
    assert counter.read_text() == "2"


def test_unlisted_failure_is_not_retried(tmp_path: Path) -> None:
    started = time.monotonic()
    with ProcessSupervisor() as supervisor, pytest.raises(CommandFailed) as caught:
        supervisor.run(
            command(tmp_path, "raise SystemExit(4)"),
            retry_policy=RetryPolicy(max_attempts=2, transient_returncodes=frozenset({75})),
        )
    assert caught.value.result.attempts == 1
    assert time.monotonic() - started < 2


def test_retry_policy_rejects_signal_codes() -> None:
    with pytest.raises(ValueError, match="positive"):
        RetryPolicy(max_attempts=2, transient_returncodes=frozenset({-15}))


def test_output_capture_is_bounded_while_the_child_is_running(tmp_path: Path) -> None:
    spec = CommandSpec.create(
        (sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000)"),
        cwd=tmp_path,
        environment={},
        timeout_seconds=5,
        output_limit=4096,
    )

    with (
        ProcessSupervisor(poll_interval=0.005) as supervisor,
        pytest.raises(ProcessOutputLimitExceeded) as caught,
    ):
        supervisor.run(spec)

    assert len(caught.value.output) == 4096


def test_windows_child_is_contained_before_resume() -> None:
    events: list[str] = []

    class Job:
        @staticmethod
        def assign(process: object) -> None:
            assert process is child
            events.append("assign")

        @staticmethod
        def resume(process: object) -> None:
            assert process is child
            events.append("resume")

    child = object()
    process_module._admit_suspended_windows_child(
        Job(),  # type: ignore[arg-type]
        child,  # type: ignore[arg-type]
    )

    assert events == ["assign", "resume"]


@pytest.mark.skipif(os.name == "nt", reason="non-Windows fail-closed path")
def test_windows_lineage_planner_is_never_ignored_off_windows(tmp_path: Path) -> None:
    called = False

    class Planner:
        def windows_lineage_plan(self, _spec: CommandSpec) -> bytes:
            nonlocal called
            called = True
            return b"{}"

    with (
        ProcessSupervisor() as supervisor,
        pytest.raises(
            process_module.ProcessLaunchError,
            match="requires native Windows",
        ),
    ):
        supervisor.run(
            command(tmp_path, "raise AssertionError('must not launch')"),
            windows_lineage_planner=Planner(),
        )

    assert called is False
