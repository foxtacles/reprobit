from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

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
def test_windows_child_checks_accounting_after_monitored_grace(
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
        def active_processes() -> int:
            events.append("accounting")
            return 0 if drains else 1

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
    expected: list[object] = ["close-process-handle", "accounting"]
    if leaked:
        expected.append(("terminate-and-drain", 2.0))
    assert events == expected


@pytest.mark.parametrize(
    ("case", "expected_error"),
    [
        ("success", None),
        ("timeout", ProcessTimedOut),
        ("cancellation", ProcessCancelled),
        ("output", ProcessOutputLimitExceeded),
        ("leak", ProcessTreeLeak),
        ("interrupt", KeyboardInterrupt),
    ],
)
def test_windows_descendant_grace_keeps_supervisor_limits_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    expected_error: type[BaseException] | None,
) -> None:
    clock = [0.0]
    token = CancellationToken()
    events: list[str] = []
    spec = CommandSpec.create(
        ("fixture",),
        cwd=tmp_path,
        timeout_seconds=0.05 if case == "timeout" else 1.0,
        output_limit=8,
    )

    class Process:
        pid = 4312
        returncode = 0

        def poll(self) -> int:
            return 0

        def wait(self, *, timeout: float) -> int:
            return 0

    class Job:
        terminated = False

        def close_process_handle(self, process: object) -> None:
            pass

        def active_processes(self) -> int:
            if self.terminated or (case == "success" and clock[0] >= 0.03):
                return 0
            return 1

        def terminate_and_drain(self, timeout: float) -> None:
            self.terminated = True
            events.append("drained")

        def close(self) -> None:
            events.append("closed")

    import tempfile

    with tempfile.TemporaryFile() as stream:
        child = process_module._OwnedChild(Process(), Job(), stream)  # type: ignore[arg-type]

        def sleep(duration: float) -> None:
            clock[0] += duration
            if case == "cancellation":
                token.cancel("cancel while descendants remain")
            if case == "output":
                stream.write(b"x" * 9)
                stream.flush()
            if case == "interrupt":
                raise KeyboardInterrupt("interrupt while descendants remain")

        monkeypatch.setattr(process_module, "os", SimpleNamespace(**(vars(os) | {"name": "nt"})))
        monkeypatch.setattr(
            process_module, "time", SimpleNamespace(monotonic=lambda: clock[0], sleep=sleep)
        )
        with ProcessSupervisor(poll_interval=0.01, termination_grace=0.1) as supervisor:
            monkeypatch.setattr(supervisor, "_spawn", lambda _spec, _planner: child)
            if expected_error is None:
                returncode, output, duration = supervisor._one_attempt(spec, token, None)
                assert (returncode, output) == (0, b"")
                assert 0.03 <= duration <= 0.04
                assert "drained" not in events
            else:
                with pytest.raises(expected_error):
                    supervisor._one_attempt(spec, token, None)
                assert "drained" in events
            assert events[-1] == "closed"
            assert stream.closed


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), 0, -1, True])
def test_process_limits_require_finite_positive_values(tmp_path: Path, value: float) -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        CommandSpec.create(("fixture",), cwd=tmp_path, timeout_seconds=value)
    with pytest.raises(ValueError, match="finite and positive"):
        ProcessSupervisor(poll_interval=value)
    with pytest.raises(ValueError, match="finite and positive"):
        ProcessSupervisor(termination_grace=value)


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


@pytest.mark.skipif(os.name not in {"posix", "nt"}, reason="requires owned process trees")
def test_supervisor_waits_for_short_lived_descendant_and_its_late_output(
    tmp_path: Path,
) -> None:
    completion = tmp_path / "descendant-complete"
    descendant = (
        "import sys,time; from pathlib import Path; time.sleep(0.15); "
        "sys.stdout.buffer.write(b'late descendant output\\n'); sys.stdout.buffer.flush(); "
        f"Path({str(completion)!r}).write_bytes(b'complete')"
    )
    program = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
        "sys.stdout.buffer.write(b'leader output\\n'); sys.stdout.buffer.flush()"
    )
    with ProcessSupervisor(poll_interval=0.01, termination_grace=1.0) as supervisor:
        result = supervisor.run(command(tmp_path, program))
        assert completion.read_bytes() == b"complete"
        assert result.output == b"leader output\nlate descendant output\n"
        assert supervisor.active_pids == ()
    assert result.succeeded
    assert (tmp_path / "command.log").read_bytes() == result.output


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX process groups")
@pytest.mark.parametrize(
    ("violation", "expected_error"),
    [
        ("timeout", ProcessTimedOut),
        ("cancellation", ProcessCancelled),
        ("output", ProcessOutputLimitExceeded),
        ("interrupt", KeyboardInterrupt),
    ],
)
def test_descendant_grace_preserves_command_limits(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    violation: str,
    expected_error: type[BaseException],
) -> None:
    gate = tmp_path / "leader-exited"
    pid_file = tmp_path / "grandchild.pid"
    descendant = (
        "import time; from pathlib import Path\n"
        f"while not Path({str(gate)!r}).exists(): time.sleep(0.01)\n"
        + ("print('x' * 4096, flush=True)\n" if violation == "output" else "")
        + "time.sleep(60)\n"
    )
    program = (
        "import subprocess,sys; from pathlib import Path; "
        f"child=subprocess.Popen([sys.executable, '-c', {descendant!r}]); "
        f"Path({str(pid_file)!r}).write_text(str(child.pid))"
    )
    token = CancellationToken()
    original_group_exists = process_module._OwnedChild._posix_group_exists

    def observe_leader_exit(child: process_module._OwnedChild) -> bool:
        exists = original_group_exists(child)
        if exists and child.process.poll() is not None and not gate.exists():
            gate.write_bytes(b"exited")
            if violation == "cancellation":
                token.cancel("cancel during descendant grace")
            if violation == "interrupt":
                raise KeyboardInterrupt("interrupt during descendant grace")
        return exists

    monkeypatch.setattr(process_module._OwnedChild, "_posix_group_exists", observe_leader_exit)
    spec = CommandSpec.create(
        (sys.executable, "-c", program),
        cwd=tmp_path,
        environment={},
        timeout_seconds=1.0 if violation == "timeout" else 5.0,
        output_limit=512,
        log_path=tmp_path / "command.log",
    )
    with ProcessSupervisor(poll_interval=0.01, termination_grace=2.0) as supervisor:
        with pytest.raises(expected_error):
            supervisor.run(spec, cancellation=token)
        assert supervisor.active_pids == ()

    assert gate.read_bytes() == b"exited"
    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_file.read_text()), 0)
    if violation == "interrupt":
        assert not (tmp_path / "command.log").exists()
    else:
        output = (tmp_path / "command.log").read_bytes()
        assert output == (b"x" * 512 if violation == "output" else b"")


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

    def cancel_after_first_attempt_started() -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                if counter.read_text() == "x":
                    token.cancel("requested stop")
                    return
            except OSError:
                pass
            time.sleep(0.01)
        token.cancel("child did not start")

    watcher = threading.Thread(target=cancel_after_first_attempt_started, daemon=True)
    watcher.start()
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
        watcher.join(timeout=5)
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
