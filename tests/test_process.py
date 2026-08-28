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


def test_windows_child_initializer_runs_after_containment_before_resume() -> None:
    events: list[object] = []

    class Job:
        @staticmethod
        def process_handle(process: object) -> int:
            assert process is child
            return 4312

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
        lambda handle: events.append(("initialize", handle)),
    )

    assert events == ["assign", ("initialize", 4312), "resume"]


def test_windows_child_initializer_failure_never_resumes() -> None:
    events: list[str] = []

    class Job:
        @staticmethod
        def process_handle(process: object) -> int:
            del process
            return 4312

        @staticmethod
        def assign(process: object) -> None:
            del process
            events.append("assign")

        @staticmethod
        def resume(process: object) -> None:
            del process
            events.append("resume")

    def reject(_handle: int) -> None:
        events.append("initialize")
        raise RuntimeError("map assignment failed")

    with pytest.raises(RuntimeError, match="map assignment failed"):
        process_module._admit_suspended_windows_child(
            Job(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
            reject,
        )

    assert events == ["assign", "initialize"]


@pytest.mark.skipif(os.name == "nt", reason="non-Windows fail-closed path")
def test_suspended_initializer_is_never_ignored_off_windows(tmp_path: Path) -> None:
    called = False

    def initialize(_handle: int) -> None:
        nonlocal called
        called = True

    with ProcessSupervisor() as supervisor, pytest.raises(
        process_module.ProcessLaunchError,
        match="requires native Windows",
    ):
        supervisor.run(
            command(tmp_path, "raise AssertionError('must not launch')"),
            suspended_process_initializer=initialize,
        )

    assert called is False
