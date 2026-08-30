"""Owned, bounded child-process execution.

Every child belongs to a process tree that the supervisor can terminate.  A
caller may opt into one bounded retry for specific positive exit codes, but a
timeout or deliberate cancellation is never classified as transient.
"""

from __future__ import annotations

import atexit
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, NoReturn, Protocol


class ProcessError(RuntimeError):
    """Base error for supervised command execution."""


class ProcessLaunchError(ProcessError):
    """A child could not be created."""


class WindowsLineagePlanner(Protocol):
    """Supply one broker contract for a native Windows producer tree."""

    def windows_lineage_plan(self, spec: CommandSpec) -> bytes: ...


_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_SUSPENDED = 0x00000004
_WINDOWS_LINEAGE_PLAN_LIMIT = 16 * 1024 * 1024


def _failure_message(summary: str, spec: CommandSpec, output: bytes) -> str:
    lines = [summary]
    if spec.log_path is not None:
        lines.append(f"full output: {spec.log_path}")
    tail = output[-4000:].decode("utf-8", "replace").strip()
    if tail:
        lines.extend(("output tail:", tail))
    return "\n".join(lines)


class ProcessTimedOut(ProcessError):
    """A child exceeded its declared absolute deadline."""

    def __init__(self, spec: CommandSpec, output: bytes) -> None:
        super().__init__(
            _failure_message(
                f"command timed out after {spec.timeout_seconds:g}s: {spec.argv[0]}",
                spec,
                output,
            )
        )
        self.spec = spec
        self.output = output


class ProcessCancelled(ProcessError):
    """A cancellation token stopped an owned child tree."""

    def __init__(self, reason: str, output: bytes = b"") -> None:
        super().__init__(reason)
        self.reason = reason
        self.output = output


class ProcessOutputLimitExceeded(ProcessError):
    """A child exceeded its bounded output capture."""

    def __init__(self, spec: CommandSpec, output: bytes) -> None:
        super().__init__(
            _failure_message(
                f"command output exceeded {spec.output_limit} bytes: {spec.argv[0]}",
                spec,
                output,
            )
        )
        self.spec = spec
        self.output = output


class ProcessTreeLeak(ProcessError):
    """A command leader exited while an owned descendant was still live."""

    def __init__(self, spec: CommandSpec, output: bytes) -> None:
        super().__init__(
            _failure_message(
                f"command exited before its owned process group drained: {spec.argv[0]}",
                spec,
                output,
            )
        )
        self.spec = spec
        self.output = output


class CommandFailed(ProcessError):
    """A supervised command exited unsuccessfully."""

    def __init__(self, result: ProcessResult, spec: CommandSpec) -> None:
        super().__init__(
            _failure_message(
                f"command failed with exit code {result.returncode}: {result.argv[0]}",
                spec,
                result.output,
            )
        )
        self.result = result
        self.spec = spec


def _text(value: object, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or "\0" in value or (not empty and not value):
        raise ValueError(f"{label} must be a NUL-free string")
    return value


def _environment(
    values: Mapping[str, str] | Iterable[tuple[str, str]],
) -> tuple[tuple[str, str], ...]:
    entries = values.items() if isinstance(values, Mapping) else values
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, value in entries:
        key = _text(key, "environment key")
        value = _text(value, f"environment value for {key}", empty=True)
        if "=" in key:
            raise ValueError("environment keys cannot contain '='")
        folded = key.casefold()
        if folded in seen:
            raise ValueError(f"duplicate case-insensitive environment key: {key}")
        seen.add(folded)
        result.append((key, value))
    return tuple(sorted(result, key=lambda entry: (entry[0].casefold(), entry[0])))


@dataclass(frozen=True, slots=True)
class CommandSpec:
    """One exact command and its execution boundary.

    The environment defaults to empty, not inherited.  Callers that need host
    state must choose and copy those variables explicitly.
    """

    argv: tuple[str, ...]
    cwd: Path
    environment: tuple[tuple[str, str], ...] = ()
    timeout_seconds: float = 300.0
    log_path: Path | None = None
    output_limit: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        argv = tuple(_text(value, "command argument") for value in self.argv)
        if not argv:
            raise ValueError("command argv must not be empty")
        object.__setattr__(self, "argv", argv)
        cwd = Path(self.cwd)
        if not cwd.is_absolute():
            raise ValueError("command cwd must be absolute")
        object.__setattr__(self, "cwd", cwd)
        object.__setattr__(self, "environment", _environment(self.environment))
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0:
            raise ValueError("command timeout must be positive")
        if self.log_path is not None:
            log_path = Path(self.log_path)
            if not log_path.is_absolute():
                raise ValueError("command log path must be absolute")
            object.__setattr__(self, "log_path", log_path)
        if not isinstance(self.output_limit, int) or self.output_limit <= 0:
            raise ValueError("command output limit must be a positive integer")

    @classmethod
    def create(
        cls,
        argv: Iterable[str],
        *,
        cwd: Path | str,
        environment: Mapping[str, str] | Iterable[tuple[str, str]] = (),
        timeout_seconds: float = 300.0,
        log_path: Path | str | None = None,
        output_limit: int = 64 * 1024 * 1024,
    ) -> CommandSpec:
        return cls(
            tuple(argv),
            Path(cwd),
            _environment(environment),
            timeout_seconds,
            None if log_path is None else Path(log_path),
            output_limit,
        )

    @property
    def environment_mapping(self) -> dict[str, str]:
        return dict(self.environment)

    def with_environment(self, values: Mapping[str, str]) -> CommandSpec:
        combined = self.environment_mapping
        folded = {key.casefold(): key for key in combined}
        for key, value in values.items():
            previous = folded.get(key.casefold())
            if previous is not None:
                del combined[previous]
            combined[key] = value
        return CommandSpec.create(
            self.argv,
            cwd=self.cwd,
            environment=combined,
            timeout_seconds=self.timeout_seconds,
            log_path=self.log_path,
            output_limit=self.output_limit,
        )


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """An explicit, bounded transient-failure policy."""

    max_attempts: int = 1
    transient_returncodes: frozenset[int] = frozenset()
    retry_launch_errors: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.max_attempts <= 2:
            raise ValueError("retry policy permits one or two total attempts")
        if any(isinstance(code, bool) or code <= 0 for code in self.transient_returncodes):
            raise ValueError("only positive wrapper exit codes may be transient")
        if self.max_attempts == 1 and (self.transient_returncodes or self.retry_launch_errors):
            raise ValueError("transient conditions require max_attempts=2")

    def permits(self, returncode: int, attempt: int) -> bool:
        return attempt < self.max_attempts and returncode in self.transient_returncodes


@dataclass(frozen=True, slots=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    output: bytes
    attempts: int
    duration_seconds: float

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0

    @property
    def output_tail(self) -> str:
        return self.output[-4000:].decode("utf-8", "replace")


class CancellationToken:
    """Thread-safe cooperative cancellation shared by a task graph."""

    def __init__(self) -> None:
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._reason = "cancelled"

    def cancel(self, reason: str = "cancelled") -> None:
        reason = _text(reason, "cancellation reason")
        with self._lock:
            if not self._event.is_set():
                self._reason = reason
                self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise ProcessCancelled(self.reason)


def _windows_lineage_plan(planner: WindowsLineagePlanner | None, spec: CommandSpec) -> bytes | None:
    """Return one validated broker plan when native lineage isolation is required."""

    if planner is None:
        return None
    plan = planner.windows_lineage_plan(spec)
    if not isinstance(plan, bytes) or not plan:
        raise ProcessLaunchError("Windows lineage planner returned an invalid broker plan")
    if len(plan) > _WINDOWS_LINEAGE_PLAN_LIMIT:
        raise ProcessLaunchError(
            "Windows lineage planner returned a broker plan larger than 16 MiB"
        )
    return plan


def _windows_lineage_broker_command() -> tuple[str, ...]:
    return (
        sys.executable,
        "-I",
        "-m",
        "reprobit.native_device_map",
        "--lineage-broker",
    )


def _windows_lineage_broker_environment(
    source: Mapping[str, str],
) -> dict[str, str]:
    folded = {key.casefold(): value for key, value in source.items()}
    if "systemroot" not in folded:
        raise ProcessLaunchError("Windows lineage broker environment lacks SystemRoot")
    return {
        name: folded[name.casefold()]
        for name in ("SystemRoot", "WINDIR")
        if name.casefold() in folded
    }


class _WindowsJob:
    """Minimal kill-on-close Job Object wrapper, instantiated only on Windows."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("Windows Job Objects are unavailable")
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        win_dll = getattr(ctypes, "WinDLL", None)
        if win_dll is None:
            raise OSError("ctypes WinDLL is unavailable")
        self._kernel32 = win_dll("kernel32", use_last_error=True)
        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.QueryInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._kernel32.QueryInformationJobObject.restype = wintypes.BOOL
        self._kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self._kernel32.TerminateJobObject.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._ntdll = win_dll("ntdll", use_last_error=True)
        self._ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        self._ntdll.NtResumeProcess.restype = ctypes.c_long

        class BasicAccounting(ctypes.Structure):
            _fields_ = [
                ("TotalUserTime", ctypes.c_longlong),
                ("TotalKernelTime", ctypes.c_longlong),
                ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                ("TotalPageFaultCount", wintypes.DWORD),
                ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD),
                ("TotalTerminatedProcesses", wintypes.DWORD),
            ]

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                (name, ctypes.c_ulonglong)
                for name in (
                    "ReadOperationCount",
                    "WriteOperationCount",
                    "OtherOperationCount",
                    "ReadTransferCount",
                    "WriteTransferCount",
                    "OtherTransferCount",
                )
            ]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self._basic_accounting = BasicAccounting

        self.handle = self._kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(self._last_error(), "CreateJobObjectW failed")
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x00002000
        if not self._kernel32.SetInformationJobObject(
            self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            error = self._last_error()
            self.close()
            raise OSError(error, "SetInformationJobObject failed")

    @staticmethod
    def process_handle(process: subprocess.Popen[bytes]) -> int:
        native_process: Any = process
        handle = int(native_process._handle)
        if handle <= 0:
            raise OSError("created process has an invalid native handle")
        return handle

    @staticmethod
    def close_process_handle(process: subprocess.Popen[bytes]) -> None:
        """Release CPython's cached handle after the leader has exited."""

        if process.returncode is None:
            raise OSError("cannot close a running process handle")
        native_process: Any = process
        close = getattr(native_process._handle, "Close", None)
        if not callable(close):
            raise OSError("created process handle does not support idempotent close")
        close()

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        from ctypes import wintypes

        handle = wintypes.HANDLE(self.process_handle(process))
        if not self._kernel32.AssignProcessToJobObject(self.handle, handle):
            raise OSError(self._last_error(), "AssignProcessToJobObject failed")

    def resume(self, process: subprocess.Popen[bytes]) -> None:
        from ctypes import wintypes

        handle = wintypes.HANDLE(self.process_handle(process))
        status = int(self._ntdll.NtResumeProcess(handle))
        if status < 0:
            raise OSError(status & 0xFFFFFFFF, "NtResumeProcess failed")

    def _last_error(self) -> int:
        getter = getattr(self._ctypes, "get_last_error", None)
        return int(getter()) if getter is not None else 0

    def terminate(self) -> None:
        if self.handle and not self._kernel32.TerminateJobObject(self.handle, 1):
            raise OSError(self._last_error(), "TerminateJobObject failed")

    def active_processes(self) -> int:
        from ctypes import wintypes

        information = self._basic_accounting()
        returned = wintypes.DWORD()
        if not self._kernel32.QueryInformationJobObject(
            self.handle,
            1,
            self._ctypes.byref(information),
            self._ctypes.sizeof(information),
            self._ctypes.byref(returned),
        ):
            raise OSError(
                self._last_error(),
                "QueryInformationJobObject(BasicAccounting) failed",
            )
        if returned.value != self._ctypes.sizeof(information):
            raise OSError("QueryInformationJobObject returned an unexpected size")
        return int(information.ActiveProcesses)

    def wait_empty(self, timeout_seconds: float | None) -> bool:
        """Poll documented accounting until no process remains in the Job."""

        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
        while self.active_processes() != 0:
            if deadline is None:
                time.sleep(0.01)
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))
        return True

    def terminate_and_drain(self, timeout_seconds: float) -> None:
        if self.active_processes() != 0:
            self.terminate()
        if not self.wait_empty(timeout_seconds):
            raise OSError("Job Object did not drain after termination")

    def close(self) -> None:
        if getattr(self, "handle", None):
            handle = self.handle
            if not self._kernel32.CloseHandle(handle):
                raise OSError(self._last_error(), "CloseHandle(Job Object) failed")
            self.handle = None


def _admit_suspended_windows_child(
    job: _WindowsJob,
    process: subprocess.Popen[bytes],
) -> None:
    """Contain one suspended child before its first instruction."""

    job.assign(process)
    job.resume(process)


@dataclass(slots=True)
class _OwnedChild:
    process: subprocess.Popen[bytes]
    job: _WindowsJob | None = None
    output_stream: BinaryIO | None = None
    wait_lock: threading.Lock = field(default_factory=threading.Lock)

    def _posix_group_exists(self) -> bool:
        if os.name != "posix":
            return False
        try:
            os.killpg(self.process.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            # Losing signal permission does not prove an owned group empty.
            return True
        return True

    def _wait_posix_group_empty(self, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while self._posix_group_exists():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))
        return True

    def signal(self, *, force: bool = False) -> None:
        try:
            if os.name == "posix":
                # The leader may already be reaped while descendants retain
                # its process-group ID, which remains our containment handle.
                os.killpg(self.process.pid, signal.SIGKILL if force else signal.SIGTERM)
            elif self.process.poll() is not None:
                return
            elif self.job is not None:
                self.job.terminate()
            elif force:
                self.process.kill()
            else:
                self.process.terminate()
        except (OSError, ProcessLookupError):
            pass

    def drain_after_leader_exit(self, grace_seconds: float) -> bool:
        """Prove the owned tree empty and report whether descendants leaked."""

        if os.name == "nt" and self.job is not None:
            self.job.close_process_handle(self.process)
            # Job accounting may remain transiently nonzero after the leader
            # handle becomes signalled, even when its nested producer tree has
            # already drained. Give normal teardown one bounded grace period
            # before classifying anything that remains as a leak.
            if self.job.wait_empty(grace_seconds):
                return False
            self.job.terminate_and_drain(grace_seconds)
            return True

        if os.name != "posix" or not self._posix_group_exists():
            return False
        self.signal()
        if not self._wait_posix_group_empty(grace_seconds):
            self.signal(force=True)
            if not self._wait_posix_group_empty(grace_seconds):
                raise ProcessError(f"owned process group {self.process.pid} could not be drained")
        return True

    def read_output(self, limit: int) -> bytes:
        if self.output_stream is None:
            return b""
        self.output_stream.flush()
        self.output_stream.seek(0)
        return self.output_stream.read(limit + 1)

    @property
    def output_size(self) -> int:
        if self.output_stream is None:
            return 0
        return os.fstat(self.output_stream.fileno()).st_size

    def terminate_and_drain(self, grace_seconds: float, output_limit: int) -> bytes:
        with self.wait_lock:
            self.signal()
            try:
                self.process.wait(timeout=grace_seconds)
            except subprocess.TimeoutExpired:
                self.signal(force=True)
                try:
                    self.process.wait(timeout=grace_seconds)
                except subprocess.TimeoutExpired as error:
                    raise ProcessError(
                        f"owned process leader {self.process.pid} could not be reaped"
                    ) from error
            finally:
                if self.job is not None and self.process.returncode is not None:
                    self.job.close_process_handle(self.process)
                    self.job.terminate_and_drain(grace_seconds)
            if (
                os.name == "posix"
                and self._posix_group_exists()
                and not self._wait_posix_group_empty(grace_seconds)
            ):
                self.signal(force=True)
                if not self._wait_posix_group_empty(grace_seconds):
                    raise ProcessError(
                        f"owned process group {self.process.pid} could not be drained"
                    )
            return self.read_output(output_limit)

    def close_capture(self) -> None:
        if self.output_stream is not None:
            self.output_stream.close()
            self.output_stream = None


class ProcessSupervisor:
    """Own child process trees and enforce per-child deadlines."""

    def __init__(self, *, poll_interval: float = 0.05, termination_grace: float = 2.0) -> None:
        if poll_interval <= 0 or termination_grace <= 0:
            raise ValueError("process polling and termination grace must be positive")
        self.poll_interval = poll_interval
        self.termination_grace = termination_grace
        self._active: dict[int, _OwnedChild] = {}
        self._lock = threading.RLock()
        self._closed = False
        atexit.register(self.cancel_all, True)

    @property
    def active_pids(self) -> tuple[int, ...]:
        with self._lock:
            return tuple(sorted(self._active))

    @staticmethod
    def _abort_launch(
        process: subprocess.Popen[bytes] | None,
        job: _WindowsJob | None,
    ) -> None:
        """Best-effort reap of a child that never completed launch admission."""

        if process is None:
            return
        if job is not None:
            job.terminate()
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired as error:
                cleanup_failure = ProcessError(
                    f"owned process leader {process.pid} could not be reaped"
                )
                if job is not None:
                    try:
                        job.close()
                    except BaseException as close_error:
                        cleanup_failure.add_note(
                            f"kill-on-close Job fallback also failed: {close_error}"
                        )
                raise cleanup_failure from error
        if job is not None:
            job.close_process_handle(process)
            job.terminate_and_drain(2.0)

    def _spawn(
        self,
        spec: CommandSpec,
        windows_lineage_planner: WindowsLineagePlanner | None,
    ) -> _OwnedChild:
        with self._lock:
            if self._closed:
                raise ProcessError("process supervisor is closed")
        if windows_lineage_planner is not None and os.name != "nt":
            raise ProcessLaunchError("Windows lineage planning requires native Windows")
        job: _WindowsJob | None = None
        process: subprocess.Popen[bytes] | None = None
        output_stream: BinaryIO | None = None
        plan_stream: BinaryIO | None = None
        try:
            # The supervisor owns this stream until the child is forgotten.
            output_stream = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115
            if os.name == "posix":
                process = subprocess.Popen(
                    spec.argv,
                    cwd=spec.cwd,
                    env=spec.environment_mapping,
                    stdout=output_stream,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
            else:
                # Start suspended, transfer the process to its Job Object, and
                # only then permit it to create descendants.
                job = _WindowsJob()
                lineage_plan = _windows_lineage_plan(windows_lineage_planner, spec)
                if lineage_plan is None:
                    process = subprocess.Popen(
                        spec.argv,
                        cwd=spec.cwd,
                        env=spec.environment_mapping,
                        stdout=output_stream,
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL,
                        creationflags=_CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP,
                    )
                else:
                    plan_stream = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115
                    plan_stream.write(lineage_plan)
                    plan_stream.flush()
                    plan_stream.seek(0)
                    broker_environment = _windows_lineage_broker_environment(os.environ)
                    process = subprocess.Popen(
                        _windows_lineage_broker_command(),
                        cwd=Path(sys.executable).resolve(strict=True).parent,
                        env=broker_environment,
                        stdout=output_stream,
                        stderr=subprocess.STDOUT,
                        stdin=plan_stream,
                        creationflags=_CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP,
                    )
            if job is not None:
                _admit_suspended_windows_child(job, process)
            if plan_stream is not None:
                plan_stream.close()
                plan_stream = None
        except BaseException as error:
            cleanup_errors: list[BaseException] = []
            try:
                self._abort_launch(process, job)
            except BaseException as exc:
                cleanup_errors.append(exc)
            if job is not None:
                try:
                    job.close()
                except BaseException as exc:
                    cleanup_errors.append(exc)
            if output_stream is not None:
                try:
                    output_stream.close()
                except BaseException as exc:
                    cleanup_errors.append(exc)
            if plan_stream is not None:
                try:
                    plan_stream.close()
                except BaseException as exc:
                    cleanup_errors.append(exc)
            for cleanup_error in cleanup_errors:
                error.add_note(f"failed launch cleanup also failed: {cleanup_error}")
            if not isinstance(error, Exception):
                raise
            raise ProcessLaunchError(f"cannot launch {spec.argv[0]}: {error}") from error
        assert process is not None
        child = _OwnedChild(process, job, output_stream)
        with self._lock:
            closed_during_launch = self._closed
            if not closed_during_launch:
                self._active[process.pid] = child
        if closed_during_launch:
            try:
                child.terminate_and_drain(self.termination_grace, spec.output_limit)
            finally:
                self._forget(child, primary_error=sys.exception())
            raise ProcessError("process supervisor closed while launching a child")
        return child

    def _forget(
        self,
        child: _OwnedChild,
        *,
        primary_error: BaseException | None = None,
    ) -> None:
        with self._lock:
            self._active.pop(child.process.pid, None)
        cleanup_errors: list[BaseException] = []
        if child.job is not None:
            try:
                child.job.close()
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            child.close_capture()
        except BaseException as error:
            cleanup_errors.append(error)
        if not cleanup_errors:
            return
        if primary_error is not None:
            for cleanup_error in cleanup_errors:
                primary_error.add_note(f"process cleanup also failed: {cleanup_error}")
            return
        failure = ProcessError("process resource cleanup failed")
        for cleanup_error in cleanup_errors:
            failure.add_note(str(cleanup_error))
        raise failure from cleanup_errors[0]

    @staticmethod
    def _write_log(path: Path | None, output: bytes) -> None:
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(output)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _one_attempt(
        self,
        spec: CommandSpec,
        cancellation: CancellationToken,
        windows_lineage_planner: WindowsLineagePlanner | None,
    ) -> tuple[int, bytes, float]:
        cancellation.raise_if_cancelled()
        child = self._spawn(spec, windows_lineage_planner)
        started = time.monotonic()
        deadline = started + spec.timeout_seconds
        try:
            while True:
                if cancellation.cancelled:
                    output = child.terminate_and_drain(self.termination_grace, spec.output_limit)
                    self._write_log(spec.log_path, output)
                    raise ProcessCancelled(cancellation.reason, output)
                if child.output_size > spec.output_limit:
                    output = child.terminate_and_drain(self.termination_grace, spec.output_limit)
                    self._write_log(spec.log_path, output[: spec.output_limit])
                    raise ProcessOutputLimitExceeded(spec, output[: spec.output_limit])
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    output = child.terminate_and_drain(self.termination_grace, spec.output_limit)
                    self._write_log(spec.log_path, output)
                    raise ProcessTimedOut(spec, output)
                if child.process.poll() is not None:
                    break
                time.sleep(min(self.poll_interval, remaining))
            leaked = child.drain_after_leader_exit(self.termination_grace)
            output = child.read_output(spec.output_limit)
            if len(output) > spec.output_limit:
                output = output[: spec.output_limit]
                self._write_log(spec.log_path, output)
                raise ProcessOutputLimitExceeded(spec, output)
            self._write_log(spec.log_path, output)
            if leaked:
                raise ProcessTreeLeak(spec, output)
            return child.process.returncode, output, time.monotonic() - started
        except BaseException:
            if child.process.poll() is None:
                child.terminate_and_drain(self.termination_grace, spec.output_limit)
            raise
        finally:
            self._forget(child, primary_error=sys.exception())

    def run(
        self,
        spec: CommandSpec,
        *,
        cancellation: CancellationToken | None = None,
        retry_policy: RetryPolicy | None = None,
        windows_lineage_planner: WindowsLineagePlanner | None = None,
        check: bool = True,
    ) -> ProcessResult:
        token = cancellation or CancellationToken()
        policy = retry_policy or RetryPolicy()
        total_started = time.monotonic()
        attempt = 1
        while True:
            token.raise_if_cancelled()
            try:
                returncode, output, _ = self._one_attempt(
                    spec,
                    token,
                    windows_lineage_planner,
                )
            except ProcessLaunchError:
                if not policy.retry_launch_errors or attempt >= policy.max_attempts:
                    raise
                attempt += 1
                continue
            result = ProcessResult(
                spec.argv,
                returncode,
                output,
                attempt,
                time.monotonic() - total_started,
            )
            if returncode == 0 or not policy.permits(returncode, attempt):
                if check and returncode != 0:
                    raise CommandFailed(result, spec)
                return result
            attempt += 1

    def cancel_all(self, force: bool = False) -> None:
        """Signal active trees; their owner threads remain responsible for waiting."""

        with self._lock:
            children = tuple(self._active.values())
        for child in children:
            child.signal(force=force)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            children = tuple(self._active.values())
        for child in children:
            child.signal()
        atexit.unregister(self.cancel_all)

    def __enter__(self) -> ProcessSupervisor:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


def fail(message: str) -> NoReturn:
    """Raise a process-layer error; useful for command adapters."""

    raise ProcessError(message)


__all__ = [
    "CancellationToken",
    "CommandFailed",
    "CommandSpec",
    "ProcessCancelled",
    "ProcessError",
    "ProcessLaunchError",
    "ProcessOutputLimitExceeded",
    "ProcessResult",
    "ProcessSupervisor",
    "ProcessTimedOut",
    "ProcessTreeLeak",
    "RetryPolicy",
    "WindowsLineagePlanner",
]
