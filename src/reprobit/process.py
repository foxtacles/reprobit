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
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, NoReturn


class ProcessError(RuntimeError):
    """Base error for supervised command execution."""


class ProcessLaunchError(ProcessError):
    """A child could not be created."""


SuspendedProcessInitializer = Callable[[int], None]


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
        self._kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self._kernel32.TerminateJobObject.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._ntdll = win_dll("ntdll", use_last_error=True)
        self._ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
        self._ntdll.NtResumeProcess.restype = ctypes.c_long

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
        if self.handle:
            self._kernel32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        if getattr(self, "handle", None):
            self._kernel32.CloseHandle(self.handle)
            self.handle = None


def _admit_suspended_windows_child(
    job: _WindowsJob,
    process: subprocess.Popen[bytes],
    initializer: SuspendedProcessInitializer | None,
) -> None:
    """Contain and initialize one suspended child before its first instruction."""

    job.assign(process)
    if initializer is not None:
        initializer(job.process_handle(process))
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
        """Prove a POSIX group empty and report whether descendants leaked."""

        if os.name != "posix" or not self._posix_group_exists():
            return False
        self.signal()
        if not self._wait_posix_group_empty(grace_seconds):
            self.signal(force=True)
            if not self._wait_posix_group_empty(grace_seconds):
                raise ProcessError(
                    f"owned process group {self.process.pid} could not be drained"
                )
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
                self.process.wait()
            finally:
                if self.job is not None:
                    self.job.close()
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
            process.wait()

    def _spawn(
        self,
        spec: CommandSpec,
        suspended_process_initializer: SuspendedProcessInitializer | None,
    ) -> _OwnedChild:
        with self._lock:
            if self._closed:
                raise ProcessError("process supervisor is closed")
        if suspended_process_initializer is not None and os.name != "nt":
            raise ProcessLaunchError(
                "suspended-process initialization requires native Windows"
            )
        job: _WindowsJob | None = None
        process: subprocess.Popen[bytes] | None = None
        output_stream: BinaryIO | None = None
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
                process = subprocess.Popen(
                    spec.argv,
                    cwd=spec.cwd,
                    env=spec.environment_mapping,
                    stdout=output_stream,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=0x00000004 | 0x00000200,
                )
            if job is not None:
                _admit_suspended_windows_child(
                    job,
                    process,
                    suspended_process_initializer,
                )
        except BaseException as error:
            cleanup_error: BaseException | None = None
            try:
                self._abort_launch(process, job)
            except BaseException as exc:
                cleanup_error = exc
            if job is not None:
                job.close()
            if output_stream is not None:
                output_stream.close()
            if cleanup_error is not None:
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
            child.terminate_and_drain(self.termination_grace, spec.output_limit)
            child.close_capture()
            raise ProcessError("process supervisor closed while launching a child")
        return child

    def _forget(self, child: _OwnedChild) -> None:
        with self._lock:
            self._active.pop(child.process.pid, None)
        if child.job is not None:
            child.job.close()
        child.close_capture()

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
        suspended_process_initializer: SuspendedProcessInitializer | None,
    ) -> tuple[int, bytes, float]:
        cancellation.raise_if_cancelled()
        child = self._spawn(spec, suspended_process_initializer)
        started = time.monotonic()
        deadline = started + spec.timeout_seconds
        try:
            while True:
                if cancellation.cancelled:
                    output = child.terminate_and_drain(
                        self.termination_grace, spec.output_limit
                    )
                    self._write_log(spec.log_path, output)
                    raise ProcessCancelled(cancellation.reason, output)
                if child.output_size > spec.output_limit:
                    output = child.terminate_and_drain(
                        self.termination_grace, spec.output_limit
                    )
                    self._write_log(spec.log_path, output[: spec.output_limit])
                    raise ProcessOutputLimitExceeded(
                        spec, output[: spec.output_limit]
                    )
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    output = child.terminate_and_drain(
                        self.termination_grace, spec.output_limit
                    )
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
            self._forget(child)

    def run(
        self,
        spec: CommandSpec,
        *,
        cancellation: CancellationToken | None = None,
        retry_policy: RetryPolicy | None = None,
        suspended_process_initializer: SuspendedProcessInitializer | None = None,
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
                    suspended_process_initializer,
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
    "SuspendedProcessInitializer",
]
