"""Deterministic dependency scheduling over private task workspaces."""

from __future__ import annotations

import hashlib
import heapq
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

from reprobit.dag_queue import DependencyQueue
from reprobit.process import (
    CancellationToken,
    CommandSpec,
    ProcessCancelled,
    ProcessResult,
    ProcessSupervisor,
    RetryPolicy,
)


class SchedulerError(RuntimeError):
    """One or more tasks failed, or the task graph is invalid."""

    def __init__(
        self,
        message: str,
        *,
        failures: Mapping[str, BaseException] | None = None,
        completed: Mapping[str, TaskResult] | None = None,
        skipped: Iterable[str] = (),
    ) -> None:
        super().__init__(message)
        self.failures = MappingProxyType(dict(failures or {}))
        self.completed = MappingProxyType(dict(completed or {}))
        self.skipped = tuple(sorted(skipped))


@dataclass(frozen=True, slots=True)
class TaskWorkspace:
    root: Path
    objects: Path
    pdb: Path
    temporary: Path
    logs: Path

    @classmethod
    def create(cls, run_root: Path, task_id: str) -> TaskWorkspace:
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", task_id).strip(".-")[:48] or "task"
        digest = hashlib.sha256(task_id.encode("utf-8")).hexdigest()[:12]
        root = run_root / f"{slug}-{digest}"
        try:
            root.mkdir(parents=True, exist_ok=False)
        except FileExistsError as error:
            raise SchedulerError(f"task workspace already exists: {root}") from error
        workspace = cls(
            root=root,
            objects=root / "objects",
            pdb=root / "pdb",
            temporary=root / "tmp",
            logs=root / "logs",
        )
        for directory in (
            workspace.objects,
            workspace.pdb,
            workspace.temporary,
            workspace.logs,
        ):
            directory.mkdir()
        return workspace

    @property
    def environment(self) -> dict[str, str]:
        return {
            "REPROBIT_TASK_ROOT": str(self.root),
            "REPROBIT_OBJECT_DIR": str(self.objects),
            "REPROBIT_PDB_DIR": str(self.pdb),
            "REPROBIT_TEMP_DIR": str(self.temporary),
        }


CommandFactory = Callable[[TaskWorkspace], CommandSpec]


@dataclass(frozen=True, slots=True)
class TaskSpec:
    task_id: str
    command: CommandSpec | CommandFactory
    dependencies: tuple[str, ...] = ()
    resource_class: str = "default"
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    inject_workspace_environment: bool = True

    def __post_init__(self) -> None:
        if (
            not isinstance(self.task_id, str)
            or not self.task_id
            or "\0" in self.task_id
            or len(self.task_id) > 256
        ):
            raise ValueError("task ID must be a bounded NUL-free string")
        dependencies = tuple(self.dependencies)
        if self.task_id in dependencies:
            raise ValueError(f"task {self.task_id!r} depends on itself")
        if len(set(dependencies)) != len(dependencies):
            raise ValueError(f"task {self.task_id!r} repeats a dependency")
        if any(not isinstance(item, str) or not item or "\0" in item for item in dependencies):
            raise ValueError("task dependencies must be non-empty NUL-free strings")
        object.__setattr__(self, "dependencies", dependencies)
        if not self.resource_class or "\0" in self.resource_class:
            raise ValueError("resource class must be a non-empty NUL-free string")

    def resolve_command(self, workspace: TaskWorkspace) -> CommandSpec:
        command = self.command(workspace) if callable(self.command) else self.command
        if not isinstance(command, CommandSpec):
            raise TypeError(f"task {self.task_id!r} did not produce a CommandSpec")
        return (
            command.with_environment(workspace.environment)
            if self.inject_workspace_environment
            else command
        )


@dataclass(frozen=True, slots=True)
class TaskResult:
    task_id: str
    workspace: TaskWorkspace
    process: ProcessResult


class TaskScheduler:
    """Run a finite DAG with stable ordering and resource ceilings."""

    def __init__(
        self,
        *,
        run_root: Path | str,
        max_workers: int,
        supervisor: ProcessSupervisor | None = None,
        resource_limits: Mapping[str, int] | None = None,
    ) -> None:
        if not isinstance(max_workers, int) or isinstance(max_workers, bool) or max_workers <= 0:
            raise ValueError("max_workers must be a positive integer")
        self.run_root = Path(run_root)
        if not self.run_root.is_absolute():
            raise ValueError("scheduler run root must be absolute")
        self.max_workers = max_workers
        self.supervisor = supervisor or ProcessSupervisor()
        self._owns_supervisor = supervisor is None
        limits = dict(resource_limits or {})
        for name, limit in limits.items():
            if not name or not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
                raise ValueError("resource limits must be named positive integers")
        self.resource_limits = MappingProxyType(limits)
        self._run_lock = threading.Lock()
        self._has_run = False

    @staticmethod
    def _validate(tasks: Iterable[TaskSpec]) -> dict[str, TaskSpec]:
        by_id: dict[str, TaskSpec] = {}
        for task in tasks:
            if task.task_id in by_id:
                raise SchedulerError(f"duplicate task ID: {task.task_id}")
            by_id[task.task_id] = task
        for task in by_id.values():
            missing = set(task.dependencies) - set(by_id)
            if missing:
                raise SchedulerError(
                    f"task {task.task_id!r} has unknown dependencies: {sorted(missing)}"
                )
        try:
            DependencyQueue({task.task_id: task.dependencies for task in by_id.values()})
        except ValueError as exc:
            raise SchedulerError(str(exc)) from exc
        return by_id

    def _run_task(
        self,
        task: TaskSpec,
        token: CancellationToken,
    ) -> TaskResult:
        token.raise_if_cancelled()
        workspace = TaskWorkspace.create(self.run_root, task.task_id)
        command = task.resolve_command(workspace)
        result = self.supervisor.run(
            command,
            cancellation=token,
            retry_policy=task.retry_policy,
        )
        return TaskResult(task.task_id, workspace, result)

    def run(self, tasks: Iterable[TaskSpec]) -> Mapping[str, TaskResult]:
        with self._run_lock:
            if self._has_run:
                raise SchedulerError("a task scheduler instance is single-use")
            self._has_run = True
        by_id = self._validate(tasks)
        if not by_id:
            return MappingProxyType({})
        self.run_root.mkdir(parents=True, exist_ok=True)
        token = CancellationToken()
        pending = set(by_id)
        queue = DependencyQueue({task.task_id: task.dependencies for task in by_id.values()})
        ready: list[str] = []
        completed: dict[str, TaskResult] = {}
        failures: dict[str, BaseException] = {}
        running: dict[Future[TaskResult], TaskSpec] = {}
        active_resources: dict[str, int] = {}

        def capacity(task: TaskSpec) -> bool:
            limit = self.resource_limits.get(task.resource_class, self.max_workers)
            return active_resources.get(task.resource_class, 0) < limit

        with ThreadPoolExecutor(
            max_workers=self.max_workers, thread_name_prefix="reprobit"
        ) as pool:
            while pending or running:
                if not failures:
                    for task_id in queue.take_ready(len(by_id)):
                        heapq.heappush(ready, task_id)
                    deferred: list[str] = []
                    while ready and len(running) < self.max_workers:
                        task_id = heapq.heappop(ready)
                        task = by_id[task_id]
                        if not capacity(task):
                            deferred.append(task_id)
                            continue
                        pending.remove(task.task_id)
                        active_resources[task.resource_class] = (
                            active_resources.get(task.resource_class, 0) + 1
                        )
                        running[pool.submit(self._run_task, task, token)] = task
                    for task_id in deferred:
                        heapq.heappush(ready, task_id)
                if not running:
                    break
                finished, _ = wait(tuple(running), return_when=FIRST_COMPLETED)
                for future in sorted(finished, key=lambda item: running[item].task_id):
                    task = running.pop(future)
                    active_resources[task.resource_class] -= 1
                    try:
                        completed[task.task_id] = future.result()
                        queue.finish(task.task_id)
                    except BaseException as error:
                        failures[task.task_id] = error
                        token.cancel(f"task {task.task_id!r} failed")
                if failures:
                    # Active owners observe the shared token and drain their trees.
                    continue

        # Cancellation exceptions from sibling tasks are useful evidence but
        # the initiating failure remains the primary scheduler failure.
        substantive = {
            task_id: error
            for task_id, error in failures.items()
            if not isinstance(error, ProcessCancelled)
        }
        if failures:
            primary = sorted(substantive or failures)[0]
            raise SchedulerError(
                f"task graph failed at {primary!r}: {(substantive or failures)[primary]}",
                failures=failures,
                completed=completed,
                skipped=pending,
            )
        if pending:
            raise SchedulerError(
                "task graph made no progress",
                completed=completed,
                skipped=pending,
            )
        return MappingProxyType(dict(sorted(completed.items())))

    def close(self) -> None:
        if self._owns_supervisor:
            self.supervisor.close()

    def __enter__(self) -> TaskScheduler:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


__all__ = [
    "CommandFactory",
    "SchedulerError",
    "TaskResult",
    "TaskScheduler",
    "TaskSpec",
    "TaskWorkspace",
]
