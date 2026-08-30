"""Execution environment, process, and lane infrastructure for classic builds."""

from __future__ import annotations

import os
import shlex
import shutil
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from threading import Condition, Lock
from types import MappingProxyType

from reprobit.assets import runtime_asset_path
from reprobit.backends import (
    ExecutionBackend,
    NativeWindowsBackend,
    PosixWineBackend,
    WorkerSandbox,
)
from reprobit.classic_project import ClassicProjectError
from reprobit.classic_runtime_files import _digest_path
from reprobit.model import Digest
from reprobit.native_device_map import NativeDeviceMapLease
from reprobit.paths import (
    MaterializedSkeleton,
    logical_relative_to,
    normalize_logical_path,
)
from reprobit.process import (
    CancellationToken,
    CommandSpec,
    ProcessResult,
    ProcessSupervisor,
    WindowsLineagePlanner,
)
from reprobit.producer_graph import ProducerRole
from reprobit.schema import ProjectBundle
from reprobit.strict_json import canonical_json
from reprobit.toolchains import ClassicMSVCToolchain
from reprobit.toolchains import profile as toolchain_profile


@dataclass(frozen=True, slots=True)
class _ExecutionLane:
    """One producer environment and its optional Windows lineage plan."""

    id: str
    environment: Mapping[str, str]
    worker: WorkerSandbox
    windows_lineage_planner: WindowsLineagePlanner | None = None


class _LazyExecutionLanePool:
    """Grow producer scheduling lanes only when concurrent work needs them.

    Constructing a prepared run is metadata-only with respect to the backend:
    no Wine prefix, wineserver, or native logical-drive binding exists until a
    producer actually acquires a lane. Concurrent lanes share that one
    run-private backend namespace while keeping independently owned producer
    process trees.
    """

    def __init__(
        self,
        *,
        maximum: int,
        create: Callable[[int], _ExecutionLane],
        close_created: Callable[[], None],
        compiler_environment_digest: Digest,
    ) -> None:
        if maximum < 1:
            raise ClassicProjectError("classic execution requires at least one lane")
        self.maximum = maximum
        self.compiler_environment_digest = compiler_environment_digest
        self._create = create
        self._close_created = close_created
        self._condition = Condition()
        self._available: list[_ExecutionLane] = []
        self._all: list[_ExecutionLane] = []
        self._borrowed: set[int] = set()
        self._creating = 0
        self._next_index = 0
        self._failure: BaseException | None = None
        self._closing = False
        self._closed = False

    @property
    def created_count(self) -> int:
        with self._condition:
            return len(self._all)

    @property
    def lanes(self) -> tuple[_ExecutionLane, ...]:
        with self._condition:
            return tuple(self._all)

    def acquire(self) -> _ExecutionLane:
        index: int | None = None
        with self._condition:
            while index is None:
                if self._closed or self._closing:
                    raise ClassicProjectError("classic execution lane pool is closed")
                if self._failure is not None:
                    raise ClassicProjectError(
                        "classic execution lane initialization previously failed"
                    ) from self._failure
                if self._available:
                    lane = self._available.pop()
                    self._borrowed.add(id(lane))
                    return lane
                if len(self._all) + self._creating < self.maximum:
                    index = self._next_index
                    self._next_index += 1
                    self._creating += 1
                    break
                self._condition.wait()
        try:
            lane = self._create(index)
            received_digest = _compiler_environment_digest(lane.environment)
            if received_digest != self.compiler_environment_digest:
                raise ClassicProjectError(
                    "classic compiler lane exposes a different frontend environment"
                )
        except BaseException as exc:
            with self._condition:
                self._creating -= 1
                if self._failure is None:
                    self._failure = exc
                self._condition.notify_all()
            raise
        with self._condition:
            self._creating -= 1
            self._all.append(lane)
            if self._closing or self._closed or self._failure is not None:
                self._condition.notify_all()
                raise ClassicProjectError(
                    "classic execution lane pool closed during initialization"
                )
            self._borrowed.add(id(lane))
            self._condition.notify_all()
            return lane

    def release(self, lane: _ExecutionLane) -> None:
        with self._condition:
            if not any(item is lane for item in self._all) or id(lane) not in self._borrowed:
                raise ClassicProjectError("classic execution returned an unknown lane")
            self._borrowed.remove(id(lane))
            if not self._closing and not self._closed and self._failure is None:
                self._available.append(lane)
            self._condition.notify_all()

    def close(self) -> None:
        with self._condition:
            if self._closed:
                return
            self._closing = True
            if self._borrowed or self._creating:
                self._closing = False
                raise ClassicProjectError(
                    "classic execution lane pool closed while lanes were active"
                )
            self._closed = True
            self._available.clear()
            self._condition.notify_all()
        self._close_created()


@dataclass(frozen=True, slots=True)
class _DirectLogicalWorkspace:
    """Run-private source/build/toolchain seats for a committed producer graph."""

    root: Path
    drive_letter: str
    effective_root: Path
    build_root: Path
    toolchain_entry: Path
    materialized: MaterializedSkeleton


def _logical_relative_parts(value: str, *, drive_letter: str) -> tuple[str, ...]:
    normalized = normalize_logical_path(value)
    path = PureWindowsPath(normalized)
    if path.drive.rstrip(":").upper() != drive_letter:
        raise ClassicProjectError(f"logical path {value!r} is outside drive {drive_letter}:")
    return tuple(path.parts[1:])


def _logical_join(root: str, relative: str) -> str:
    suffix = "\\".join(PurePosixPath(relative).parts)
    return normalize_logical_path(root.rstrip("\\") + "\\" + suffix)


_CLASSIC_TOOLCHAIN_ENVIRONMENT_VARIABLES = ("PATH", "INCLUDE", "LIB", "LIBPATH")
_CLASSIC_TEMPORARY_PROFILE = PureWindowsPath(
    "Users",
    "reprobit",
    "AppData",
    "Local",
    "Temp",
)


def _classic_temporary_directory(logical_path: str) -> str:
    """Return the canonical compiler-visible temporary directory."""

    canonical = normalize_logical_path(logical_path)
    drive = PureWindowsPath(canonical).drive
    if not drive:
        raise ClassicProjectError("classic temporary directory requires a logical drive")
    return normalize_logical_path(str(PureWindowsPath(drive + "\\", _CLASSIC_TEMPORARY_PROFILE)))


def _materialize_dos_directory(root: Path, parts: Sequence[str]) -> Path:
    """Create one directory path without POSIX/DOS case aliases."""

    current = root
    for part in parts:
        matches = tuple(
            child for child in current.iterdir() if child.name.casefold() == part.casefold()
        )
        if len(matches) > 1:
            raise ClassicProjectError("classic logical drive contains a DOS-case collision")
        if matches:
            child = matches[0]
            metadata = child.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or int(getattr(metadata, "st_file_attributes", 0)) & 0x400
            ):
                raise ClassicProjectError(
                    "classic temporary directory ancestor is redirected or not a directory"
                )
        else:
            child = current / part
            child.mkdir()
        current = child
    return current


def _rooted_toolchain_environment(
    environment: Mapping[str, str],
    *,
    logical_toolchain_root: str,
) -> dict[str, str]:
    """Render the rooted path spelling in the classic producer contract."""

    root = normalize_logical_path(logical_toolchain_root)
    rendered = dict(environment)
    folded = [key.casefold() for key in rendered]
    if len(folded) != len(set(folded)):
        raise ClassicProjectError("classic environment repeats a case-insensitive key")
    keys = {key.casefold(): key for key in rendered}
    for name in _CLASSIC_TOOLCHAIN_ENVIRONMENT_VARIABLES:
        key = keys.get(name.casefold())
        if key is None:
            raise ClassicProjectError(f"classic producer environment lacks one {name}")
        parts = tuple(rendered[key].split(";"))
        if not parts or any(not item for item in parts):
            raise ClassicProjectError(f"classic producer environment {name} is malformed")
        rooted: list[str] = []
        for item in parts:
            try:
                canonical = normalize_logical_path(item)
                if canonical != item:
                    raise ValueError("path presentation is not canonical")
                logical_relative_to(canonical, root)
            except Exception as exc:
                raise ClassicProjectError(
                    f"classic producer environment {name} leaves the toolchain root"
                ) from exc
            rooted.append(canonical[2:])
        rendered[key] = ";".join(rooted)
    return rendered


def _classic_producer_environment(
    installation: ClassicMSVCToolchain,
    *,
    temp_directory: str,
) -> dict[str, str]:
    environment = installation.default_environment(temp_directory=temp_directory)
    environment["LIBPATH"] = environment["LIB"]
    return _rooted_toolchain_environment(
        environment,
        logical_toolchain_root=installation.logical_root,
    )


def _compiler_environment_path_material(value: str) -> dict[str, str]:
    if value.startswith("\\") and not value.startswith("\\\\"):
        canonical = normalize_logical_path("Z:" + value)
        if canonical[2:] != value:
            raise ValueError("rooted path presentation is not canonical")
        return {
            "kind": "rooted-no-drive",
            "presentation": value,
        }
    canonical = normalize_logical_path(value)
    if canonical != value:
        raise ValueError("drive-absolute path presentation is not canonical")
    return {
        "kind": "drive-absolute",
        "presentation": value,
    }


def _compiler_environment_digest(environment: Mapping[str, str]) -> Digest:
    """Validate and bind exact frontend-visible toolchain path presentations."""

    variables: dict[str, tuple[dict[str, str], ...]] = {}
    for name in ("INCLUDE", "LIB", "LIBPATH", "TEMP", "TMP", "WINEPATH"):
        matches = [value for key, value in environment.items() if key.casefold() == name.casefold()]
        if len(matches) > 1 or (name != "WINEPATH" and len(matches) != 1):
            raise ClassicProjectError(f"compiler environment does not uniquely bind {name}")
        if not matches:
            variables[name] = ()
            continue
        parts = tuple(matches[0].split(";"))
        if not parts or any(not item for item in parts):
            raise ClassicProjectError(f"compiler environment {name} is malformed")
        try:
            variables[name] = tuple(_compiler_environment_path_material(item) for item in parts)
        except Exception as exc:
            raise ClassicProjectError(
                f"compiler environment {name} leaves the logical path profile"
            ) from exc
    if variables["TEMP"] != variables["TMP"]:
        raise ClassicProjectError("compiler environment TEMP/TMP presentations differ")
    override_matches = [
        value for key, value in environment.items() if key.casefold() == "winedlloverrides"
    ]
    if len(override_matches) > 1 or any(not value or "\0" in value for value in override_matches):
        raise ClassicProjectError("compiler environment does not uniquely bind DLL overrides")
    return Digest.from_bytes(
        canonical_json(
            {
                "schema": 4,
                "dll_overrides": override_matches[0] if override_matches else None,
                "variables": {name: list(values) for name, values in variables.items()},
            }
        )
    )


def _materialize_direct_logical_workspace(
    bundle: ProjectBundle,
    *,
    session_root: Path,
    toolchain_root: Path,
) -> _DirectLogicalWorkspace:
    """Materialize only seats named by the committed producer graph.

    Runtime authenticity never runs project CMake, so no host CMake runtime or
    probe tree is projected into the producer-visible drive.
    """

    declared = tuple(
        normalize_logical_path(value)
        for value in (
            bundle.spec.paths.source,
            bundle.spec.paths.build,
            bundle.spec.paths.toolchain,
        )
    )
    drives = {PureWindowsPath(value).drive.rstrip(":").upper() for value in declared}
    if len(drives) != 1:
        raise ClassicProjectError("classic logical seats must share one DOS drive")
    drive_letter = drives.pop()
    seats = (*declared, _classic_temporary_directory(declared[0]))
    folded = tuple(value.casefold().rstrip("\\") for value in seats)
    for index, left in enumerate(folded):
        for right in folded[index + 1 :]:
            if left == right or left.startswith(right + "\\") or right.startswith(left + "\\"):
                raise ClassicProjectError("classic logical seats overlap")
    root = session_root / "logical-drive"

    def host_path(logical: str) -> Path:
        return root.joinpath(*_logical_relative_parts(logical, drive_letter=drive_letter))

    # The direct executor projects the finite locked toolchain closure into
    # this real drive tree below.  Mapping the caller's entire installation
    # would expose unpinned siblings to producer/source-controlled paths.
    toolchain_root.resolve(strict=True)
    root.mkdir(parents=True, exist_ok=False)
    effective_root = host_path(declared[0])
    build_root = host_path(declared[1])
    toolchain_entry = host_path(declared[2])
    build_root.mkdir(parents=True, exist_ok=False)
    materialized = MaterializedSkeleton(root.resolve(strict=True), drive_letter, ())
    return _DirectLogicalWorkspace(
        root=root,
        drive_letter=drive_letter,
        effective_root=effective_root,
        build_root=build_root,
        toolchain_entry=toolchain_entry,
        materialized=materialized,
    )


def _project_locked_toolchain(
    bundle: ProjectBundle,
    *,
    source_root: Path,
    destination: Path,
) -> tuple[Path, ...]:
    """Copy only lock-admitted producer/runtime/tree files into the DOS seat."""

    source_root = source_root.resolve(strict=True)
    if destination.exists():
        raise ClassicProjectError("locked toolchain projection destination already exists")
    destination.mkdir(parents=True)
    relatives: set[PurePosixPath] = {
        PurePosixPath(item.path)
        for item in (
            *bundle.toolchain_lock.tools,
            *bundle.toolchain_lock.runtime_files,
        )
    }
    for tree in bundle.toolchain_lock.input_trees:
        relative_root = PurePosixPath(tree.path)
        physical_root = source_root.joinpath(*relative_root.parts)
        if physical_root.is_symlink() or not physical_root.is_dir():
            raise ClassicProjectError(
                f"locked toolchain input tree is absent or redirected: {tree.path!r}"
            )
        for child in physical_root.rglob("*"):
            if child.is_symlink():
                raise ClassicProjectError(
                    f"locked toolchain input tree contains a symlink: {child}"
                )
            if child.is_file():
                relatives.add(relative_root / child.relative_to(physical_root).as_posix())
    folded = [relative.as_posix().casefold() for relative in relatives]
    if len(folded) != len(set(folded)):
        raise ClassicProjectError("locked toolchain closure has DOS-case collisions")
    originals: list[Path] = []
    for relative in sorted(relatives, key=lambda item: item.as_posix().casefold()):
        source = source_root.joinpath(*relative.parts)
        if source.is_symlink() or not source.is_file():
            raise ClassicProjectError(
                f"locked toolchain file is absent or redirected: {relative.as_posix()!r}"
            )
        target = destination.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(stat.S_IMODE(source.stat().st_mode))
        if target.is_symlink() or _digest_path(target) != _digest_path(source):
            raise ClassicProjectError(
                f"locked toolchain projection differs: {relative.as_posix()!r}"
            )
        originals.append(source.resolve(strict=True))
    return tuple(originals)


def _install_path_proxies(
    session_root: Path,
) -> tuple[Mapping[str, Path], Path]:
    template = runtime_asset_path("ReproBitPathProxy.sh")
    if template.is_symlink() or not template.is_file():
        raise ClassicProjectError("classic path-proxy template is absent or redirected")
    proxy_root = session_root / "path-proxies"
    proxy_root.mkdir()
    proxies: dict[str, Path] = {}
    for name in ("cl", "rc", "link", "lib"):
        destination = proxy_root / name
        shutil.copyfile(template, destination)
        destination.chmod(stat.S_IRUSR | stat.S_IXUSR)
        proxies[name] = destination
    return MappingProxyType(proxies), template


def _install_pinned_wine_alias(session_root: Path, wine: Path) -> Path:
    """Give an opaque transport's ``command -v wine`` one exact pinned result."""

    wine = wine.resolve(strict=True)
    if wine.is_symlink() or not wine.is_file():
        raise ClassicProjectError("pinned Wine executable is absent or redirected")
    alias_root = session_root / "host-tool-aliases"
    alias_root.mkdir(exist_ok=False)
    alias = alias_root / "wine"
    alias.write_text(
        "#!/bin/sh\nexec " + shlex.quote(str(wine)) + ' "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    alias.chmod(stat.S_IRUSR | stat.S_IXUSR)
    return alias.resolve(strict=True)


def _close_unbound_wine_worker(backend: PosixWineBackend, worker: WorkerSandbox) -> None:
    """Reap one initialized worker that never reached logical-drive binding."""

    try:
        backend.terminate_worker_server(worker)
    finally:
        backend.scrub_worker_drive_mappings(worker)


def _prepare_execution_lanes(
    bundle: ProjectBundle,
    *,
    installation: ClassicMSVCToolchain,
    backend: ExecutionBackend,
    logical_workspace: _DirectLogicalWorkspace,
    session_root: Path,
    role_commands: Mapping[ProducerRole, Path],
    host_programs: Sequence[Path],
    frontend_environment: Mapping[str, str],
    jobs: int,
    initialization_timeout: float,
    cleanup_timeout: float,
    wine_alias: Path | None,
) -> _LazyExecutionLanePool:
    """Describe a lazy producer-lane pool without initializing its backend."""

    if jobs < 1 or min(initialization_timeout, cleanup_timeout) <= 0:
        raise ClassicProjectError("classic execution lane limits must be positive")
    # Runtime-authority files trust and seal their containing-directory anchor;
    # paths above it are identity-held but deliberately ignore unrelated
    # sibling churn.  Create the lazy worker container before any namespace
    # lease is acquired so a lane never mutates an ancestor of a readable
    # session authority after that authority has been sealed.
    backend_workers_root = session_root / "backend-workers"
    backend_workers_root.mkdir(exist_ok=False)
    logical_temporary = _classic_temporary_directory(bundle.spec.paths.build)
    _materialize_dos_directory(
        logical_workspace.root,
        _logical_relative_parts(
            logical_temporary,
            drive_letter=logical_workspace.drive_letter,
        ),
    )
    binding_lock = Lock()
    runtime_binding: tuple[WorkerSandbox, ExitStack] | None = None
    # MSVC 4.2 derives temporary names from the Windows thread id.  One
    # run-private wineserver gives concurrent lanes one PID/TID namespace,
    # just like native Windows, so the canonical shared TEMP remains safe.
    wine_worker: WorkerSandbox | None = None
    wine_initialization_failure: BaseException | None = None
    native_worker: WorkerSandbox | None = None
    native_lineage_planner: WindowsLineagePlanner | None = None

    def producer_environment() -> dict[str, str]:
        return _classic_producer_environment(
            installation,
            temp_directory=logical_temporary,
        )

    digest_environment = producer_environment()
    if isinstance(backend, PosixWineBackend):
        path_values = [
            value for key, value in digest_environment.items() if key.casefold() == "path"
        ]
        if len(path_values) != 1:
            raise ClassicProjectError("classic Wine environment lacks one PATH")
        digest_environment["WINEPATH"] = path_values[0]
        overrides = ";".join(
            f"{library}={mode}" for library, mode in installation.profile.wine_dll_overrides
        )
        if overrides:
            digest_environment["WINEDLLOVERRIDES"] = overrides
    compiler_environment_digest = _compiler_environment_digest(digest_environment)

    def bind_worker(
        worker: WorkerSandbox,
    ) -> tuple[ExitStack, WindowsLineagePlanner | None]:
        stack = ExitStack()
        try:
            binding = stack.enter_context(
                backend.bind_skeleton(worker, logical_workspace.materialized)
            )
            if isinstance(backend, PosixWineBackend):
                backend.verify_worker_drive_mappings(
                    worker, logical_drive=logical_workspace.drive_letter
                )
            lineage_planner: WindowsLineagePlanner | None = None
            if isinstance(backend, NativeWindowsBackend):
                if not isinstance(binding, NativeDeviceMapLease):
                    raise ClassicProjectError(
                        "native Windows backend returned an unrecognized logical-drive lease"
                    )
                lineage_planner = binding
            return stack, lineage_planner
        except BaseException:
            stack.close()
            raise

    def initialize_wine_runtime() -> WorkerSandbox:
        nonlocal runtime_binding
        nonlocal wine_initialization_failure, wine_worker
        if not isinstance(backend, PosixWineBackend):
            raise ClassicProjectError("classic Wine runtime requires the POSIX backend")
        wine_backend = backend
        with binding_lock:
            if wine_initialization_failure is not None:
                raise ClassicProjectError(
                    "classic Wine runtime initialization previously failed"
                ) from wine_initialization_failure
            if wine_worker is not None:
                return wine_worker
            candidate = wine_backend.create_worker(backend_workers_root, "producer-graph")
            stack: ExitStack | None = None
            prefix_initialized = False
            try:
                wine_backend.initialize_worker_prefix(
                    candidate,
                    timeout_seconds=min(initialization_timeout, 300),
                )
                prefix_initialized = True
                stack, lineage_planner = bind_worker(candidate)
                if lineage_planner is not None:
                    raise ClassicProjectError(
                        "POSIX backend unexpectedly returned a Windows lineage planner"
                    )
                wine_backend.configure_worker_temporary_environment(
                    candidate,
                    temporary=logical_temporary,
                    timeout_seconds=min(initialization_timeout, 30),
                )
                wine_backend.verify_worker_drive_mappings(
                    candidate,
                    logical_drive=logical_workspace.drive_letter,
                )
            except BaseException as original:
                wine_initialization_failure = original
                cleanup_error: BaseException | None = None
                try:
                    if stack is not None:
                        _close_backend_runtime(
                            wine_backend,
                            candidate,
                            stack,
                            logical_drive=logical_workspace.drive_letter,
                            timeout_seconds=cleanup_timeout,
                        )
                    elif prefix_initialized:
                        _close_unbound_wine_worker(wine_backend, candidate)
                except BaseException as exc:
                    cleanup_error = exc
                if cleanup_error is not None:
                    original.add_note(
                        f"classic Wine runtime initialization cleanup also failed: {cleanup_error}"
                    )
                raise
            assert stack is not None
            wine_worker = candidate
            runtime_binding = (candidate, stack)
            return candidate

    def create(index: int) -> _ExecutionLane:
        nonlocal native_lineage_planner, native_worker
        nonlocal runtime_binding
        lane_id = f"lane-{index:04d}"
        worker: WorkerSandbox
        if isinstance(backend, PosixWineBackend):
            worker = initialize_wine_runtime()
        else:
            with binding_lock:
                if native_worker is None:
                    candidate = backend.create_worker(backend_workers_root, "producer-graph")
                    candidate_stack, candidate_planner = bind_worker(candidate)
                    if isinstance(backend, NativeWindowsBackend) and (candidate_planner is None):
                        raise ClassicProjectError(
                            "native Windows lane lacks a fresh-LUID lineage planner"
                        )
                    native_worker = candidate
                    native_lineage_planner = candidate_planner
                    runtime_binding = (candidate, candidate_stack)
                worker = native_worker

        windows_environment = producer_environment()
        environment = _host_environment((*host_programs, *role_commands.values()))
        if isinstance(backend, PosixWineBackend):
            environment.update(
                backend.worker_environment(
                    worker,
                    windows_environment=windows_environment,
                    dll_overrides=installation.profile.wine_dll_overrides,
                )
            )
            environment.update(
                {
                    **frontend_environment,
                    "REPROBIT_PHYSICAL_DRIVE_ROOT": str(logical_workspace.root),
                    "REPROBIT_LOGICAL_DRIVE_ROOT": (f"{logical_workspace.drive_letter}:"),
                    "REPROBIT_PHYSICAL_TOOLCHAIN_ROOT": str(installation.root),
                    "REPROBIT_LOGICAL_TOOLCHAIN_ROOT": (
                        bundle.spec.paths.toolchain.replace("\\", "/")
                    ),
                }
            )
            if wine_alias is None:
                raise ClassicProjectError("POSIX execution omitted the pinned Wine alias")
            environment["PATH"] = os.pathsep.join((str(wine_alias.parent), environment["PATH"]))
        else:
            windows_environment["PATH"] = os.pathsep.join(
                (windows_environment["PATH"], environment["PATH"])
            )
            environment.update(windows_environment)
        return _ExecutionLane(
            lane_id,
            MappingProxyType(environment),
            worker,
            native_lineage_planner,
        )

    def close_created() -> None:
        nonlocal runtime_binding
        with binding_lock:
            owned = runtime_binding
            runtime_binding = None
        if owned is None:
            return
        worker, stack = owned
        _close_backend_runtime(
            backend,
            worker,
            stack,
            logical_drive=logical_workspace.drive_letter,
            timeout_seconds=cleanup_timeout,
        )

    return _LazyExecutionLanePool(
        maximum=jobs,
        create=create,
        close_created=close_created,
        compiler_environment_digest=compiler_environment_digest,
    )


def _close_backend_runtime(
    backend: ExecutionBackend,
    worker: WorkerSandbox,
    stack: ExitStack,
    *,
    logical_drive: str,
    timeout_seconds: float = 10.0,
) -> None:
    if timeout_seconds <= 0:
        raise ClassicProjectError("classic runtime cleanup timeout must be positive")
    try:
        if isinstance(backend, PosixWineBackend):
            try:
                # Certification fails if Wine exposed any additional host
                # drive while producers were live.
                backend.verify_worker_drive_mappings(
                    worker,
                    logical_drive=logical_drive,
                )
                backend.complete_worker_drive_mapping_lifetime(worker)
            finally:
                # Even a failed certification must stop and reap the private
                # server before mappings are unbound and scrubbed.
                backend.terminate_worker_server(worker, timeout_seconds=timeout_seconds)
    finally:
        try:
            stack.close()
        finally:
            if isinstance(backend, PosixWineBackend):
                backend.scrub_worker_drive_mappings(worker)


def _admitted_host_wrapper(path: Path, *, toolchain_root: Path, label: str) -> Path:
    """Admit an explicitly selected local MSVC transport frontend.

    Canonical toolchain locks identify the Microsoft producers separately from
    their POSIX transport.  Each executed transport sibling is admitted below
    only when the toolchain lock also seals that exact regular file.
    """

    resolved = path.expanduser().resolve(strict=True)
    root = toolchain_root.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ClassicProjectError(f"{label} must be inside the admitted toolchain root") from exc
    if path.is_symlink() or resolved.is_symlink() or not resolved.is_file():
        raise ClassicProjectError(f"{label} must be a regular non-symlink file")
    if not os.access(resolved, os.X_OK):
        raise ClassicProjectError(f"{label} is not executable: {resolved}")
    return resolved


def _locked_wrapper_runtime_files(
    bundle: ProjectBundle,
    wrappers: Sequence[Path],
    *,
    toolchain_root: Path,
) -> tuple[Path, ...]:
    """Admit only the explicitly selected, lock-pinned POSIX transport closure."""

    root = toolchain_root.resolve(strict=True)
    receipts = {
        item.path.replace("\\", "/").casefold(): item
        for item in bundle.toolchain_lock.runtime_files
    }
    admitted: list[Path] = []
    for wrapper in wrappers:
        resolved = wrapper.resolve(strict=True)
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError as exc:
            raise ClassicProjectError("transport file escapes the locked toolchain") from exc
        receipt = receipts.get(relative.casefold())
        if receipt is None:
            raise ClassicProjectError(f"POSIX transport file is not runtime-pinned: {relative!r}")
        if (
            resolved.is_symlink()
            or not resolved.is_file()
            or (receipt.size is not None and receipt.size != resolved.stat().st_size)
            or receipt.digest != _digest_path(resolved)
        ):
            raise ClassicProjectError(
                f"POSIX transport file differs from its runtime pin: {relative!r}"
            )
        admitted.append(resolved)
    folded = [path.as_posix().casefold() for path in admitted]
    if len(folded) != len(set(folded)):
        raise ClassicProjectError("POSIX transport closure repeats a file")
    return tuple(admitted)


def _toolchain_tree_files(bundle: ProjectBundle, root: Path) -> tuple[Path, ...]:
    """Expand locked portable input-tree membership into immutable run inputs."""

    files: set[Path] = set()
    admitted_root = root.resolve(strict=True)
    for tree in bundle.toolchain_lock.input_trees:
        tree_root = admitted_root.joinpath(*PurePosixPath(tree.path).parts)
        if tree_root.is_symlink() or not tree_root.is_dir():
            raise ClassicProjectError(f"locked toolchain tree is absent: {tree.path!r}")
        for child in tree_root.rglob("*"):
            if child.is_symlink():
                raise ClassicProjectError(
                    f"locked toolchain tree contains a runtime symlink: {child}"
                )
            if child.is_file():
                files.add(child.resolve(strict=True))
    return tuple(sorted(files, key=str))


def _toolchain_include_reader_payloads(
    bundle: ProjectBundle,
    root: Path,
) -> Mapping[str, bytes]:
    """Read the locked toolchain trees that can feed the preprocessor."""

    include_roots = {
        path.casefold().rstrip("/")
        for path in toolchain_profile(bundle.toolchain_lock.profile).include_roots
    }
    include_roots.update(
        tree.path.casefold().rstrip("/")
        for tree in bundle.toolchain_lock.input_trees
        if "include" in {part.casefold() for part in PurePosixPath(tree.path).parts}
    )
    admitted_root = root.resolve(strict=True)
    payloads: dict[str, bytes] = {}
    for path in _toolchain_tree_files(bundle, admitted_root):
        relative = path.relative_to(admitted_root).as_posix()
        if not any(
            relative.casefold().startswith(include_root + "/") for include_root in include_roots
        ):
            continue
        payloads[f"toolchain/{relative}"] = path.read_bytes()
    return MappingProxyType(payloads)


def _host_environment(programs: Sequence[Path]) -> dict[str, str]:
    path = os.pathsep.join(
        dict.fromkeys([*(str(item.parent) for item in programs), *os.defpath.split(os.pathsep)])
    )
    values = {"PATH": path, "LANG": "C", "LC_ALL": "C"}
    if os.name == "nt" and "SYSTEMROOT" in os.environ:
        values["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return values


def _run(
    supervisor: ProcessSupervisor,
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout: float,
    log: Path,
    cancellation: CancellationToken | None = None,
    windows_lineage_planner: WindowsLineagePlanner | None = None,
) -> tuple[ProcessResult, CommandSpec]:
    spec = CommandSpec.create(
        argv,
        cwd=cwd,
        environment=environment,
        timeout_seconds=timeout,
        log_path=log,
    )
    return (
        supervisor.run(
            spec,
            cancellation=cancellation,
            windows_lineage_planner=windows_lineage_planner,
        ),
        spec,
    )
