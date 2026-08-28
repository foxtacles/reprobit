"""Execution-backend capability seams for Wine and native Windows."""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import signal
import subprocess
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from contextlib import AbstractContextManager, suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Self

from reprobit.native_device_map import (
    NativeDeviceMapLease,
    probe_native_device_map,
    probe_native_device_map_execution,
)
from reprobit.paths import MaterializedSkeleton

POSIX_WINE_BACKEND = "posix_wine_v1"
WINDOWS_NATIVE_BACKEND = "windows_native_v1"


def _host_system() -> str:
    """Identify Windows without allowing ``platform`` to spawn ``ver``."""

    if os.name == "nt":
        return "Windows"
    return platform.system()


class BackendError(RuntimeError):
    """A backend contract, capability, or owned resource failed closed."""


@dataclass(frozen=True, slots=True)
class BackendCapabilities:
    identifier: str
    host_systems: tuple[str, ...]
    process_tree_primitive: str
    logical_path_primitive: str
    private_wine_prefix: bool
    native_windows: bool
    cold_workers: bool = True
    bounded_children: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    passed: bool
    detail: str
    required: bool = True


@dataclass(frozen=True, slots=True)
class BackendDoctorReport:
    backend: str
    host_system: str
    checks: tuple[DoctorCheck, ...]
    executed_probe: bool = False

    @property
    def ok(self) -> bool:
        return all(check.passed for check in self.checks if check.required)

    def require_ok(self) -> None:
        failures = [check for check in self.checks if check.required and not check.passed]
        if failures:
            raise BackendError("; ".join(f"{check.name}: {check.detail}" for check in failures))


@dataclass(frozen=True, slots=True)
class HostExecutablePin:
    path: Path
    size: int
    sha256: str

    def verify(self) -> bool:
        return (
            self.path.is_file()
            and not self.path.is_symlink()
            and self.path.stat().st_size == self.size
            and _sha256_file(self.path) == self.sha256
        )


@dataclass(frozen=True, slots=True)
class WorkerSandbox:
    worker_id: str
    root: Path
    work: Path
    objects: Path
    pdb: Path
    temporary: Path
    logs: Path
    wine_prefix: Path | None

    @property
    def environment(self) -> dict[str, str]:
        values = {
            "REPROBIT_WORKER_ROOT": str(self.root),
            "REPROBIT_OBJECT_DIR": str(self.objects),
            "REPROBIT_PDB_DIR": str(self.pdb),
            "REPROBIT_TEMP_DIR": str(self.temporary),
        }
        if self.wine_prefix is not None:
            values.update(
                {
                    "WINEPREFIX": str(self.wine_prefix),
                    "WINEDEBUG": "-all",
                }
            )
        return values


@dataclass(slots=True)
class _WineServerLease:
    """One pinned foreground wineserver owned until worker cleanup."""

    worker_root: Path
    prefix: Path
    prefix_identity: tuple[int, int]
    executable: HostExecutablePin
    process: subprocess.Popen[bytes]
    process_group: int
    log_stream: Any


@dataclass(frozen=True, slots=True)
class _WineDriveMappingSnapshot:
    directory_identity: tuple[int, int, int, int, int, int, int]
    members: tuple[str, ...]
    c_identity: tuple[int, int, int, int, int, int, int]
    c_target: str
    logical_identity: tuple[int, int, int, int, int, int, int]
    logical_target: str


def _mapping_metadata(value: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _safe_worker_id(value: str) -> str:
    if not isinstance(value, str) or not value or "\0" in value or len(value) > 256:
        raise BackendError("worker ID must be a bounded NUL-free string")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip(".-")[:48] or "worker"
    return f"{slug}-{hashlib.sha256(value.encode()).hexdigest()[:12]}"


def _command(command: Iterable[str]) -> tuple[str, ...]:
    values = tuple(command)
    if not values or any(
        not isinstance(value, str) or not value or "\0" in value for value in values
    ):
        raise BackendError("backend command must contain NUL-free arguments")
    return values


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_executable(value: str | Path) -> HostExecutablePin | None:
    raw = os.fspath(value)
    if not raw or "\0" in raw:
        raise BackendError("host executable name is empty or contains NUL")
    if Path(raw).is_absolute():
        candidate = Path(raw)
    elif os.sep in raw or (os.altsep is not None and os.altsep in raw):
        raise BackendError(f"host executable path must be absolute: {raw}")
    else:
        located = shutil.which(raw)
        if located is None:
            return None
        candidate = Path(located)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    if not resolved.is_file() or resolved.is_symlink():
        return None
    return HostExecutablePin(resolved, resolved.stat().st_size, _sha256_file(resolved))


class ExecutionBackend(ABC):
    """Capability-based host execution boundary."""

    identifier: str
    capabilities: BackendCapabilities

    @abstractmethod
    def doctor(self, *, execute_probe: bool = False) -> BackendDoctorReport:
        """Inspect availability; probes are opt-in and bounded."""

    @abstractmethod
    def wrap_command(self, command: Iterable[str]) -> tuple[str, ...]:
        """Return host argv for a declared producer argv."""

    @abstractmethod
    def bind_skeleton(
        self, worker: WorkerSandbox, skeleton: MaterializedSkeleton
    ) -> AbstractContextManager[Any]:
        """Bind one materialized DOS-path skeleton for a worker lifetime."""

    def create_worker(self, state_root: Path | str, worker_id: str) -> WorkerSandbox:
        root = Path(state_root)
        if not root.is_absolute():
            raise BackendError("worker state root must be absolute")
        root.mkdir(parents=True, exist_ok=True)
        worker_root = root / _safe_worker_id(worker_id)
        try:
            worker_root.mkdir(exist_ok=False)
        except FileExistsError as error:
            raise BackendError(f"worker sandbox already exists: {worker_root}") from error
        wine_prefix = worker_root / "wine-prefix" if self.capabilities.private_wine_prefix else None
        sandbox = WorkerSandbox(
            worker_id=worker_id,
            root=worker_root,
            work=worker_root / "work",
            objects=worker_root / "objects",
            pdb=worker_root / "pdb",
            temporary=worker_root / "tmp",
            logs=worker_root / "logs",
            wine_prefix=wine_prefix,
        )
        for directory in (
            sandbox.work,
            sandbox.objects,
            sandbox.pdb,
            sandbox.temporary,
            sandbox.logs,
        ):
            directory.mkdir()
        if wine_prefix is not None:
            wine_prefix.mkdir()
        return sandbox


class WineDriveBinding(AbstractContextManager["WineDriveBinding"]):
    """One owned Wine-prefix DOS drive symlink."""

    def __init__(
        self,
        backend: PosixWineBackend,
        worker: WorkerSandbox,
        skeleton: MaterializedSkeleton,
    ) -> None:
        if worker.wine_prefix is None:
            raise BackendError("Wine drive binding requires a private prefix")
        self.backend = backend
        self.worker = worker
        self.skeleton = skeleton
        self.link = worker.wine_prefix / "dosdevices" / f"{skeleton.drive_letter.lower()}:"
        self._mapped = False
        self._snapshot: _WineDriveMappingSnapshot | None = None
        self._lifetime_complete = False

    def _capture(self) -> _WineDriveMappingSnapshot:
        dosdevices = self.link.parent
        c_drive = dosdevices / "c:"
        if not dosdevices.is_dir() or dosdevices.is_symlink():
            raise BackendError("Wine dosdevices directory changed type")
        if not c_drive.is_symlink() or not self.link.is_symlink():
            raise BackendError("Wine drive mapping seal requires c: and the logical drive")
        try:
            c_target = os.readlink(c_drive)
            logical_target = os.readlink(self.link)
            members = tuple(sorted(item.name for item in dosdevices.iterdir()))
            return _WineDriveMappingSnapshot(
                _mapping_metadata(dosdevices.stat(follow_symlinks=False)),
                members,
                _mapping_metadata(c_drive.stat(follow_symlinks=False)),
                c_target,
                _mapping_metadata(self.link.stat(follow_symlinks=False)),
                logical_target,
            )
        except OSError as exc:
            raise BackendError("cannot seal Wine drive mapping identity") from exc

    def verify_lifetime(self) -> None:
        if not self._mapped or self._snapshot is None:
            raise BackendError("Wine drive mapping has no active lifetime seal")
        received = self._capture()
        if received != self._snapshot:
            raise BackendError(
                "Wine dosdevices mapping changed during producer execution"
            )

    def complete_lifetime(self) -> None:
        self.verify_lifetime()
        self._lifetime_complete = True

    def map(self) -> None:
        if self._mapped or self.link.exists() or self.link.is_symlink():
            raise BackendError(f"Wine logical drive is already mapped: {self.link}")
        if not self.skeleton.root.is_dir() or self.skeleton.root.is_symlink():
            raise BackendError("Wine skeleton root must be a real directory")
        try:
            self.link.symlink_to(self.skeleton.root, target_is_directory=True)
        except OSError as error:
            raise BackendError(f"cannot create Wine logical drive {self.link}") from error
        if self.link.resolve(strict=True) != self.skeleton.root.resolve(strict=True):
            self.link.unlink(missing_ok=True)
            raise BackendError("Wine logical drive resolves to the wrong skeleton")
        self._mapped = True
        try:
            self._snapshot = self._capture()
            self.backend._register_drive_binding(self)
        except BaseException:
            self.link.unlink(missing_ok=True)
            self._mapped = False
            self._snapshot = None
            raise

    def close(self) -> None:
        if self._mapped:
            error: BaseException | None = None
            try:
                if not self._lifetime_complete:
                    self.verify_lifetime()
            except BaseException as exc:
                error = exc
            try:
                if not self.link.is_symlink():
                    raise BackendError("Wine logical drive changed type before cleanup")
                self.link.unlink()
            except BaseException as exc:
                error = error or exc
            finally:
                try:
                    self.backend._unregister_drive_binding(self)
                except BaseException as exc:
                    error = error or exc
                finally:
                    self._mapped = False
                    self._snapshot = None
            if error is not None:
                raise error

    def __enter__(self) -> Self:
        self.map()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class PosixWineBackend(ExecutionBackend):
    identifier = POSIX_WINE_BACKEND
    capabilities = BackendCapabilities(
        identifier=identifier,
        host_systems=("Darwin", "Linux"),
        process_tree_primitive="posix_process_group",
        logical_path_primitive="private_wine_dosdevices",
        private_wine_prefix=True,
        native_windows=False,
    )

    def __init__(
        self,
        *,
        wine: str | Path = "wine",
        wineserver: str | Path = "wineserver",
    ) -> None:
        self.wine = os.fspath(wine)
        self.wineserver = os.fspath(wineserver)
        self.wine_pin = _resolve_executable(wine)
        self.wineserver_pin = _resolve_executable(wineserver)
        self._server_leases: dict[Path, _WineServerLease] = {}
        self._server_lease_lock = Lock()
        self._drive_bindings: dict[Path, WineDriveBinding] = {}
        self._drive_binding_lock = Lock()

    def doctor(self, *, execute_probe: bool = False) -> BackendDoctorReport:
        system = _host_system()
        checks = [
            DoctorCheck(
                "host",
                os.name == "posix" and system in self.capabilities.host_systems,
                f"detected {system or os.name}",
            ),
            DoctorCheck(
                "wine",
                self.wine_pin is not None and self.wine_pin.verify(),
                (
                    f"{self.wine_pin.path} sha256={self.wine_pin.sha256}"
                    if self.wine_pin is not None
                    else f"{self.wine} not found"
                ),
            ),
            DoctorCheck(
                "wineserver",
                self.wineserver_pin is not None and self.wineserver_pin.verify(),
                (
                    f"{self.wineserver_pin.path} sha256={self.wineserver_pin.sha256}"
                    if self.wineserver_pin is not None
                    else f"{self.wineserver} not found"
                ),
            ),
        ]
        if execute_probe:
            if self.wine_pin is None or not self.wine_pin.verify():
                checks.append(DoctorCheck("wine probe", False, "Wine executable is absent"))
            else:
                try:
                    completed = subprocess.run(
                        [self.wine_pin.path, "--version"],
                        env=self._loader_environment(None),
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        timeout=10,
                        check=False,
                    )
                    detail = completed.stdout.decode("utf-8", "replace").strip()
                    checks.append(
                        DoctorCheck("wine probe", completed.returncode == 0, detail or "no output")
                    )
                except (OSError, subprocess.TimeoutExpired) as error:
                    checks.append(DoctorCheck("wine probe", False, str(error)))
        return BackendDoctorReport(self.identifier, system, tuple(checks), execute_probe)

    def wrap_command(self, command: Iterable[str]) -> tuple[str, ...]:
        if self.wine_pin is None or not self.wine_pin.verify():
            raise BackendError("the pinned Wine executable is absent or changed")
        return (str(self.wine_pin.path), *_command(command))

    def _loader_environment(self, worker: WorkerSandbox | None) -> dict[str, str]:
        pins = tuple(
            pin for pin in (self.wine_pin, self.wineserver_pin) if pin is not None
        )
        executable_directories = tuple(dict.fromkeys(str(pin.path.parent) for pin in pins))
        search_path = (*executable_directories, "/usr/bin", "/bin", "/usr/sbin", "/sbin")
        environment = {
            "PATH": os.pathsep.join(dict.fromkeys(search_path)),
            "LC_ALL": "C",
            "LANG": "C",
        }
        if worker is not None:
            if worker.wine_prefix is None:
                raise BackendError("Wine environment requires a private prefix")
            xdg = worker.root / "xdg-runtime"
            xdg.mkdir(mode=0o700, exist_ok=True)
            environment.update(
                {
                    "HOME": str(worker.root),
                    "USER": "reprobit",
                    "LOGNAME": "reprobit",
                    "TMPDIR": str(worker.temporary),
                    "XDG_RUNTIME_DIR": str(xdg),
                    "WINEPREFIX": str(worker.wine_prefix),
                    "WINEDEBUG": "-all",
                }
            )
        library_roots = tuple(
            path
            for pin in pins
            for path in (pin.path.parent.parent / "lib", pin.path.parent.parent / "lib64")
            if path.is_dir()
        )
        if library_roots:
            variable = (
                "DYLD_FALLBACK_LIBRARY_PATH"
                if _host_system() == "Darwin"
                else "LD_LIBRARY_PATH"
            )
            environment[variable] = os.pathsep.join(
                dict.fromkeys(str(path) for path in library_roots)
            )
        return environment

    def worker_environment(
        self,
        worker: WorkerSandbox,
        *,
        windows_environment: Mapping[str, str] | Iterable[tuple[str, str]] = (),
        dll_overrides: Iterable[tuple[str, str]] = (),
    ) -> dict[str, str]:
        """Build the complete host environment for one Wine producer."""

        declared = dict(
            windows_environment.items()
            if isinstance(windows_environment, Mapping)
            else windows_environment
        )
        folded_keys = [key.casefold() for key in declared]
        if len(set(folded_keys)) != len(folded_keys):
            raise BackendError("Windows environment repeats a case-insensitive key")
        reserved = {
            "wineprefix",
            "winedebug",
            "winepath",
            "winedlloverrides",
            "home",
            "tmpdir",
            "xdg_runtime_dir",
            "ld_library_path",
            "dyld_fallback_library_path",
        }
        conflicts = sorted(key for key in declared if key.casefold() in reserved)
        if conflicts:
            raise BackendError(f"Windows environment overrides backend keys: {conflicts}")
        environment = self._loader_environment(worker)
        windows_path = next(
            (value for key, value in declared.items() if key.casefold() == "path"), None
        )
        for key in tuple(declared):
            if key.casefold() == "path":
                del declared[key]
        environment.update(declared)
        if windows_path:
            environment["WINEPATH"] = windows_path
        overrides: list[str] = []
        seen: set[str] = set()
        for library, mode in dll_overrides:
            if (
                not re.fullmatch(r"[A-Za-z0-9_.-]+", library)
                or mode not in {"n", "b", "n,b", "b,n", ""}
                or library.casefold() in seen
            ):
                raise BackendError("Wine DLL override declaration is invalid")
            seen.add(library.casefold())
            overrides.append(f"{library}={mode}")
        if overrides:
            environment["WINEDLLOVERRIDES"] = ";".join(overrides)
        return environment

    def bind_skeleton(
        self, worker: WorkerSandbox, skeleton: MaterializedSkeleton
    ) -> WineDriveBinding:
        return WineDriveBinding(self, worker, skeleton)

    def _register_drive_binding(self, binding: WineDriveBinding) -> None:
        key = binding.worker.root.resolve(strict=True)
        with self._drive_binding_lock:
            if key in self._drive_bindings:
                raise BackendError("Wine worker already owns a drive-mapping lease")
            self._drive_bindings[key] = binding

    def _unregister_drive_binding(self, binding: WineDriveBinding) -> None:
        key = binding.worker.root.resolve(strict=True)
        with self._drive_binding_lock:
            received = self._drive_bindings.pop(key, None)
        if received is not binding:
            raise BackendError("Wine drive-mapping lease ownership changed")

    def complete_worker_drive_mapping_lifetime(self, worker: WorkerSandbox) -> None:
        key = worker.root.resolve(strict=True)
        with self._drive_binding_lock:
            binding = self._drive_bindings.get(key)
        if binding is None:
            raise BackendError("worker has no owned drive-mapping lifetime lease")
        binding.complete_lifetime()

    def _start_worker_server(
        self,
        worker: WorkerSandbox,
        *,
        environment: Mapping[str, str],
    ) -> _WineServerLease:
        """Start one foreground private-prefix server in its own process group."""

        if worker.wine_prefix is None or self.wineserver_pin is None:
            raise BackendError("Wine server lease lacks a private prefix or pin")
        if not self.wineserver_pin.verify():
            raise BackendError("the pinned wineserver executable changed")
        prefix_metadata = worker.wine_prefix.stat(follow_symlinks=False)
        key = worker.root.resolve(strict=True)
        with self._server_lease_lock:
            if key in self._server_leases:
                raise BackendError("Wine worker already owns a server lease")
        log_path = worker.logs / "wineserver.log"
        log_stream = log_path.open("xb")
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                (str(self.wineserver_pin.path), "-f", "-p"),
                cwd=worker.root,
                env=dict(environment),
                stdin=subprocess.DEVNULL,
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            process_group = os.getpgid(process.pid)
            if process_group != process.pid:
                raise BackendError("foreground wineserver lacks an isolated process group")
            # The server must survive long enough for wineboot to attach.  A
            # failed executable normally exits immediately with a diagnostic.
            try:
                process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                pass
            else:
                raise BackendError(
                    f"foreground wineserver exited during lease creation: "
                    f"{process.returncode}"
                )
            lease = _WineServerLease(
                key,
                worker.wine_prefix.resolve(strict=True),
                (prefix_metadata.st_dev, prefix_metadata.st_ino),
                self.wineserver_pin,
                process,
                process_group,
                log_stream,
            )
            with self._server_lease_lock:
                if key in self._server_leases:
                    raise BackendError("Wine worker server lease raced another owner")
                self._server_leases[key] = lease
            return lease
        except BaseException:
            if process is not None and process.poll() is None:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            log_stream.close()
            raise

    def _server_lease(self, worker: WorkerSandbox) -> _WineServerLease | None:
        key = worker.root.resolve(strict=True)
        with self._server_lease_lock:
            return self._server_leases.get(key)

    def _pop_server_lease(self, worker: WorkerSandbox) -> _WineServerLease | None:
        key = worker.root.resolve(strict=True)
        with self._server_lease_lock:
            return self._server_leases.pop(key, None)

    def initialize_worker_prefix(
        self, worker: WorkerSandbox, *, timeout_seconds: float = 120
    ) -> None:
        """Bootstrap one cold prefix before replacing Wine's default ``z:``.

        Wine creates its registry and ``drive_c`` lazily and expects its own
        host-root ``z:`` mapping during that bootstrap.  Authentic execution
        cannot retain that broad mapping.  Keep the private server created by
        ``wineboot`` alive, remove every non-private drive mapping, and let the
        caller bind its closed logical skeleton to that same server.  Stopping
        the server here would let the next producer recreate host-volume drive
        mappings before it executes.
        """

        if worker.wine_prefix is None:
            raise BackendError("Wine prefix initialization requires a private prefix")
        if timeout_seconds <= 0:
            raise BackendError("Wine prefix initialization timeout must be positive")
        if self.wine_pin is None or not self.wine_pin.verify():
            raise BackendError("the pinned Wine executable is absent or changed")
        prefix = worker.wine_prefix
        if prefix.is_symlink() or not prefix.is_dir():
            raise BackendError("cold Wine prefix is absent or redirected")
        if any(prefix.iterdir()):
            raise BackendError("Wine prefix initialization requires a cold worker prefix")

        from reprobit.process import CommandSpec, ProcessSupervisor

        bootstrap_started = False
        try:
            environment = self.worker_environment(worker)
            overrides = environment.get("WINEDLLOVERRIDES", "")
            if any(
                item.split("=", 1)[0].casefold() == "winemenubuilder.exe"
                for item in overrides.split(";")
                if item
            ):
                raise BackendError(
                    "Wine bootstrap environment predefines winemenubuilder policy"
                )
            environment["WINEDLLOVERRIDES"] = ";".join(
                item for item in (overrides, "winemenubuilder.exe=d") if item
            )
            self._start_worker_server(worker, environment=environment)
            bootstrap_started = True
            specification = CommandSpec.create(
                (str(self.wine_pin.path), "wineboot", "--init"),
                cwd=worker.root,
                environment=environment,
                timeout_seconds=timeout_seconds,
                log_path=worker.logs / "wine-prefix-init.log",
            )
            with ProcessSupervisor() as supervisor:
                supervisor.run(specification)
            default_z = prefix / "dosdevices" / "z:"
            if not default_z.is_symlink():
                raise BackendError("Wine prefix bootstrap omitted its default z: mapping")
            try:
                default_target = default_z.resolve(strict=True)
            except OSError as error:
                raise BackendError("Wine bootstrap z: mapping is dangling") from error
            if default_target != Path("/").resolve(strict=True):
                raise BackendError("Wine bootstrap z: mapping does not name the host root")
            # A live wineserver can retain registry state in memory until its
            # final reap, so only filesystem/drive invariants are available at
            # this point.  Final cleanup below requires the persisted registry.
            self.scrub_worker_drive_mappings(worker, require_sealed_state=False)
        except BaseException:
            try:
                if bootstrap_started:
                    self.terminate_worker_server(
                        worker, timeout_seconds=min(timeout_seconds, 10)
                    )
            finally:
                # Best-effort removal is still bounded to symlinks in this
                # abandoned private prefix.  Any unsafe entry remains a hard
                # error from the scrubber instead of being deleted.
                if (prefix / "dosdevices").is_dir():
                    self.scrub_worker_drive_mappings(worker)
            raise

    def _private_c_drive(
        self, worker: WorkerSandbox, *, require_sealed_state: bool
    ) -> tuple[Path, Path]:
        """Validate and return one worker's dosdevices directory and c: link."""

        if worker.wine_prefix is None:
            raise BackendError("worker has no private Wine prefix")
        prefix = worker.wine_prefix
        drive_c = prefix / "drive_c"
        dosdevices = prefix / "dosdevices"
        registry = (prefix / "system.reg", prefix / "user.reg", prefix / "userdef.reg")
        if (
            not drive_c.is_dir()
            or drive_c.is_symlink()
            or not dosdevices.is_dir()
            or dosdevices.is_symlink()
            or (
                require_sealed_state
                and any(not item.is_file() or item.is_symlink() for item in registry)
            )
        ):
            raise BackendError("Wine prefix bootstrap omitted its sealed runtime state")
        c_drive = dosdevices / "c:"
        if not c_drive.is_symlink():
            raise BackendError("Wine prefix bootstrap omitted its private c: mapping")
        try:
            c_target = c_drive.resolve(strict=True)
        except OSError as error:
            raise BackendError("Wine private c: mapping is dangling") from error
        if c_target != drive_c.resolve(strict=True):
            raise BackendError("Wine private c: mapping escapes its worker prefix")
        return dosdevices, c_drive

    def scrub_worker_drive_mappings(
        self,
        worker: WorkerSandbox,
        *,
        require_sealed_state: bool = True,
    ) -> None:
        """Remove Wine-created host mappings and retain only the private c: drive."""

        dosdevices, c_drive = self._private_c_drive(
            worker,
            require_sealed_state=require_sealed_state,
        )
        for mapping in tuple(dosdevices.iterdir()):
            if mapping == c_drive:
                continue
            if not mapping.is_symlink():
                raise BackendError(
                    f"Wine runtime left an unowned drive entry: {mapping.name}"
                )
            mapping.unlink()
        if tuple(dosdevices.iterdir()) != (c_drive,):
            raise BackendError("Wine runtime drive cleanup was incomplete")

    def verify_worker_drive_mappings(
        self, worker: WorkerSandbox, *, logical_drive: str
    ) -> None:
        """Require exactly private c: plus the currently owned logical drive."""

        if not re.fullmatch(r"[A-Za-z]", logical_drive):
            raise BackendError("logical Wine drive must be one ASCII letter")
        dosdevices, c_drive = self._private_c_drive(
            worker,
            require_sealed_state=False,
        )
        logical = dosdevices / f"{logical_drive.casefold()}:"
        if logical == c_drive or not logical.is_symlink():
            raise BackendError("Wine logical drive mapping is absent")
        present = {item.name for item in dosdevices.iterdir()}
        expected = {c_drive.name, logical.name}
        if present != expected:
            raise BackendError(
                f"Wine runtime exposes undeclared drive mappings: {sorted(present - expected)}"
            )

    def terminate_worker_server(
        self, worker: WorkerSandbox, *, timeout_seconds: float = 10
    ) -> None:
        """Validate, stop, and reap one typed private-prefix server lease."""

        if worker.wine_prefix is None:
            raise BackendError("worker has no private Wine prefix")
        if timeout_seconds <= 0:
            raise BackendError("wineserver timeout must be positive")
        if self.wineserver_pin is None or not self.wineserver_pin.verify():
            raise BackendError("the pinned wineserver executable is absent or changed")
        lease = self._server_lease(worker)
        if lease is None:
            raise BackendError("worker has no owned wineserver lifetime lease")
        errors: list[str] = []
        try:
            prefix_metadata = worker.wine_prefix.stat(follow_symlinks=False)
            if (
                worker.wine_prefix.resolve(strict=True) != lease.prefix
                or (prefix_metadata.st_dev, prefix_metadata.st_ino)
                != lease.prefix_identity
            ):
                errors.append("private Wine prefix changed during its server lease")
        except OSError as exc:
            errors.append(f"private Wine prefix disappeared: {exc}")
        if lease.executable != self.wineserver_pin or not lease.executable.verify():
            errors.append("wineserver executable identity changed during its lease")
        if lease.process.poll() is not None:
            errors.append("owned wineserver exited before bounded cleanup")
        else:
            try:
                if os.getpgid(lease.process.pid) != lease.process_group:
                    errors.append("owned wineserver PID/PGID identity changed")
            except ProcessLookupError:
                errors.append("owned wineserver PID disappeared before cleanup")
        environment = self.worker_environment(worker)
        command_error: str | None = None
        for argument, action in (("-k", "stop"), ("-w", "reap")):
            try:
                completed = subprocess.run(
                    [self.wineserver_pin.path, argument],
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                command_error = f"cannot {action} worker wineserver: {error}"
                break
            if completed.returncode != 0:
                detail = completed.stdout[-4000:].decode("utf-8", "replace")
                command_error = f"worker wineserver refused {action}: {detail}"
                break
        if command_error is not None:
            errors.append(command_error)
        try:
            lease.process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            errors.append("owned wineserver did not exit after prefix shutdown")
            with suppress(ProcessLookupError):
                os.killpg(lease.process_group, signal.SIGKILL)
            try:
                lease.process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                errors.append("owned wineserver process group could not be reaped")
        else:
            if lease.process.returncode != 0:
                errors.append(
                    f"owned wineserver exited with code {lease.process.returncode}"
                )
        try:
            os.killpg(lease.process_group, 0)
        except ProcessLookupError:
            pass
        else:
            errors.append("owned wineserver process group remained live after cleanup")
        popped = self._pop_server_lease(worker)
        if popped is not lease:
            errors.append("wineserver lifetime lease ownership changed during cleanup")
        lease.log_stream.close()
        if errors:
            raise BackendError("; ".join(errors))


class NativeWindowsBackend(ExecutionBackend):
    identifier = WINDOWS_NATIVE_BACKEND
    capabilities = BackendCapabilities(
        identifier=identifier,
        host_systems=("Windows",),
        process_tree_primitive="windows_kill_on_close_job_object",
        logical_path_primitive="fresh_luid_local_dos_device_map",
        private_wine_prefix=False,
        native_windows=True,
    )

    def doctor(self, *, execute_probe: bool = False) -> BackendDoctorReport:
        system = _host_system()
        map_probe = probe_native_device_map()
        checks = [
            DoctorCheck(
                "host",
                os.name == "nt" and system == "Windows",
                f"detected {system or os.name}",
            ),
            DoctorCheck(
                "job objects",
                os.name == "nt",
                "kernel32 Job Object API" if os.name == "nt" else "Win32 API unavailable",
            ),
            DoctorCheck(
                "certifying logical drive",
                map_probe.available,
                map_probe.detail,
            ),
        ]
        if execute_probe:
            execution_probe = probe_native_device_map_execution()
            checks.append(
                DoctorCheck(
                    "fresh-LUID process lineage",
                    execution_probe.available,
                    execution_probe.detail,
                )
            )
        return BackendDoctorReport(self.identifier, system, tuple(checks), execute_probe)

    def wrap_command(self, command: Iterable[str]) -> tuple[str, ...]:
        return _command(command)

    def bind_skeleton(
        self, worker: WorkerSandbox, skeleton: MaterializedSkeleton
    ) -> NativeDeviceMapLease:
        if worker.wine_prefix is not None:
            raise BackendError("native Windows worker unexpectedly owns a Wine prefix")
        return NativeDeviceMapLease(skeleton.root, skeleton.drive_letter)


def backend_for_host() -> ExecutionBackend:
    system = _host_system()
    if os.name == "nt" and system == "Windows":
        return NativeWindowsBackend()
    if os.name == "posix" and system in {"Darwin", "Linux"}:
        return PosixWineBackend()
    raise BackendError(f"no supported execution backend for {system or os.name}")


def backend_by_id(identifier: str) -> ExecutionBackend:
    if identifier == POSIX_WINE_BACKEND:
        return PosixWineBackend()
    if identifier == WINDOWS_NATIVE_BACKEND:
        return NativeWindowsBackend()
    raise BackendError(f"unsupported execution backend: {identifier}")


__all__ = [
    "POSIX_WINE_BACKEND",
    "WINDOWS_NATIVE_BACKEND",
    "BackendCapabilities",
    "BackendDoctorReport",
    "BackendError",
    "DoctorCheck",
    "ExecutionBackend",
    "HostExecutablePin",
    "NativeWindowsBackend",
    "PosixWineBackend",
    "WineDriveBinding",
    "WorkerSandbox",
    "backend_by_id",
    "backend_for_host",
]
