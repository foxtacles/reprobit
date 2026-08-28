from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from reprobit.backends import (
    POSIX_WINE_BACKEND,
    WINDOWS_NATIVE_BACKEND,
    BackendError,
    NativeWindowsBackend,
    PosixWineBackend,
    backend_by_id,
    backend_for_host,
)
from reprobit.native_device_map import (
    NativeDeviceMapError,
    NativeDeviceMapLease,
    NativeDeviceMapProbe,
)
from reprobit.paths import MaterializedSkeleton
from reprobit.process import CommandSpec, ProcessResult


class _FakeWineServerProcess:
    """Minimal foreground-server process used by backend lease tests."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        self.pid = 43210
        self.returncode: int | None = None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired(("wineserver",), timeout)
        return self.returncode


def test_capabilities_are_inspectable_cross_host() -> None:
    wine = backend_by_id(POSIX_WINE_BACKEND).capabilities
    native = backend_by_id(WINDOWS_NATIVE_BACKEND).capabilities

    assert wine.private_wine_prefix is True
    assert wine.process_tree_primitive == "posix_process_group"
    assert native.native_windows is True
    assert native.process_tree_primitive == "windows_kill_on_close_job_object"
    assert native.logical_path_primitive == "process_private_nt_device_map"
    assert backend_by_id(wine.identifier).identifier == wine.identifier
    with pytest.raises(BackendError, match="unsupported"):
        backend_by_id("unknown")


def test_doctor_does_not_execute_wine_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    called = False

    def forbidden(*args: object, **kwargs: object) -> None:
        nonlocal called
        called = True
        raise AssertionError("probe executed")

    monkeypatch.setattr("reprobit.backends.subprocess.run", forbidden)
    report = PosixWineBackend().doctor()
    assert report.executed_probe is False
    assert called is False


@pytest.mark.skipif(os.name == "nt", reason="requires a non-Windows host")
def test_native_doctor_fails_closed_when_host_lacks_private_device_map() -> None:
    report = NativeWindowsBackend().doctor(execute_probe=True)

    assert report.ok is False
    assert report.executed_probe is True
    mapping = next(
        check for check in report.checks if check.name == "certifying logical drive"
    )
    assert mapping.required is True
    assert mapping.passed is False
    assert "require Windows" in mapping.detail
    with pytest.raises(BackendError, match="certifying logical drive"):
        report.require_ok()


def test_native_doctor_executes_process_lineage_only_when_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def primitives() -> NativeDeviceMapProbe:
        calls.append("primitives")
        return NativeDeviceMapProbe(True, "native primitives available")

    def execution() -> NativeDeviceMapProbe:
        calls.append("execution")
        return NativeDeviceMapProbe(True, "process lineage verified")

    monkeypatch.setattr("reprobit.backends.probe_native_device_map", primitives)
    monkeypatch.setattr(
        "reprobit.backends.probe_native_device_map_execution",
        execution,
    )

    passive = NativeWindowsBackend().doctor()
    active = NativeWindowsBackend().doctor(execute_probe=True)

    assert passive.executed_probe is False
    assert all(check.name != "private-map process lineage" for check in passive.checks)
    assert active.executed_probe is True
    assert next(
        check for check in active.checks if check.name == "private-map process lineage"
    ).passed
    assert calls == ["primitives", "primitives", "execution"]


@pytest.mark.skipif(os.name == "nt", reason="non-Windows lease failure path")
def test_native_backend_lease_fails_closed_off_windows(tmp_path: Path) -> None:
    backend = NativeWindowsBackend()
    worker = backend.create_worker(tmp_path / "workers", "native-refused")
    skeleton_root = tmp_path / "logical-drive"
    skeleton_root.mkdir()

    with (
        pytest.raises(NativeDeviceMapError, match="require Windows"),
        backend.bind_skeleton(
            worker,
            MaterializedSkeleton(skeleton_root, "Q", ()),
        ),
    ):
        pass


def test_native_backend_returns_exact_private_device_map_lease(
    tmp_path: Path,
) -> None:
    backend = NativeWindowsBackend()
    worker = backend.create_worker(tmp_path / "workers", "native-private")
    skeleton_root = tmp_path / "logical-drive"
    skeleton_root.mkdir()
    binding = backend.bind_skeleton(
        worker,
        MaterializedSkeleton(skeleton_root, "Q", ()),
    )

    assert isinstance(binding, NativeDeviceMapLease)
    assert binding.root == skeleton_root
    assert binding.drive_letter == "Q"


@pytest.mark.skipif(os.name != "posix", reason="Wine prefixes require POSIX symlinks")
def test_wine_workers_have_private_prefixes_and_drive_links(tmp_path: Path) -> None:
    backend = PosixWineBackend()
    worker = backend.create_worker(tmp_path / "workers", "compile:one")
    assert worker.wine_prefix is not None
    assert worker.pdb.is_dir()
    assert worker.environment["WINEPREFIX"] == str(worker.wine_prefix)

    skeleton_root = tmp_path / "skeleton"
    skeleton_root.mkdir()
    assert worker.wine_prefix is not None
    drive_c = worker.wine_prefix / "drive_c"
    drive_c.mkdir()
    dosdevices = worker.wine_prefix / "dosdevices"
    dosdevices.mkdir()
    (dosdevices / "c:").symlink_to(drive_c, target_is_directory=True)
    skeleton = MaterializedSkeleton(skeleton_root, "R", ())
    binding = backend.bind_skeleton(worker, skeleton)
    with binding:
        assert binding.link.is_symlink()
        assert binding.link.resolve() == skeleton_root
    assert not binding.link.exists()


@pytest.mark.skipif(os.name != "posix", reason="Wine lifecycle requires POSIX process groups")
def test_wine_prefix_bootstrap_keeps_server_live_and_scrubs_host_mappings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = PosixWineBackend(wine=sys.executable, wineserver=sys.executable)
    worker = backend.create_worker(tmp_path / "workers", "compile")
    assert worker.wine_prefix is not None
    dosdevices = worker.wine_prefix / "dosdevices"
    assert not dosdevices.exists()
    lifecycle: list[tuple[str, ...]] = []

    def bootstrap(
        supervisor: object,
        specification: CommandSpec,
        **kwargs: object,
    ) -> ProcessResult:
        del supervisor, kwargs
        lifecycle.append(tuple(specification.argv[1:]))
        assert specification.argv == (
            str(Path(sys.executable).resolve()),
            "wineboot",
            "--init",
        )
        assert specification.environment_mapping["WINEPREFIX"] == str(worker.wine_prefix)
        (worker.wine_prefix / "drive_c").mkdir()
        dosdevices.mkdir()
        (dosdevices / "c:").symlink_to(
            worker.wine_prefix / "drive_c",
            target_is_directory=True,
        )
        (dosdevices / "z:").symlink_to("/", target_is_directory=True)
        (dosdevices / "d::").symlink_to("/dev/null")
        for name in ("system.reg", "user.reg", "userdef.reg"):
            (worker.wine_prefix / name).write_text("sealed\n", encoding="utf-8")
        return ProcessResult(specification.argv, 0, b"", 1, 0.01)

    def unexpected_wineserver(
        command: list[str | Path],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        arguments = tuple(str(item) for item in command[1:])
        lifecycle.append(arguments)
        if arguments == ("-w",):
            server.returncode = 0
        return subprocess.CompletedProcess(command, 0, b"")

    server = _FakeWineServerProcess()

    def popen(*args: object, **kwargs: object) -> _FakeWineServerProcess:
        del args, kwargs
        return server

    def getpgid(pid: int) -> int:
        assert pid == server.pid
        if server.returncode is not None:
            raise ProcessLookupError
        return pid

    def killpg(pid: int, signal_number: int) -> None:
        del signal_number
        assert pid == server.pid
        if server.returncode is not None:
            raise ProcessLookupError

    monkeypatch.setattr("reprobit.process.ProcessSupervisor.run", bootstrap)
    monkeypatch.setattr("reprobit.backends.subprocess.run", unexpected_wineserver)
    monkeypatch.setattr("reprobit.backends.subprocess.Popen", popen)
    monkeypatch.setattr("reprobit.backends.os.getpgid", getpgid)
    monkeypatch.setattr("reprobit.backends.os.killpg", killpg)

    backend.initialize_worker_prefix(worker)

    assert lifecycle == [("wineboot", "--init")]
    assert (worker.wine_prefix / "drive_c").is_dir()
    assert not os.path.lexists(dosdevices / "z:")
    assert not os.path.lexists(dosdevices / "d::")
    assert tuple(dosdevices.iterdir()) == (dosdevices / "c:",)

    skeleton_root = tmp_path / "logical-drive"
    skeleton_root.mkdir()
    binding = backend.bind_skeleton(
        worker,
        MaterializedSkeleton(skeleton_root, "Z", ()),
    )
    with binding:
        assert binding.link.resolve(strict=True) == skeleton_root
        assert tuple(sorted(path.name for path in dosdevices.iterdir())) == ("c:", "z:")
    assert not os.path.lexists(binding.link)
    assert tuple(dosdevices.iterdir()) == (dosdevices / "c:",)
    backend.terminate_worker_server(worker)
    assert lifecycle == [("wineboot", "--init"), ("-k",), ("-w",)]


def test_backend_wraps_only_at_the_host_boundary() -> None:
    command = (r"R:\toolchain\bin\cl.exe", "/c", r"R:\src\unit.cpp")
    backend = PosixWineBackend(wine=sys.executable, wineserver=sys.executable)
    assert backend.wrap_command(command) == (str(Path(sys.executable).resolve()), *command)
    assert NativeWindowsBackend().wrap_command(command) == command


def test_wine_environment_is_minimal_and_declares_classic_runtime(tmp_path: Path) -> None:
    backend = PosixWineBackend(wine=sys.executable, wineserver=sys.executable)
    worker = backend.create_worker(tmp_path / "workers", "compile")
    environment = backend.worker_environment(
        worker,
        windows_environment={"PATH": r"R:\toolchain\bin", "INCLUDE": r"R:\include"},
        dll_overrides=(("msvcrt40", "n"), ("msvcrt20", "n")),
    )

    assert environment["WINEPATH"] == r"R:\toolchain\bin"
    assert environment["WINEDLLOVERRIDES"] == "msvcrt40=n;msvcrt20=n"
    assert environment["INCLUDE"] == r"R:\include"
    assert environment["WINEPREFIX"] == str(worker.wine_prefix)
    assert environment["PATH"].split(os.pathsep)[0] == str(Path(sys.executable).resolve().parent)


def test_worker_ids_are_exclusive(tmp_path: Path) -> None:
    backend = PosixWineBackend()
    backend.create_worker(tmp_path, "same")
    with pytest.raises(BackendError, match="already exists"):
        backend.create_worker(tmp_path, "same")


def test_host_backend_matches_operating_system() -> None:
    backend = backend_for_host()
    assert backend.identifier == (WINDOWS_NATIVE_BACKEND if os.name == "nt" else POSIX_WINE_BACKEND)
