from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PureWindowsPath
from typing import Any

import pytest

import reprobit.native_device_map as native_device_map_module
import reprobit.process as process_module
from reprobit.backends import NativeWindowsBackend
from reprobit.classic_includes import parse_msvc_sbr
from reprobit.native_device_map import (
    NativeDeviceMapError,
    NativeDeviceMapLease,
    _lineage_inner_command,
    _LineageApi,
    _minimal_broker_environment,
    _run_suspended_producer_tree,
    _serialize_windows_environment,
    probe_native_device_map,
    probe_native_device_map_execution,
)
from reprobit.paths import LogicalPathSkeleton, LogicalSeat
from reprobit.process import CommandSpec, ProcessSupervisor, ProcessTimedOut

_WINDOWS = os.name == "nt"
_CREATE_SUSPENDED = 0x00000004
_CREATE_NEW_PROCESS_GROUP = 0x00000200


def test_native_device_map_rejects_non_letter_drive() -> None:
    with pytest.raises(NativeDeviceMapError, match="one ASCII letter"):
        NativeDeviceMapLease(Path.cwd(), "RR")


def test_lineage_brokers_are_isolated_and_receive_a_minimal_environment() -> None:
    assert _lineage_inner_command()[1:3] == ("-I", "-m")
    entries = _minimal_broker_environment(
        {
            "PYTHONPATH": r"C:\attacker",
            "systemroot": r"C:\Windows",
            "windir": r"C:\Windows",
        }
    )

    assert entries == (
        ("SystemRoot", r"C:\Windows"),
        ("WINDIR", r"C:\Windows"),
    )
    assert _serialize_windows_environment(entries) == (
        "SystemRoot=C:\\Windows\0WINDIR=C:\\Windows\0\0"
    )


def test_lineage_plan_preserves_long_commands_and_exact_environment(
    tmp_path: Path,
) -> None:
    lease = NativeDeviceMapLease(tmp_path, "R")
    lease._active = True
    lease._target = r"\Device\HarddiskVolume1\private"
    lease._controller_authentication_id = (123, 0)
    long_argument = "x" * 4096
    spec = CommandSpec.create(
        (r"R:\toolchain\bin\CL.EXE", long_argument),
        cwd=tmp_path,
        environment=(("EMPTY", ""), ("VALUE", "exact")),
    )

    plan = json.loads(lease.windows_lineage_plan(spec))
    selected = process_module._windows_lineage_plan(
        lease,
        spec,
    )

    assert plan["argv"] == [r"R:\toolchain\bin\CL.EXE", long_argument]
    assert plan["cwd"] == str(tmp_path)
    assert plan["environment"] == [["EMPTY", ""], ["VALUE", "exact"]]
    assert selected is not None and json.loads(selected) == plan


@pytest.mark.parametrize(
    ("leader_exit", "expected_tail"),
    [
        (0, ["leader-wait", "leader-handle-close", "job-wait", "job-close"]),
        (7, ["leader-wait", "leader-handle-close", "job-terminate", "job-close"]),
    ],
)
def test_lineage_tree_drains_after_the_producer_leader(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    leader_exit: int,
    expected_tail: list[str],
) -> None:
    events: list[str] = []

    class FakeProducer:
        returncode: int | None = None

        def wait(self, timeout: float | None = None) -> int:
            del timeout
            events.append("leader-wait")
            self.returncode = leader_exit
            return leader_exit

        def poll(self) -> int | None:
            return self.returncode

        def kill(self) -> None:
            events.append("leader-kill")

    class FakeJob:
        def __init__(self) -> None:
            events.append("job-create")

        def assign(self, _producer: object) -> None:
            events.append("job-assign")

        def resume(self, _producer: object) -> None:
            events.append("job-resume")

        def close_process_handle(self, _producer: object) -> None:
            events.append("leader-handle-close")

        def wait_empty(self, _timeout: float | None) -> bool:
            events.append("job-wait")
            return True

        def terminate_and_drain(self, _timeout: float) -> None:
            events.append("job-terminate")

        def close(self) -> None:
            events.append("job-close")

    def fake_popen(*_args: object, **kwargs: object) -> FakeProducer:
        assert kwargs["creationflags"] == _CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP
        events.append("producer-create-suspended")
        return FakeProducer()

    monkeypatch.setattr("reprobit.process._WindowsJob", FakeJob)
    monkeypatch.setattr("reprobit.native_device_map.subprocess.Popen", fake_popen)
    spec = CommandSpec.create(
        ("producer",),
        cwd=tmp_path,
        environment={},
    )

    assert _run_suspended_producer_tree(spec) == leader_exit
    assert events[:4] == [
        "job-create",
        "producer-create-suspended",
        "job-assign",
        "job-resume",
    ]
    assert events[4:] == expected_tail


def test_lineage_broker_keeps_mapping_when_tree_drain_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    failure = NativeDeviceMapError("producer Job drain failed")
    spec = CommandSpec.create(("producer",), cwd=tmp_path)
    document = {
        "argv": ["producer"],
        "controller_authentication_id": [10, 0],
        "cwd": str(tmp_path),
        "drive": "R:",
        "environment": [],
        "target": r"\Device\HarddiskVolume1\root",
        "version": 1,
    }

    class WindowsOs:
        name = "nt"

    class FakeApi:
        @staticmethod
        def process_authentication_id(_process: int) -> tuple[int, int]:
            return (20, 0)

        @staticmethod
        def define_local_drive(_drive: str, _target: str) -> None:
            events.append("define")

        @staticmethod
        def remove_local_drive(_drive: str, _target: str) -> None:
            events.append("remove")

    def fail_tree(_spec: CommandSpec) -> int:
        events.append("run")
        raise failure

    monkeypatch.setattr(native_device_map_module, "os", WindowsOs())
    monkeypatch.setattr(
        native_device_map_module,
        "_read_lineage_plan",
        lambda: (document, spec),
    )
    monkeypatch.setattr(native_device_map_module, "_LineageApi", FakeApi)
    monkeypatch.setattr(
        native_device_map_module,
        "_run_suspended_producer_tree",
        fail_tree,
    )

    with pytest.raises(NativeDeviceMapError) as caught:
        native_device_map_module._run_lineage_broker()

    assert caught.value is failure
    assert events == ["define", "run"]


def test_broker_main_surfaces_cleanup_notes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    failure = NativeDeviceMapError("primary failure")
    failure.add_note("descendant cleanup failed")

    def fail() -> int:
        raise failure

    monkeypatch.setattr(native_device_map_module, "_run_lineage_broker", fail)

    assert native_device_map_module._main(["--lineage-inner"]) == 125
    assert "cleanup note: descendant cleanup failed" in capsys.readouterr().err


@pytest.mark.skipif(not _WINDOWS, reason="requires a native Windows junction")
def test_native_device_map_rejects_junction_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    junction = tmp_path / "junction"
    target.mkdir()
    result = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(target)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"fixture host cannot create a junction: {result.stdout.strip()}")

    with pytest.raises(NativeDeviceMapError, match="must not be redirected"):
        NativeDeviceMapLease(junction, _free_drive()).open()


@pytest.mark.skipif(_WINDOWS, reason="non-Windows capability result")
def test_native_device_map_probe_fails_closed_off_windows() -> None:
    probe = probe_native_device_map()
    assert probe.available is False
    assert "require Windows" in probe.detail
    execution = probe_native_device_map_execution()
    assert execution.available is False
    assert "require Windows" in execution.detail


def _kernel32() -> Any:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryDosDeviceW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_uint32,
    ]
    kernel32.QueryDosDeviceW.restype = ctypes.c_uint32
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.GetProcessHandleCount.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel32.GetProcessHandleCount.restype = ctypes.c_int
    return kernel32


def _query_drive(letter: str) -> str | None:
    kernel32 = _kernel32()
    buffer = ctypes.create_unicode_buffer(32767)
    ctypes.set_last_error(0)
    if kernel32.QueryDosDeviceW(f"{letter}:", buffer, len(buffer)):
        return buffer.value
    error = int(ctypes.get_last_error())
    if error in {2, 3}:
        return None
    raise OSError(error, f"QueryDosDeviceW({letter}:) failed")


def _free_drive() -> str:
    for letter in "RQPONMLKJIHGFEDBA":
        if _query_drive(letter) is None:
            return letter
    pytest.skip("Windows runner has no controller-unmapped drive candidate")


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows lineage namespace")
def test_native_device_map_feature_probe_is_harmless() -> None:
    probe = probe_native_device_map()
    assert probe.available, probe.detail


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows lineage namespace")
def test_lineage_lease_does_not_map_the_controller_drive(tmp_path: Path) -> None:
    drive = _free_drive()
    root = tmp_path / "private-root"
    root.mkdir()

    with NativeDeviceMapLease(root, drive):
        assert _query_drive(drive) is None
    assert _query_drive(drive) is None


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows lineage namespace")
def test_repeated_short_lineage_commands_drain_without_false_leaks(
    tmp_path: Path,
) -> None:
    """Exercise the Job-accounting handoff that follows a fast broker exit."""

    drive = _free_drive()
    root = tmp_path / "private-root"
    root.mkdir()
    environment = {"SYSTEMROOT": os.environ["SYSTEMROOT"]}

    with (
        NativeDeviceMapLease(root, drive) as lease,
        ProcessSupervisor() as supervisor,
    ):
        for _ in range(32):
            result = supervisor.run(
                CommandSpec.create(
                    (sys.executable, "-c", "pass"),
                    cwd=root,
                    environment=environment,
                    timeout_seconds=20,
                ),
                windows_lineage_planner=lease,
            )
            assert result.succeeded


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows lineage namespace")
def test_lineage_drive_reaches_producer_and_descendant(
    tmp_path: Path,
) -> None:
    """A controller-local peer mapping cannot leak into the fresh LUID."""

    drive = _free_drive()
    root = tmp_path / "private-root"
    decoy = tmp_path / "controller-decoy"
    root.mkdir()
    decoy.mkdir()
    (root / "marker.txt").write_text("descendant-private", encoding="utf-8")
    (decoy / "marker.txt").write_text("controller-private", encoding="utf-8")
    grandchild = (
        "from pathlib import Path; "
        f"print(Path(r'{drive}:\\marker.txt').read_text(encoding='utf-8'))"
    )
    child = textwrap.dedent(
        f"""
        import subprocess
        import sys
        from pathlib import Path

        print(Path(r'{drive}:\\marker.txt').read_text(encoding='utf-8'))

        result = subprocess.run(
            [sys.executable, "-c", {grandchild!r}],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )
        print(result.stdout, end="")
        raise SystemExit(result.returncode)
        """
    )
    environment = {}
    system_root = os.environ.get("SYSTEMROOT")
    if system_root:
        environment["SYSTEMROOT"] = system_root

    api = _LineageApi()
    device = f"{drive}:"
    decoy_target = api.final_nt_path(decoy.resolve(strict=True))
    api.define_local_drive(device, decoy_target)
    try:
        assert Path(rf"{drive}:\marker.txt").read_text(encoding="utf-8") == "controller-private"
        with (
            NativeDeviceMapLease(root, drive) as lease,
            ProcessSupervisor() as supervisor,
        ):
            result = supervisor.run(
                CommandSpec.create(
                    (sys.executable, "-c", child),
                    cwd=root,
                    environment=environment,
                    timeout_seconds=20,
                ),
                windows_lineage_planner=lease,
            )
        assert Path(rf"{drive}:\marker.txt").read_text(encoding="utf-8") == "controller-private"
    finally:
        api.remove_local_drive(device, decoy_target)

    assert result.output.splitlines() == [
        b"descendant-private",
        b"descendant-private",
    ]


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows lineage namespace")
def test_concurrent_fresh_luids_isolate_the_same_drive_letter(
    tmp_path: Path,
) -> None:
    drive = _free_drive()
    roots = (tmp_path / "first-root", tmp_path / "second-root")
    ready = (tmp_path / "first.ready", tmp_path / "second.ready")
    labels = ("first-private", "second-private")
    for root, label in zip(roots, labels, strict=True):
        root.mkdir()
        (root / "marker.txt").write_text(label, encoding="utf-8")
    environment = {"SYSTEMROOT": os.environ["SYSTEMROOT"]}

    def run(index: int) -> bytes:
        script = textwrap.dedent(
            f"""
            import time
            from pathlib import Path

            own = Path({str(ready[index])!r})
            peer = Path({str(ready[1 - index])!r})
            own.write_text("ready", encoding="ascii")
            deadline = time.monotonic() + 10
            while not peer.exists():
                if time.monotonic() >= deadline:
                    raise RuntimeError("parallel lineage peer did not start")
                time.sleep(0.01)
            print(
                Path(r'{drive}:\\marker.txt').read_text(encoding='utf-8'),
                flush=True,
            )
            """
        )
        with (
            NativeDeviceMapLease(roots[index], drive) as lease,
            ProcessSupervisor() as supervisor,
        ):
            return supervisor.run(
                CommandSpec.create(
                    (sys.executable, "-c", script),
                    cwd=roots[index],
                    environment=environment,
                    timeout_seconds=20,
                ),
                windows_lineage_planner=lease,
            ).output

    with ThreadPoolExecutor(max_workers=2) as executor:
        outputs = tuple(executor.map(run, range(2)))

    assert outputs == tuple(f"{label}{os.linesep}".encode() for label in labels)


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows lineage namespace")
def test_lineage_mapping_outlives_an_immediately_exiting_producer(
    tmp_path: Path,
) -> None:
    """The broker must retain R: until an orphaned producer descendant exits."""

    drive = _free_drive()
    root = tmp_path / "private-root"
    root.mkdir()
    (root / "marker.txt").write_text("late-descendant-private", encoding="utf-8")
    grandchild = textwrap.dedent(
        f"""
        import time
        from pathlib import Path

        time.sleep(0.5)
        print(
            Path(r'{drive}:\\marker.txt').read_text(encoding='utf-8'),
            flush=True,
        )
        """
    )
    producer = textwrap.dedent(
        f"""
        import subprocess
        import sys

        subprocess.Popen([sys.executable, "-c", {grandchild!r}])
        print("producer-exit", flush=True)
        """
    )
    environment = {}
    system_root = os.environ.get("SYSTEMROOT")
    if system_root:
        environment["SYSTEMROOT"] = system_root

    with (
        NativeDeviceMapLease(root, drive) as lease,
        ProcessSupervisor() as supervisor,
    ):
        result = supervisor.run(
            CommandSpec.create(
                (sys.executable, "-c", producer),
                cwd=root,
                environment=environment,
                timeout_seconds=20,
            ),
            windows_lineage_planner=lease,
        )

    assert result.output.splitlines() == [
        b"producer-exit",
        b"late-descendant-private",
    ]


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows lineage namespace")
def test_lineage_broker_preserves_long_argv_environment_and_capture(
    tmp_path: Path,
) -> None:
    drive = _free_drive()
    root = tmp_path / "private-root"
    root.mkdir()
    long_argument = "x" * 4096
    script = textwrap.dedent(
        """
        import os
        import sys

        print(len(sys.argv[1]), flush=True)
        print(os.environ["LINEAGE_VALUE"], flush=True)
        print(",".join(sorted(key.casefold() for key in os.environ)), flush=True)
        print("captured-stderr", file=sys.stderr)
        """
    )
    environment = {"LINEAGE_VALUE": "exact"}
    system_root = os.environ.get("SYSTEMROOT")
    if system_root:
        environment["SYSTEMROOT"] = system_root

    with (
        NativeDeviceMapLease(root, drive) as lease,
        ProcessSupervisor() as supervisor,
    ):
        result = supervisor.run(
            CommandSpec.create(
                (sys.executable, "-c", script, long_argument),
                cwd=root,
                environment=environment,
                timeout_seconds=20,
            ),
            windows_lineage_planner=lease,
        )

    assert result.output.splitlines() == [
        b"4096",
        b"exact",
        b"lineage_value,systemroot",
        b"captured-stderr",
    ]


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows lineage namespace")
def test_lineage_broker_remains_owned_when_the_producer_times_out(
    tmp_path: Path,
) -> None:
    drive = _free_drive()
    root = tmp_path / "private-root"
    root.mkdir()
    started = tmp_path / "descendant.started"
    release = tmp_path / "descendant.release"
    forbidden = tmp_path / "descendant-survived"
    descendant = textwrap.dedent(
        f"""
        import time
        from pathlib import Path

        started = Path({str(started)!r})
        release = Path({str(release)!r})
        started.write_text("started", encoding="ascii")
        while not release.exists():
            time.sleep(0.01)
        Path({str(forbidden)!r}).write_text("escaped", encoding="ascii")
        """
    )
    producer = textwrap.dedent(
        f"""
        import subprocess
        import sys
        import time

        subprocess.Popen([sys.executable, "-c", {descendant!r}])
        time.sleep(60)
        """
    )

    with (
        NativeDeviceMapLease(root, drive) as lease,
        ProcessSupervisor(poll_interval=0.01, termination_grace=0.2) as supervisor,
        pytest.raises(ProcessTimedOut),
    ):
        supervisor.run(
            CommandSpec.create(
                (sys.executable, "-c", producer),
                cwd=root,
                environment={"SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
                timeout_seconds=3,
            ),
            windows_lineage_planner=lease,
        )

    assert supervisor.active_pids == ()
    assert started.is_file(), "producer descendant did not start before the timeout"
    release.write_text("release", encoding="ascii")
    time.sleep(0.5)
    assert not forbidden.exists()


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows and MSVC 4.2")
def test_native_backend_runs_the_authenticated_msvc42_producer_chain(
    tmp_path: Path,
) -> None:
    """Exercise the native producer chain and a discarded `/Fr` replay."""

    raw_toolchain = os.environ.get("REPROBIT_MSVC_4_2_ROOT")
    if not raw_toolchain:
        pytest.skip("REPROBIT_MSVC_4_2_ROOT is not configured")
    toolchain_root = Path(raw_toolchain).resolve(strict=True)
    compiler = toolchain_root / "bin" / "CL.EXE"
    if compiler.is_symlink() or not compiler.is_file():
        pytest.fail("authenticated MSVC 4.2 root lacks bin/CL.EXE")
    log_root = Path(os.environ.get("REPROBIT_NATIVE_LOG_DIR", tmp_path))
    log_root.mkdir(parents=True, exist_ok=True)

    drive = _free_drive()
    source_root = tmp_path / "source"
    build_root = tmp_path / "build"
    source_root.mkdir()
    build_root.mkdir()
    (source_root / "smoke.cpp").write_text(
        'extern "C" int main(void) { return 0; }\n',
        encoding="ascii",
        newline="\r\n",
    )
    (source_root / "smoke.rc").write_text(
        "1 RCDATA\r\nBEGIN\r\n  1, 2, 3, 4\r\nEND\r\n",
        encoding="ascii",
        newline="",
    )
    skeleton = LogicalPathSkeleton(
        (
            LogicalSeat("source", source_root, rf"{drive}:\source"),
            LogicalSeat("build", build_root, rf"{drive}:\build", writable=True),
            LogicalSeat("toolchain", toolchain_root, rf"{drive}:\toolchain"),
        )
    )
    backend = NativeWindowsBackend()
    worker = backend.create_worker(tmp_path / "workers", "native-cl-smoke")

    with (
        skeleton.temporary_materialization(tmp_path / "skeletons") as materialized,
        backend.bind_skeleton(worker, materialized) as binding,
        ProcessSupervisor() as supervisor,
    ):
        environment = {
            "INCLUDE": r"\toolchain\include",
            "LIB": r"\toolchain\lib",
            "LIBPATH": r"\toolchain\lib",
            "PATH": r"\toolchain\bin",
            "TEMP": rf"{drive}:\build",
            "TMP": rf"{drive}:\build",
        }
        system_root = os.environ.get("SYSTEMROOT")
        if system_root:
            environment["SYSTEMROOT"] = system_root
        compile_result = supervisor.run(
            CommandSpec.create(
                (
                    rf"{drive}:\toolchain\bin\CL.EXE",
                    "/nologo",
                    "/c",
                    "/MD",
                    "/Zi",
                    rf"/Fo{drive}:\build\smoke.obj",
                    rf"/Fd{drive}:\build\smoke.pdb",
                    rf"{drive}:\source\smoke.cpp",
                ),
                cwd=Path(rf"{drive}:\build"),
                environment=environment,
                timeout_seconds=60,
                log_path=log_root / "native-cl-smoke.log",
            ),
            windows_lineage_planner=binding,
        )
        assert compile_result.succeeded, compile_result.output_tail
        canonical_object = (build_root / "smoke.obj").read_bytes()
        canonical_pdb = (build_root / "smoke.pdb").read_bytes()
        dependency_result = supervisor.run(
            CommandSpec.create(
                (
                    rf"{drive}:\toolchain\bin\CL.EXE",
                    "/nologo",
                    "/c",
                    "/MD",
                    "/Zi",
                    rf"/Fo{drive}:\build\dependencies.obj",
                    rf"/Fd{drive}:\build\dependencies.pdb",
                    rf"/Fr{drive}:\build\dependencies.sbr",
                    rf"{drive}:\source\smoke.cpp",
                ),
                cwd=Path(rf"{drive}:\build"),
                environment=environment,
                timeout_seconds=60,
                log_path=log_root / "native-cl-dependencies-smoke.log",
            ),
            windows_lineage_planner=binding,
        )
        assert dependency_result.succeeded, dependency_result.output_tail
        resource_result = supervisor.run(
            CommandSpec.create(
                (
                    rf"{drive}:\toolchain\bin\RC.EXE",
                    rf"/fo{drive}:\build\smoke.res",
                    rf"{drive}:\source\smoke.rc",
                ),
                cwd=Path(rf"{drive}:\build"),
                environment=environment,
                timeout_seconds=60,
                log_path=log_root / "native-rc-smoke.log",
            ),
            windows_lineage_planner=binding,
        )
        link_result = supervisor.run(
            CommandSpec.create(
                (
                    rf"{drive}:\toolchain\bin\LINK.EXE",
                    "/nologo",
                    "/incremental:no",
                    "/subsystem:console",
                    rf"/out:{drive}:\build\smoke.exe",
                    rf"{drive}:\build\smoke.obj",
                    rf"{drive}:\build\smoke.res",
                ),
                cwd=Path(rf"{drive}:\build"),
                environment=environment,
                timeout_seconds=60,
                log_path=log_root / "native-link-smoke.log",
            ),
            windows_lineage_planner=binding,
        )

    object_path = build_root / "smoke.obj"
    pdb_path = build_root / "smoke.pdb"
    dependency_object_path = build_root / "dependencies.obj"
    dependency_pdb_path = build_root / "dependencies.pdb"
    dependency_sbr_path = build_root / "dependencies.sbr"
    resource_path = build_root / "smoke.res"
    executable_path = build_root / "smoke.exe"
    assert resource_result.succeeded, resource_result.output_tail
    assert link_result.succeeded, link_result.output_tail
    assert object_path.is_file() and not object_path.is_symlink()
    assert object_path.stat().st_size > 0
    assert pdb_path.is_file() and not pdb_path.is_symlink()
    assert dependency_object_path.is_file() and not dependency_object_path.is_symlink()
    assert dependency_pdb_path.is_file() and not dependency_pdb_path.is_symlink()
    assert dependency_sbr_path.is_file() and not dependency_sbr_path.is_symlink()
    assert object_path.read_bytes() == canonical_object
    assert pdb_path.read_bytes() == canonical_pdb
    trace = parse_msvc_sbr(dependency_sbr_path.read_bytes())
    assert trace.working_directory.casefold() == rf"{drive}:\build".casefold()
    assert PureWindowsPath(trace.sources[0].raw_path).name.casefold() == "smoke.cpp"
    assert trace.sources[0].parent_index is None
    assert not (build_root / "smoke.sbr").exists()
    assert resource_path.is_file() and resource_path.stat().st_size > 0
    assert executable_path.is_file() and executable_path.stat().st_size > 0
