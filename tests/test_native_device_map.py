from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path, PureWindowsPath
from typing import Any

import pytest

from reprobit.backends import NativeWindowsBackend
from reprobit.classic_includes import parse_msvc_sbr
from reprobit.native_device_map import (
    NativeDeviceMapError,
    NativeDeviceMapLease,
    _NativeApi,
    _ProcessDeviceMapInformation,
    _ProcessDeviceMapQuery,
    _ProcessDeviceMapSet,
    probe_native_device_map,
    probe_native_device_map_execution,
)
from reprobit.paths import LogicalPathSkeleton, LogicalSeat
from reprobit.process import CommandSpec, ProcessSupervisor

_WINDOWS = os.name == "nt"
_CREATE_SUSPENDED = 0x00000004
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_DDD_RAW_TARGET_PATH = 0x00000001
_DDD_REMOVE_DEFINITION = 0x00000002
_DDD_EXACT_MATCH_ON_REMOVE = 0x00000004
_DDD_NO_BROADCAST_SYSTEM = 0x00000008


def test_process_device_map_binding_passes_the_complete_native_union() -> None:
    assert ctypes.sizeof(_ProcessDeviceMapSet) == ctypes.sizeof(ctypes.c_void_p)
    assert ctypes.sizeof(_ProcessDeviceMapQuery) == 36
    assert ctypes.sizeof(_ProcessDeviceMapInformation) == 40
    assert _ProcessDeviceMapInformation.Set.offset == 0
    assert _ProcessDeviceMapInformation.Query.offset == 0
    calls: list[tuple[int, int]] = []
    api = object.__new__(_NativeApi)

    def set_information(
        _process: object,
        _information_class: int,
        _information: object,
        length: int,
    ) -> int:
        information = ctypes.cast(
            _information,
            ctypes.POINTER(_ProcessDeviceMapInformation),
        ).contents
        calls.append((int(information.Set.DirectoryHandle), length))
        return 0

    api.NtSetInformationProcess = set_information
    api.set_process_map(1, 2)

    assert calls == [(2, ctypes.sizeof(_ProcessDeviceMapInformation))]


def test_native_device_map_rejects_non_letter_drive() -> None:
    with pytest.raises(NativeDeviceMapError, match="one ASCII letter"):
        NativeDeviceMapLease(Path.cwd(), "RR")


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
    pytest.skip("Windows runner has no free logical drive")


def _handle_count() -> int:
    kernel32 = _kernel32()
    count = ctypes.c_uint32()
    if not kernel32.GetProcessHandleCount(
        kernel32.GetCurrentProcess(), ctypes.byref(count)
    ):
        raise OSError(int(ctypes.get_last_error()), "GetProcessHandleCount failed")
    return int(count.value)


def _resume(process: subprocess.Popen[str]) -> None:
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtResumeProcess.argtypes = [ctypes.c_void_p]
    ntdll.NtResumeProcess.restype = ctypes.c_int32
    native_process: Any = process
    status = int(ntdll.NtResumeProcess(ctypes.c_void_p(int(native_process._handle))))
    if status < 0:
        process.kill()
        process.wait(timeout=5)
        raise OSError(status & 0xFFFFFFFF, "NtResumeProcess failed")


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows Object Manager")
def test_native_device_map_feature_probe_is_harmless() -> None:
    probe = probe_native_device_map()
    assert probe.available, probe.detail


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows Object Manager")
def test_native_device_map_restores_on_failure_without_handle_leak(
    tmp_path: Path,
) -> None:
    assert probe_native_device_map().available
    drive = _free_drive()
    root = tmp_path / "private-root"
    root.mkdir()
    (root / "marker.txt").write_text("private", encoding="utf-8")
    host_probe = Path(sys.executable)
    before = _handle_count()
    installed_target: str | None = None

    with (
        pytest.raises(RuntimeError, match="producer failed"),
        NativeDeviceMapLease(root, drive),
    ):
        installed_target = _query_drive(drive)
        assert installed_target is not None
        assert Path(rf"{drive}:\marker.txt").read_text(encoding="utf-8") == "private"
        assert host_probe.is_file()
        raise RuntimeError("producer failed")

    assert _query_drive(drive) != installed_target
    assert host_probe.is_file()
    assert _handle_count() == before


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows Object Manager")
def test_native_device_map_rejects_an_existing_host_drive(tmp_path: Path) -> None:
    system_root = Path(os.environ["SYSTEMROOT"])
    occupied = system_root.drive.rstrip(":")
    assert occupied and _query_drive(occupied) is not None
    root = tmp_path / "private-root"
    root.mkdir()

    with (
        pytest.raises(NativeDeviceMapError, match="already mapped"),
        NativeDeviceMapLease(root, occupied),
    ):
        raise AssertionError("occupied drive must not be admitted")


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows Object Manager")
def test_suspended_child_receives_private_map_before_first_instruction(
    tmp_path: Path,
) -> None:
    drive = _free_drive()
    root = tmp_path / "private-root"
    root.mkdir()
    (root / "marker.txt").write_text("child-private", encoding="utf-8")
    script = (
        "from pathlib import Path; "
        f"print(Path(r'{drive}:\\marker.txt').read_text(encoding='utf-8'))"
    )

    installed_target: str | None = None
    with NativeDeviceMapLease(root, drive) as lease:
        installed_target = _query_drive(drive)
        assert installed_target is not None
        child = subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            creationflags=_CREATE_SUSPENDED | _CREATE_NEW_PROCESS_GROUP,
        )
        try:
            native_child: Any = child
            lease.assign_to_suspended_process(int(native_child._handle))
            _resume(child)
            output, _ = child.communicate(timeout=20)
        except BaseException:
            child.kill()
            child.wait(timeout=5)
            raise

    assert child.returncode == 0, output
    assert output.strip() == "child-private"
    assert _query_drive(drive) != installed_target


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows Object Manager")
def test_supervised_child_passes_private_map_to_its_descendant(
    tmp_path: Path,
) -> None:
    """Gate the exact direct-assignment plus producer-descendant lifecycle."""

    drive = _free_drive()
    root = tmp_path / "private-root"
    root.mkdir()
    (root / "marker.txt").write_text("descendant-private", encoding="utf-8")
    grandchild = (
        "from pathlib import Path; "
        f"print(Path(r'{drive}:\\marker.txt').read_text(encoding='utf-8'))"
    )
    child = textwrap.dedent(
        f"""
        import subprocess
        import sys

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
            suspended_process_initializer=lease.assign_to_suspended_process,
        )

    assert result.output.strip() == b"descendant-private"


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
        "extern \"C\" int main(void) { return 0; }\n",
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
            suspended_process_initializer=binding.assign_to_suspended_process,
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
            suspended_process_initializer=binding.assign_to_suspended_process,
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
            suspended_process_initializer=binding.assign_to_suspended_process,
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
            suspended_process_initializer=binding.assign_to_suspended_process,
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


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows Object Manager")
def test_automatic_child_and_grandchild_visibility_is_release_gated(
    tmp_path: Path,
) -> None:
    """Record whether an unassigned direct child happens to inherit the map.

    The backend never relies on this behavior: it assigns every direct child
    while suspended.  Its strict process-lineage gate separately proves that
    an assigned producer passes the map to its own descendants.
    """

    drive = _free_drive()
    root = tmp_path / "private-root"
    root.mkdir()
    (root / "marker.txt").write_text("descendant-private", encoding="utf-8")
    grandchild = (
        "from pathlib import Path; "
        f"print(Path(r'{drive}:\\marker.txt').read_text(encoding='utf-8'))"
    )
    child = textwrap.dedent(
        f"""
        import subprocess
        import sys

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

    with NativeDeviceMapLease(root, drive):
        result = subprocess.run(
            [sys.executable, "-c", child],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=20,
        )
    if result.returncode != 0 or result.stdout.strip() != "descendant-private":
        pytest.xfail(
            "an unassigned direct child did not inherit the controller's DeviceMap; "
            "the backend's suspended-child assignment remains required"
        )


_PEER_PROGRAM = textwrap.dedent(
    r"""
    import ctypes
    import json
    import sys

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.QueryDosDeviceW.argtypes = [
        ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32
    ]
    kernel32.QueryDosDeviceW.restype = ctypes.c_uint32
    kernel32.DefineDosDeviceW.argtypes = [
        ctypes.c_uint32, ctypes.c_wchar_p, ctypes.c_wchar_p
    ]
    kernel32.DefineDosDeviceW.restype = ctypes.c_int

    def query(device):
        buffer = ctypes.create_unicode_buffer(32767)
        ctypes.set_last_error(0)
        if kernel32.QueryDosDeviceW(device, buffer, len(buffer)):
            return buffer.value
        error = ctypes.get_last_error()
        if error in (2, 3):
            return None
        raise OSError(error, "QueryDosDeviceW failed")

    for raw in sys.stdin:
        command = json.loads(raw)
        try:
            if command["op"] == "query":
                result = query(command["device"])
            elif command["op"] == "map":
                flags = 0x1 | 0x8
                if not kernel32.DefineDosDeviceW(
                    flags, command["device"], command["target"]
                ):
                    raise OSError(ctypes.get_last_error(), "DefineDosDeviceW failed")
                result = query(command["device"])
            elif command["op"] == "remove":
                flags = 0x1 | 0x2 | 0x4 | 0x8
                if not kernel32.DefineDosDeviceW(
                    flags, command["device"], command["target"]
                ):
                    raise OSError(ctypes.get_last_error(), "DefineDosDeviceW removal failed")
                result = query(command["device"])
            elif command["op"] == "exit":
                print(json.dumps({"ok": True, "result": None}), flush=True)
                break
            else:
                raise ValueError("unknown operation")
            print(json.dumps({"ok": True, "result": result}), flush=True)
        except BaseException as error:
            print(json.dumps({"ok": False, "error": repr(error)}), flush=True)
    """
)


def _peer_request(peer: subprocess.Popen[str], request: dict[str, str]) -> str | None:
    assert peer.stdin is not None and peer.stdout is not None
    peer.stdin.write(json.dumps(request) + "\n")
    peer.stdin.flush()
    response = json.loads(peer.stdout.readline())
    if not response["ok"]:
        raise AssertionError(response["error"])
    result = response["result"]
    assert result is None or isinstance(result, str)
    return result


@pytest.mark.skipif(not _WINDOWS, reason="requires native Windows Object Manager")
def test_peer_cannot_observe_or_transiently_remap_private_drive(
    tmp_path: Path,
) -> None:
    drive = _free_drive()
    device = f"{drive}:"
    root = tmp_path / "private-root"
    decoy = tmp_path / "peer-decoy"
    root.mkdir()
    decoy.mkdir()
    (root / "marker.txt").write_text("private", encoding="utf-8")
    (decoy / "marker.txt").write_text("peer", encoding="utf-8")
    peer_target = rf"\??\{decoy}"

    # Start the peer before installing the process-private map so it remains in
    # the ordinary logon-session DOS namespace.
    peer = subprocess.Popen(
        [sys.executable, "-c", _PEER_PROGRAM],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    peer_mapped = False
    installed_target: str | None = None
    try:
        with NativeDeviceMapLease(root, drive):
            installed_target = _query_drive(drive)
            assert installed_target is not None
            peer_initial = _peer_request(peer, {"op": "query", "device": device})
            if peer_initial is not None:
                pytest.skip(f"logical drive raced with external mapping: {peer_initial}")
            observed = _peer_request(
                peer,
                {
                    "op": "map",
                    "device": device,
                    "target": peer_target,
                },
            )
            peer_mapped = True
            assert observed == peer_target
            assert Path(rf"{drive}:\marker.txt").read_text(encoding="utf-8") == "private"
            assert _query_drive(drive) == installed_target
            assert (
                _peer_request(
                    peer,
                    {
                        "op": "remove",
                        "device": device,
                        "target": peer_target,
                    },
                )
                is None
            )
            peer_mapped = False
            assert Path(rf"{drive}:\marker.txt").read_text(encoding="utf-8") == "private"
    finally:
        if peer_mapped and peer.poll() is None:
            _peer_request(
                peer,
                {
                    "op": "remove",
                    "device": device,
                    "target": peer_target,
                },
            )
        if peer.poll() is None:
            _peer_request(peer, {"op": "exit", "device": device})
        try:
            peer.wait(timeout=10)
        except subprocess.TimeoutExpired:
            peer.kill()
            peer.wait(timeout=5)

    assert peer.returncode == 0
    assert _query_drive(drive) != installed_target
