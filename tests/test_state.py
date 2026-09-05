from __future__ import annotations

import os
import shutil
import threading
import time
from pathlib import Path

import pytest

import reprobit.state as state_module
from reprobit.atomic_io import write_json_atomic
from reprobit.cache import IncrementalCache, cache_key
from reprobit.state import (
    KeepWorkspace,
    RunArena,
    StateStore,
    human_bytes,
    report_publication_lease,
)
from reprobit.state_lock import AdvisoryFileLock, StateError


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows directory handles")
def test_windows_initial_state_write_refuses_a_replaced_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directory = tmp_path / "arena"
    directory.mkdir()
    expected = state_module._real_directory_identity(directory, label="fixture arena")
    original = tmp_path / "original-arena"
    real_publish = state_module.atomic_publish_relative_if_current
    swapped = False

    def swap_before_open(
        root: Path,
        relative: str,
        payload: bytes,
        **options: object,
    ):
        nonlocal swapped
        if not swapped:
            swapped = True
            directory.rename(original)
            directory.mkdir()
            (directory / "valuable.txt").write_bytes(b"keep me")
        return real_publish(root, relative, payload, **options)

    monkeypatch.setattr(state_module, "atomic_publish_relative_if_current", swap_before_open)

    with pytest.raises(StateError, match="cannot securely create state record"):
        state_module._write_json_in_exact_directory(
            directory,
            expected,
            ".outcome.json",
            {"outcome": "interrupted"},
        )

    assert swapped
    assert (directory / "valuable.txt").read_bytes() == b"keep me"
    assert not (directory / ".outcome.json").exists()
    assert not (original / ".outcome.json").exists()


def test_locked_marker_is_read_through_its_own_held_handle(tmp_path: Path) -> None:
    marker = tmp_path / "marker.lock"
    marker.write_bytes(b"\0")

    lock = AdvisoryFileLock(marker, create=False)
    try:
        assert lock.acquire(nonblocking=False)
        assert lock.read_locked(maximum=1) == b"\0"
    finally:
        lock.close()


def test_lock_rejects_a_symlink_without_initializing_its_target(
    tmp_path: Path,
) -> None:
    target = tmp_path / "outside.lock"
    target.write_bytes(b"")
    marker = tmp_path / "marker.lock"
    try:
        marker.symlink_to(target)
    except OSError:
        pytest.skip("file symlinks are unavailable")

    with pytest.raises((OSError, StateError)):
        AdvisoryFileLock(marker)

    assert target.read_bytes() == b""


def test_run_arena_removes_success_and_retains_failure_by_default(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()

    with RunArena(state, kind="build", run_id="success") as arena:
        success_path = arena.path
        (arena.path / "payload.bin").write_bytes(b"payload")
    assert not success_path.exists()

    failure_path: Path
    with (
        pytest.raises(RuntimeError, match="failed"),
        RunArena(state, kind="verify", run_id="failure") as arena,
    ):
        failure_path = arena.path
        (arena.path / "diagnostic.log").write_text("failure", encoding="utf-8")
        raise RuntimeError("failed")
    assert failure_path.is_dir()
    status = StateStore(state).status()
    assert len(status.runs) == 1
    assert status.runs[0].outcome == "failed"
    assert not status.runs[0].active


def test_run_kind_cannot_be_ambiguous_with_its_identifier(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()

    with pytest.raises(StateError, match="invalid run kind"):
        RunArena(state, kind="project-grind")


def test_run_arena_retention_modes_are_explicit(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="build",
        run_id="kept",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        kept = arena.path
    assert kept.is_dir()

    removed: Path
    with (
        pytest.raises(KeyboardInterrupt),
        RunArena(
            state,
            kind="build",
            run_id="discarded",
            keep=KeepWorkspace.NEVER,
        ) as arena,
    ):
        removed = arena.path
        raise KeyboardInterrupt
    assert not removed.exists()


def test_run_arena_releases_lease_under_maintenance_gate_before_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    arena = RunArena(state, kind="build", run_id="lease-release")
    arena.__enter__()
    lease = arena._lease
    assert lease is not None and lease.locked
    real_close = lease.close
    real_move = state_module._move_to_quarantine
    released = False

    def close_under_gate() -> None:
        nonlocal released
        contender = AdvisoryFileLock(state / ".maintenance.lock", create=False)
        try:
            assert not contender.acquire(nonblocking=True)
        finally:
            contender.close()
        real_close()
        released = True

    def move_after_release(path: Path, quarantine: Path) -> None:
        assert released and lease.stream.closed
        real_move(path, quarantine)

    monkeypatch.setattr(lease, "close", close_under_gate)
    monkeypatch.setattr(state_module, "_move_to_quarantine", move_after_release)
    arena.finish(succeeded=True)

    assert released
    assert not arena.path.exists()


def test_run_arena_rechecks_identity_after_releasing_its_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    arena = RunArena(state, kind="build", run_id="lease-release-race")
    arena.__enter__()
    lease = arena._lease
    assert lease is not None
    real_close = lease.close
    original = arena.path.parent / "original-run"

    def swap_after_release() -> None:
        real_close()
        arena.path.rename(original)
        arena.path.mkdir()
        (arena.path / "valuable.txt").write_bytes(b"keep me")

    monkeypatch.setattr(lease, "close", swap_after_release)

    with pytest.raises(StateError, match="run arena changed before cleanup"):
        arena.finish(succeeded=True)

    assert lease.stream.closed
    assert (arena.path / "valuable.txt").read_bytes() == b"keep me"
    assert (original / ".outcome.json").is_file()


def test_run_arena_cleanup_preserves_a_directory_swapped_before_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    real_move = state_module._move_to_quarantine
    arena_path: Path | None = None
    original: Path | None = None
    swapped = False

    def swap_before_move(path: Path, quarantine: Path) -> None:
        nonlocal swapped
        if path == arena_path and not swapped:
            assert original is not None
            swapped = True
            real_move(path, original)
            path.mkdir()
            (path / "valuable.txt").write_bytes(b"keep me")
        real_move(path, quarantine)

    monkeypatch.setattr(state_module, "_move_to_quarantine", swap_before_move)

    with (
        pytest.raises(StateError, match="run arena changed during cleanup"),
        RunArena(state, kind="build", run_id="cleanup-race") as arena,
    ):
        arena_path = arena.path
        original = arena.path.parent / "original-run"

    assert swapped
    assert arena_path is not None
    assert original is not None
    quarantined = next(arena_path.parent.glob(f".{arena_path.name}.reprobit-remove-*"))
    assert (quarantined / "valuable.txt").read_bytes() == b"keep me"
    assert (original / ".outcome.json").is_file()


def test_run_arena_exit_refuses_a_replacement_at_its_active_path(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    arena = RunArena(
        state,
        kind="build",
        run_id="active-path-swap",
        keep=KeepWorkspace.NEVER,
    )
    arena.__enter__()
    original = arena.path.parent / "original-run"
    if os.name == "nt":
        # The live lease denies delete sharing on Windows, so the OS blocks
        # this replacement before the arena's exit-time identity check.
        owned = arena.path / "owned.txt"
        owned.write_bytes(b"owned")
        with pytest.raises(PermissionError):
            arena.path.rename(original)
        assert not original.exists()
        assert owned.read_bytes() == b"owned"
        arena.__exit__(None, None, None)
        assert not arena.path.exists()
        return
    arena.path.rename(original)
    arena.path.mkdir()
    sentinel = arena.path / "valuable.txt"
    sentinel.write_bytes(b"keep me")

    with pytest.raises(StateError, match="run arena changed before writing its outcome"):
        arena.__exit__(None, None, None)

    assert sentinel.read_bytes() == b"keep me"
    assert (original / ".outcome.json").is_file()


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX directory replacement")
def test_run_arena_finish_binds_outcome_publication_to_the_arena(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    arena = RunArena(
        state,
        kind="build",
        run_id="finish-seat-swap",
        keep=KeepWorkspace.ALWAYS,
    )
    arena.__enter__()
    outcome = arena.path / ".outcome.json"
    interrupted = outcome.read_bytes()
    replacement = arena.path.parent / "replacement-run"
    replacement.mkdir()
    os.link(outcome, replacement / outcome.name)
    (replacement / "valuable.txt").write_bytes(b"keep me")
    outcome_relative = outcome.relative_to(state).as_posix()
    _payload, arena._outcome_snapshot = state_module.read_relative_file(
        state,
        outcome_relative,
    )
    original = arena.path.parent / "original-run"
    real_publish = state_module.atomic_publish_relative_if_current
    swapped = False

    def swap_before_publish(
        root: Path,
        relative: str,
        payload: bytes,
        **options: object,
    ):
        nonlocal swapped
        if relative == outcome_relative and not swapped:
            swapped = True
            arena.path.rename(original)
            replacement.rename(arena.path)
        return real_publish(root, relative, payload, **options)

    monkeypatch.setattr(state_module, "atomic_publish_relative_if_current", swap_before_publish)

    with pytest.raises(StateError, match="changed before writing its outcome"):
        arena.finish(succeeded=True)

    assert swapped
    assert (arena.path / "valuable.txt").read_bytes() == b"keep me"
    assert (arena.path / ".outcome.json").read_bytes() == interrupted
    assert (original / ".outcome.json").read_bytes() == interrupted


def test_state_finds_and_cleans_a_retained_external_cmake_workspace(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="import",
        run_id="retained-cmake",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        arena_path = arena.path
        workspace = arena.create_cmake_workspace()
        (workspace / "large.bin").write_bytes(b"x" * 4096)

    assert workspace.is_dir()
    status = StateStore(state).status()
    assert status.runs[0].path == arena_path
    assert status.runs[0].bytes >= 4096
    assert status.runs[0].files >= 4

    result = StateStore(state).gc()

    assert result.removed == (arena_path,)
    assert result.reclaimed_bytes >= 4096
    assert not workspace.exists()
    assert not arena_path.exists()


def test_cmake_workspace_creation_failure_preserves_a_competing_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    temporary_root = tmp_path / "temporary"
    temporary_root.mkdir()
    monkeypatch.setattr(state_module.tempfile, "gettempdir", lambda: str(temporary_root))
    real_mkdir = Path.mkdir
    competitor: list[Path] = []

    def create_competitor_then_fail(
        path: Path,
        mode: int = 0o777,
        parents: bool = False,
        exist_ok: bool = False,
    ) -> None:
        if path.parent == temporary_root and path.name.startswith("rbit-cmake-"):
            real_mkdir(path, mode=mode, parents=parents, exist_ok=exist_ok)
            (path / "valuable.txt").write_bytes(b"keep me")
            competitor.append(path)
            raise FileExistsError(path)
        real_mkdir(path, mode=mode, parents=parents, exist_ok=exist_ok)

    monkeypatch.setattr(Path, "mkdir", create_competitor_then_fail)

    with RunArena(state, kind="import", run_id="creation-race") as arena:
        with pytest.raises(FileExistsError):
            arena.create_cmake_workspace()
        assert not (arena.path / ".cmake-workspace.json").exists()

    assert len(competitor) == 1
    assert (competitor[0] / "valuable.txt").read_bytes() == b"keep me"


def test_state_gc_refuses_a_markerless_cmake_workspace(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="import",
        run_id="markerless-cmake",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        arena_path = arena.path

    nonce = "a" * 32
    workspace = (tmp_path / f"rbit-cmake-{nonce}").resolve()
    workspace.mkdir()
    write_json_atomic(
        arena_path / ".cmake-workspace.json",
        {
            "schema": "reprobit.cmake-workspace.v1",
            "arena": str(arena_path.resolve(strict=True)),
            "workspace": str(workspace),
            "nonce": nonce,
        },
    )

    with pytest.raises(StateError, match="marker is missing"):
        StateStore(state).gc()

    assert workspace.is_dir()
    assert arena_path.is_dir()


def test_state_gc_refuses_to_remove_a_replaced_cmake_workspace(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    temporary_root = tmp_path / "temporary"
    temporary_root.mkdir()
    monkeypatch.setattr(state_module.tempfile, "gettempdir", lambda: str(temporary_root))
    with RunArena(
        state,
        kind="import",
        run_id="cleanup-race",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        arena_path = arena.path
        workspace = arena.create_cmake_workspace()

    original = temporary_root / "original-workspace"
    real_move = state_module._move_to_quarantine
    swapped = False

    def swap_before_move(path: Path, quarantine: Path) -> None:
        nonlocal swapped
        if path == workspace and not swapped:
            swapped = True
            real_move(workspace, original)
            workspace.mkdir()
            (workspace / "valuable.txt").write_bytes(b"keep me")
        real_move(path, quarantine)

    monkeypatch.setattr(state_module, "_move_to_quarantine", swap_before_move)

    with pytest.raises(StateError, match="changed during cleanup"):
        StateStore(state).gc()

    assert swapped
    quarantined = next(temporary_root.glob(f".{workspace.name}.reprobit-remove-*"))
    assert (quarantined / "valuable.txt").read_bytes() == b"keep me"
    assert (original / ".reprobit-cmake-workspace.json").is_file()
    assert arena_path.is_dir()


def test_owned_workspace_cleanup_refuses_a_new_pointer(tmp_path: Path, monkeypatch) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="import",
        run_id="late-pointer",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        arena_path = arena.path
    identity = state_module._real_directory_identity(arena_path, label="fixture arena")
    workspace = tmp_path / f"rbit-cmake-{'a' * 32}"
    real_record = state_module._owned_cmake_workspace_record
    injected = False

    def inject_pointer(path: Path):
        nonlocal injected
        if not injected:
            injected = True
            workspace.mkdir()
            ownership = {
                "schema": "reprobit.cmake-workspace.v1",
                "arena": str(arena_path.resolve()),
                "workspace": str(workspace.resolve()),
                "nonce": "a" * 32,
            }
            write_json_atomic(
                workspace / ".reprobit-cmake-workspace.json",
                ownership,
            )
            write_json_atomic(path / ".cmake-workspace.json", ownership)
        return real_record(path)

    monkeypatch.setattr(state_module, "_owned_cmake_workspace_record", inject_pointer)

    with pytest.raises(StateError, match="pointer changed before cleanup"):
        state_module._remove_owned_cmake_workspace(arena_path, identity)

    assert workspace.is_dir()
    assert (arena_path / ".cmake-workspace.json").is_file()


def test_owned_workspace_cleanup_preserves_a_replaced_pointer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="import",
        run_id="pointer-swap",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        workspace = arena.create_cmake_workspace()
        pointer = arena.path / ".cmake-workspace.json"
        original_pointer = arena.path / ".original-cmake-workspace.json"
        real_remove = state_module.remove_published_relative

        def swap_pointer(root: Path, relative: str, **kwargs: object) -> bool:
            pointer.rename(original_pointer)
            pointer.write_bytes(b"foreign pointer")
            return real_remove(root, relative, **kwargs)

        monkeypatch.setattr(state_module, "remove_published_relative", swap_pointer)
        with pytest.raises(StateError, match="pointer changed before cleanup"):
            arena.remove_cmake_workspace(workspace)

        assert pointer.read_bytes() == b"foreign pointer"
        assert original_pointer.is_file()


def test_owned_workspace_cleanup_checks_the_sealed_pointer_before_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="import",
        run_id="pointer-owner-swap",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        first_workspace = arena.create_cmake_workspace()
        pointer = arena.path / ".cmake-workspace.json"
        first_pointer = arena.path / ".first-cmake-workspace.json"
        second_nonce = "b" * 32
        second_workspace = tmp_path / f"rbit-cmake-{second_nonce}"
        second_workspace.mkdir()
        second_ownership = {
            "schema": "reprobit.cmake-workspace.v1",
            "arena": str(arena.path.resolve()),
            "workspace": str(second_workspace.resolve()),
            "nonce": second_nonce,
        }
        write_json_atomic(
            second_workspace / ".reprobit-cmake-workspace.json",
            second_ownership,
        )
        real_record = state_module._owned_cmake_workspace_record
        swapped = False

        def swap_owner(path: Path, **kwargs: object):
            nonlocal swapped
            if kwargs.get("pointer_payload") is not None and not swapped:
                swapped = True
                pointer.rename(first_pointer)
                write_json_atomic(pointer, second_ownership)
            return real_record(path, **kwargs)

        monkeypatch.setattr(state_module, "_owned_cmake_workspace_record", swap_owner)

        with pytest.raises(StateError, match="pointer changed before cleanup"):
            arena.remove_cmake_workspace(first_workspace)

        assert first_workspace.is_dir()
        assert second_workspace.is_dir()
        assert pointer.is_file()
        assert first_pointer.is_file()


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX directory replacement")
def test_owned_workspace_reseal_is_bound_to_the_arena(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    arena = RunArena(
        state,
        kind="import",
        run_id="pointer-seat-swap",
        keep=KeepWorkspace.ALWAYS,
    )
    arena.__enter__()
    workspace = arena.create_cmake_workspace()
    pointer = arena.path / ".cmake-workspace.json"
    replacement = arena.path.parent / "replacement-run"
    replacement.mkdir()
    os.link(pointer, replacement / pointer.name)
    (replacement / "valuable.txt").write_bytes(b"keep me")
    original = arena.path.parent / "original-run"
    real_reseal = state_module.reseal_relative_file
    swapped = False

    def swap_before_reseal(root: Path, relative: str, **options: object):
        nonlocal swapped
        if not swapped:
            swapped = True
            arena.path.rename(original)
            replacement.rename(arena.path)
        return real_reseal(root, relative, **options)

    monkeypatch.setattr(state_module, "reseal_relative_file", swap_before_reseal)

    with pytest.raises(StateError, match="pointer changed before cleanup"):
        arena.remove_cmake_workspace(workspace)

    assert swapped
    assert workspace.is_dir()
    assert (arena.path / "valuable.txt").read_bytes() == b"keep me"
    displaced = arena.path.parent / "replacement-after-test"
    arena.path.rename(displaced)
    original.rename(arena.path)
    arena.finish(succeeded=False)


def test_state_gc_checks_arena_identity_before_owned_workspace_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="import",
        run_id="arena-swap-before-workspace",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        arena_path = arena.path
        workspace = arena.create_cmake_workspace()
    original = arena_path.parent / "original-arena"
    real_remove = state_module._remove_owned_cmake_workspace
    swapped = False

    def swap_arena(path: Path, expected: tuple[int, int]) -> None:
        nonlocal swapped
        if not swapped:
            swapped = True
            path.rename(original)
            path.mkdir()
            (path / "valuable.txt").write_bytes(b"keep me")
        real_remove(path, expected)

    monkeypatch.setattr(state_module, "_remove_owned_cmake_workspace", swap_arena)

    with pytest.raises(StateError, match="run arena changed"):
        StateStore(state).gc()

    assert (arena_path / "valuable.txt").read_bytes() == b"keep me"
    assert workspace.is_dir()
    assert original.is_dir()


def test_state_gc_skips_a_live_lease_and_reclaims_completed_runs(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="build",
        run_id="completed",
        keep=KeepWorkspace.ALWAYS,
    ) as completed:
        completed_path = completed.path
        (completed.path / "large.bin").write_bytes(b"x" * 4096)

    with RunArena(
        state,
        kind="verify",
        run_id="active",
        keep=KeepWorkspace.ALWAYS,
    ) as active:
        result = StateStore(state).gc()
        assert result.removed == (completed_path,)
        assert result.reclaimed_bytes >= 4096
        assert result.skipped_active == (active.path,)
        assert active.path.is_dir()
    assert not completed_path.exists()


def test_state_gc_never_scans_an_active_arena(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="build",
        run_id="completed-scan",
        keep=KeepWorkspace.ALWAYS,
    ) as completed:
        completed_path = completed.path

    real_tree_usage = state_module._tree_usage
    with RunArena(
        state,
        kind="verify",
        run_id="active-scan",
        keep=KeepWorkspace.ALWAYS,
    ) as active:

        def guarded_tree_usage(path: Path) -> tuple[int, int, int]:
            assert path != active.path
            return real_tree_usage(path)

        monkeypatch.setattr(state_module, "_tree_usage", guarded_tree_usage)
        result = StateStore(state).gc()

    assert result.removed == (completed_path,)
    assert result.skipped_active == (active.path,)


def test_state_gc_does_not_create_or_refresh_a_missing_lease(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    abandoned = state / "runs" / "build-abandoned"
    abandoned.mkdir(parents=True)
    payload = abandoned / "payload.bin"
    payload.write_bytes(b"abandoned")
    old_seconds = time.time() - 3600
    os.utime(payload, (old_seconds, old_seconds))
    os.utime(abandoned, (old_seconds, old_seconds))
    before = {path: path.stat(follow_symlinks=False).st_mtime_ns for path in (abandoned, payload)}

    preview = StateStore(state).gc(older_than_seconds=1800, dry_run=True)

    assert preview.removed == (abandoned,)
    assert not (abandoned / ".lease").exists()
    assert {
        path: path.stat(follow_symlinks=False).st_mtime_ns for path in (abandoned, payload)
    } == before
    assert StateStore(state).gc(older_than_seconds=1800).removed == (abandoned,)
    assert not abandoned.exists()


def test_state_gc_collectors_share_one_close_to_remove_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="build",
        run_id="gc-race",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        arena_path = arena.path

    first_at_remove = threading.Event()
    release_first = threading.Event()
    second_attempted_gate = threading.Event()
    real_move = state_module._move_to_quarantine
    real_acquire = AdvisoryFileLock.acquire

    def paused_move(source: Path, quarantine: Path) -> None:
        if source == arena_path and threading.current_thread().name == "gc-first":
            first_at_remove.set()
            assert release_first.wait(5)
        real_move(source, quarantine)

    def observed_acquire(
        lock: AdvisoryFileLock,
        *,
        nonblocking: bool,
    ) -> bool:
        if lock.path.name == ".maintenance.lock" and threading.current_thread().name == "gc-second":
            second_attempted_gate.set()
        return real_acquire(lock, nonblocking=nonblocking)

    monkeypatch.setattr(state_module, "_move_to_quarantine", paused_move)
    monkeypatch.setattr(AdvisoryFileLock, "acquire", observed_acquire)
    results: dict[str, object] = {}

    def collect(name: str) -> None:
        try:
            results[name] = StateStore(state).gc()
        except BaseException as exc:  # pragma: no cover - asserted below
            results[name] = exc

    first = threading.Thread(target=collect, args=("first",), name="gc-first")
    second = threading.Thread(target=collect, args=("second",), name="gc-second")
    first.start()
    assert first_at_remove.wait(5)
    second.start()
    try:
        assert second_attempted_gate.wait(5)
        assert second.is_alive()
        assert (arena_path / ".lease").is_file()
    finally:
        release_first.set()
        first.join(5)
        second.join(5)

    assert not first.is_alive()
    assert not second.is_alive()
    first_result = results["first"]
    second_result = results["second"]
    assert isinstance(first_result, state_module.GCResult)
    assert isinstance(second_result, state_module.GCResult)
    assert first_result.removed == (arena_path,)
    assert second_result.removed == ()
    assert not arena_path.exists()


def test_run_arena_creation_holds_the_state_maintenance_gate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    creator_at_prelease = threading.Event()
    release_creator = threading.Event()
    arena_active = threading.Event()
    finish_arena = threading.Event()
    gc_attempted_gate = threading.Event()
    gc_finished = threading.Event()
    real_init = AdvisoryFileLock.__init__
    real_acquire = AdvisoryFileLock.acquire
    result: list[object] = []

    def paused_init(
        lock: AdvisoryFileLock,
        path: Path,
        *,
        create: bool = True,
    ) -> None:
        if path.name == ".lease" and threading.current_thread().name == "creator":
            creator_at_prelease.set()
            assert release_creator.wait(5)
        real_init(lock, path, create=create)

    def observed_acquire(
        lock: AdvisoryFileLock,
        *,
        nonblocking: bool,
    ) -> bool:
        if (
            lock.path.name == ".maintenance.lock"
            and threading.current_thread().name == "gc-during-create"
        ):
            gc_attempted_gate.set()
        return real_acquire(lock, nonblocking=nonblocking)

    monkeypatch.setattr(AdvisoryFileLock, "__init__", paused_init)
    monkeypatch.setattr(AdvisoryFileLock, "acquire", observed_acquire)

    def create_arena() -> None:
        with RunArena(
            state,
            kind="build",
            run_id="creation-race",
            keep=KeepWorkspace.ALWAYS,
        ):
            arena_active.set()
            assert finish_arena.wait(5)

    def collect() -> None:
        try:
            result.append(StateStore(state).gc())
        except BaseException as exc:  # pragma: no cover - asserted below
            result.append(exc)
        finally:
            gc_finished.set()

    creator = threading.Thread(target=create_arena, name="creator")
    gc_thread = threading.Thread(target=collect, name="gc-during-create")
    creator.start()
    assert creator_at_prelease.wait(5)
    gc_thread.start()
    try:
        assert gc_attempted_gate.wait(5)
        assert not gc_finished.is_set()
        release_creator.set()
        assert arena_active.wait(5)
        assert gc_finished.wait(5)
    finally:
        release_creator.set()
        finish_arena.set()
        creator.join(5)
        gc_thread.join(5)

    assert not creator.is_alive()
    assert not gc_thread.is_alive()
    assert len(result) == 1
    gc_result = result[0]
    assert isinstance(gc_result, state_module.GCResult)
    assert gc_result.skipped_active == (state / "runs" / "build-creation-race",)


def test_state_gc_honors_age_and_never_follows_run_symlinks(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="build",
        run_id="recent",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        recent = arena.path
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("keep", encoding="utf-8")
    (state / "runs" / "build-symlink").symlink_to(outside, target_is_directory=True)

    result = StateStore(state).gc(older_than_seconds=60)
    assert result.removed == ()
    assert result.skipped_recent == (recent,)
    assert (outside / "keep.txt").read_text(encoding="utf-8") == "keep"


def test_status_is_read_only_for_legacy_runs_without_a_lease(tmp_path: Path) -> None:
    state = tmp_path / "state"
    legacy = state / "runs" / "build-legacy"
    legacy.mkdir(parents=True)
    (legacy / "artifact.bin").write_bytes(b"abc")
    before = tuple(legacy.iterdir())

    status = StateStore(state).status()

    assert tuple(legacy.iterdir()) == before
    assert status.run_bytes == 3
    assert status.run_files == 1
    assert status.runs[0].outcome == "incomplete"


def test_status_and_explicit_gc_account_for_only_managed_reports(tmp_path: Path) -> None:
    state = tmp_path / "state"
    reports = state / "reports"
    grind = reports / "grind" / "project"
    grind.mkdir(parents=True)
    canonical_html = reports / "report.html"
    canonical_json = reports / "report.json"
    grind_report = grind / "report.html"
    unmanaged = reports / "notes.txt"
    canonical_html.write_bytes(b"html")
    canonical_json.write_bytes(b"json!")
    grind_report.write_bytes(b"grind!")
    unmanaged.write_bytes(b"keep me")

    status = StateStore(state).status()

    assert status.report_files == 3
    assert status.report_bytes == 15
    assert status.total_files == 3
    assert status.total_bytes == 15
    assert StateStore(state).gc().report_files == 0
    assert canonical_html.is_file()
    assert canonical_json.is_file()
    assert grind_report.is_file()

    preview = StateStore(state).gc(dry_run=True, include_reports=True)
    assert preview.reports_removed == (canonical_html, canonical_json, reports / "grind")
    assert preview.report_files == 3
    assert preview.report_bytes == 15
    assert preview.reclaimed_bytes == 15
    assert canonical_html.is_file()
    assert grind_report.is_file()

    result = StateStore(state).gc(include_reports=True)
    assert result.reports_removed == preview.reports_removed
    assert result.report_files == 3
    assert result.reclaimed_bytes == 15
    assert not canonical_html.exists()
    assert not canonical_json.exists()
    assert not (reports / "grind").exists()
    assert unmanaged.read_bytes() == b"keep me"
    assert StateStore(state).status().report_files == 0


def test_report_cleanup_waits_for_an_active_publication_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    report = state / "reports/report.json"
    report.parent.mkdir(parents=True)
    report.write_bytes(b"report")
    cleanup_attempted = threading.Event()
    cleanup_finished = threading.Event()
    real_acquire = AdvisoryFileLock.acquire
    result: list[object] = []

    def observed_acquire(
        lock: AdvisoryFileLock,
        *,
        nonblocking: bool,
    ) -> bool:
        if (
            lock.path == state / ".maintenance.lock"
            and threading.current_thread().name == "report-cleanup"
        ):
            cleanup_attempted.set()
        return real_acquire(lock, nonblocking=nonblocking)

    monkeypatch.setattr(AdvisoryFileLock, "acquire", observed_acquire)

    def clean() -> None:
        try:
            result.append(StateStore(state).gc(include_reports=True))
        except BaseException as exc:  # pragma: no cover - asserted below
            result.append(exc)
        finally:
            cleanup_finished.set()

    thread = threading.Thread(target=clean, name="report-cleanup")
    with report_publication_lease(state):
        thread.start()
        assert cleanup_attempted.wait(5)
        assert not cleanup_finished.is_set()
        assert report.is_file()
    thread.join(5)

    assert not thread.is_alive()
    assert len(result) == 1
    cleanup = result[0]
    assert isinstance(cleanup, state_module.GCResult)
    assert cleanup.reports_removed == (report,)
    assert not report.exists()


def test_status_rejects_a_redirected_reports_root(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (state / "reports").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")

    with pytest.raises(StateError, match="reports root is not a real directory"):
        StateStore(state).status()


def test_status_skips_an_arena_removed_during_its_usage_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="build",
        run_id="vanishing",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        arena_path = arena.path

    real_tree_usage = state_module._tree_usage

    def remove_then_inspect(path: Path) -> tuple[int, int, int]:
        if path == arena_path:
            shutil.rmtree(path)
        return real_tree_usage(path)

    monkeypatch.setattr(state_module, "_tree_usage", remove_then_inspect)

    status = StateStore(state).status()

    assert status.runs == ()


def test_state_rejects_unsafe_roots_and_formats_bytes(tmp_path: Path) -> None:
    with pytest.raises(StateError, match="absolute"):
        StateStore(Path("relative"))
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    try:
        alias.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    with pytest.raises(StateError, match="real directory"):
        StateStore(alias)
    assert human_bytes(0) == "0 B"
    assert human_bytes(1536) == "1.5 KiB"


@pytest.mark.skipif(os.name == "nt", reason="POSIX mtime test uses nanosecond utime")
def test_state_gc_reclaims_only_runs_older_than_cutoff(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    with RunArena(
        state,
        kind="build",
        run_id="old",
        keep=KeepWorkspace.ALWAYS,
    ) as arena:
        old = arena.path
    old_time = time.time_ns() - 3_600_000_000_000
    for path in (old, *old.iterdir()):
        os.utime(path, ns=(old_time, old_time), follow_symlinks=False)

    result = StateStore(state).gc(older_than_seconds=1800)
    assert result.removed == (old,)


def test_state_gc_preserves_cache_by_default_and_explicit_gc_honors_leases(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "output.obj"
    source.write_bytes(b"cached output")
    cache = IncrementalCache(state, implementation="state-test-v1")
    key = cache_key(
        "producer",
        {"node": "compile"},
        implementation="state-test-v1",
    )
    with cache.lease() as lease:
        lease.store("producer", key, {"build/output.obj": source})
        status = StateStore(state).status()
        assert status.cache_records == 1
        assert status.cache_blobs == 1
        assert status.cache_active_leases == 1
        result = StateStore(state).gc(include_cache=True)
        assert result.cache_active_leases == 1
        assert result.cache_removed_records == 0
    result = StateStore(state).gc()
    assert result.cache_removed_records == 0
    assert StateStore(state).status().cache_records == 1
    result = StateStore(state).gc(dry_run=True, include_cache=True)
    assert result.dry_run is True
    assert result.cache_removed_records == 1
    assert StateStore(state).status().cache_records == 1
    result = StateStore(state).gc(include_cache=True)
    assert result.cache_removed_records == 1
    assert result.cache_removed_blobs == 1
    assert StateStore(state).status().cache_records == 0


def test_state_gc_cache_cleanup_also_removes_the_probe_store(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    probe_store = state / "repair-probes" / "v1" / "ab"
    probe_store.mkdir(parents=True)
    (probe_store / "abcd.bin").write_bytes(b"x" * 100)

    status = StateStore(state).status()
    assert status.cache_bytes == 0
    assert status.cache_files == 0
    assert status.repair_probe_cache_bytes == 100
    assert status.repair_probe_cache_files == 1
    assert status.total_bytes == 100
    assert status.total_files == 1

    preview = StateStore(state).gc(dry_run=True, include_cache=True)
    assert (state / "repair-probes").is_dir()
    assert preview.reclaimed_bytes == status.repair_probe_cache_bytes
    assert preview.repair_probe_cache_files == status.repair_probe_cache_files
    assert preview.repair_probe_cache_bytes == status.repair_probe_cache_bytes
    assert preview.removed == ()

    kept = StateStore(state).gc()
    assert (state / "repair-probes").is_dir()
    assert kept.reclaimed_bytes == 0

    result = StateStore(state).gc(include_cache=True)
    assert not (state / "repair-probes").exists()
    assert result.reclaimed_bytes == status.repair_probe_cache_bytes
    assert result.repair_probe_cache_files == status.repair_probe_cache_files
    assert result.repair_probe_cache_bytes == status.repair_probe_cache_bytes
    assert result.removed == ()


def test_state_status_counts_the_persistent_repair_ledger(tmp_path: Path) -> None:
    state = tmp_path / "state"
    ledger = state / "ledger" / "composed-bodies.json"
    ledger.parent.mkdir(parents=True)
    ledger.write_bytes(b"ledger")

    status = StateStore(state).status()

    assert status.repair_ledger_bytes == 6
    assert status.repair_ledger_files == 1
    assert status.total_bytes == 6
    assert status.total_files == 1
