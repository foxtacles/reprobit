from __future__ import annotations

import os
import shutil
import threading
import time
from pathlib import Path

import pytest

import reprobit.state as state_module
from reprobit.cache import IncrementalCache, cache_key
from reprobit.state import (
    KeepWorkspace,
    RunArena,
    StateStore,
    human_bytes,
)
from reprobit.state_lock import AdvisoryFileLock, StateError


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
    os.utime(payload, (old_seconds, old_seconds), follow_symlinks=False)
    os.utime(abandoned, (old_seconds, old_seconds), follow_symlinks=False)
    before = {
        path: path.stat(follow_symlinks=False).st_mtime_ns
        for path in (abandoned, payload)
    }

    preview = StateStore(state).gc(older_than_seconds=1800, dry_run=True)

    assert preview.removed == (abandoned,)
    assert not (abandoned / ".lease").exists()
    assert {
        path: path.stat(follow_symlinks=False).st_mtime_ns
        for path in (abandoned, payload)
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
    real_rmtree = shutil.rmtree
    real_acquire = AdvisoryFileLock.acquire

    def paused_rmtree(path: Path) -> None:
        if Path(path) == arena_path and threading.current_thread().name == "gc-first":
            first_at_remove.set()
            assert release_first.wait(5)
        real_rmtree(path)

    def observed_acquire(
        lock: AdvisoryFileLock,
        *,
        nonblocking: bool,
    ) -> bool:
        if (
            lock.path.name == ".maintenance.lock"
            and threading.current_thread().name == "gc-second"
        ):
            second_attempted_gate.set()
        return real_acquire(lock, nonblocking=nonblocking)

    monkeypatch.setattr(shutil, "rmtree", paused_rmtree)
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
    assert gc_result.skipped_active == (
        state / "runs" / "build-creation-race",
    )


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
