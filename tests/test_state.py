from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from reprobit.cache import IncrementalCache, cache_key
from reprobit.state import KeepWorkspace, RunArena, StateError, StateStore, human_bytes


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


def test_state_status_and_gc_include_incremental_cache_leases(tmp_path: Path) -> None:
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
        result = StateStore(state).gc()
        assert result.cache_active_leases == 1
        assert result.cache_removed_records == 0
    result = StateStore(state).gc(dry_run=True)
    assert result.dry_run is True
    assert result.cache_removed_records == 1
    assert StateStore(state).status().cache_records == 1
    result = StateStore(state).gc()
    assert result.cache_removed_records == 1
    assert result.cache_removed_blobs == 1
    assert StateStore(state).status().cache_records == 0
