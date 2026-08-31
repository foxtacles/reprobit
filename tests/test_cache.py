from __future__ import annotations

import os
import re
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest

import reprobit.cache as cache_module
import reprobit.secure_paths as secure_paths
from reprobit.cache import (
    CacheError,
    CachePoisonError,
    CacheRecord,
    IncrementalCache,
    cache_key,
)


def _key(value: str, *, implementation: str = "test-implementation-v1") -> str:
    return cache_key(
        "producer",
        {"node": value},
        implementation=implementation,
    )


def _hold_posix_unlink_until_competing_observation(
    monkeypatch: pytest.MonkeyPatch,
    *,
    matches_name: Callable[[str], bool],
    observation: Literal["read", "stat"] = "read",
) -> tuple[threading.Event, threading.Event, threading.Event]:
    unlink_started = threading.Event()
    observation_started = threading.Event()
    unlink_finished = threading.Event()
    publication_identity: tuple[int, int] | None = None
    original_unlink = secure_paths.os.unlink
    original_read = secure_paths.os.read
    original_fstat = secure_paths.os.fstat

    def unlink_after_competing_read_opens(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal publication_identity
        name = os.fsdecode(path)
        candidate = (
            os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
            if dir_fd is not None and matches_name(name)
            else None
        )
        if not unlink_started.is_set() and candidate is not None and candidate.st_nlink == 2:
            publication_identity = (candidate.st_dev, candidate.st_ino)
            unlink_started.set()
            if not observation_started.wait(timeout=5):
                raise RuntimeError("competing cache validation did not begin")
            try:
                original_unlink(path, dir_fd=dir_fd)
            finally:
                unlink_finished.set()
            return
        if dir_fd is None:
            original_unlink(path)
        else:
            original_unlink(path, dir_fd=dir_fd)

    def read_after_staging_unlink(fd: int, size: int) -> bytes:
        metadata = original_fstat(fd)
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            observation == "read"
            and unlink_started.is_set()
            and not unlink_finished.is_set()
            and identity == publication_identity
        ):
            observation_started.set()
            if not unlink_finished.wait(timeout=5):
                raise RuntimeError("winning cache publication did not settle")
        return original_read(fd, size)

    def stat_across_staging_unlink(fd: int) -> os.stat_result:
        metadata = original_fstat(fd)
        identity = (metadata.st_dev, metadata.st_ino)
        if (
            observation == "stat"
            and unlink_started.is_set()
            and not unlink_finished.is_set()
            and identity == publication_identity
        ):
            observation_started.set()
            if not unlink_finished.wait(timeout=5):
                raise RuntimeError("winning cache publication did not settle")
            # Return the deliberately stale pre-unlink metadata once.  The
            # named entry now has a newer ctime, forcing the strict probe to
            # reject this observation and exercise its bounded retry.
        return metadata

    monkeypatch.setattr(secure_paths.os, "unlink", unlink_after_competing_read_opens)
    if observation == "read":
        monkeypatch.setattr(secure_paths.os, "read", read_after_staging_unlink)
    else:
        monkeypatch.setattr(secure_paths.os, "fstat", stat_across_staging_unlink)
    return unlink_started, observation_started, unlink_finished


def _pause_posix_publication_before_link(
    monkeypatch: pytest.MonkeyPatch,
    *,
    matches_name: Callable[[str], bool],
) -> tuple[threading.Event, threading.Event]:
    link_started = threading.Event()
    release_link = threading.Event()
    original_link = secure_paths.os.link

    def pause_matching_link(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        if not link_started.is_set() and matches_name(os.fsdecode(source)):
            link_started.set()
            if not release_link.wait(timeout=5):
                raise RuntimeError("paused cache publication was not released")
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(secure_paths.os, "link", pause_matching_link)
    return link_started, release_link


def _store_concurrently(
    cache: IncrementalCache,
    key: str,
    source: Path,
) -> tuple[list[CacheRecord], list[BaseException]]:
    barrier = threading.Barrier(2)
    records: list[CacheRecord] = []
    errors: list[BaseException] = []

    def publish() -> None:
        try:
            with cache.lease() as lease:
                barrier.wait(timeout=5)
                records.append(lease.store("producer", key, {"build/a.obj": source}))
        except BaseException as exc:  # pragma: no cover - asserted by the caller
            errors.append(exc)

    threads = [threading.Thread(target=publish) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)
    return records, errors


def test_cache_round_trip_restores_by_copy_and_preserves_source(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "source.obj"
    source.write_bytes(b"object bytes")
    source.chmod(0o700)
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    key = _key("compile.a")

    with cache.lease() as lease:
        stored = lease.store(
            "producer",
            key,
            {"build/a.obj": source},
            metadata={"trace": ["source/a.cpp", "toolchain/include/a.h"]},
        )
        assert lease.lookup("producer", key) == stored
        restore_root = tmp_path / "restore"
        restore_root.mkdir()
        destination = restore_root / "build" / "a.obj"
        lease.restore(
            stored,
            {"build/a.obj": destination},
            allowed_root=restore_root,
        )

    assert destination.read_bytes() == b"object bytes"
    assert destination.stat().st_ino != source.stat().st_ino
    blob = (
        state
        / "cache"
        / "v1"
        / "blobs"
        / "sha256"
        / stored.outputs[0].digest[:2]
        / stored.outputs[0].digest
    )
    assert destination.stat().st_ino != blob.stat().st_ino
    destination.write_bytes(b"local mutation")
    source.write_bytes(b"source mutation")
    with cache.lease() as lease:
        assert lease.lookup("producer", key) == stored


@pytest.mark.parametrize("settlement", ("before_after", "after_terminal"))
@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link publication regression")
def test_cache_restore_accepts_content_authorized_staging_link_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    settlement: str,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "source.obj"
    source.write_bytes(b"stable")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    with cache.lease() as lease:
        record = lease.store("producer", _key(settlement), {"build/a.obj": source})
    output = record.outputs[0]
    blob = state / "cache" / "v1" / "blobs" / "sha256" / output.digest[:2] / output.digest
    pending = state / "cache" / "v1" / "incoming" / f"pending-{settlement}"
    os.link(blob, pending)
    blob_identity = (blob.stat().st_dev, blob.stat().st_ino)
    settled = threading.Event()
    original_fstat = secure_paths.os.fstat
    original_stat = secure_paths.os.stat
    source_fstats = 0
    source_stats = 0

    def settle_before_after(fd: int) -> os.stat_result:
        nonlocal source_fstats
        metadata = original_fstat(fd)
        if (metadata.st_dev, metadata.st_ino) == blob_identity:
            source_fstats += 1
            if settlement == "before_after" and source_fstats == 3:
                pending.unlink()
                settled.set()
                metadata = original_fstat(fd)
        return metadata

    def settle_after_terminal(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        nonlocal source_stats
        if dir_fd is None:
            metadata = original_stat(path, follow_symlinks=follow_symlinks)
        else:
            metadata = original_stat(
                path,
                dir_fd=dir_fd,
                follow_symlinks=follow_symlinks,
            )
        if (metadata.st_dev, metadata.st_ino) == blob_identity:
            source_stats += 1
            if settlement == "after_terminal" and source_stats == 2:
                pending.unlink()
                settled.set()
                if dir_fd is None:
                    metadata = original_stat(path, follow_symlinks=follow_symlinks)
                else:
                    metadata = original_stat(
                        path,
                        dir_fd=dir_fd,
                        follow_symlinks=follow_symlinks,
                    )
        return metadata

    monkeypatch.setattr(secure_paths.os, "fstat", settle_before_after)
    monkeypatch.setattr(secure_paths.os, "stat", settle_after_terminal)
    restore_root = tmp_path / "restore"
    restore_root.mkdir()
    destination = restore_root / "build/a.obj"

    with cache.lease() as lease:
        lease.restore(record, {"build/a.obj": destination}, allowed_root=restore_root)

    assert settled.is_set()
    assert destination.read_bytes() == b"stable"


@pytest.mark.skipif(
    not (Path("/var").is_symlink() and Path("/var").resolve() == Path("/private/var")),
    reason="macOS /var root alias is unavailable",
)
def test_cache_accepts_macos_var_alias_without_admitting_project_symlinks(
    tmp_path: Path,
) -> None:
    canonical = tmp_path.resolve(strict=True)
    try:
        relative = canonical.relative_to("/private/var")
    except ValueError:
        pytest.skip("temporary directory is outside /private/var")
    alias_root = Path("/var").joinpath(*relative.parts)
    state = alias_root / "state"
    state.mkdir()
    source = alias_root / "source.obj"
    source.write_bytes(b"alias-object")
    destination = alias_root / "workspace" / "restored.obj"
    destination.parent.mkdir()

    cache = IncrementalCache(state, implementation="test-implementation-v1")
    with cache.lease() as lease:
        record = lease.store("producer", _key("macos-alias"), {"build/out.obj": source})
    with cache.lease() as lease:
        lease.restore(
            record,
            {"build/out.obj": destination},
            allowed_root=alias_root / "workspace",
        )
    assert destination.read_bytes() == b"alias-object"


def test_cache_keys_separate_domain_and_implementation() -> None:
    material = {"node": "compile.a"}
    assert cache_key("producer", material, implementation="one") != cache_key(
        "trace", material, implementation="one"
    )
    assert cache_key("producer", material, implementation="one") != cache_key(
        "producer", material, implementation="two"
    )


def test_missing_record_is_a_safe_miss_but_corrupt_blob_is_explicit(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "a.obj"
    source.write_bytes(b"good")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    key = _key("compile.a")
    with cache.lease() as lease:
        assert lease.lookup("producer", _key("missing")) is None
        record = lease.store("producer", key, {"build/a.obj": source})
        blob = (
            state
            / "cache"
            / "v1"
            / "blobs"
            / "sha256"
            / record.outputs[0].digest[:2]
            / record.outputs[0].digest
        )
        blob.write_bytes(b"poison")
        with pytest.raises(CachePoisonError, match="integrity"):
            lease.lookup("producer", key)


def test_existing_key_cannot_be_rebound_to_different_output_or_metadata(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    left = tmp_path / "left.obj"
    right = tmp_path / "right.obj"
    left.write_bytes(b"left")
    right.write_bytes(b"right")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    key = _key("compile.a")
    with cache.lease() as lease:
        lease.store("producer", key, {"build/a.obj": left}, metadata={"version": 1})
        with pytest.raises(CachePoisonError, match="different immutable"):
            lease.store(
                "producer",
                key,
                {"build/a.obj": right},
                metadata={"version": 1},
            )
        with pytest.raises(CachePoisonError, match="different immutable"):
            lease.store(
                "producer",
                key,
                {"build/a.obj": left},
                metadata={"version": 2},
            )


def test_restore_rejects_escape_symlink_and_preexisting_destination(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "a.obj"
    source.write_bytes(b"a")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    with cache.lease() as lease:
        record = lease.store("producer", _key("a"), {"build/a.obj": source})
        restore_root = tmp_path / "restore"
        restore_root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        with pytest.raises(CacheError, match="escapes"):
            lease.restore(
                record,
                {"build/a.obj": outside / "a.obj"},
                allowed_root=restore_root,
            )
        alias = restore_root / "build"
        try:
            alias.symlink_to(outside, target_is_directory=True)
        except OSError:
            pytest.skip("directory symlinks are unavailable")
        with pytest.raises(CachePoisonError, match="redirected"):
            lease.restore(
                record,
                {"build/a.obj": alias / "a.obj"},
                allowed_root=restore_root,
            )


def test_gc_never_races_active_lease_and_collects_after_release(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "a.obj"
    source.write_bytes(b"a" * 4096)
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    with cache.lease() as lease:
        lease.store("producer", _key("a"), {"build/a.obj": source})
        result = cache.gc()
        assert result.active_leases == 1
        assert result.removed_records == 0
    result = cache.gc()
    assert result.active_leases == 0
    assert result.removed_records == 1
    assert result.removed_blobs == 1
    assert result.reclaimed_bytes >= 4096


def test_gc_dry_run_and_age_retain_recent_records(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "a.obj"
    source.write_bytes(b"a")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    with cache.lease() as lease:
        lease.store("producer", _key("a"), {"build/a.obj": source})
    preview = cache.gc(dry_run=True)
    assert preview.removed_records == 1
    assert preview.removed_blobs == 1
    assert cache.status().records == 1
    recent = cache.gc(older_than_seconds=3600)
    assert recent.removed_records == 0
    assert recent.skipped_recent_records == 1


def test_gc_collects_stale_lookup_indexes_with_records(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "unit.obj"
    source.write_bytes(b"unit")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    base = _key("base")
    with cache.lease() as lease:
        record = lease.store(
            "producer",
            _key("record"),
            {"build/unit.obj": source},
        )
        lease.index_record("producer", "compiler-base", base, record)
    result = cache.gc()
    assert result.removed_records == 1
    assert result.removed_indexes == 1


def test_gc_removes_only_obsolete_implementation_family_records(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    shared = tmp_path / "shared.obj"
    stale_only = tmp_path / "stale.obj"
    discovery_only = tmp_path / "discovery.obj"
    shared.write_bytes(b"shared")
    stale_only.write_bytes(b"stale only")
    discovery_only.write_bytes(b"discovery")
    family = "classic-producer-graph-"
    current = IncrementalCache(state, implementation=f"{family}current")
    obsolete = IncrementalCache(state, implementation=f"{family}obsolete")
    unrelated = IncrementalCache(state, implementation="discovery-current")
    with current.lease() as lease:
        current_record = lease.store(
            "producer",
            _key("current", implementation=current.implementation),
            {"shared.obj": shared},
        )
        lease.index_record(
            "producer",
            "compiler-base",
            _key("current-base", implementation=current.implementation),
            current_record,
        )
    with obsolete.lease() as lease:
        obsolete_record = lease.store(
            "producer",
            _key("obsolete", implementation=obsolete.implementation),
            {"shared.obj": shared, "stale.obj": stale_only},
        )
        lease.index_record(
            "producer",
            "compiler-base",
            _key("obsolete-base", implementation=obsolete.implementation),
            obsolete_record,
        )
    with unrelated.lease() as lease:
        unrelated_record = lease.store(
            "discovery-cell",
            cache_key(
                "discovery-cell",
                {"node": "unrelated"},
                implementation=unrelated.implementation,
            ),
            {"discovery.obj": discovery_only},
        )

    status = current.status(implementation_family=family)
    assert status.records == 3
    assert status.current_records == 1
    assert status.obsolete_records == 1
    recent = current.gc(
        older_than_seconds=3600,
        obsolete_implementation_family=family,
    )
    assert recent.removed_records == 0
    assert recent.skipped_recent_records == 1
    preview = current.gc(dry_run=True, obsolete_implementation_family=family)
    assert preview.removed_records == 1
    assert preview.removed_blobs == 1
    assert preview.removed_indexes == 1
    assert current.status().records == 3

    result = current.gc(obsolete_implementation_family=family)

    assert result.removed_records == 1
    assert result.removed_blobs == 1
    assert result.removed_indexes == 1
    with current.lease() as lease:
        assert lease.lookup("producer", current_record.key) == current_record
    with obsolete.lease() as lease:
        assert lease.lookup("producer", obsolete_record.key) is None
    with unrelated.lease() as lease:
        assert lease.lookup("discovery-cell", unrelated_record.key) == unrelated_record
    status = current.status(implementation_family=family)
    assert status.records == 2
    assert status.current_records == 1
    assert status.obsolete_records == 0


def test_concurrent_publishers_converge_on_one_immutable_record(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "a.obj"
    source.write_bytes(b"stable")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    key = _key("a")
    records, errors = _store_concurrently(cache, key, source)
    assert not errors
    assert len(records) == 2
    assert records[0] == records[1]
    assert cache.status().records == 1
    assert cache.status().blobs == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link publication regression")
@pytest.mark.parametrize("observation", ("read", "stat"))
def test_concurrent_blob_validation_waits_for_posix_link_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    observation: Literal["read", "stat"],
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "a.obj"
    source.write_bytes(b"stable")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    key = _key("a")
    original_promote = cache_module.promote_relative_new
    unlink_started, validation_started, unlink_finished = (
        _hold_posix_unlink_until_competing_observation(
            monkeypatch,
            matches_name=lambda name: (
                len(name) == 32 and all(character in "0123456789abcdef" for character in name)
            ),
            observation=observation,
        )
    )
    promotion_lock = threading.Lock()
    follower_ready = threading.Event()
    promotion_calls = 0

    def promote_together(
        root: Path,
        source_relative: str,
        destination_relative: str,
        *,
        expected: secure_paths.SecureFileSnapshot,
    ) -> secure_paths.SecureFileSnapshot:
        nonlocal promotion_calls
        with promotion_lock:
            promotion_calls += 1
            leader = promotion_calls == 1
        if leader:
            if not follower_ready.wait(timeout=5):
                raise RuntimeError("competing cache promotion did not begin")
        else:
            follower_ready.set()
            if not unlink_started.wait(timeout=5):
                raise RuntimeError("winning cache publication did not link")
        return original_promote(
            root,
            source_relative,
            destination_relative,
            expected=expected,
        )

    # Give one publisher a deterministic head start, then release the losing
    # publisher only while the winner's staging unlink is paused.  A barrier
    # alone still allowed the loser to validate the tiny blob before that
    # pause on fast runners, which made this race regression itself flaky.
    monkeypatch.setattr(cache_module, "promote_relative_new", promote_together)
    records, errors = _store_concurrently(cache, key, source)
    assert unlink_started.is_set()
    assert validation_started.is_set()
    assert unlink_finished.is_set()
    assert not errors
    assert len(records) == 2
    assert records[0] == records[1]
    assert cache.status().records == 1
    assert cache.status().blobs == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link publication regression")
def test_concurrent_immutable_publication_waits_for_posix_link_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "marker"
    payload = b"immutable marker\n"
    barrier = threading.Barrier(2)
    unlink_started, read_started, unlink_finished = _hold_posix_unlink_until_competing_observation(
        monkeypatch,
        matches_name=lambda name: name.startswith(".marker.reprobit-"),
    )
    errors: list[BaseException] = []

    def publish() -> None:
        try:
            barrier.wait(timeout=5)
            cache_module._publish_immutable(target, payload)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=publish) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    assert unlink_started.is_set()
    assert read_started.is_set()
    assert unlink_finished.is_set()
    assert not errors
    assert target.read_bytes() == payload


def test_layout_validation_retries_one_immutable_settlement_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    original_read = cache_module._secure_read
    transient = True

    def fail_once(path: Path, *, maximum: int | None = None) -> bytes:
        nonlocal transient
        if transient and path.name == "format.json":
            transient = False
            raise CachePoisonError("simulated POSIX staging-link settlement")
        return original_read(path, maximum=maximum)

    monkeypatch.setattr(cache_module, "_secure_read", fail_once)

    cache._ensure_layout()
    assert not transient


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link publication regression")
def test_concurrent_record_lookup_waits_for_posix_link_settlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "a.obj"
    source.write_bytes(b"stable")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    key = _key("a")
    unlink_started, read_started, unlink_finished = _hold_posix_unlink_until_competing_observation(
        monkeypatch,
        matches_name=lambda name: name.startswith(f".{key}.json.reprobit-"),
    )
    records, errors = _store_concurrently(cache, key, source)
    assert unlink_started.is_set()
    assert read_started.is_set()
    assert unlink_finished.is_set()
    assert not errors
    assert len(records) == 2
    assert records[0] == records[1]


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link publication regression")
def test_record_snapshot_ignores_owned_in_flight_publication_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "a.obj"
    source.write_bytes(b"stable")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    key = _key("a")
    with cache.lease() as lease:
        record = lease.stage_record("producer", key, {"build/a.obj": source})
    link_started, release_link = _pause_posix_publication_before_link(
        monkeypatch,
        matches_name=lambda name: name.startswith(f".{key}.json.reprobit-"),
    )
    errors: list[BaseException] = []

    def publish() -> None:
        try:
            with cache.lease() as lease:
                lease.publish_record(record)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=publish)
    thread.start()
    assert link_started.wait(timeout=5)
    with cache.lease() as lease:
        assert lease.records("producer") == ()
    release_link.set()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert not errors
    with cache.lease() as lease:
        assert lease.records("producer") == (record,)


@pytest.mark.skipif(os.name != "posix", reason="POSIX hard-link publication regression")
def test_status_ignores_owned_in_flight_lease_temp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    link_started, release_link = _pause_posix_publication_before_link(
        monkeypatch,
        matches_name=lambda name: bool(
            re.fullmatch(r"\.[0-9a-f]{32}\.lease\.reprobit-[0-9a-f]{32}", name)
        ),
    )
    errors: list[BaseException] = []

    def acquire_lease() -> None:
        try:
            with cache.lease():
                pass
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    thread = threading.Thread(target=acquire_lease)
    thread.start()
    assert link_started.wait(timeout=5)
    assert cache.status().active_leases == 0
    release_link.set()
    thread.join(timeout=10)

    assert not thread.is_alive()
    assert not errors


@pytest.mark.parametrize("location", ("lease", "record"))
def test_owned_publication_temp_may_disappear_during_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    if location == "lease":
        temporary = cache.format_root / "leases" / f".{('a' * 32)}.lease.reprobit-{'b' * 32}"
    else:
        temporary = (
            cache.format_root
            / "records"
            / cache.implementation
            / "producer"
            / "aa"
            / f".{('a' * 64)}.json.reprobit-{'b' * 32}"
        )
        temporary.parent.mkdir(parents=True)
    temporary.write_bytes(b"in flight")
    original_stat = Path.stat

    def disappear_then_stat(path: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if path == temporary:
            path.unlink()
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", disappear_then_stat)

    if location == "lease":
        assert cache.status().active_leases == 0
    else:
        with cache.lease() as lease:
            assert lease.records("producer") == ()


@pytest.mark.parametrize("location", ("lease", "record"))
def test_owned_publication_temp_must_still_be_regular(
    tmp_path: Path,
    location: str,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    if location == "lease":
        temporary = cache.format_root / "leases" / f".{('a' * 32)}.lease.reprobit-{'b' * 32}"
    else:
        temporary = (
            cache.format_root
            / "records"
            / cache.implementation
            / "producer"
            / "aa"
            / f".{('a' * 64)}.json.reprobit-{'b' * 32}"
        )
        temporary.parent.mkdir(parents=True)
    temporary.mkdir()

    with pytest.raises(CachePoisonError, match="unsafe entry"):
        if location == "lease":
            cache.status()
        else:
            with cache.lease() as lease:
                lease.records("producer")


def test_domain_record_snapshot_is_validated_and_canonical(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    outputs = []
    for index in range(3):
        source = tmp_path / f"{index}.obj"
        source.write_text(str(index))
        outputs.append((source, _key(f"node.{index}")))
    with cache.lease() as lease:
        expected = tuple(
            lease.store(
                "producer",
                key,
                {f"build/{source.name}": source},
                metadata={"base_key": f"base-{index}"},
            )
            for index, (source, key) in enumerate(outputs)
        )
        assert lease.records("producer") == tuple(sorted(expected, key=lambda item: item.key))
        assert lease.records("trace") == ()


def test_bounded_index_returns_recent_validated_candidates(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    base = _key("compiler-base")
    expected = []
    with cache.lease() as lease:
        for index in range(20):
            source = tmp_path / f"generation-{index}.obj"
            source.write_text(str(index))
            key = _key(f"generation-{index}")
            record = lease.store(
                "producer",
                key,
                {"build/unit.obj": source},
                metadata={"base": base, "generation": index},
            )
            lease.index_record("producer", "compiler-base", base, record)
            expected.insert(0, record)
        assert lease.indexed_records("producer", "compiler-base", base) == tuple(expected[:16])


def test_corrupt_non_authoritative_index_is_a_safe_miss(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    source = tmp_path / "unit.obj"
    source.write_bytes(b"unit")
    base = _key("compiler-base")
    with cache.lease() as lease:
        record = lease.store(
            "producer",
            _key("unit"),
            {"build/unit.obj": source},
        )
        lease.index_record("producer", "compiler-base", base, record)
        index_path = (
            state
            / "cache"
            / "v1"
            / "indexes"
            / "test-implementation-v1"
            / "producer"
            / "compiler-base"
            / base[:2]
            / f"{base}.json"
        )
        index_path.write_bytes(b"not json")
        assert lease.indexed_records("producer", "compiler-base", base) == ()
        assert lease.lookup("producer", record.key) == record


def test_redirected_index_lock_is_explicit_poison(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    base = _key("compiler-base-lock")
    first_source = tmp_path / "first.obj"
    first_source.write_bytes(b"first")
    second_source = tmp_path / "second.obj"
    second_source.write_bytes(b"second")
    outside = tmp_path / "outside.lock"
    outside.write_bytes(b"outside")
    with cache.lease() as lease:
        first = lease.store(
            "producer",
            _key("lock-first"),
            {"build/unit.obj": first_source},
        )
        lease.index_record("producer", "compiler-base", base, first)
        lock_path = (
            state
            / "cache"
            / "v1"
            / "indexes"
            / "test-implementation-v1"
            / "producer"
            / "compiler-base"
            / base[:2]
            / f"{base}.lock"
        )
        lock_path.unlink()
        try:
            lock_path.symlink_to(outside)
        except OSError:
            pytest.skip("file symlinks are unavailable")
        second = lease.store(
            "producer",
            _key("lock-second"),
            {"build/unit.obj": second_source},
        )
        with pytest.raises(CachePoisonError, match="publication failed"):
            lease.index_record("producer", "compiler-base", base, second)
    assert outside.read_bytes() == b"outside"


def test_cache_root_format_and_record_redirects_are_explicit_poison(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    outside = tmp_path / "outside"
    state.mkdir()
    outside.mkdir()
    (state / "cache").symlink_to(outside, target_is_directory=True)
    with pytest.raises(CachePoisonError, match="publication failed"):
        IncrementalCache(state, implementation="test-implementation-v1")
    assert tuple(outside.iterdir()) == ()

    (state / "cache").unlink()
    (state / "cache").mkdir()
    (state / "cache" / "v1").symlink_to(outside, target_is_directory=True)
    with pytest.raises(CachePoisonError, match="publication failed"):
        IncrementalCache(state, implementation="test-implementation-v1")
    assert tuple(outside.iterdir()) == ()

    (state / "cache" / "v1").unlink()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    source = tmp_path / "unit.obj"
    source.write_bytes(b"unit")
    with cache.lease() as lease:
        record = lease.store("producer", _key("unit"), {"unit.obj": source})
        record_path = (
            state
            / "cache"
            / "v1"
            / "records"
            / "test-implementation-v1"
            / "producer"
            / record.key[:2]
            / f"{record.key}.json"
        )
        saved = outside / "record.json"
        record_path.rename(saved)
        record_path.symlink_to(saved)
        with pytest.raises(CachePoisonError, match="redirected"):
            lease.lookup("producer", record.key)
        assert saved.is_file()


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO poisoning regression")
def test_format_and_record_special_files_fail_without_blocking(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    marker = state / "cache" / "v1" / "format.json"
    marker.unlink()
    os.mkfifo(marker)
    with pytest.raises(CachePoisonError, match="redirected"):
        IncrementalCache(
            state,
            implementation="test-implementation-v1",
            create=False,
        )

    marker.unlink()
    marker.write_bytes(b'{"schema":1}\n')
    source = tmp_path / "unit.obj"
    source.write_bytes(b"unit")
    with cache.lease() as lease:
        record = lease.store("producer", _key("fifo"), {"unit.obj": source})
        record_path = (
            state
            / "cache"
            / "v1"
            / "records"
            / "test-implementation-v1"
            / "producer"
            / record.key[:2]
            / f"{record.key}.json"
        )
        record_path.unlink()
        os.mkfifo(record_path)
        with pytest.raises(CachePoisonError, match="redirected"):
            lease.lookup("producer", record.key)


def test_first_large_blob_store_and_restore_use_one_streaming_copy_each(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "large.obj"
    with source.open("wb") as stream:
        stream.seek((12 * 1024 * 1024) - 1)
        stream.write(b"x")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    copy_calls: list[tuple[str, str]] = []
    digest_calls: list[str] = []
    original_copy = cache_module.atomic_copy_new_relative
    original_digest = cache_module.digest_relative_file

    def counted_copy(
        source_root: Path,
        source_relative: str,
        destination_root: Path,
        destination_relative: str,
        **kwargs: object,
    ) -> object:
        copy_calls.append((source_relative, destination_relative))
        return original_copy(
            source_root,
            source_relative,
            destination_root,
            destination_relative,
            **kwargs,  # type: ignore[arg-type]
        )

    def counted_digest(root: Path, relative: str) -> object:
        digest_calls.append(relative)
        return original_digest(root, relative)

    monkeypatch.setattr(cache_module, "atomic_copy_new_relative", counted_copy)
    monkeypatch.setattr(cache_module, "digest_relative_file", counted_digest)
    with cache.lease() as lease:
        record = lease.store("producer", _key("large"), {"large.obj": source})
        restore_root = tmp_path / "restore"
        restore_root.mkdir()
        lease.restore(
            record,
            {"large.obj": restore_root / "large.obj"},
            allowed_root=restore_root,
        )

    assert len(copy_calls) == 2
    assert copy_calls[0][0].endswith("large.obj")
    assert "/blobs/sha256/" in copy_calls[1][0]
    assert digest_calls == []


@pytest.mark.skipif(os.name == "nt", reason="Windows chmod has no executable mode bit")
def test_store_rejects_executable_mode_change_between_stat_and_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "unit.obj"
    source.write_bytes(b"object")
    source.chmod(0o755)
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    original_copy = cache_module.atomic_copy_new_relative
    changed = False

    def chmod_then_copy(
        source_root: Path,
        source_relative: str,
        destination_root: Path,
        destination_relative: str,
        **kwargs: object,
    ) -> object:
        nonlocal changed
        if not changed:
            source.chmod(0o644)
            changed = True
        return original_copy(
            source_root,
            source_relative,
            destination_root,
            destination_relative,
            **kwargs,  # type: ignore[arg-type]
        )

    monkeypatch.setattr(cache_module, "atomic_copy_new_relative", chmod_then_copy)
    key = _key("mode-race")
    with cache.lease() as lease:
        with pytest.raises(CacheError, match="source changed"):
            lease.store("producer", key, {"unit.obj": source})
        assert lease.lookup("producer", key) is None


def test_staged_record_is_invisible_until_explicit_publication(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "unit.obj"
    source.write_bytes(b"object")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    key = _key("staged")

    with cache.lease() as lease:
        staged = lease.stage_record("producer", key, {"unit.obj": source})
        assert lease.lookup("producer", key) is None
        published = lease.publish_record(staged)
        assert lease.lookup("producer", key) == published


def test_concurrent_same_index_writers_merge_latest_history_under_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    base = _key("shared-base")
    first_publish = threading.Event()
    release_first = threading.Event()
    publication_lock = threading.Lock()
    delayed = False
    original_publish = cache_module.atomic_publish_relative

    def synchronized_publish(root: Path, relative: str, payload: bytes) -> object:
        nonlocal delayed
        if "/indexes/" in f"/{relative}":
            with publication_lock:
                should_delay = not delayed
                delayed = True
            if should_delay:
                first_publish.set()
                assert release_first.wait(timeout=10)
        return original_publish(root, relative, payload)

    monkeypatch.setattr(cache_module, "atomic_publish_relative", synchronized_publish)
    records = []
    errors: list[BaseException] = []

    def publish(index: int) -> None:
        try:
            source = tmp_path / f"unit-{index}.obj"
            source.write_bytes(f"unit-{index}".encode())
            with cache.lease() as lease:
                record = lease.store(
                    "producer",
                    _key(f"unit-{index}"),
                    {"unit.obj": source},
                )
                records.append(record)
                lease.index_record("producer", "compiler-base", base, record)
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=publish, args=(index,)) for index in range(2)]
    threads[0].start()
    assert first_publish.wait(timeout=10)
    threads[1].start()
    release_first.set()
    for thread in threads:
        thread.join(timeout=15)

    assert not errors
    assert len(records) == 2
    assert all(not thread.is_alive() for thread in threads)
    with cache.lease() as lease:
        indexed = lease.indexed_records("producer", "compiler-base", base)
        assert len(indexed) == 2
        assert {item.key for item in indexed} == {item.key for item in records}
        assert all(lease.lookup("producer", item.key) == item for item in records)


def test_sibling_lease_reader_publisher_and_gc_do_not_race(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "shared.obj"
    source.write_bytes(b"shared blob")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    ready = threading.Event()
    release = threading.Event()
    errors: list[BaseException] = []

    with cache.lease() as reader:
        first = reader.store("producer", _key("first"), {"shared.obj": source})
        blob = (
            state
            / "cache"
            / "v1"
            / "blobs"
            / "sha256"
            / first.outputs[0].digest[:2]
            / first.outputs[0].digest
        )
        inode = blob.stat().st_ino

        def publish_sibling() -> None:
            try:
                with cache.lease() as publisher:
                    publisher.store("producer", _key("second"), {"shared.obj": source})
                    ready.set()
                    release.wait(timeout=10)
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)
                ready.set()

        thread = threading.Thread(target=publish_sibling)
        thread.start()
        assert ready.wait(timeout=10)
        restore_root = tmp_path / "restore"
        restore_root.mkdir()
        reader.restore(
            first,
            {"shared.obj": restore_root / "shared.obj"},
            allowed_root=restore_root,
        )
        gc_result = cache.gc()
        assert gc_result.active_leases == 2
        assert gc_result.removed_records == 0
        assert blob.stat().st_ino == inode
        release.set()
        thread.join(timeout=10)

    assert not errors
    assert not thread.is_alive()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ancestor-swap regression")
def test_blob_publication_parent_swap_never_writes_outside(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "unit.obj"
    source.write_bytes(b"unit")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    cache_root = state / "cache"
    held_cache = state / "cache-held"
    outside = tmp_path / "outside"
    outside.mkdir()
    original_link = secure_paths.os.link
    swapped = False

    def swap_then_link(*args: object, **kwargs: object) -> None:
        nonlocal swapped
        if not swapped:
            cache_root.rename(held_cache)
            cache_root.symlink_to(outside, target_is_directory=True)
            swapped = True
        original_link(*args, **kwargs)

    with cache.lease() as lease:
        monkeypatch.setattr(secure_paths.os, "link", swap_then_link)
        try:
            with pytest.raises(CacheError):
                lease.store("producer", _key("swap"), {"unit.obj": source})
        finally:
            monkeypatch.setattr(secure_paths.os, "link", original_link)
            cache_root.unlink()
            held_cache.rename(cache_root)

    assert tuple(outside.iterdir()) == ()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ancestor-swap regression")
def test_restore_parent_swap_and_destination_race_never_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "unit.obj"
    source.write_bytes(b"unit")
    cache = IncrementalCache(state, implementation="test-implementation-v1")
    original_link = secure_paths.os.link
    with cache.lease() as lease:
        record = lease.store("producer", _key("restore-swap"), {"unit.obj": source})
        restore_root = tmp_path / "restore"
        restore_root.mkdir()
        destination = restore_root / "build" / "unit.obj"
        held_build = restore_root / "build-held"
        outside = tmp_path / "outside"
        outside.mkdir()
        swapped = False

        def swap_then_link(*args: object, **kwargs: object) -> None:
            nonlocal swapped
            if not swapped:
                destination.parent.rename(held_build)
                destination.parent.symlink_to(outside, target_is_directory=True)
                swapped = True
            original_link(*args, **kwargs)

        monkeypatch.setattr(secure_paths.os, "link", swap_then_link)
        try:
            with pytest.raises(CachePoisonError, match="redirected"):
                lease.restore(
                    record,
                    {"unit.obj": destination},
                    allowed_root=restore_root,
                )
        finally:
            monkeypatch.setattr(secure_paths.os, "link", original_link)
            destination.parent.unlink()
            held_build.rename(destination.parent)
        assert not (outside / "unit.obj").exists()
        assert not destination.exists()

        def race_then_link(*args: object, **kwargs: object) -> None:
            destination.write_bytes(b"racer")
            original_link(*args, **kwargs)

        monkeypatch.setattr(secure_paths.os, "link", race_then_link)
        with pytest.raises(CacheError, match="safely publish"):
            lease.restore(
                record,
                {"unit.obj": destination},
                allowed_root=restore_root,
            )
        assert destination.read_bytes() == b"racer"


@pytest.mark.skipif(os.name == "nt", reason="POSIX timestamp mutation is deterministic")
def test_gc_collects_old_records_across_implementation_namespaces(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    source = tmp_path / "a.obj"
    source.write_bytes(b"shared")
    first = IncrementalCache(state, implementation="implementation-one")
    second = IncrementalCache(state, implementation="implementation-two")
    with first.lease() as lease:
        lease.store("producer", _key("a", implementation="implementation-one"), {"a": source})
    with second.lease() as lease:
        lease.store("producer", _key("a", implementation="implementation-two"), {"a": source})
    old = time.time_ns() - 3_600_000_000_000
    records_root = state / "cache" / "v1" / "records"
    for path in records_root.rglob("*.json"):
        os.utime(path, ns=(old, old), follow_symlinks=False)
    result = first.gc(older_than_seconds=1800)
    assert result.removed_records == 2
    assert result.removed_blobs == 1
