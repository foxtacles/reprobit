from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from reprobit.classic_incremental_context import (
    SNAPSHOT_IDENTITY_FIELDS,
    ClassicIncrementalError,
    PhysicalInputCensus,
    snapshot_identity_is_exact,
)
from reprobit.model import Digest
from reprobit.secure_path_contracts import SecureFileIdentity, SecureFileSnapshot


def test_known_path_returns_exact_sample_without_resolving_again(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.cpp"
    source.write_text("int value = 1;\n")
    census = PhysicalInputCensus()
    sampled = census.sampled_path(source)

    def unexpected_resolve(*_args: object, **_kwargs: object) -> Path:
        raise AssertionError("an exact sampled path must not be resolved again")

    monkeypatch.setattr(Path, "resolve", unexpected_resolve)
    assert census.known_path(sampled) == sampled


def test_known_path_resolves_lexical_and_symlink_aliases(tmp_path: Path) -> None:
    source = tmp_path / "source.cpp"
    source.write_text("int value = 1;\n")
    nested = tmp_path / "nested"
    nested.mkdir()
    census = PhysicalInputCensus()
    sampled = census.sampled_path(source)

    assert census.known_path(nested / ".." / source.name) == sampled

    if os.name != "nt":
        alias = tmp_path / "source-alias.cpp"
        alias.symlink_to(source)
        assert census.known_path(alias) == sampled


def test_known_path_does_not_cache_a_symlink_resolution(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("portable Windows test environments do not guarantee symlink creation")
    first = tmp_path / "first.cpp"
    second = tmp_path / "second.cpp"
    first.write_text("int first = 1;\n")
    second.write_text("int second = 2;\n")
    alias = tmp_path / "alias.cpp"
    alias.symlink_to(first)
    census = PhysicalInputCensus()
    sampled = census.sampled_path(first)

    assert census.known_path(alias) == sampled
    alias.unlink()
    alias.symlink_to(second)
    assert census.known_path(alias) is None


def test_known_path_does_not_lexically_collapse_parent_after_symlink(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("portable Windows test environments do not guarantee symlink creation")
    sampled = tmp_path / "source.cpp"
    sampled.write_text("int sampled = 1;\n")
    elsewhere = tmp_path / "elsewhere"
    child = elsewhere / "child"
    child.mkdir(parents=True)
    (elsewhere / "source.cpp").write_text("int elsewhere = 2;\n")
    alias = tmp_path / "alias"
    alias.symlink_to(child, target_is_directory=True)
    census = PhysicalInputCensus()
    census.sampled_path(sampled)

    assert census.known_path(alias / ".." / "source.cpp") is None


def test_known_path_observes_a_path_sampled_after_an_initial_miss(tmp_path: Path) -> None:
    source = tmp_path / "later.cpp"
    census = PhysicalInputCensus()

    assert census.known_path(source) is None
    source.write_text("int later = 1;\n")
    sampled = census.sampled_path(source)
    assert census.known_path(source) == sampled


def test_known_path_exact_fast_path_is_thread_safe(tmp_path: Path) -> None:
    source = tmp_path / "source.cpp"
    source.write_text("int value = 1;\n")
    census = PhysicalInputCensus()
    sampled = census.sampled_path(source)

    with ThreadPoolExecutor(max_workers=8) as pool:
        received = tuple(pool.map(lambda _index: census.known_path(sampled), range(1_000)))

    assert received == (sampled,) * 1_000


def test_census_still_rejects_mutation_after_exact_known_path_lookup(tmp_path: Path) -> None:
    source = tmp_path / "source.cpp"
    source.write_text("int value = 1;\n")
    census = PhysicalInputCensus()
    sampled = census.sampled_path(source)
    assert census.known_path(sampled) == sampled

    source.write_text("int value = 2;\n")
    with pytest.raises(ClassicIncrementalError, match="changed before cache publication"):
        census.validate_all()


def _count_hashes(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Record every full content hash the census performs."""

    import reprobit.classic_incremental_context as context

    hashed: list[Path] = []
    real_digest = context.digest_relative_file

    def counting_digest(root: Path, relative: str) -> SecureFileSnapshot:
        hashed.append(root.joinpath(*relative.split("/")))
        return real_digest(root, relative)

    monkeypatch.setattr(context, "digest_relative_file", counting_digest)
    return hashed


def test_snapshot_reuses_an_exact_sample_without_hashing_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.cpp"
    source.write_text("int value = 1;\n")
    hashed = _count_hashes(monkeypatch)
    census = PhysicalInputCensus()

    first = census.snapshot(source)
    assert len(hashed) == 1
    assert census.snapshot(source) == first
    assert census.snapshot(tmp_path / "nested" / ".." / "source.cpp") == first
    assert len(hashed) == 1

    census.validate_all()
    census.validate([source])
    assert len(hashed) == 1


@pytest.mark.parametrize("field", SNAPSHOT_IDENTITY_FIELDS)
def test_snapshot_hashes_again_when_any_identity_field_differs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    import reprobit.classic_incremental_context as context

    source = tmp_path / "source.cpp"
    source.write_text("int value = 1;\n")
    hashed = _count_hashes(monkeypatch)
    census = PhysicalInputCensus()
    first = census.snapshot(source)
    real_stat = context.stat_relative_file

    def drifted_stat(root: Path, relative: str) -> SecureFileIdentity:
        identity = real_stat(root, relative)
        recorded = getattr(identity, field)
        drifted = recorded + b"\x01" if isinstance(recorded, bytes) else recorded + 1
        return replace(identity, **{field: drifted})

    monkeypatch.setattr(context, "stat_relative_file", drifted_stat)
    # The file itself is unchanged, so the forced re-hash agrees with the sample.
    assert census.snapshot(source) == first
    assert len(hashed) == 2
    census.validate_all()
    assert len(hashed) == 3


def test_snapshot_hashes_again_when_the_identity_lacks_an_attribute(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import reprobit.classic_incremental_context as context

    source = tmp_path / "source.cpp"
    source.write_text("int value = 1;\n")
    hashed = _count_hashes(monkeypatch)
    census = PhysicalInputCensus()
    first = census.snapshot(source)
    real_stat = context.stat_relative_file

    def partial_stat(root: Path, relative: str) -> object:
        identity = real_stat(root, relative)
        values = {name: getattr(identity, name) for name in SNAPSHOT_IDENTITY_FIELDS}
        del values["ctime_ns"]
        return SimpleNamespace(path=identity.path, **values)

    monkeypatch.setattr(context, "stat_relative_file", partial_stat)
    assert census.snapshot(source) == first
    assert len(hashed) == 2


def test_snapshot_identity_is_exact_requires_the_same_path_and_every_field() -> None:
    recorded = SecureFileSnapshot(
        Path("/held/source.cpp"), Digest.from_bytes(b"x"), 1, 2, 3, 4, 5, 6, b"id", 7
    )
    same = SecureFileIdentity(Path("/held/source.cpp"), 1, 2, 3, 4, 5, 6, b"id", 7)
    assert snapshot_identity_is_exact(recorded, same)
    assert not snapshot_identity_is_exact(recorded, replace(same, path=Path("/held/other.cpp")))
    for field in SNAPSHOT_IDENTITY_FIELDS:
        current = getattr(same, field)
        drifted = current + b"!" if isinstance(current, bytes) else current + 1
        assert not snapshot_identity_is_exact(recorded, replace(same, **{field: drifted}))
    assert not snapshot_identity_is_exact(recorded, SimpleNamespace(path=recorded.path))
    assert not snapshot_identity_is_exact(recorded, object())


def test_census_rejects_an_edit_that_keeps_the_size_and_modification_time(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.cpp"
    source.write_text("int value = 1;\n")
    hashed = _count_hashes(monkeypatch)
    census = PhysicalInputCensus()
    census.snapshot(source)
    original = os.stat(source)

    source.write_text("int value = 2;\n")
    os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
    # Same size and mtime, but the change time and content differ: the edit is
    # hashed again and rejected everywhere the census is consulted.
    with pytest.raises(ClassicIncrementalError, match="changed while planning"):
        census.snapshot(source)
    with pytest.raises(ClassicIncrementalError, match="changed before cache publication"):
        census.validate_all()
    assert len(hashed) == 3


def test_census_rejects_a_touch_that_leaves_the_content_alone(tmp_path: Path) -> None:
    source = tmp_path / "source.cpp"
    source.write_text("int value = 1;\n")
    census = PhysicalInputCensus()
    sampled = census.snapshot(source)

    os.utime(source, ns=(sampled.mtime_ns + 1_000_000_000, sampled.mtime_ns + 1_000_000_000))
    with pytest.raises(ClassicIncrementalError, match="changed before cache publication"):
        census.validate_all()
