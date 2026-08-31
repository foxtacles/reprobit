from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from reprobit.classic_incremental_context import (
    ClassicIncrementalError,
    PhysicalInputCensus,
)


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
