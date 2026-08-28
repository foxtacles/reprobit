from __future__ import annotations

import os
from pathlib import Path

import pytest

from reprobit.paths import (
    LogicalPathSkeleton,
    LogicalSeat,
    MaterializedSkeleton,
    PathContractError,
    logical_relative_to,
    normalize_logical_path,
)


def test_logical_path_normalization_is_strict() -> None:
    assert normalize_logical_path(r"r:\src\File.cpp") == r"R:\src\File.cpp"
    assert str(logical_relative_to(r"R:\SRC\File.cpp", r"r:\src")) == "File.cpp"
    for value in (
        "src\\file.cpp",
        "R:/src/file.cpp",
        r"R:\src\..\file.cpp",
        r"\\host\src",
        r"R:\src\CON.txt",
        "R:\\src\\trailing. ",
        r"R:\src\name:stream",
        r"R:\src\wild?.h",
        r"é:\src\file.cpp",
        r"Ω:\src\file.cpp",
    ):
        with pytest.raises(PathContractError):
            normalize_logical_path(value)


@pytest.mark.parametrize("prefix", ("COM", "lpt"))
@pytest.mark.parametrize("index", ("¹", "²", "³"))
def test_logical_paths_reject_windows_superscript_device_names(
    prefix: str,
    index: str,
) -> None:
    with pytest.raises(PathContractError, match="unsafe DOS component"):
        normalize_logical_path(fr"R:\src\{prefix}{index}.artifact.tar")


def test_materialized_skeleton_requires_an_ascii_dos_drive(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    for drive in ("é", "Ω", "Ж"):
        with pytest.raises(PathContractError, match="drive letter is invalid"):
            MaterializedSkeleton(root, drive, ())

    assert MaterializedSkeleton(root, "r:", ()).drive_letter == "R"


def test_logical_seat_names_use_ascii_segmented_identifiers(tmp_path: Path) -> None:
    for name in ("source", "worker-0000", "cmake_runtime", "A1-b2_c3"):
        assert LogicalSeat(name, tmp_path, r"R:\seat").name == name

    for name in (
        "",
        "-worker",
        "worker-",
        "worker--0000",
        "worker__0000",
        "worker 0000",
        "worker.0000",
        "café",
    ):
        with pytest.raises(PathContractError, match="unsafe logical seat name"):
            LogicalSeat(name, tmp_path, r"R:\seat")


def test_skeleton_translates_both_directions(tmp_path: Path) -> None:
    source = tmp_path / "physical-source"
    build = tmp_path / "physical-build"
    source.mkdir()
    build.mkdir()
    unit = source / "nested" / "unit.cpp"
    unit.parent.mkdir()
    unit.write_text("int f();\n")
    skeleton = LogicalPathSkeleton(
        (
            LogicalSeat("source", source, r"R:\src"),
            LogicalSeat("build", build, r"R:\build", writable=True),
        )
    )

    assert skeleton.to_logical(unit) == r"R:\src\nested\unit.cpp"
    assert skeleton.to_physical(r"r:\SRC\nested\unit.cpp") == unit
    skeleton.verify_round_trip()

    with pytest.raises(PathContractError, match="no logical seat"):
        skeleton.to_logical(tmp_path / "other")
    with pytest.raises(PathContractError, match="no physical seat"):
        skeleton.to_physical(r"R:\other\file")


def test_materialization_is_owned_and_cleaned(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    skeleton = LogicalPathSkeleton((LogicalSeat("source", source, r"R:\src"),))

    with skeleton.temporary_materialization(tmp_path / "runs") as materialized:
        link = materialized.root / "src"
        assert link.is_symlink()
        assert link.resolve() == source
        temporary_root = materialized.root
    assert not temporary_root.exists()


def test_materialization_preserves_the_complete_logical_suffix(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    skeleton = LogicalPathSkeleton(
        (
            LogicalSeat(
                "source",
                source,
                r"Z:\Users\builder\Projects\sample\source",
            ),
        )
    )
    staging = tmp_path / "staging"

    materialized = skeleton.materialize(staging)

    seat = staging / "Users" / "builder" / "Projects" / "sample" / "source"
    assert materialized.created_entries == (seat,)
    assert seat.resolve(strict=True) == source.resolve(strict=True)


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory junctions")
def test_windows_materialization_uses_non_admin_junctions(tmp_path: Path) -> None:
    import stat

    source = tmp_path / "source"
    source.mkdir()
    skeleton = LogicalPathSkeleton(
        (LogicalSeat("source", source, r"R:\deep\pinned\source"),)
    )

    with skeleton.temporary_materialization(tmp_path / "runs") as materialized:
        entry = materialized.created_entries[0]
        metadata = entry.lstat()
        assert metadata.st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
        assert entry.resolve(strict=True) == source.resolve(strict=True)
        owned_root = materialized.root
    assert not owned_root.exists()


def test_skeleton_rejects_overlapping_seats(tmp_path: Path) -> None:
    physical = tmp_path / "physical"
    nested = physical / "nested"
    nested.mkdir(parents=True)
    with pytest.raises(PathContractError, match="logical seats overlap"):
        LogicalPathSkeleton(
            (
                LogicalSeat("one", physical, r"R:\src"),
                LogicalSeat("two", tmp_path / "elsewhere", r"R:\src\nested"),
            )
        )
    with pytest.raises(PathContractError, match="physical seats overlap"):
        LogicalPathSkeleton(
            (
                LogicalSeat("one", physical, r"R:\src"),
                LogicalSeat("two", nested, r"R:\generated"),
            )
        )
