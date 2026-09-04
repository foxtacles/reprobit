from __future__ import annotations

import io
import os
from pathlib import Path
from typing import BinaryIO

import pytest

import reprobit.secure_paths as secure_paths
import reprobit.secure_paths_posix as secure_paths_posix
import reprobit.secure_paths_windows as secure_paths_windows
from reprobit.model import Digest
from reprobit.secure_path_contracts import SecureFileSnapshot, SecurePathError
from reprobit.secure_paths import (
    atomic_copy_new_relative,
    atomic_publish_new_relative,
    atomic_publish_new_relative_from_stream,
    atomic_publish_relative,
    atomic_publish_relative_if_current,
    digest_relative_file,
    hold_relative_file_set,
    promote_relative_new,
    read_relative_file,
    remove_published_relative,
    reseal_relative_file,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX handle-relative implementation")


def test_secure_read_rejects_redirected_ancestor(tmp_path: Path) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "input.h").write_bytes(b"unadmitted host bytes")
    (root / "vendor").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SecurePathError, match="absent or redirected"):
        read_relative_file(root, "vendor/input.h")


def test_secure_read_and_digest_snapshots_have_identical_mode_receipts(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    source = root / "input.txt"
    source.write_bytes(b"input")

    payload, read_snapshot = read_relative_file(root, "input.txt")
    digest_snapshot = digest_relative_file(root, "input.txt")

    assert payload == b"input"
    assert read_snapshot == digest_snapshot
    assert read_snapshot.mode != 0


def test_expected_directory_identity_blocks_a_replacement_seat(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    seat = root / "state" / "seat"
    moved = root / "state" / "moved"
    (seat / "incoming").mkdir(parents=True)
    (seat / "journal.json").write_bytes(b"journal")
    (seat / "incoming" / "object").write_bytes(b"staged")
    journal = digest_relative_file(root, "state/seat/journal.json")
    staged = digest_relative_file(root, "state/seat/incoming/object")
    metadata = seat.stat(follow_symlinks=False)
    expected_directories = {"state/seat": (metadata.st_dev, metadata.st_ino)}
    os.replace(seat, moved)
    seat.mkdir()
    (seat / "keep.txt").write_bytes(b"replacement")

    with pytest.raises(SecurePathError, match="directory changed"):
        read_relative_file(
            root,
            "state/seat/journal.json",
            expected_directories=expected_directories,
        )
    with pytest.raises(SecurePathError, match="directory changed"):
        digest_relative_file(
            root,
            "state/seat/journal.json",
            expected_directories=expected_directories,
        )
    with pytest.raises(SecurePathError, match="directory changed"):
        atomic_publish_relative_if_current(
            root,
            "state/seat/journal.json",
            b"replacement journal",
            expected=journal,
            expected_directories=expected_directories,
        )
    with pytest.raises(SecurePathError, match="directory changed"):
        atomic_publish_new_relative_from_stream(
            root,
            "state/seat/staged/new",
            io.BytesIO(b"new"),
            expected_directories=expected_directories,
        )
    with pytest.raises(SecurePathError, match="directory changed"):
        promote_relative_new(
            root,
            "state/seat/incoming/object",
            "build/object",
            expected=staged,
            expected_directories=expected_directories,
        )
    with pytest.raises(SecurePathError, match="directory changed"):
        remove_published_relative(
            root,
            "state/seat/journal.json",
            expected=journal,
            expected_directories=expected_directories,
        )

    assert tuple(path.name for path in seat.iterdir()) == ("keep.txt",)
    assert (moved / "journal.json").read_bytes() == b"journal"
    assert (moved / "incoming" / "object").read_bytes() == b"staged"
    assert not (root / "build").exists()


def test_expected_directory_identity_must_name_a_path_ancestor(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()

    with pytest.raises(ValueError, match="canonical path ancestor"):
        atomic_publish_new_relative_from_stream(
            root,
            "state/value",
            io.BytesIO(b"value"),
            expected_directories={"unrelated": (1, 2)},
        )

    assert not (root / "state").exists()


def test_promotion_checks_source_change_time_when_size_and_mtime_are_restored(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    source = root / "staged"
    source.write_bytes(b"first")
    expected = digest_relative_file(root, "staged")
    source.write_bytes(b"other")
    os.utime(source, ns=(expected.mtime_ns, expected.mtime_ns))

    with pytest.raises(SecurePathError, match="promotion source changed"):
        promote_relative_new(
            root,
            "staged",
            "published",
            expected=expected,
        )

    assert source.read_bytes() == b"other"
    assert not (root / "published").exists()


def test_atomic_publication_replaces_only_regular_targets_and_reseals(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    published = atomic_publish_relative(root, "build/APP.EXE", b"candidate")

    assert (root / "build/APP.EXE").read_bytes() == b"candidate"
    assert reseal_relative_file(root, "build/APP.EXE", expected=published) == published
    replacement = atomic_publish_relative(root, "build/APP.EXE", b"replacement")
    assert (root / "build/APP.EXE").read_bytes() == b"replacement"
    assert replacement.digest != published.digest
    assert reseal_relative_file(root, "build/APP.EXE", expected=replacement) == replacement

    (root / "build/APP.EXE").write_bytes(b"same inode mutation")
    with pytest.raises(SecurePathError, match="changed before final seal"):
        reseal_relative_file(root, "build/APP.EXE", expected=replacement)


def test_conditional_publication_preserves_a_changed_preimage(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    expected = atomic_publish_relative(root, "build/APP.EXE", b"original")
    atomic_publish_relative(root, "build/APP.EXE", b"peer")

    with pytest.raises(SecurePathError, match="preimage changed"):
        atomic_publish_relative_if_current(
            root,
            "build/APP.EXE",
            b"candidate",
            expected=expected,
        )

    assert (root / "build/APP.EXE").read_bytes() == b"peer"


def test_conditional_publication_preserves_a_replacement_raced_at_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "build/APP.EXE"
    moved = root / "build/original.exe"
    expected = atomic_publish_relative(root, "build/APP.EXE", b"original")
    original_rename = secure_paths_posix._rename_noreplace_at
    raced = False

    def replace_before_quarantine(parent: int, source: str, destination: str) -> None:
        nonlocal raced
        if source == "APP.EXE" and ".reprobit-guard-" in destination and not raced:
            os.replace(target, moved)
            target.write_bytes(b"peer")
            raced = True
        original_rename(parent, source, destination)

    monkeypatch.setattr(
        secure_paths_posix,
        "_rename_noreplace_at",
        replace_before_quarantine,
    )

    with pytest.raises(SecurePathError, match="preimage changed"):
        atomic_publish_relative_if_current(
            root,
            "build/APP.EXE",
            b"candidate",
            expected=expected,
        )

    assert raced
    assert target.read_bytes() == b"peer"
    assert moved.read_bytes() == b"original"


def test_replace_never_restores_a_changed_private_guard_to_the_public_name(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "build/APP.EXE"
    saved = root / "build/saved-original.exe"
    expected = atomic_publish_relative(root, "build/APP.EXE", b"original")
    real_discard = secure_paths_posix._discard_quarantine_if_exact
    raced = False

    def replace_guard_before_discard(
        parent: int,
        quarantine: str,
        descriptor: int,
        metadata: os.stat_result,
        *,
        digest: Digest,
    ) -> None:
        nonlocal raced
        guard = target.parent / quarantine
        os.replace(guard, saved)
        guard.write_bytes(b"peer")
        raced = True
        real_discard(
            parent,
            quarantine,
            descriptor,
            metadata,
            digest=digest,
        )

    monkeypatch.setattr(
        secure_paths_posix,
        "_discard_quarantine_if_exact",
        replace_guard_before_discard,
    )

    with pytest.raises(SecurePathError, match="preimage guard changed"):
        atomic_publish_relative_if_current(
            root,
            "build/APP.EXE",
            b"candidate",
            expected=expected,
        )

    assert raced
    assert not target.exists()
    assert saved.read_bytes() == b"original"
    guards = tuple(target.parent.glob(".APP.EXE.reprobit-guard-*"))
    assert len(guards) == 1
    assert guards[0].read_bytes() == b"peer"


def test_byte_publication_rejects_commit_time_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    target = root / "build/APP.EXE"
    root.mkdir()
    original_rename = secure_paths_posix._rename_noreplace_at

    def rename_then_chmod(parent: int, source: str, destination: str) -> None:
        original_rename(parent, source, destination)
        if destination == "APP.EXE":
            target.chmod(0o755)

    monkeypatch.setattr(secure_paths_posix, "_rename_noreplace_at", rename_then_chmod)
    with pytest.raises(SecurePathError, match="attributes changed during commit"):
        atomic_publish_relative(root, "build/APP.EXE", b"candidate")


def test_stream_publication_rejects_commit_time_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    target = root / "cache/object"
    root.mkdir()
    original_rename = secure_paths_posix._rename_noreplace_at

    def rename_then_chmod(parent: int, source: str, destination: str) -> None:
        original_rename(parent, source, destination)
        if destination == "object":
            target.chmod(0o755)

    monkeypatch.setattr(secure_paths_posix, "_rename_noreplace_at", rename_then_chmod)
    with pytest.raises(SecurePathError, match="attributes changed during commit"):
        atomic_publish_new_relative_from_stream(
            root,
            "cache/object",
            io.BytesIO(b"candidate"),
            executable=False,
        )


def test_reseal_rejects_mode_only_mutation(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    snapshot = atomic_publish_relative(root, "build/APP.EXE", b"candidate")
    (root / "build/APP.EXE").chmod(0o600)

    with pytest.raises(SecurePathError, match="changed before final seal"):
        reseal_relative_file(root, "build/APP.EXE", expected=snapshot)


def test_held_file_set_detects_earlier_member_mutation_while_reading_later(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    first = atomic_publish_relative(root, "artifacts/app.exe", b"app")
    second = atomic_publish_relative(root, "artifacts/tool.exe", b"tool")
    original_read = secure_paths.os.read
    mutated = False

    def mutate_first_while_reading_second(descriptor: int, size: int) -> bytes:
        nonlocal mutated
        if os.fstat(descriptor).st_ino == second.inode and not mutated:
            (root / "artifacts/app.exe").write_bytes(b"peer-app")
            mutated = True
        return original_read(descriptor, size)

    monkeypatch.setattr(secure_paths.os, "read", mutate_first_while_reading_second)
    with (
        pytest.raises(SecurePathError, match="held file set member changed"),
        hold_relative_file_set(
            root,
            {
                "artifacts/app.exe": first,
                "artifacts/tool.exe": second,
            },
        ),
    ):
        pass

    assert mutated
    assert (root / "artifacts/app.exe").read_bytes() == b"peer-app"


def test_atomic_create_if_absent_never_replaces_existing_bytes(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    snapshot = atomic_publish_new_relative(root, "cache/object", b"first")

    assert reseal_relative_file(root, "cache/object", expected=snapshot) == snapshot
    with pytest.raises(SecurePathError, match="already exists"):
        atomic_publish_new_relative(root, "cache/object", b"second")
    assert (root / "cache/object").read_bytes() == b"first"


def test_streamed_create_is_bounded_one_pass_and_no_overwrite(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    payload = (b"0123456789abcdef" * (1024 * 1024)) + b"tail"

    class BoundedStream:
        def __init__(self, value: bytes) -> None:
            self.value = value
            self.offset = 0
            self.maximum_request = 0
            self.reads = 0

        def read(self, size: int = -1) -> bytes:
            assert 0 < size <= 1024 * 1024
            self.maximum_request = max(self.maximum_request, size)
            self.reads += 1
            block = self.value[self.offset : self.offset + size]
            self.offset += len(block)
            return block

    stream = BoundedStream(payload)
    snapshot = atomic_publish_new_relative_from_stream(
        root,
        "cache/object",
        stream,  # type: ignore[arg-type]
        expected_digest=Digest.from_bytes(payload),
        expected_size=len(payload),
    )

    assert snapshot.size == len(payload)
    assert snapshot.digest == Digest.from_bytes(payload)
    assert stream.maximum_request == 1024 * 1024
    assert stream.reads > 2
    with pytest.raises(SecurePathError, match="already exists"):
        atomic_publish_new_relative_from_stream(
            root,
            "cache/object",
            BoundedStream(b"replacement"),  # type: ignore[arg-type]
        )
    assert (root / "cache/object").read_bytes() == payload


def test_streamed_create_checks_expected_content_before_commit(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    source: BinaryIO = (tmp_path / "source").open("w+b")
    try:
        source.write(b"content")
        source.seek(0)
        with pytest.raises(SecurePathError, match="digest differs"):
            atomic_publish_new_relative_from_stream(
                root,
                "cache/object",
                source,
                expected_digest=Digest.from_bytes(b"different"),
                expected_size=7,
            )
    finally:
        source.close()
    assert not (root / "cache/object").exists()


def test_secure_digest_and_copy_stream_without_hardlinking(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "destination"
    source_root.mkdir()
    destination_root.mkdir()
    source = source_root / "large.bin"
    source.write_bytes((b"abcdefgh" * (2 * 1024 * 1024)) + b"tail")

    receipt = digest_relative_file(source_root, "large.bin")
    published = atomic_copy_new_relative(
        source_root,
        "large.bin",
        destination_root,
        "objects/large.bin",
        expected_digest=receipt.digest,
        expected_size=receipt.size,
    )

    destination = destination_root / "objects/large.bin"
    assert published.digest == receipt.digest
    assert published.size == receipt.size
    assert destination.stat().st_ino != source.stat().st_ino
    assert digest_relative_file(destination_root, "objects/large.bin").digest == (receipt.digest)


def test_atomic_copy_rejects_a_replaced_source_root(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    moved = tmp_path / "source-original"
    destination_root = tmp_path / "destination"
    source_root.mkdir()
    destination_root.mkdir()
    (source_root / "input.bin").write_bytes(b"input")
    metadata = source_root.stat(follow_symlinks=False)
    os.replace(source_root, moved)
    source_root.mkdir()
    (source_root / "input.bin").write_bytes(b"replacement")

    with pytest.raises(SecurePathError, match="root changed before use"):
        atomic_copy_new_relative(
            source_root,
            "input.bin",
            destination_root,
            "output.bin",
            expected_source_directories={".": (metadata.st_dev, metadata.st_ino)},
        )

    assert not (destination_root / "output.bin").exists()
    assert (moved / "input.bin").read_bytes() == b"input"


def test_atomic_copy_rejects_a_replaced_destination_root(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    destination_root = tmp_path / "destination"
    moved = tmp_path / "destination-original"
    source_root.mkdir()
    destination_root.mkdir()
    (source_root / "input.bin").write_bytes(b"input")
    metadata = destination_root.stat(follow_symlinks=False)
    os.replace(destination_root, moved)
    destination_root.mkdir()
    (destination_root / "keep.bin").write_bytes(b"replacement")

    with pytest.raises(SecurePathError, match="root changed before use"):
        atomic_copy_new_relative(
            source_root,
            "input.bin",
            destination_root,
            "output.bin",
            expected_destination_directories={
                ".": (metadata.st_dev, metadata.st_ino),
            },
        )

    assert tuple(path.name for path in destination_root.iterdir()) == ("keep.bin",)
    assert moved.is_dir()


def test_atomic_create_if_absent_rejects_final_symlink(tmp_path: Path) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    (root / "cache").mkdir(parents=True)
    outside.write_bytes(b"outside")
    (root / "cache/object").symlink_to(outside)

    with pytest.raises(SecurePathError, match="redirected/non-regular"):
        atomic_publish_new_relative(root, "cache/object", b"candidate")
    assert outside.read_bytes() == b"outside"


def test_atomic_create_if_absent_loses_race_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    original_rename = secure_paths_posix._rename_noreplace_at

    def publish_racer_then_rename(parent: int, source: str, destination: str) -> None:
        if destination == "object":
            (root / "cache/object").write_bytes(b"racer")
        original_rename(parent, source, destination)

    monkeypatch.setattr(
        secure_paths_posix,
        "_rename_noreplace_at",
        publish_racer_then_rename,
    )
    with pytest.raises(SecurePathError, match="cannot atomically create"):
        atomic_publish_new_relative(root, "cache/object", b"candidate")
    assert (root / "cache/object").read_bytes() == b"racer"


def test_atomic_publication_rejects_preexisting_final_symlink(tmp_path: Path) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside.bin"
    (root / "build").mkdir(parents=True)
    outside.write_bytes(b"outside")
    (root / "build/APP.EXE").symlink_to(outside)

    with pytest.raises(SecurePathError, match="redirected/non-regular"):
        atomic_publish_relative(root, "build/APP.EXE", b"candidate")
    assert outside.read_bytes() == b"outside"


def test_atomic_publication_rejects_concurrent_ancestor_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    output = root / "build"
    held_output = root / "build-held"
    outside = tmp_path / "outside"
    output.mkdir(parents=True)
    outside.mkdir()
    original_rename = secure_paths_posix._rename_noreplace_at
    swapped = False

    def swap_then_rename(parent: int, source: str, destination: str) -> None:
        nonlocal swapped
        if destination == "APP.EXE" and not swapped:
            output.rename(held_output)
            output.symlink_to(outside, target_is_directory=True)
            swapped = True
        original_rename(parent, source, destination)

    monkeypatch.setattr(secure_paths_posix, "_rename_noreplace_at", swap_then_rename)
    with pytest.raises(SecurePathError, match="component changed while held"):
        atomic_publish_relative(root, "build/APP.EXE", b"candidate")

    assert not (outside / "APP.EXE").exists()
    assert not (held_output / "APP.EXE").exists()


def test_failed_publication_cleanup_preserves_competing_final_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    target = root / "build/APP.EXE"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"previous")
    original_rename = secure_paths_posix._rename_noreplace_at
    raced = False

    def rename_then_compete(parent: int, source: str, destination: str) -> None:
        nonlocal raced
        original_rename(parent, source, destination)
        if destination == "APP.EXE" and not raced:
            target.unlink()
            target.write_bytes(b"competing replacement")
            raced = True

    monkeypatch.setattr(secure_paths_posix, "_rename_noreplace_at", rename_then_compete)
    with pytest.raises(SecurePathError, match=r"changed during commit|original entry"):
        atomic_publish_relative(root, "build/APP.EXE", b"candidate")

    assert target.read_bytes() == b"competing replacement"


def test_failed_stream_publication_preserves_competing_final_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "cache/object"
    original_rename = secure_paths_posix._rename_noreplace_at
    raced = False

    def rename_then_compete(parent: int, source: str, destination: str) -> None:
        nonlocal raced
        original_rename(parent, source, destination)
        if destination == "object" and not raced:
            target.unlink()
            target.write_bytes(b"competing replacement")
            raced = True

    monkeypatch.setattr(secure_paths_posix, "_rename_noreplace_at", rename_then_compete)
    with pytest.raises(SecurePathError, match="changed during commit"):
        atomic_publish_new_relative_from_stream(
            root,
            "cache/object",
            io.BytesIO(b"candidate"),
        )

    assert target.read_bytes() == b"competing replacement"


def test_failed_promotion_preserves_competing_final_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    root.mkdir()
    source = root / "incoming/object"
    source.parent.mkdir()
    source.write_bytes(b"candidate")
    expected = digest_relative_file(root, "incoming/object")
    target = root / "blobs/object"
    original_rename = secure_paths_posix._rename_noreplace_between
    raced = False

    def rename_then_compete(
        source_parent: int,
        source_name: str,
        destination_parent: int,
        destination_name: str,
    ) -> None:
        nonlocal raced
        original_rename(
            source_parent,
            source_name,
            destination_parent,
            destination_name,
        )
        if destination_name == "object" and not raced:
            target.unlink()
            target.write_bytes(b"competing replacement")
            raced = True

    monkeypatch.setattr(
        secure_paths_posix,
        "_rename_noreplace_between",
        rename_then_compete,
    )
    with pytest.raises(SecurePathError, match="competing entry preserved"):
        promote_relative_new(
            root,
            "incoming/object",
            "blobs/object",
            expected=expected,
        )

    assert not source.exists()
    assert not target.exists()
    guards = tuple(target.parent.glob(".object.reprobit-guard-*"))
    assert len(guards) == 1
    assert guards[0].read_bytes() == b"competing replacement"


def test_promotion_preserves_a_source_replacement_raced_at_move(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "state"
    source = root / "incoming/object"
    moved = root / "incoming/original"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"candidate")
    expected = digest_relative_file(root, "incoming/object")
    original_rename = secure_paths_posix._rename_noreplace_between
    raced = False

    def replace_before_move(
        source_parent: int,
        name: str,
        destination_parent: int,
        destination: str,
    ) -> None:
        nonlocal raced
        if name == "object" and destination == "object" and not raced:
            os.replace(source, moved)
            source.write_bytes(b"peer")
            raced = True
        original_rename(source_parent, name, destination_parent, destination)

    monkeypatch.setattr(
        secure_paths_posix,
        "_rename_noreplace_between",
        replace_before_move,
    )

    with pytest.raises(SecurePathError, match="competing entry preserved"):
        promote_relative_new(
            root,
            "incoming/object",
            "published/object",
            expected=expected,
        )

    assert raced
    assert not source.exists()
    assert moved.read_bytes() == b"candidate"
    assert not (root / "published/object").exists()
    guards = tuple((root / "published").glob(".object.reprobit-guard-*"))
    assert len(guards) == 1
    assert guards[0].read_bytes() == b"peer"


def test_atomic_publication_rejects_redirected_final_parent(tmp_path: Path) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "build").symlink_to(outside, target_is_directory=True)

    with pytest.raises(SecurePathError, match="absent or redirected"):
        atomic_publish_relative(root, "build/APP.EXE", b"candidate")
    assert not (outside / "APP.EXE").exists()


def test_publication_rollback_removes_only_the_exact_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    snapshot = atomic_publish_relative(root, "reports/report.json", b"first")

    assert remove_published_relative(root, "reports/report.json", expected=snapshot)
    assert not (root / "reports/report.json").exists()

    snapshot = atomic_publish_relative(root, "reports/report.json", b"second")
    (root / "reports/report.json").write_bytes(b"attacker replacement")
    assert not remove_published_relative(root, "reports/report.json", expected=snapshot)
    assert (root / "reports/report.json").read_bytes() == b"attacker replacement"


def test_publication_rollback_preserves_a_replacement_raced_at_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "reports/report.json"
    moved = root / "reports/original.json"
    snapshot = atomic_publish_relative(root, "reports/report.json", b"report")
    original_rename = secure_paths_posix._rename_noreplace_at
    raced = False

    def replace_before_quarantine(parent: int, source: str, destination: str) -> None:
        nonlocal raced
        if source == "report.json" and ".reprobit-guard-" in destination and not raced:
            os.replace(target, moved)
            target.write_bytes(b"peer")
            raced = True
        original_rename(parent, source, destination)

    monkeypatch.setattr(
        secure_paths_posix,
        "_rename_noreplace_at",
        replace_before_quarantine,
    )

    assert not remove_published_relative(root, "reports/report.json", expected=snapshot)
    assert raced
    assert target.read_bytes() == b"peer"
    assert moved.read_bytes() == b"report"


def test_publication_rollback_preserves_same_inode_mode_mutation(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    snapshot = atomic_publish_relative(root, "reports/report.json", b"report")
    target = root / "reports/report.json"
    target.chmod(0o755)

    assert not remove_published_relative(
        root,
        "reports/report.json",
        expected=snapshot,
    )
    assert target.read_bytes() == b"report"
    assert target.stat().st_mode & 0o777 == 0o755


def test_native_held_set_and_rollback_use_strong_write_excluding_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    payload = b"native"
    strong = (
        0x1234567800000007,
        b"file-id",
        5,
        13,
        17,
        len(payload),
        1,
        False,
        0x22,
    )
    volume, index = (
        (strong[0], int.from_bytes(strong[1], "little"))
        if secure_paths_windows._STAT_USES_FILE_ID_INFO
        else (7, 11)
    )
    basic = (volume, index, len(payload), 13, 0x22)
    expected = SecureFileSnapshot(
        root / "target.exe",
        Digest.from_bytes(payload),
        len(payload),
        basic[0],
        basic[1],
        basic[3],
        0,
        strong[4],
        strong[1],
        strong[8],
    )

    class FakeApi:
        def __init__(self) -> None:
            self.opens: list[dict[str, object]] = []
            self.deleted = False

        def open_relative(self, _parent: object, _name: str, **kwargs: object) -> object:
            self.opens.append(kwargs)
            return object()

        def identity(self, _handle: object) -> tuple[int, int, int, int, int]:
            return basic

        def strong_identity(
            self, _handle: object
        ) -> tuple[int, bytes, int, int, int, int, int, bool, int]:
            return strong

        def read(self, _handle: object) -> bytes:
            return payload

        def delete_on_close(self, _handle: object) -> None:
            self.deleted = True

        def close(self, _handle: object) -> None:
            return None

    class FakeHeld:
        def __init__(self, path: Path, api: FakeApi) -> None:
            self.path = path
            self.api = api

        def __enter__(self) -> FakeHeld:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def parent_chain(
            self, _relative: object, *, create: bool
        ) -> tuple[list[object], list[object], str]:
            assert create is False
            return [object()], [], "target.exe"

        def recheck(self, _edges: object) -> None:
            return None

    apis: list[FakeApi] = []

    def held_factory(path: Path) -> FakeHeld:
        api = FakeApi()
        apis.append(api)
        return FakeHeld(path, api)

    monkeypatch.setattr(secure_paths.os, "name", "nt")
    monkeypatch.setattr(secure_paths_windows, "_HeldWindowsRoot", held_factory)

    with hold_relative_file_set(root, {"target.exe": expected}):
        pass
    assert len(apis[0].opens) == 2
    assert all(value["deny_other_writes"] is True for value in apis[0].opens)

    assert remove_published_relative(root, "target.exe", expected=expected)
    assert len(apis[1].opens) == 1
    assert apis[1].opens[0]["delete"] is True
    assert apis[1].opens[0]["deny_other_writes"] is True
    assert apis[1].deleted is True


def test_native_basic_attribute_preflight_rejects_nonrecreatable_states() -> None:
    assert secure_paths.windows_attributes_are_basic_restorable(0x20)
    assert secure_paths.windows_attributes_are_basic_restorable(0x1 | 0x2 | 0x4)
    assert secure_paths.windows_attributes_are_basic_restorable(0x80)
    assert not secure_paths.windows_attributes_are_basic_restorable(0x80 | 0x20)
    assert not secure_paths.windows_attributes_are_basic_restorable(0x200)  # sparse
    assert not secure_paths.windows_attributes_are_basic_restorable(0x800)  # compressed
    assert not secure_paths.windows_attributes_are_basic_restorable(0x4000)  # encrypted


def test_publication_rollback_never_follows_a_replacement_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    outside = tmp_path / "outside.json"
    root.mkdir()
    outside.write_bytes(b"outside")
    snapshot = atomic_publish_relative(root, "reports/report.json", b"report")
    (root / "reports/report.json").unlink()
    (root / "reports/report.json").symlink_to(outside)

    assert not remove_published_relative(root, "reports/report.json", expected=snapshot)
    assert outside.read_bytes() == b"outside"
