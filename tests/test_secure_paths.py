from __future__ import annotations

import io
import os
from pathlib import Path
from typing import BinaryIO

import pytest

import reprobit.secure_paths as secure_paths
from reprobit.model import Digest
from reprobit.secure_paths import (
    SecurePathError,
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

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="POSIX handle-relative implementation"
)


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


def test_atomic_publication_replaces_only_regular_targets_and_reseals(
    tmp_path: Path,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    published = atomic_publish_relative(root, "build/APP.EXE", b"candidate")

    assert (root / "build/APP.EXE").read_bytes() == b"candidate"
    assert reseal_relative_file(
        root, "build/APP.EXE", expected=published
    ) == published
    replacement = atomic_publish_relative(
        root, "build/APP.EXE", b"replacement"
    )
    assert (root / "build/APP.EXE").read_bytes() == b"replacement"
    assert replacement.digest != published.digest
    assert reseal_relative_file(
        root, "build/APP.EXE", expected=replacement
    ) == replacement

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


def test_byte_publication_rejects_commit_time_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    target = root / "build/APP.EXE"
    root.mkdir()
    original_replace = secure_paths.os.replace

    def replace_then_chmod(*args: object, **kwargs: object) -> None:
        original_replace(*args, **kwargs)
        target.chmod(0o755)

    monkeypatch.setattr(secure_paths.os, "replace", replace_then_chmod)
    with pytest.raises(SecurePathError, match="attributes changed during commit"):
        atomic_publish_relative(root, "build/APP.EXE", b"candidate")


def test_stream_publication_rejects_commit_time_chmod(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    target = root / "cache/object"
    root.mkdir()
    original_link = secure_paths.os.link

    def link_then_chmod(*args: object, **kwargs: object) -> None:
        original_link(*args, **kwargs)
        target.chmod(0o755)

    monkeypatch.setattr(secure_paths.os, "link", link_then_chmod)
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
    assert digest_relative_file(destination_root, "objects/large.bin").digest == (
        receipt.digest
    )


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
    original_link = secure_paths.os.link

    def publish_racer_then_link(*args: object, **kwargs: object) -> None:
        (root / "cache/object").write_bytes(b"racer")
        original_link(*args, **kwargs)

    monkeypatch.setattr(secure_paths.os, "link", publish_racer_then_link)
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
    original_replace = secure_paths.os.replace
    swapped = False

    def swap_then_replace(*args: object, **kwargs: object) -> None:
        nonlocal swapped
        if not swapped:
            output.rename(held_output)
            output.symlink_to(outside, target_is_directory=True)
            swapped = True
        original_replace(*args, **kwargs)

    monkeypatch.setattr(secure_paths.os, "replace", swap_then_replace)
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
    original_replace = secure_paths.os.replace
    raced = False

    def replace_then_compete(*args: object, **kwargs: object) -> None:
        nonlocal raced
        original_replace(*args, **kwargs)
        if not raced:
            target.unlink()
            target.write_bytes(b"competing replacement")
            raced = True

    monkeypatch.setattr(secure_paths.os, "replace", replace_then_compete)
    with pytest.raises(SecurePathError, match="changed during commit"):
        atomic_publish_relative(root, "build/APP.EXE", b"candidate")

    assert target.read_bytes() == b"competing replacement"


def test_failed_stream_publication_preserves_competing_final_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "cache/object"
    original_link = secure_paths.os.link
    raced = False

    def link_then_compete(*args: object, **kwargs: object) -> None:
        nonlocal raced
        original_link(*args, **kwargs)
        if not raced:
            target.unlink()
            target.write_bytes(b"competing replacement")
            raced = True

    monkeypatch.setattr(secure_paths.os, "link", link_then_compete)
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
    original_link = secure_paths.os.link
    raced = False

    def link_then_compete(*args: object, **kwargs: object) -> None:
        nonlocal raced
        original_link(*args, **kwargs)
        if not raced:
            target.unlink()
            target.write_bytes(b"competing replacement")
            raced = True

    monkeypatch.setattr(secure_paths.os, "link", link_then_compete)
    with pytest.raises(SecurePathError, match="promotion target changed"):
        promote_relative_new(
            root,
            "incoming/object",
            "blobs/object",
            expected=expected,
        )

    assert source.read_bytes() == b"candidate"
    assert target.read_bytes() == b"competing replacement"


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

    assert remove_published_relative(
        root, "reports/report.json", expected=snapshot
    )
    assert not (root / "reports/report.json").exists()

    snapshot = atomic_publish_relative(root, "reports/report.json", b"second")
    (root / "reports/report.json").write_bytes(b"attacker replacement")
    assert not remove_published_relative(
        root, "reports/report.json", expected=snapshot
    )
    assert (root / "reports/report.json").read_bytes() == b"attacker replacement"


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
    basic = (7, 11, len(payload), 13, 0x22)
    strong = (7, b"file-id", 5, 13, 17, len(payload), 1, False, 0x22)
    expected = secure_paths.SecureFileSnapshot(
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
    monkeypatch.setattr(secure_paths, "_HeldWindowsRoot", held_factory)

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

    assert not remove_published_relative(
        root, "reports/report.json", expected=snapshot
    )
    assert outside.read_bytes() == b"outside"
