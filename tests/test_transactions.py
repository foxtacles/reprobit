from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, BinaryIO

import pytest

import reprobit.transactions as transactions
from reprobit.secure_path_contracts import SecurePathError
from reprobit.transactions import CASTransaction, TransactionConflict, TransactionError

TRANSACTION_ID = "a" * 32


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recovery_record(
    *,
    transaction_id: str = TRANSACTION_ID,
    transaction_directory: str | None = None,
    state: str = "prepared",
    operations: list[dict[str, object]] | None = None,
    directories: dict[str, list[int]] | None = None,
) -> dict[str, object]:
    return {
        "schema": CASTransaction.JOURNAL_SCHEMA,
        "transaction_id": transaction_id,
        "state": state,
        "operations": operations or [],
        "directories": directories or {},
        "transaction_directory": transaction_directory or transaction_id,
    }


def directory_record(path: Path) -> list[int]:
    metadata = path.stat(follow_symlinks=False)
    return [metadata.st_dev, metadata.st_ino]


def _create_windows_junction(junction: Path, target: Path) -> None:
    result = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(target)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip(f"fixture host cannot create a junction: {result.stdout.strip()}")


def test_transaction_atomically_writes_and_deletes(tmp_path: Path) -> None:
    old = tmp_path / "old.txt"
    old.write_bytes(b"old")
    with CASTransaction(tmp_path) as transaction:
        transaction.write("nested/new.txt", b"new", expected_sha256=None)
        transaction.delete("old.txt", expected_sha256=digest(b"old"))

    assert (tmp_path / "nested/new.txt").read_bytes() == b"new"
    assert not old.exists()
    assert list((tmp_path / ".reprobit-transactions").glob("*/journal.json")) == []


def test_transaction_accepts_native_paths_but_rejects_raw_backslashes(
    tmp_path: Path,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write(Path("nested") / "result.txt", b"result", expected_sha256=None)
    transaction.commit()

    assert (tmp_path / "nested/result.txt").read_bytes() == b"result"
    with pytest.raises(ValueError, match="unsafe character"):
        CASTransaction(tmp_path).write(
            r"nested\result.txt",
            b"unsafe",
            expected_sha256=None,
        )


def test_preimage_conflict_leaves_every_target_unchanged(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    transaction = CASTransaction(tmp_path)
    transaction.write("first.txt", b"changed", expected_sha256=digest(b"one"))
    transaction.write("second.txt", b"changed", expected_sha256=digest(b"wrong"))

    with pytest.raises(TransactionConflict):
        transaction.commit()
    assert first.read_bytes() == b"one"
    assert second.read_bytes() == b"two"


def test_automatic_preimage_is_still_compare_and_swap(tmp_path: Path) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"before")
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"after")
    target.write_bytes(b"raced")

    with pytest.raises(TransactionConflict):
        transaction.commit()
    assert target.read_bytes() == b"raced"


def test_prepared_preimage_conflict_preserves_concurrent_file_and_cleans_staging(
    tmp_path: Path,
) -> None:
    target = tmp_path / "new.txt"
    transaction = CASTransaction(tmp_path)
    transaction.write("new.txt", b"transaction", expected_sha256=None)
    target.write_bytes(b"concurrent")

    with pytest.raises(TransactionConflict, match="transaction preimage conflict"):
        transaction.commit()

    assert target.read_bytes() == b"concurrent"
    state_root = tmp_path / ".reprobit-transactions"
    assert tuple(path for path in state_root.iterdir() if path.is_dir()) == ()


def test_recovery_removes_private_staging_left_before_payload_copy(tmp_path: Path) -> None:
    state = tmp_path / ".reprobit-transactions"
    directory = state / TRANSACTION_ID
    (directory / "staged").mkdir(parents=True)
    (directory / "backups").mkdir()
    record = {
        "schema": CASTransaction.JOURNAL_SCHEMA,
        "transaction_id": TRANSACTION_ID,
        "state": "prepared",
        "operations": [
            {
                "index": 0,
                "kind": "write",
                "path": "value.txt",
                "expected_sha256": None,
                "result_sha256": digest(b"new"),
                "preimage": None,
                "staged": None,
                "backup": "backups/0",
                "staged_path": "staged/0",
            }
        ],
        "transaction_directory": TRANSACTION_ID,
    }
    (directory / "journal.json").write_text(json.dumps(record))

    assert CASTransaction.recover(tmp_path) == (TRANSACTION_ID,)
    assert not directory.exists()


def test_apply_rechecks_an_existing_preimage_after_moving_it_to_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"before")
    original = tmp_path / "original.txt"
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"after", expected_sha256=digest(b"before"))
    real_move = transactions._move_to_backup
    raced = False

    def swap_after_verification(
        root: Path,
        source: Path,
        backup: Path,
        *,
        expected: Any,
        expected_directories: dict[str, tuple[int, int]],
    ) -> object:
        nonlocal raced
        if source == Path("value.txt") and not raced:
            raced = True
            os.replace(target, original)
            target.write_bytes(b"external")
        return real_move(
            root,
            source,
            backup,
            expected=expected,
            expected_directories=expected_directories,
        )

    monkeypatch.setattr(transactions, "_move_to_backup", swap_after_verification)

    with pytest.raises(TransactionConflict, match="changed while applying") as caught:
        transaction.commit()

    assert raced
    assert target.read_bytes() == b"external"
    assert original.read_bytes() == b"before"
    assert any("rollback also failed" in note for note in caught.value.__notes__)


def test_preimage_move_never_follows_an_ancestor_swapped_to_a_link(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested = tmp_path / "nested"
    moved = tmp_path / "moved"
    outside = tmp_path / "outside"
    nested.mkdir()
    outside.mkdir()
    (nested / "value.txt").write_bytes(b"before")
    (outside / "value.txt").write_bytes(b"outside")
    transaction = CASTransaction(tmp_path)
    transaction.write("nested/value.txt", b"after", expected_sha256=digest(b"before"))
    real_move = transactions._move_to_backup

    def swap_parent_then_move(
        root: Path,
        source: Path,
        backup: Path,
        *,
        expected: Any,
        expected_directories: dict[str, tuple[int, int]],
    ) -> object:
        os.replace(nested, moved)
        try:
            nested.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            pytest.skip(f"host cannot create a test symlink: {error}")
        return real_move(
            root,
            source,
            backup,
            expected=expected,
            expected_directories=expected_directories,
        )

    monkeypatch.setattr(transactions, "_move_to_backup", swap_parent_then_move)

    with pytest.raises(TransactionConflict, match="changed while applying"):
        transaction.commit()

    assert (outside / "value.txt").read_bytes() == b"outside"
    assert (moved / "value.txt").read_bytes() == b"before"


def test_failed_existing_write_never_removes_an_external_same_content_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"before")
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"after", expected_sha256=digest(b"before"))
    real_publish = transactions._promote_staged

    def create_external_then_publish(
        root: Path,
        source: Path,
        relative: Path,
        **kwargs: Any,
    ) -> object:
        target.write_bytes(b"after")
        return real_publish(root, source, relative, **kwargs)

    monkeypatch.setattr(
        transactions,
        "_promote_staged",
        create_external_then_publish,
    )

    with pytest.raises(TransactionConflict, match="changed while applying") as caught:
        transaction.commit()

    assert target.read_bytes() == b"after"
    assert any("rollback also failed" in note for note in caught.value.__notes__)
    journal = tmp_path / ".reprobit-transactions" / transaction.transaction_id / "journal.json"
    assert journal.is_file()


def test_apply_never_overwrites_a_target_created_after_absent_preimage_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "new.txt"
    transaction = CASTransaction(tmp_path)
    transaction.write("new.txt", b"transaction", expected_sha256=None)
    real_publish = transactions._promote_staged
    raced = False

    def create_external_then_publish(
        root: Path,
        source: Path,
        relative: Path,
        **kwargs: Any,
    ) -> object:
        nonlocal raced
        raced = True
        target.write_bytes(b"external")
        return real_publish(root, source, relative, **kwargs)

    monkeypatch.setattr(
        transactions,
        "_promote_staged",
        create_external_then_publish,
    )

    with pytest.raises(TransactionConflict, match="changed while applying"):
        transaction.commit()

    assert raced
    assert target.read_bytes() == b"external"
    state_root = tmp_path / ".reprobit-transactions"
    assert tuple(path for path in state_root.iterdir() if path.is_dir()) == ()


def test_apply_refuses_a_replaced_real_target_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "nested"
    moved = tmp_path / "original-parent"
    parent.mkdir()
    transaction = CASTransaction(tmp_path)
    transaction.write("nested/new.txt", b"transaction", expected_sha256=None)
    real_publish = transactions._promote_staged

    def swap_parent_then_publish(
        root: Path,
        source: Path,
        relative: Path,
        **kwargs: Any,
    ) -> object:
        os.replace(parent, moved)
        parent.mkdir()
        (parent / "keep.txt").write_bytes(b"replacement")
        return real_publish(root, source, relative, **kwargs)

    monkeypatch.setattr(transactions, "_promote_staged", swap_parent_then_publish)

    with pytest.raises(TransactionConflict, match="changed while applying"):
        transaction.commit()

    assert not (moved / "new.txt").exists()
    assert tuple(path.name for path in parent.iterdir()) == ("keep.txt",)


def test_json_assertion_refuses_a_replaced_real_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    moved = tmp_path / "original-authority"
    authority.mkdir()
    (authority / "first.json").write_bytes(b"first")
    transaction = CASTransaction(tmp_path)
    transaction.assert_json_members("authority", expected_members=("first.json",))
    transaction.write("result.json", b"result", expected_sha256=None)
    real_publish = transactions._promote_staged

    def swap_authority_then_publish(
        root: Path,
        source: Path,
        relative: Path,
        **kwargs: Any,
    ) -> object:
        os.replace(authority, moved)
        authority.mkdir()
        (authority / "first.json").write_bytes(b"first")
        return real_publish(root, source, relative, **kwargs)

    monkeypatch.setattr(transactions, "_promote_staged", swap_authority_then_publish)

    with pytest.raises(TransactionConflict, match="transaction directory changed"):
        transaction.commit()

    assert (authority / "first.json").read_bytes() == b"first"
    assert (moved / "first.json").read_bytes() == b"first"
    assert not (tmp_path / "result.json").exists()


def test_write_postimage_is_rechecked_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "result.bin"
    transaction = CASTransaction(tmp_path)
    transaction.write("result.bin", b"transaction", expected_sha256=None)
    real_publish = transactions._promote_staged

    def replace_after_publish(
        root: Path,
        source: Path,
        relative: Path,
        **kwargs: Any,
    ) -> object:
        published = real_publish(root, source, relative, **kwargs)
        target.write_bytes(b"external")
        return published

    monkeypatch.setattr(transactions, "_promote_staged", replace_after_publish)

    with pytest.raises(TransactionConflict, match="postimage conflict") as caught:
        transaction.commit()

    assert target.read_bytes() == b"external"
    assert any("rollback also failed" in note for note in caught.value.__notes__)


def test_delete_postimage_is_rechecked_before_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "value.bin"
    target.write_bytes(b"before")
    transaction = CASTransaction(tmp_path)
    transaction.delete("value.bin", expected_sha256=digest(b"before"))
    real_move = transactions._move_to_backup

    def replace_after_move(
        root: Path,
        source: Path,
        backup: Path,
        *,
        expected: Any,
        expected_directories: dict[str, tuple[int, int]],
    ) -> object:
        moved = real_move(
            root,
            source,
            backup,
            expected=expected,
            expected_directories=expected_directories,
        )
        target.write_bytes(b"external")
        return moved

    monkeypatch.setattr(transactions, "_move_to_backup", replace_after_move)

    with pytest.raises(TransactionConflict, match="postimage conflict") as caught:
        transaction.commit()

    assert target.read_bytes() == b"external"
    assert any("rollback also failed" in note for note in caught.value.__notes__)


def test_transaction_does_not_duplicate_payload_in_its_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("result.bin", b"payload", expected_sha256=None)
    real_stage = transactions._publish_new_from_stream
    real_promote = transactions._promote_staged
    staged_calls = 0

    def stage_once(
        root: Path,
        relative: str,
        source: BinaryIO,
        **kwargs: Any,
    ) -> object:
        nonlocal staged_calls
        staged_calls += 1
        assert relative.endswith("/staged/0")
        return real_stage(root, relative, source, **kwargs)

    def inspect_then_promote(
        root: Path,
        source: Path,
        relative: Path,
        **kwargs: Any,
    ) -> object:
        transaction_directory = tmp_path / ".reprobit-transactions" / transaction.transaction_id
        assert not (transaction_directory / "payloads").exists()
        operation = json.loads(
            (transaction_directory / "journal.json").read_text(encoding="utf-8")
        )["operations"][0]
        assert "payload" not in operation
        assert operation["staged"] is not None
        return real_promote(root, source, relative, **kwargs)

    monkeypatch.setattr(
        transactions,
        "_publish_new_from_stream",
        stage_once,
    )
    monkeypatch.setattr(transactions, "_promote_staged", inspect_then_promote)

    transaction.commit()

    assert staged_calls == 1
    assert (tmp_path / "result.bin").read_bytes() == b"payload"


def test_transaction_seat_is_durable_before_its_first_journal_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("result.bin", b"payload", expected_sha256=None)
    state_root = tmp_path / ".reprobit-transactions"
    real_sync = transactions.fsync_directory
    real_write = transactions._write_journal
    synced: list[Path] = []

    def observe_sync(path: Path) -> None:
        synced.append(path)
        real_sync(path)

    def require_sync(*args: Any, **kwargs: Any) -> object:
        assert synced[:2] == [tmp_path, state_root]
        return real_write(*args, **kwargs)

    monkeypatch.setattr(transactions, "fsync_directory", observe_sync)
    monkeypatch.setattr(transactions, "_write_journal", require_sync)

    transaction.commit()

    assert (tmp_path / "result.bin").read_bytes() == b"payload"


def test_transaction_refuses_a_state_root_swapped_before_lock_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / ".reprobit-transactions"
    state_root.mkdir()
    moved = tmp_path / "original-transaction-state"
    transaction = CASTransaction(tmp_path)
    transaction.write("result.bin", b"payload", expected_sha256=None)
    real_open = transactions._open_project_lock

    def swap_then_open(path: Path, identity: tuple[int, int]) -> object:
        os.replace(state_root, moved)
        state_root.mkdir()
        (state_root / "keep.txt").write_bytes(b"replacement")
        return real_open(path, identity)

    monkeypatch.setattr(transactions, "_open_project_lock", swap_then_open)

    with pytest.raises(TransactionError, match="transaction lock"):
        transaction.commit()

    assert not (tmp_path / "result.bin").exists()
    assert tuple(path.name for path in state_root.iterdir()) == ("keep.txt",)
    assert tuple(moved.iterdir()) == ()


def test_transaction_never_creates_a_seat_in_a_replacement_state_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state_root = tmp_path / ".reprobit-transactions"
    moved = tmp_path / "original-transaction-state"
    transaction = CASTransaction(tmp_path)
    transaction.write("result.bin", b"payload", expected_sha256=None)
    real_create = transactions.create_directory_in_exact_parent
    swap_blocked = False

    def swap_then_create(path: Path, identity: tuple[int, int]) -> tuple[int, int]:
        nonlocal swap_blocked
        if path.name == transaction.transaction_id:
            if os.name == "nt":
                # The held project lock denies delete sharing, so Windows
                # prevents replacing its directory before seat creation.
                with pytest.raises(PermissionError):
                    os.replace(state_root, moved)
                swap_blocked = True
            else:
                os.replace(state_root, moved)
                state_root.mkdir()
                (state_root / "keep.txt").write_bytes(b"replacement")
        return real_create(path, identity)

    monkeypatch.setattr(
        transactions,
        "create_directory_in_exact_parent",
        swap_then_create,
    )

    if os.name == "nt":
        transaction.commit()
        assert swap_blocked
        assert not moved.exists()
        assert (tmp_path / "result.bin").read_bytes() == b"payload"
        assert not (state_root / transaction.transaction_id).exists()
        assert (state_root / "project.lock").is_file()
        return

    with pytest.raises(TransactionError, match="create transaction seat"):
        transaction.commit()

    assert not (tmp_path / "result.bin").exists()
    assert tuple(path.name for path in state_root.iterdir()) == ("keep.txt",)
    assert not (state_root / transaction.transaction_id).exists()
    assert (moved / "project.lock").is_file()


def test_private_subdirectories_are_durable_before_applying(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "result.bin"
    target.write_bytes(b"before")
    transaction = CASTransaction(tmp_path)
    transaction.write("result.bin", b"after", expected_sha256=digest(b"before"))
    directory = tmp_path / ".reprobit-transactions" / transaction.transaction_id
    real_sync = transactions._sync_transaction_directory
    real_write = transactions._write_journal
    private_synced = False

    def observe_sync(path: Path, identity: tuple[int, int]) -> None:
        nonlocal private_synced
        assert (path / "staged").is_dir()
        assert (path / "backups" / ".ready").is_file()
        real_sync(path, identity)
        private_synced = True

    def require_sync_before_applying(
        root: Path,
        relative: Path,
        record: dict[str, Any],
        **kwargs: Any,
    ) -> object:
        if record["state"] == "applying":
            assert private_synced
            assert directory.is_dir()
        return real_write(root, relative, record, **kwargs)

    monkeypatch.setattr(transactions, "_sync_transaction_directory", observe_sync)
    monkeypatch.setattr(transactions, "_write_journal", require_sync_before_applying)

    transaction.commit()

    assert target.read_bytes() == b"after"


def test_compare_only_precondition_is_not_rewritten_or_reported_changed(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "authority.json"
    authority.write_bytes(b"authority")
    before = authority.stat()
    transaction = CASTransaction(tmp_path)
    transaction.assert_unchanged("authority.json")
    transaction.write("result.json", b"result", expected_sha256=None)

    committed = transaction.commit()

    after = authority.stat()
    assert authority.read_bytes() == b"authority"
    assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    assert committed.changed_paths == (Path("result.json"),)


def test_same_content_write_becomes_a_compare_only_precondition(tmp_path: Path) -> None:
    target = tmp_path / "large.bin"
    target.write_bytes(b"unchanged")
    before = target.stat()
    transaction = CASTransaction(tmp_path)
    transaction.write("large.bin", b"unchanged")

    committed = transaction.commit()

    after = target.stat()
    assert committed.changed_paths == ()
    assert (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino)
    assert (
        tuple(path for path in (tmp_path / ".reprobit-transactions").iterdir() if path.is_dir())
        == ()
    )


def test_compare_only_precondition_aborts_a_racing_write(tmp_path: Path) -> None:
    authority = tmp_path / "authority.json"
    authority.write_bytes(b"authority")
    transaction = CASTransaction(tmp_path)
    transaction.assert_unchanged("authority.json")
    transaction.write("result.json", b"result", expected_sha256=None)
    authority.write_bytes(b"raced")

    with pytest.raises(TransactionConflict):
        transaction.commit()
    assert not (tmp_path / "result.json").exists()


def test_compare_only_precondition_is_rechecked_after_output_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority.json"
    authority.write_bytes(b"authority")
    transaction = CASTransaction(tmp_path)
    transaction.assert_unchanged("authority.json")
    transaction.write("result.json", b"result", expected_sha256=None)
    real_publish = transactions._promote_staged

    def race_then_publish(
        root: Path,
        source: Path,
        relative: Path,
        **kwargs: Any,
    ) -> object:
        authority.write_bytes(b"raced")
        return real_publish(root, source, relative, **kwargs)

    monkeypatch.setattr(transactions, "_promote_staged", race_then_publish)

    with pytest.raises(TransactionConflict, match="postimage conflict"):
        transaction.commit()

    assert authority.read_bytes() == b"raced"
    assert not (tmp_path / "result.json").exists()


def test_directory_membership_assertion_only_transaction_is_checked(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    (authority / "first.json").write_bytes(b"first")
    transaction = CASTransaction(tmp_path)
    transaction.assert_json_members(
        "authority",
        expected_members=("first.json",),
    )

    committed = transaction.commit()

    assert committed.changed_paths == ()


def test_empty_directory_membership_allows_first_transaction_write(tmp_path: Path) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.assert_json_members("authority", expected_members=())
    transaction.write("authority/first.json", b"first", expected_sha256=None)

    committed = transaction.commit()

    assert committed.changed_paths == (Path("authority/first.json"),)
    assert (tmp_path / "authority/first.json").read_bytes() == b"first"


def test_missing_directory_conflicts_with_nonempty_membership(tmp_path: Path) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.assert_json_members("authority", expected_members=("first.json",))

    with pytest.raises(TransactionConflict, match="authority membership conflict"):
        transaction.commit()


def test_missing_directory_membership_rejects_a_first_external_json_write(
    tmp_path: Path,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.assert_json_members("authority", expected_members=())
    transaction.write("authority/first.json", b"first", expected_sha256=None)
    authority = tmp_path / "authority"
    authority.mkdir()
    (authority / "raced.json").write_bytes(b"raced")

    with pytest.raises(TransactionConflict, match="authority membership conflict"):
        transaction.commit()
    assert not (authority / "first.json").exists()
    assert (authority / "raced.json").read_bytes() == b"raced"


def test_directory_membership_assertion_only_transaction_rejects_a_race(
    tmp_path: Path,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    (authority / "first.json").write_bytes(b"first")
    transaction = CASTransaction(tmp_path)
    transaction.assert_json_members(
        "authority",
        expected_members=("first.json",),
    )
    (authority / "second.json").write_bytes(b"second")

    with pytest.raises(TransactionConflict, match="authority membership conflict"):
        transaction.commit()


def test_directory_membership_is_rechecked_after_output_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = tmp_path / "authority"
    authority.mkdir()
    (authority / "first.json").write_bytes(b"first")
    transaction = CASTransaction(tmp_path)
    transaction.assert_json_members("authority", expected_members=("first.json",))
    transaction.write("result.json", b"result", expected_sha256=None)
    real_publish = transactions._promote_staged

    def race_then_publish(
        root: Path,
        source: Path,
        relative: Path,
        **kwargs: Any,
    ) -> object:
        (authority / "second.json").write_bytes(b"second")
        return real_publish(root, source, relative, **kwargs)

    monkeypatch.setattr(transactions, "_promote_staged", race_then_publish)

    with pytest.raises(TransactionConflict, match="authority membership conflict"):
        transaction.commit()

    assert (authority / "first.json").read_bytes() == b"first"
    assert (authority / "second.json").read_bytes() == b"second"
    assert not (tmp_path / "result.json").exists()


def test_recovery_rolls_back_an_interrupted_install(tmp_path: Path) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"new")
    publication = transactions._publication_record(
        transactions.digest_relative_file(tmp_path, "value.txt")
    )
    state = tmp_path / ".reprobit-transactions"
    directory = state / TRANSACTION_ID
    backup = directory / "backups" / "0"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"old")
    backup_snapshot = transactions._publication_record(
        transactions.digest_relative_file(tmp_path, backup.relative_to(tmp_path).as_posix())
    )
    record = {
        "schema": CASTransaction.JOURNAL_SCHEMA,
        "transaction_id": TRANSACTION_ID,
        "state": "applying",
        "directories": {".": directory_record(tmp_path)},
        "operations": [
            {
                "index": 0,
                "kind": "write",
                "path": "value.txt",
                "expected_sha256": digest(b"old"),
                "result_sha256": digest(b"new"),
                "preimage": backup_snapshot,
                "staged": publication,
                "backup": "backups/0",
                "staged_path": "staged/0",
            }
        ],
        "transaction_directory": TRANSACTION_ID,
    }
    (directory / "journal.json").write_text(json.dumps(record))

    assert CASTransaction.recover(tmp_path) == (TRANSACTION_ID,)
    assert target.read_bytes() == b"old"
    assert not directory.exists()


def test_recovery_refuses_to_overwrite_unknown_post_crash_contents(tmp_path: Path) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"new")
    publication = transactions._publication_record(
        transactions.digest_relative_file(tmp_path, "value.txt")
    )
    target.write_bytes(b"changed after crash")
    state = tmp_path / ".reprobit-transactions"
    directory = state / TRANSACTION_ID
    backup = directory / "backups" / "0"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"old")
    backup_snapshot = transactions._publication_record(
        transactions.digest_relative_file(tmp_path, backup.relative_to(tmp_path).as_posix())
    )
    record = {
        "schema": CASTransaction.JOURNAL_SCHEMA,
        "transaction_id": TRANSACTION_ID,
        "state": "applying",
        "directories": {".": directory_record(tmp_path)},
        "operations": [
            {
                "index": 0,
                "kind": "write",
                "path": "value.txt",
                "expected_sha256": digest(b"old"),
                "result_sha256": digest(b"new"),
                "preimage": backup_snapshot,
                "staged": publication,
                "backup": "backups/0",
                "staged_path": "staged/0",
            }
        ],
        "transaction_directory": TRANSACTION_ID,
    }
    (directory / "journal.json").write_text(json.dumps(record))

    with pytest.raises(TransactionError, match="unknown contents"):
        CASTransaction.recover(tmp_path)
    assert target.read_bytes() == b"changed after crash"
    assert backup.read_bytes() == b"old"


@pytest.mark.skipif(os.name != "posix", reason="checks POSIX ctime receipts")
def test_recovery_refuses_a_backup_mutated_with_restored_size_and_mtime(
    tmp_path: Path,
) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"new")
    publication = transactions._publication_record(
        transactions.digest_relative_file(tmp_path, "value.txt")
    )
    directory = tmp_path / ".reprobit-transactions" / TRANSACTION_ID
    backup = directory / "backups" / "0"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"old")
    captured = transactions.digest_relative_file(
        tmp_path,
        backup.relative_to(tmp_path).as_posix(),
    )
    backup_record = transactions._publication_record(captured)
    backup.write_bytes(b"bad")
    os.utime(backup, ns=(captured.mtime_ns, captured.mtime_ns))
    operation: dict[str, object] = {
        "index": 0,
        "kind": "write",
        "path": "value.txt",
        "expected_sha256": digest(b"old"),
        "result_sha256": digest(b"new"),
        "preimage": backup_record,
        "staged": publication,
        "backup": "backups/0",
        "staged_path": "staged/0",
    }
    (directory / "journal.json").write_text(
        json.dumps(
            recovery_record(
                state="applying",
                operations=[operation],
                directories={".": directory_record(tmp_path)},
            )
        )
    )

    with pytest.raises(TransactionError, match="transaction backup changed"):
        CASTransaction.recover(tmp_path)

    assert target.read_bytes() == b"new"
    assert backup.read_bytes() == b"bad"


def test_transaction_records_target_directory_identities_before_applying(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "nested"
    parent.mkdir()
    transaction = CASTransaction(tmp_path)
    transaction.write("nested/value.txt", b"new", expected_sha256=None)
    real_write = transactions._write_journal
    applying_directories: dict[str, object] = {}

    def capture_applying_directories(*args: Any, **kwargs: Any) -> object:
        record = args[2]
        if record["state"] == "applying":
            applying_directories.update(record["directories"])
        return real_write(*args, **kwargs)

    monkeypatch.setattr(transactions, "_write_journal", capture_applying_directories)

    transaction.commit()

    assert applying_directories == {
        ".": directory_record(tmp_path),
        "nested": directory_record(parent),
    }


def test_recovery_restores_a_preimage_moved_before_a_crash(tmp_path: Path) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"old")
    preimage = transactions.digest_relative_file(tmp_path, "value.txt")
    state = tmp_path / ".reprobit-transactions"
    directory = state / TRANSACTION_ID
    staged = directory / "staged" / "0"
    backup = directory / "backups" / "0"
    staged.parent.mkdir(parents=True)
    backup.parent.mkdir()
    staged.write_bytes(b"new")
    staged_snapshot = transactions.digest_relative_file(
        tmp_path,
        staged.relative_to(tmp_path).as_posix(),
    )
    transactions.promote_relative_new(
        tmp_path,
        "value.txt",
        backup.relative_to(tmp_path).as_posix(),
        expected=preimage,
    )
    record = {
        "schema": CASTransaction.JOURNAL_SCHEMA,
        "transaction_id": TRANSACTION_ID,
        "state": "applying",
        "directories": {".": directory_record(tmp_path)},
        "operations": [
            {
                "index": 0,
                "kind": "write",
                "path": "value.txt",
                "expected_sha256": digest(b"old"),
                "result_sha256": digest(b"new"),
                "preimage": transactions._publication_record(preimage),
                "staged": transactions._publication_record(staged_snapshot),
                "backup": "backups/0",
                "staged_path": "staged/0",
            }
        ],
        "transaction_directory": TRANSACTION_ID,
    }
    (directory / "journal.json").write_text(json.dumps(record))

    assert CASTransaction.recover(tmp_path) == (TRANSACTION_ID,)
    assert target.read_bytes() == b"old"
    assert not directory.exists()


def test_recovery_removes_a_new_output_promoted_before_a_crash(tmp_path: Path) -> None:
    state = tmp_path / ".reprobit-transactions"
    directory = state / TRANSACTION_ID
    staged = directory / "staged" / "0"
    (directory / "backups").mkdir(parents=True)
    staged.parent.mkdir()
    staged.write_bytes(b"new")
    staged_snapshot = transactions.digest_relative_file(
        tmp_path,
        staged.relative_to(tmp_path).as_posix(),
    )
    transactions.promote_relative_new(
        tmp_path,
        staged.relative_to(tmp_path).as_posix(),
        "value.txt",
        expected=staged_snapshot,
    )
    record = {
        "schema": CASTransaction.JOURNAL_SCHEMA,
        "transaction_id": TRANSACTION_ID,
        "state": "applying",
        "directories": {".": directory_record(tmp_path)},
        "operations": [
            {
                "index": 0,
                "kind": "write",
                "path": "value.txt",
                "expected_sha256": None,
                "result_sha256": digest(b"new"),
                "preimage": None,
                "staged": transactions._publication_record(staged_snapshot),
                "backup": "backups/0",
                "staged_path": "staged/0",
            }
        ],
        "transaction_directory": TRANSACTION_ID,
    }
    (directory / "journal.json").write_text(json.dumps(record))

    assert CASTransaction.recover(tmp_path) == (TRANSACTION_ID,)
    assert not (tmp_path / "value.txt").exists()
    assert not directory.exists()


def test_recovery_cleans_a_canonical_seat_left_before_its_journal(tmp_path: Path) -> None:
    directory = tmp_path / ".reprobit-transactions" / TRANSACTION_ID
    (directory / "staged").mkdir(parents=True)
    (directory / "staged" / "partial").write_bytes(b"partial")

    assert CASTransaction.recover(tmp_path) == (TRANSACTION_ID,)
    assert not directory.exists()


def test_recovery_rejects_a_noncanonical_real_seat(tmp_path: Path) -> None:
    directory = tmp_path / ".reprobit-transactions" / "not-a-transaction"
    directory.mkdir(parents=True)

    with pytest.raises(TransactionError, match="invalid transaction seat"):
        CASTransaction.recover(tmp_path)

    assert directory.is_dir()


def test_recovery_ignores_non_directory_seats_without_following_them(tmp_path: Path) -> None:
    state = tmp_path / ".reprobit-transactions"
    outside = tmp_path / "outside"
    state.mkdir()
    outside.mkdir()
    (outside / "keep.txt").write_bytes(b"keep")
    (state / TRANSACTION_ID).symlink_to(outside, target_is_directory=True)
    (state / ("b" * 32)).write_bytes(b"not a seat")

    assert CASTransaction.recover(tmp_path) == ()
    assert (outside / "keep.txt").read_bytes() == b"keep"
    assert (state / TRANSACTION_ID).is_symlink()


@pytest.mark.parametrize(
    ("transaction_id", "transaction_directory"),
    [
        ("b" * 32, TRANSACTION_ID),
        (TRANSACTION_ID, "b" * 32),
    ],
)
def test_recovery_binds_journal_identity_to_its_seat(
    tmp_path: Path,
    transaction_id: str,
    transaction_directory: str,
) -> None:
    directory = tmp_path / ".reprobit-transactions" / TRANSACTION_ID
    directory.mkdir(parents=True)
    (directory / "journal.json").write_text(
        json.dumps(
            recovery_record(
                transaction_id=transaction_id,
                transaction_directory=transaction_directory,
            )
        )
    )

    with pytest.raises(TransactionError, match="does not match its seat"):
        CASTransaction.recover(tmp_path)

    assert directory.is_dir()


def test_recovery_rejects_private_paths_that_escape_the_exact_seat(tmp_path: Path) -> None:
    directory = tmp_path / ".reprobit-transactions" / TRANSACTION_ID
    directory.mkdir(parents=True)
    operation: dict[str, object] = {
        "index": 0,
        "kind": "write",
        "path": "value.txt",
        "expected_sha256": None,
        "result_sha256": digest(b"new"),
        "preimage": None,
        "staged": None,
        "backup": "../outside",
        "staged_path": "staged/0",
    }
    (directory / "journal.json").write_text(json.dumps(recovery_record(operations=[operation])))

    with pytest.raises(TransactionError, match="malformed transaction operation"):
        CASTransaction.recover(tmp_path)

    assert directory.is_dir()


def test_recovery_requires_a_complete_target_directory_map(tmp_path: Path) -> None:
    parent = tmp_path / "nested"
    parent.mkdir()
    directory = tmp_path / ".reprobit-transactions" / TRANSACTION_ID
    directory.mkdir(parents=True)
    operation: dict[str, object] = {
        "index": 0,
        "kind": "write",
        "path": "nested/value.txt",
        "expected_sha256": None,
        "result_sha256": digest(b"new"),
        "preimage": None,
        "staged": None,
        "backup": "backups/0",
        "staged_path": "staged/0",
    }
    (directory / "journal.json").write_text(
        json.dumps(
            recovery_record(
                state="applying",
                operations=[operation],
                directories={".": directory_record(tmp_path)},
            )
        )
    )

    with pytest.raises(TransactionError, match="malformed transaction directories"):
        CASTransaction.recover(tmp_path)

    assert directory.is_dir()


def test_recovery_refuses_a_seat_swapped_before_journal_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / ".reprobit-transactions"
    directory = state / TRANSACTION_ID
    moved = state / ("b" * 32)
    directory.mkdir(parents=True)
    (directory / "journal.json").write_text(
        json.dumps(
            recovery_record(
                state="committed",
                directories={".": directory_record(tmp_path)},
            )
        )
    )
    real_read = transactions.read_relative_file

    def swap_then_read(root: Path, relative: str, **kwargs: Any) -> object:
        os.replace(directory, moved)
        directory.mkdir()
        (directory / "keep.txt").write_bytes(b"replacement")
        return real_read(root, relative, **kwargs)

    monkeypatch.setattr(transactions, "read_relative_file", swap_then_read)

    with pytest.raises(TransactionError, match="transaction seat changed"):
        CASTransaction.recover(tmp_path)

    assert (directory / "keep.txt").read_bytes() == b"replacement"
    assert (moved / "journal.json").is_file()


def test_recovery_refuses_a_state_root_swapped_before_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / ".reprobit-transactions"
    directory = state / TRANSACTION_ID
    directory.mkdir(parents=True)
    (directory / "journal.json").write_text(
        json.dumps(
            recovery_record(
                state="committed",
                directories={".": directory_record(tmp_path)},
            )
        )
    )
    moved = tmp_path / "original-transaction-state"
    real_scandir = os.scandir
    swapped = False

    def swap_then_scan(path: str | bytes | os.PathLike[str] | os.PathLike[bytes]) -> Any:
        nonlocal swapped
        if not swapped and Path(path) == state:
            swapped = True
            os.replace(state, moved)
            state.mkdir()
            (state / "keep.txt").write_bytes(b"replacement")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", swap_then_scan)

    with pytest.raises(TransactionError, match="transaction state changed"):
        CASTransaction.recover(tmp_path)

    assert tuple(path.name for path in state.iterdir()) == ("keep.txt",)
    assert (moved / TRANSACTION_ID / "journal.json").is_file()


def test_recovery_refuses_a_seat_swapped_after_journal_read_before_rollback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"new")
    publication = transactions._publication_record(
        transactions.digest_relative_file(tmp_path, "value.txt")
    )
    state = tmp_path / ".reprobit-transactions"
    directory = state / TRANSACTION_ID
    moved = state / ("b" * 32)
    backup = directory / "backups" / "0"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"old")
    backup_snapshot = transactions._publication_record(
        transactions.digest_relative_file(tmp_path, backup.relative_to(tmp_path).as_posix())
    )
    operation: dict[str, object] = {
        "index": 0,
        "kind": "write",
        "path": "value.txt",
        "expected_sha256": digest(b"old"),
        "result_sha256": digest(b"new"),
        "preimage": backup_snapshot,
        "staged": publication,
        "backup": "backups/0",
        "staged_path": "staged/0",
    }
    (directory / "journal.json").write_text(
        json.dumps(
            recovery_record(
                state="applying",
                operations=[operation],
                directories={".": directory_record(tmp_path)},
            )
        )
    )
    real_rollback = CASTransaction._rollback_record

    def swap_then_rollback(
        root: Path,
        seat: Path,
        identity: tuple[int, int],
        state_identity: tuple[int, int],
        record: dict[str, Any],
    ) -> None:
        os.replace(directory, moved)
        directory.mkdir()
        (directory / "keep.txt").write_bytes(b"replacement")
        real_rollback(root, seat, identity, state_identity, record)

    monkeypatch.setattr(CASTransaction, "_rollback_record", staticmethod(swap_then_rollback))

    with pytest.raises(TransactionError, match="transaction seat changed"):
        CASTransaction.recover(tmp_path)

    assert target.read_bytes() == b"new"
    assert (directory / "keep.txt").read_bytes() == b"replacement"
    assert (moved / "backups" / "0").read_bytes() == b"old"


def test_recovery_refuses_a_target_parent_swapped_after_journal_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "nested"
    moved = tmp_path / "original-parent"
    parent.mkdir()
    target = parent / "value.txt"
    target.write_bytes(b"new")
    publication = transactions._publication_record(
        transactions.digest_relative_file(tmp_path, "nested/value.txt")
    )
    directory = tmp_path / ".reprobit-transactions" / TRANSACTION_ID
    backup = directory / "backups" / "0"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"old")
    backup_snapshot = transactions._publication_record(
        transactions.digest_relative_file(tmp_path, backup.relative_to(tmp_path).as_posix())
    )
    operation: dict[str, object] = {
        "index": 0,
        "kind": "write",
        "path": "nested/value.txt",
        "expected_sha256": digest(b"old"),
        "result_sha256": digest(b"new"),
        "preimage": backup_snapshot,
        "staged": publication,
        "backup": "backups/0",
        "staged_path": "staged/0",
    }
    (directory / "journal.json").write_text(
        json.dumps(
            recovery_record(
                state="applying",
                operations=[operation],
                directories={
                    ".": directory_record(tmp_path),
                    "nested": directory_record(parent),
                },
            )
        )
    )
    real_rollback = CASTransaction._rollback_record

    def swap_then_rollback(
        root: Path,
        seat: Path,
        identity: tuple[int, int],
        state_identity: tuple[int, int],
        record: dict[str, Any],
    ) -> None:
        os.replace(parent, moved)
        parent.mkdir()
        (parent / "value.txt").write_bytes(b"external")
        real_rollback(root, seat, identity, state_identity, record)

    monkeypatch.setattr(CASTransaction, "_rollback_record", staticmethod(swap_then_rollback))

    with pytest.raises(TransactionError, match="transaction seat changed"):
        CASTransaction.recover(tmp_path)

    assert (parent / "value.txt").read_bytes() == b"external"
    assert (moved / "value.txt").read_bytes() == b"new"
    assert backup.read_bytes() == b"old"


def test_committed_transaction_reports_a_replacement_seat_cleanup_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"new", expected_sha256=None)
    state = tmp_path / ".reprobit-transactions"
    directory = state / transaction.transaction_id
    moved = state / ("b" * 32)
    real_remove = transactions._remove_transaction_directory

    def swap_then_remove(
        root: Path,
        seat: Path,
        identity: tuple[int, int],
        state_identity: tuple[int, int],
        *,
        journal: Any,
    ) -> None:
        os.replace(directory, moved)
        directory.mkdir()
        (directory / "keep.txt").write_bytes(b"replacement")
        real_remove(root, seat, identity, state_identity, journal=journal)

    monkeypatch.setattr(transactions, "_remove_transaction_directory", swap_then_remove)

    result = transaction.commit()

    assert (tmp_path / "value.txt").read_bytes() == b"new"
    assert result.cleanup_warning is not None
    assert "recovery state remains" in result.cleanup_warning
    assert (directory / "keep.txt").read_bytes() == b"replacement"
    journal = json.loads((moved / "journal.json").read_text())
    assert journal["state"] == "committed"


def test_committed_transaction_reports_a_quarantine_cleanup_warning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"new", expected_sha256=None)
    moved = tmp_path / "moved-original-seat"
    replacement: Path | None = None
    real_remove = transactions.remove_exact_directory_tree

    def swap_then_remove(path: Path, identity: tuple[int, int]) -> None:
        nonlocal replacement
        os.replace(path, moved)
        path.mkdir()
        (path / "keep.txt").write_bytes(b"replacement")
        replacement = path
        real_remove(path, identity)

    monkeypatch.setattr(transactions, "remove_exact_directory_tree", swap_then_remove)

    result = transaction.commit()

    assert (tmp_path / "value.txt").read_bytes() == b"new"
    assert result.cleanup_warning is not None
    assert "recovery state remains" in result.cleanup_warning
    assert replacement is not None
    assert (replacement / "keep.txt").read_bytes() == b"replacement"
    assert moved.is_dir()


def test_committed_transaction_succeeds_when_private_cleanup_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"new", expected_sha256=None)
    directory = tmp_path / ".reprobit-transactions" / transaction.transaction_id
    real_remove = transactions._remove_transaction_directory

    def refuse_cleanup(*args: Any, **kwargs: Any) -> None:
        raise TransactionError("simulated exact cleanup refusal")

    monkeypatch.setattr(transactions, "_remove_transaction_directory", refuse_cleanup)
    result = transaction.commit()

    assert result.changed_paths == (Path("value.txt"),)
    assert result.cleanup_warning is not None
    assert "simulated exact cleanup refusal" in result.cleanup_warning
    assert (tmp_path / "value.txt").read_bytes() == b"new"
    assert json.loads((directory / "journal.json").read_text())["state"] == "committed"

    monkeypatch.setattr(transactions, "_remove_transaction_directory", real_remove)
    assert CASTransaction.recover(tmp_path) == (transaction.transaction_id,)
    assert not directory.exists()


def test_staging_never_writes_into_a_replacement_transaction_seat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"new", expected_sha256=None)
    state = tmp_path / ".reprobit-transactions"
    directory = state / transaction.transaction_id
    moved = state / ("b" * 32)
    real_stage = transactions._publish_new_from_stream

    def swap_then_stage(root: Path, relative: str, source: BinaryIO, **kwargs: Any) -> object:
        os.replace(directory, moved)
        directory.mkdir()
        (directory / "keep.txt").write_bytes(b"replacement")
        return real_stage(root, relative, source, **kwargs)

    monkeypatch.setattr(transactions, "_publish_new_from_stream", swap_then_stage)

    with pytest.raises(SecurePathError, match="directory changed"):
        transaction.commit()

    assert not (tmp_path / "value.txt").exists()
    assert tuple(path.name for path in directory.iterdir()) == ("keep.txt",)
    assert (moved / "journal.json").is_file()


def test_initial_journal_never_writes_into_a_replacement_transaction_seat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"new", expected_sha256=None)
    state = tmp_path / ".reprobit-transactions"
    directory = state / transaction.transaction_id
    moved = state / ("b" * 32)
    real_write = transactions._write_journal

    def swap_then_write(*args: Any, **kwargs: Any) -> object:
        os.replace(directory, moved)
        directory.mkdir()
        (directory / "keep.txt").write_bytes(b"replacement")
        return real_write(*args, **kwargs)

    monkeypatch.setattr(transactions, "_write_journal", swap_then_write)

    with pytest.raises(TransactionError, match="transaction journal changed"):
        transaction.commit()

    assert not (tmp_path / "value.txt").exists()
    assert tuple(path.name for path in directory.iterdir()) == ("keep.txt",)
    assert not (moved / "journal.json").exists()


def test_journal_compare_and_swap_preserves_an_external_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"new", expected_sha256=None)
    journal = tmp_path / ".reprobit-transactions" / transaction.transaction_id / "journal.json"
    real_write = transactions._write_journal
    writes = 0

    def replace_before_second_write(*args: Any, **kwargs: Any) -> object:
        nonlocal writes
        writes += 1
        if writes == 2:
            journal.write_bytes(b"external journal")
        return real_write(*args, **kwargs)

    monkeypatch.setattr(transactions, "_write_journal", replace_before_second_write)

    with pytest.raises(TransactionError, match="transaction journal changed"):
        transaction.commit()

    assert journal.read_bytes() == b"external journal"
    assert not (tmp_path / "value.txt").exists()


def test_staged_promotion_never_reads_from_a_replacement_transaction_seat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"new", expected_sha256=None)
    state = tmp_path / ".reprobit-transactions"
    directory = state / transaction.transaction_id
    moved = state / ("b" * 32)
    real_promote = transactions._promote_staged

    def swap_then_promote(
        root: Path,
        source: Path,
        target: Path,
        **kwargs: Any,
    ) -> object:
        os.replace(directory, moved)
        directory.mkdir()
        (directory / "keep.txt").write_bytes(b"replacement")
        return real_promote(root, source, target, **kwargs)

    monkeypatch.setattr(transactions, "_promote_staged", swap_then_promote)

    with pytest.raises(TransactionError, match="transaction journal changed"):
        transaction.commit()

    assert not (tmp_path / "value.txt").exists()
    assert tuple(path.name for path in directory.iterdir()) == ("keep.txt",)
    assert (moved / "journal.json").is_file()


def test_backup_promotion_never_moves_a_target_into_a_replacement_seat(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"old")
    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"new", expected_sha256=digest(b"old"))
    state = tmp_path / ".reprobit-transactions"
    directory = state / transaction.transaction_id
    moved = state / ("b" * 32)
    real_move = transactions._move_to_backup

    def swap_then_move(
        root: Path,
        source: Path,
        backup: Path,
        **kwargs: Any,
    ) -> object:
        os.replace(directory, moved)
        directory.mkdir()
        (directory / "keep.txt").write_bytes(b"replacement")
        return real_move(root, source, backup, **kwargs)

    monkeypatch.setattr(transactions, "_move_to_backup", swap_then_move)

    with pytest.raises(TransactionConflict, match="changed while applying"):
        transaction.commit()

    assert target.read_bytes() == b"old"
    assert tuple(path.name for path in directory.iterdir()) == ("keep.txt",)
    assert (moved / "journal.json").is_file()


def test_transaction_refuses_redirected_state_root(tmp_path: Path) -> None:
    outside = tmp_path / "outside-state"
    outside.mkdir()
    state = tmp_path / ".reprobit-transactions"
    try:
        state.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"host cannot create a test symlink: {error}")

    transaction = CASTransaction(tmp_path)
    transaction.write("value.txt", b"value", expected_sha256=None)
    with pytest.raises(TransactionError, match="not a real directory"):
        transaction.commit()
    with pytest.raises(TransactionError, match="not a real directory"):
        CASTransaction.recover(tmp_path)


def test_transaction_refuses_redirected_project_root(tmp_path: Path) -> None:
    project = tmp_path / "project"
    redirected = tmp_path / "redirected"
    project.mkdir()
    try:
        redirected.symlink_to(project, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"host cannot create a test symlink: {error}")

    with pytest.raises(ValueError, match="existing real directory"):
        CASTransaction(redirected)
    with pytest.raises(ValueError, match="existing absolute real directory"):
        CASTransaction.recover(redirected)


def test_transaction_refuses_symlink_targets(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    (tmp_path / "link").symlink_to(outside)
    transaction = CASTransaction(tmp_path)
    with pytest.raises(TransactionError, match="redirected"):
        transaction.write("link", b"bad")
    assert outside.read_bytes() == b"outside"


def test_transaction_refuses_redirected_authority_parent(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    try:
        (project / "authority").symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"host cannot create a test symlink: {error}")
    transaction = CASTransaction(project)
    transaction.assert_json_members("authority", expected_members=())
    transaction.write("authority/first.json", b"first", expected_sha256=None)

    with pytest.raises(TransactionError, match="redirected"):
        transaction.commit()
    assert not (outside / "first.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory junctions")
def test_transaction_refuses_windows_junction_authority(tmp_path: Path) -> None:
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    authority = project / "authority"
    project.mkdir()
    outside.mkdir()
    _create_windows_junction(authority, outside)
    transaction = CASTransaction(project)
    transaction.assert_json_members("authority", expected_members=())
    transaction.write("authority/first.json", b"first", expected_sha256=None)

    with pytest.raises(TransactionError, match="redirected"):
        transaction.commit()
    assert not (outside / "first.json").exists()


@pytest.mark.skipif(os.name != "nt", reason="requires Windows directory junctions")
def test_transaction_refuses_windows_junction_boundaries(tmp_path: Path) -> None:
    project = tmp_path / "project"
    root_junction = tmp_path / "root-junction"
    project.mkdir()
    state_target = project / "state-target"
    state_target.mkdir()
    _create_windows_junction(root_junction, project)

    with pytest.raises(ValueError, match="existing real directory"):
        CASTransaction(root_junction)
    with pytest.raises(ValueError, match="existing absolute real directory"):
        CASTransaction.recover(root_junction)

    state_junction = project / ".reprobit-transactions"
    _create_windows_junction(state_junction, state_target)
    transaction = CASTransaction(project)
    transaction.write("first.json", b"first", expected_sha256=None)
    with pytest.raises(TransactionError, match="not a real directory"):
        transaction.commit()
    with pytest.raises(TransactionError, match="not a real directory"):
        CASTransaction.recover(project)
    assert not (project / "first.json").exists()
    assert not tuple(state_target.iterdir())


def test_transaction_rejects_duplicate_or_escaping_paths(tmp_path: Path) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("same", b"one", expected_sha256=None)
    with pytest.raises(TransactionError, match="repeated"):
        transaction.write("same", b"two", expected_sha256=None)
    with pytest.raises(ValueError):
        CASTransaction(tmp_path).write("../escape", b"bad", expected_sha256=None)
