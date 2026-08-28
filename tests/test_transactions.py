from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from reprobit.transactions import CASTransaction, TransactionConflict, TransactionError


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_transaction_atomically_writes_and_deletes(tmp_path: Path) -> None:
    old = tmp_path / "old.txt"
    old.write_bytes(b"old")
    with CASTransaction(tmp_path) as transaction:
        transaction.write("nested/new.txt", b"new", expected_sha256=None)
        transaction.delete("old.txt", expected_sha256=digest(b"old"))

    assert (tmp_path / "nested/new.txt").read_bytes() == b"new"
    assert not old.exists()
    assert list((tmp_path / ".reprobit-transactions").glob("*/journal.json")) == []


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


def test_recovery_rolls_back_an_interrupted_install(tmp_path: Path) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"new")
    state = tmp_path / ".reprobit-transactions"
    directory = state / "abandoned"
    backup = directory / "backups" / "0"
    backup.parent.mkdir(parents=True)
    (directory / "payloads").mkdir()
    backup.write_bytes(b"old")
    record = {
        "schema": CASTransaction.JOURNAL_SCHEMA,
        "transaction_id": "abandoned",
        "state": "applying",
        "operations": [
            {
                "index": 0,
                "kind": "write",
                "path": "value.txt",
                "expected_sha256": digest(b"old"),
                "result_sha256": digest(b"new"),
                "payload": "payloads/0",
                "backup": "backups/0",
            }
        ],
        "transaction_directory": "abandoned",
    }
    (directory / "journal.json").write_text(json.dumps(record))

    assert CASTransaction.recover(tmp_path) == ("abandoned",)
    assert target.read_bytes() == b"old"
    assert not directory.exists()


def test_recovery_refuses_to_overwrite_unknown_post_crash_contents(tmp_path: Path) -> None:
    target = tmp_path / "value.txt"
    target.write_bytes(b"changed after crash")
    state = tmp_path / ".reprobit-transactions"
    directory = state / "abandoned"
    backup = directory / "backups" / "0"
    backup.parent.mkdir(parents=True)
    (directory / "payloads").mkdir()
    backup.write_bytes(b"old")
    record = {
        "schema": CASTransaction.JOURNAL_SCHEMA,
        "transaction_id": "abandoned",
        "state": "applying",
        "operations": [
            {
                "index": 0,
                "kind": "write",
                "path": "value.txt",
                "expected_sha256": digest(b"old"),
                "result_sha256": digest(b"new"),
                "payload": "payloads/0",
                "backup": "backups/0",
            }
        ],
        "transaction_directory": "abandoned",
    }
    (directory / "journal.json").write_text(json.dumps(record))

    with pytest.raises(TransactionError, match="unknown contents"):
        CASTransaction.recover(tmp_path)
    assert target.read_bytes() == b"changed after crash"
    assert backup.read_bytes() == b"old"


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


def test_transaction_refuses_symlink_targets(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    (tmp_path / "link").symlink_to(outside)
    transaction = CASTransaction(tmp_path)
    with pytest.raises(TransactionError, match="symlink"):
        transaction.write("link", b"bad")
    assert outside.read_bytes() == b"outside"


def test_transaction_rejects_duplicate_or_escaping_paths(tmp_path: Path) -> None:
    transaction = CASTransaction(tmp_path)
    transaction.write("same", b"one", expected_sha256=None)
    with pytest.raises(TransactionError, match="repeated"):
        transaction.write("same", b"two", expected_sha256=None)
    with pytest.raises(ValueError):
        CASTransaction(tmp_path).write("../escape", b"bad", expected_sha256=None)
