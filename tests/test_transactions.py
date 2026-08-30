from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

from reprobit.transactions import CASTransaction, TransactionConflict, TransactionError


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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
