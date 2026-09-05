from __future__ import annotations

import json
from pathlib import Path

import pytest

import reprobit.discovery_state as discovery_state
from reprobit.cli import main
from reprobit.discovery_state import (
    MARKER_NAME,
    DiscoveryStateError,
    inspect_owned_state,
    register_state,
    remove_owned_state,
    state_lock,
)


def _owned_state(root: Path, *, request_name: str = "request.json") -> Path:
    request = root / request_name
    request.write_text("{}\n", encoding="utf-8")
    state = Path(".reprobit-discovery")
    (root / state / "cache").mkdir(parents=True)
    (root / state / "cache" / "cell.obj").write_bytes(b"cached object")
    lock = state_lock(root, state)
    assert lock.acquire(nonblocking=True)
    try:
        register_state(root, state, request.name)
    finally:
        lock.close()
    return request


def test_discovery_cleanup_previews_then_removes_only_owned_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _owned_state(tmp_path)
    report = tmp_path / "request.report.html"
    report.write_text("kept", encoding="utf-8")

    assert main(["discover", "clean", str(request), "--preview"]) == 0
    preview = capsys.readouterr().out
    assert "Would remove" in preview
    assert (tmp_path / ".reprobit-discovery").is_dir()

    assert main(["discover", "clean", str(request)]) == 0
    removed = capsys.readouterr().out
    assert "Removed" in removed
    assert "Discovery reports were kept" in removed
    assert not (tmp_path / ".reprobit-discovery").exists()
    assert request.is_file()
    assert report.read_text(encoding="utf-8") == "kept"


def test_discovery_cleanup_refuses_unmarked_or_redirected_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = tmp_path / "request.json"
    request.write_text("{}\n", encoding="utf-8")
    state = tmp_path / ".reprobit-discovery"
    state.mkdir()
    payload = state / "valuable.txt"
    payload.write_text("keep", encoding="utf-8")

    assert main(["discover", "clean", str(request)]) == 2
    assert "refusing to clean unmarked discovery state" in capsys.readouterr().err
    assert payload.read_text(encoding="utf-8") == "keep"

    marker = {
        "schema_version": 1,
        "kind": "reprobit-discovery-state",
        "state_directory": ".reprobit-discovery",
        "requests": [request.name],
    }
    (state / MARKER_NAME).write_text(
        json.dumps(marker, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    redirected = state / "redirected"
    try:
        redirected.symlink_to(outside)
    except OSError:
        pytest.skip("this host cannot create the cleanup safety symlink")

    assert main(["discover", "clean", str(request)]) == 2
    assert "redirected discovery state entry" in capsys.readouterr().err
    assert outside.read_text(encoding="utf-8") == "outside"
    assert state.is_dir()


def test_discovery_cleanup_refuses_an_active_campaign(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _owned_state(tmp_path)
    lock = state_lock(tmp_path, Path(".reprobit-discovery"))
    assert lock.acquire(nonblocking=True)
    try:
        assert main(["discover", "clean", str(request)]) == 2
        assert "another discovery campaign owns" in capsys.readouterr().err
        assert (tmp_path / ".reprobit-discovery").is_dir()
    finally:
        lock.close()


def test_discovery_cleanup_is_idempotent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _owned_state(tmp_path)

    assert main(["discover", "clean", str(request)]) == 0
    capsys.readouterr()
    assert main(["discover", "clean", str(request)]) == 0
    assert "No advanced discovery state exists" in capsys.readouterr().out


def test_discovery_cleanup_uses_ownership_marker_after_request_is_removed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _owned_state(tmp_path)
    request.unlink()

    assert main(["discover", "clean", str(request), "--preview"]) == 0
    assert "Would remove" in capsys.readouterr().out
    assert main(["discover", "clean", str(request)]) == 0
    assert "Removed" in capsys.readouterr().out
    assert not (tmp_path / ".reprobit-discovery").exists()


def test_discovery_state_rejects_absolute_paths_at_ownership_boundary(
    tmp_path: Path,
) -> None:
    with pytest.raises(DiscoveryStateError, match="relative directory"):
        state_lock(tmp_path, tmp_path / ".reprobit-discovery")

    assert not (tmp_path / ".reprobit-discovery-locks").exists()


def test_discovery_cleanup_requires_explicit_shared_state_consent(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    first = _owned_state(tmp_path, request_name="first.json")
    second = tmp_path / "second.json"
    second.write_text("{}\n", encoding="utf-8")
    state = Path(".reprobit-discovery")
    lock = state_lock(tmp_path, state)
    assert lock.acquire(nonblocking=True)
    try:
        register_state(tmp_path, state, second.name)
    finally:
        lock.close()

    assert main(["discover", "clean", str(first)]) == 2
    error = capsys.readouterr().err
    assert "shared by 'first.json', 'second.json'" in error
    assert "--all-requests" in error
    assert (tmp_path / state).is_dir()

    assert main(["discover", "clean", str(first), "--all-requests", "--preview"]) == 0
    assert "Would remove" in capsys.readouterr().out
    assert (tmp_path / state).is_dir()

    assert main(["discover", "clean", str(second), "--all-requests"]) == 0
    assert "Removed" in capsys.readouterr().out
    assert not (tmp_path / state).exists()


def test_discovery_cleanup_revalidates_directory_identity_before_removal(
    tmp_path: Path,
) -> None:
    request = _owned_state(tmp_path)
    state = Path(".reprobit-discovery")
    usage = inspect_owned_state(tmp_path, state, request.name)
    assert usage is not None

    original = tmp_path / ".original-discovery-state"
    usage.path.rename(original)
    usage.path.mkdir()
    (usage.path / MARKER_NAME).write_bytes((original / MARKER_NAME).read_bytes())
    replacement = usage.path / "replacement.txt"
    replacement.write_text("keep", encoding="utf-8")

    with pytest.raises(DiscoveryStateError, match="changed before cleanup"):
        remove_owned_state(usage, request.name)

    assert replacement.read_text(encoding="utf-8") == "keep"
    assert original.is_dir()


def test_discovery_cleanup_revalidates_marker_ownership_before_removal(
    tmp_path: Path,
) -> None:
    request = _owned_state(tmp_path)
    state = Path(".reprobit-discovery")
    usage = inspect_owned_state(tmp_path, state, request.name)
    assert usage is not None
    marker = usage.path / MARKER_NAME
    document = json.loads(marker.read_text(encoding="utf-8"))
    document["requests"].append("another.json")
    marker.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(DiscoveryStateError, match="ownership changed before cleanup"):
        remove_owned_state(usage, request.name, allow_shared=True)

    assert usage.path.is_dir()


def test_discovery_cleanup_preserves_directory_replaced_at_quarantine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _owned_state(tmp_path)
    state = tmp_path / ".reprobit-discovery"
    original = tmp_path / "retained-original"
    move = discovery_state.move_directory_in_exact_parent

    def replace_before_move(
        source: Path,
        identity: tuple[int, int],
        destination: Path,
        parent_identity: tuple[int, int],
    ) -> None:
        source.rename(original)
        source.mkdir()
        (source / "valuable.txt").write_bytes(b"unowned replacement")
        move(source, identity, destination, parent_identity)

    monkeypatch.setattr(discovery_state, "move_directory_in_exact_parent", replace_before_move)
    assert main(["discover", "clean", str(request)]) == 2
    captured = capsys.readouterr()
    assert "Removed" not in captured.out
    assert "changed before move" in captured.err
    assert (state / "valuable.txt").read_bytes() == b"unowned replacement"
    assert (original / "cache/cell.obj").read_bytes() == b"cached object"


def test_discovery_cleanup_preserves_directory_replaced_at_deletion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _owned_state(tmp_path)
    preserved = tmp_path / "retained-original"
    replacements: list[Path] = []
    remove = discovery_state.remove_exact_directory_tree

    def replace_before_delete(path: Path, identity: tuple[int, int]) -> None:
        path.rename(preserved)
        path.mkdir()
        (path / "valuable.txt").write_bytes(b"unowned replacement")
        replacements.append(path)
        remove(path, identity)

    monkeypatch.setattr(discovery_state, "remove_exact_directory_tree", replace_before_delete)
    assert main(["discover", "clean", str(request)]) == 2
    captured = capsys.readouterr()
    assert "Removed" not in captured.out
    assert "quarantined discovery state" in captured.err
    assert (replacements[0] / "valuable.txt").read_bytes() == b"unowned replacement"
    assert (preserved / "cache/cell.obj").read_bytes() == b"cached object"
