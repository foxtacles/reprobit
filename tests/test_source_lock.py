from __future__ import annotations

import os
from pathlib import Path

import pytest

from reprobit.source_lock import (
    ResolvedSourceRoot,
    SourceLockError,
    build_source_manifest,
    receipt_source_input,
    resolve_source_root,
)


def _tree(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "src/input.cpp").write_bytes(b"int fixture;\n")
    (root / "src/other.cpp").write_bytes(b"int other;\n")


def test_a_shared_resolved_root_receipts_exactly_what_a_plain_root_does(tmp_path: Path) -> None:
    _tree(tmp_path)
    shared = resolve_source_root(tmp_path)

    assert shared.path == tmp_path.resolve(strict=True)
    for relative in ("src/input.cpp", "src/other.cpp"):
        assert receipt_source_input(shared, relative, capture=True) == receipt_source_input(
            tmp_path, relative, capture=True
        )
    manifest = build_source_manifest(tmp_path, ("src/input.cpp", "src/other.cpp"))
    assert [item.path for item in manifest.entries] == ["src/input.cpp", "src/other.cpp"]


def test_a_resolved_root_is_resolved_once_and_never_re_resolved_per_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _tree(tmp_path)
    shared = resolve_source_root(tmp_path)
    real_resolve = Path.resolve
    resolved: list[Path] = []

    def counting_resolve(self: Path, strict: bool = False) -> Path:
        resolved.append(self)
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", counting_resolve)
    receipt_source_input(shared, "src/input.cpp")
    receipt_source_input(shared, "src/other.cpp")
    # Each receipt still resolves its own input before and after reading it.
    assert shared.path not in resolved
    assert len(resolved) == 4


def test_a_resolved_root_still_rejects_redirected_and_absent_inputs(tmp_path: Path) -> None:
    _tree(tmp_path)
    shared = resolve_source_root(tmp_path)

    with pytest.raises(SourceLockError, match="escapes or is absent"):
        receipt_source_input(shared, "src/missing.cpp")
    with pytest.raises(SourceLockError, match="not canonical"):
        receipt_source_input(shared, "../src/input.cpp")
    if os.name != "nt":
        (tmp_path / "src/alias.cpp").symlink_to(tmp_path / "src/input.cpp")
        with pytest.raises(SourceLockError, match="is redirected"):
            receipt_source_input(shared, "src/alias.cpp")


def test_a_resolved_root_follows_a_root_symlink_only_when_it_is_built(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("portable Windows test environments do not guarantee symlink creation")
    actual = tmp_path / "actual"
    _tree(actual)
    link = tmp_path / "link"
    link.symlink_to(actual, target_is_directory=True)

    shared = resolve_source_root(link)
    assert shared.path == actual.resolve(strict=True)
    assert receipt_source_input(shared, "src/input.cpp") == receipt_source_input(
        actual, "src/input.cpp"
    )


def test_a_resolved_root_must_be_absolute() -> None:
    with pytest.raises(SourceLockError, match="must be absolute"):
        ResolvedSourceRoot(Path("relative"))
