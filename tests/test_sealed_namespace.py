from __future__ import annotations

import os
from pathlib import Path

import pytest

import reprobit.sealed_namespace as sealed_namespace
from reprobit.sealed_namespace import (
    NamespaceFile,
    NamespaceTree,
    SealedNamespaceError,
    SealedNamespaceLease,
    estimate_namespace_descriptor_requirement,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX namespace lease")


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    anchor = tmp_path / "arena"
    source = anchor / "logical" / "source"
    toolchain = anchor / "logical" / "toolchain"
    source.mkdir(parents=True)
    toolchain.mkdir(parents=True)
    (source / "unit.cpp").write_bytes(b'#include "unit.h"\n')
    (source / "unit.h").write_bytes(b"#define VALUE 7\n")
    (toolchain / "stddef.h").write_bytes(b"typedef unsigned size_t;\n")
    return anchor, source, toolchain


def test_namespace_lease_captures_complete_payload_census(tmp_path: Path) -> None:
    anchor, source, toolchain = _fixture(tmp_path)
    transport = anchor / "transport.sh"
    transport.write_bytes(b"#!/bin/sh\n")

    with SealedNamespaceLease(
        trees=(
            NamespaceTree("source", source, anchor),
            NamespaceTree("toolchain", toolchain, anchor),
        ),
        files=(NamespaceFile("transport", transport, anchor),),
        retain_payload_labels=("toolchain",),
    ) as lease:
        assert [item.relative_path for item in lease.snapshot.files_for("source")] == [
            "unit.cpp",
            "unit.h",
        ]
        assert lease.snapshot.files_for("toolchain")[0].payload == (b"typedef unsigned size_t;\n")
        assert lease.snapshot.files_for("transport")[0].relative_path == "transport.sh"


def test_namespace_lease_rejects_write_then_byte_restore(tmp_path: Path) -> None:
    anchor, source, _toolchain = _fixture(tmp_path)
    header = source / "unit.h"
    original = header.read_bytes()

    with (
        pytest.raises(SealedNamespaceError, match="changed while held"),
        SealedNamespaceLease(trees=(NamespaceTree("source", source, anchor),)),
    ):
        header.write_bytes(b"#define VALUE 999\n")
        header.write_bytes(original)


def test_namespace_lease_rejects_transient_shadow_create_delete(
    tmp_path: Path,
) -> None:
    anchor, source, _toolchain = _fixture(tmp_path)

    with (
        pytest.raises(SealedNamespaceError, match="changed while held"),
        SealedNamespaceLease(trees=(NamespaceTree("source", source, anchor),)),
    ):
        shadow = source / "shadow.h"
        shadow.write_bytes(b"host injection\n")
        shadow.unlink()


def test_namespace_lease_rejects_parent_swap_and_restore(tmp_path: Path) -> None:
    anchor, source, _toolchain = _fixture(tmp_path)
    held = anchor / "logical-held"
    logical = anchor / "logical"
    replacement = anchor / "replacement"
    replacement.mkdir()

    with (
        pytest.raises(SealedNamespaceError, match="changed while held"),
        SealedNamespaceLease(trees=(NamespaceTree("source", source, anchor),)),
    ):
        logical.rename(held)
        replacement.rename(logical)
        logical.rename(replacement)
        held.rename(logical)


def test_namespace_lease_rejects_symlinked_tree_entry(tmp_path: Path) -> None:
    anchor, source, _toolchain = _fixture(tmp_path)
    outside = tmp_path / "outside.h"
    outside.write_bytes(b"outside\n")
    (source / "redirect.h").symlink_to(outside)

    with pytest.raises(SealedNamespaceError, match="regular file/directory"):
        SealedNamespaceLease(trees=(NamespaceTree("source", source, anchor),))


def test_namespace_lease_ignores_sibling_changes_outside_declared_anchor(
    tmp_path: Path,
) -> None:
    _anchor, source, _toolchain = _fixture(tmp_path)
    runs = tmp_path / "runs"
    declared_run = runs / "declared"
    declared_source = declared_run / "source"
    declared_source.mkdir(parents=True)
    (declared_source / "unit.cpp").write_bytes(b"int unit();\n")

    with SealedNamespaceLease(trees=(NamespaceTree("source", declared_source, declared_run),)):
        sibling = runs / "unrelated-concurrent-run"
        sibling.mkdir()
        (sibling / "progress").write_bytes(b"running")
        (sibling / "progress").unlink()
        sibling.rmdir()

    # The original fixture remains useful as a sanity check that the test did
    # not accidentally move or alias a declared tree.
    assert (source / "unit.cpp").is_file()


def test_standalone_file_lease_ignores_sibling_churn_above_parent_anchor(
    tmp_path: Path,
) -> None:
    authority_root = tmp_path / "installed" / "transport"
    authority_root.mkdir(parents=True)
    transport = authority_root / "compiler-transport"
    transport.write_bytes(b"transport-v1\n")

    with SealedNamespaceLease(
        trees=(),
        files=(NamespaceFile("transport", transport, authority_root),),
    ):
        sibling = tmp_path / "unrelated-home-sibling"
        sibling.mkdir()
        (sibling / "progress").write_bytes(b"running\n")
        (sibling / "progress").unlink()
        sibling.rmdir()


def test_standalone_file_lease_rejects_parent_swap_below_anchor(
    tmp_path: Path,
) -> None:
    trusted = tmp_path / "trusted"
    authority_root = trusted / "transport"
    authority_root.mkdir(parents=True)
    transport = authority_root / "compiler-transport"
    transport.write_bytes(b"transport-v1\n")
    held = trusted / "transport-held"
    replacement = trusted / "transport-replacement"
    replacement.mkdir()
    (replacement / transport.name).write_bytes(b"transport-v2\n")

    with (
        pytest.raises(SealedNamespaceError, match="changed while held"),
        SealedNamespaceLease(
            trees=(),
            files=(NamespaceFile("transport", transport, authority_root),),
        ),
    ):
        authority_root.rename(held)
        replacement.rename(authority_root)
        authority_root.rename(replacement)
        held.rename(authority_root)


def test_namespace_preflight_raises_soft_descriptor_limit_for_large_project_scale(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    anchor = tmp_path / "arena"
    source = anchor / "source"
    source.mkdir(parents=True)
    for index in range(1412):
        (source / f"file-{index:04d}.h").write_bytes(b"")
    trees = (NamespaceTree("source", source, anchor),)
    estimated = estimate_namespace_descriptor_requirement(trees, ())
    assert estimated >= 1412

    class FakeResource:
        RLIMIT_NOFILE = 7
        RLIM_INFINITY = -1

        def __init__(self) -> None:
            self.limit = (1024, 4096)
            self.updates: list[tuple[int, int]] = []

        def getrlimit(self, _kind: int) -> tuple[int, int]:
            return self.limit

        def setrlimit(self, _kind: int, value: tuple[int, int]) -> None:
            self.updates.append(value)
            self.limit = value

    fake = FakeResource()
    monkeypatch.setattr(sealed_namespace, "resource", fake)
    monkeypatch.setattr(sealed_namespace, "_open_descriptor_count", lambda: 20)

    sealed_namespace._PosixNamespaceLease._require_descriptor_capacity(trees, ())

    assert fake.updates == [(20 + estimated + 128, 4096)]
