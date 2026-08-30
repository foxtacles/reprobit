from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from reprobit.cache import IncrementalCache, cache_key
from reprobit.incremental_executor import (
    IncrementalDAGExecutor,
    IncrementalNode,
    PreparedNodeInputs,
)
from reprobit.sealed_namespace import (
    NamespaceTree,
    SealedNamespaceError,
    SealedNamespaceLease,
)

pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows namespace lease")


def _source_tree(tmp_path: Path) -> Path:
    source = tmp_path / "arena" / "source"
    source.mkdir(parents=True)
    (source / "unit.cpp").write_bytes(b'#include "unit.h"\n')
    (source / "unit.h").write_bytes(b"#define VALUE 7\n")
    return source


def test_windows_namespace_lease_holds_complete_tree(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)

    with SealedNamespaceLease(
        trees=(NamespaceTree("source", source, tmp_path),),
        retain_payload_labels=("source",),
    ) as lease:
        assert tuple(item.relative_path for item in lease.snapshot.files) == (
            "unit.cpp",
            "unit.h",
        )
        assert all(item.payload is not None for item in lease.snapshot.files)


def test_windows_namespace_lease_denies_in_place_file_mutation(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)

    with (
        SealedNamespaceLease(trees=(NamespaceTree("source", source, tmp_path),)),
        pytest.raises(OSError),
    ):
        (source / "unit.h").write_bytes(b"mutated\n")


def test_windows_namespace_lease_observes_transient_shadow_entry(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)

    with (
        pytest.raises(SealedNamespaceError, match="changed while held"),
        SealedNamespaceLease(trees=(NamespaceTree("source", source, tmp_path),)),
    ):
        shadow = source / "shadow.h"
        shadow.write_bytes(b"transient\n")
        shadow.unlink()


def test_windows_namespace_watcher_survives_dependent_build_waves(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = workspace / "first.obj"
    second = workspace / "second.obj"

    def execute(
        output: Path,
    ) -> Callable[[SealedNamespaceLease, object, PreparedNodeInputs], None]:
        def run(
            _runtime: SealedNamespaceLease,
            _cancellation: object,
            _inputs: PreparedNodeInputs,
        ) -> None:
            output.write_bytes(b"object")

        return run

    IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=workspace,
        runtime_factory=lambda: SealedNamespaceLease(
            trees=(NamespaceTree("source", source, tmp_path / "arena"),)
        ),
        runtime_close=lambda runtime: runtime.close(),
        max_workers=1,
    ).execute(
        (
            IncrementalNode(
                id="first",
                domain="producer",
                depends_on=(),
                outputs={"build/first.obj": first},
                key=lambda _deps: cache_key(
                    "producer",
                    {"node": "first"},
                    implementation="dag-test-v1",
                ),
                execute=execute(first),
                metadata=lambda _deps: {},
            ),
            IncrementalNode(
                id="second",
                domain="producer",
                depends_on=("first",),
                order_only=("first",),
                outputs={"build/second.obj": second},
                key=lambda _deps: cache_key(
                    "producer",
                    {"node": "second"},
                    implementation="dag-test-v1",
                ),
                execute=execute(second),
                metadata=lambda _deps: {},
            ),
        )
    )


def test_windows_namespace_lease_rejects_reparse_entry(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    outside = tmp_path / "outside.h"
    outside.write_bytes(b"outside\n")
    redirect = source / "redirect.h"
    try:
        redirect.symlink_to(outside)
    except OSError:
        pytest.skip("test account cannot create native symlinks")

    with pytest.raises(SealedNamespaceError, match=r"redirected|absent"):
        SealedNamespaceLease(trees=(NamespaceTree("source", source, tmp_path),))


def test_windows_namespace_lease_allows_unrelated_sibling_run_changes(
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path)

    with SealedNamespaceLease(trees=(NamespaceTree("source", source, tmp_path / "arena"),)):
        sibling = tmp_path / "unrelated-run"
        sibling.mkdir()
        (sibling / "state.json").write_text("temporary\n", encoding="utf-8")
        (sibling / "state.json").unlink()
        sibling.rmdir()


def test_windows_namespace_lease_denies_trusted_anchor_swap(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    anchor = tmp_path / "arena"
    replacement = tmp_path / "replacement"
    replacement.mkdir()

    with (
        SealedNamespaceLease(trees=(NamespaceTree("source", source, anchor),)),
        pytest.raises(OSError),
    ):
        os.replace(anchor, replacement / "stolen")
