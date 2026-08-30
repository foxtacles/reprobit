from __future__ import annotations

import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

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


def _source_tree(tmp_path: Path, name: str = "source") -> Path:
    source = tmp_path / "arena" / name
    source.mkdir(parents=True)
    (source / "unit.cpp").write_bytes(b'#include "unit.h"\n')
    (source / "unit.h").write_bytes(b"#define VALUE 7\n")
    return source


class _LazyLeaseHolder:
    def __init__(self, tree: NamespaceTree, creator_threads: list[threading.Thread]) -> None:
        self._tree = tree
        self._creator_threads = creator_threads
        self._lease: SealedNamespaceLease | None = None

    def get(self) -> SealedNamespaceLease:
        if self._lease is None:
            self._creator_threads.append(threading.current_thread())
            self._lease = SealedNamespaceLease(trees=(self._tree,))
        return self._lease

    def close(self) -> None:
        if self._lease is not None:
            self._lease.close()


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


def test_windows_namespace_lease_holds_two_watched_trees(tmp_path: Path) -> None:
    first = _source_tree(tmp_path, "first")
    second = _source_tree(tmp_path, "second")

    with SealedNamespaceLease(
        trees=(
            NamespaceTree("first", first, tmp_path / "arena"),
            NamespaceTree("second", second, tmp_path / "arena"),
        )
    ) as lease:
        assert {(item.label, item.relative_path) for item in lease.snapshot.files} == {
            ("first", "unit.cpp"),
            ("first", "unit.h"),
            ("second", "unit.cpp"),
            ("second", "unit.h"),
        }


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


def test_windows_namespace_lease_rejects_change_completed_during_teardown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _source_tree(tmp_path)
    lease = SealedNamespaceLease(trees=(NamespaceTree("source", source, tmp_path),))
    implementation = cast(Any, lease._implementation)
    watcher = implementation._watchers[0]
    original_verify = implementation.verify
    api = implementation.api
    api.kernel32.WaitForSingleObject.argtypes = [
        api.wintypes.HANDLE,
        api.wintypes.DWORD,
    ]
    api.kernel32.WaitForSingleObject.restype = api.wintypes.DWORD

    def verify_then_change() -> None:
        original_verify()
        shadow = source / "teardown-shadow.h"
        shadow.write_bytes(b"transient\n")
        shadow.unlink()
        assert api.kernel32.WaitForSingleObject(watcher.event, 5_000) == 0

    monkeypatch.setattr(implementation, "verify", verify_then_change)
    with pytest.raises(
        SealedNamespaceError,
        match="directory change/overflow during teardown",
    ):
        lease.close()


def test_windows_namespace_watcher_survives_dependent_build_waves(tmp_path: Path) -> None:
    source = _source_tree(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = workspace / "first.obj"
    second = workspace / "second.obj"
    creator_threads: list[threading.Thread] = []
    action_threads: list[threading.Thread] = []
    tree = NamespaceTree("source", source, tmp_path / "arena")

    def execute(
        output: Path,
    ) -> Callable[[_LazyLeaseHolder, object, PreparedNodeInputs], None]:
        def run(
            runtime: _LazyLeaseHolder,
            _cancellation: object,
            _inputs: PreparedNodeInputs,
        ) -> None:
            runtime.get()
            action_threads.append(threading.current_thread())
            if output == second:
                assert not creator_threads[0].is_alive()
            output.write_bytes(b"object")

        return run

    IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=workspace,
        runtime_factory=lambda: _LazyLeaseHolder(tree, creator_threads),
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

    assert action_threads[0] is creator_threads[0]
    assert action_threads[1] is not creator_threads[0]
    assert not creator_threads[0].is_alive()


def test_windows_namespace_watcher_detects_transient_change_after_creator_exit(
    tmp_path: Path,
) -> None:
    source = _source_tree(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    first = workspace / "first.obj"
    second = workspace / "second.obj"
    creator_threads: list[threading.Thread] = []
    tree = NamespaceTree("source", source, tmp_path / "arena")

    def first_wave(
        runtime: _LazyLeaseHolder,
        _cancellation: object,
        _inputs: PreparedNodeInputs,
    ) -> None:
        runtime.get()
        assert threading.current_thread() is creator_threads[0]
        first.write_bytes(b"object")

    def second_wave(
        runtime: _LazyLeaseHolder,
        _cancellation: object,
        _inputs: PreparedNodeInputs,
    ) -> None:
        runtime.get()
        assert not creator_threads[0].is_alive()
        shadow = source / "shadow.h"
        shadow.write_bytes(b"transient\n")
        shadow.unlink()
        second.write_bytes(b"object")

    with pytest.raises(SealedNamespaceError, match="changed while held"):
        IncrementalDAGExecutor(
            cache=IncrementalCache(state, implementation="dag-test-v1"),
            workspace_root=workspace,
            runtime_factory=lambda: _LazyLeaseHolder(tree, creator_threads),
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
                        {"node": "transient-first"},
                        implementation="dag-test-v1",
                    ),
                    execute=first_wave,
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
                        {"node": "transient-second"},
                        implementation="dag-test-v1",
                    ),
                    execute=second_wave,
                    metadata=lambda _deps: {},
                ),
            )
        )

    assert not creator_threads[0].is_alive()


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
