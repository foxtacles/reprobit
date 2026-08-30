from __future__ import annotations

import sys
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import MappingProxyType

import pytest

from reprobit.cache import CacheLease, IncrementalCache, cache_key
from reprobit.incremental_executor import (
    CacheProbeDecision,
    IncrementalDAGExecutor,
    IncrementalExecutionError,
    IncrementalNode,
    NodeKeyDecision,
    NodeOutcome,
    PreparedNodeInputs,
    ReceiptBoundInput,
)
from reprobit.progress import ProgressKind


def _node_key(node: str, dependency: str = "") -> str:
    return cache_key(
        "producer",
        {"node": node, "dependency": dependency},
        implementation="dag-test-v1",
    )


def _materialize_inputs(
    root: Path,
    consumer: str,
    owners: Mapping[str, str],
) -> Callable[[CacheLease, Mapping[str, NodeOutcome]], PreparedNodeInputs]:
    """Restore declared predecessor outputs into one private consumer view."""

    def materialize(
        lease: CacheLease,
        outcomes: Mapping[str, NodeOutcome],
    ) -> PreparedNodeInputs:
        entries: dict[str, ReceiptBoundInput] = {}
        for index, (name, owner) in enumerate(sorted(owners.items())):
            outcome = outcomes[owner]
            destination = root / ".inputs" / consumer / f"{index:03d}-{Path(name).name}"
            snapshots = lease.restore_selected(
                outcome.record,
                {name: destination},
                allowed_root=root,
            )
            receipts = {item.name: item for item in outcome.record.outputs}
            entries[name] = ReceiptBoundInput(receipts[name], snapshots[name])
        return PreparedNodeInputs(MappingProxyType(entries))

    return materialize


def test_all_hit_dag_never_constructs_runtime(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    first_root = tmp_path / "first"
    first_root.mkdir()
    cache = IncrementalCache(state, implementation="dag-test-v1")
    runtime_calls = 0
    publication_checks = 0

    def runtime() -> object:
        nonlocal runtime_calls
        runtime_calls += 1
        return object()

    def before_publish() -> None:
        nonlocal publication_checks
        publication_checks += 1

    def nodes(root: Path) -> tuple[IncrementalNode[object], ...]:
        first = root / "first.obj"
        second = root / "second.lib"

        def execute_first(
            _runtime: object,
            _cancellation: object,
            _inputs: PreparedNodeInputs,
        ) -> None:
            first.write_bytes(b"object")

        def execute_second(
            _runtime: object,
            _cancellation: object,
            inputs: PreparedNodeInputs,
        ) -> None:
            source = inputs.entries["build/first.obj"].snapshot.path
            second.write_bytes(source.read_bytes() + b" library")

        return (
            IncrementalNode(
                id="compile",
                domain="producer",
                depends_on=(),
                outputs={"build/first.obj": first},
                key=lambda _dependencies: _node_key("compile"),
                execute=execute_first,
                metadata=lambda _dependencies: {"kind": "compiler"},
            ),
            IncrementalNode(
                id="library",
                domain="producer",
                depends_on=("compile",),
                outputs={"build/second.lib": second},
                key=lambda dependencies: _node_key(
                    "library", dependencies["compile"].record.outputs[0].digest
                ),
                execute=execute_second,
                materialize_inputs=_materialize_inputs(
                    root, "library", {"build/first.obj": "compile"}
                ),
                metadata=lambda dependencies: {"parent": dependencies["compile"].key},
            ),
        )

    first = IncrementalDAGExecutor(
        cache=cache,
        workspace_root=first_root,
        runtime_factory=runtime,
        runtime_close=lambda _runtime: None,
        max_workers=2,
        before_publish=before_publish,
    ).execute(nodes(first_root))
    assert first.summary.producer_misses == 2
    assert runtime_calls == 1
    assert publication_checks == 1

    second_root = tmp_path / "second"
    second_root.mkdir()
    second = IncrementalDAGExecutor(
        cache=cache,
        workspace_root=second_root,
        runtime_factory=runtime,
        runtime_close=lambda _runtime: None,
        max_workers=2,
        before_publish=before_publish,
    ).execute(nodes(second_root))
    assert second.summary.producer_hits == 2
    assert second.summary.producer_misses == 0
    assert second.summary.runtime_init_count == 0
    assert second.runtime_created is False
    assert runtime_calls == 1
    assert publication_checks == 1
    assert (second_root / "second.lib").read_bytes() == b"object library"


def test_one_miss_initializes_one_lazy_runtime_not_the_worker_budget(
    tmp_path: Path,
) -> None:
    """The adapter, not ``max_workers``, controls lane growth on first demand."""

    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = workspace / "single.obj"
    lane_initializations: list[int] = []

    class FakeReplayRuntime:
        def execute_one(self) -> None:
            output.write_bytes(b"object")

    def runtime_factory() -> FakeReplayRuntime:
        # A classic adapter supplies a lazily growing pool here.  A single miss
        # must start its minimum one-lane capacity, not the CLI worker budget.
        lane_initializations.append(1)
        return FakeReplayRuntime()

    result = IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=workspace,
        runtime_factory=runtime_factory,
        runtime_close=lambda _runtime: None,
        max_workers=8,
        runtime_init_count=lambda: len(lane_initializations),
    ).execute(
        (
            IncrementalNode(
                id="compile.single",
                domain="producer",
                depends_on=(),
                outputs={"build/single.obj": output},
                key=lambda _deps: NodeKeyDecision(None, "no prior non-certifying replay hint"),
                execute=lambda runtime, _cancellation, _inputs: runtime.execute_one(),
                final_key=lambda _deps: _node_key("compile.single", "reads-v1"),
                metadata=lambda _deps: {
                    "certifying": False,
                    "replay_hint": "reads-v1",
                },
            ),
        )
    )

    assert result.summary.producer_misses == 1
    assert result.summary.runtime_init_count == 1
    assert lane_initializations == [1]


def test_typed_probe_reuses_selected_record_without_second_generic_lookup(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="dag-test-v1")
    source = tmp_path / "cached.obj"
    source.write_bytes(b"object")
    key = _node_key("compiler-probe")
    with cache.lease() as lease:
        expected = lease.store("producer", key, {"build/unit.obj": source})

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = workspace / "unit.obj"
    probe_lookups = 0

    def probe(lease: object, _dependencies: object) -> CacheProbeDecision:
        nonlocal probe_lookups
        probe_lookups += 1
        selected = lease.lookup("producer", key)  # type: ignore[attr-defined]
        assert selected == expected
        return CacheProbeDecision(key, selected)

    result = IncrementalDAGExecutor(
        cache=cache,
        workspace_root=workspace,
        runtime_factory=lambda: (_ for _ in ()).throw(
            AssertionError("cache hit initialized the runtime")
        ),
        runtime_close=lambda _runtime: None,
        max_workers=4,
    ).execute(
        (
            IncrementalNode(
                id="compile.unit",
                domain="producer",
                depends_on=(),
                outputs={"build/unit.obj": output},
                key=lambda _deps: (_ for _ in ()).throw(
                    AssertionError("typed probe fell back to generic key lookup")
                ),
                probe=probe,  # type: ignore[arg-type]
                execute=lambda _runtime, _cancellation, _inputs: (_ for _ in ()).throw(
                    AssertionError("cache hit executed the node")
                ),
                metadata=lambda _deps: {},
            ),
        )
    )

    assert result.summary.producer_hits == 1
    assert result.summary.runtime_init_count == 0
    assert probe_lookups == 1
    assert output.read_bytes() == b"object"


def test_dependency_key_rebuilds_only_downstream_closure(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="dag-test-v1")
    source_version = "one"

    def run(root: Path) -> tuple[int, int, dict[str, bool]]:
        root.mkdir()
        first = root / "first.obj"
        unrelated = root / "other.obj"
        linked = root / "app.exe"
        nodes = (
            IncrementalNode(
                id="compile.first",
                domain="producer",
                depends_on=(),
                outputs={"build/first.obj": first},
                key=lambda _deps: _node_key("first", source_version),
                execute=lambda _runtime, _cancellation, _inputs: first.write_text(source_version),
                metadata=lambda _deps: {},
            ),
            IncrementalNode(
                id="compile.other",
                domain="producer",
                depends_on=(),
                outputs={"build/other.obj": unrelated},
                key=lambda _deps: _node_key("other"),
                execute=lambda _runtime, _cancellation, _inputs: unrelated.write_text("other"),
                metadata=lambda _deps: {},
            ),
            IncrementalNode(
                id="link",
                domain="producer",
                depends_on=("compile.first", "compile.other"),
                outputs={"build/app.exe": linked},
                key=lambda deps: _node_key(
                    "link",
                    deps["compile.first"].record.outputs[0].digest
                    + deps["compile.other"].record.outputs[0].digest,
                ),
                execute=lambda _runtime, _cancellation, inputs: linked.write_bytes(
                    inputs.entries["build/first.obj"].snapshot.path.read_bytes()
                    + inputs.entries["build/other.obj"].snapshot.path.read_bytes()
                ),
                materialize_inputs=_materialize_inputs(
                    root,
                    "link",
                    {
                        "build/first.obj": "compile.first",
                        "build/other.obj": "compile.other",
                    },
                ),
                metadata=lambda _deps: {},
            ),
        )
        result = IncrementalDAGExecutor(
            cache=cache,
            workspace_root=root,
            runtime_factory=object,
            runtime_close=lambda _runtime: None,
            max_workers=2,
        ).execute(nodes)
        return (
            result.summary.producer_hits,
            result.summary.producer_misses,
            {item: outcome.cache_hit for item, outcome in result.outcomes.items()},
        )

    assert run(tmp_path / "one")[:2] == (0, 3)
    source_version = "two"
    hits, misses, outcomes = run(tmp_path / "two")
    assert (hits, misses) == (1, 2)
    assert outcomes == {
        "compile.first": False,
        "compile.other": True,
        "link": False,
    }


def test_key_decision_records_explicit_invalidation_reason(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="dag-test-v1")

    def run(root: Path, generation: str, reason: str | None = None) -> object:
        root.mkdir()
        output = root / "out.obj"
        return IncrementalDAGExecutor(
            cache=cache,
            workspace_root=root,
            runtime_factory=object,
            runtime_close=lambda _runtime: None,
            max_workers=1,
        ).execute(
            (
                IncrementalNode(
                    id="compile",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/out.obj": output},
                    key=lambda _deps: NodeKeyDecision(_node_key("validate", generation), reason),
                    execute=lambda _runtime, _cancellation, _inputs: output.write_bytes(b"object"),
                    metadata=lambda _deps: {},
                ),
            )
        )

    first = run(tmp_path / "one", "one")
    assert first.summary.producer_misses == 1  # type: ignore[attr-defined]
    second = run(
        tmp_path / "two",
        "two",
        "recursive include shadow changed",
    )
    assert second.summary.producer_misses == 1  # type: ignore[attr-defined]
    assert second.summary.invalidations == (  # type: ignore[attr-defined]
        ("compile", "recursive include shadow changed"),
    )


def test_forced_miss_can_publish_a_post_execution_final_key(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="dag-test-v1")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = workspace / "out.obj"
    final = _node_key("post-execution", "recursive-read-digest")
    result = IncrementalDAGExecutor(
        cache=cache,
        workspace_root=workspace,
        runtime_factory=object,
        runtime_close=lambda _runtime: None,
        max_workers=1,
    ).execute(
        (
            IncrementalNode(
                id="compile",
                domain="producer",
                depends_on=(),
                outputs={"build/out.obj": output},
                key=lambda _deps: NodeKeyDecision(None, "no prior recursive-read hint"),
                execute=lambda _runtime, _cancellation, _inputs: output.write_bytes(b"object"),
                final_key=lambda _deps: final,
                metadata=lambda _deps: {"recursive_reads": ["source/unit.cpp"]},
            ),
        )
    )
    assert result.outcomes["compile"].key == final
    with cache.lease() as lease:
        assert lease.lookup("producer", final) is not None


def test_same_final_key_ignores_run_local_invalidation_reason(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    final = _node_key("stable-final")

    def run(index: int, reason: str) -> None:
        workspace = tmp_path / f"workspace-{index}"
        workspace.mkdir()
        output = workspace / "out.obj"
        result = IncrementalDAGExecutor(
            cache=IncrementalCache(state, implementation="dag-test-v1"),
            workspace_root=workspace,
            runtime_factory=object,
            runtime_close=lambda _runtime: None,
            max_workers=1,
        ).execute(
            (
                IncrementalNode(
                    id="compile",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/out.obj": output},
                    key=lambda _deps: NodeKeyDecision(None, reason),
                    execute=lambda _runtime, _cancellation, _inputs: output.write_bytes(b"stable"),
                    final_key=lambda _deps: final,
                    metadata=lambda _deps: {"stable": True},
                ),
            )
        )
        assert result.summary.invalidations == (("compile", reason),)

    run(1, "no history")
    run(2, "history was stale for a different local reason")
    with IncrementalCache(state, implementation="dag-test-v1").lease() as lease:
        record = lease.lookup("producer", final)
    assert record is not None
    assert dict(record.metadata) == {"stable": True}


def test_concurrent_same_final_key_publishers_ignore_local_reasons(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    final = _node_key("concurrent-stable-final")
    barrier = threading.Barrier(2)
    # Initialize both views before measuring concurrent publication.  On
    # Windows, first-use layout publication can be delayed by filesystem
    # scanning and is unrelated to the record-convergence behavior under test.
    caches = (
        IncrementalCache(state, implementation="dag-test-v1"),
        IncrementalCache(state, implementation="dag-test-v1"),
    )

    def run(index: int) -> str:
        workspace = tmp_path / f"concurrent-{index}"
        workspace.mkdir()
        output = workspace / "out.obj"

        def execute(
            _runtime: object,
            _cancellation: object,
            _inputs: PreparedNodeInputs,
        ) -> None:
            output.write_bytes(b"same-output")
            barrier.wait(timeout=5)

        result = IncrementalDAGExecutor(
            cache=caches[index - 1],
            workspace_root=workspace,
            runtime_factory=object,
            runtime_close=lambda _runtime: None,
            max_workers=1,
        ).execute(
            (
                IncrementalNode(
                    id="compile",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/out.obj": output},
                    key=lambda _deps: NodeKeyDecision(None, f"local-reason-{index}"),
                    execute=execute,
                    final_key=lambda _deps: final,
                    metadata=lambda _deps: {"stable": True},
                ),
            )
        )
        return result.outcomes["compile"].record.key

    with ThreadPoolExecutor(max_workers=2) as pool:
        keys = tuple(pool.map(run, (1, 2)))
    assert keys == (final, final)


def test_runtime_is_closed_after_action_failure(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    closed: list[object] = []
    runtime = object()

    def fail(
        _runtime: object,
        _cancellation: object,
        _inputs: PreparedNodeInputs,
    ) -> None:
        raise RuntimeError("action failed")

    executor = IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=workspace,
        runtime_factory=lambda: runtime,
        runtime_close=closed.append,
        max_workers=1,
    )
    with pytest.raises(IncrementalExecutionError, match="action failed"):
        executor.execute(
            (
                IncrementalNode(
                    id="failing",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/failing.obj": workspace / "failing.obj"},
                    key=lambda _deps: _node_key("failing"),
                    execute=fail,
                    metadata=lambda _deps: {},
                ),
            )
        )
    assert closed == [runtime]


def test_runtime_factory_failure_is_not_retried_and_needs_no_close(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    calls = 0
    closed: list[object] = []

    def factory() -> object:
        nonlocal calls
        calls += 1
        raise RuntimeError("factory failed")

    executor = IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=workspace,
        runtime_factory=factory,
        runtime_close=closed.append,
        max_workers=2,
    )
    nodes = tuple(
        IncrementalNode(
            id=f"node.{index}",
            domain="producer",
            depends_on=(),
            outputs={f"build/{index}.obj": workspace / f"{index}.obj"},
            key=lambda _deps, index=index: _node_key(f"factory.{index}"),
            execute=lambda _runtime, _cancellation, _inputs: None,
            metadata=lambda _deps: {},
        )
        for index in range(2)
    )
    with pytest.raises(
        IncrementalExecutionError,
        match="runtime construction failed: factory failed",
    ):
        executor.execute(nodes)
    assert calls == 1
    assert closed == []


def test_output_alias_and_symlink_parent_are_rejected_before_cache_access(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    common = {
        "domain": "producer",
        "depends_on": (),
        "key": lambda _deps: _node_key("alias"),
        "execute": lambda _runtime, _cancellation, _inputs: None,
        "metadata": lambda _deps: {},
    }
    executor = IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=workspace,
        runtime_factory=object,
        runtime_close=lambda _runtime: None,
        max_workers=1,
    )
    with pytest.raises(IncrementalExecutionError, match="aliases"):
        executor.execute(
            (
                IncrementalNode(
                    id="alias",
                    outputs={
                        "build/upper.obj": workspace / "A.obj",
                        "build/lower.obj": workspace / "a.obj",
                    },
                    **common,  # type: ignore[arg-type]
                ),
            )
        )
    outside = tmp_path / "outside"
    outside.mkdir()
    alias = workspace / "build"
    try:
        alias.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    with pytest.raises(IncrementalExecutionError, match="redirected"):
        executor.execute(
            (
                IncrementalNode(
                    id="redirected",
                    outputs={"build/out.obj": alias / "out.obj"},
                    **common,  # type: ignore[arg-type]
                ),
            )
        )


def test_workspace_prefix_alias_is_canonicalized_without_allowing_inner_symlinks(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    alias_parent = tmp_path / "alias"
    try:
        alias_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable")
    real_workspace = real_parent / "workspace"
    real_workspace.mkdir()
    alias_workspace = alias_parent / "workspace"
    alias_output = alias_workspace / "build" / "out.obj"

    def execute(
        _runtime: object,
        _cancellation: object,
        _inputs: PreparedNodeInputs,
    ) -> None:
        alias_output.parent.mkdir()
        alias_output.write_bytes(b"object")

    result = IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=alias_workspace,
        runtime_factory=object,
        runtime_close=lambda _runtime: None,
        max_workers=1,
    ).execute(
        (
            IncrementalNode(
                id="aliased-root",
                domain="producer",
                depends_on=(),
                outputs={"build/out.obj": alias_output},
                key=lambda _deps: _node_key("aliased-root"),
                execute=execute,
                metadata=lambda _deps: {},
            ),
        )
    )

    assert result.summary.producer_misses == 1
    assert (real_workspace / "build" / "out.obj").read_bytes() == b"object"


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS /var alias regression")
def test_macos_var_workspace_alias_maps_to_private_var(tmp_path: Path) -> None:
    real_workspace = tmp_path / "workspace"
    real_workspace.mkdir()
    rendered = str(real_workspace)
    if not rendered.startswith("/private/var/"):
        pytest.skip("temporary root is not beneath /private/var")
    alias_workspace = Path(rendered.removeprefix("/private"))
    assert alias_workspace.resolve(strict=True) == real_workspace.resolve(strict=True)
    state = tmp_path / "state"
    state.mkdir()
    output = alias_workspace / "out.obj"

    result = IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=alias_workspace,
        runtime_factory=object,
        runtime_close=lambda _runtime: None,
        max_workers=1,
    ).execute(
        (
            IncrementalNode(
                id="macos-alias",
                domain="producer",
                depends_on=(),
                outputs={"out.obj": output},
                key=lambda _deps: _node_key("macos-alias"),
                execute=lambda _runtime, _cancellation, _inputs: output.write_bytes(b"object"),
                metadata=lambda _deps: {},
            ),
        )
    )

    assert result.summary.producer_misses == 1
    assert (real_workspace / "out.obj").read_bytes() == b"object"


def test_parallel_failure_cancels_sibling_and_emits_typed_cache_misses(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    sibling_started = threading.Event()
    sibling_cancelled = threading.Event()
    progress: list[tuple[ProgressKind, str, str | None]] = []

    def fail(
        _runtime: object,
        _cancellation: object,
        _inputs: PreparedNodeInputs,
    ) -> None:
        sibling_started.wait(timeout=2)
        raise RuntimeError("first failed")

    def sibling(
        _runtime: object,
        cancellation: object,
        _inputs: PreparedNodeInputs,
    ) -> None:
        sibling_started.set()
        token = cancellation
        while True:
            try:
                token.raise_if_cancelled()  # type: ignore[attr-defined]
            except Exception:
                sibling_cancelled.set()
                raise

    executor = IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=workspace,
        runtime_factory=object,
        runtime_close=lambda _runtime: None,
        max_workers=2,
        progress=lambda kind, _done, _total, phase, node, reason: progress.append(
            (kind, f"{phase}:{node}", reason)
        ),
    )
    with pytest.raises(IncrementalExecutionError, match="failed"):
        executor.execute(
            (
                IncrementalNode(
                    id="fail",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/fail.obj": workspace / "fail.obj"},
                    key=lambda _deps: _node_key("parallel.fail"),
                    execute=fail,
                    metadata=lambda _deps: {},
                ),
                IncrementalNode(
                    id="sibling",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/sibling.obj": workspace / "sibling.obj"},
                    key=lambda _deps: _node_key("parallel.sibling"),
                    execute=sibling,
                    metadata=lambda _deps: {},
                ),
            )
        )
    assert sibling_cancelled.wait(timeout=2)
    assert {item[0] for item in progress} == {ProgressKind.CACHE_MISS}


def test_cache_miss_is_discovery_and_completion_advances_after_store(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = workspace / "out.obj"
    progress: list[tuple[ProgressKind, int, int]] = []

    def execute(
        _runtime: object,
        _cancellation: object,
        _inputs: PreparedNodeInputs,
    ) -> None:
        assert progress == [(ProgressKind.CACHE_MISS, 0, 2)]
        output.write_bytes(b"object")

    def close(_runtime: object) -> None:
        assert progress == [
            (ProgressKind.CACHE_MISS, 0, 2),
            (ProgressKind.UNIT_FINISHED, 1, 2),
        ]

    IncrementalDAGExecutor(
        cache=IncrementalCache(state, implementation="dag-test-v1"),
        workspace_root=workspace,
        runtime_factory=object,
        runtime_close=close,
        max_workers=1,
        progress=lambda kind, done, total, _phase, _node, _reason: progress.append(
            (kind, done, total)
        ),
    ).execute(
        (
            IncrementalNode(
                id="compile",
                domain="producer",
                depends_on=(),
                outputs={"build/out.obj": output},
                key=lambda _deps: _node_key("progress-after-store"),
                execute=execute,
                metadata=lambda _deps: {},
            ),
        )
    )

    assert progress == [
        (ProgressKind.CACHE_MISS, 0, 2),
        (ProgressKind.UNIT_FINISHED, 1, 2),
        (ProgressKind.UNIT_FINISHED, 2, 2),
    ]


def test_pre_store_input_race_leaves_no_cache_record(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = workspace / "out.obj"
    key = _node_key("pre-store-race")
    cache = IncrementalCache(state, implementation="dag-test-v1")

    with pytest.raises(IncrementalExecutionError, match="sampled input changed"):
        IncrementalDAGExecutor(
            cache=cache,
            workspace_root=workspace,
            runtime_factory=object,
            runtime_close=lambda _runtime: None,
            max_workers=1,
        ).execute(
            (
                IncrementalNode(
                    id="compile",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/out.obj": output},
                    key=lambda _deps: key,
                    execute=lambda _runtime, _cancellation, _inputs: output.write_bytes(b"object"),
                    metadata=lambda _deps: {},
                    pre_store=lambda _runtime, _deps: (_ for _ in ()).throw(
                        RuntimeError("sampled input changed")
                    ),
                ),
            )
        )

    with cache.lease() as lease:
        assert lease.lookup("producer", key) is None


def test_runtime_close_failure_leaves_staged_record_unpublished(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = workspace / "out.obj"
    key = _node_key("runtime-close-failure")
    cache = IncrementalCache(state, implementation="dag-test-v1")
    progress: list[ProgressKind] = []

    def fail_close(_runtime: object) -> None:
        raise RuntimeError("sealed namespace changed while held")

    with pytest.raises(RuntimeError, match="sealed namespace changed while held"):
        IncrementalDAGExecutor(
            cache=cache,
            workspace_root=workspace,
            runtime_factory=object,
            runtime_close=fail_close,
            max_workers=1,
            progress=lambda kind, _done, _total, _phase, _node, _reason: progress.append(kind),
        ).execute(
            (
                IncrementalNode(
                    id="compile",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/out.obj": output},
                    key=lambda _deps: key,
                    execute=lambda _runtime, _cancellation, _inputs: output.write_bytes(b"object"),
                    metadata=lambda _deps: {},
                ),
            )
        )

    # The immutable blob may have converged in the CAS, but the authoritative
    # record name is withheld until the runtime's readable authority closes.
    with cache.lease() as lease:
        assert lease.lookup("producer", key) is None
    assert progress == [ProgressKind.CACHE_MISS, ProgressKind.UNIT_FINISHED]


def test_before_publish_reseal_failure_leaves_record_unpublished(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    output = workspace / "out.obj"
    key = _node_key("implementation-reseal-failure")
    cache = IncrementalCache(state, implementation="dag-test-v1")
    progress: list[tuple[ProgressKind, int, int, str, str]] = []

    with pytest.raises(RuntimeError, match="implementation changed"):
        IncrementalDAGExecutor(
            cache=cache,
            workspace_root=workspace,
            runtime_factory=object,
            runtime_close=lambda _runtime: None,
            max_workers=1,
            before_publish=lambda: (_ for _ in ()).throw(RuntimeError("implementation changed")),
            progress=lambda kind, done, total, phase, node, _reason: progress.append(
                (kind, done, total, phase, node)
            ),
        ).execute(
            (
                IncrementalNode(
                    id="compile",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/out.obj": output},
                    key=lambda _deps: key,
                    execute=lambda _runtime, _cancellation, _inputs: output.write_bytes(b"object"),
                    metadata=lambda _deps: {},
                ),
            )
        )

    with cache.lease() as lease:
        assert lease.lookup("producer", key) is None
    assert [item[0] for item in progress] == [
        ProgressKind.CACHE_MISS,
        ProgressKind.UNIT_FINISHED,
    ]
    assert all(done < total for _kind, done, total, _phase, _node in progress)


@pytest.mark.parametrize("parent_is_hit", (False, True))
def test_final_workspace_reseal_covers_hit_and_miss_outcomes_before_publication(
    tmp_path: Path,
    parent_is_hit: bool,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="dag-test-v1")
    parent_key = _node_key("reseal-parent")
    child_key = _node_key("reseal-child")
    existing_parent = None
    if parent_is_hit:
        cached = tmp_path / "cached.obj"
        cached.write_bytes(b"parent")
        with cache.lease() as lease:
            existing_parent = lease.store(
                "producer",
                parent_key,
                {"build/parent.obj": cached},
            )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    parent = workspace / "parent.obj"
    child = workspace / "child.lib"

    def mutate_parent(
        _runtime: object,
        _cancellation: object,
        _inputs: PreparedNodeInputs,
    ) -> None:
        parent.write_bytes(b"mutated-by-child")
        child.write_bytes(b"child")

    with pytest.raises(IncrementalExecutionError, match="changed before publication"):
        IncrementalDAGExecutor(
            cache=cache,
            workspace_root=workspace,
            runtime_factory=object,
            runtime_close=lambda _runtime: None,
            max_workers=1,
        ).execute(
            (
                IncrementalNode(
                    id="parent",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/parent.obj": parent},
                    key=lambda _deps: parent_key,
                    execute=lambda _runtime, _cancellation, _inputs: parent.write_bytes(b"parent"),
                    metadata=lambda _deps: {},
                ),
                IncrementalNode(
                    id="child",
                    domain="producer",
                    depends_on=("parent",),
                    outputs={"build/child.lib": child},
                    key=lambda _deps: child_key,
                    execute=mutate_parent,
                    materialize_inputs=_materialize_inputs(
                        workspace, "child", {"build/parent.obj": "parent"}
                    ),
                    metadata=lambda _deps: {},
                ),
            )
        )

    with cache.lease() as lease:
        assert lease.lookup("producer", parent_key) == existing_parent
        assert lease.lookup("producer", child_key) is None


def test_data_dependency_requires_receipt_bound_materializer(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    with pytest.raises(
        IncrementalExecutionError,
        match="data dependencies but no receipt-bound input materializer",
    ):
        IncrementalDAGExecutor(
            cache=IncrementalCache(state, implementation="dag-test-v1"),
            workspace_root=workspace,
            runtime_factory=object,
            runtime_close=lambda _runtime: None,
            max_workers=1,
        ).execute(
            (
                IncrementalNode(
                    id="parent",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/parent.obj": workspace / "parent.obj"},
                    key=lambda _deps: _node_key("required-input-parent"),
                    execute=lambda _runtime, _cancel, _inputs: None,
                    metadata=lambda _deps: {},
                ),
                IncrementalNode(
                    id="child",
                    domain="producer",
                    depends_on=("parent",),
                    outputs={"build/child.lib": workspace / "child.lib"},
                    key=lambda _deps: _node_key("required-input-child"),
                    execute=lambda _runtime, _cancel, _inputs: None,
                    metadata=lambda _deps: {},
                ),
            )
        )


def test_transient_workspace_dependency_mutation_cannot_poison_child_record(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    cache = IncrementalCache(state, implementation="dag-test-v1")

    def run(root: Path) -> object:
        root.mkdir()
        parent = root / "parent.obj"
        child = root / "child.lib"

        def consume(
            _runtime: object,
            _cancellation: object,
            inputs: PreparedNodeInputs,
        ) -> None:
            # This exact good -> evil -> good race defeats post-hoc workspace
            # reseals.  The child must consume its independent CAS restore.
            parent.write_bytes(b"evil")
            immutable_parent = inputs.entries["build/parent.obj"].snapshot.path
            consumed = immutable_parent.read_bytes()
            parent.write_bytes(b"good")
            child.write_bytes(consumed + b":child")

        return IncrementalDAGExecutor(
            cache=cache,
            workspace_root=root,
            runtime_factory=object,
            runtime_close=lambda _runtime: None,
            max_workers=1,
        ).execute(
            (
                IncrementalNode(
                    id="parent",
                    domain="producer",
                    depends_on=(),
                    outputs={"build/parent.obj": parent},
                    key=lambda _deps: _node_key("transient-parent"),
                    execute=lambda _runtime, _cancel, _inputs: parent.write_bytes(b"good"),
                    metadata=lambda _deps: {},
                ),
                IncrementalNode(
                    id="child",
                    domain="producer",
                    depends_on=("parent",),
                    outputs={"build/child.lib": child},
                    key=lambda deps: _node_key(
                        "transient-child", deps["parent"].record.outputs[0].digest
                    ),
                    execute=consume,
                    materialize_inputs=_materialize_inputs(
                        root, "transient-child", {"build/parent.obj": "parent"}
                    ),
                    metadata=lambda _deps: {},
                ),
            )
        )

    first = run(tmp_path / "first")
    assert first.summary.misses == 2  # type: ignore[attr-defined]
    assert (tmp_path / "first" / "child.lib").read_bytes() == b"good:child"
    second = run(tmp_path / "second")
    assert second.summary.hits == 2  # type: ignore[attr-defined]
    assert (tmp_path / "second" / "child.lib").read_bytes() == b"good:child"
