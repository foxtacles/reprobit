from __future__ import annotations

from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import cast

import pytest

from reprobit.dag_queue import DependencyQueue


def test_queue_releases_successor_without_waiting_for_other_roots() -> None:
    queue = DependencyQueue(
        {"slow": (), "parent": ("prior",), "child": ("parent",)}, completed={"prior"}
    )
    assert queue.take_ready(2) == ("parent", "slow")
    queue.finish("parent")
    assert queue.take_ready(1) == ("child",)
    queue.finish("child")
    assert queue
    queue.finish("slow")
    assert not queue


@pytest.mark.parametrize("graph", [{"a": ("missing",)}, {"a": ("b",), "b": ("a",)}])
def test_queue_rejects_invalid_graph_before_execution(graph: dict[str, tuple[str, ...]]) -> None:
    with pytest.raises(ValueError):
        DependencyQueue(graph)


def test_cold_producer_releases_ready_child_before_unrelated_node(tmp_path: Path) -> None:
    from reprobit.classic_runtime_producer import ClassicProducerExecution
    from reprobit.execution import StepExecutionReceipt
    from reprobit.model import Digest
    from reprobit.process import CancellationToken, ProcessSupervisor
    from reprobit.producer_graph import ProducerNode, ProducerRole

    child_started = Event()
    digest = Digest.from_bytes(b"receipt")
    nodes = tuple(
        ProducerNode.model_construct(
            id=name,
            role=ProducerRole.COMPILER,
            depends_on=("b_parent",) if name == "c_child" else (),
        )
        for name in ("a_slow", "b_parent", "c_child")
    )

    def run_node(
        _supervisor: ProcessSupervisor,
        node: ProducerNode,
        _cancellation: CancellationToken,
        **_kwargs: object,
    ) -> tuple[StepExecutionReceipt, ...]:
        if node.id == "a_slow":
            assert child_started.wait(timeout=5), "ready child waited for unrelated work"
        elif node.id == "c_child":
            child_started.set()
        return (StepExecutionReceipt(node.id, 0, 1, 0.0, digest, digest),)

    producer = cast(
        ClassicProducerExecution,
        SimpleNamespace(
            jobs=2,
            run_node=run_node,
            node_outputs=lambda node: (tmp_path / node.id,),
            _progress=SimpleNamespace(emit=lambda *_args: None),
        ),
    )
    completed: set[str] = set()
    output_steps: dict[Path, str] = {}
    with ProcessSupervisor() as supervisor:
        receipts = ClassicProducerExecution.run_graph_nodes(
            producer,
            supervisor,
            nodes,
            completed=completed,
            output_steps=output_steps,
            cancellation=CancellationToken(),
        )
    assert completed == {node.id for node in nodes}
    assert {item.step_id for item in receipts} == completed
    assert set(output_steps.values()) == completed
