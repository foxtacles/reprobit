"""Stable ready-node selection for the cold and warm producer schedulers."""

from __future__ import annotations

import heapq
from collections.abc import Iterable, Mapping
from graphlib import CycleError, TopologicalSorter


class DependencyQueue:
    """Release successors immediately after their last predecessor completes.

    The queue is owned by the scheduling thread. Callers retain responsibility
    for execution, cancellation, resource limits, and publication boundaries.
    """

    def __init__(
        self,
        dependencies: Mapping[str, Iterable[str]],
        *,
        completed: Iterable[str] = (),
    ) -> None:
        prior = set(completed)
        graph = {node: set(parents) - prior for node, parents in dependencies.items()}
        unknown = set().union(*graph.values()) - set(graph) if graph else set()
        if unknown:
            raise ValueError(f"dependency graph has unknown predecessors: {sorted(unknown)}")
        self._sorter = TopologicalSorter(graph)
        try:
            self._sorter.prepare()
        except CycleError as exc:
            raise ValueError(f"dependency graph contains a cycle: {exc.args[1]}") from exc
        self._ready: list[tuple[str, str]] = []
        self._collect_ready()

    def _collect_ready(self) -> None:
        for node in self._sorter.get_ready():
            heapq.heappush(self._ready, (node.casefold(), node))

    def take_ready(self, capacity: int) -> tuple[str, ...]:
        return tuple(heapq.heappop(self._ready)[1] for _ in range(min(capacity, len(self._ready))))

    def finish(self, node: str) -> None:
        self._sorter.done(node)
        self._collect_ready()

    def __bool__(self) -> bool:
        return self._sorter.is_active()
