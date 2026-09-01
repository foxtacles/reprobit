"""Authentic producer ancestry for one classic terminal link.

Build scheduling dependencies are not necessarily linker inputs.  This module
therefore follows ownership of actual ``build/`` inputs, descends through
non-link producers such as librarians, and treats an upstream linker output as
an opaque boundary (for example, a DLL import library).
"""

from __future__ import annotations

from dataclasses import dataclass

from reprobit.classic.link_closure import (
    ClassicLinkClosureError,
    direct_terminal_link_control_references,
)
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole


class ClassicLinkTopologyError(ValueError):
    """A terminal link lacks one closed, input-derived producer topology."""


@dataclass(frozen=True, slots=True)
class TerminalLinkInputTopology:
    """Compiler producers and archives that can affect one terminal link."""

    compiler_node_ids: tuple[str, ...]
    archive_refs: tuple[str, ...]


def terminal_link_input_topology(
    graph: ProducerGraphDocument,
    target_id: str,
) -> TerminalLinkInputTopology:
    """Return the actual input closure, stopping at upstream LINK boundaries."""

    terminals = tuple(
        node
        for node in graph.nodes
        if node.role is ProducerRole.LINKER and node.target_id == target_id
    )
    if len(terminals) != 1:
        raise ClassicLinkTopologyError(
            f"target {target_id!r} has {len(terminals)} terminal linker nodes"
        )
    terminal = terminals[0]

    output_owners: dict[str, ProducerNode] = {}
    for node in graph.nodes:
        for reference in node.outputs:
            identity = reference.casefold()
            previous = output_owners.setdefault(identity, node)
            if previous is not node:
                raise ClassicLinkTopologyError(f"producer output {reference!r} has multiple owners")

    compiler_ids: set[str] = set()
    visited: set[str] = set()

    def visit_inputs(node: ProducerNode) -> None:
        if node.id in visited:
            return
        visited.add(node.id)
        for reference in node.inputs:
            if not reference.startswith("build/"):
                continue
            producer = output_owners.get(reference.casefold())
            if producer is None:
                raise ClassicLinkTopologyError(
                    f"producer {node.id!r} consumes unowned build input {reference!r}"
                )
            if producer.role is ProducerRole.COMPILER:
                compiler_ids.add(producer.id)
            elif producer.role is not ProducerRole.LINKER:
                visit_inputs(producer)

    visit_inputs(terminal)
    try:
        references = direct_terminal_link_control_references(terminal)
    except ClassicLinkClosureError as exc:
        raise ClassicLinkTopologyError(str(exc)) from exc
    return TerminalLinkInputTopology(
        tuple(sorted(compiler_ids, key=str.casefold)),
        references.archives,
    )


__all__ = [
    "ClassicLinkTopologyError",
    "TerminalLinkInputTopology",
    "terminal_link_input_topology",
]
