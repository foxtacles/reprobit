"""Derive the composed-body ledger from one finished producer-graph run.

The runtime already knows every fact the ledger needs: the terminal linker of
each target and its positional inputs, the librarians whose archive members
those inputs expand to, which compiled object belongs to which reviewed
translation unit, and where the composed objects were written.  This module
only reads those objects back and applies the first-definer rule.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Protocol

from reprobit.composition_ledger import (
    ComposedBodyLedger,
    ProvidedObject,
    build_ledger,
    function_bodies,
)
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    librarian_input_sequence,
    linker_input_sequence,
    producer_graph_digest,
)


class CompositionLedgerError(RuntimeError):
    """The finished run does not describe its linker inputs completely."""


def _suffix(reference: str) -> str:
    return PurePosixPath(reference.split("/", 1)[1]).suffix.casefold()


def _expand_linker_inputs(graph: ProducerGraphDocument, linker: ProducerNode) -> tuple[str, ...]:
    """Positional objects, then each archive's members in librarian order."""

    owners: dict[str, ProducerNode] = {}
    for node in graph.nodes:
        for output in node.outputs:
            owners[output.casefold()] = node
    objects: list[str] = []
    archives: list[str] = []
    for reference in linker_input_sequence(linker):
        suffix = _suffix(reference)
        if suffix == ".obj":
            objects.append(reference)
        elif suffix == ".lib" and reference in archives:
            continue
        elif suffix == ".lib":
            archives.append(reference)
    expanded = list(objects)
    for archive in archives:
        owner = owners.get(archive.casefold())
        if owner is None or owner.role is not ProducerRole.LIBRARIAN:
            continue  # System or quarantine archives never carry project functions.
        expanded.extend(librarian_input_sequence(owner))
    return tuple(expanded)


def compose_ledger(
    graph: ProducerGraphDocument,
    *,
    link_nodes: Mapping[str, str],
    resolve: Callable[[str], Path | None],
    unit_by_object: Mapping[Path, str],
    read: Callable[[Path], bytes] = Path.read_bytes,
) -> ComposedBodyLedger:
    """Build the ledger of one finished run.

    ``link_nodes`` maps target ids to their terminal linker node ids;
    ``resolve`` turns a graph reference into the host path the run wrote;
    ``unit_by_object`` names the reviewed translation unit behind a composed
    object path (plain compiled objects have none).
    """

    nodes = {node.id: node for node in graph.nodes}
    targets: dict[str, Sequence[ProvidedObject]] = {}
    for target_id, node_id in sorted(link_nodes.items()):
        linker = nodes.get(node_id)
        if linker is None or linker.role is not ProducerRole.LINKER:
            raise CompositionLedgerError(f"target {target_id!r} names no linker node")
        provided: list[ProvidedObject] = []
        for reference in _expand_linker_inputs(graph, linker):
            path = resolve(reference)
            if path is None:
                raise CompositionLedgerError(f"linker input {reference!r} has no host path")
            resolved = path.resolve(strict=False)
            provided.append(
                ProvidedObject(
                    provider=reference,
                    bodies=function_bodies(read(resolved)),
                    translation_unit_id=unit_by_object.get(resolved),
                )
            )
        targets[target_id] = tuple(provided)
    return build_ledger(producer_graph_digest(graph).value, targets)


class _UnitPlan(Protocol):
    id: str


class _PreparedUnit(Protocol):
    plan: _UnitPlan


class _CompileRecord(Protocol):
    object_path: Path


class _Target(Protocol):
    target_id: str
    link_node_id: str


class _Donors(Protocol):
    def record_for_unit(self, unit: _PreparedUnit) -> _CompileRecord: ...


class _Producer(Protocol):
    def reference(self, value: str) -> Path | None: ...


class FinishedRun(Protocol):
    """The parts of a producer-graph executor the ledger reads after a run."""

    graph: ProducerGraphDocument
    targets: Sequence[_Target]
    units: Sequence[_PreparedUnit]
    donors: _Donors
    producer: _Producer


def ledger_from_run(run: FinishedRun) -> ComposedBodyLedger:
    """Derive the ledger from a finished executor while its workspace still exists."""

    return compose_ledger(
        run.graph,
        link_nodes={target.target_id: target.link_node_id for target in run.targets},
        resolve=run.producer.reference,
        unit_by_object=unit_objects(
            (unit.plan.id, run.donors.record_for_unit(unit).object_path) for unit in run.units
        ),
    )


def unit_objects(pairs: Iterable[tuple[str, Path]]) -> dict[Path, str]:
    """Index composed object paths by translation-unit id, resolved like the runtime does."""

    return {path.resolve(strict=False): unit_id for unit_id, path in pairs}


__all__ = [
    "CompositionLedgerError",
    "FinishedRun",
    "compose_ledger",
    "ledger_from_run",
    "unit_objects",
]
