"""Derive the composed-body ledger from one finished producer-graph run.

The actual terminal link map supplies liveness and provider identity.  Object
contents supply body digests only after the map selects that object.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Protocol

from reprobit.composition_ledger import (
    ComposedBodyLedger,
    ProvidedObject,
    build_ledger,
    function_bodies,
)
from reprobit.linker_map import live_public_providers, provider_name
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
    for reference in (*linker_input_sequence(linker), *linker.directive_inputs):
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
    link_maps: Mapping[str, bytes],
    logical_path: Callable[[Path], str] = str,
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
    selections: dict[str, dict[str, str]] = {}
    for target_id, node_id in sorted(link_nodes.items()):
        linker = nodes.get(node_id)
        if linker is None or linker.role is not ProducerRole.LINKER:
            raise CompositionLedgerError(f"target {target_id!r} names no linker node")
        if node_id not in link_maps:
            raise CompositionLedgerError(f"linker {node_id!r} has no captured live map")
        inventory: list[tuple[str, Path]] = []
        aliases: dict[str, set[str]] = {}
        owners = {output.casefold(): node for node in graph.nodes for output in node.outputs}
        direct = set((*linker_input_sequence(linker), *linker.directive_inputs))
        archives: dict[str, set[str]] = {}
        for reference in direct:
            owner = owners.get(reference.casefold())
            if owner is not None and owner.role is ProducerRole.LIBRARIAN:
                for member in librarian_input_sequence(owner):
                    archives.setdefault(member, set()).add(reference)

        def names(reference: str, path: Path | None) -> set[str]:
            values = {
                provider_name(reference.split("/", 1)[1]),
                provider_name(PureWindowsPath(reference).name),
            }
            if path is not None:
                values.add(provider_name(logical_path(path)))
            return values

        def archive_names(reference: str, path: Path | None) -> set[str]:
            values = names(reference, path)
            return values | {name[:-4] for name in values if name.endswith(".lib")}

        external_archives: set[str] = set()
        project_archives: set[str] = set()
        for reference in direct:
            if _suffix(reference) != ".lib":
                continue
            owner = owners.get(reference.casefold())
            destination = (
                project_archives
                if owner is not None and owner.role is ProducerRole.LIBRARIAN
                else external_archives
            )
            destination.update(archive_names(reference, resolve(reference)))
        ambiguous_archives = external_archives.intersection(project_archives)
        external_archives.difference_update(project_archives)

        for reference in dict.fromkeys(_expand_linker_inputs(graph, linker)):
            path = resolve(reference)
            if path is None:
                raise CompositionLedgerError(f"linker input {reference!r} has no host path")
            resolved = path.resolve(strict=False)
            member_names = names(reference, path)
            if reference in direct:
                for name in member_names:
                    aliases.setdefault(name, set()).add(reference)
            for archive in archives.get(reference, ()):
                archive_path = resolve(archive)
                if archive_path is None:
                    raise CompositionLedgerError(f"archive {archive!r} has no host path")
                for archive_name in archive_names(archive, archive_path):
                    for member_name in member_names:
                        aliases.setdefault(archive_name + ":" + member_name, set()).add(reference)
            inventory.append((reference, resolved))
        selections[target_id] = live_public_providers(
            link_maps[node_id],
            {name: frozenset(values) for name, values in aliases.items()},
            external_archives=frozenset(external_archives),
            ambiguous_archives=frozenset(ambiguous_archives),
        )
        selected_references = set(selections[target_id].values())
        targets[target_id] = tuple(
            ProvidedObject(reference, function_bodies(read(path)), unit_by_object.get(path))
            for reference, path in inventory
            if reference in selected_references
        )
    return build_ledger(producer_graph_digest(graph).value, targets, selections)


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
    def logical_for_host_path(self, path: Path) -> str: ...
    @property
    def linker_maps(self) -> Mapping[str, bytes]: ...


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
        link_maps=run.producer.linker_maps,
        logical_path=run.producer.logical_for_host_path,
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
