from __future__ import annotations

from reprobit.classic.source_overlay import _ancestor_compilers, _graph_archives
from reprobit.classic.link_topology import terminal_link_input_topology
from reprobit.classic_orchestration import compiler_terminal_consumer_targets
from reprobit.model import Digest
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole


def _compiler(owner: str) -> ProducerNode:
    return ProducerNode(
        id=f"compiler.{owner}.0000",
        role=ProducerRole.COMPILER,
        owner=owner,
        arguments=(
            "/c",
            f"${{SOURCE}}/{owner}.cpp",
            f"/Fo${{BUILD}}/{owner}.obj",
        ),
        inputs=(f"source/{owner}.cpp",),
        outputs=(f"build/{owner}.obj",),
    )


def _linked_target_graph() -> tuple[ProducerGraphDocument, dict[str, ProducerNode]]:
    compilers = {name: _compiler(name) for name in ("app", "irrelevant", "static", "upstream")}
    librarian = ProducerNode(
        id="librarian.static.0000",
        role=ProducerRole.LIBRARIAN,
        owner="static",
        arguments=("/out:${BUILD}/static.lib", "${BUILD}/static.obj"),
        inputs=("build/static.obj",),
        outputs=("build/static.lib",),
        depends_on=(compilers["static"].id,),
    )
    upstream = ProducerNode(
        id="linker.upstream.0000",
        role=ProducerRole.LINKER,
        owner="upstream",
        target_id="upstream",
        arguments=(
            "${BUILD}/upstream.obj",
            "/dll",
            "/implib:${BUILD}/upstream.lib",
            "/out:${BUILD}/upstream.dll",
        ),
        inputs=("build/upstream.obj",),
        outputs=("build/upstream.dll", "build/upstream.lib"),
        depends_on=(compilers["upstream"].id,),
    )
    downstream = ProducerNode(
        id="linker.downstream.0000",
        role=ProducerRole.LINKER,
        owner="downstream",
        target_id="downstream",
        arguments=(
            "${BUILD}/app.obj",
            "${BUILD}/static.lib",
            "${BUILD}/upstream.lib",
            "direct.lib",
            "/out:${BUILD}/downstream.exe",
        ),
        inputs=(
            "build/app.obj",
            "build/static.lib",
            "build/upstream.lib",
            "system-library/direct.lib",
        ),
        directive_inputs=("system-library/hidden.lib",),
        outputs=("build/downstream.exe",),
        depends_on=tuple(
            sorted(
                (
                    compilers["app"].id,
                    compilers["irrelevant"].id,
                    librarian.id,
                    upstream.id,
                ),
                key=str.casefold,
            )
        ),
    )
    nodes = (*compilers.values(), librarian, upstream, downstream)
    graph = ProducerGraphDocument(
        schema_version=3,
        toolchain_lock_digest=Digest.from_bytes(b"toolchain"),
        path_profile_id="fixture",
        extractor="cmake-makefiles-v1",
        nodes=tuple(sorted(nodes, key=lambda node: node.id.casefold())),
    )
    return graph, {
        **compilers,
        "librarian": librarian,
        "upstream_linker": upstream,
        "downstream_linker": downstream,
    }


def test_terminal_link_topology_follows_inputs_and_stops_at_linker() -> None:
    graph, nodes = _linked_target_graph()

    upstream = terminal_link_input_topology(graph, "upstream")
    downstream = terminal_link_input_topology(graph, "downstream")

    assert upstream.compiler_node_ids == (nodes["upstream"].id,)
    assert upstream.archive_refs == ()
    assert downstream.compiler_node_ids == (
        nodes["app"].id,
        nodes["static"].id,
    )
    assert nodes["upstream"].id not in downstream.compiler_node_ids
    assert nodes["irrelevant"].id not in downstream.compiler_node_ids
    assert downstream.archive_refs == (
        "build/static.lib",
        "build/upstream.lib",
        "system-library/direct.lib",
        "system-library/hidden.lib",
    )


def test_semantic_and_orchestration_closures_share_linker_boundary() -> None:
    graph, nodes = _linked_target_graph()

    consumers = compiler_terminal_consumer_targets(graph)

    assert consumers[nodes["upstream"].id] == frozenset({"upstream"})
    assert consumers[nodes["app"].id] == frozenset({"downstream"})
    assert consumers[nodes["static"].id] == frozenset({"downstream"})
    assert consumers[nodes["irrelevant"].id] == frozenset()
    assert _ancestor_compilers(graph, "downstream") == frozenset(
        {nodes["app"].id, nodes["static"].id}
    )
    assert _graph_archives(graph, "downstream") == (
        "build/static.lib",
        "build/upstream.lib",
        "system-library/direct.lib",
        "system-library/hidden.lib",
    )
