"""The ledger derived from a run follows the linker's positional and archive order."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import test_classic_fpo_mosaic_identity as fixture

from reprobit import composition_ledger_runtime as subject
from reprobit.model import Digest
from reprobit.producer_graph import (
    ProducerGraphDocument,
    ProducerNode,
    ProducerRole,
    producer_graph_digest,
)
from reprobit.publication_evidence import collect_verified_publication_evidence

SYMBOL = fixture.TARGET_SYMBOL


def _object(first_byte: int) -> bytes:
    body = bytearray(fixture.SEED_BODY)
    body[0] = first_byte
    return fixture.make_coff(body=bytes(body))


def _compiler(name: str) -> ProducerNode:
    return ProducerNode(
        id=f"compiler.{name}",
        role=ProducerRole.COMPILER,
        owner="program",
        arguments=("/c", f"${{SOURCE}}/src/{name}.cpp", f"/Fo${{BUILD}}/{name}.obj"),
        inputs=(f"source/src/{name}.cpp",),
        outputs=(f"build/{name}.obj",),
    )


def _linker(*positional: str) -> ProducerNode:
    inputs = tuple(
        sorted([*(f"build/{item}" for item in positional), "system-library/kernel32.lib"])
    )
    return ProducerNode(
        id="linker.program",
        role=ProducerRole.LINKER,
        owner="program",
        target_id="program",
        arguments=(
            "/nologo",
            "/dll",
            "/out:${BUILD}/PROGRAM.DLL",
            *(f"${{BUILD}}/{item}" for item in positional),
            "kernel32.lib",
        ),
        inputs=inputs,
        outputs=("build/PROGRAM.DLL",),
        depends_on=tuple(
            sorted(
                {
                    "librarian.core",
                    *(f"compiler.{item[:-4]}" for item in positional if item.endswith(".obj")),
                }
            )
        ),
    )


def _graph(*positional: str) -> ProducerGraphDocument:
    librarian = ProducerNode(
        id="librarian.core",
        role=ProducerRole.LIBRARIAN,
        owner="core",
        arguments=("/nologo", "/out:${BUILD}/core.lib", "${BUILD}/c.obj", "${BUILD}/b.obj"),
        inputs=("build/b.obj", "build/c.obj"),
        outputs=("build/core.lib",),
        depends_on=("compiler.b", "compiler.c"),
    )
    return ProducerGraphDocument(
        schema_version=3,
        toolchain_lock_digest=Digest(value="0" * 64),
        path_profile_id="profile",
        extractor="cmake-makefiles-v1",
        nodes=(_compiler("a"), _compiler("b"), _compiler("c"), librarian, _linker(*positional)),
    )


def test_ledger_orders_positional_objects_before_archive_members(tmp_path: Path) -> None:
    graph = _graph("a.obj", "core.lib")
    payloads = {"a": _object(0x90), "b": _object(0x91), "c": _object(0x92)}
    for name, payload in payloads.items():
        (tmp_path / f"{name}.obj").write_bytes(payload)

    def resolve(reference: str) -> Path | None:
        kind, relative = reference.split("/", 1)
        return tmp_path / relative if kind == "build" else None

    ledger = subject.compose_ledger(
        graph,
        link_nodes={"program": "linker.program"},
        resolve=resolve,
        unit_by_object=subject.unit_objects([("tu.a", tmp_path / "a.obj")]),
    )

    function = ledger.targets["program"].functions[SYMBOL]
    assert (function.provider, function.translation_unit_id) == ("build/a.obj", "tu.a")
    assert ledger.graph_digest == producer_graph_digest(graph).value

    # Without a.obj the linker takes the first archive member in librarian order: c.obj.
    graph_without_a = _graph("core.lib")
    ledger = subject.compose_ledger(
        graph_without_a,
        link_nodes={"program": "linker.program"},
        resolve=resolve,
        unit_by_object={},
    )
    function = ledger.targets["program"].functions[SYMBOL]
    assert (function.provider, function.translation_unit_id) == ("build/c.obj", None)


def test_ledger_refuses_unknown_linker_or_unresolved_input(tmp_path: Path) -> None:
    graph = _graph("a.obj", "core.lib")
    with pytest.raises(subject.CompositionLedgerError, match="names no linker node"):
        subject.compose_ledger(
            graph, link_nodes={"program": "compiler.a"}, resolve=lambda _r: None, unit_by_object={}
        )
    with pytest.raises(subject.CompositionLedgerError, match="has no host path"):
        subject.compose_ledger(
            graph,
            link_nodes={"program": "linker.program"},
            resolve=lambda _r: None,
            unit_by_object={},
        )


def test_ledger_from_run_reads_the_executor_like_the_runtime(tmp_path: Path) -> None:
    from types import SimpleNamespace

    graph = _graph("a.obj", "core.lib")
    for name, first in (("a", 0x90), ("b", 0x91), ("c", 0x92)):
        (tmp_path / f"{name}.obj").write_bytes(_object(first))

    def reference(value: str) -> Path | None:
        kind, relative = value.split("/", 1)
        return tmp_path / relative if kind == "build" else None

    unit = SimpleNamespace(plan=SimpleNamespace(id="tu.a"))
    run = SimpleNamespace(
        graph=graph,
        targets=(SimpleNamespace(target_id="program", link_node_id="linker.program"),),
        units=(unit,),
        donors=SimpleNamespace(
            record_for_unit=lambda item: SimpleNamespace(object_path=tmp_path / "a.obj")
        ),
        producer=SimpleNamespace(reference=reference),
    )

    ledger = subject.ledger_from_run(run)

    function = ledger.targets["program"].functions[SYMBOL]
    assert (function.provider, function.translation_unit_id) == ("build/a.obj", "tu.a")


def test_verify_records_the_ledger_only_when_it_could_be_derived(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from contextlib import contextmanager

    import reprobit.project_execution as cli_build
    from reprobit.composition_ledger import read_ledger

    leases: list[Path] = []

    @contextmanager
    def publication_lease(path: Path):  # type: ignore[no-untyped-def]
        leases.append(path)
        yield

    monkeypatch.setattr(cli_build, "report_publication_lease", publication_lease)

    ledger, error = cli_build._composed_body_ledger(object())
    assert ledger is None and error is not None and "AttributeError" in error
    stale = tmp_path / "ledger" / "composed-bodies.json"
    stale.parent.mkdir()
    stale.write_bytes(b"old ledger\n")
    publication = cli_build._publish_composed_body_ledger(tmp_path, ledger, error)
    assert publication.outcome == "skipped"
    assert publication.functions is None
    assert "removed the older saved repair data" in publication.message
    assert not stale.exists()

    graph = _graph("a.obj", "core.lib")
    for name, first in (("a", 0x90), ("b", 0x91), ("c", 0x92)):
        (tmp_path / f"{name}.obj").write_bytes(_object(first))
    derived = subject.compose_ledger(
        graph,
        link_nodes={"program": "linker.program"},
        resolve=lambda value: (
            tmp_path / value.split("/", 1)[1] if value.startswith("build/") else None
        ),
        unit_by_object={},
    )
    publication = cli_build._publish_composed_body_ledger(tmp_path, derived, None)
    assert publication.outcome == "succeeded"
    assert publication.functions == 1
    assert next(iter(derived.targets["program"].functions.values())).translation_unit_id is None
    assert publication.payload == (tmp_path / "ledger" / "composed-bodies.json").read_bytes()
    assert read_ledger(tmp_path / "ledger" / "composed-bodies.json") == derived

    def fail_write(*_args: object, **_kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(cli_build, "write_ledger", fail_write)
    publication = cli_build._publish_composed_body_ledger(tmp_path, derived, None)
    assert publication.outcome == "skipped"
    assert publication.functions is None
    assert "disk full" in publication.message
    assert "removed the older saved repair data" in publication.message
    assert not stale.exists()
    assert leases == [tmp_path, tmp_path, tmp_path]


def test_verified_evidence_accepts_the_exact_ledger_payload_with_a_null_unit(
    tmp_path: Path,
) -> None:
    from reprobit.composition_ledger import (
        ComposedBodyLedger,
        ComposedTargetLedger,
        LedgerFunction,
        canonical_ledger_payload,
    )

    ledger = ComposedBodyLedger(
        graph_digest="0" * 64,
        targets={
            "program": ComposedTargetLedger(
                functions={
                    "function": LedgerFunction(
                        provider="build/library.lib",
                        translation_unit_id=None,
                        body_sha256="1" * 64,
                        body_length=1,
                    )
                }
            )
        },
    )
    ledger_payload = canonical_ledger_payload(ledger)
    report_json = tmp_path / "reports/report.json"
    report_html = tmp_path / "reports/report.html"
    verified = SimpleNamespace(
        project=tmp_path,
        report_json=report_json,
        report_html=report_html,
        report_json_payload=b"{}\n",
        report_html_payload=b"<html></html>\n",
        ledger=SimpleNamespace(
            path=tmp_path / "ledger/composed-bodies.json",
            outcome="succeeded",
            payload=ledger_payload,
        ),
        engine=SimpleNamespace(
            build=SimpleNamespace(outputs=()),
            targets=(),
            report=SimpleNamespace(proof=SimpleNamespace(supplemental_outputs=())),
            report_payloads={
                report_json: b"{}\n",
                report_html: b"<html></html>\n",
            },
        ),
    )

    evidence = collect_verified_publication_evidence(
        verified,
        staged_root=tmp_path,
        output_paths=(),
        target_paths=(),
        report_json=report_json,
        report_html=report_html,
        ledger_path=tmp_path / "ledger/composed-bodies.json",
    )

    assert b'"translation_unit_id":null' in ledger_payload
    assert evidence.composed_body_ledger == ledger_payload
