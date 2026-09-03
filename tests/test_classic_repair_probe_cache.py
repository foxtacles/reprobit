"""Streamed donor probes replay seats from the compile store instead of recompiling."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reprobit import classic_repair_probe_cache as store_module
from reprobit import classic_repair_probe_execution as subject
from reprobit.classic_runtime_probe import ClassicDonorProbeInput, ClassicDonorProbeOutput
from reprobit.execution import StepExecutionReceipt
from reprobit.model import Digest


def _unit(seat: str, source: str = "src/unit.cpp", rendered: bytes = b"int x;\n") -> Any:
    request = SimpleNamespace(
        compiler_seat=seat,
        family=SimpleNamespace(value="declaration_shape"),
        build_target="program",
        logical_source=source,
        staged_source="s.cpp",
        files={"s.cpp": rendered},
        logical_outputs={source: rendered},
        compiler_additions=SimpleNamespace(
            force_includes=(), include_directories=(), include_projection="none"
        ),
        carrier_identifiers=frozenset(),
    )
    return SimpleNamespace(
        plan=SimpleNamespace(build_target="program", source=source),
        donors=[SimpleNamespace(request=request)],
    )


def _output(donor_id: str, payload: bytes = b"object") -> ClassicDonorProbeOutput:
    digest = Digest.from_bytes(payload)
    return ClassicDonorProbeOutput(
        donor_id,
        "unit.fixture",
        "program",
        "src/unit.cpp",
        "compiler.program.0001",
        (ClassicDonorProbeInput("src/unit.cpp", Digest.from_bytes(b"int x;\n"), 7, b"int x;\n"),),
        digest,
        Digest.from_bytes(b"pdb"),
        payload,
        b"pdb",
        StepExecutionReceipt("probe", 0, 1, 0.25, digest, digest),
    )


def _stream(
    prepared: dict[str, Any],
    windows: list[tuple[str, ...]],
    *,
    jobs: int = 2,
    cache: store_module.ClassicDonorCompileStore | None = None,
    evaluate: Any = None,
    epoch: str = "epoch-a",
) -> tuple[Any, ...]:
    progress: list[tuple[int, int, str]] = []
    return subject._stream_compiles(
        SimpleNamespace(),
        prepared,
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        iter(windows),
        evaluate=evaluate or (lambda outcomes: False),
        progress=lambda completed, total, donor_id: progress.append((completed, total, donor_id)),
        planned_candidates=sum(len(window) for window in windows),
        cache=cache,
        epoch=epoch,
        jobs=jobs,
    )


def test_cached_seat_is_replayed_under_the_new_probe_id(monkeypatch: pytest.MonkeyPatch) -> None:
    compiled: list[str] = []

    def fake_compile(*args: Any) -> Any:
        donor_id = args[-1]
        compiled.append(donor_id)
        return _output(donor_id, f"object of {donor_id}".encode())

    monkeypatch.setattr(subject, "_compile_output", fake_compile)
    prepared = {
        "probe_1": (_unit("seat-a"), 0),
        "probe_2": (_unit("seat-b"), 0),
        "probe_3": (_unit("SEAT-A"), 0),  # same seat, different spelling
        "probe_4": (_unit("seat-a", source="src/other.cpp"), 0),  # another unit: never shared
    }
    cache = store_module.ClassicDonorCompileStore()

    first = _stream(prepared, [("probe_1", "probe_2")], cache=cache)
    second = _stream(prepared, [("probe_3", "probe_4")], cache=cache)

    assert sorted(compiled) == ["probe_1", "probe_2", "probe_4"]
    assert sorted(item.donor_id for item in first) == ["probe_1", "probe_2"]
    assert second[0].donor_id == "probe_3"  # replayed before any compile
    replayed = next(item for item in second if item.donor_id == "probe_3")
    assert replayed.object_payload == b"object of probe_1"
    assert cache.memory_hits == 1 and cache.misses == 3 and len(cache) == 3


def test_same_seat_with_other_rendered_inputs_is_never_replayed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiled: list[str] = []
    monkeypatch.setattr(
        subject, "_compile_output", lambda *args: compiled.append(args[-1]) or _output(args[-1])
    )
    prepared = {
        "probe_1": (_unit("seat-a", rendered=b"class A;\nint x;\n"), 0),
        "probe_2": (_unit("seat-a", rendered=b"int x;\nclass A;\n"), 0),
    }
    cache = store_module.ClassicDonorCompileStore()

    _stream(prepared, [("probe_1",)], jobs=1, cache=cache)
    _stream(prepared, [("probe_2",)], jobs=1, cache=cache)

    assert compiled == ["probe_1", "probe_2"]
    assert len(cache) == 2


def test_refusals_are_cached_and_replayed_with_the_new_donor_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def failing_compile(*args: Any) -> Any:
        nonlocal calls
        calls += 1
        raise subject.ClassicProjectError("compiler exited without an object")

    monkeypatch.setattr(subject, "_compile_output", failing_compile)
    prepared = {"probe_1": (_unit("seat-a"), 0), "probe_2": (_unit("seat-a"), 0)}
    cache = store_module.ClassicDonorCompileStore()

    first = _stream(prepared, [("probe_1",)], jobs=1, cache=cache)
    second = _stream(prepared, [("probe_2",)], jobs=1, cache=cache)

    assert calls == 1
    assert isinstance(first[0], subject.ClassicDonorCompileRefusal)
    assert isinstance(second[0], subject.ClassicDonorCompileRefusal)
    assert (first[0].donor_id, second[0].donor_id) == ("probe_1", "probe_2")
    assert second[0].reason == first[0].reason


def test_without_a_cache_every_seat_compiles(monkeypatch: pytest.MonkeyPatch) -> None:
    compiled: list[str] = []
    monkeypatch.setattr(
        subject, "_compile_output", lambda *args: compiled.append(args[-1]) or _output(args[-1])
    )
    prepared = {"probe_1": (_unit("seat-a"), 0), "probe_2": (_unit("seat-a"), 0)}

    _stream(prepared, [("probe_1",)], jobs=1)
    _stream(prepared, [("probe_2",)], jobs=1)

    assert compiled == ["probe_1", "probe_2"]


def test_another_epoch_never_replays_a_seat(monkeypatch: pytest.MonkeyPatch) -> None:
    compiled: list[str] = []
    monkeypatch.setattr(
        subject, "_compile_output", lambda *args: compiled.append(args[-1]) or _output(args[-1])
    )
    prepared = {"probe_1": (_unit("seat-a"), 0), "probe_2": (_unit("seat-a"), 0)}
    cache = store_module.ClassicDonorCompileStore()

    _stream(prepared, [("probe_1",)], jobs=1, cache=cache, epoch="epoch-a")
    _stream(prepared, [("probe_2",)], jobs=1, cache=cache, epoch="epoch-b")

    assert compiled == ["probe_1", "probe_2"]


def test_streaming_keeps_workers_busy_and_stops_pulling_after_settlement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A slow candidate never holds back the others; settlement stops new pulls only."""

    started: list[str] = []
    active = 0
    peak = 0
    lock = threading.Lock()

    def fake_compile(*args: Any) -> Any:
        nonlocal active, peak
        donor_id = args[-1]
        with lock:
            started.append(donor_id)
            active += 1
            peak = max(peak, active)
        time.sleep(0.3 if donor_id == "slow" else 0.02)
        with lock:
            active -= 1
        return _output(donor_id)

    monkeypatch.setattr(subject, "_compile_output", fake_compile)
    prepared = {
        name: (_unit(f"seat-{name}"), 0) for name in ("slow", "b", "c", "d", "e", "f", "never")
    }
    pulled: list[tuple[str, ...]] = []

    def windows() -> Any:
        for window in (("slow", "b"), ("c", "d"), ("e", "f"), ("never",)):
            pulled.append(window)
            yield window

    settled_on: list[str] = []

    def evaluate(outcomes: tuple[Any, ...]) -> bool:
        assert len(outcomes) == 1
        settled_on.append(outcomes[0].donor_id)
        return outcomes[0].donor_id == "e"

    outcomes = subject._stream_compiles(
        SimpleNamespace(),
        prepared,
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        object(),  # type: ignore[arg-type]
        windows(),
        evaluate=evaluate,
        progress=None,
        planned_candidates=7,
        cache=None,
        epoch="",
        jobs=2,
    )

    assert peak == 2
    assert "never" not in started and "never" not in {item.donor_id for item in outcomes}
    # Everything that had started was still recorded, including the slow one.
    assert {item.donor_id for item in outcomes} == set(started)
    assert "slow" in {item.donor_id for item in outcomes}
    # Windows were pulled lazily: the last one was never requested.
    assert ("never",) not in pulled


def test_store_round_trips_outputs_through_its_directory(tmp_path: Path) -> None:
    payload = b"\x00object bytes" * 1000
    original = _output("compiled", payload)
    key = ("program", "src/unit.cpp", "seat-a")

    writer = store_module.ClassicDonorCompileStore(tmp_path / "repair-probes")
    writer.put("epoch-a", key, original)
    assert writer.stored == 1
    files = list((tmp_path / "repair-probes").rglob("*.bin"))
    assert len(files) == 1

    reader = store_module.ClassicDonorCompileStore(tmp_path / "repair-probes")
    replayed = reader.get("epoch-a", key, donor_id="later")
    assert isinstance(replayed, ClassicDonorProbeOutput)
    assert replayed.donor_id == "later"
    assert replayed.object_payload == payload
    assert replayed.pdb_payload == original.pdb_payload
    assert replayed.rendered_inputs == original.rendered_inputs
    assert replayed.step == original.step
    assert replayed.translation_unit_id == original.translation_unit_id
    assert reader.disk_hits == 1
    # The second read of the same key is served from memory.
    assert reader.get("epoch-a", key, donor_id="again") is not None
    assert reader.memory_hits == 1

    assert reader.get("epoch-b", key, donor_id="other") is None
    assert reader.get("epoch-a", ("program", "src/unit.cpp", "seat-b"), donor_id="x") is None


def test_store_discards_a_damaged_entry_and_never_persists_refusals(tmp_path: Path) -> None:
    key = ("program", "src/unit.cpp", "seat-a")
    store = store_module.ClassicDonorCompileStore(tmp_path / "repair-probes")
    store.put("epoch-a", key, _output("compiled", b"payload"))
    (entry,) = list((tmp_path / "repair-probes").rglob("*.bin"))
    data = bytearray(entry.read_bytes())
    data[-3] ^= 0xFF
    entry.write_bytes(bytes(data))

    reader = store_module.ClassicDonorCompileStore(tmp_path / "repair-probes")
    assert reader.get("epoch-a", key, donor_id="x") is None
    assert not entry.exists()

    reader.put("epoch-a", key, store_module.ClassicDonorCompileRefusal("r", "boom"))
    assert list((tmp_path / "repair-probes").rglob("*.bin")) == []
    replayed = reader.get("epoch-a", key, donor_id="y")
    assert isinstance(replayed, store_module.ClassicDonorCompileRefusal)
    assert replayed.donor_id == "y"


def test_compile_epoch_names_graph_environment_authority_and_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reprobit.classic_execution_records import ClassicActiveCompilerEpoch
    from reprobit.classic_includes import IncludeOrigin, SealedIncludeAuthority, SealedIncludeFile

    graph_digests: dict[str, Digest] = {"value": Digest.from_bytes(b"graph-1")}
    monkeypatch.setattr(
        store_module, "producer_graph_digest", lambda _graph: graph_digests["value"]
    )
    root = tmp_path / "source"
    root.mkdir()
    (root / "a.cpp").write_bytes(b"int a;\n")
    authority = SealedIncludeAuthority(
        ("Z:\\src",),
        (
            SealedIncludeFile(
                "Z:\\src\\a.h", Digest.from_bytes(b"h"), 1, IncludeOrigin.PROJECT_SOURCE
            ),
        ),
    )
    seal = {root.resolve() / "a.cpp": (7, Digest.from_bytes(b"int a;\n"))}
    epoch = ClassicActiveCompilerEpoch("ns", authority, seal, False)
    environment = Digest.from_bytes(b"env")
    graph: Any = object()

    first = store_module.compile_epoch_digest(graph, environment, epoch, effective_root=root)
    same = store_module.compile_epoch_digest(graph, environment, epoch, effective_root=root)
    other_environment = store_module.compile_epoch_digest(
        graph, Digest.from_bytes(b"env2"), epoch, effective_root=root
    )
    other_sources = store_module.compile_epoch_digest(
        graph,
        environment,
        ClassicActiveCompilerEpoch(
            "ns", authority, {root.resolve() / "a.cpp": (8, Digest.from_bytes(b"int aa;\n"))}, False
        ),
        effective_root=root,
    )
    other_authority = store_module.compile_epoch_digest(
        graph,
        environment,
        ClassicActiveCompilerEpoch("ns", SealedIncludeAuthority(("Z:\\src",), ()), seal, False),
        effective_root=root,
    )
    graph_digests["value"] = Digest.from_bytes(b"graph-2")
    other_graph = store_module.compile_epoch_digest(graph, environment, epoch, effective_root=root)

    assert first == same
    assert len({first, other_environment, other_sources, other_authority, other_graph}) == 5
