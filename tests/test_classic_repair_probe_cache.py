"""Streamed donor probes replay seats from the compile store instead of recompiling."""

from __future__ import annotations

import gc
import json
import os
import threading
import time
import weakref
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reprobit import classic_repair_probe_cache as store_module
from reprobit import classic_repair_probe_execution as subject
from reprobit.classic_runtime_probe import ClassicDonorProbeInput, ClassicDonorProbeOutput
from reprobit.execution import StepExecutionReceipt
from reprobit.model import Digest
from reprobit.secure_path_contracts import SecureFileSnapshot
from reprobit.strict_json import canonical_json


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


def _entry_path(directory: Path, epoch: str, key: store_module.ProbeSeatKey) -> Path:
    name = store_module._entry_name(epoch, key)
    return directory / store_module.PROBE_STORE_VERSION / name[:2] / f"{name}.bin"


def _replace_header(encoded: bytes, **updates: object) -> bytes:
    newline = encoded.index(b"\n")
    header = json.loads(encoded[:newline])
    header.update(updates)
    return canonical_json(header) + encoded[newline + 1 :]


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
    assert sorted(first) == ["probe_1", "probe_2"]
    assert second[0] == "probe_3"  # replayed before any compile
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
    observed: list[Any] = []

    def evaluate(outcomes: tuple[Any, ...]) -> bool:
        observed.extend(outcomes)
        return False

    first = _stream(prepared, [("probe_1",)], jobs=1, cache=cache, evaluate=evaluate)
    second = _stream(prepared, [("probe_2",)], jobs=1, cache=cache, evaluate=evaluate)

    assert calls == 1
    assert first == ("probe_1",)
    assert second == ("probe_2",)
    assert all(isinstance(item, subject.ClassicDonorCompileRefusal) for item in observed)
    assert (observed[0].donor_id, observed[1].donor_id) == ("probe_1", "probe_2")
    assert observed[1].reason == observed[0].reason


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
    slow_started = threading.Event()
    settled = threading.Event()

    def fake_compile(*args: Any) -> Any:
        nonlocal active, peak
        donor_id = args[-1]
        with lock:
            started.append(donor_id)
            active += 1
            peak = max(peak, active)
        if donor_id == "slow":
            slow_started.set()
            assert settled.wait(timeout=5), "streaming stopped behind the slow candidate"
        else:
            assert slow_started.wait(timeout=5), "slow candidate never started"
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
        if outcomes[0].donor_id == "e":
            assert not settled.is_set()
            settled.set()
            return True
        return False

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
    assert settled_on[:4] == ["b", "c", "d", "e"]
    assert "never" not in started and "never" not in outcomes
    # Everything that had started was still recorded, including the slow one.
    assert set(outcomes) == set(started)
    assert "slow" in outcomes
    # Windows were pulled lazily: the last one was never requested.
    assert ("never",) not in pulled


def test_streaming_does_not_retain_evaluated_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TrackedOutcome:
        __slots__ = ("__weakref__", "donor_id", "payload")

        def __init__(self, donor_id: str) -> None:
            self.donor_id = donor_id
            self.payload = bytearray(4096)

    donor_ids = tuple(f"probe_{index}" for index in range(32))
    prepared = {donor_id: (_unit(f"seat-{donor_id}"), 0) for donor_id in donor_ids}
    references: list[weakref.ReferenceType[TrackedOutcome]] = []
    live_high_water = 0

    def compile_outcome(*args: Any) -> TrackedOutcome:
        return TrackedOutcome(args[-1])

    def evaluate(outcomes: tuple[Any, ...]) -> bool:
        nonlocal live_high_water
        references.append(weakref.ref(outcomes[0]))
        gc.collect()
        live_high_water = max(
            live_high_water, sum(reference() is not None for reference in references)
        )
        return False

    monkeypatch.setattr(subject, "_compile_output", compile_outcome)
    completed = _stream(
        prepared,
        [(donor_id,) for donor_id in donor_ids],
        jobs=1,
        evaluate=evaluate,
    )
    gc.collect()

    assert completed == donor_ids
    assert live_high_water <= 2
    assert all(reference() is None for reference in references)


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


def test_store_never_follows_a_symlinked_entry_parent(tmp_path: Path) -> None:
    directory = tmp_path / "repair-probes"
    outside = tmp_path / "outside"
    directory.mkdir()
    outside.mkdir()
    (directory / store_module.PROBE_STORE_VERSION).symlink_to(outside, target_is_directory=True)
    key = ("program", "src/unit.cpp", "seat-a")
    entry = _entry_path(directory, "epoch-a", key)
    outside_entry = outside / entry.relative_to(directory / store_module.PROBE_STORE_VERSION)
    outside_entry.parent.mkdir()
    encoded = store_module._encode_output("epoch-a", key, _output("outside"))
    assert encoded is not None
    outside_entry.write_bytes(encoded)

    reader = store_module.ClassicDonorCompileStore(directory)
    assert reader.get("epoch-a", key, donor_id="reader") is None
    assert outside_entry.read_bytes() == encoded

    writer = store_module.ClassicDonorCompileStore(directory)
    writer.put("epoch-a", key, _output("writer", b"replacement"))
    assert writer.stored == 0
    assert outside_entry.read_bytes() == encoded


def test_store_discards_an_oversized_entry_before_reading_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "repair-probes"
    key = ("program", "src/unit.cpp", "seat-a")
    entry = _entry_path(directory, "epoch-a", key)
    entry.parent.mkdir(parents=True)
    entry.write_bytes(b"x" * 65)
    monkeypatch.setattr(store_module, "_MAX_PROBE_ENTRY_BYTES", 64)

    def unexpected_read(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("oversized cache entry was read")

    monkeypatch.setattr(store_module, "read_relative_file", unexpected_read)
    reader = store_module.ClassicDonorCompileStore(directory)

    assert reader.get("epoch-a", key, donor_id="reader") is None
    assert not entry.exists()


def test_store_discards_a_compression_bomb(tmp_path: Path) -> None:
    directory = tmp_path / "repair-probes"
    key = ("program", "src/unit.cpp", "seat-a")
    entry = _entry_path(directory, "epoch-a", key)
    entry.parent.mkdir(parents=True)
    encoded = store_module._encode_output("epoch-a", key, _output("bomb", b"x" * 1_000_000))
    assert encoded is not None
    entry.write_bytes(_replace_header(encoded, object_length=1))

    reader = store_module.ClassicDonorCompileStore(directory)
    assert reader.get("epoch-a", key, donor_id="reader") is None
    assert not entry.exists()


def test_store_compresses_probe_payloads_incrementally(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads: list[bytes] = []

    class Compressor:
        def compress(self, payload: bytes) -> bytes:
            payloads.append(payload)
            return b""

        def flush(self) -> bytes:
            return b"compressed"

    monkeypatch.setattr(store_module.zlib, "compressobj", lambda _level: Compressor())

    encoded = store_module._encode_output(
        "epoch-a",
        ("program", "src/unit.cpp", "seat-a"),
        _output("probe", b"object"),
    )

    assert encoded is not None and encoded.endswith(b"compressed")
    assert payloads == [b"int x;\n", b"object", b"pdb"]


def test_store_rejects_an_oversized_declared_payload_before_decompression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "repair-probes"
    key = ("program", "src/unit.cpp", "seat-a")
    entry = _entry_path(directory, "epoch-a", key)
    entry.parent.mkdir(parents=True)
    encoded = store_module._encode_output("epoch-a", key, _output("oversized"))
    assert encoded is not None
    entry.write_bytes(
        _replace_header(
            encoded,
            object_length=store_module._MAX_PROBE_PAYLOAD_BYTES + 1,
        )
    )

    def unexpected_decompressor() -> object:
        raise AssertionError("oversized declared payload was decompressed")

    monkeypatch.setattr(store_module.zlib, "decompressobj", unexpected_decompressor)
    reader = store_module.ClassicDonorCompileStore(directory)

    assert reader.get("epoch-a", key, donor_id="reader") is None
    assert not entry.exists()


def test_disk_backed_successes_use_a_bounded_lru(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _output("first", b"a" * 16)
    second = _output("second", b"b" * 16)
    third = _output("third", b"c" * 16)
    monkeypatch.setattr(
        store_module,
        "_MAX_DISK_BACKED_MEMORY_BYTES",
        store_module._output_payload_bytes(first) * 2,
    )
    keys = {
        name: ("program", "src/unit.cpp", f"seat-{name}") for name in ("first", "second", "third")
    }
    store = store_module.ClassicDonorCompileStore(tmp_path / "repair-probes")

    store.put("epoch-a", keys["first"], first)
    store.put("epoch-a", keys["second"], second)
    assert store.get("epoch-a", keys["first"], donor_id="first-again") is not None
    store.put("epoch-a", keys["third"], third)

    assert len(store) == 2
    assert store.get("epoch-a", keys["first"], donor_id="first-latest") is not None
    assert store.memory_hits == 2
    assert store.get("epoch-a", keys["second"], donor_id="second-again") is not None
    assert store.disk_hits == 1
    assert store.get("epoch-a", keys["third"], donor_id="third-again") is not None
    assert store.disk_hits == 2
    assert len(list((tmp_path / "repair-probes").rglob("*.bin"))) == 3


def test_disk_backed_lru_never_evicts_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = _output("first", b"a" * 16)
    monkeypatch.setattr(
        store_module,
        "_MAX_DISK_BACKED_MEMORY_BYTES",
        store_module._output_payload_bytes(output),
    )
    store = store_module.ClassicDonorCompileStore(tmp_path / "repair-probes")
    refusal_key = ("program", "src/unit.cpp", "seat-refusal")

    store.put(
        "epoch-a",
        refusal_key,
        store_module.ClassicDonorCompileRefusal("refusal", "compiler rejected input"),
    )
    store.put("epoch-a", ("program", "src/unit.cpp", "seat-first"), output)
    store.put(
        "epoch-a",
        ("program", "src/unit.cpp", "seat-second"),
        _output("second", b"b" * 16),
    )

    assert len(store) == 2
    replayed = store.get("epoch-a", refusal_key, donor_id="refusal-again")
    assert isinstance(replayed, store_module.ClassicDonorCompileRefusal)
    assert replayed.donor_id == "refusal-again"
    assert store.memory_hits == 1


def test_directoryless_store_keeps_all_successes_in_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(store_module, "_MAX_DISK_BACKED_MEMORY_BYTES", 0)
    store = store_module.ClassicDonorCompileStore()
    keys = [("program", "src/unit.cpp", f"seat-{index}") for index in range(3)]
    for index, key in enumerate(keys):
        store.put("epoch-a", key, _output(f"probe-{index}", bytes([index])))

    assert len(store) == 3
    assert all(store.get("epoch-a", key, donor_id="again") is not None for key in keys)
    assert store.memory_hits == 3


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


def test_probe_store_gc_removes_only_entries_older_than_the_requested_age(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    old_entry = state / "repair-probes" / "v1" / "aa" / "old.bin"
    recent_entry = state / "repair-probes" / "v1" / "bb" / "recent.bin"
    old_entry.parent.mkdir(parents=True)
    recent_entry.parent.mkdir(parents=True)
    old_entry.write_bytes(b"old")
    recent_entry.write_bytes(b"recent")
    now_ns = time.time_ns()
    old_ns = now_ns - 7_200_000_000_000
    os.utime(old_entry, ns=(old_ns, old_ns))

    preview = store_module.gc_probe_store(
        state,
        older_than_seconds=3600,
        dry_run=True,
        now_ns=now_ns,
    )

    assert preview == store_module.ProbeStoreGCResult(1, 3, 1)
    assert old_entry.is_file() and recent_entry.is_file()

    result = store_module.gc_probe_store(
        state,
        older_than_seconds=3600,
        now_ns=now_ns,
    )

    assert result == preview
    assert not old_entry.exists()
    assert recent_entry.read_bytes() == b"recent"


def test_probe_store_gc_preserves_an_entry_replaced_after_its_age_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    entry = state / "repair-probes" / "v1" / "aa" / "old.bin"
    entry.parent.mkdir(parents=True)
    entry.write_bytes(b"old")
    now_ns = time.time_ns()
    old_ns = now_ns - 7_200_000_000_000
    os.utime(entry, ns=(old_ns, old_ns))
    real_remove = store_module.remove_published_relative

    def replace_then_remove(
        root: Path,
        relative: str,
        *,
        expected: SecureFileSnapshot,
    ) -> bool:
        entry.write_bytes(b"fresh")
        return real_remove(root, relative, expected=expected)

    monkeypatch.setattr(store_module, "remove_published_relative", replace_then_remove)

    result = store_module.gc_probe_store(
        state,
        older_than_seconds=3600,
        now_ns=now_ns,
    )

    assert result == store_module.ProbeStoreGCResult(0, 0, 0)
    assert entry.read_bytes() == b"fresh"


def test_probe_store_gc_does_not_hash_recent_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    entry = state / "repair-probes" / "v1" / "aa" / "recent.bin"
    entry.parent.mkdir(parents=True)
    entry.write_bytes(b"recent")

    def fail_digest(_root: Path, _relative: str) -> object:
        raise AssertionError("recent entries must not be hashed during cleanup")

    monkeypatch.setattr(store_module, "digest_relative_file", fail_digest)

    result = store_module.gc_probe_store(
        state,
        older_than_seconds=3600,
        now_ns=time.time_ns(),
    )

    assert result == store_module.ProbeStoreGCResult(0, 0, 1)
    assert entry.read_bytes() == b"recent"


def test_probe_store_gc_preserves_an_empty_directory_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    seat = state / "repair-probes" / "v1" / "aa"
    seat.mkdir(parents=True)
    original = seat.with_name("original-aa")
    real_remove = store_module.remove_exact_empty_directory
    swapped = False

    def replace_then_remove(path: Path, expected: tuple[int, int]) -> None:
        nonlocal swapped
        if path == seat and not swapped:
            swapped = True
            seat.rename(original)
            seat.mkdir()
        real_remove(path, expected)

    monkeypatch.setattr(store_module, "remove_exact_empty_directory", replace_then_remove)

    result = store_module.gc_probe_store(state, older_than_seconds=0)

    assert result == store_module.ProbeStoreGCResult(0, 0, 0)
    assert swapped
    assert seat.is_dir()
    assert original.is_dir()


def test_ordered_stream_bounds_cache_hits_behind_a_slow_predecessor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ready = threading.Event()
    release = threading.Event()
    looked_up: list[str] = []
    delivered: list[str] = []
    prepared = {str(index): (_unit(str(index)), 0) for index in range(20)}

    class Cache:
        def get(self, _epoch, _key, *, donor_id):  # type: ignore[no-untyped-def]
            looked_up.append(donor_id)
            return None if donor_id == "0" else _output(donor_id)

        def put(self, *_args):  # type: ignore[no-untyped-def]
            pass

    def compile_first(*args: Any) -> ClassicDonorProbeOutput:
        assert args[-1] == "0"
        ready.set()
        assert release.wait(5)
        return _output("0")

    original_wait = subject.wait

    def wait_for_predecessor(*args: Any, **kwargs: Any) -> Any:
        assert ready.wait(5)
        assert looked_up == ["0", "1"]  # One running plus one buffered, never all 20.
        assert delivered == []
        release.set()
        return original_wait(*args, **kwargs)

    monkeypatch.setattr(subject, "_compile_output", compile_first)
    monkeypatch.setattr(subject, "wait", wait_for_predecessor)
    try:
        result = subject._stream_compiles(
            SimpleNamespace(),
            prepared,
            object(),
            object(),
            object(),
            (tuple(prepared),),
            evaluate=lambda outcomes: delivered.extend(item.donor_id for item in outcomes) or False,
            progress=None,
            planned_candidates=20,
            cache=Cache(),
            epoch="test",
            jobs=2,
            ordered_outcomes=True,
        )
    finally:
        release.set()
    assert result[:2] == ("1", "0")  # Completion reporting remains responsive.
    assert len(result) == len(prepared) and set(result) == set(prepared)
    assert delivered == list(prepared)
