from __future__ import annotations

import threading
import time

import pytest

from reprobit.progress import ProgressEmitter, ProgressEvent, ProgressKind


def test_phase_emits_ordered_start_unit_and_finish_events() -> None:
    events: list[ProgressEvent] = []
    emitter = ProgressEmitter(events.append, heartbeat_seconds=60)

    with emitter.phase("execute", "executing producers") as phase:
        phase.advance(
            completed=1,
            total=2,
            phase="compile",
            node_id="compiler.sample.0001",
        )
        phase.cache(
            hit=True,
            completed=2,
            total=2,
            phase="link",
            node_id="linker.sample.0002",
            reason="exact producer key",
        )

    assert [event.kind for event in events] == [
        ProgressKind.PHASE_STARTED,
        ProgressKind.UNIT_FINISHED,
        ProgressKind.CACHE_HIT,
        ProgressKind.PHASE_FINISHED,
    ]
    assert [event.sequence for event in events] == [1, 2, 3, 4]
    assert events[1].as_dict()["node_id"] == "compiler.sample.0001"
    assert events[2].as_dict()["reason"] == "exact producer key"


def test_failed_phase_has_one_terminal_failure_event() -> None:
    events: list[ProgressEvent] = []
    emitter = ProgressEmitter(events.append, heartbeat_seconds=60)

    with (
        pytest.raises(RuntimeError, match="producer failed"),
        emitter.phase("execute", "executing producers"),
    ):
        raise RuntimeError("producer failed")

    assert [event.kind for event in events] == [
        ProgressKind.PHASE_STARTED,
        ProgressKind.PHASE_FAILED,
    ]
    assert events[-1].message == "executing producers"
    assert events[-1].reason == "producer failed"
    assert events[-1].as_dict()["reason"] == "producer failed"


def test_failed_phase_preserves_an_exception_with_no_rendered_message() -> None:
    events: list[ProgressEvent] = []
    emitter = ProgressEmitter(events.append, heartbeat_seconds=60)

    with pytest.raises(RuntimeError) as raised, emitter.phase("execute", "executing producers"):
        raise RuntimeError()

    assert type(raised.value) is RuntimeError
    assert [event.kind for event in events] == [
        ProgressKind.PHASE_STARTED,
        ProgressKind.PHASE_FAILED,
    ]
    assert events[-1].message == "executing producers"
    assert events[-1].reason == "RuntimeError"


def test_long_silent_phase_emits_heartbeat() -> None:
    events: list[ProgressEvent] = []
    received = threading.Event()

    def observe(event: ProgressEvent) -> None:
        events.append(event)
        if event.kind is ProgressKind.HEARTBEAT:
            received.set()

    emitter = ProgressEmitter(observe, heartbeat_seconds=0.01)
    with emitter.phase("prepare", "preparing workspace"):
        assert received.wait(timeout=1)

    assert ProgressKind.HEARTBEAT in {event.kind for event in events}
    assert events[-1].kind is ProgressKind.PHASE_FINISHED


def test_heartbeat_retains_latest_count_and_named_subphase() -> None:
    events: list[ProgressEvent] = []
    received = threading.Event()

    def observe(event: ProgressEvent) -> None:
        events.append(event)
        if event.kind is ProgressKind.HEARTBEAT and event.completed == 7:
            received.set()

    emitter = ProgressEmitter(observe, heartbeat_seconds=0.01)
    with emitter.phase("execute", "building project") as phase:
        phase.advance(
            completed=7,
            total=10,
            phase="compile",
            node_id="compiler.sample.0007",
        )
        phase.activity(
            kind=ProgressKind.PHASE_STARTED,
            phase="evidence",
            message="assembling authenticity evidence",
        )
        assert received.wait(timeout=1)

    heartbeat = next(
        event
        for event in events
        if event.kind is ProgressKind.HEARTBEAT and event.completed == 7
    )
    assert (heartbeat.completed, heartbeat.total) == (7, 10)
    assert heartbeat.phase == "evidence"
    assert heartbeat.node_id == "assembling authenticity evidence"
    assert events[-1].kind is ProgressKind.PHASE_FINISHED
    assert (events[-1].completed, events[-1].total) == (7, 10)


def test_parallel_progress_emission_is_totally_ordered() -> None:
    events: list[ProgressEvent] = []
    emitter = ProgressEmitter(events.append, heartbeat_seconds=60)

    def emit(index: int) -> None:
        emitter.emit(
            ProgressKind.UNIT_FINISHED,
            "compile",
            f"completed unit {index}",
            completed=1,
            total=1,
            node_id=f"unit.{index}",
        )

    threads = [threading.Thread(target=emit, args=(index,)) for index in range(50)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=1)

    assert len(events) == 50
    assert [event.sequence for event in events] == list(range(1, 51))


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"phase": "Bad Phase"}, "phase"),
        ({"completed": 2, "total": 1}, "counts"),
        ({"completed": 1}, "together"),
    ],
)
def test_progress_events_reject_malformed_machine_contracts(
    kwargs: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "sequence": 1,
        "kind": ProgressKind.UNIT_FINISHED,
        "phase": "compile",
        "message": "completed unit",
        "elapsed_seconds": 0.0,
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=message):
        ProgressEvent(**values)  # type: ignore[arg-type]


def test_progress_elapsed_time_is_monotonic() -> None:
    events: list[ProgressEvent] = []
    emitter = ProgressEmitter(events.append, heartbeat_seconds=60)
    emitter.emit(ProgressKind.PHASE_STARTED, "prepare", "prepare")
    time.sleep(0.001)
    emitter.emit(ProgressKind.PHASE_FINISHED, "prepare", "prepare")
    assert events[1].elapsed_seconds >= events[0].elapsed_seconds


def test_phase_elapsed_is_relative_for_each_phase() -> None:
    events: list[ProgressEvent] = []
    now = [100.0]
    emitter = ProgressEmitter(
        events.append,
        heartbeat_seconds=60,
        clock=lambda: now[0],
    )

    with emitter.phase("prepare", "preparing"):
        now[0] = 103.0
    now[0] = 120.0
    with emitter.phase("execute", "executing"):
        now[0] = 124.5

    finished = [
        event for event in events if event.kind is ProgressKind.PHASE_FINISHED
    ]
    assert [event.elapsed_seconds for event in finished] == [3.0, 4.5]
