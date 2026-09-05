"""Cold map side outputs preserve exact link controls and closed output paths."""

from __future__ import annotations

from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from typing import Any

import pytest

from reprobit import classic_runtime_producer as subject
from reprobit.classic_project import ClassicProjectError
from reprobit.model import Digest
from reprobit.process import CancellationToken
from reprobit.producer_graph import ProducerGraphDocument, ProducerNode, ProducerRole


def _producer(root: Path) -> tuple[subject.ClassicProducerExecution, ProducerNode]:
    producer = object.__new__(subject.ClassicProducerExecution)
    producer._mode = "certifying"
    producer._logical_drive_root = root.resolve()
    producer._logical_drive_letter = "C"
    producer.build_root = root / "build"
    producer.effective_root = root / "source"
    producer.toolchain_root = root / "toolchain"
    producer.build_root.mkdir()
    producer.bundle = SimpleNamespace(
        spec=SimpleNamespace(
            paths=SimpleNamespace(build=r"C:\build", source=r"C:\source", toolchain=r"C:\toolchain")
        )
    )
    node = ProducerNode(
        id="linker.program",
        owner="program",
        target_id="program",
        role=ProducerRole.LINKER,
        inputs=(),
        outputs=("build/PROGRAM.EXE",),
        arguments=("/OUT:${BUILD}/PROGRAM.EXE", "/OPT:REF", "/INCREMENTAL:NO"),
    )
    producer.graph = ProducerGraphDocument(
        schema_version=3,
        toolchain_lock_digest=Digest(value="0" * 64),
        path_profile_id="profile",
        extractor="cmake-makefiles-v1",
        nodes=(node,),
    )
    producer._output_lock = Lock()
    producer._physical_outputs = {}
    producer._linker_map_paths = {}
    producer._linker_maps = {}
    return producer, node


def test_private_map_adds_only_one_diagnostic_option_and_developer_link_stays_unchanged(
    tmp_path: Path,
) -> None:
    producer, node = _producer(tmp_path)
    original = producer.node_arguments(node)
    command, path = producer._linker_map_command(node, original)
    assert command[:-1] == original
    assert command[-1].startswith("/MAP:C:\\build\\.reprobit-link-maps\\")
    assert path is not None and path.parent == producer.build_root / ".reprobit-link-maps"
    assert len(path.stem) == 20
    producer._mode = "developer"
    assert producer._linker_map_command(node, original) == (original, None)


@pytest.mark.parametrize(
    "control, relative",
    [
        ("/MAP:C:\\build\\reports\\original.map", "reports/original.map"),
        ("/MAP:original.map", "original.map"),
        ("/MAP", "PROGRAM.map"),
    ],
)
def test_existing_map_control_is_preserved(tmp_path: Path, control: str, relative: str) -> None:
    producer, node = _producer(tmp_path)
    original = (*producer.node_arguments(node), control)
    command, path = producer._linker_map_command(node, original)
    assert command == original
    assert path == producer.build_root / relative


@pytest.mark.parametrize(
    "controls, reason",
    [
        (("/MAP", "/MAP:other.map"), "repeats"),
        (("/MAP:",), "empty map"),
        (("/MAP:C:\\source\\source.cpp",), "escapes"),
        (("/MAP:C:\\build\\PROGRAM.EXE",), "aliases"),
        (("/MAP:C:\\build\\program.exe",), "aliases"),
    ],
)
def test_map_control_rejects_overwrites_and_escaping_paths(
    tmp_path: Path, controls: tuple[str, ...], reason: str
) -> None:
    producer, node = _producer(tmp_path)
    with pytest.raises(ClassicProjectError, match=reason):
        producer._linker_map_command(node, (*producer.node_arguments(node), *controls))


def test_map_capture_is_from_the_actual_cold_link_and_is_a_declared_phase_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    producer, node = _producer(tmp_path)
    producer.role_commands = {ProducerRole.LINKER: tmp_path / "LINK.EXE"}
    producer.compile_timeout = producer.link_timeout = 10
    producer.session_root = tmp_path / "session"
    lane = SimpleNamespace(environment={}, windows_lineage_planner=None)
    producer._lane_pool = SimpleNamespace(acquire=lambda: lane, release=lambda _lane: None)
    payload = b"live map from this exact invocation"
    commands: list[tuple[str, ...]] = []

    def run(_supervisor: Any, command: tuple[str, ...], **_kwargs: Any) -> tuple[Any, Any]:
        commands.append(command)
        (producer.build_root / "PROGRAM.EXE").write_bytes(b"exact image")
        map_arg = next(arg for arg in command if arg.startswith("/MAP:"))
        map_path = producer._logical_drive_root.joinpath(
            *map_arg.split(":", 2)[2].strip("\\").split("\\")
        )
        map_path.write_bytes(payload)
        return object(), object()

    monkeypatch.setattr(subject, "_run", run)
    monkeypatch.setattr(subject, "_step_receipt", lambda *_args: "receipt")
    result = producer.run_node(object(), node, CancellationToken())
    assert result == ("receipt",)
    assert commands[0][1:-1] == producer.node_arguments(node)
    assert producer.linker_maps == {node.id: payload}
    # Final publication and warm restoration require exactly one physical
    # product per authenticated graph output; diagnostics belong only to writes.
    assert producer.node_outputs(node) == (producer.build_root / "PROGRAM.EXE",)
    assert len(producer.node_outputs(node)) == len(node.outputs)
    assert len(producer.node_write_outputs(node)) == 2
    # Subsequent mutation of the diagnostic file cannot replace the captured evidence.
    map_path = next(path for path in producer.node_write_outputs(node) if path.suffix == ".map")
    map_path.write_bytes(b"replacement")
    assert producer.linker_maps[node.id] == payload
