"""Cold developer dependency guards share warm edit rules without using the cache."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from test_incremental import _bundle

import reprobit.classic_runtime as runtime
from reprobit.classic_includes import (
    IncludeOrigin,
    MsvcSbrSource,
    MsvcSbrTrace,
    SealedIncludeAuthority,
    SealedIncludeFile,
)
from reprobit.classic_runtime_dependencies import ClassicCompilerDependencyReplay
from reprobit.developer_authority import IncrementalAuthorityError, current_worktree_authority
from reprobit.process import CancellationToken, ProcessSupervisor
from reprobit.producer_graph import ProducerRole


@pytest.mark.parametrize(
    ("changed", "trace_available", "error"),
    (
        ("include/common.h", True, "invalidate reviewed intervention"),
        ("notes.txt", True, None),
        ("notes.txt", False, "cannot revalidate recursive inputs"),
    ),
)
def test_cold_developer_resolves_current_recursive_inputs_before_accepting_protected_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changed: str,
    trace_available: bool,
    error: str | None,
) -> None:
    committed = _bundle(tmp_path, protected=True)
    assert committed.producer_graph is not None
    compiler, linker = committed.producer_graph.nodes
    compiler = compiler.model_copy(
        update={
            "arguments": (
                "/nologo",
                "/Zi",
                "/I${SOURCE}/include",
                "/Fo${BUILD}/unit.obj",
                "/Fd${BUILD}/unit.pdb",
                "-c",
                "${SOURCE}/src/unit.cpp",
            ),
        }
    )
    committed = committed.model_copy(
        update={
            "producer_graph": committed.producer_graph.model_copy(
                update={"nodes": (compiler, linker)}
            )
        }
    )
    (tmp_path / changed).write_bytes(b"changed\n")
    authority = current_worktree_authority(committed, tmp_path)
    assert authority.bundle.source_manifest is not None
    include_authority = SealedIncludeAuthority(
        logical_roots=(r"R:\source",),
        files=tuple(
            SealedIncludeFile(
                "R:\\source\\" + entry.path.replace("/", "\\"),
                entry.digest,
                entry.size,
                IncludeOrigin.PROJECT_SOURCE,
            )
            for entry in authority.bundle.source_manifest.entries
        ),
    )
    trace = MsvcSbrTrace(
        r"R:\build",
        (
            MsvcSbrSource(r"R:\source\src\unit.cpp", None),
            MsvcSbrSource(r"R:\source\include\common.h", 0),
        ),
    )
    replays: list[str] = []

    def replay(
        _producer: object, _supervisor: object, node: object, **_kwargs: object
    ) -> ClassicCompilerDependencyReplay:
        assert node == compiler
        replays.append(compiler.id)
        return ClassicCompilerDependencyReplay(
            trace if trace_available else None,
            None if trace_available else "fixture trace unavailable",
        )

    monkeypatch.setattr(runtime, "replay_compiler_dependencies", replay)
    executor = object.__new__(runtime.ClassicProducerGraphBuildExecutor)
    executor.developer_authority = authority
    executor.bundle = authority.bundle
    executor.graph = authority.bundle.producer_graph
    executor.role_tool_ids = {ProducerRole.COMPILER: "compiler"}
    executor.producer = SimpleNamespace(
        lane_pool=SimpleNamespace(
            acquire=lambda: SimpleNamespace(environment={"INCLUDE": ""}),
            release=lambda _lane: None,
        )
    )

    def check() -> None:
        executor._check_developer_recursive_inputs(
            cast(ProcessSupervisor, object()), (compiler,), include_authority, CancellationToken()
        )

    if error is None:
        check()
    else:
        with pytest.raises(IncrementalAuthorityError, match=error):
            check()
    assert replays == [compiler.id]
    assert not (tmp_path / ".state").exists()


def test_certification_never_replays_developer_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected(*_args: object, **_kwargs: object) -> None:
        pytest.fail("certification must not use developer dependency hints")

    monkeypatch.setattr(runtime, "replay_compiler_dependencies", unexpected)
    executor = object.__new__(runtime.ClassicProducerGraphBuildExecutor)
    executor.developer_authority = None
    executor._check_developer_recursive_inputs(
        cast(ProcessSupervisor, object()), (), SealedIncludeAuthority((), ()), CancellationToken()
    )
