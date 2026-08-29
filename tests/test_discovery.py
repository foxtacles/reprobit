from __future__ import annotations

import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from reprobit.discovery import (
    DiscoveryCampaignRunner,
    require_discovery_directory,
)
from reprobit.discovery_contracts import (
    CellObservation,
    CompileReceipt,
    DeclarationFamily,
    DeclarationPlacement,
    DeclarationShapeSearch,
    DeclarationState,
    DiscoveryArtifactPayload,
    DiscoveryCompileOutput,
    DiscoveryCompilerReceipt,
    DiscoveryError,
    DiscoveryPlan,
    DiscoveryProduct,
    DiscoveryProposal,
    ExternRunPairSearch,
    ForwardDeclarationSearch,
    FunctionObservation,
    InclusiveRange,
    PadShapeSearch,
    declaration_state_id,
    enumerate_declaration_states,
)
from reprobit.model import Digest
from reprobit.process import CancellationToken
from reprobit.progress import ProgressEvent, ProgressKind
from reprobit.strict_json import JsonValue, canonical_json


def _range(start: int, stop: int) -> InclusiveRange:
    return InclusiveRange(start=start, stop=stop)


def _forward_plan(stop: int, *, max_cells: int | None = None) -> DiscoveryPlan:
    return DiscoveryPlan(
        target="neutral",
        translation_unit="widget",
        searches=(
            ForwardDeclarationSearch(
                family=DeclarationFamily.FORWARD_DECLARATION_RUN,
                prefix="Carrier",
                counts=_range(1, stop),
                width=1,
                placements=(DeclarationPlacement.PREFIX,),
            ),
        ),
        max_cells=stop if max_cells is None else max_cells,
    )


class _FakeAdapter:
    identity = "fake-msvc"

    def __init__(
        self,
        *,
        maximum_parallelism: int = 4,
        fail: bool = False,
        fail_once_on_call: int | None = None,
        analysis_salt: bytes = b"fake-analysis-v1",
        analysis_implementation_salt: bytes = b"fake-analysis-implementation-v1",
        functions_per_cell: int = 0,
    ) -> None:
        self._maximum_parallelism = maximum_parallelism
        self.fail = fail
        self.fail_once_on_call = fail_once_on_call
        self.analysis_salt = analysis_salt
        self.analysis_implementation_salt = analysis_implementation_salt
        self.functions_per_cell = functions_per_cell
        self.compile_calls = 0
        self.observe_calls = 0
        self.authority_calls = 0
        self.compile_workspaces: list[Path] = []
        self.active = 0
        self.maximum_active = 0
        self._lock = threading.Lock()

    @property
    def maximum_parallelism(self) -> int:
        return self._maximum_parallelism

    def compile_implementation_digest(self) -> Digest:
        return Digest.from_bytes(b"fake-compile-implementation-v1")

    def analysis_implementation_digest(self) -> Digest:
        return Digest.from_bytes(self.analysis_implementation_salt)

    def compiler_receipt(self) -> DiscoveryCompilerReceipt:
        return DiscoveryCompilerReceipt(
            identity=self.identity,
            executable="/neutral/fake-compiler",
            arguments=("/nologo",),
            toolchain_authority=Digest.from_bytes(b"fake toolchain"),
        )

    def compile_authority_digest(self) -> Digest:
        self.authority_calls += 1
        return Digest.from_bytes(b"fake-authority-v1")

    def revalidate_compile_authority(self, expected: Digest) -> None:
        if self.compile_authority_digest() != expected:
            raise RuntimeError("fake compile authority changed")

    def analysis_authority_digest(self, compile_authority: Digest) -> Digest:
        return Digest.from_bytes(
            canonical_json(
                {
                    "compile_authority": compile_authority,
                    "analysis_salt": self.analysis_salt.hex(),
                }
            )
        )

    def cache_material(self, state: DeclarationState) -> Mapping[str, JsonValue]:
        return {"state_id": declaration_state_id(state)}

    def compile(
        self,
        state: DeclarationState,
        workspace: Path,
        cancellation: CancellationToken,
    ) -> DiscoveryCompileOutput:
        cancellation.raise_if_cancelled()
        with self._lock:
            self.compile_calls += 1
            self.compile_workspaces.append(workspace)
            call = self.compile_calls
            self.active += 1
            self.maximum_active = max(self.maximum_active, self.active)
        try:
            if self.fail or call == self.fail_once_on_call:
                raise RuntimeError("compiler unavailable")
            # Keep workers overlapped and make every state converge on the same
            # immutable blob while retaining distinct per-state records.
            time.sleep(0.01)
            output = workspace / "candidate.obj"
            output.write_bytes(b"neutral fake object")
            return DiscoveryCompileOutput(
                object_path=output,
                receipt=CompileReceipt(
                    compiler_context=Digest.from_bytes(b"fake compiler"),
                    command=Digest.from_bytes(canonical_json(state)),
                    working_directory=str(workspace.resolve(strict=True)),
                ),
                metadata=MappingProxyType({"fake": True}),
            )
        finally:
            with self._lock:
                self.active -= 1

    def observe(
        self,
        *,
        cell_id: str,
        state: DeclarationState,
        object_path: Path,
        receipt: CompileReceipt,
    ) -> CellObservation:
        self.observe_calls += 1
        return CellObservation(
            cell_id=cell_id,
            state_id=declaration_state_id(state),
            state=state,
            object=Digest.from_path(object_path),
            compile=receipt,
            functions=tuple(
                FunctionObservation(
                    symbol=f"?Function{index}@@YAHXZ",
                    section_number=index + 1,
                    section_offset=0,
                    body_size=1,
                    body=Digest.from_bytes(bytes((index % 256,))),
                    relocation_count=0,
                    relocations=Digest.from_bytes(b"relocations"),
                    line_count=0,
                    metadata=Digest.from_bytes(b"metadata"),
                    comdat_selection=2,
                )
                for index in range(self.functions_per_cell)
            ),
        )

    def analyze(
        self,
        *,
        campaign_id: str,
        plan: DiscoveryPlan,
        products: Sequence[DiscoveryProduct],
    ) -> tuple[DiscoveryProposal, ...]:
        del campaign_id, plan, products
        return ()

    def proposal_artifacts(
        self,
        *,
        campaign_id: str,
        proposals: Sequence[DiscoveryProposal],
        products: Sequence[DiscoveryProduct],
    ) -> tuple[DiscoveryArtifactPayload, ...]:
        del campaign_id, proposals, products
        return ()


class _InterruptingAdapter(_FakeAdapter):
    def __init__(self) -> None:
        super().__init__(maximum_parallelism=2)
        self.barrier = threading.Barrier(2)
        self.sibling_cancelled = threading.Event()

    def compile(
        self,
        state: DeclarationState,
        workspace: Path,
        cancellation: CancellationToken,
    ) -> DiscoveryCompileOutput:
        del state, workspace
        with self._lock:
            self.compile_calls += 1
            call = self.compile_calls
        self.barrier.wait(timeout=2)
        if call == 1:
            raise KeyboardInterrupt
        try:
            while True:
                cancellation.raise_if_cancelled()
                time.sleep(0.01)
        finally:
            self.sibling_cancelled.set()


def test_four_declaration_families_expand_deterministically() -> None:
    plan = DiscoveryPlan(
        target="neutral",
        translation_unit="widget",
        searches=(
            DeclarationShapeSearch(
                family=DeclarationFamily.DECLARATION_SHAPE,
                classes=_range(1, 2),
                functions=_range(1, 3),
            ),
            PadShapeSearch(
                family=DeclarationFamily.PAD_SHAPE,
                classes=_range(1, 1),
                functions_per_class=_range(1, 2),
            ),
            ForwardDeclarationSearch(
                family=DeclarationFamily.FORWARD_DECLARATION_RUN,
                prefix="Carrier",
                counts=_range(1, 2),
                width=1,
                placements=(
                    DeclarationPlacement.AFTER_INCLUDES,
                    DeclarationPlacement.FORCE_INCLUDE,
                ),
            ),
            ExternRunPairSearch(
                family=DeclarationFamily.EXTERN_RUN_PAIR,
                header_prefix="gHeader_",
                seat_prefix="gSeat_",
                header_counts=_range(0, 1),
                seat_counts=_range(0, 1),
                width=1,
            ),
        ),
        max_cells=20,
    )

    first = enumerate_declaration_states(plan)
    second = enumerate_declaration_states(plan)

    assert first == second
    assert tuple(canonical_json(item) for item in first) == tuple(
        sorted(canonical_json(item) for item in first)
    )
    assert {item.family for item in first} == set(DeclarationFamily)
    assert len({declaration_state_id(item) for item in first}) == len(first)


def test_campaign_budget_and_generator_domains_fail_before_compilation() -> None:
    with pytest.raises(ValidationError, match="classes must stay"):
        DeclarationShapeSearch(
            family=DeclarationFamily.DECLARATION_SHAPE,
            classes=_range(1, 11),
            functions=_range(1, 2),
        )

    with pytest.raises(DiscoveryError, match="above max_cells"):
        enumerate_declaration_states(_forward_plan(3, max_cells=2))


def test_duplicate_search_state_is_rejected() -> None:
    search = ForwardDeclarationSearch(
        family=DeclarationFamily.FORWARD_DECLARATION_RUN,
        prefix="Carrier",
        counts=_range(1, 1),
        width=1,
        placements=(DeclarationPlacement.PREFIX,),
    )
    plan = DiscoveryPlan(
        target="neutral",
        translation_unit="widget",
        searches=(search, search),
        max_cells=2,
    )
    with pytest.raises(DiscoveryError, match="duplicate state"):
        enumerate_declaration_states(plan)


def test_cold_resume_and_one_cell_extension_are_incremental(tmp_path: Path) -> None:
    events: list[ProgressEvent] = []
    adapter = _FakeAdapter(maximum_parallelism=3)
    runner = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=adapter,
        jobs=8,
        progress=events.append,
    )

    cold = runner.run(_forward_plan(6))
    resumed = runner.run(_forward_plan(6))
    extended = runner.run(_forward_plan(7))

    assert (cold.cells_built, cold.cells_cached) == (6, 0)
    assert (resumed.cells_built, resumed.cells_cached) == (0, 6)
    assert (extended.cells_built, extended.cells_cached) == (1, 6)
    assert adapter.compile_calls == 7
    assert adapter.observe_calls == 7
    assert adapter.authority_calls == 6
    assert 2 <= adapter.maximum_active <= 3
    assert cold.observations == resumed.observations
    assert cold.compile_implementation_digest == resumed.compile_implementation_digest
    assert cold.analysis_implementation_digest == resumed.analysis_implementation_digest
    completion_events = [
        event
        for event in events
        if event.phase == "discovery-compile"
        and event.kind in {ProgressKind.CACHE_HIT, ProgressKind.CACHE_MISS}
    ]
    assert len(completion_events) == 19
    assert not any(
        event.phase == "discovery-compile" and event.kind is ProgressKind.UNIT_FINISHED
        for event in events
    )
    forwarded_phases = {
        event.phase
        for event in events
        if event.kind is ProgressKind.UNIT_FINISHED
    }
    assert forwarded_phases >= {
        "discovery-enumerate",
        "discovery-analyze",
        "discovery-finalize",
    }
    final = [
        event
        for event in events
        if event.phase == "discovery-finalize"
        and event.kind is ProgressKind.UNIT_FINISHED
    ][-1]
    assert final.completed == final.total
    assert all(
        event.completed is not None
        and event.total is not None
        and event.completed < event.total
        for event in events
        if event.phase == "discovery-compile"
        and event.kind in {ProgressKind.CACHE_HIT, ProgressKind.CACHE_MISS}
    )


def test_cached_cell_reuses_authenticated_restore_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = _FakeAdapter(maximum_parallelism=1)
    runner = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=adapter,
        jobs=1,
    )
    plan = _forward_plan(1)
    runner.run(plan)

    def unexpected_path_digest(
        cls: type[Digest],
        path: str | Path,
        *,
        chunk_size: int = 1024 * 1024,
    ) -> Digest:
        del cls, path, chunk_size
        raise AssertionError("cached object was hashed again after authenticated restore")

    monkeypatch.setattr(Digest, "from_path", classmethod(unexpected_path_digest))

    resumed = runner.run(plan)

    assert (resumed.cells_built, resumed.cells_cached) == (0, 1)
    assert adapter.compile_calls == 1
    assert adapter.observe_calls == 1


def test_first_failure_stops_replenishing_bounded_window(tmp_path: Path) -> None:
    adapter = _FakeAdapter(maximum_parallelism=2, fail=True)
    runner = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=adapter,
        jobs=2,
    )

    with pytest.raises(DiscoveryError, match="compiler unavailable"):
        runner.run(_forward_plan(9))

    assert 1 <= adapter.compile_calls <= 4
    assert any((tmp_path / "work").iterdir())


def test_interrupt_cancels_active_sibling_without_waiting_for_cell_timeouts(
    tmp_path: Path,
) -> None:
    adapter = _InterruptingAdapter()
    runner = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=adapter,
        jobs=2,
    )
    started = time.monotonic()

    with pytest.raises(KeyboardInterrupt):
        runner.run(_forward_plan(2))

    assert time.monotonic() - started < 2
    assert adapter.sibling_cancelled.wait(timeout=0.1)


def test_partial_failure_resumes_completed_immutable_cells(tmp_path: Path) -> None:
    adapter = _FakeAdapter(maximum_parallelism=1, fail_once_on_call=2)
    runner = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=adapter,
        jobs=1,
    )
    plan = _forward_plan(2)

    with pytest.raises(DiscoveryError, match="compiler unavailable"):
        runner.run(plan)
    resumed = runner.run(plan)

    assert adapter.compile_calls == 3
    assert (resumed.cells_built, resumed.cells_cached) == (1, 1)
    assert adapter.compile_workspaces[1] == adapter.compile_workspaces[2]


def test_campaign_observed_function_limit_fails_closed(tmp_path: Path) -> None:
    adapter = _FakeAdapter(functions_per_cell=1)
    plan = DiscoveryPlan.model_validate(
        {
            **_forward_plan(2).model_dump(mode="python"),
            "max_observed_functions": 1,
        }
    )

    with pytest.raises(DiscoveryError, match="max_observed_functions 1"):
        DiscoveryCampaignRunner(
            state_root=tmp_path / "state",
            workspace_root=tmp_path / "work",
            adapter=adapter,
            jobs=1,
        ).run(plan)

    assert adapter.compile_calls == 2


def test_analysis_authority_changes_reuse_compiled_cells(tmp_path: Path) -> None:
    first_adapter = _FakeAdapter(analysis_salt=b"first")
    first = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=first_adapter,
        jobs=2,
    ).run(_forward_plan(3))
    second_adapter = _FakeAdapter(analysis_salt=b"second")
    second = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=second_adapter,
        jobs=2,
    ).run(_forward_plan(3))

    assert (first.cells_built, first.cells_cached) == (3, 0)
    assert (second.cells_built, second.cells_cached) == (0, 3)
    assert second_adapter.compile_calls == 0
    assert second_adapter.observe_calls == 0
    assert first.compile_authority_digest == second.compile_authority_digest
    assert first.analysis_authority_digest != second.analysis_authority_digest
    assert first.campaign_id != second.campaign_id


def test_analysis_implementation_change_reuses_raw_compiler_objects(
    tmp_path: Path,
) -> None:
    first_adapter = _FakeAdapter(analysis_implementation_salt=b"analysis-v1")
    first = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=first_adapter,
        jobs=2,
    ).run(_forward_plan(3))
    second_adapter = _FakeAdapter(analysis_implementation_salt=b"analysis-v2")
    second = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=second_adapter,
        jobs=2,
    ).run(_forward_plan(3))

    assert (first.cells_built, first.cells_cached) == (3, 0)
    assert (second.cells_built, second.cells_cached) == (0, 3)
    assert second_adapter.compile_calls == 0
    assert second_adapter.observe_calls == 3
    assert first.compile_implementation_digest == second.compile_implementation_digest
    assert first.analysis_implementation_digest != second.analysis_implementation_digest


def _directory_symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"directory symlinks are unavailable: {exc}")


def test_state_directory_walk_rejects_redirected_runtime_component(
    tmp_path: Path,
) -> None:
    state = require_discovery_directory(
        tmp_path / "state",
        label="test discovery state",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    _directory_symlink(state / "runtime", outside)

    with pytest.raises(DiscoveryError, match="redirected/non-directory"):
        require_discovery_directory(
            state / "runtime" / "tmp",
            label="test discovery runtime",
        )

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_runner_rejects_redirected_cells_root_without_deleting_target(
    tmp_path: Path,
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    _directory_symlink(work / "cells", outside)

    with pytest.raises(DiscoveryError, match="redirected/non-directory"):
        DiscoveryCampaignRunner(
            state_root=tmp_path / "state",
            workspace_root=work,
            adapter=_FakeAdapter(),
            jobs=1,
        ).run(_forward_plan(1))

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_runner_rejects_redirected_workspace_root_without_deleting_target(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    workspace = tmp_path / "runs"
    _directory_symlink(workspace, outside)

    with pytest.raises(DiscoveryError, match="redirected/non-directory"):
        DiscoveryCampaignRunner(
            state_root=tmp_path / "state",
            workspace_root=workspace,
            adapter=_FakeAdapter(),
            jobs=1,
        ).run(_forward_plan(1))

    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_runner_never_recursively_cleans_redirected_cell(
    tmp_path: Path,
) -> None:
    adapter = _FakeAdapter(maximum_parallelism=1, fail=True)
    runner = DiscoveryCampaignRunner(
        state_root=tmp_path / "state",
        workspace_root=tmp_path / "work",
        adapter=adapter,
        jobs=1,
    )
    with pytest.raises(DiscoveryError, match="compiler unavailable"):
        runner.run(_forward_plan(1))
    cell = adapter.compile_workspaces[0]
    cell.rmdir()
    outside = tmp_path / "outside-cell"
    outside.mkdir()
    sentinel = outside / "keep.txt"
    sentinel.write_text("keep", encoding="utf-8")
    _directory_symlink(cell, outside)
    adapter.fail = False

    with pytest.raises(DiscoveryError, match="redirected/non-directory"):
        runner.run(_forward_plan(1))

    assert sentinel.read_text(encoding="utf-8") == "keep"
