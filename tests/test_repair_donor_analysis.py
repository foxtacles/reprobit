from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import reprobit.repair_donor_analysis as subject
from reprobit.classic.repair_probe import (
    ClassicDonorRetuneProbeResult,
    ClassicDonorRetuneRepair,
)
from reprobit.classic.repair_session import ClassicRepairRefusal
from reprobit.progress import ProgressKind


class _Output:
    def __init__(self) -> None:
        self.activities: list[tuple[str, str]] = []
        self.producer_descriptions: list[str] = []
        self.progress: list[tuple[object, ...]] = []

    @contextmanager
    def activity(self, description: str, *, phase: str):
        self.activities.append((description, phase))
        yield lambda _message: None

    @contextmanager
    def producer_activity(self, description: str):
        self.producer_descriptions.append(description)

        def progress(*values: object) -> None:
            self.progress.append(values)

        yield progress


class _Arena:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.entered = False
        self.exited = False

    def __enter__(self) -> _Arena:
        self.entered = True
        self.path.mkdir(parents=True)
        return self

    def __exit__(self, *_args: object) -> None:
        self.exited = True


class _Prepared:
    def __init__(
        self,
        effective_root: Path,
        overlay: dict[str, bytes],
        units: tuple[object, ...],
    ) -> None:
        self.producer = SimpleNamespace(is_open=True)
        self.probes = SimpleNamespace(effective_root=effective_root, units=units)
        self.donors = SimpleNamespace(overlay_effective_outputs=overlay)
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        self.producer.is_open = False


def _args(root: Path) -> argparse.Namespace:
    return argparse.Namespace(
        project=str(root),
        toolchain_root="/toolchain",
        backend="auto",
        wine=None,
        wineserver=None,
        compiler_transport="/transport/cl",
        resource_transport="/transport/rc",
        jobs=3,
        initialization_timeout=1.0,
        compile_timeout=2.0,
        link_timeout=3.0,
        cleanup_timeout=4.0,
    )


def _refusals() -> tuple[ClassicRepairRefusal, ...]:
    action = SimpleNamespace(id="function.fixture")
    receipt = SimpleNamespace(
        id="proof.function.fixture",
        intervention_id=action.id,
    )
    unit = SimpleNamespace(
        plan=SimpleNamespace(id="unit.fixture"),
        donors=(),
        functions=(action,),
        legacy_actions=(),
        actions=(action,),
        receipts=(receipt,),
        compiler_identity=None,
    )
    return (
        ClassicRepairRefusal(
            unit_id=unit.plan.id,
            action_index=0,
            intervention=cast(Any, action),
            receipt=cast(Any, receipt),
            materials=cast(Any, SimpleNamespace(seed_object=b"seed")),
            unit=cast(Any, unit),
            reason="saved donor no longer composes",
        ),
    )


def _wire_preparation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[_Prepared, _Arena, dict[str, Any], object]:
    root = tmp_path / "project"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "unit.cpp").write_bytes(b"clean source")
    effective_root = tmp_path / "effective"
    (effective_root / "src").mkdir(parents=True)
    (effective_root / "src" / "unit.cpp").write_bytes(b"effective source")

    spec = SimpleNamespace(
        toolchain=SimpleNamespace(profile="msvc-4.2"),
    )
    bundle = SimpleNamespace(
        spec=spec,
        source_manifest=SimpleNamespace(
            entries=(SimpleNamespace(path="src/unit.cpp"),),
        ),
    )
    prepared = _Prepared(
        effective_root,
        {"generated.cpp": b"generated overlay"},
        tuple(item.unit for item in _refusals()),
    )
    arena = _Arena(tmp_path / "state" / "run")
    execution = object()
    observed: dict[str, Any] = {}

    monkeypatch.setattr(subject, "project_root", lambda _project: root)
    monkeypatch.setattr(subject, "load_project_tree", lambda loaded: bundle)
    monkeypatch.setattr(subject, "canonical_overlay_operations", lambda loaded: {"x": ("op",)})
    monkeypatch.setattr(subject, "state_root", lambda loaded, loaded_spec: tmp_path / "state")

    def make_arena(
        state: Path,
        *,
        kind: str,
        keep: subject.KeepWorkspace,
    ) -> _Arena:
        observed["arena"] = (state, kind, keep)
        return arena

    monkeypatch.setattr(subject, "RunArena", make_arena)
    backend = object()
    monkeypatch.setattr(subject, "selected_backend", lambda args: backend)

    def resolve(**values: object) -> object:
        observed["resolve"] = values
        return execution

    monkeypatch.setattr(subject, "resolve_classic_execution_inputs", resolve)

    def prepare(*values: object, **keywords: object) -> _Prepared:
        observed["prepare_positional"] = values
        observed["prepare"] = keywords
        return prepared

    monkeypatch.setattr(subject, "prepare_producer_graph_run", prepare)
    observed.update(root=root, bundle=bundle, backend=backend)
    return prepared, arena, observed, execution


def test_probe_uses_one_ordinary_runtime_and_exposes_progress(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prepared, arena, observed, execution = _wire_preparation(monkeypatch, tmp_path)
    output = _Output()
    expected = ClassicDonorRetuneProbeResult((), (), 1)
    expected_refusals = _refusals()

    def probe(probes: object, refusals: object, **values: object):
        observed["probe"] = (probes, refusals, values)
        progress = values["progress"]
        assert callable(progress)
        progress(1, 9, "donor-1")
        prepared.producer.is_open = False
        return expected

    monkeypatch.setattr(subject, "probe_bounded_donor_retunes", probe)

    args = _args(cast(Path, observed["root"]))
    actual = subject.probe_classic_donor_repairs(
        args,
        cast(Any, output),
        expected_refusals,
        candidate_budget=17,
    )

    assert actual is expected
    assert observed["arena"] == (
        tmp_path / "state",
        "repair-probe",
        subject.KeepWorkspace.NEVER,
    )
    assert observed["resolve"] == {
        "profile": "msvc-4.2",
        "explicit_toolchain_root": "/toolchain",
        "backend": observed["backend"],
        "compiler_transport": "/transport/cl",
        "resource_transport": "/transport/rc",
    }
    assert observed["prepare_positional"] == (args, observed["bundle"])
    prepare = observed["prepare"]
    assert prepare["project_root"] == observed["root"]
    assert prepare["session_root"] == arena.path / "classic"
    assert prepare["execution"] is execution
    assert callable(prepare["progress"])
    probes, refusals, probe_values = observed["probe"]
    assert probes is prepared.probes
    assert refusals == expected_refusals
    assert refusals[0].unit is prepared.probes.units[0]
    assert probe_values["clean_sources"] == {"src/unit.cpp": b"clean source"}
    assert probe_values["effective_sources"] == {
        "src/unit.cpp": b"effective source",
        "generated.cpp": b"generated overlay",
    }
    assert probe_values["canonical_overlay_operations"] == {"x": ("op",)}
    assert probe_values["candidate_budget"] == 17
    assert output.activities == [("preparing a safe donor search", "repair-probe-prepare")]
    assert output.producer_descriptions == [
        "trying nearby donor settings (the shown total is an upper bound)"
    ]
    assert output.progress == [(1, 9, "repair-probe", "donor-1", ProgressKind.UNIT_FINISHED, None)]
    assert prepared.close_calls == 0
    assert arena.entered and arena.exited


def test_probe_rejects_stale_prepared_unit_authority_and_closes_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prepared, _arena, observed, _execution = _wire_preparation(monkeypatch, tmp_path)
    refusal = _refusals()[0]
    stale_unit = SimpleNamespace(**vars(refusal.unit))
    stale_unit.plan = SimpleNamespace(id=refusal.unit_id, source="src/other.cpp")
    stale = replace(refusal, unit=cast(Any, stale_unit))
    monkeypatch.setattr(
        subject,
        "probe_bounded_donor_retunes",
        lambda *_args, **_kwargs: pytest.fail("stale authority must not reach the probe"),
    )

    with pytest.raises(subject.ClassicProjectError, match="no longer matches"):
        subject.probe_classic_donor_repairs(
            _args(cast(Path, observed["root"])),
            cast(Any, _Output()),
            (stale,),
        )

    assert prepared.close_calls == 1


def test_probe_rejects_refusal_that_names_the_wrong_fresh_action(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prepared, _arena, observed, _execution = _wire_preparation(monkeypatch, tmp_path)
    refusal = _refusals()[0]
    wrong_action = SimpleNamespace(id="function.other")
    inconsistent = replace(refusal, intervention=cast(Any, wrong_action))
    monkeypatch.setattr(
        subject,
        "probe_bounded_donor_retunes",
        lambda *_args, **_kwargs: pytest.fail("inconsistent refusal must not reach the probe"),
    )

    with pytest.raises(subject.ClassicProjectError, match="freshly prepared action"):
        subject.probe_classic_donor_repairs(
            _args(cast(Path, observed["root"])),
            cast(Any, _Output()),
            (inconsistent,),
        )

    assert prepared.close_calls == 1


def test_probe_closes_any_runtime_the_probe_leaves_open(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prepared, _arena, observed, _execution = _wire_preparation(monkeypatch, tmp_path)
    monkeypatch.setattr(
        subject,
        "probe_bounded_donor_retunes",
        lambda *_args, **_kwargs: ClassicDonorRetuneProbeResult((), (), 0),
    )

    subject.probe_classic_donor_repairs(
        _args(cast(Path, observed["root"])),
        cast(Any, _Output()),
        _refusals(),
    )

    assert prepared.close_calls == 1


@pytest.mark.parametrize("probe_closed", [False, True])
def test_probe_failure_closes_only_an_open_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    probe_closed: bool,
) -> None:
    prepared, _arena, observed, _execution = _wire_preparation(monkeypatch, tmp_path)

    def fail(*_args: object, **_kwargs: object) -> None:
        prepared.producer.is_open = not probe_closed
        raise RuntimeError("candidate compiler failed")

    monkeypatch.setattr(subject, "probe_bounded_donor_retunes", fail)

    with pytest.raises(RuntimeError, match="candidate compiler failed"):
        subject.probe_classic_donor_repairs(
            _args(cast(Path, observed["root"])),
            cast(Any, _Output()),
            _refusals(),
        )

    assert prepared.close_calls == (0 if probe_closed else 1)


def test_source_loading_failure_closes_the_prepared_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    prepared, _arena, observed, _execution = _wire_preparation(monkeypatch, tmp_path)
    (prepared.probes.effective_root / "src" / "unit.cpp").unlink()
    monkeypatch.setattr(
        subject,
        "probe_bounded_donor_retunes",
        lambda *_args, **_kwargs: pytest.fail("probe must not run without source bytes"),
    )

    with pytest.raises(FileNotFoundError):
        subject.probe_classic_donor_repairs(
            _args(cast(Path, observed["root"])),
            cast(Any, _Output()),
            _refusals(),
        )

    assert prepared.close_calls == 1


def test_empty_probe_skips_project_and_runtime_work(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        subject,
        "project_root",
        lambda _project: pytest.fail("empty probe must not load the project"),
    )

    result = subject.probe_classic_donor_repairs(
        _args(tmp_path),
        cast(Any, _Output()),
        (),
    )

    assert result == ClassicDonorRetuneProbeResult((), (), 0)


def test_apply_flattens_all_typed_edits_into_one_transaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: dict[str, object] = {}
    repairs = cast(
        tuple[ClassicDonorRetuneRepair, ...],
        (
            SimpleNamespace(intervention_edits=("i1",), receipt_edits=("r1", "r2")),
            SimpleNamespace(intervention_edits=("i2",), receipt_edits=("r3",)),
        ),
    )
    spec = cast(Any, object())

    def apply(root: Path, actual_spec: object, **values: object) -> tuple[str, ...]:
        observed.update(root=root, spec=actual_spec, **values)
        return ("reprobit/interventions/unit.json", "reprobit/proofs/unit.json")

    monkeypatch.setattr(subject, "apply_classic_authority_edits", apply)

    changed = subject.apply_classic_donor_repairs(tmp_path, spec, repairs)

    assert changed == (
        "reprobit/interventions/unit.json",
        "reprobit/proofs/unit.json",
    )
    assert observed == {
        "root": tmp_path,
        "spec": spec,
        "interventions": ("i1", "i2"),
        "receipts": ("r1", "r2", "r3"),
    }


def test_apply_skips_an_empty_transaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        subject,
        "apply_classic_authority_edits",
        lambda *_args, **_kwargs: pytest.fail("empty repair must not start a transaction"),
    )

    assert subject.apply_classic_donor_repairs(tmp_path, cast(Any, object()), ()) == ()
