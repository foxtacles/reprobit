from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "reprobit_build_benchmark", Path(__file__).parents[1] / "scripts" / "benchmark_build.py"
)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = benchmark
SPEC.loader.exec_module(benchmark)


def _summary(**changes: object) -> str:
    return json.dumps(
        {
            "event": "incremental_build_summary",
            "hits": 10,
            "misses": 0,
            "runtime_init_count": 0,
            "published_targets": 0,
            "published_comparison_pairs": 0,
            **changes,
        }
    )


@pytest.mark.parametrize(
    "changed",
    ("misses", "runtime_init_count", "published_targets", "published_comparison_pairs"),
)
def test_benchmark_refuses_to_label_rebuilds_as_no_change(changed: str) -> None:
    sample = benchmark.read_measurement(_summary(**{changed: 1}), 0.1)
    with pytest.raises(ValueError, match="no-change build"):
        benchmark.require_unchanged(sample)


def test_benchmark_keeps_process_wall_time_and_requires_one_complete_summary() -> None:
    progress = json.dumps({"event": "workflow_progress"})
    sample = benchmark.read_measurement(progress + "\n" + _summary(), 1.5)
    benchmark.require_unchanged(sample)
    assert sample.wall_seconds == 1.5
    assert sample.hits == 10
    for invalid in (progress, _summary() + "\n" + _summary(), _summary(misses=True)):
        with pytest.raises(ValueError):
            benchmark.read_measurement(invalid, 1.5)
