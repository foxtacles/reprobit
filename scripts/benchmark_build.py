"""Measure fresh-process, no-change builds after an explicit cache-priming build.

Run against a disposable project checkout: this invokes normal developer builds
and therefore writes project state and outputs. No timing limit is imposed unless
--max-warm-seconds is supplied for a controlled benchmark host.
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Measurement:
    wall_seconds: float
    hits: int
    misses: int
    runtime_init_count: int
    published_targets: int
    published_comparison_pairs: int


def read_measurement(stdout: str, elapsed: float) -> Measurement:
    summaries: list[dict[str, object]] = []
    for line in stdout.splitlines():
        event = json.loads(line)
        if isinstance(event, dict) and event.get("event") == "incremental_build_summary":
            summaries.append(event)
    if len(summaries) != 1:
        raise ValueError("build must emit exactly one incremental summary")
    fields = (
        "hits",
        "misses",
        "runtime_init_count",
        "published_targets",
        "published_comparison_pairs",
    )
    values: list[int] = []
    for name in fields:
        value = summaries[0].get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"build summary has an invalid {name}")
        values.append(value)
    if sum(values[:2]) == 0:
        raise ValueError("build summary contains no cacheable work")
    return Measurement(elapsed, *values)


def require_unchanged(measurement: Measurement) -> None:
    if any(
        (
            measurement.misses,
            measurement.runtime_init_count,
            measurement.published_targets,
            measurement.published_comparison_pairs,
        )
    ):
        raise ValueError("no-change build rebuilt work, started a compiler, or changed outputs")


def measure(command: Sequence[str]) -> Measurement:
    started = time.perf_counter()
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    elapsed = time.perf_counter() - started
    if completed.returncode:
        raise ValueError(
            f"build failed with exit {completed.returncode}\n{completed.stdout}\n{completed.stderr}"
        )
    return read_measurement(completed.stdout, elapsed)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    parser.add_argument(
        "--runs", type=int, default=3, help="measured builds after priming (default: 3)"
    )
    parser.add_argument("--jobs", type=int, help="worker count passed to every build")
    parser.add_argument("--max-warm-seconds", type=float, help="optional median wall-time limit")
    args = parser.parse_args(argv)
    if args.runs < 1 or (args.jobs is not None and args.jobs < 1):
        parser.error("--runs and --jobs must be positive")
    if args.max_warm_seconds is not None and (
        not math.isfinite(args.max_warm_seconds) or args.max_warm_seconds <= 0
    ):
        parser.error("--max-warm-seconds must be finite and positive")
    command = [
        sys.executable,
        "-m",
        "reprobit.cli",
        "build",
        str(args.project.expanduser().resolve()),
        "--format",
        "ndjson",
        "--keep-workspace",
        "never",
    ]
    if args.jobs is not None:
        command.extend(("--jobs", str(args.jobs)))
    try:
        priming = measure(command)
        warm = []
        for _ in range(args.runs):
            sample = measure(command)
            require_unchanged(sample)
            warm.append(sample)
    except (OSError, ValueError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        return 2
    median = statistics.median(sample.wall_seconds for sample in warm)
    print(
        json.dumps(
            {
                "schema_version": 1,
                "command": command,
                "priming": asdict(priming),
                "warm": [asdict(sample) for sample in warm],
                "median_warm_seconds": median,
            },
            indent=2,
        )
    )
    return int(args.max_warm_seconds is not None and median > args.max_warm_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
