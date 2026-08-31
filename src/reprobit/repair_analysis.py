"""Explicit non-certifying analysis pass used by the repair workflow."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from reprobit.classic.repair_session import (
    ClassicReceiptRepair,
    ClassicRepairRefusal,
    ClassicRepairSession,
)
from reprobit.cli_build import command_build
from reprobit.cli_output import CLIOutput
from reprobit.state import KeepWorkspace


class RepairAnalysisError(RuntimeError):
    """A non-certifying analysis failed outside a recorded repair seat."""


@dataclass(frozen=True, slots=True)
class RepairAnalysisResult:
    """Measured and structural fallout from one bounded incremental pass."""

    completed: bool
    measured_repairs: tuple[ClassicReceiptRepair, ...]
    structural_refusals: tuple[ClassicRepairRefusal, ...]


def analyze_classic_repair(
    args: argparse.Namespace,
    output: CLIOutput,
    *,
    cache_root: Path | None = None,
    progress_description: str = "checking affected source files",
) -> RepairAnalysisResult:
    """Run one warm analysis and distinguish repair fallout from fatal failure."""

    session = ClassicRepairSession()
    values = vars(args).copy()
    values.update(
        cold=False,
        keep_workspace=KeepWorkspace.NEVER.value,
        _classic_measured_receipt_repair=session,
        _classic_repair_analysis_only=True,
        _incremental_cache_root=cache_root,
        _incremental_progress_description=progress_description,
    )
    try:
        status = command_build(argparse.Namespace(**values), output)
    except Exception as exc:
        raise RepairAnalysisError(f"repair analysis failed: {exc}") from exc
    if status != 0:
        raise RepairAnalysisError(f"repair analysis returned failure status {status}")
    return RepairAnalysisResult(
        not session.refusals,
        session.repairs,
        session.refusals,
    )


__all__ = [
    "RepairAnalysisError",
    "RepairAnalysisResult",
    "analyze_classic_repair",
]
