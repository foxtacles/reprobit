"""Receipt construction shared by classic runtime executors."""

from __future__ import annotations

import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

from reprobit.classic_project import ClassicProjectError
from reprobit.classic_runtime_files import _digest_path
from reprobit.execution import FileReceipt, StepExecutionReceipt
from reprobit.model import Digest
from reprobit.process import CommandSpec, ProcessResult
from reprobit.strict_json import canonical_json


def _receipt(path: Path, *, fresh: bool, producer_step: str | None) -> FileReceipt:
    if path.is_symlink() or not path.is_file():
        raise ClassicProjectError(f"classic output is absent or redirected: {path}")
    before = path.stat()
    if not stat.S_ISREG(before.st_mode):
        raise ClassicProjectError(f"classic output is not regular: {path}")
    digest = _digest_path(path)
    after = path.stat()
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_after:
        raise ClassicProjectError(f"classic output changed while receipted: {path}")
    return FileReceipt(
        path.resolve(strict=True),
        digest,
        after.st_size,
        fresh,
        producer_step,
        after.st_dev,
        after.st_ino,
    )


def _command_digest(argv: Sequence[str], cwd: Path, environment: Mapping[str, str]) -> Digest:
    return Digest.from_bytes(
        canonical_json(
            {
                "argv": list(argv),
                "cwd": str(cwd),
                "environment": dict(sorted(environment.items())),
            }
        )
    )


def _step_receipt(step_id: str, result: ProcessResult, spec: CommandSpec) -> StepExecutionReceipt:
    return StepExecutionReceipt(
        step_id,
        result.returncode,
        result.attempts,
        result.duration_seconds,
        Digest.from_bytes(result.output),
        _command_digest(result.argv, spec.cwd, spec.environment_mapping),
    )


def _internal_step(step_id: str, material: object, duration: float) -> StepExecutionReceipt:
    digest = Digest.from_bytes(canonical_json(material))
    return StepExecutionReceipt(step_id, 0, 1, duration, digest, digest)


__all__ = []
