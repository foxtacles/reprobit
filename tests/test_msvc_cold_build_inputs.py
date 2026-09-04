"""Exercise developer input guardrails through the installed CLI and real MSVC."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest
from test_msvc_repair_integration import (
    REFERENCE_IMAGE_SHA256,
    SAMPLE,
    _events,
    _rbit,
    _run,
)

from reprobit.developer_authority import current_worktree_authority
from reprobit.model import Digest
from reprobit.project_loader import load_project_tree

pytestmark = [
    pytest.mark.msvc42,
    pytest.mark.skipif(
        not os.environ.get("REPROBIT_MSVC_4_2_ROOT"),
        reason="requires an authenticated MSVC 4.2 CI lane",
    ),
]


def _tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def test_authenticated_msvc42_cold_build_uses_current_unprotected_inputs(
    tmp_path: Path,
) -> None:
    configured = os.environ.get("REPROBIT_MSVC_4_2_ROOT")
    assert configured, "CI must provision REPROBIT_MSVC_4_2_ROOT"
    toolchain_root = Path(configured).resolve(strict=True)
    project = tmp_path / "repair"
    shutil.copytree(
        SAMPLE,
        project,
        ignore=shutil.ignore_patterns(
            "__pycache__",
            ".reprobit-state",
            ".reprobit-transactions",
            "build",
            "reference",
        ),
    )
    environment = os.environ.copy()
    environment["REPROBIT_MSVC_4_2_ROOT"] = os.fspath(toolchain_root)
    environment["PYTHONUTF8"] = "1"
    prepared = _run(
        (sys.executable, project / "prepare_reference.py", "--toolchain-root", toolchain_root),
        cwd=project,
        environment=environment,
    )
    assert prepared.returncode == 0, prepared.stdout + prepared.stderr
    reference = project / "reference/repair.exe"
    assert Digest.from_path(reference).value == REFERENCE_IMAGE_SHA256

    committed = load_project_tree(project)
    original_authority = _tree_bytes(project / "reprobit")
    original_spec = (project / "reprobit.toml").read_bytes()
    source = project / "support.cpp"
    source.write_bytes(source.read_bytes() + b"\n// Harmless developer edit.\n")
    authority = current_worktree_authority(committed, project)
    assert authority.changed_paths == ("support.cpp",)
    assert "support.cpp" not in authority.protected_sources
    assert "transform.cpp" in authority.protected_sources
    cache = project / committed.spec.state_dir / "cache"
    assert not cache.exists()

    built = _run(
        (_rbit(), "--format", "ndjson", "build", project, "--cold"),
        cwd=project,
        environment=environment,
    )
    events = _events(built)
    completions = [event for event in events if event.get("event") == "build_complete"]
    assert len(completions) == 1
    assert completions[0]["cold"] is True
    assert Digest.from_path(project / "build/repair.exe") == Digest.from_path(reference)
    assert not cache.exists()
    assert _tree_bytes(project / "reprobit") == original_authority
    assert (project / "reprobit.toml").read_bytes() == original_spec
    published = _tree_bytes(project / "build")
    assert "repair.exe" in published

    verification = _run(
        (_rbit(), "--format", "ndjson", "verify", project),
        cwd=project,
        environment=environment,
    )
    assert verification.returncode != 0, verification.stdout + verification.stderr
    diagnostic = verification.stdout + verification.stderr
    assert "source input differs from portable manifest: 'support.cpp'" in diagnostic
    assert _tree_bytes(project / "build") == published
    assert _tree_bytes(project / "reprobit") == original_authority
    assert not cache.exists()

    header = project / "shared.h"
    header.write_bytes(header.read_bytes() + b"\n// Changed input to reviewed transform.cpp.\n")
    for options in (("--cold",), ()):
        refused = _run(
            (_rbit(), "--format", "ndjson", "build", project, *options),
            cwd=project,
            environment=environment,
        )
        assert refused.returncode != 0, refused.stdout + refused.stderr
        refusal = refused.stdout + refused.stderr
        assert "recursive input edit(s) 'shared.h'" in refusal
        assert "protected translation unit 'tu.transform'" in refusal
        assert "invalidate reviewed intervention(s)" in refusal
        assert "run rbit repair" in refusal
        assert _tree_bytes(project / "build") == published
        assert _tree_bytes(project / "reprobit") == original_authority
        assert (project / "reprobit.toml").read_bytes() == original_spec
        if options:
            assert not cache.exists()
