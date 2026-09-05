from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import reprobit

ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize("prefix", ["", "v"])
def test_release_tag_accepts_the_packaged_version(prefix: str) -> None:
    tag = prefix + reprobit.__version__
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_release_tag.py"), tag],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert f"tag {tag} names the packaged version {reprobit.__version__}" in result.stdout


@pytest.mark.parametrize("tag", ["0.0.0", "v0.0.0", "master", "release-0.1.0"])
def test_release_tag_rejects_a_different_version_or_name(tag: str) -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/check_release_tag.py"), tag],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "does not name the packaged version" in result.stderr
