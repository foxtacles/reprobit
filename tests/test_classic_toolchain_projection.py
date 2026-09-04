from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import reprobit.classic_runtime_environment as runtime_environment
from reprobit.classic_project import ClassicProjectError
from reprobit.model import Digest
from reprobit.schema import (
    InputTreeReceipt,
    LockedTool,
    MsvcRelease,
    ProjectBundle,
    ToolchainLock,
)
from reprobit.secure_path_contracts import SecureFileIdentity, SecureFileSnapshot


def _bundle(
    *,
    compiler: bytes,
    runtime: bytes,
) -> ProjectBundle:
    lock = ToolchainLock(
        schema_version=3,
        profile="msvc_4_2",
        release=MsvcRelease.V4_2,
        tools=(
            LockedTool(
                id="compiler",
                path="bin/CL.EXE",
                digest=Digest.from_bytes(compiler),
                size=len(compiler),
            ),
        ),
        runtime_files=(
            LockedTool(
                id="runtime",
                path="runtime/helper.sh",
                digest=Digest.from_bytes(runtime),
                size=len(runtime),
            ),
        ),
        input_trees=(
            InputTreeReceipt(
                id="include",
                path="include",
                entry_count=2,
                max_depth=1,
                membership_digest=Digest.from_bytes(b"membership"),
                content_digest=Digest.from_bytes(b"tree content"),
            ),
        ),
    )
    return cast(ProjectBundle, SimpleNamespace(toolchain_lock=lock))


def test_locked_toolchain_projection_streams_each_file_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_root = tmp_path / "toolchain"
    destination = tmp_path / "projected"
    files = {
        "bin/CL.EXE": b"compiler",
        "include/sdk/header.h": b"#define FIXTURE 1\n",
        "runtime/helper.sh": b"#!/bin/sh\nexit 0\n",
    }
    for relative, payload in files.items():
        path = source_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    (source_root / "bin/CL.EXE").chmod(0o751)
    (source_root / "include/sdk/header.h").chmod(0o744)
    (source_root / "runtime/helper.sh").chmod(0o640)

    def forbidden_path_operation(*_args: object, **_kwargs: object) -> None:
        pytest.fail("projection used the old path copy/hash pipeline")

    monkeypatch.setattr(runtime_environment, "_digest_path", forbidden_path_operation)
    monkeypatch.setattr(runtime_environment.shutil, "copyfile", forbidden_path_operation)
    real_copy = runtime_environment.atomic_copy_new_relative
    calls: list[
        tuple[
            str,
            str,
            bool,
            Digest | None,
            int | None,
            SecureFileIdentity | None,
        ]
    ] = []

    def counted_copy(
        source: Path,
        source_relative: str,
        target: Path,
        target_relative: str,
        *,
        executable: bool = False,
        expected_digest: Digest | None = None,
        expected_size: int | None = None,
        expected_source: SecureFileIdentity | None = None,
    ) -> SecureFileSnapshot:
        calls.append(
            (
                source_relative,
                target_relative,
                executable,
                expected_digest,
                expected_size,
                expected_source,
            )
        )
        return real_copy(
            source,
            source_relative,
            target,
            target_relative,
            executable=executable,
            expected_digest=expected_digest,
            expected_size=expected_size,
            expected_source=expected_source,
        )

    monkeypatch.setattr(runtime_environment, "atomic_copy_new_relative", counted_copy)

    originals = runtime_environment._project_locked_toolchain(
        _bundle(compiler=files["bin/CL.EXE"], runtime=files["runtime/helper.sh"]),
        source_root=source_root,
        destination=destination,
    )

    expected_order = ("bin/CL.EXE", "include/sdk/header.h", "runtime/helper.sh")
    assert tuple(item[0] for item in calls) == expected_order
    assert tuple(item[1] for item in calls) == expected_order
    assert all(item[5] is not None for item in calls)
    assert calls[0][3:5] == (Digest.from_bytes(files["bin/CL.EXE"]), len(files["bin/CL.EXE"]))
    assert calls[1][3:5] == (None, len(files["include/sdk/header.h"]))
    assert calls[2][3:5] == (
        Digest.from_bytes(files["runtime/helper.sh"]),
        len(files["runtime/helper.sh"]),
    )
    assert originals == tuple(source_root / relative for relative in expected_order)
    for relative, payload in files.items():
        projected = destination / relative
        assert projected.read_bytes() == payload
        if os.name != "nt":
            assert bool(projected.stat().st_mode & stat.S_IXUSR) == bool(
                (source_root / relative).stat().st_mode & stat.S_IXUSR
            )


def test_locked_toolchain_projection_rejects_a_lock_mismatch(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "toolchain"
    compiler = source_root / "bin/CL.EXE"
    runtime = source_root / "runtime/helper.sh"
    header = source_root / "include/sdk/header.h"
    for path, payload in (
        (compiler, b"changed compiler"),
        (runtime, b"runtime"),
        (header, b"header"),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    with pytest.raises(ClassicProjectError, match=r"projection failed.*digest differs"):
        runtime_environment._project_locked_toolchain(
            _bundle(compiler=b"locked compiler", runtime=b"runtime"),
            source_root=source_root,
            destination=tmp_path / "projected",
        )

    assert not (tmp_path / "projected/bin/CL.EXE").exists()
