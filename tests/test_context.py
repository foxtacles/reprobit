from __future__ import annotations

import copy

import pytest

from reprobit.context import CompileContext, CompileContextError


def make_context(**changes: object) -> CompileContext:
    values: dict[str, object] = {
        "argv": (r"R:\toolchain\bin\cl.exe", "/c", r"R:\src\unit.cpp"),
        "cwd": r"R:\build",
        "source": r"R:\src\unit.cpp",
        "object_file": r"R:\workers\a\objects\unit.obj",
        "pdb_file": r"R:\workers\a\pdb\unit.pdb",
        "temp_directory": r"R:\workers\a\tmp",
        "include_paths": (r"R:\src\include",),
        "forced_includes": (r"R:\src\config.h",),
        "defines": ("NDEBUG", "VALUE=7"),
        "environment": {"TMP": r"R:\workers\a\tmp", "Path": r"R:\toolchain\bin"},
        "toolchain_profile": "msvc_4_2",
        "backend_profile": "posix_wine_v1",
    }
    values.update(changes)
    return CompileContext.create(**values)  # type: ignore[arg-type]


def test_receipt_is_canonical_and_round_trips() -> None:
    left = make_context(environment={"TMP": r"R:\workers\a\tmp", "Path": "x"})
    right = make_context(environment={"Path": "x", "TMP": r"R:\workers\a\tmp"})

    assert left.digest == right.digest
    assert left.to_json() == right.to_json()
    assert CompileContext.from_receipt(left.to_receipt()) == left


def test_receipt_tampering_is_refused() -> None:
    receipt = copy.deepcopy(make_context().to_receipt())
    receipt["argv"].append("/O2")

    with pytest.raises(CompileContextError, match="digest differs"):
        CompileContext.from_receipt(receipt)


def test_receipt_unknown_fields_are_refused_even_with_old_digest() -> None:
    receipt = make_context().to_receipt()
    receipt["undeclared"] = True

    with pytest.raises(CompileContextError, match="unknown"):
        CompileContext.from_receipt(receipt)


def test_artifacts_must_be_worker_private() -> None:
    context = make_context()
    context.require_private_artifacts(r"R:\workers\a")

    escaped = make_context(pdb_file=r"R:\shared\compiler.pdb")
    with pytest.raises(CompileContextError, match="not private"):
        escaped.require_private_artifacts(r"R:\workers\a")


def test_context_rejects_ambiguous_paths_and_environment() -> None:
    with pytest.raises(CompileContextError, match="invalid source"):
        make_context(source="R:/src/unit.cpp")
    with pytest.raises(CompileContextError, match="duplicate"):
        make_context(environment=(("Path", "a"), ("PATH", "b")))
    with pytest.raises(CompileContextError, match="must differ"):
        make_context(pdb_file=r"R:\workers\a\objects\unit.obj")
