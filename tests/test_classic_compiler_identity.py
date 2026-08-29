from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from reprobit.classic.compiler_identity import (
    MSVC420_WIN32_I386_TARGET,
    Msvc420CompilerIdentity,
    issue_msvc420_compiler_identity,
)
from reprobit.model import Digest
from reprobit.schema import (
    LockedTool,
    MsvcRelease,
    ToolchainLock,
    ToolchainProfileSource,
)
from reprobit.strict_json import canonical_json

SOURCE_REPOSITORY = "https://github.com/archaic-msvc/msvc420.git"
SOURCE_REVISION = "b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50"
CANONICAL_TOOLS = (
    (
        "bin/CL.EXE",
        37_888,
        "c5bf7ad84482e8a54d5753fcbd3e648d8a1192f5ca8b8cf1f5d23b651750585f",
        ("compiler",),
    ),
    (
        "bin/C1XX.EXE",
        793_088,
        "9e0782ec157b30a387ca855374bc4c1b8a605dfb12364425497ba431541a5bf9",
        ("runtime",),
    ),
    (
        "bin/C2.EXE",
        549_888,
        "2aa1fcace0779531b3ec80b730663acd98f181aed3cdff51366440c602b724b5",
        ("runtime",),
    ),
)


def canonical_lock() -> ToolchainLock:
    return ToolchainLock(
        schema_version=3,
        adapter="classic-msvc",
        profile="msvc_4_2",
        release=MsvcRelease.V4_2,
        profile_sources=(
            ToolchainProfileSource(
                repository=SOURCE_REPOSITORY,
                revision=SOURCE_REVISION,
                paths=("bin/C1XX.EXE", "bin/C2.EXE", "bin/CL.EXE"),
            ),
        ),
        tools=tuple(
            LockedTool(
                id=f"tool.compiler-{index}",
                path=path,
                size=size,
                digest=Digest(value=sha256),
                roles=roles,
            )
            for index, (path, size, sha256, roles) in enumerate(CANONICAL_TOOLS)
        ),
    )


def replace_tool(lock: ToolchainLock, index: int, **changes: object) -> ToolchainLock:
    tools = list(lock.tools)
    tools[index] = tools[index].model_copy(update=changes)
    return lock.model_copy(update={"tools": tuple(tools)})


def test_issues_immutable_canonical_identity_and_proof_receipt() -> None:
    lock = canonical_lock()
    evidence = issue_msvc420_compiler_identity(lock)

    assert isinstance(evidence, Msvc420CompilerIdentity)
    assert evidence.target == MSVC420_WIN32_I386_TARGET
    assert evidence.toolchain_lock_digest == Digest.from_bytes(canonical_json(lock))
    assert [tool.path for tool in evidence.tools] == [item[0] for item in CANONICAL_TOOLS]
    assert evidence.canonical_receipt() == canonical_json(evidence.receipt_material())
    assert evidence.receipt_digest() == Digest.from_bytes(evidence.canonical_receipt())
    assert evidence.proof_receipt()["receipt_digest"] == evidence.receipt_digest().model_dump(
        mode="json"
    )
    with pytest.raises(FrozenInstanceError):
        evidence.toolchain_lock_digest = Digest(value="0" * 64)  # type: ignore[misc]


def test_identity_cannot_be_minted_without_the_validated_lock_issuer() -> None:
    with pytest.raises(TypeError, match="issued from a validated lock"):
        Msvc420CompilerIdentity(Digest(value="0" * 64))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 2),
        ("adapter", "classic-msvc-forged"),
        ("profile", "msvc_4_2_forged"),
        ("release", MsvcRelease.V5_RTM),
        ("release", "4.2"),
    ],
)
def test_refuses_forged_lock_labels(field: str, value: object) -> None:
    forged = canonical_lock().model_copy(update={field: value})
    assert issue_msvc420_compiler_identity(forged) is None


@pytest.mark.parametrize(
    ("repository", "revision"),
    [
        ("https://github.com/example/msvc420.git", SOURCE_REVISION),
        (SOURCE_REPOSITORY, "0" * 40),
    ],
)
def test_refuses_forged_source_pin(repository: str, revision: str) -> None:
    lock = canonical_lock()
    source = lock.profile_sources[0].model_copy(
        update={"repository": repository, "revision": revision}
    )
    assert (
        issue_msvc420_compiler_identity(lock.model_copy(update={"profile_sources": (source,)}))
        is None
    )


def test_refuses_missing_source_assignment() -> None:
    lock = canonical_lock()
    source = lock.profile_sources[0].model_copy(update={"paths": ("bin/C1XX.EXE", "bin/CL.EXE")})
    assert (
        issue_msvc420_compiler_identity(lock.model_copy(update={"profile_sources": (source,)}))
        is None
    )


def test_refuses_noncanonical_path_spelling() -> None:
    lock = canonical_lock()
    source = lock.profile_sources[0].model_copy(
        update={"paths": ("bin/C1XX.EXE", "bin/C2.EXE", "bin/cl.exe")}
    )
    forged = replace_tool(lock, 0, path="bin/cl.exe").model_copy(
        update={"profile_sources": (source,)}
    )
    assert issue_msvc420_compiler_identity(forged) is None


def test_refuses_missing_compiler_tool() -> None:
    lock = canonical_lock()
    missing = lock.model_copy(update={"tools": lock.tools[:-1]})
    assert issue_msvc420_compiler_identity(missing) is None


@pytest.mark.parametrize(
    ("index", "changes"),
    [
        (0, {"size": 37_887}),
        (1, {"digest": Digest(value="0" * 64)}),
        (2, {"path": "bin/C2-COPY.EXE"}),
        (0, {"roles": ("compiler", "runtime")}),
        (1, {"roles": ()}),
    ],
)
def test_refuses_forged_tool_receipt(index: int, changes: dict[str, object]) -> None:
    assert issue_msvc420_compiler_identity(replace_tool(canonical_lock(), index, **changes)) is None


def test_refuses_an_extra_compiler_role_tool() -> None:
    lock = canonical_lock()
    forged = LockedTool(
        id="tool.forged-compiler",
        path="bin/FORGED.EXE",
        size=1,
        digest=Digest(value="0" * 64),
        roles=("compiler",),
    )
    with_extra = lock.model_copy(update={"tools": (*lock.tools, forged)})
    assert issue_msvc420_compiler_identity(with_extra) is None
