from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from reprobit.classic.linker_identity import (
    MSVC420_LINKER_TARGET,
    Msvc420LinkerIdentity,
    issue_msvc420_linker_identity,
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
LINKER_PATH = "bin/LINK.EXE"
LINKER_SIZE = 514_048
LINKER_DIGEST = (
    "6ca5a19155e4170e8df08247769b4586fa951743f09f1d8fcec838fc4eb9750e"
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
                paths=(LINKER_PATH,),
            ),
        ),
        tools=(
            LockedTool(
                id="tool.linker",
                path=LINKER_PATH,
                size=LINKER_SIZE,
                digest=Digest(value=LINKER_DIGEST),
                roles=("linker",),
            ),
        ),
    )


def replace_linker(lock: ToolchainLock, **changes: object) -> ToolchainLock:
    linker = lock.tools[0].model_copy(update=changes)
    return lock.model_copy(update={"tools": (linker,)})


def test_issues_immutable_canonical_identity_and_proof_receipt() -> None:
    lock = canonical_lock()
    evidence = issue_msvc420_linker_identity(lock)

    assert isinstance(evidence, Msvc420LinkerIdentity)
    assert evidence.target == MSVC420_LINKER_TARGET
    assert evidence.tool.path == LINKER_PATH
    assert evidence.tool.size == LINKER_SIZE
    assert evidence.tool.digest == Digest(value=LINKER_DIGEST)
    assert evidence.tool.roles == ("linker",)
    assert evidence.toolchain_lock_digest == Digest.from_bytes(canonical_json(lock))
    assert evidence.canonical_receipt() == canonical_json(evidence.receipt_material())
    assert evidence.receipt_digest() == Digest.from_bytes(evidence.canonical_receipt())
    assert evidence.proof_receipt() == {
        **evidence.receipt_material(),
        "receipt_digest": evidence.receipt_digest().model_dump(mode="json"),
    }
    with pytest.raises(FrozenInstanceError):
        evidence.toolchain_lock_digest = Digest(value="0" * 64)  # type: ignore[misc]


def test_identity_cannot_be_minted_without_the_validated_lock_issuer() -> None:
    with pytest.raises(TypeError, match="issued from a validated lock"):
        Msvc420LinkerIdentity(Digest(value="0" * 64))


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
    assert issue_msvc420_linker_identity(forged) is None


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
        issue_msvc420_linker_identity(lock.model_copy(update={"profile_sources": (source,)}))
        is None
    )


def test_refuses_missing_source_assignment() -> None:
    lock = canonical_lock()
    assert issue_msvc420_linker_identity(lock.model_copy(update={"profile_sources": ()})) is None


def test_refuses_noncanonical_path_spelling() -> None:
    lock = canonical_lock()
    source = lock.profile_sources[0].model_copy(update={"paths": ("bin/link.exe",)})
    forged = replace_linker(lock, path="bin/link.exe").model_copy(
        update={"profile_sources": (source,)}
    )

    assert issue_msvc420_linker_identity(forged) is None


@pytest.mark.parametrize(
    "changes",
    [
        {"path": "bin/LINK-COPY.EXE"},
        {"digest": Digest(value="0" * 64)},
        {"size": LINKER_SIZE - 1},
        {"roles": ()},
        {"roles": ("linker", "runtime")},
    ],
)
def test_refuses_forged_linker_receipt(changes: dict[str, object]) -> None:
    assert issue_msvc420_linker_identity(replace_linker(canonical_lock(), **changes)) is None


def test_refuses_an_extra_linker_role_tool() -> None:
    lock = canonical_lock()
    forged = LockedTool(
        id="tool.forged-linker",
        path="bin/FORGED.EXE",
        size=1,
        digest=Digest(value="0" * 64),
        roles=("linker",),
    )
    with_extra = lock.model_copy(update={"runtime_files": (forged,)})

    assert issue_msvc420_linker_identity(with_extra) is None
