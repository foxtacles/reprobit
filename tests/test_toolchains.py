from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from reprobit.backends import POSIX_WINE_BACKEND
from reprobit.context import CompileContext
from reprobit.model import Digest
from reprobit.paths import LogicalPathSkeleton, LogicalSeat
from reprobit.process import CommandSpec, ProcessSupervisor
from reprobit.schema import LockedTool, MsvcRelease, ToolchainProfileSource
from reprobit.schema import ToolchainLock as SchemaToolchainLock
from reprobit.toolchains import (
    MSVC_42,
    MSVC_50_RTM,
    MSVC_50_SP1,
    MSVC_50_SP2,
    MSVC_50_SP3,
    TOOLCHAIN_PROFILES,
    ClassicMSVCToolchain,
    ToolchainError,
    ToolchainLock,
    ToolchainSourcePin,
    profile_source_pins_for_paths,
)

_INTEGRATION_ROOTS = {
    MSVC_42: "REPROBIT_MSVC_4_2_ROOT",
    MSVC_50_RTM: "REPROBIT_MSVC_5_0_RTM_ROOT",
    MSVC_50_SP1: "REPROBIT_MSVC_5_0_SP1_ROOT",
    MSVC_50_SP2: "REPROBIT_MSVC_5_0_SP2_ROOT",
    MSVC_50_SP3: "REPROBIT_MSVC_5_0_SP3_ROOT",
}


def fake_installation(tmp_path: Path, identifier: str) -> ClassicMSVCToolchain:
    profile = TOOLCHAIN_PROFILES[identifier]
    root = tmp_path / identifier
    for relative in (*profile.required_producers, *profile.required_runtime_files):
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((identifier + ":" + relative).encode())
    for relative in (*profile.include_roots, *profile.library_roots):
        path = root.joinpath(*relative.split("/"))
        path.mkdir(parents=True, exist_ok=True)
        (path / "fixture.dat").write_text(relative)
    return ClassicMSVCToolchain(identifier, root)


def test_all_classic_profiles_are_explicit_and_revision_pinned() -> None:
    assert set(TOOLCHAIN_PROFILES) == {
        MSVC_42,
        MSVC_50_RTM,
        MSVC_50_SP1,
        MSVC_50_SP2,
        MSVC_50_SP3,
    }
    assert TOOLCHAIN_PROFILES[MSVC_42].capabilities.compiler_frontend_form == "executable"
    assert TOOLCHAIN_PROFILES[MSVC_42].wine_dll_overrides == (
        ("msvcrt40", "n"),
        ("msvcrt20", "n"),
    )
    msvc42 = TOOLCHAIN_PROFILES[MSVC_42]
    assert {
        (source.repository, source.revision) for source in msvc42.sources
    } == {
        (
            "https://github.com/archaic-msvc/msvc420.git",
            "b42c244f0a83ba15ba2ffb62b0dc240d7b2dea50",
        ),
        (
            "https://github.com/archaic-msvc/msvc500.git",
            "8abf95ce980161ad87b0b02402269cce76988953",
        ),
    }
    assert msvc42.source_for_path("bin/CL.EXE").repository.endswith("/msvc420.git")
    assert msvc42.source_for_path("bin/RCDLL.DLL").repository.endswith("/msvc420.git")
    assert msvc42.source_for_path("bin/MSVCRT40.dll").repository.endswith("/msvc500.git")
    for identifier in (MSVC_50_RTM, MSVC_50_SP1, MSVC_50_SP2, MSVC_50_SP3):
        profile = TOOLCHAIN_PROFILES[identifier]
        assert profile.capabilities.compiler_frontend_form == "dynamic_library"
        assert len(profile.sources) == 1
        assert len(profile.sources[0].revision) == 40


def test_toolchain_lock_detects_producer_drift(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    lock = toolchain.create_lock(include_trees=True)
    assert toolchain.doctor(lock).ok

    toolchain.host_path(toolchain.profile.compiler).write_bytes(b"changed")
    report = toolchain.doctor(lock)
    assert not report.ok
    assert any(check.detail == "digest differs" for check in report.checks)


def test_runtime_lock_has_an_authenticated_v2_receipt_and_schema_v3_conversion(
    tmp_path: Path,
) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    runtime_lock = toolchain.create_lock(include_trees=True)

    encoded = runtime_lock.to_dict()
    decoded = ToolchainLock.from_dict(json.loads(json.dumps(encoded)))
    schema_lock = decoded.to_schema_v3()

    assert decoded == runtime_lock
    assert schema_lock.schema_version == 3
    assert tuple(
        (source.repository, source.revision, source.paths)
        for source in schema_lock.profile_sources
    ) == tuple(
        (source.repository, source.revision, source.paths)
        for source in toolchain.profile.sources
    )
    assert {item.path for item in schema_lock.tools} == set(
        toolchain.profile.required_producers
    )
    assert {item.path for item in schema_lock.runtime_files} == set(
        toolchain.profile.required_runtime_files
    )
    assert {item.path for item in schema_lock.input_trees} == {
        *toolchain.profile.include_roots,
        *toolchain.profile.library_roots,
    }
    assert {item.algorithm for item in schema_lock.input_trees} == {"portable-tree-v1"}
    assert ToolchainLock.from_schema_v3(schema_lock) == runtime_lock

    encoded["sha256"] = "0" * 64
    with pytest.raises(ToolchainError, match="digest differs"):
        ToolchainLock.from_dict(encoded)


def test_schema_v3_conversion_rejects_profile_source_drift(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    schema_lock = toolchain.create_lock().to_schema_v3()
    first = schema_lock.profile_sources[0]
    mismatched = schema_lock.model_copy(
        update={
            "profile_sources": (
                first.model_copy(update={"revision": "0" * 40}),
                *schema_lock.profile_sources[1:],
            )
        }
    )

    with pytest.raises(ToolchainError, match="profile-source mapping differs"):
        ToolchainLock.from_schema_v3(mismatched)


def test_schema_profile_source_cannot_name_an_unlocked_path(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    document = toolchain.create_lock().to_schema_v3().model_dump()
    sources = list(document["profile_sources"])
    first = dict(sources[0])
    first["paths"] = tuple(
        sorted((*first["paths"], "bin/UNLOCKED.EXE"), key=str.casefold)
    )
    sources[0] = first
    document["profile_sources"] = tuple(sources)

    with pytest.raises(ValidationError, match="unlocked paths"):
        SchemaToolchainLock.model_validate(document)


@pytest.mark.parametrize("legacy_field", ("source_revision", "sources"))
def test_schema_v3_rejects_pre_release_source_fields(
    tmp_path: Path, legacy_field: str
) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    document = toolchain.create_lock().to_schema_v3().model_dump()
    profile_sources = document.pop("profile_sources")
    document[legacy_field] = (
        "0" * 40 if legacy_field == "source_revision" else profile_sources
    )

    with pytest.raises(ValidationError, match=legacy_field):
        SchemaToolchainLock.model_validate(document)


def test_schema_v3_conversion_admits_and_verifies_extra_runtime_files(
    tmp_path: Path,
) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    wrapper = toolchain.host_path("wine/x86/cl")
    wrapper.parent.mkdir(parents=True)
    wrapper.write_bytes(b"pinned wrapper")
    runtime_lock = toolchain.create_lock(runtime_paths=("wine/x86/cl",))
    schema_lock = runtime_lock.to_schema_v3()
    assigned_paths = {
        path.casefold()
        for source in schema_lock.profile_sources
        for path in source.paths
    }
    assert "wine/x86/cl" not in assigned_paths

    # Older migrations sometimes placed support files in ``tools``.  Runtime
    # projection canonicalizes by profile membership instead of trusting that
    # historical bucket choice.
    extra = schema_lock.runtime_files[-1]
    mixed_schema = schema_lock.model_copy(
        update={
            "tools": (*schema_lock.tools, extra),
            "runtime_files": schema_lock.runtime_files[:-1],
        }
    )
    projected = ToolchainLock.from_schema_v3(mixed_schema)

    assert {item.path for item in projected.files} == set(
        toolchain.profile.required_producers
    )
    assert "wine/x86/cl" in {item.path for item in projected.runtime_files}
    assert toolchain.doctor(projected).ok

    wrapper.write_bytes(b"changed wrapper")
    report = toolchain.doctor(projected)
    assert not report.ok
    assert any(
        check.path == "wine/x86/cl" and check.detail == "runtime digest differs"
        for check in report.checks
    )


def test_locked_wrapper_cannot_claim_an_extra_profile_source(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    wrapper = toolchain.host_path("wine/x86/cl")
    wrapper.parent.mkdir(parents=True)
    wrapper.write_bytes(b"pinned wrapper")
    runtime_lock = toolchain.create_lock(runtime_paths=("wine/x86/cl",))
    extra_source = ToolchainSourcePin(
        "https://example.invalid/unreviewed-wrapper.git",
        "f" * 40,
        ("wine/x86/cl",),
    )

    with pytest.raises(ValueError, match="profile-source assignment set differs"):
        ToolchainLock(
            runtime_lock.schema,
            runtime_lock.profile,
            (*runtime_lock.profile_sources, extra_source),
            runtime_lock.files,
            runtime_lock.tree_digests,
            runtime_lock.runtime_files,
        )

    schema_lock = runtime_lock.to_schema_v3()
    overclaimed = schema_lock.model_copy(
        update={
            "profile_sources": (
                *schema_lock.profile_sources,
                ToolchainProfileSource(
                    repository=extra_source.repository,
                    revision=extra_source.revision,
                    paths=extra_source.paths,
                ),
            )
        }
    )
    with pytest.raises(ToolchainError, match="profile-source assignment set differs"):
        ToolchainLock.from_schema_v3(overclaimed)


def test_schema_v3_conversion_rejects_missing_required_producer(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    schema_lock = toolchain.create_lock().to_schema_v3()
    omitted_path = schema_lock.tools[0].path.casefold()
    incomplete = schema_lock.model_copy(
        update={
            "tools": schema_lock.tools[1:],
            "profile_sources": tuple(
                source.model_copy(
                    update={
                        "paths": tuple(
                            path
                            for path in source.paths
                            if path.casefold() != omitted_path
                        )
                    }
                )
                for source in schema_lock.profile_sources
            ),
        }
    )

    with pytest.raises(ToolchainError, match="omits required producers"):
        ToolchainLock.from_schema_v3(incomplete)


def test_schema_v3_conversion_rejects_missing_required_runtime_file(
    tmp_path: Path,
) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    schema_lock = toolchain.create_lock().to_schema_v3()
    omitted_path = schema_lock.runtime_files[0].path.casefold()
    incomplete = schema_lock.model_copy(
        update={
            "runtime_files": schema_lock.runtime_files[1:],
            "profile_sources": tuple(
                source.model_copy(
                    update={
                        "paths": tuple(
                            path
                            for path in source.paths
                            if path.casefold() != omitted_path
                        )
                    }
                )
                for source in schema_lock.profile_sources
            ),
        }
    )

    with pytest.raises(ToolchainError, match="omits required runtime files"):
        ToolchainLock.from_schema_v3(incomplete)


def test_schema_v3_conversion_rejects_profile_release_disagreement(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    schema_lock = toolchain.create_lock().to_schema_v3()
    mismatched = schema_lock.model_copy(update={"release": MsvcRelease.V5_RTM})

    with pytest.raises(ToolchainError, match="release differs"):
        ToolchainLock.from_schema_v3(mismatched)


def test_create_lock_requires_declared_runtime_file_to_exist(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)

    with pytest.raises(ToolchainError, match="declared runtime file is absent"):
        toolchain.create_lock(runtime_paths=("wine/x86/missing-wrapper",))


def test_runtime_receipt_with_unknown_tool_is_still_separately_pinned(
    tmp_path: Path,
) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    schema_lock = toolchain.create_lock().to_schema_v3()
    support = toolchain.host_path("bin/CL.ERR")
    support.write_bytes(b"diagnostic catalog")
    extra = LockedTool(
        id="runtime.cl-errors",
        path="bin/CL.ERR",
        digest=Digest.from_bytes(b"diagnostic catalog"),
        size=len(b"diagnostic catalog"),
        roles=("runtime",),
    )
    schema_lock = schema_lock.model_copy(
        update={"runtime_files": (*schema_lock.runtime_files, extra)}
    )

    runtime_lock = ToolchainLock.from_schema_v3(schema_lock)

    assert toolchain.doctor(runtime_lock).ok


def test_doctor_rejects_a_lock_with_an_unpinned_producer(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    original = toolchain.create_lock()
    incomplete = ToolchainLock(
        original.schema,
        original.profile,
        profile_source_pins_for_paths(
            toolchain.profile, (item.path for item in original.files[:-1])
        ),
        original.files[:-1],
    )

    report = toolchain.doctor(incomplete)

    assert not report.ok
    assert any(check.path == "lock.files" and not check.passed for check in report.checks)


def test_portable_tree_receipts_ignore_physical_roots_and_host_modes(
    tmp_path: Path,
) -> None:
    first = fake_installation(tmp_path / "short", MSVC_42)
    second = fake_installation(tmp_path / "a-much-longer-physical-root", MSVC_42)
    if os.name == "posix":
        first.host_path("include").chmod(0o700)
        first.host_path("include/fixture.dat").chmod(0o755)
        second.host_path("include").chmod(0o755)
        second.host_path("include/fixture.dat").chmod(0o600)

    first_receipts = first.create_lock().tree_digests
    second_receipts = second.create_lock().tree_digests

    assert first_receipts == second_receipts
    assert {item.algorithm for item in first_receipts} == {"portable-tree-v1"}


def test_portable_tree_receipt_rejects_symlinks(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    link = toolchain.host_path("include/linked.dat")
    try:
        link.symlink_to(toolchain.host_path("include/fixture.dat"))
    except OSError as error:
        pytest.skip(f"host cannot create a test symlink: {error}")

    with pytest.raises(ToolchainError, match="contains a symlink"):
        toolchain.create_lock()


def test_portable_tree_receipt_rejects_casefold_collisions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    include = toolchain.host_path("include")
    real_scandir = os.scandir

    class CollisionScan:
        def __init__(self, directory: Path) -> None:
            self._iterator = real_scandir(directory)
            self._directory = directory

        def __enter__(self) -> object:
            entries = list(self._iterator)
            if self._directory == include:
                entries.append(SimpleNamespace(name=entries[0].name.swapcase()))
            return iter(entries)

        def __exit__(self, *args: object) -> None:
            self._iterator.close()

    monkeypatch.setattr(
        "reprobit.toolchains.os.scandir",
        lambda directory: CollisionScan(Path(directory)),
    )

    with pytest.raises(ToolchainError, match="casefold collision"):
        toolchain.create_lock()


def test_portable_tree_receipt_rejects_a_file_mutation_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    real_fstat = os.fstat
    calls = 0

    def drifting_fstat(descriptor: int) -> os.stat_result | SimpleNamespace:
        nonlocal calls
        calls += 1
        metadata = real_fstat(descriptor)
        if calls != 2:
            return metadata
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_dev=metadata.st_dev,
            st_ino=metadata.st_ino,
            st_size=metadata.st_size,
            st_mtime_ns=metadata.st_mtime_ns + 1,
            st_ctime_ns=metadata.st_ctime_ns,
        )

    monkeypatch.setattr("reprobit.toolchains.os.fstat", drifting_fstat)

    with pytest.raises(ToolchainError, match="changed while hashed"):
        toolchain.create_lock()


def test_doctor_detects_portable_input_tree_drift(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    lock = toolchain.create_lock()
    toolchain.host_path("include/fixture.dat").write_text("changed")

    report = toolchain.doctor(lock)

    assert not report.ok
    assert any(
        check.path == "include" and check.detail == "tree receipt differs"
        for check in report.checks
    )


def test_compile_context_preserves_exact_dos_inputs_and_private_outputs(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_50_SP3)
    context = toolchain.compile_context(
        source=r"R:\src\unit.cpp",
        object_file=r"R:\workers\a\objects\unit.obj",
        pdb_file=r"R:\workers\a\pdb\unit.pdb",
        cwd=r"R:\build",
        temp_directory=r"R:\workers\a\tmp",
        backend_profile=POSIX_WINE_BACKEND,
        include_paths=(r"R:\src\include",),
        forced_includes=(r"R:\src\forced.h",),
        defines=("VALUE=2",),
        options=("/O2", "/GX"),
        logical_worker_root=r"R:\workers\a",
    )

    assert isinstance(context, CompileContext)
    assert context.argv == (
        r"R:\toolchain\bin\cl.exe",
        "/nologo",
        "/c",
        "/O2",
        "/GX",
        "/DVALUE=2",
        r"/IR:\src\include",
        r"/FIR:\src\forced.h",
        r"/FoR:\workers\a\objects\unit.obj",
        r"/FdR:\workers\a\pdb\unit.pdb",
        r"R:\src\unit.cpp",
    )
    assert context.environment_mapping["TMP"] == r"R:\workers\a\tmp"


def test_non_private_pdb_is_refused(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_42)
    with pytest.raises(ValueError, match="not private"):
        toolchain.compile_context(
            source=r"R:\src\unit.cpp",
            object_file=r"R:\workers\a\objects\unit.obj",
            pdb_file=r"R:\shared\compiler.pdb",
            cwd=r"R:\build",
            temp_directory=r"R:\workers\a\tmp",
            backend_profile=POSIX_WINE_BACKEND,
            logical_worker_root=r"R:\workers\a",
        )


def test_compile_receipt_is_independent_of_the_physical_source_root(tmp_path: Path) -> None:
    toolchain = fake_installation(tmp_path, MSVC_50_SP3)
    contexts: list[CompileContext] = []
    for name in ("physical-a", "a-much-longer-physical-root-b"):
        source = tmp_path / name / "source"
        output = tmp_path / name / "output"
        source.mkdir(parents=True)
        output.mkdir()
        unit = source / "unit.cpp"
        unit.write_text("extern \"C\" int value() { return 7; }\n")
        skeleton = LogicalPathSkeleton(
            (
                LogicalSeat("source", source, r"R:\Users\builder\project\source"),
                LogicalSeat(
                    "output",
                    output,
                    r"R:\Users\builder\project\output",
                    writable=True,
                ),
            )
        )
        assert skeleton.to_logical(unit) == r"R:\Users\builder\project\source\unit.cpp"
        with skeleton.temporary_materialization(tmp_path / name / "skeletons") as materialized:
            compiler_view = (
                materialized.root / "Users" / "builder" / "project" / "source"
            )
            assert compiler_view.resolve(strict=True) == source.resolve(strict=True)
        contexts.append(
            toolchain.compile_context(
                source=r"R:\Users\builder\project\source\unit.cpp",
                object_file=r"R:\Users\builder\project\output\unit.obj",
                pdb_file=r"R:\Users\builder\project\output\unit.pdb",
                cwd=r"R:\Users\builder\project\source",
                temp_directory=r"R:\Users\builder\project\output",
                backend_profile=POSIX_WINE_BACKEND,
                logical_worker_root=r"R:\Users\builder\project\output",
            )
        )

    assert contexts[0].canonical_data() == contexts[1].canonical_data()
    assert contexts[0].digest == contexts[1].digest


@pytest.mark.parametrize("identifier", tuple(_INTEGRATION_ROOTS))
def test_opt_in_profile_compiler_smoke(
    tmp_path: Path,
    identifier: str,
) -> None:
    """Real compiler coverage; ordinary CI skips unless installation roots are declared."""

    variable = _INTEGRATION_ROOTS[identifier]
    configured_root = os.environ.get(variable)
    if configured_root is None:
        pytest.skip(f"set {variable} to run the classic compiler integration")
    if os.name != "posix":
        pytest.skip("this integration exercises the POSIX Wine backend")
    installation_root = Path(configured_root).resolve(strict=True)
    toolchain = ClassicMSVCToolchain(identifier, installation_root)
    toolchain.doctor().require_ok()
    fixture = Path(__file__).parent / "fixtures" / "classic_smoke.cpp"
    wrapper = installation_root / "wine" / "x86" / "cl"
    if not wrapper.is_file():
        pytest.skip(f"declared integration root has no compiler wrapper: {wrapper}")
    wine = shutil.which("wine")
    if wine is None:
        pytest.skip("the declared integration root requires Wine")
    host_environment = {
        "HOME": os.environ["HOME"],
        "USER": os.environ.get("USER", "reprobit"),
        "LOGNAME": os.environ.get("LOGNAME", "reprobit"),
        "TMPDIR": str(tmp_path),
        "PATH": os.pathsep.join(
            (str(Path(wine).resolve().parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin")
        ),
        "LC_ALL": "C",
        "LANG": "C",
        "WINEDEBUG": "-all",
        "MVK_CONFIG_LOG_LEVEL": "0",
    }
    output_root = tmp_path / "private-output"
    output_root.mkdir()
    object_file = output_root / "classic_smoke.obj"
    pdb_file = output_root / "classic_smoke.pdb"
    command = CommandSpec.create(
        (
            str(wrapper),
            "/nologo",
            "/c",
            str(fixture),
            f"/Fo{object_file}",
            f"/Fd{pdb_file}",
        ),
        cwd=output_root,
        environment=host_environment,
        timeout_seconds=60,
        log_path=output_root / "compile.log",
    )
    with ProcessSupervisor() as supervisor:
        supervisor.run(command)
    assert object_file.is_file() and object_file.stat().st_size > 0
    assert len(hashlib.sha256(object_file.read_bytes()).hexdigest()) == 64
